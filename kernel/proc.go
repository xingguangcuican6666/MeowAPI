package kernel

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ProcState is the lifecycle state of a process table record.
type ProcState string

const (
	// ProcRunning is a live context.
	ProcRunning ProcState = "running"
	// ProcTerminated is a context that ran and stopped.
	ProcTerminated ProcState = "terminated"
	// ProcRejected is a context the kernel refused to run, for example a module
	// whose manifest failed validation. It never becomes terminated: "the kernel
	// refused this" and "this ran and stopped" are different facts, and an audit
	// needs both.
	ProcRejected ProcState = "rejected"
)

// ProcRecord is one row of the process table. Records are appended and never
// removed: this is the provenance log of what ran, under which context, with
// which grants.
//
// Identity fields (PID, UID, Domain, Name, PPID, Created) are fixed at creation.
// Artifact, ManifestDigest, State and Terminated are written by the kernel under
// the table's lock, after the fact, as the module's real state becomes known.
type ProcRecord struct {
	PID            PID
	UID            UID
	Domain         Domain
	Name           string
	PPID           PID
	Created        time.Time
	Artifact       string
	ManifestDigest string
	State          ProcState
	Terminated     time.Time
}

// ProcSnapshot is an immutable copy of a process table row, safe to hand out.
// Callers get this rather than *ProcRecord so no one outside the table can
// mutate a live audit row.
type ProcSnapshot struct {
	PID            PID       `json:"pid"`
	UID            UID       `json:"uid"`
	Domain         Domain    `json:"domain"`
	Name           string    `json:"name"`
	PPID           PID       `json:"ppid"`
	Created        time.Time `json:"created"`
	Artifact       string    `json:"artifact,omitempty"`
	ManifestDigest string    `json:"manifest_digest,omitempty"`
	State          ProcState `json:"state"`
	Terminated     time.Time `json:"terminated,omitempty"`
}

// contextManager owns pid and uid allocation and the append-only process table.
// There is exactly one, held by the kernel singleton. It does not own the
// metadata store, which lives in metadata.go with its own lock: the two are
// independent subsystems that happened to share a struct in the prototype.
type contextManager struct {
	mu      sync.Mutex
	nextPID PID
	nextUID UID
	procs   []*ProcRecord

	root   *sContext
	handed bool
}

// kscm is the kernel context manager singleton. It is constructed eagerly with a
// valid zero state so no code path can observe it nil, and resetKernel clears the
// accounting for a fresh boot.
var kscm = &contextManager{nextPID: 1, nextUID: firstPluginUID}

// handoffRootContext transfers the pid 0 context exactly once per boot. The
// second call is a kernel panic, not a nil return: a silent no-op would let a
// caller believe it still holds root.
func (m *contextManager) handoffRootContext() (*sContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.handed {
		fault(nil, "Kernel Panic: Root context already transferred", nil)
		return nil, errors.New("kernel: root context already transferred")
	}
	m.handed = true
	m.root = newRootContext("kernel")
	m.appendLocked(m.root, 0)
	return m.root, nil
}

// spawn creates a child context. It enforces both halves of a spawn decision:
// the process:fork grant and the domain transition rule. The uid comes from the
// kernel's own counter, never from the caller.
func (m *contextManager) spawn(parent *sContext, dom Domain, name string) (*sContext, error) {
	if err := check(parent, OpProcessFork); err != nil {
		return nil, err
	}
	if !canSpawnInto(parent.dom, dom) {
		d := &DeniedError{
			Op: OpProcessFork, Ctx: parent,
			Reason: fmt.Sprintf("transition %s -> %s not permitted", parent.dom, dom),
		}
		fault(parent, d.Error(), map[string]any{"reason": d.Reason})
		kaudit.record(AuditEscalation, parent, "denied domain transition", map[string]any{
			"from": string(parent.dom), "to": string(dom), "reason": d.Reason,
		})
		return nil, d
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pid := m.nextPID
	m.nextPID++
	child := &sContext{pid: pid, uid: m.uidForLocked(dom), dom: dom, name: name}
	m.appendLocked(child, parent.pid)
	kaudit.record(AuditSpawn, child, "context spawned", map[string]any{
		"ppid": parent.pid, "domain": string(dom), "name": name, "uid": child.uid,
	})
	return child, nil
}

// uidForLocked assigns a uid from the domain. Caller holds m.mu.
func (m *contextManager) uidForLocked(dom Domain) UID {
	switch dom {
	case DomainKernel:
		return uidKernel
	case DomainInit:
		return uidInit
	}
	uid := m.nextUID
	m.nextUID++
	return uid
}

// appendLocked records a context. Caller holds m.mu.
//
// The parent pid is passed in explicitly rather than inferred from table order.
// Inference would race under concurrent spawns and silently attribute a module to
// the wrong parent, which is exactly the provenance error this table exists to
// prevent.
func (m *contextManager) appendLocked(ctx *sContext, ppid PID) {
	m.procs = append(m.procs, &ProcRecord{
		PID:     ctx.pid,
		UID:     ctx.uid,
		Domain:  ctx.dom,
		Name:    ctx.name,
		PPID:    ppid,
		Created: nowUTC(),
		State:   ProcRunning,
	})
}

// setArtifact records what a pid actually loaded, after validation. The module
// loader calls it with ProcRunning on success or ProcRejected on failure, so the
// table shows the real artifact and manifest digest rather than only the intent.
func (m *contextManager) setArtifact(pid PID, artifact, digest string, state ProcState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.procs {
		if r.PID == pid {
			r.Artifact = artifact
			r.ManifestDigest = digest
			r.State = state
			if state != ProcRunning {
				r.Terminated = nowUTC()
			}
			return
		}
	}
}

// terminate marks a pid's record terminated without removing it. A record already
// in a terminal state keeps it, so a rejected load is never laundered into a
// clean termination.
func (m *contextManager) terminate(pid PID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.procs {
		if r.PID == pid {
			if r.State == ProcRunning {
				r.State = ProcTerminated
				r.Terminated = nowUTC()
			}
			return
		}
	}
}

// ProcTable returns an immutable snapshot of the whole process table, oldest
// first.
func ProcTable() []ProcSnapshot {
	kscm.mu.Lock()
	defer kscm.mu.Unlock()
	out := make([]ProcSnapshot, 0, len(kscm.procs))
	for _, r := range kscm.procs {
		out = append(out, ProcSnapshot{
			PID: r.PID, UID: r.UID, Domain: r.Domain, Name: r.Name, PPID: r.PPID,
			Created: r.Created, Artifact: r.Artifact, ManifestDigest: r.ManifestDigest,
			State: r.State, Terminated: r.Terminated,
		})
	}
	return out
}

// reset clears pid/uid allocation and the process table for a fresh boot. Called
// only from resetKernel, under the boot guard. It does not touch grants, usage or
// the metadata store; each of those owns its own reset.
func (m *contextManager) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextPID = 1
	m.nextUID = firstPluginUID
	m.procs = nil
	m.root = nil
	m.handed = false
}

// booted guards the boot sequence. It is an atomic.Bool with CompareAndSwap
// rather than sync.Once because a second boot must fail loudly; sync.Once would
// silently no-op and leave the caller believing the kernel came up.
var booted atomic.Bool

// SyscallProc is the process half of the syscall surface.
type SyscallProc interface {
	// SyscallSpawn creates a child context. Requires process:fork, and the
	// target domain must be permitted by the transition rule.
	SyscallSpawn(dom Domain, name string) (SContext, error)
}

func (c *sContext) SyscallSpawn(dom Domain, name string) (SContext, error) {
	if err := c.syscall(""); err != nil {
		return nil, err
	}
	// spawn performs the policy check and the transition check itself, so that
	// both are enforced together and neither can be skipped by a future caller.
	return kscm.spawn(c, dom, name)
}
