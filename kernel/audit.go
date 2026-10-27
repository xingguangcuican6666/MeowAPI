package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// AuditKind classifies an audit event. The set is closed: an unknown kind is
// rejected rather than recorded as a generic event, because a classification the
// kernel cannot name is one it cannot later query.
type AuditKind string

const (
	// AuditBoot and AuditShutdown bracket one kernel lifetime.
	AuditBoot     AuditKind = "boot"
	AuditShutdown AuditKind = "shutdown"
	// AuditSpawn and AuditExit are process birth and death.
	AuditSpawn AuditKind = "spawn"
	AuditExit  AuditKind = "exit"
	// AuditDenial is an avc denial. Every denial in the kernel lands here.
	AuditDenial AuditKind = "denial"
	// AuditEscalation is any attempt to widen privilege: spawning into a more
	// privileged domain, emitting a fault record, requesting a non-grantable
	// operation.
	AuditEscalation AuditKind = "escalation"
	// AuditLoad, AuditUnload and AuditReject are module lifecycle events.
	AuditLoad   AuditKind = "load"
	AuditUnload AuditKind = "unload"
	AuditReject AuditKind = "reject"
	// AuditRequest brackets one client request, linking every event that carries
	// its trace id.
	AuditRequest AuditKind = "request"
	// AuditUsage and AuditSettle are accounting events.
	AuditUsage  AuditKind = "usage"
	AuditSettle AuditKind = "settle"
	// AuditSecret records the use of a credential. Never its value.
	AuditSecret AuditKind = "secret"
	// AuditPanic records an unrecovered fault in kernel or module code.
	AuditPanic AuditKind = "panic"
	// AuditPolicy records a policy-relevant kernel action such as publishing
	// configuration or sealing the trust root.
	AuditPolicy AuditKind = "policy"
	// AuditPeer and AuditSlash record mesh events.
	AuditPeer  AuditKind = "peer"
	AuditSlash AuditKind = "slash"
)

// AuditEntry is one link in the audit chain.
//
// The chain is the tamper-evidence mechanism. Each entry carries Prev, the hash
// of the entry before it, and Hash, the hash of itself including Prev. Rewriting
// or deleting any entry invalidates every hash after it, so an edit is detectable
// rather than invisible. This is what makes the record evidence instead of a log:
// a log can be edited, a chain cannot be edited without being noticed.
type AuditEntry struct {
	Seq    int64          `json:"seq"`
	Time   int64          `json:"time"`
	Kind   AuditKind      `json:"kind"`
	PID    PID            `json:"pid"`
	Domain Domain         `json:"domain,omitempty"`
	Msg    string         `json:"msg"`
	Trace  string         `json:"trace,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
	Prev   string         `json:"prev"`
	Hash   string         `json:"hash"`
}

// auditLog is the kernel black box.
//
// It is bounded in memory and spills to a sealed file, so a long-running kernel
// neither grows without limit nor loses the record on restart. The memory window
// is what a live query reads; the file is what an investigation reconstructs from.
type auditLog struct {
	mu       sync.Mutex
	entries  []AuditEntry
	nextSeq  int64
	lastHash string
	truncate int64
	sink     AuditSink
	genesis  bool
}

// AuditSink receives sealed entries. Implementations must not retain a reference
// to the entry's Fields map; the kernel does not copy it.
type AuditSink interface {
	WriteAudit(e AuditEntry) error
}

// AuditSinkFunc adapts a function to AuditSink.
type AuditSinkFunc func(e AuditEntry) error

func (f AuditSinkFunc) WriteAudit(e AuditEntry) error { return f(e) }

// auditWindow is how many entries stay queryable in memory.
const auditWindow = 8192

var kaudit = &auditLog{lastHash: "0"}

// genesis is the hash of an empty chain. A verifier that sees this as Prev knows
// it is reading the first entry of a boot.
const auditGenesis = "0"

// record appends one entry. It is called by the kernel, never by a module: the
// module-reachable syscall only permits reading and appending to a request's own
// trace.
func (a *auditLog) record(kind AuditKind, ctx *sContext, msg string, fields map[string]any) AuditEntry {
	return a.append(kind, ctx, msg, "", fields)
}

func (a *auditLog) append(kind AuditKind, ctx *sContext, msg, trace string, fields map[string]any) AuditEntry {
	a.mu.Lock()

	e := AuditEntry{
		Seq:    a.nextSeq,
		Time:   mono(),
		Kind:   kind,
		Msg:    msg,
		Trace:  trace,
		Fields: fields,
		Prev:   a.lastHash,
	}
	a.nextSeq++
	if ctx != nil {
		e.PID = ctx.pid
		e.Domain = ctx.dom
	}

	e.Hash = hashEntry(e)
	a.lastHash = e.Hash

	a.entries = append(a.entries, e)
	if over := len(a.entries) - auditWindow; over > 0 {
		a.truncate += int64(over)
		a.entries = a.entries[over:]
	}
	sink := a.sink
	a.mu.Unlock()

	// Sinking outside the lock: a slow disk must not block the kernel's own
	// audit path, and an audit record is written before the event completes, so
	// losing a sink write is visible as a gap rather than silent.
	if sink != nil {
		if err := sink.WriteAudit(e); err != nil {
			fault(ctx, "audit sink write failed", map[string]any{"seq": e.Seq, "error": err.Error()})
		}
	}
	return e
}

// hashEntry is the chain function. It hashes a canonical JSON encoding, so the
// hash does not depend on map iteration order.
func hashEntry(e AuditEntry) string {
	type canonical struct {
		Seq    int64     `json:"seq"`
		Time   int64     `json:"time"`
		Kind   AuditKind `json:"kind"`
		PID    PID       `json:"pid"`
		Domain Domain    `json:"domain"`
		Msg    string    `json:"msg"`
		Trace  string    `json:"trace"`
		Prev   string    `json:"prev"`
	}
	c := canonical{e.Seq, e.Time, e.Kind, e.PID, e.Domain, e.Msg, e.Trace, e.Prev}

	h := sha256.New()
	// Fields are hashed separately so an unencodable value cannot silently
	// change the chain. Encoding failure is itself part of the hash input.
	if enc, err := json.Marshal(c); err == nil {
		h.Write(enc)
	} else {
		h.Write([]byte("unencodable-header:" + err.Error()))
	}
	if e.Fields != nil {
		if enc, err := json.Marshal(e.Fields); err == nil {
			h.Write(enc)
		} else {
			h.Write([]byte("unencodable-fields"))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyEntry recomputes one entry's hash. Exported so an external auditor can
// check a chain it read from the sink without trusting the kernel's own verdict.
func VerifyEntry(e AuditEntry) bool { return hashEntry(e) == e.Hash }

// VerifyChain checks a sequence of entries for internal consistency: hashes
// correct, Prev links matching, sequence numbers contiguous. It reports the index
// of the first broken link, or -1 when the chain is intact.
//
// The first entry's Prev is checked against expectPrev, which lets a verifier
// splice a chunk onto a chain it already validated. Passing auditGenesis checks
// from the beginning of a boot.
func VerifyChain(entries []AuditEntry, expectPrev string) int {
	prev := expectPrev
	for i, e := range entries {
		if e.Prev != prev {
			return i
		}
		if !VerifyEntry(e) {
			return i
		}
		if i > 0 && e.Seq != entries[i-1].Seq+1 {
			return i
		}
		prev = e.Hash
	}
	return -1
}

// SetSink installs the audit sink. It is reachable only from the bootloader, not
// from a module, so a module cannot redirect the audit trail to a sink it
// controls. A nil sink disables spilling and keeps memory-only.
func (a *auditLog) setSink(s AuditSink) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sink = s
}

// Head returns the most recent entry's hash, or the genesis value for an empty
// chain. This is what a verifier anchors on.
func (a *auditLog) head() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastHash
}

// AuditHead returns the current chain head. Exported for the console dump and for
// an operator checkpointing the trail.
func AuditHead() string { return kaudit.head() }

// AuditQuery returns entries matching a filter, oldest first. It reads a copy, so
// a caller cannot mutate the chain through the result.
func AuditQuery(f AuditFilter) []AuditEntry {
	kaudit.mu.Lock()
	defer kaudit.mu.Unlock()

	var out []AuditEntry
	for _, e := range kaudit.entries {
		if f.Kind != "" && e.Kind != f.Kind {
			continue
		}
		if f.PID != 0 && e.PID != f.PID {
			continue
		}
		if f.Trace != "" && e.Trace != f.Trace {
			continue
		}
		if f.Since > 0 && e.Seq < f.Since {
			continue
		}
		cp := e
		if e.Fields != nil {
			cp.Fields = copyFields(e.Fields)
		}
		out = append(out, cp)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

// AuditFilter selects entries. Zero values mean "no constraint on this field".
type AuditFilter struct {
	Kind  AuditKind
	PID   PID
	Trace string
	Since int64
	Limit int
}

func copyFields(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// AuditLen reports how many entries are queryable in memory and how many have
// been evicted to the sink.
func AuditLen() (retained int, evicted int64) {
	kaudit.mu.Lock()
	defer kaudit.mu.Unlock()
	return len(kaudit.entries), kaudit.truncate
}

func (a *auditLog) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = nil
	a.nextSeq = 0
	a.lastHash = auditGenesis
	a.truncate = 0
	a.genesis = false
}

// ErrAuditChainBroken is returned when a chain fails verification.
var ErrAuditChainBroken = errors.New("kernel: audit chain verification failed")

// AuditCheckpoint writes a chain-head marker. An operator takes one before a
// deployment so that a later investigation can prove the trail was intact up to
// that point, and only the tail after it is in question.
func AuditCheckpoint(ctx *sContext, label string) (string, error) {
	if err := check(ctx, OpAuditAppend); err != nil {
		return "", err
	}
	e := kaudit.record(AuditPolicy, ctx, "audit checkpoint: "+label, map[string]any{
		"prev_head": kaudit.head(),
	})
	return e.Hash, nil
}

// SyscallAuditRead is the module-reachable audit read. It requires audit:read and
// returns copies. A module cannot read the chain unless its manifest declares it,
// and it can never write to it.
func (c *sContext) SyscallAuditRead(f AuditFilter) ([]AuditEntry, error) {
	if err := c.alive(); err != nil {
		return nil, err
	}
	if err := check(c, OpAuditRead); err != nil {
		return nil, err
	}
	return AuditQuery(f), nil
}

// SyscallAuditAppend lets a module attach a note to an existing request trace. It
// requires audit:append, which the plugin domain does not hold by default: the
// ordinary module path is log:write. Granting audit:append to a module is a
// deliberate decision that the module's notes become evidence.
//
// The entry is attributed to the calling pid and cannot be attributed to anyone
// else, so a module can annotate its own behavior and cannot fabricate a record
// for another module.
func (c *sContext) SyscallAuditAppend(kind AuditKind, trace, msg string, fields map[string]any) (AuditEntry, error) {
	if err := c.alive(); err != nil {
		return AuditEntry{}, err
	}
	if err := check(c, OpAuditAppend); err != nil {
		return AuditEntry{}, err
	}
	if !validAuditKind(kind) {
		return AuditEntry{}, fmt.Errorf("kernel: unknown audit kind %q", kind)
	}
	// A module may not append the kinds that describe kernel decisions. Those
	// would let it record its own authorization as fact.
	switch kind {
	case AuditBoot, AuditShutdown, AuditDenial, AuditEscalation,
		AuditReject, AuditPolicy, AuditPanic:
		fault(c, "module attempted to append a kernel-only audit kind",
			map[string]any{"kind": string(kind)})
		return AuditEntry{}, &DeniedError{
			Op: OpAuditAppend, Ctx: c,
			Reason: fmt.Sprintf("audit kind %q is reserved to the kernel", kind),
		}
	}
	return kaudit.append(kind, c, msg, trace, fields), nil
}

func validAuditKind(k AuditKind) bool {
	switch k {
	case AuditBoot, AuditShutdown, AuditSpawn, AuditExit, AuditDenial,
		AuditEscalation, AuditLoad, AuditUnload, AuditReject, AuditRequest,
		AuditUsage, AuditSettle, AuditSecret, AuditPanic, AuditPolicy,
		AuditPeer, AuditSlash:
		return true
	}
	return false
}
