/*
Copyright (C) 2026 xingguangcuican6666

This file is part of MeowAPI, which is licensed under the GNU Affero General
Public License v3.0.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package kernel

// ktty: the operator console device (subsystem: ktty, the analogue of /dev/console
// plus a physical-console credential).
//
// SYSCALL WIRING FOR THE INTEGRATOR.
//
// The exported functions below are the implementation; paste this block into
// kernel/context.go to expose them as syscalls.
//
// 1. Add the group to the SContext interface's group list, next to SyscallTrace -
//    the same observability family that policy.go puts OpTraceSpan and OpTTYOpen in:
//
//	SyscallTTY
//
// 2. Add the group interface and the methods:
//
//	// SyscallTTY is the operator console. Reading it needs no credential because it
//	// hands back nothing an operator could not already see; the privileged acts need
//	// one, and no method here returns it.
//	type SyscallTTY interface {
//	    // SyscallTTYOpen opens a console handle. Requires tty:open, which the init
//	    // domain holds and the plugin domain does not.
//	    SyscallTTYOpen() (FD, error)
//	    // SyscallTTYRead returns a bounded window of console history through one
//	    // handle. Requires tty:open.
//	    SyscallTTYRead(fd FD, since int) (TTYWindow, error)
//	    // SyscallTTYWrite emits one console line. Requires log:write.
//	    SyscallTTYWrite(fd FD, level Level, msg string) error
//	    // SyscallTTYLoadModule loads a module on the operator's behalf. Requires
//	    // tty:open and the console credential; module:load is re-checked inside.
//	    SyscallTTYLoadModule(fd FD, credential []byte, m Manifest) (PID, error)
//	    // SyscallTTYUnloadModule unloads a module on the operator's behalf. Requires
//	    // tty:open and the console credential; module:unload is re-checked inside.
//	    SyscallTTYUnloadModule(fd FD, credential []byte, pid PID) error
//	    // SyscallTTYProcessTable reads the process table. Requires tty:open and the
//	    // console credential.
//	    SyscallTTYProcessTable(fd FD, credential []byte) ([]ProcSnapshot, error)
//	}
//
//	func (c *sContext) SyscallTTYOpen() (FD, error) { return TTYOpen(c) }
//	func (c *sContext) SyscallTTYRead(fd FD, since int) (TTYWindow, error) {
//	    return TTYRead(c, fd, since)
//	}
//	func (c *sContext) SyscallTTYWrite(fd FD, level Level, msg string) error {
//	    return TTYWrite(c, fd, level, msg)
//	}
//	func (c *sContext) SyscallTTYLoadModule(fd FD, credential []byte, m Manifest) (PID, error) {
//	    return TTYLoadModule(c, fd, credential, m)
//	}
//	func (c *sContext) SyscallTTYUnloadModule(fd FD, credential []byte, pid PID) error {
//	    return TTYUnloadModule(c, fd, credential, pid)
//	}
//	func (c *sContext) SyscallTTYProcessTable(fd FD, credential []byte) ([]ProcSnapshot, error) {
//	    return TTYProcessTable(c, fd, credential)
//	}
//
// 3. Add resetTTYs() to resetKernel() in kernel/kernel.go, in the "Secrets, then the
//    root they derive from" block immediately BEFORE resetKeyring(). The console
//    credential is host-installed credential material, so it is wiped with the other
//    secrets and before kboot.reset() drops the root it was installed under.
//
// 4. Add dropTTYsFor(pid) to UnloadModule's teardown list in kernel/module.go, next to
//    DropPipesFor(pid). It is a defensive backstop and NOT a reachable path today:
//    tty:open is refused to the plugin domain, so no module can hold a console handle,
//    and init never goes through UnloadModule. It exists so that if the owner ever
//    widens tty:open, reclamation is already correct rather than silently leaking
//    registry entries.
//
// 5. Optional, and dump.go is the integrator's call: a "--- tty ---" section reading
//    TTYStatsSnapshot(), modelled on the secrets and receipts sections.
//
// POLICY NOTE.
//
// No new operation is added. OpTTYOpen already exists, is in AllOps, is held by
// DomainInit, is refused to DomainPlugin, and is classified unscoped, so
// TestIsScopedMatchesTheScopedSet is unaffected. TTYWrite rides OpLogWrite, which both
// init and the plugin domain hold, and reproduces SyscallLog's fault-level rule exactly
// so a console handle adds no way to emit a fault record. The privileged acts sit under
// OpTTYOpen AND the existing module operations, so policy is checked twice: a future
// tty holder without module:load is still refused, fail-closed.
//
// POLICY HOT-UPDATE IS DELIBERATELY NOT IMPLEMENTED, and the reason is not that it is
// hard. policy.go's rules table is compiled into the kernel because a policy an attacker
// can write to is not a policy, and a manifest may only narrow that ceiling. A runtime
// "apply this policy" entry point contradicts both:
//
//   - Accepting a full table reopens exactly the hole the compiled table closes. A
//     console credential is a secret, not a proof that widening the kernel's own policy
//     ceiling is safe, and a session holding one could grant itself everything and then
//     remove the tty surface it came through.
//   - Accepting only narrowing deltas adds nothing a manifest does not already do
//     better: at load time, under review, with a digest recorded in the process table.
//     Narrowing a RUNNING module's grants is worse than not narrowing at all, because
//     the handles it already holds and the connections it already opened do not roll
//     back, leaving a half-new half-old state that is harder to reason about than
//     either. To narrow, unload and load a new manifest - which is the existing
//     mechanism and needs no new entry point.
//
// The only form that would be safe is a sealed, per-boot, host-installed narrowing set
// on the kboot model, and that is redundant with manifests. Left to the owner.

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
)

// The guarantee this file provides is two-sided.
//
// On the privileged side: module load, module unload and process inspection performed
// through a console handle are gated on a credential a module cannot read. It is
// installed only by the host through the Kernel handle, never returned by any syscall,
// never written to the audit chain or the console or a dump, never rendered in an error
// message, and compared only in constant time against a copy taken under the registry
// lock. Every privileged act lands on the kaudit chain, so a console that can load a
// module is never a console that can erase the fact that it did.
//
// On the unprivileged side: a console handle is a VIEW, not a key. Reading through it
// returns copies of console history an operator can already see; writing through it goes
// through the same level rules as log:write and adds no privilege; and nothing a module
// could do with an open handle reaches the credential-gated surface, because those acts
// check the credential AND re-check module:load and module:unload independently.
//
// What this is not. It is not an interactive shell and has no command interpreter: the
// surface is open, read, write, ps, load and unload, and a command loop in the kernel
// would be business logic. It is not a policy editor, for the reasons in the policy note
// above. It is not a remote-access path - there is no network surface here at all. And it
// is not an address-space boundary: a module with a memory-corruption primitive can read
// the kernel's heap, which is true of every guarantee in this kernel and is what AGENT.md
// says about MAC generally. What ktty contains is what a module can make the kernel do,
// not what it can compute.

// TTYError reports a refused console operation. It is a distinct type so a caller can
// tell "the kernel will not" from "the kernel could not", and so a credential refusal is
// not mistaken for a policy denial - an operator must be able to see the difference
// between "this session lacks the console key" and "policy refused the operation".
type TTYError struct {
	Msg string
	Err error
}

func (e *TTYError) Error() string {
	if e.Err == nil {
		return "kernel: tty refused: " + e.Msg
	}
	return "kernel: tty refused: " + e.Msg + ": " + e.Err.Error()
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *TTYError) Unwrap() error { return e.Err }

// Console sentinels.
var (
	// ErrTTYLimit is the sentinel for every console ceiling.
	ErrTTYLimit = errors.New("kernel: tty limit reached")
	// ErrTTYBootGone means the kernel was reset while an install was in flight.
	ErrTTYBootGone = errors.New("kernel: the boot this credential was destined for is gone")

	// There is deliberately no ErrTTYNoCredential. A credential that is wrong and a
	// credential that was never installed return the same error, because a distinct
	// sentinel for "not installed" is exactly the oracle the design forbids: it would
	// tell a caller whether a credential exists before it had to guess one.
)

func ttyErr(format string, a ...any) error {
	return &TTYError{Msg: fmt.Sprintf(format, a...)}
}

func ttyLimit(err error, format string, a ...any) error {
	return &TTYError{Msg: fmt.Sprintf(format, a...), Err: err}
}

// TTYInfo describes one open console handle, for the host and for tests. No field
// carries console content: the information here is that a handle exists, who holds it,
// how much it has been used and when it was opened, all of which the fd table and the
// console already report about every other resource. Opened is a mono() reading and is
// never rendered as a human timestamp.
type TTYInfo struct {
	FD     FD     `json:"fd"`
	PID    PID    `json:"pid"`
	Label  string `json:"label,omitempty"`
	Opened int64  `json:"opened_mono"`
	Writes int64  `json:"writes"`
	Reads  int64  `json:"reads"`
	Closed bool   `json:"closed"`
}

// TTYStats are the console counters.
//
// Refused is ONE counter covering a wrong credential, a missing credential and a
// foreign-context call alike. That is deliberate: aggregate visibility for an operator
// without a per-candidate signal for an attacker. Credential holds a bool and never the
// value, and no field here or anywhere in this file carries the credential or its length.
type TTYStats struct {
	Open       int   `json:"open"`
	Credential bool  `json:"credential"`
	Issued     int64 `json:"issued"`
	Refused    int64 `json:"refused"`
	Reads      int64 `json:"reads"`
	Writes     int64 `json:"writes"`
	MaxPerPID  int   `json:"max_per_pid"`
}

// TTYWindow is one bounded read of console history.
//
// Base and Dropped exist because `since` cannot be a stable cursor. Console retention is
// bounded and drops the oldest record, so an index into history shifts whenever the
// buffer trims. A caller that treated `since` as "resume from line N" would silently skip
// or repeat lines after a trim and never know. Base is the index the first returned
// record occupied, and Dropped is the console's total eviction count, so a caller can
// detect that records were lost between two reads rather than assuming continuity it does
// not have.
type TTYWindow struct {
	// Base is the index into the console's history at the time of this read that the
	// first record in Records occupied.
	Base int `json:"base"`
	// Records are copies of the console lines, oldest first.
	Records []Record `json:"records"`
	// Dropped is how many console records have been evicted in total.
	Dropped int64 `json:"dropped"`
}

// Console ceilings. They are package constants rather than BootLimits fields because
// adding a field to the sealed trust root is a change owned by kboot, and a subsystem must
// not widen the struct it reads.
const (
	// maxTTYsPerModule is one, and the number is the argument. A tty models ONE
	// physical console, which is also why there is one credential rather than one per
	// handle: multiple consoles would multiply the brute-force surface for no
	// capability anybody asked for. A second handle in the same pid is a defect, not a
	// feature. Widening this is a host decision about how many operator sessions one
	// process should support, and it is not a decision this file should make quietly.
	maxTTYsPerModule = 1
	// maxTTYLineBytes bounds one console line written through a handle.
	maxTTYLineBytes = 4096
	// maxTTYReadLines bounds one read, so a caller cannot copy the whole console
	// buffer in a single call.
	maxTTYReadLines = 256
	// maxTTYCredentialBytes bounds the credential the host may install. It is a
	// ceiling on a value this kernel never generates, so it exists to stop an
	// accidental multi-megabyte environment variable from being copied and wiped on
	// every privileged call.
	maxTTYCredentialBytes = 4096
	// minTTYCredentialBytes is the floor. A credential shorter than this is not a
	// credential, and accepting one would make the gate decorative while looking
	// like a control.
	minTTYCredentialBytes = 16
)

// ttyHandle is the fd-table resource for one console handle.
type ttyHandle struct {
	closedFlag
	pid        PID
	fd         FD
	label      string
	openedMono int64

	// Nothing blocks on a console handle: a read is a non-blocking snapshot of
	// history and a write is a single emit. So there is no cond and Close has no
	// broadcast to make, which puts this resource in receiptRef's family rather than
	// lockHandle's.
	mu     sync.Mutex
	reads  int64
	writes int64
}

// Kind names the resource for the fd table and the console dump. It is a constant,
// which install() requires because it caches the value at install time.
func (h *ttyHandle) Kind() string { return "tty" }

// Close releases the handle. It tolerates being called twice, which reclamation
// depends on: a handle closed explicitly and then reached again by reclaimFDs during
// unload must report errClosed rather than corrupting the registry.
func (h *ttyHandle) Close() error {
	if !h.mark() {
		return errClosed
	}
	kttys.release(h)
	return nil
}

// ttyRegistry holds the console credential and the open-handle table. Its mutex is
// ktty's one subsystem lock; the per-handle mutex above guards only that handle's
// counters.
type ttyRegistry struct {
	mu sync.Mutex

	// credential is nil until the host installs one. It is a []byte rather than a
	// string because wipe() mutates in place and a Go string is immutable: storing a
	// credential as a string would make the wipe-on-every-path guarantee
	// unimplementable, leaving the operator's console key on the heap for the life of
	// the process. That is the exact hazard keyring.go documents and defends against.
	credential []byte
	// generation is bumped by resetTTYs. InstallConsoleCredential captures it before
	// its shutdown check and re-reads it under the lock, which is what stops a host
	// call that was already in flight when Shutdown ran from installing a credential
	// into the next boot. keyring tolerates the analogous race because a late secret
	// install is a harmless host fact; a surviving console credential is a
	// trust-relevant one, so this one is closed rather than tolerated.
	generation uint64

	open     map[PID]int
	byHandle map[*ttyHandle]struct{}

	issued  int64
	refused int64
	reads   int64
	writes  int64
}

var kttys = &ttyRegistry{open: map[PID]int{}, byHandle: map[*ttyHandle]struct{}{}}

// InstallConsoleCredential installs or rotates the physical console credential.
//
// It is a method on the handle and not a free function, which is the structural reason
// the credential is unforgeable to a module: Boot refuses a second call, every field of
// Kernel is unexported, and a module never receives the handle. A module that cannot
// obtain the value cannot present it, and there is no oracle to recover it from - see
// verifyConsoleCredential.
//
// Ownership of the bytes transfers. The caller's slice is wiped on every return path
// including refusals, so a host that read the credential from an environment variable or
// a file does not leave it recoverable in its own heap after the call. That is
// SecretSpec.Value's contract and the reason the parameter is []byte.
//
// Rotation replaces the credential with a NEW buffer and wipes the old one only after the
// swap, under the same lock ordering keyring uses for secret rotation. Wiping in place
// while a comparison could be reading the buffer would leave a window in which a
// concurrently arriving all-zero candidate matched a fully wiped credential.
func (k *Kernel) InstallConsoleCredential(credential []byte) error {
	generation := ttyGeneration()

	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		wipe(credential)
		return errors.New("kernel: already shut down")
	}
	return installConsoleCredential(k.initCtx, generation, credential)
}

func ttyGeneration() uint64 {
	kttys.mu.Lock()
	defer kttys.mu.Unlock()
	return kttys.generation
}

func installConsoleCredential(ctx *sContext, generation uint64, credential []byte) error {
	if len(credential) == 0 {
		wipe(credential)
		return ttyErr("a console credential must not be empty")
	}
	if len(credential) < minTTYCredentialBytes {
		wipe(credential)
		return ttyErr("a console credential must be at least %d bytes", minTTYCredentialBytes)
	}
	if len(credential) > maxTTYCredentialBytes {
		wipe(credential)
		return ttyLimit(ErrTTYLimit,
			"a console credential of %d bytes exceeds the ceiling %d", len(credential), maxTTYCredentialBytes)
	}

	kttys.mu.Lock()
	if kttys.generation != generation {
		kttys.mu.Unlock()
		wipe(credential)
		return &TTYError{
			Msg: "the kernel was reset while this credential was being installed",
			Err: ErrTTYBootGone,
		}
	}

	rotated := kttys.credential != nil
	// The stored value is a copy, so the caller's slice can be wiped immediately and
	// independently of what happens to the registry afterwards.
	stored := make([]byte, len(credential))
	copy(stored, credential)
	old := kttys.credential
	kttys.credential = stored
	kttys.mu.Unlock()

	// Both wipes happen outside the lock and after the swap, so no in-flight
	// comparison can be holding either buffer: a comparison that started before the
	// swap copied the old value under the lock and is done with the registry by now,
	// and one that starts after sees the new value.
	wipe(credential)
	if old != nil {
		wipe(old)
	}

	// The value and its LENGTH are never recorded. A length narrows a brute-force
	// search and the chain is readable by anything holding audit:read, which is the
	// same reason keyring records neither a secret nor its size.
	kaudit.record(AuditPolicy, ctx, "console credential installed", map[string]any{"rotate": rotated})
	return nil
}

// verifyConsoleCredential is the one place the credential is compared.
//
// Three properties make the credential unforgeable, and they are stated here because the
// guarantee is only as strong as the weakest one:
//
//   - Wrong, missing and uninstalled all return the SAME error. A caller cannot learn
//     whether a credential exists, so the call is not an oracle.
//   - The comparison is constant-time. An early-returning comparison is a brute-force
//     accelerator, and this function is callable in a loop by anything holding tty:open.
//   - No path returns, logs, audits or faults the value or its length.
//
// The stored credential is COPIED under the lock and the copy is compared outside it,
// following keyring's applySecret. Taking a slice reference instead would race rotation's
// in-place wipe and could match an all-zero candidate against a buffer being zeroed.
//
// The credential is bound to (pid, live handle) rather than to an fd number, because fd
// numbers repeat across pids and the fd table already guarantees the rest.
func verifyConsoleCredential(ctx *sContext, fd FD, credential []byte) error {
	// One refusal path, used by all three cases. The message, the fault and the audit
	// entry are identical whether the credential is wrong, absent or uninstalled,
	// because a caller that could tell those apart has an oracle for whether a
	// credential exists at all.
	refuse := func() error {
		wipe(credential)
		kttys.mu.Lock()
		kttys.refused++
		kttys.mu.Unlock()
		fault(ctx, "console credential refused", map[string]any{"pid": ctx.pid, "fd": fd})
		// An attempt to wield the console without the physical credential is an
		// attempt to act beyond what this session holds, which is precisely what
		// AuditEscalation is for. It is not a DeniedError: policy did not refuse the
		// operation, the session lacked the key, and conflating the two would make a
		// lost credential look like a policy bug.
		kaudit.record(AuditEscalation, ctx, "console credential refused", map[string]any{
			"pid": ctx.pid, "fd": fd,
		})
		return ttyErr("this session does not hold the physical console credential")
	}

	kttys.mu.Lock()
	if kttys.credential == nil {
		kttys.mu.Unlock()
		return refuse()
	}
	working := make([]byte, len(kttys.credential))
	copy(working, kttys.credential)
	kttys.mu.Unlock()

	match := constantTimeEqualBytes(working, credential)
	wipe(working)

	if !match {
		return refuse()
	}
	wipe(credential)
	return nil
}

// TTYOpen opens a console handle. Requires tty:open, which the init domain holds and the
// plugin domain does not.
func TTYOpen(ctx SContext) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	if err := c.syscall(OpTTYOpen); err != nil {
		return noFD, err
	}

	kttys.mu.Lock()
	if kttys.open[c.pid] >= maxTTYsPerModule {
		kttys.mu.Unlock()
		// The attributed fault is emitted here rather than left to install(), whose
		// own ceiling fault names no context. lock.go and pipe.go both do this for the
		// same reason: a refusal an operator cannot attribute to a pid is a refusal
		// nobody can act on.
		fault(c, "tty ceiling reached", map[string]any{
			"pid": c.pid, "max_tty_per_module": maxTTYsPerModule,
		})
		return noFD, ttyLimit(ErrTTYLimit,
			"pid %d holds the maximum of %d console handles", c.pid, maxTTYsPerModule)
	}
	kttys.mu.Unlock()

	h := &ttyHandle{pid: c.pid, label: "console", openedMono: mono()}
	fd, err := install(c.pid, h, h.label)
	if err != nil {
		kttys.mu.Lock()
		delete(kttys.byHandle, h)
		kttys.mu.Unlock()
		fault(c, "cannot open a console handle", map[string]any{
			"pid": c.pid, "error": err.Error(),
		})
		return noFD, ttyLimit(ErrTTYLimit, "cannot open a console handle: %v", err)
	}

	h.fd = fd
	kttys.mu.Lock()
	kttys.open[c.pid]++
	kttys.byHandle[h] = struct{}{}
	kttys.mu.Unlock()
	return fd, nil
}

// TTYRead returns a bounded window of console history through one handle. Requires
// tty:open.
//
// It names an operation rather than passing "", and the reason is worth stating because
// the obvious reading is the wrong one. Per-pid handle resolution gates reaching this
// function, but the data it returns is the GLOBAL console buffer: every pid's log lines,
// every fault, every avc denial record. A gate on reaching a function is not a scope on
// the state it returns, so this is not self-scoped in the sense the nine unprivileged
// syscalls are, and it does not take the tenth slot in that list.
func TTYRead(ctx SContext, fd FD, since int) (TTYWindow, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return TTYWindow{}, errForeignContext
	}
	if err := c.syscall(OpTTYOpen); err != nil {
		return TTYWindow{}, err
	}

	h, err := ttyHandleFor(c, fd)
	if err != nil {
		return TTYWindow{}, err
	}

	history := kconsole.History()
	if since < 0 {
		since = 0
	}
	if since > len(history) {
		// A `since` past the end means the caller's cursor referred to records that
		// have since been evicted. Returning an empty window with the real base is
		// what makes that detectable; silently clamping would report continuity the
		// caller does not have.
		since = len(history)
	}
	end := since + maxTTYReadLines
	if end > len(history) {
		end = len(history)
	}
	window := TTYWindow{Base: since, Records: history[since:end], Dropped: kconsole.Dropped()}

	h.mu.Lock()
	h.reads++
	h.mu.Unlock()

	kttys.mu.Lock()
	kttys.reads++
	kttys.mu.Unlock()
	return window, nil
}

// TTYWrite emits one console line through a handle. Requires log:write.
//
// Writing to the console IS log:write, so tty adds no write privilege, and the fault-level
// rule is reproduced exactly as SyscallLog states it. A console handle is not a way around
// the reservation of fault records to the kernel: letting a module emit them would let it
// forge a record of its own good behavior or bury a real denial in noise.
func TTYWrite(ctx SContext, fd FD, level Level, msg string) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpLogWrite); err != nil {
		return err
	}
	if err := knownLevel(level); err != nil {
		return err
	}
	if level == LogFault && c.dom != DomainKernel && c.dom != DomainInit {
		fault(c, "attempt to emit fault record from unprivileged domain", map[string]any{"msg": msg})
		kaudit.record(AuditEscalation, c, "denied fault-record emission", map[string]any{"msg": msg})
		return &DeniedError{Op: OpLogWrite, Ctx: c, Reason: "fault level reserved for the kernel"}
	}
	if len(msg) > maxTTYLineBytes {
		return ttyLimit(ErrTTYLimit,
			"a console line of %d bytes exceeds the ceiling %d", len(msg), maxTTYLineBytes)
	}
	// Line breaks are refused rather than sanitized. A message carrying "\n" would
	// render as two console lines and the second one would look like a kernel record
	// that no kernel call produced, which is the same forgery keyring's validAlias and
	// kpeer's identifier filters exist to prevent. Refusing is honest in a way that
	// quietly rewriting the operator's text is not.
	if bytes.ContainsAny([]byte(msg), "\n\r") {
		return ttyErr("a console line must not contain a line break")
	}

	h, err := ttyHandleFor(c, fd)
	if err != nil {
		return err
	}

	kconsole.Emit(level, c.pid, c.dom, msg, nil)

	h.mu.Lock()
	h.writes++
	h.mu.Unlock()

	kttys.mu.Lock()
	kttys.writes++
	kttys.issued++
	kttys.mu.Unlock()
	return nil
}

// TTYLoadModule loads a module on the operator's behalf. Requires tty:open, the console
// credential, and - re-checked inside LoadModule - module:load.
//
// The delegation is load-bearing rather than convenient. LoadModule runs its own
// check(c, OpModuleLoad), so policy is enforced twice and a hypothetical future tty
// holder without module:load is still refused. The credential is not a substitute for the
// grant; it is an additional fact about where the command came from.
//
// The audit record is written AFTER the load returns and carries the resulting pid. It
// cannot be written before, because a record saying "console module load" written before
// the load would state an intention as an accomplished fact, and on a failed load the
// chain would read as though the module loaded and was then rejected. module.go already
// writes AuditLoad on success and AuditReject on failure; this record adds the provenance
// the loader cannot know.
func TTYLoadModule(ctx SContext, fd FD, credential []byte, m Manifest) (PID, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		wipe(credential)
		return 0, errForeignContext
	}
	if err := c.syscall(OpTTYOpen); err != nil {
		wipe(credential)
		return 0, err
	}
	if _, err := ttyHandleFor(c, fd); err != nil {
		wipe(credential)
		return 0, err
	}
	if err := verifyConsoleCredential(c, fd, credential); err != nil {
		return 0, err
	}

	pid, err := LoadModule(c, m)
	if err != nil {
		return 0, err
	}
	kaudit.record(AuditPolicy, c, "console module load", map[string]any{
		"module": m.Name, "pid": pid,
	})
	return pid, nil
}

// TTYUnloadModule unloads a module on the operator's behalf. Requires tty:open, the
// console credential, and module:unload re-checked inside UnloadModule.
func TTYUnloadModule(ctx SContext, fd FD, credential []byte, pid PID) error {
	c, ok := ctx.(*sContext)
	if !ok {
		wipe(credential)
		return errForeignContext
	}
	if err := c.syscall(OpTTYOpen); err != nil {
		wipe(credential)
		return err
	}
	if _, err := ttyHandleFor(c, fd); err != nil {
		wipe(credential)
		return err
	}
	if err := verifyConsoleCredential(c, fd, credential); err != nil {
		return err
	}

	if err := UnloadModule(c, pid); err != nil {
		return err
	}
	kaudit.record(AuditPolicy, c, "console module unload", map[string]any{"pid": pid})
	return nil
}

// TTYProcessTable reads the process table. Requires tty:open and the console credential.
//
// It returns ProcTable() verbatim rather than a parallel registry. Two tables describing
// the same processes drift, and a console that reports a process table which is not the
// kernel's is worse than no console at all.
//
// The read is gated on the credential and audited even though ProcTable itself grants no
// privilege, because a process inspection performed through a physical console is an act
// an investigator should be able to see, and the same reasoning is why Dump is a host
// surface rather than a syscall.
func TTYProcessTable(ctx SContext, fd FD, credential []byte) ([]ProcSnapshot, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		wipe(credential)
		return nil, errForeignContext
	}
	if err := c.syscall(OpTTYOpen); err != nil {
		wipe(credential)
		return nil, err
	}
	if _, err := ttyHandleFor(c, fd); err != nil {
		wipe(credential)
		return nil, err
	}
	if err := verifyConsoleCredential(c, fd, credential); err != nil {
		return nil, err
	}

	table := ProcTable()
	kaudit.record(AuditPolicy, c, "console process table read", map[string]any{
		"pid": c.pid, "processes": len(table),
	})
	return table, nil
}

// ttyHandleFor resolves one console handle inside the calling pid, kind-checked.
//
// The kind check is what makes a handle unforgeable across subsystems: passing a pipe or a
// lock where a console handle is expected fails with "not a tty" rather than being
// reinterpreted. The concrete assertion is used rather than the e.kind comparison because
// the handle is needed, copying receipt.go's ReceiptHandle, and done() is checked after
// the assertion because lookup returns a live entry and a concurrent close can win the
// race.
func ttyHandleFor(c *sContext, fd FD) (*ttyHandle, error) {
	entry, err := lookup(c.pid, fd)
	if err != nil {
		return nil, err
	}
	h, ok := entry.res.(*ttyHandle)
	if !ok {
		return nil, fmt.Errorf("kernel: fd %d is a %s, not a tty", fd, entry.kind)
	}
	if h.done() {
		return nil, errClosed
	}
	return h, nil
}

// TTYList returns the console handles held by one pid, for the host and for tests.
func TTYList(pid PID) []TTYInfo {
	kttys.mu.Lock()
	handles := make([]*ttyHandle, 0, len(kttys.byHandle))
	for h := range kttys.byHandle {
		if h.pid == pid {
			handles = append(handles, h)
		}
	}
	kttys.mu.Unlock()

	out := make([]TTYInfo, 0, len(handles))
	for _, h := range handles {
		h.mu.Lock()
		out = append(out, TTYInfo{
			FD: h.fd, PID: h.pid, Label: h.label, Opened: h.openedMono,
			Writes: h.writes, Reads: h.reads, Closed: h.done(),
		})
		h.mu.Unlock()
	}
	return out
}

// TTYStatsSnapshot returns the console counters. It takes no context and performs no
// check, which puts it in the family of ProcTable, RouteTable and SecretInventory:
// read-only observability that grants no privilege. It reports whether a credential is
// installed and never the credential, its length or any part of it.
func TTYStatsSnapshot() TTYStats {
	kttys.mu.Lock()
	defer kttys.mu.Unlock()

	open := 0
	for _, n := range kttys.open {
		open += n
	}
	return TTYStats{
		Open: open, Credential: kttys.credential != nil, Issued: kttys.issued,
		Refused: kttys.refused, Reads: kttys.reads, Writes: kttys.writes,
		MaxPerPID: maxTTYsPerModule,
	}
}

// release drops one handle's registry entry. It tolerates a handle that was never
// registered, because reclamation and an explicit close can both reach a resource whose
// entry is already gone.
func (r *ttyRegistry) release(h *ttyHandle) {
	r.mu.Lock()
	delete(r.byHandle, h)
	if n, ok := r.open[h.pid]; ok {
		if n <= 1 {
			delete(r.open, h.pid)
		} else {
			r.open[h.pid] = n - 1
		}
	}
	r.mu.Unlock()
}

// dropTTYsFor releases every console handle a pid holds. It is the backstop for registry
// entries whose resource was never installed, following the DropPipesFor pattern, and it
// is not a reachable path today: tty:open is refused to the plugin domain so no module can
// hold a handle, and init never goes through UnloadModule. It exists so that widening
// tty:open later does not silently leak registry entries.
//
// Handles are collected under the lock and released outside it, because release
// re-enters the registry.
func dropTTYsFor(pid PID) {
	kttys.mu.Lock()
	var handles []*ttyHandle
	for h := range kttys.byHandle {
		if h.pid == pid {
			handles = append(handles, h)
		}
	}
	kttys.mu.Unlock()

	for _, h := range handles {
		_ = h.Close()
	}
}

// resetTTYs drops the console credential and the open-handle table. Called only from
// resetKernel, immediately before resetKeyring.
//
// The credential is WIPED rather than merely dropped, so a restarted kernel can never
// coexist with the previous operator session's console key - not even for the instant
// between the two resets. That is resetKeyring's reasoning applied to the same class of
// material.
//
// It does not close live handles. Unload reclamation already did, and a non-empty
// registry after a full unload cycle is evidence of a reclamation bug rather than
// something a reset should paper over.
func resetTTYs() {
	kttys.mu.Lock()
	if kttys.credential != nil {
		wipe(kttys.credential)
	}
	kttys.credential = nil
	// Bumped under the same lock installConsoleCredential reads it under, which is what
	// makes the in-flight-install race closable rather than merely unlikely.
	kttys.generation++
	kttys.open = map[PID]int{}
	kttys.byHandle = map[*ttyHandle]struct{}{}
	kttys.issued, kttys.refused, kttys.reads, kttys.writes = 0, 0, 0, 0
	kttys.mu.Unlock()
}

// knownLevel refuses a level outside the closed set. The set already exists in console.go
// and is enforced on the Emit path; checking it here means a console write carrying an
// invented level is refused at the boundary rather than rendered as an unknown string an
// operator's log filter does not match.
func knownLevel(level Level) error {
	switch level {
	case LogDebug, LogInfo, LogWarn, LogError, LogFault:
		return nil
	}
	return ttyErr("unknown console level %q", level)
}

// SyscallTTY is the operator console half of the syscall surface.
//
// Reading through it needs no credential because it hands back nothing an operator could
// not already see on the console. The privileged acts need one, and no method here returns
// it: the credential crosses the boundary inward only, is wiped on every path, and the
// only observable outcome of presenting it is a permitted action or a refusal that does not
// distinguish wrong from missing.
type SyscallTTY interface {
	// SyscallTTYOpen opens a console handle. Requires tty:open.
	SyscallTTYOpen() (FD, error)
	// SyscallTTYRead returns a bounded window of console history through one handle.
	// Requires tty:open.
	SyscallTTYRead(fd FD, since int) (TTYWindow, error)
	// SyscallTTYWrite emits one console line. Requires log:write.
	SyscallTTYWrite(fd FD, level Level, msg string) error
	// SyscallTTYLoadModule loads a module on the operator's behalf. Requires
	// tty:open and the console credential.
	SyscallTTYLoadModule(fd FD, credential []byte, m Manifest) (PID, error)
	// SyscallTTYUnloadModule unloads a module on the operator's behalf. Requires
	// tty:open and the console credential.
	SyscallTTYUnloadModule(fd FD, credential []byte, pid PID) error
	// SyscallTTYProcessTable reads the process table. Requires tty:open and the
	// console credential.
	SyscallTTYProcessTable(fd FD, credential []byte) ([]ProcSnapshot, error)
}

func (c *sContext) SyscallTTYOpen() (FD, error) { return TTYOpen(c) }
func (c *sContext) SyscallTTYRead(fd FD, since int) (TTYWindow, error) {
	return TTYRead(c, fd, since)
}
func (c *sContext) SyscallTTYWrite(fd FD, level Level, msg string) error {
	return TTYWrite(c, fd, level, msg)
}
func (c *sContext) SyscallTTYLoadModule(fd FD, credential []byte, m Manifest) (PID, error) {
	return TTYLoadModule(c, fd, credential, m)
}
func (c *sContext) SyscallTTYUnloadModule(fd FD, credential []byte, pid PID) error {
	return TTYUnloadModule(c, fd, credential, pid)
}
func (c *sContext) SyscallTTYProcessTable(fd FD, credential []byte) ([]ProcSnapshot, error) {
	return TTYProcessTable(c, fd, credential)
}
