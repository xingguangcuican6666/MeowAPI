/*
Copyright (C) 2023-2026 xingguangcuican6666

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

// ksignal: control signals to a pid. The analogue of POSIX signal delivery - a
// small closed set of kinds, asynchronous delivery, a bounded pending queue, a
// handler the process installs, and a default action for the ones it does not.
//
// WHY THIS EXISTS
//
// Unloading a module is only safe if the module can be told to stop. Without a
// signal path the kernel has two options and both are bad: wait for module code to
// notice on its own, which it may never do, or abandon it with work still in
// flight, which leaves a goroutine writing to a provider, a half-sent stream and a
// client that will never get an answer. ksignal gives the kernel the middle path:
// announce the intent, let the module wind down, and terminate it if it does not.
//
// The kinds map onto the four things an operator actually needs to say:
//
//	reload - configuration changed, re-read it (SIGHUP)
//	drain  - stop accepting new work and finish what is in flight (SIGTERM)
//	kill   - stop now (SIGKILL)
//	abort  - the client on the other end of this work went away; stop the stream
//
// WHAT IS ENFORCED, STATED PLAINLY
//
// A signal is a request, not a stop. The kernel can deliver it, can refuse new work
// from a drained or condemned module, can cancel the supervised runs the kernel
// itself started, can reclaim every handle the module holds and can unload it. It
// cannot interrupt a goroutine the module started with the standard library, because
// Go gives no kernel-side code a way to preempt one. A module that ignores drain
// therefore does not survive it: the default action for an unhandled drain is
// termination, which is what makes unload safe rather than hopeful.
//
// WIRING - the integration agent pastes this into kernel/context.go:
//
//	// in the SContext interface, beside the other groups:
//		SyscallSignal
//
//	// the methods:
//	func (c *sContext) SyscallSignalSend(target PID, kind SignalKind) error {
//		return SignalSend(c, target, kind)
//	}
//	func (c *sContext) SyscallSignalHandle(h SignalHandler) error { return SignalHandle(c, h) }
//
// The SyscallSignal interface itself is declared at the bottom of this file.
//
// RESET - resetKernel() in kernel/kernel.go must call:
//
//	resetSched()
//	resetSignals()
//	resetWatchdog()

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// SignalKind is one of the four things the kernel can say to a module. The set is
// closed: an unnamed kind is refused rather than delivered as a generic event,
// because a handler cannot act on a meaning it cannot read.
type SignalKind string

const (
	// SignalReload asks a module to re-read its configuration. The analogue is
	// SIGHUP. Default action: none, recorded.
	SignalReload SignalKind = "reload"
	// SignalDrain asks a module to stop accepting new work and finish what is in
	// flight. The analogue is SIGTERM. Default action: terminate, because a
	// module that ignores drain and never exits makes unload unsafe.
	SignalDrain SignalKind = "drain"
	// SignalKill asks a module to stop now. The analogue is SIGKILL. Default
	// action: terminate. There is no way to ignore it: the kernel performs the
	// teardown itself.
	SignalKill SignalKind = "kill"
	// SignalAbort reports that the client behind some in-flight work went away.
	// It cancels the module's supervised runs so a stream stops being produced
	// for a reader that is gone. Default action: cancel in-flight work, do not
	// terminate.
	SignalAbort SignalKind = "abort"
)

// SignalKinds lists the kinds the kernel delivers, for diagnostics and tests.
func SignalKinds() []SignalKind {
	return []SignalKind{SignalReload, SignalDrain, SignalKill, SignalAbort}
}

// SignalInfo is what a handler receives. From and FromDomain are the sender as the
// kernel knows it, not as the sender describes itself.
type SignalInfo struct {
	// Kind is the signal.
	Kind SignalKind `json:"kind"`
	// From is the sender's pid.
	From PID `json:"from"`
	// FromDomain is the sender's domain.
	FromDomain Domain `json:"from_domain"`
	// SentAt is a mono() reading taken when the kernel accepted the signal.
	SentAt int64 `json:"sent_at"`
}

// SignalHandler is a module's own response to a signal. It runs supervised: under
// the module's context, inside the sealed call ceiling, with panics recovered and
// with kwatchdog registered. A handler that hangs is therefore reported and the
// module is still terminated, which is why a handler is not a way to survive a
// kill.
type SignalHandler func(info SignalInfo)

// SignalQueueError reports a signal refused because the target's pending queue is
// full. It is a distinct type so a caller can tell "the target is not keeping up"
// from "you are not permitted".
type SignalQueueError struct {
	Target PID
	Max    int
}

func (e *SignalQueueError) Error() string {
	return fmt.Sprintf("kernel: signal queue for pid %d is full (%d pending)", e.Target, e.Max)
}

// IsSignalQueueFull reports whether err is a full-queue refusal.
func IsSignalQueueFull(err error) bool {
	var q *SignalQueueError
	return errors.As(err, &q)
}

// ErrDraining refuses new work to a module that has been asked to wind down. It is
// not a policy denial: the module holds sched:spawn, and the refusal is about the
// state the kernel put it in, not about its grants.
var ErrDraining = errors.New("kernel: module is draining; no new work accepted")

// maxPendingSignalsPerPID bounds one pid's undelivered signals. A module that
// stops consuming signals must not be able to grow kernel memory by being signalled
// faster than it reacts; the bound is what turns that into a visible refusal at the
// sender instead.
const maxPendingSignalsPerPID = 64

// signalState is one pid's signal endpoint.
type signalState struct {
	// pid is fixed when the endpoint is created. The teardown goroutine reads it
	// from here rather than from the map key, so one that outlives a reset still
	// knows which module it was asked to stop and can tell from closed that the
	// answer no longer matters.
	pid     PID
	mu      sync.Mutex
	queue   chan SignalInfo
	stop    chan struct{}
	handler SignalHandler
	ctx     *sContext
	closed  bool

	draining    bool
	terminating bool
	terminated  atomic.Bool
}

var (
	signalsMu sync.Mutex
	signals   = map[PID]*signalState{}

	// teardowns counts kernel-initiated teardowns still in flight, and
	// teardownsRefused blocks new ones while a reset drains. See resetSignals for
	// why a reset has to wait rather than clear.
	teardowns        sync.WaitGroup
	teardownsRefused atomic.Bool
)

// signalStateFor returns a pid's endpoint, creating it on first use and starting its
// delivery worker.
//
// One worker per endpoint, rather than one goroutine per signal, is what makes the
// pending queue a real bound. With a goroutine per signal every sender also creates a
// consumer, so the queue can never fill no matter how fast signals arrive, and the
// ceiling on undelivered signals would be decoration. With one worker, a module whose
// handler is stuck stops consuming, the queue fills, and the next sender gets a typed
// refusal it can act on.
func signalStateFor(pid PID) *signalState {

	signalsMu.Lock()
	s, ok := signals[pid]
	if !ok {
		stop := make(chan struct{})
		s = &signalState{
			pid:   pid,
			queue: make(chan SignalInfo, maxPendingSignalsPerPID),
			stop:  stop,
		}
		signals[pid] = s
		// The stop channel is passed by value rather than read from the struct
		// inside the loop: closeSignalEndpoint clears the field, and a select
		// reading it concurrently would be a data race on a field the closer
		// owns.
		go s.loop(stop)
	}
	signalsMu.Unlock()
	return s
}

// signalLookup returns a pid's endpoint only if one already exists.
//
// Read paths go through this rather than signalStateFor. Creating an endpoint as a
// side effect of asking whether a module is draining would resurrect state after
// resetSignals has cleared it, and a teardown goroutine still in flight from the
// previous boot would then leave the next boot holding a condemned flag for a pid it
// has not allocated yet.
func signalLookup(pid PID) *signalState {
	signalsMu.Lock()
	defer signalsMu.Unlock()
	return signals[pid]
}

// SignalSend delivers a signal to a pid.
//
// Delivery is asynchronous: the call returns once the signal is queued, and the
// target's single delivery worker invokes its handler or applies the default action
// afterwards. Kill is the exception and is applied by the kernel before returning,
// because it is never handed to a handler and must not wait behind one.
//
// Requires signal:send, plus the target rules documented on signalPermitted.
func SignalSend(ctx SContext, target PID, kind SignalKind) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errors.New("kernel: SignalSend requires a kernel-issued context")
	}
	if err := c.syscall(OpSignalSend); err != nil {
		return err
	}
	if !knownSignalKind(kind) {
		return fmt.Errorf("kernel: unknown signal kind %q", kind)
	}
	if err := signalPermitted(c, target); err != nil {
		return err
	}

	info := SignalInfo{Kind: kind, From: c.pid, FromDomain: c.dom, SentAt: mono()}
	s := signalStateFor(target)

	// Kill is applied here rather than queued, and both reasons are structural.
	// It is never handed to module code, so there is no delivery order to preserve;
	// and an endpoint whose handler is stuck has a worker that is not draining its
	// queue, so a queued kill would sit behind the very thing it was sent to stop.
	// Queuing kill would make the one signal that cannot be caught also the one that
	// cannot arrive - and it would make a full queue, which is a module's own
	// failure to keep up, a way to become unkillable.
	if kind == SignalKill {
		s.terminate("kill signal", true)
		kaudit.record(AuditPolicy, c, "signal sent", map[string]any{
			"target": target, "kind": string(kind),
		})
		return nil
	}

	// The audit record is written after the enqueue succeeds, never before. An
	// entry saying "signal sent" for a signal the kernel refused would be false
	// evidence in exactly the investigation that cares: did the operator's drain
	// reach the module, or was the module too far behind to be told?
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("kernel: pid %d is gone; its signal endpoint is closed", target)
	}
	select {
	case s.queue <- info:
		s.mu.Unlock()
	default:
		s.mu.Unlock()
		// A full queue is the target's failure to keep up, and it is reported to
		// the sender rather than silently dropping a signal. Silently dropping
		// drain is how a module survives a wind-down it was told about.
		err := &SignalQueueError{Target: target, Max: maxPendingSignalsPerPID}
		fault(c, "signal refused: target queue full",
			map[string]any{"target": target, "kind": string(kind)})
		kaudit.record(AuditPolicy, c, "signal queue full", map[string]any{
			"target": target, "kind": string(kind), "max_pending": maxPendingSignalsPerPID,
		})
		return err
	}
	kaudit.record(AuditPolicy, c, "signal sent", map[string]any{
		"target": target, "kind": string(kind),
	})
	return nil
}

// SignalHandle installs the calling module's signal handler. Re-installing replaces
// the previous one; passing nil removes it, which restores the default actions.
//
// Requires no operation. Handling a signal sent to your own pid is not a
// capability - it cannot widen what the module may do, only narrow its own response
// - and the handler is bound to the caller's context, so there is no call shape in
// which a module installs a handler that runs as another.
//
// The kernel retains the caller's context here, which is the one place in the
// kernel a live module context is held in package state. It is held so the handler
// can be invoked under the module's own identity, and it is dropped on termination
// and on reset.
func SignalHandle(ctx SContext, h SignalHandler) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errors.New("kernel: SignalHandle requires a kernel-issued context")
	}
	if err := c.syscall(""); err != nil {
		return err
	}

	s := signalStateFor(c.pid)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("kernel: pid %d is gone; its signal endpoint is closed", c.pid)
	}
	s.handler = h
	if h != nil {
		s.ctx = c
	} else {
		s.ctx = nil
	}
	return nil
}

// SignalPending reports how many signals are queued but not yet delivered to a pid.
func SignalPending(pid PID) int {
	s := signalLookup(pid)
	if s == nil {
		return 0
	}
	return len(s.queue)
}

// SignalState reports what the kernel has decided about a pid. Both flags are set by
// the kernel and cleared only by a reset; a module cannot clear either.
func SignalState(pid PID) (draining, terminating bool) {
	s := signalLookup(pid)
	if s == nil {
		return false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.draining, s.terminating
}

// admissionBlocked is ksched's gate: it refuses new supervised work to a module the
// kernel has told to wind down or has condemned. Living in ksignal rather than in
// ksched is what keeps one definition of "this module may not start anything new",
// which is the property drain exists to establish.
func admissionBlocked(pid PID) error {
	s := signalLookup(pid)
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.terminating:
		return ErrTerminating
	case s.draining:
		return ErrDraining
	}
	return nil
}

// markDraining sets the wind-down flag. New supervised work is refused from this
// point; work already in flight is left alone, because finishing it is the whole
// point of drain as opposed to kill.
func markDraining(s *signalState) {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
}

// markTerminating sets the condemned flag and returns true for the caller that set it
// first, so a teardown runs exactly once however many paths ask for it - a kill
// signal, an unhandled drain and a watchdog detection can all arrive for one pid.
func markTerminating(s *signalState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	first := !s.terminating && !s.closed
	s.terminating = true
	return first
}

// signalAuthority is the context the kernel acts under when it performs a teardown
// on its own initiative. It is constructed here rather than passed in because no
// caller outside package kernel can reach this function, and it exists so the
// teardown goes through the same UnloadModule path - and therefore the same audit
// record and the same handle reclamation - as an operator-initiated unload.
//
// It is deliberately not stored anywhere: a long-lived kernel-domain context is the
// privilege-retention mistake the boot sequence exists to avoid.
func signalAuthority() *sContext {
	return &sContext{pid: 0, uid: uidKernel, dom: DomainKernel, name: "kernel"}
}

// signalPermitted is the target rule. check() has already decided that the caller
// holds signal:send; this decides whom that grant reaches.
//
// Three refusals, each with a reason:
//
//   - pid 0 and init are never targets. Pid 0 is the retired root context and init
//     is the sequence that decides what code runs. A module that could signal init
//     could drain or kill the thing supervising it, which turns a wind-down request
//     into a way to end enforcement.
//   - A plugin may signal itself, or a pid it spawned. Cross-module coordination
//     goes through ipc:call, so the call graph stays visible to policy; a signal is
//     a lifecycle command and lifecycle commands do not travel sideways between
//     peers.
//   - An unknown pid is an error rather than a denial: nothing was refused, the
//     target simply does not exist in this boot.
func signalPermitted(c *sContext, target PID) error {
	if target < 0 {
		return fmt.Errorf("kernel: invalid signal target pid %d", target)
	}

	var rec *ProcSnapshot
	tbl := ProcTable()
	for i := range tbl {
		if tbl[i].PID == target {
			rec = &tbl[i]
			break
		}
	}

	refuse := func(reason string) error {
		d := &DeniedError{Op: OpSignalSend, Ctx: c, Reason: reason}
		fault(c, d.Error(), map[string]any{"target": target, "reason": reason})
		// Recorded with the same fields check() uses, so an operator querying
		// denials by operation finds these too. A target refusal is a denial of
		// signal:send and must not be invisible to the query that counts them.
		kaudit.record(AuditDenial, c, d.Error(), map[string]any{
			"op": string(OpSignalSend), "reason": reason, "target": target,
		})
		return d
	}

	// Pid 0 is the kernel's own retired root context. It is refused before the
	// table lookup so the answer does not depend on the record still being there.
	if target == 0 {
		return refuse("pid 0 is the kernel and is never a signal target")
	}
	if rec == nil {
		return fmt.Errorf("kernel: no process record for pid %d in this boot", target)
	}
	if rec.Domain == DomainKernel || rec.Domain == DomainInit {
		return refuse(fmt.Sprintf("pid %d runs as %s and is never a signal target", target, rec.Domain))
	}
	if target == c.pid {
		return nil
	}
	// The kernel and init domains supervise everything, so they reach every
	// module. This is the path the host uses to wind a module down.
	if c.dom == DomainKernel || c.dom == DomainInit {
		return nil
	}
	if rec.PPID == c.pid {
		return nil
	}
	return refuse(fmt.Sprintf("pid %d is not the sender and was not spawned by it", target))
}

// loop is the endpoint's single delivery worker. It drains the queue in order and
// stops when the endpoint is closed by a reset.
//
// Serial delivery is the POSIX reading: signals to one process are handled one at a
// time, in order, by that process. It also means a stuck handler is visible as a
// growing SignalPending count rather than as an unbounded number of goroutines all
// stuck at once.
func (s *signalState) loop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case info := <-s.queue:
			s.dispatch(info)
		}
	}
}

// dispatch acts on one dequeued signal.
//
// Kill never reaches here: SignalSend applies it before queuing, because it is not
// delivered to a handler and must not wait behind one. That is faithful to SIGKILL -
// it cannot be caught or ignored - and it is why a module cannot survive termination
// by installing a handler that blocks.
func (s *signalState) dispatch(info SignalInfo) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	handler, ctx := s.handler, s.ctx
	s.mu.Unlock()

	pid := s.pid
	// Drain is marked before the handler runs, not after. The handler is the
	// module's chance to wind down, and a wind-down that still accepts new work is
	// not a wind-down: without this, a drain handler could submit fresh supervised
	// runs and the module would be busier after the signal than before it.
	if info.Kind == SignalDrain {
		markDraining(s)
	}

	// A pid that is no longer running gets no delivery. UnloadModule cannot reach
	// into this subsystem, so without this check a signal arriving after an unload
	// would run a handler closure belonging to a module that is gone, under a
	// context the kernel handed out for a load that has already ended. Dropping it
	// here also releases the closure and the retained context promptly, rather than
	// holding module code in kernel state until the next reset.
	if !signalTargetLive(pid) {
		s.mu.Lock()
		s.handler = nil
		s.ctx = nil
		s.mu.Unlock()
		kaudit.record(AuditPolicy, nil, "signal dropped: target is not running", map[string]any{
			"target": pid, "kind": string(info.Kind), "from": info.From,
		})
		return
	}

	if handler != nil && ctx != nil {
		s.runHandler(pid, ctx, handler, info)
		return
	}
	s.defaultAction(pid, info)
}

// signalTargetLive reports whether a pid still has a running process-table record.
// The process table is append-only and only the kernel writes state into it, so this
// is a fact about the pid rather than a claim by the sender.
func signalTargetLive(pid PID) bool {
	for _, r := range ProcTable() {
		if r.PID == pid {
			return r.State == ProcRunning
		}
	}
	return false
}

// runHandler invokes module code under supervision. The handler is the module's, so
// it gets the same treatment as any other module function the kernel runs: the
// module's own context, the sealed ceiling, panic recovery, watchdog registration.
func (s *signalState) runHandler(pid PID, ctx *sContext, h SignalHandler, info SignalInfo) {
	// Registered with the timeout form: the handler has no deadline computed
	// elsewhere, so there is nothing for an absolute-deadline registration to agree
	// with, and deriving it twice would risk the two disagreeing.
	ticket := watchdogRegister(kindSignal, pid, "signal handler: "+string(info.Kind), 0, callCeiling(0))

	done := make(chan struct{})
	go func() {
		defer func() {
			if p := recover(); p != nil {
				fault(ctx, "signal handler panicked", map[string]any{
					"kind": string(info.Kind), "panic": fmt.Sprint(p),
				})
				kaudit.record(AuditPanic, ctx, "signal handler panicked", map[string]any{
					"kind": string(info.Kind), "panic": fmt.Sprint(p),
				})
			}
			close(done)
		}()
		h(info)
	}()

	select {
	case <-done:
	case <-time.After(callCeiling(0)):
		// A handler that outlives the ceiling does not get to keep the signal
		// it was sent: the kernel reports the hang and applies the default
		// action anyway, so a module cannot survive drain by handling it slowly.
		kconsole.Emit(LogWarn, pid, DomainPlugin, "signal handler exceeded the call ceiling",
			map[string]any{"kind": string(info.Kind), "stack": watchdogCurrentStack()})
		ticket.Release()
		s.defaultAction(pid, info)
		return
	}
	ticket.Release()

	// Drain was marked before this call, and it is not advisory: from here the
	// kernel refuses the module new supervised work, so the wind-down does not
	// depend on module code choosing to stop submitting. Kill is unreachable here.
}

// defaultAction is what the kernel does when a module has no handler. Each default
// is the safe reading of the signal: doing nothing is only safe where nothing is
// what the signal means.
func (s *signalState) defaultAction(pid PID, info SignalInfo) {
	switch info.Kind {
	case SignalReload:
		// No handler means no configuration to re-read. Recording it keeps the
		// fact that an operator asked visible in the audit trail.
		kaudit.record(AuditPolicy, nil, "reload signal had no handler", map[string]any{
			"target": pid, "from": info.From,
		})
	case SignalDrain:
		// The default for an unhandled drain is termination. The module was
		// already marked draining in dispatch; this is the half that makes
		// ignoring drain fatal rather than merely noted. A module that ignores
		// drain and never exits is a module that cannot be unloaded safely, and
		// the kernel does not have the option of waiting forever.
		s.terminate("unhandled drain signal", false)
	case SignalAbort:
		// The client is gone. The module lives; the work it was doing for that
		// client does not.
		cancelSchedWork(pid, "abort signal")
		kaudit.record(AuditPolicy, nil, "abort signal cancelled in-flight work",
			map[string]any{"target": pid, "from": info.From})
	}
}

// terminate performs a kernel-initiated teardown of this endpoint's pid. It runs once
// per pid, asynchronously, and through the same UnloadModule path an operator-initiated
// unload takes, so the audit record, the handle reclamation and the process-table
// transition are identical whichever way the module was stopped.
//
// immediate distinguishes kill from drain: a kill cancels in-flight supervised work
// first, a drain leaves it running so the module can finish what it started.
//
// It is a method on the endpoint rather than a function taking a pid so a teardown can
// never resurrect an endpoint that resetSignals has dropped. One still in flight from
// the previous boot finds its own endpoint closed and does nothing, instead of
// condemning a pid the next boot has not allocated yet.
func (s *signalState) terminate(reason string, immediate bool) {
	if !markTerminating(s) {
		return
	}
	pid := s.pid
	kaudit.record(AuditPolicy, nil, "kernel-initiated termination", map[string]any{
		"target": pid, "reason": reason, "immediate": immediate,
	})
	fault(nil, "kernel terminating module", map[string]any{"target": pid, "reason": reason})

	// The count is taken synchronously, under signalsMu, rather than inside the
	// goroutine. A WaitGroup whose Add can happen after a Wait has returned is a
	// misuse that panics, and taking it here is what lets resetSignals drain safely.
	signalsMu.Lock()
	refused := teardownsRefused.Load()
	if !refused {
		teardowns.Add(1)
	}
	signalsMu.Unlock()
	if refused {
		return
	}

	// The teardown runs on its own goroutine. UnloadModule can block for up to the
	// unload timeout inside module code, and the kernel does not block on module
	// code - not here, and not on the path that got here.
	go func() {
		defer teardowns.Done()

		// Re-checked inside the goroutine: if a reset closed this endpoint
		// between the decision to terminate and getting here, the pid may
		// already have been re-allocated to an unrelated module in a new boot.
		// Unloading it then would be the kernel destroying the wrong module on
		// the authority of the last one.
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return
		}

		if immediate {
			cancelSchedWork(pid, reason)
		}
		err := UnloadModule(signalAuthority(), pid)

		s.mu.Lock()
		closed = s.closed
		s.terminated.Store(!closed)
		s.handler = nil
		s.ctx = nil
		s.mu.Unlock()
		if closed {
			return
		}
		if err != nil {
			fault(nil, "kernel-initiated termination failed", map[string]any{
				"target": pid, "reason": reason, "error": err.Error(),
			})
			// Even a failed unload reclaims what the kernel can reach. A module
			// that hangs in OnUnload still loses its handles, so it cannot keep
			// writing to a pipe or holding a timer after the kernel gave up on it.
			reclaimFDs(pid)
		}
	}()
}

// terminateModule is the pid-keyed form used by kwatchdog, which has a pid and a
// deadline in hand and no endpoint. A pid with no endpoint gets one, because a hang
// detected in work another subsystem registered still has to end in a teardown, and
// the teardown needs somewhere to record that it happened exactly once.
func terminateModule(pid PID, reason string, immediate bool) {
	signalStateFor(pid).terminate(reason, immediate)
}

// SignalTerminated reports whether a kernel-initiated teardown of a pid has finished.
// It is the fact an operator or a test waits on to know a condemned module is gone.
func SignalTerminated(pid PID) bool {
	s := signalLookup(pid)
	if s == nil {
		return false
	}
	return s.terminated.Load()
}

func knownSignalKind(k SignalKind) bool {
	switch k {
	case SignalReload, SignalDrain, SignalKill, SignalAbort:
		return true
	}
	return false
}

// closeSignalEndpoint stops a pid's worker and drops its handler and retained
// context. Called on reset only: within a boot an endpoint stays open so a late
// signal to a terminated module is a visible refusal rather than a silent drop.
//
// Dropping the handler and the context it was installed with matters. A handler is a
// module closure, and a retained module context in package state is the one thing the
// context design says must not outlive the module; leaving either behind across a
// boot would run the previous boot's code under a pid the new boot has re-allocated.
func closeSignalEndpoint(s *signalState) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.handler = nil
	s.ctx = nil
	s.draining = false
	s.terminating = false
	stop := s.stop
	s.mu.Unlock()
	s.terminated.Store(false)
	close(stop)
}

// resetSignals clears ksignal state for a fresh boot. Called only from resetKernel.
//
// Every endpoint is closed and dropped. Handlers are module closures and must not
// survive into the next boot: a stale handler would run the previous boot's code
// under a pid the new boot has allocated to something else.
//
// It also refuses new teardowns and waits for the ones in flight. Clearing the table
// without draining would let a teardown goroutine from this boot call UnloadModule
// against the next one, where pids start again at 1 and the module at that number is
// somebody else entirely - the kernel destroying an innocent module on the authority
// of a previous one's watchdog detection. The wait is bounded by the unload timeout
// Shutdown already accepts.
func resetSignals() {
	signalsMu.Lock()
	teardownsRefused.Store(true)
	signalsMu.Unlock()

	teardowns.Wait()

	signalsMu.Lock()
	endpoints := make([]*signalState, 0, len(signals))
	for _, s := range signals {
		endpoints = append(endpoints, s)
	}
	signals = map[PID]*signalState{}
	teardownsRefused.Store(false)
	signalsMu.Unlock()

	for _, s := range endpoints {
		closeSignalEndpoint(s)
	}
}

// SyscallSignal is the signal half of the syscall surface.
type SyscallSignal interface {
	// SyscallSignalSend delivers a signal to a pid. Requires signal:send, and the
	// target must be permitted by the rules in ksignal: never pid 0, never init,
	// and for a plugin only itself or a pid it spawned. Delivery is asynchronous
	// through a bounded per-pid queue.
	SyscallSignalSend(target PID, kind SignalKind) error
	// SyscallSignalHandle installs the caller's own signal handler, replacing any
	// previous one. Requires no operation: it can only narrow the caller's own
	// response to a signal, never widen what the caller may do.
	SyscallSignalHandle(h SignalHandler) error
}
