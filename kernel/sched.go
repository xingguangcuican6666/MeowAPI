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

// ksched: supervised execution. The analogue of a kernel work queue plus a
// per-process ITIMER: work is submitted, the kernel runs it, the kernel owns the
// deadline, and the submitting process does not get to choose how long it may take.
//
// WHY THIS EXISTS
//
// A module that writes `go f()` creates work the kernel has never seen. That
// goroutine carries no context, so nothing it does is attributed to a pid; it has
// no deadline, so nothing stops it; and it outlives the module that started it, so
// unloading the module does not unload the work. An in-process kernel cannot take
// the goroutine away - Go offers no preemption the kernel could apply to code it
// does not own - but it can refuse to be the only party that never notices.
//
// So ksched offers the alternative: a module hands the kernel a function and gets
// an fd back. The kernel runs the function on a goroutine it started, under the
// caller's own sealed context, with a deadline measured on mono() and clamped to
// the sealed CallTimeoutMillis ceiling, with panics recovered, with the run
// registered in kwatchdog, and with the whole thing cancellable by closing the fd,
// by a signal from ksignal, or by reclaiming the pid's handle table on unload.
//
// WHAT IS ENFORCED, STATED PLAINLY
//
// The guarantee covers work the kernel runs, not work a module runs. A module that
// calls the standard library directly and starts its own goroutine is not stopped
// by this file or by any policy check: it is invisible to ksched, and catching it
// is a review and signing concern rather than a runtime control. What ksched does
// guarantee is that every goroutine the kernel started for a module inherits that
// module's context, is accounted to that module's pid, is bounded by a deadline the
// module cannot raise, has its panic recovered by the kernel instead of the host,
// and is cancellable without the module's cooperation.
//
// WIRING - the integration agent pastes this into kernel/context.go:
//
//	// in the SContext interface, beside the other groups:
//		SyscallSched
//		SyscallSignal
//
//	// the methods:
//	func (c *sContext) SyscallSchedSpawn(job SchedJob) (FD, error) { return SchedSpawn(c, job) }
//	func (c *sContext) SyscallSchedTimer(spec TimerSpec) (FD, error) { return SchedTimer(c, spec) }
//	func (c *sContext) SyscallSchedWait(fd FD) (SchedOutcome, error) { return SchedWait(c, fd) }
//
// The SyscallSched interface itself is declared at the bottom of this file, next to
// the subsystem that implements it.
//
// RESET - resetKernel() in kernel/kernel.go must call, in this order and before the
// existing resetFDTables():
//
//	resetWatchdog()
//	resetSched()
//	resetSignals()

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// SchedState is the state of a supervised run. The set is closed, because a state
// the kernel cannot name is one an operator cannot later query.
type SchedState string

const (
	// SchedRunning is a run the kernel has started and not finished.
	SchedRunning SchedState = "running"
	// SchedCompleted is a run whose function returned before any deadline.
	SchedCompleted SchedState = "completed"
	// SchedTimedOut is a run whose deadline expired and whose function did not
	// return within the grace period. The kernel stopped waiting for it; the
	// goroutine may still be running, which is the limit documented above.
	SchedTimedOut SchedState = "timed_out"
	// SchedPanicked is a run whose function panicked. The panic was recovered by
	// the kernel, so it never reached the host process.
	SchedPanicked SchedState = "panicked"
	// SchedCancelled is a run the kernel asked to stop - handle closed, module
	// signalled, kernel reset - that did not return in time.
	SchedCancelled SchedState = "cancelled"
	// SchedPending is an armed timer that has not fired.
	SchedPending SchedState = "pending"
)

// SchedFunc is work a module asks the kernel to run.
//
// The context handed to it is the caller's own, so the job inherits the caller's
// pid, uid, domain and manifest grants. Every syscall it makes is decided against
// the same ceiling as one made from OnLoad: moving work onto a kernel goroutine
// buys a deadline and attribution, and buys no privilege.
//
// done is closed when the run's deadline expires, when the module closes the
// handle, when the module is signalled to stop, or when the kernel resets. A
// well-behaved job selects on it and returns promptly. A job that ignores it is
// not stopped - see the file header - but the run is then recorded as timed out,
// kwatchdog captures its stack, and the module is put forward for termination.
type SchedFunc func(ctx SContext, done <-chan struct{})

// SchedJob is one request for supervised execution.
type SchedJob struct {
	// Label names the run in the console, in the audit record and in a watchdog
	// event. It is a diagnostic string chosen by the module and is never
	// interpreted by the kernel, so it is length-bounded rather than trusted.
	Label string
	// TimeoutMillis bounds this run. Zero or negative means the sealed ceiling.
	// A value above the ceiling is clamped down: a module may ask for less time
	// than the trust root allows and may never ask for more, because a timeout
	// the timed-out party chooses is not a timeout.
	TimeoutMillis int64
	// Fn is the work. Nil is refused rather than scheduled.
	Fn SchedFunc
}

// TimerSpec is one request for a deferred callback.
//
// Timers are single-shot on purpose. A periodic timer is a way to keep creating
// work forever from one declaration, and the reviewable artifact - the manifest -
// would say nothing about the rate. A module that needs a period re-arms from
// inside the callback, which puts every period through the same ceiling, the same
// quota and the same accounting as the first one.
type TimerSpec struct {
	// Label names the timer in diagnostics.
	Label string
	// DelayMillis is how long to wait before firing. The fire time is a mono()
	// reading, so a wall-clock step - NTP, an operator changing the date, a VM
	// migration - cannot move a timer armed here. The runtime timer underneath is
	// only the wakeup mechanism.
	DelayMillis int64
	// Fn runs under the same supervision as a spawned job: the caller's context,
	// the ceiling timeout, panic recovery, watchdog registration.
	Fn SchedFunc
}

// SchedOutcome is what the kernel recorded about one run. It is always a copy:
// handing out the live record would let a module rewrite the evidence of its own
// timeout.
type SchedOutcome struct {
	// ID is the kernel-allocated run id, unique within a boot.
	ID int64 `json:"id"`
	// Label is the module's own diagnostic string.
	Label string `json:"label,omitempty"`
	// Kind is "job" or "timer".
	Kind string `json:"kind"`
	// State is the terminal state, or SchedRunning / SchedPending while live.
	State SchedState `json:"state"`
	// Detail explains a non-completed state: the panic value, "deadline
	// expired", "handle closed", "module terminated".
	Detail string `json:"detail,omitempty"`
	// StartedAt and ElapsedNanos are mono() readings taken by the kernel around
	// the module's function, so a module cannot report a duration shorter than
	// the one it actually occupied.
	StartedAt    int64 `json:"started_at,omitempty"`
	ElapsedNanos int64 `json:"elapsed_nanos,omitempty"`
	// Deadline is the mono() value at which the run was required to stop.
	Deadline int64 `json:"deadline,omitempty"`
	// Stack is a snapshot of the offending goroutine when the run timed out, was
	// abandoned or panicked. It is empty on a clean completion.
	Stack string `json:"stack,omitempty"`
}

// SchedLimitError reports a supervised-execution request refused by a ceiling. It
// is a distinct type so a caller can tell "you asked for too much" from "the
// kernel is broken" without matching on a message.
type SchedLimitError struct{ Msg string }

func (e *SchedLimitError) Error() string { return "kernel: sched limit: " + e.Msg }

// IsSchedLimit reports whether err is a ceiling refusal from ksched.
func IsSchedLimit(err error) bool {
	var l *SchedLimitError
	return errors.As(err, &l)
}

func schedLimitErr(format string, a ...any) error {
	return &SchedLimitError{Msg: fmt.Sprintf(format, a...)}
}

// ErrTerminating refuses new work to a module the kernel has already decided to
// terminate. Accepting work from a condemned module would create a goroutine whose
// only supervisor is about to be asked to go away, and that goroutine would then be
// unaccounted - the one outcome ksched exists to prevent.
var ErrTerminating = errors.New("kernel: module is being terminated; no new work accepted")

// maxSchedLabelLen bounds a module-chosen string the kernel stores and echoes into
// records. It is hygiene, not quota: the label is not the scarce resource.
const maxSchedLabelLen = 128

// maxLiveTimersPerPID bounds armed timers for one module. A timer is cheap but not
// free, and an unbounded count of them is a way to grow the runtime's timer heap
// from inside a module. The handle-table ceiling from the trust root applies on top
// of this, so the effective bound is the smaller of the two.
const maxLiveTimersPerPID = 128

// kindJob and kindTimer are the fd-table kind strings for supervised runs.
const (
	kindJob   = "job"
	kindTimer = "timer"
)

// cancelByHandle and cancelByDeadline are the two cancellation causes the kernel
// distinguishes. A deadline is a timeout; a closed handle is the module exercising
// its own right to stop work it started. The strings are compared by the supervisor
// and by the console filter, so they are named rather than spelled inline.
const (
	cancelByHandle   = "handle closed"
	cancelByDeadline = "deadline expired"
)

// runResult is the kernel's own account of one invocation of module code.
type runResult struct {
	state   SchedState
	detail  string
	stack   string
	start   int64
	elapsed int64
}

// schedRun is one supervised run. It is a resource, so the fd table owns it:
// closing the handle cancels the run, and reclaiming the pid's table on unload
// cancels every run the module had. That is what makes "a crashed module leaks
// nothing" true of its goroutines as well as of its buffers.
type schedRun struct {
	closedFlag

	id       int64
	pid      PID
	label    string
	kind     string
	deadline int64

	// cancel is closed by cancelOnce and handed to the module's function as
	// done.
	cancel   chan struct{}
	cancelBy atomic.Value // string

	// gid is the goroutine id of the module's function. kwatchdog reads it to
	// pick that goroutine's frames out of a full dump. It is atomic because the
	// worker writes it once at start and the supervisor reads it concurrently.
	gid atomic.Uint64

	// armed holds the runtime timer for a pending one, so Close can stop it.
	armed atomic.Pointer[time.Timer]

	// timerSlot records that this run still owes the per-pid timer counter one
	// slot. Exactly one of the three paths that can end a pending timer - it
	// fires, it is cancelled, Close stops it - wins the swap, so the counter
	// cannot be decremented twice.
	timerSlot atomic.Bool

	// holdsSlot records that this run owes the per-pid supervised-run counter one
	// slot. A job takes it at spawn; a timer takes it when it fires, because a
	// firing timer becomes in-flight work and work is bounded. The swap is what
	// keeps a run that is finished twice - by its worker and by Close - from
	// releasing the same slot twice and handing the next module a free one.
	holdsSlot atomic.Bool

	// started records that supervise has begun. A pending timer has no supervisor
	// listening on its cancel channel yet, so cancelling one has to be done for it
	// rather than left to a goroutine that does not exist. See cancelSchedWork.
	started atomic.Bool

	// settled records that the run reached a terminal state. It is an atomic rather
	// than a bool under mu because two readers need it without taking the lock: the
	// timer callback deciding whether the run it was about to start is already over,
	// and setState refusing to move a finished run backwards. finish swaps it under
	// mu, so exactly one caller ever owns the record.
	settled atomic.Bool

	mu       sync.Mutex
	state    SchedState
	detail   string
	stack    string
	start    int64
	elapsed  int64
	finished chan struct{}
}

// Kind names the resource for the fd table and for diagnostics.
func (r *schedRun) Kind() string { return r.kind }

// Close cancels the run. It is called by an explicit SyscallClose, by reclaiming
// the pid's handle table on unload, and by the termination path in signal.go. All
// three mean the same thing here: stop being supervised, and stop soon.
//
// Close is once-only through the embedded closedFlag, which is what lets an
// explicit close and a reclaim-on-unload both run without the second one being
// reported as a failure to close a live resource.
func (r *schedRun) Close() error {
	if !r.mark() {
		return nil
	}
	r.cancelOnce(cancelByHandle)
	if t := r.armed.Swap(nil); t != nil {
		t.Stop()
	}
	// A timer that had not fired yet will never become work, so its run is
	// terminal now rather than left for a waiter to discover at the ceiling.
	if r.timerSlot.Swap(false) {
		releaseTimer(r.pid)
		r.finish(SchedCancelled, cancelByHandle, "")
	}
	return nil
}

// cancelOnce closes the done channel at most once and records why. Every
// cancellation path goes through it, so the reason in the outcome is the real first
// cause rather than whichever path happened to run last.
func (r *schedRun) cancelOnce(reason string) {
	if r.cancelBy.CompareAndSwap(nil, reason) {
		close(r.cancel)
	}
}

// cancelReason reports why the run was cancelled, or "" if it was not.
func (r *schedRun) cancelReason() string {
	v, _ := r.cancelBy.Load().(string)
	return v
}

var (
	schedMu     sync.Mutex
	schedLive   = map[PID]int{}
	schedTimers = map[PID]int{}
	schedSeq    atomic.Int64
)

// SchedSpawn asks the kernel to run a function on the caller's behalf and returns a
// handle to the run. Wait on it with SchedWait, cancel it by closing it, and lose it
// - along with every other handle - when the module is unloaded.
//
// Requires sched:spawn.
func SchedSpawn(ctx SContext, job SchedJob) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errors.New("kernel: SchedSpawn requires a kernel-issued context")
	}
	// c.syscall is the liveness gate followed by check(), so a retired context is
	// refused as retired rather than being misreported as an unauthorized one.
	if err := c.syscall(OpSchedSpawn); err != nil {
		return noFD, err
	}
	if job.Fn == nil {
		return noFD, errors.New("kernel: SchedSpawn requires a function")
	}
	if len(job.Label) > maxSchedLabelLen {
		return noFD, schedLimitErr("label longer than %d bytes", maxSchedLabelLen)
	}
	// A module the kernel has told to wind down or has condemned gets no new
	// goroutines. Without this, drain would mean nothing to a module that kept
	// submitting work.
	if err := admissionBlocked(c.pid); err != nil {
		return noFD, err
	}

	timeout := callCeiling(job.TimeoutMillis)
	r := newRun(c.pid, kindJob, job.Label, mono()+timeout.Nanoseconds())

	if err := r.reserveLive(c); err != nil {
		return noFD, err
	}
	fd, err := install(c.pid, r, job.Label)
	if err != nil {
		r.releaseSlot()
		fault(c, "supervised spawn refused by the handle ceiling",
			map[string]any{"label": job.Label, "error": err.Error()})
		return noFD, err
	}

	go r.supervise(c, job.Fn, timeout)
	return fd, nil
}

// SchedTimer arms a single-shot callback after a delay measured on mono(). The
// returned handle cancels the timer when closed, and is reclaimed with everything
// else the module holds when the module is unloaded.
//
// Requires sched:timer.
func SchedTimer(ctx SContext, spec TimerSpec) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errors.New("kernel: SchedTimer requires a kernel-issued context")
	}
	if err := c.syscall(OpSchedTimer); err != nil {
		return noFD, err
	}
	if spec.Fn == nil {
		return noFD, errors.New("kernel: SchedTimer requires a function")
	}
	if spec.DelayMillis < 0 {
		return noFD, errors.New("kernel: SchedTimer requires a non-negative delay")
	}
	if len(spec.Label) > maxSchedLabelLen {
		return noFD, schedLimitErr("label longer than %d bytes", maxSchedLabelLen)
	}
	if err := admissionBlocked(c.pid); err != nil {
		return noFD, err
	}

	if err := reserveTimer(c, spec.Label); err != nil {
		return noFD, err
	}

	timeout := callCeiling(0)
	delay := time.Duration(spec.DelayMillis) * time.Millisecond
	fireAt := mono() + delay.Nanoseconds()
	r := newRun(c.pid, kindTimer, spec.Label, fireAt+timeout.Nanoseconds())
	r.setState(SchedPending)
	r.timerSlot.Store(true)

	fd, err := install(c.pid, r, spec.Label)
	if err != nil {
		releaseTimer(c.pid)
		r.timerSlot.Store(false)
		fault(c, "timer refused by the handle ceiling",
			map[string]any{"label": spec.Label, "error": err.Error()})
		return noFD, err
	}

	r.arm(c, spec.Fn, delay, timeout)
	return fd, nil
}

// SchedWait blocks until the run behind a handle reaches a terminal state and
// returns a copy of its outcome.
//
// It waits at most the sealed call ceiling, so a module that waits on a job which
// ignores cancellation gets an answer instead of a hang: the returned state is
// SchedRunning and the run stays registered with kwatchdog, which is the party that
// can still act on it.
//
// Requires no operation. Waiting on your own handle is not a capability, and the
// handle resolves only inside the caller's own pid table.
func SchedWait(ctx SContext, fd FD) (SchedOutcome, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return SchedOutcome{}, errors.New("kernel: SchedWait requires a kernel-issued context")
	}
	if err := c.syscall(""); err != nil {
		return SchedOutcome{}, err
	}
	r, err := schedRunFor(c.pid, fd)
	if err != nil {
		return SchedOutcome{}, err
	}

	select {
	case <-r.completion():
		return r.snapshot(), nil
	case <-time.After(callCeiling(0)):
		out := r.snapshot()
		out.Detail = "wait exceeded the call ceiling; the run is still supervised by kwatchdog"
		return out, nil
	}
}

// SchedCount reports how many supervised runs are in flight and how many timers are
// armed for a pid, for the console dump and for a leak check in tests.
func SchedCount(pid PID) (running int, timers int) {
	schedMu.Lock()
	defer schedMu.Unlock()
	return schedLive[pid], schedTimers[pid]
}

// newRun builds an unregistered run. The fd table takes ownership on install.
func newRun(pid PID, kind, label string, deadline int64) *schedRun {
	return &schedRun{
		id:       schedSeq.Add(1),
		pid:      pid,
		kind:     kind,
		label:    label,
		deadline: deadline,
		cancel:   make(chan struct{}),
		state:    SchedRunning,
		finished: make(chan struct{}),
	}
}

// completion returns the channel closed when the run reaches a terminal state.
func (r *schedRun) completion() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finished
}

// setState moves the run to a new state, unless it has already reached a terminal
// one. Without that guard a timer callback that lost a race with Close would flip the
// recorded state back to running after a caller had already read "cancelled", and the
// outcome the kernel handed out would no longer be the one it holds.
func (r *schedRun) setState(s SchedState) {
	if r.settled.Load() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.settled.Load() {
		return
	}
	r.state = s
}

func (r *schedRun) deadlineNow() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deadline
}

func (r *schedRun) setDeadline(d int64) {
	if r.settled.Load() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.settled.Load() {
		return
	}
	r.deadline = d
}

// callCeiling clamps a module-requested timeout to the sealed trust root. A request
// for less is honoured; a request for more is not, and neither is a request for
// none.
func callCeiling(requestedMillis int64) time.Duration {
	ceiling := time.Duration(Limits().CallTimeoutMillis) * time.Millisecond
	if ceiling <= 0 {
		// An unsealed or zero-valued root must not produce a zero deadline, which
		// would make every run instantly expired.
		ceiling = defaultCallCeiling
	}
	if requestedMillis <= 0 {
		return ceiling
	}
	return min(time.Duration(requestedMillis)*time.Millisecond, ceiling)
}

// defaultCallCeiling is the fallback when the trust root carries no ceiling.
const defaultCallCeiling = 30 * time.Second

// reserveLive takes one slot in the per-pid bound on supervised runs.
//
// The number is the same sealed ceiling that bounds a module's in-flight
// operations, but ksched keeps its own counter rather than sharing one with
// admission control. Acquiring a concurrency slot is a module's admission decision
// about serving a request; this is the kernel's own bound on goroutines it starts
// on a module's behalf. One shared counter would let a module that never acquires a
// slot exhaust the scheduler anyway, and would leak a slot whenever a spawn is
// refused after the acquire.
func (r *schedRun) reserveLive(c *sContext) error {
	limit := Limits().MaxSlotsPerModule
	if limit <= 0 {
		limit = defaultLimits().MaxSlotsPerModule
	}

	schedMu.Lock()
	full := schedLive[c.pid] >= limit
	if !full {
		schedLive[c.pid]++
		r.holdsSlot.Store(true)
	}
	schedMu.Unlock()
	if !full {
		return nil
	}

	// Reported outside the lock: a refusal is written to the console and to the
	// audit chain, and neither of those may serialize every other spawn.
	err := schedLimitErr("pid %d has the maximum of %d supervised runs in flight", c.pid, limit)
	fault(c, "supervised spawn refused by quota",
		map[string]any{"label": r.label, "error": err.Error()})
	kaudit.record(AuditReject, c, "supervised spawn refused by quota", map[string]any{
		"label": r.label, "kind": r.kind, "max_slots_per_module": limit,
	})
	return err
}

// releaseSlot gives back the run's supervised-run slot, at most once.
func (r *schedRun) releaseSlot() {
	if r.holdsSlot.Swap(false) {
		releaseLive(r.pid)
	}
}

func reserveTimer(c *sContext, label string) error {
	schedMu.Lock()
	full := schedTimers[c.pid] >= maxLiveTimersPerPID
	if !full {
		schedTimers[c.pid]++
	}
	schedMu.Unlock()
	if !full {
		return nil
	}

	err := schedLimitErr("pid %d holds the maximum of %d armed timers", c.pid, maxLiveTimersPerPID)
	fault(c, "timer refused by quota", map[string]any{"label": label, "error": err.Error()})
	return err
}

func releaseLive(pid PID) {
	schedMu.Lock()
	defer schedMu.Unlock()
	if schedLive[pid] > 0 {
		schedLive[pid]--
	}
	if schedLive[pid] == 0 {
		delete(schedLive, pid)
	}
}

func releaseTimer(pid PID) {
	schedMu.Lock()
	defer schedMu.Unlock()
	if schedTimers[pid] > 0 {
		schedTimers[pid]--
	}
	if schedTimers[pid] == 0 {
		delete(schedTimers, pid)
	}
}

// arm schedules the timer callback.
func (r *schedRun) arm(c *sContext, fn SchedFunc, delay, timeout time.Duration) {
	t := time.AfterFunc(delay, func() {
		if r.timerSlot.Swap(false) {
			releaseTimer(r.pid)
		}
		if r.settled.Load() {
			// Already terminal: cancelled by Close, or by a signal that reached
			// the module while this timer was still armed. Firing now would
			// resurrect a run the kernel has already reported as finished.
			return
		}
		if r.closedFlag.done() || r.settled.Load() {
			// Cancelled between arming and firing. The run never became work.
			r.finish(SchedCancelled, r.cancelReason(), "")
			return
		}
		// A timer that fires becomes in-flight work, and in-flight work is
		// bounded. Taking the slot only at spawn time would let a module arm
		// maxLiveTimersPerPID timers that all fire at once and run that many
		// goroutines past the ceiling it was given. The refusal is recorded
		// rather than silently dropping the callback, because a timer that never
		// runs and never reports is indistinguishable from one the kernel lost.
		if err := r.reserveLive(c); err != nil {
			r.finish(SchedCancelled, "supervised run limit reached when the timer fired", "")
			return
		}
		go r.supervise(c, fn, timeout)
	})
	r.armed.Store(t)

	// A cancellation that raced the arm must still stop the timer.
	if r.closedFlag.done() {
		t.Stop()
	}
}

// supervise owns one run's deadline. It is kernel code, and the module's function
// runs on a separate goroutine underneath it, so the deadline is enforced by a party
// the module cannot influence.
//
// The supervisor gives up waiting after a grace period rather than blocking forever
// on a function that ignores cancellation. Giving up does not stop the goroutine -
// nothing in Go can - but it ends the kernel's accounting for the run, records the
// timeout with a stack snapshot as evidence, and leaves kwatchdog to ask for the
// module to be terminated.
func (r *schedRun) supervise(c *sContext, fn SchedFunc, timeout time.Duration) {
	r.started.Store(true)
	if r.kind == kindTimer {
		// The timer stops being a pending timer and becomes in-flight work with
		// its own deadline starting now.
		r.setDeadline(mono() + timeout.Nanoseconds())
		r.setState(SchedRunning)
	}

	deadline := r.deadlineNow()
	remaining := time.Duration(deadline - mono())
	if remaining < 0 {
		remaining = 0
	}
	timer := time.AfterFunc(remaining, func() { r.cancelOnce(cancelByDeadline) })
	defer timer.Stop()

	// The patrol deadline sits behind the supervisor's own, not on it. This
	// supervisor is the first line of defence: it knows the deadline to the
	// nanosecond, it abandons the run a grace period after it passes, and it
	// records the outcome. kwatchdog is the backstop for the case where this
	// supervisor is itself the thing that is stuck - wedged on a lock, starved,
	// or gone because the goroutine that owned it panicked outside the recover.
	// Registering both at the same instant would make the backstop fire first in
	// the ordinary case, and then a routine timeout would be reported as a hang
	// and the recorded state would depend on which of the two got scheduled.
	ticket := watchdogRegisterAt(r.kind, r.pid, r.label, r.id, deadline+watchdogBackstop().Nanoseconds())

	work := make(chan runResult, 1)
	go func() { work <- r.invoke(c, fn, ticket) }()

	select {
	case res := <-work:
		r.record(res)
		r.finish(res.state, res.detail, res.stack)
		ticket.Release()
	case <-r.cancel:
		// Ask once more, briefly. A function that returns during the grace period
		// gets its real result recorded, which is the difference between evidence
		// that says "it was slow" and evidence that says "it never listens".
		select {
		case res := <-work:
			if res.state == SchedCompleted {
				res.state = r.cancelledState()
				res.detail = r.cancelReason() + "; returned after cancellation"
			}
			r.record(res)
			r.finish(res.state, res.detail, res.stack)
			ticket.Release()
		case <-time.After(watchdogGrace()):
			// Abandoned. The goroutine is still running and the kernel has
			// stopped accounting for it, so the patrol deliberately stays
			// registered: from here kwatchdog is the only party that can still
			// see this work, and its detection ends in a termination request.
			// Releasing the ticket here would be releasing the only witness.
			r.finish(r.cancelledState(), r.cancelReason(), watchdogStackOf(r.gid.Load()))
		}
	}
}

// cancelledState maps the cancellation cause onto the state an operator reads. A
// deadline is a timeout; anything else was a deliberate stop.
func (r *schedRun) cancelledState() SchedState {
	if r.cancelReason() == cancelByDeadline {
		return SchedTimedOut
	}
	return SchedCancelled
}

// invoke runs the module's function with panics recovered. This is the only place a
// supervised panic is caught, and catching it here is what keeps one module's defect
// from becoming a host-process crash.
func (r *schedRun) invoke(c *sContext, fn SchedFunc, ticket watchdogTicket) (res runResult) {
	gid := watchdogGoroutineID()
	r.gid.Store(gid)
	// Publishing the goroutine id is what lets the watchdog snapshot this run's
	// frames rather than a whole-process dump when it detects an overrun. Only the
	// running goroutine knows its own id, so it is published from here.
	ticket.SetGoroutine(gid)

	res.start = mono()
	defer func() {
		res.elapsed = mono() - res.start
		if p := recover(); p != nil {
			res.state = SchedPanicked
			res.detail = fmt.Sprint(p)
			res.stack = watchdogCurrentStack()
			fault(c, "supervised run panicked", map[string]any{
				"label": r.label, "run": r.id, "panic": res.detail,
			})
			kaudit.record(AuditPanic, c, "supervised run panicked", map[string]any{
				"label": r.label, "run": r.id, "panic": res.detail,
			})
		}
	}()

	fn(c, r.cancel)
	res.state = SchedCompleted
	return res
}

// record stores the kernel's own timing for the run.
func (r *schedRun) record(res runResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.start = res.start
	r.elapsed = res.elapsed
}

// finish closes out a run exactly once. Callers may race - the worker, the
// cancellation path, Close, the watchdog - and the first one to arrive owns the
// record.
func (r *schedRun) finish(state SchedState, detail, stack string) {
	r.mu.Lock()
	if r.settled.Swap(true) {
		r.mu.Unlock()
		return
	}
	r.state = state
	r.detail = detail
	r.stack = watchdogTruncate(stack)
	close(r.finished)
	kind, pid, label, id := r.kind, r.pid, r.label, r.id
	r.mu.Unlock()

	r.releaseSlot()

	// A run the module closed itself is not something an operator needs to see:
	// cancelling your own handle is the documented way to stop work you started.
	// What the console line exists for is the kernel having stopped waiting on
	// module code that would not stop.
	if state != SchedCompleted && detail != cancelByHandle {
		kconsole.Emit(LogWarn, pid, DomainPlugin, "supervised run did not complete", map[string]any{
			"run": id, "kind": kind, "label": label, "state": string(state), "detail": detail,
		})
	}
}

// snapshot copies the outcome under the lock.
func (r *schedRun) snapshot() SchedOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return SchedOutcome{
		ID: r.id, Label: r.label, Kind: r.kind, State: r.state, Detail: r.detail,
		StartedAt: r.start, ElapsedNanos: r.elapsed, Deadline: r.deadline, Stack: r.stack,
	}
}

// schedRunFor resolves a handle to a supervised run inside one pid's table. A handle
// from another module's table does not resolve, which is the isolation a handle gives
// and an object pointer would not.
func schedRunFor(pid PID, fd FD) (*schedRun, error) {
	e, err := lookup(pid, fd)
	if err != nil {
		return nil, err
	}
	r, ok := e.res.(*schedRun)
	if !ok {
		return nil, fmt.Errorf("kernel: fd %d is a %s, not a supervised run", fd, e.kind)
	}
	return r, nil
}

// cancelSchedWork cancels every supervised run and armed timer a pid holds. It is
// the ksched half of a kernel-initiated termination: the module's own goroutines are
// out of reach, but the ones the kernel started are not.
func cancelSchedWork(pid PID, reason string) int {
	cancelled := 0
	for _, info := range FDList(pid) {
		if info.Kind != kindJob && info.Kind != kindTimer {
			continue
		}
		e, err := lookup(pid, info.FD)
		if err != nil {
			continue
		}
		r, ok := e.res.(*schedRun)
		if !ok {
			continue
		}
		r.cancelOnce(reason)
		// A pending timer has no supervisor goroutine waiting on its cancel
		// channel, so closing the channel alone would leave the run unfinished
		// until the timer fired - and a caller reading the outcome would see
		// "still running" for work the kernel has already abandoned. Finish it
		// here, which is the same thing the supervisor would have done.
		if !r.started.Load() && r.timerSlot.Swap(false) {
			releaseTimer(r.pid)
			r.finish(SchedCancelled, reason, "")
		}
		cancelled++
	}
	return cancelled
}

// resetSched clears ksched state for a fresh boot. Called only from resetKernel.
//
// Every live run is cancelled before the counters are dropped. Clearing the counters
// alone would leave goroutines from the previous boot running against a kernel that
// no longer knows their pid, and they would then be accounted to whatever the next
// boot allocates at the same number - exactly the confusion pid monotonicity exists
// to prevent.
//
// It must run before resetFDTables(), because cancelling walks the handle table.
func resetSched() {
	schedMu.Lock()
	seen := map[PID]bool{}
	pids := make([]PID, 0, len(schedLive)+len(schedTimers))
	for pid := range schedLive {
		seen[pid] = true
		pids = append(pids, pid)
	}
	for pid := range schedTimers {
		if !seen[pid] {
			pids = append(pids, pid)
		}
	}
	schedLive = map[PID]int{}
	schedTimers = map[PID]int{}
	schedMu.Unlock()

	for _, pid := range pids {
		cancelSchedWork(pid, "kernel reset")
	}
	schedSeq.Store(0)
}

// SyscallSched is the supervised-execution half of the syscall surface.
type SyscallSched interface {
	// SyscallSchedSpawn asks the kernel to run a function under the caller's own
	// context, a deadline clamped to the sealed ceiling, and panic recovery, and
	// returns a handle to the run. Requires sched:spawn.
	SyscallSchedSpawn(job SchedJob) (FD, error)
	// SyscallSchedTimer arms a single-shot callback after a delay measured on
	// mono(). Requires sched:timer. Closing the returned handle cancels it.
	SyscallSchedTimer(spec TimerSpec) (FD, error)
	// SyscallSchedWait blocks until a run reaches a terminal state and returns a
	// copy of its outcome. Requires no operation, and the handle resolves only
	// inside the caller's own pid.
	SyscallSchedWait(fd FD) (SchedOutcome, error)
}
