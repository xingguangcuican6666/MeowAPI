package kernel

// kwatchdog: hang detection. The analogue of a kernel soft-lockup detector and a
// hardware watchdog timer: work that was supposed to finish by a deadline and did
// not is noticed by someone other than the party that missed the deadline, and the
// response does not depend on that party cooperating.
//
// WHY THIS EXISTS
//
// Every deadline in the kernel is enforced by a goroutine waiting on a timer. If the
// waiter is itself the thing that hangs, the deadline is never observed and the
// kernel's own accounting goes quiet - which looks exactly like a healthy system with
// nothing in flight. kwatchdog is the third party. It keeps a registry of work the
// kernel is running on a module's behalf, together with the mono() value at which
// each piece of that work was required to finish, and sweeps the registry on an
// interval derived from the sealed ceiling.
//
// When a sweep finds an overdue entry it does three things, in this order: records an
// audit event naming the pid, the label and how far past the deadline it is; captures
// a stack snapshot of the offending goroutine with runtime.Stack, so the evidence says
// where the code was stuck rather than only that it was; and asks for the module to be
// terminated through the same teardown path ksignal uses, so the handles are reclaimed
// and the process-table record is closed.
//
// WHAT IT CANNOT DO, STATED PLAINLY
//
// The watchdog sees work registered with it. That is work the kernel started - a
// supervised run from ksched, a timer callback, a signal handler - and any deadline
// another subsystem registers here, such as a pipe read or a lock wait. It cannot see,
// and therefore cannot preempt, a goroutine a module started itself with the standard
// library. Go offers no mechanism by which in-process code can interrupt an arbitrary
// goroutine, so a detection-only guarantee is the honest one: the watchdog detects and
// reports a hang in work the kernel is running, and requests termination of the module
// responsible. It does not stop the hung goroutine, and nothing here should be
// described as doing so.
//
// WIRING - nothing to paste into kernel/context.go. kwatchdog exposes no syscall and
// has no operation of its own in the policy table, because a module never asks the
// kernel to police it. Other kernel subsystems reach it through WatchdogRegister;
// tests, the console dump and an operator console reach it through WatchdogPatrol
// and WatchdogSnapshot.
//
// RESET - resetKernel() in kernel/kernel.go must call, in this order and before the
// existing resetFDTables():
//
//	resetWatchdog()
//	resetSched()
//	resetSignals()

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WatchdogEvent is one recorded detection. It is the evidence an operator reads to
// find out why a module was terminated.
type WatchdogEvent struct {
	// Seq orders events within a boot.
	Seq int64 `json:"seq"`
	// At is the mono() reading when the sweep detected the overrun.
	At int64 `json:"at"`
	// Kind is the registered work type: job, timer, signal, pipe, lock.
	Kind string `json:"kind"`
	// PID is the module the kernel was acting for.
	PID PID `json:"pid"`
	// Label is the diagnostic name the registering subsystem supplied.
	Label string `json:"label,omitempty"`
	// RunID is the ksched run id, or 0 for work registered without one.
	RunID int64 `json:"run_id,omitempty"`
	// Deadline is the mono() value the work was required to finish by.
	Deadline int64 `json:"deadline"`
	// OverdueNanos is how far past the deadline the sweep found it.
	OverdueNanos int64 `json:"overdue_nanos"`
	// Stack is the snapshot of the offending goroutine, truncated to
	// MaxWatchdogStackBytes.
	Stack string `json:"stack,omitempty"`
}

// MaxWatchdogStackBytes bounds the stack snapshot kept with an event and echoed into
// console records. A full goroutine dump can be hundreds of kilobytes, and neither
// the audit chain nor the console retention is a place for one.
const MaxWatchdogStackBytes = 8192

// MaxWatchdogEvents bounds retained detection events, so a module that hangs
// repeatedly cannot grow kernel memory by being detected over and over. The oldest are
// dropped. Exported because an operator sizing an audit pipeline needs to know how much
// history the kernel keeps on its own.
const MaxWatchdogEvents = 256

// minWatchdogInterval and maxWatchdogInterval bound the sweep period however the
// sealed ceiling is configured. A ceiling of zero must not produce a busy loop, and a
// ceiling of an hour must not leave a hang undetected for an hour.
const (
	minWatchdogInterval = 10 * time.Millisecond
	maxWatchdogInterval = 2 * time.Second
)

// kindSignal is the registration kind ksignal uses for a module's handler.
const kindSignal = "signal"

// watchdogEntry is one registered piece of in-flight work.
type watchdogEntry struct {
	seq      int64
	kind     string
	pid      PID
	label    string
	runID    int64
	deadline atomic.Int64
	// gid is the goroutine running the work, published by that goroutine once it
	// starts. Zero means unknown, and the snapshot falls back to the reporting
	// goroutine's own stack.
	gid atomic.Uint64
	// released makes Release idempotent, which matters because the paths that end
	// a run - completion, cancellation, close, unload - can race.
	released atomic.Bool
}

var (
	watchdogMu       sync.Mutex
	watchdogEntries  = map[int64]*watchdogEntry{}
	watchdogEvents   []WatchdogEvent
	watchdogSeq      atomic.Int64
	watchdogEventSeq atomic.Int64

	watchdogStartMu sync.Mutex
	watchdogRunning atomic.Bool
	watchdogStop    chan struct{}
	watchdogSweeps  atomic.Int64
	watchdogFound   atomic.Int64
)

// watchdogTicket is a registration held by the subsystem whose work is being
// patrolled. Release ends the patrol; Extend moves the deadline forward, which is how
// a subsystem with a long-lived but live wait - a pipe read that keeps receiving -
// avoids being reported as hung.
//
// The ticket and its constructor are unexported on purpose, and that is a security
// decision rather than a style one. Registration names a pid and a deadline, and the
// only thing the patrol does with an overdue entry is ask for that module to be
// terminated. An exported registration function would therefore be an exported
// terminate-any-pid function: a module holding no operation at all could patrol a
// victim with a deadline already in the past and have the kernel tear it down. Keeping
// it inside package kernel means the callers are the subsystems that computed the
// deadline they are registering, and there is no call shape in which a module reaches
// it.
//
// A ticket value may be copied and used from several goroutines. Its methods touch
// only atomics and the registry lock, so SetGoroutine from the worker and Release from
// the supervisor cannot race.
type watchdogTicket struct{ e *watchdogEntry }

// SetGoroutine publishes the goroutine id whose frames should be snapshotted if this
// work is detected as hung. The work itself calls it, since only the running
// goroutine knows its own id.
func (t watchdogTicket) SetGoroutine(gid uint64) {
	if t.e != nil {
		t.e.gid.Store(gid)
	}
}

// Extend moves the deadline to timeout from now. A shorter deadline is ignored: a
// subsystem cannot accidentally shrink another's window, and a deadline that only ever
// moves forward cannot be made to retroactively expire.
func (t watchdogTicket) Extend(timeout time.Duration) {
	if t.e == nil || timeout <= 0 {
		return
	}
	want := mono() + timeout.Nanoseconds()
	for {
		cur := t.e.deadline.Load()
		if want <= cur {
			return
		}
		if t.e.deadline.CompareAndSwap(cur, want) {
			return
		}
	}
}

// Release ends the patrol for this work. Calling it more than once is harmless.
func (t watchdogTicket) Release() {
	if t.e == nil || t.e.released.Swap(true) {
		return
	}
	watchdogMu.Lock()
	delete(watchdogEntries, t.e.seq)
	watchdogMu.Unlock()
}

// watchdogRegister puts in-flight work under patrol, with a deadline timeout from now
// measured on mono().
//
// This is the entry point for the other kernel subsystems that hold deadlines on a
// module's behalf - kpipe, klock, kevent - so a hang in any of them is detected by the
// same sweeper and reported in the same shape. It is unexported; see watchdogTicket for
// why that is the control and not an oversight.
func watchdogRegister(kind string, pid PID, label string, runID int64, timeout time.Duration) watchdogTicket {
	if timeout <= 0 {
		timeout = callCeiling(0)
	}
	return watchdogRegisterAt(kind, pid, label, runID, mono()+timeout.Nanoseconds())
}

// watchdogRegisterAt is the absolute-deadline form. ksched and ksignal use it because
// they have already computed the deadline they will enforce, and registering a second,
// independently computed one would let the two disagree.
func watchdogRegisterAt(kind string, pid PID, label string, runID int64, deadline int64) watchdogTicket {

	e := &watchdogEntry{
		seq: watchdogSeq.Add(1), kind: kind, pid: pid, label: label, runID: runID,
	}
	e.deadline.Store(deadline)

	watchdogMu.Lock()
	watchdogEntries[e.seq] = e
	watchdogMu.Unlock()

	watchdogEnsureRunning()
	return watchdogTicket{e: e}
}

// watchdogInterval derives the sweep period from the sealed ceiling. A tenth of the
// ceiling means an overrun is reported promptly relative to the timeout it violated,
// and the clamps keep a pathological ceiling from producing either a busy loop or a
// detector that never runs.
func watchdogInterval() time.Duration {
	ceiling := time.Duration(Limits().CallTimeoutMillis) * time.Millisecond
	if ceiling <= 0 {
		ceiling = defaultCallCeiling
	}
	return max(minWatchdogInterval, min(ceiling/10, maxWatchdogInterval))
}

// watchdogGrace is how long ksched waits after cancelling a run before it stops
// accounting for it. One sweep interval: long enough that a function on its way out is
// recorded with its real result, short enough that the kernel does not block behind a
// function that has already ignored its cancellation.
func watchdogGrace() time.Duration { return min(watchdogInterval(), maxWatchdogGrace) }

// maxWatchdogGrace caps the grace period however the sealed ceiling is configured. The
// grace is how long the kernel waits on a function that has already ignored its
// cancellation, and spending a whole sweep interval on a goroutine the kernel has given
// up on would slow every timeout by that much under a generous ceiling.
const maxWatchdogGrace = 250 * time.Millisecond

// watchdogBackstop is how far behind a run's own deadline its patrol deadline sits.
//
// ksched's supervisor enforces the deadline first, because it is the party holding the
// timer and it can record the run's real outcome. kwatchdog exists for the case where
// that supervisor is itself wedged, so its deadline has to be later - otherwise a
// routine timeout would be reported as a hang, and which of the two won would depend on
// scheduling. Three sweep intervals is enough for the supervisor to abandon the run and
// release its ticket in the ordinary case, and short enough that a wedged supervisor is
// still caught promptly.
func watchdogBackstop() time.Duration { return watchdogGrace() + 3*watchdogInterval() }

// watchdogEnsureRunning starts the patrol goroutine on first registration. It is lazy
// because resetWatchdog stops the patrol, and a subsystem must not have to know
// whether the kernel has booted in order to register work safely.
func watchdogEnsureRunning() {
	if watchdogRunning.Load() {
		return
	}
	watchdogStartMu.Lock()
	defer watchdogStartMu.Unlock()
	if watchdogRunning.Load() {
		return
	}
	watchdogStop = make(chan struct{})
	watchdogRunning.Store(true)
	go watchdogPatrolLoop(watchdogStop)
}

// watchdogPatrolLoop sweeps until stopped. The interval is re-derived each time rather
// than fixed for the life of the goroutine, so a restart under a different sealed
// ceiling patrols at that ceiling's rate.
func watchdogPatrolLoop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(watchdogInterval()):
		}
		WatchdogPatrol()
	}
}

// WatchdogPatrol runs one sweep now and returns how many overdue entries it acted on.
// The background loop calls it; an operator console and tests call it directly, which
// is what makes detection verifiable without waiting on a timer.
//
// It is safe to call from a module and deliberately so: it registers nothing and takes
// no pid, so the worst a caller can do is sweep early and find nothing overdue. The
// read-only exports below are the same shape - they report what the kernel already
// recorded, and grant no ability to change it.
//
// A sweep collects the overdue entries under the lock and acts on them outside it.
// Acting means capturing a stack, writing an audit entry and starting a teardown, and
// none of those may hold the registry lock: a teardown reclaims handles, and closing a
// handle releases a ticket, which takes the same lock.
func WatchdogPatrol() int {
	watchdogSweeps.Add(1)
	now := mono()

	watchdogMu.Lock()
	var overdue []*watchdogEntry
	for _, e := range watchdogEntries {
		if now >= e.deadline.Load() {
			overdue = append(overdue, e)
		}
	}
	// Removed from the registry before acting, so a second sweep - the background
	// loop runs concurrently with a manual call - cannot report the same hang twice
	// or start two teardowns for it.
	for _, e := range overdue {
		delete(watchdogEntries, e.seq)
	}
	watchdogMu.Unlock()

	sort.Slice(overdue, func(i, j int) bool { return overdue[i].seq < overdue[j].seq })
	for _, e := range overdue {
		watchdogReport(e, now)
	}
	return len(overdue)
}

// watchdogReport records one detection and requests termination.
func watchdogReport(e *watchdogEntry, now int64) {
	deadline := e.deadline.Load()
	stack := watchdogStackOf(e.gid.Load())

	ev := WatchdogEvent{
		Seq: watchdogEventSeq.Add(1), At: now, Kind: e.kind, PID: e.pid, Label: e.label,
		RunID: e.runID, Deadline: deadline, OverdueNanos: now - deadline, Stack: stack,
	}

	watchdogMu.Lock()
	watchdogEvents = append(watchdogEvents, ev)
	if len(watchdogEvents) > MaxWatchdogEvents {
		watchdogEvents = append([]WatchdogEvent(nil),
			watchdogEvents[len(watchdogEvents)-MaxWatchdogEvents:]...)
	}
	watchdogMu.Unlock()

	watchdogFound.Add(1)
	fault(nil, "watchdog: in-flight work exceeded its deadline", map[string]any{
		"pid": e.pid, "kind": e.kind, "label": e.label,
		"overdue_ms": (now - deadline) / int64(time.Millisecond),
	})
	kaudit.record(AuditPolicy, nil, "watchdog detected a hang", map[string]any{
		"pid": e.pid, "kind": e.kind, "label": e.label, "run_id": e.runID,
		"deadline": deadline, "overdue_nanos": now - deadline,
	})

	// The request goes through ksignal's teardown, so a watchdog detection and an
	// operator kill produce the same audit record, the same handle reclamation and
	// the same process-table transition. A detector that invented its own teardown
	// would be a second, less-reviewed path to the same destructive action.
	//
	// Pid 0 and init are excluded, for the same reason ksignal refuses them as
	// targets. Init holds sched:spawn, so init can have supervised work that overruns,
	// and condemning it would mean a hung module job could end the sequence that
	// decides what code runs. The detection is still recorded - the evidence is the
	// point of the event - but the destructive half stops at the same boundary the
	// signal path stops at.
	if !watchdogTerminable(e.pid) {
		fault(nil, "watchdog: refusing to terminate a kernel-owned pid", map[string]any{
			"pid": e.pid, "kind": e.kind, "label": e.label,
		})
		kaudit.record(AuditDenial, nil, "watchdog termination refused for a kernel-owned pid",
			map[string]any{
				"op": "watchdog:terminate", "pid": e.pid, "kind": e.kind, "label": e.label,
				"reason": "pid 0 and init are never terminated on a module's account",
			})
		return
	}

	terminateModule(e.pid,
		fmt.Sprintf("watchdog: %s %q exceeded its deadline", e.kind, e.label), true)
}

// watchdogTerminable reports whether a pid may be torn down by the kernel on a
// detection. Only a live module qualifies: pid 0 is the kernel's own retired root
// context, init is the sequence that supervises everything else, and a pid with no
// running record is a detection for work whose owner is already gone.
func watchdogTerminable(pid PID) bool {
	if pid <= 0 {
		return false
	}
	for _, r := range ProcTable() {
		if r.PID != pid {
			continue
		}
		if r.State != ProcRunning {
			return false
		}
		return r.Domain != DomainKernel && r.Domain != DomainInit
	}
	return false
}

// WatchdogSnapshot returns retained detection events oldest first, plus the sweep and
// detection counters. The events are copies; the stack strings are already truncated.
func WatchdogSnapshot() (events []WatchdogEvent, sweeps int64, detected int64) {
	watchdogMu.Lock()
	events = make([]WatchdogEvent, len(watchdogEvents))
	copy(events, watchdogEvents)
	watchdogMu.Unlock()

	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })
	return events, watchdogSweeps.Load(), watchdogFound.Load()
}

// WatchdogLive reports how many pieces of work are currently under patrol. It is the
// number an operator reads to tell "nothing is running" from "the detector is not
// looking".
func WatchdogLive() int {
	watchdogMu.Lock()
	defer watchdogMu.Unlock()
	return len(watchdogEntries)
}

// watchdogGoroutineID returns the calling goroutine's id, parsed from the first line
// of its own stack.
//
// The runtime does not export this and parsing it is the standard substitute. It is
// used only to choose which goroutine's frames to snapshot - a diagnostic choice - and
// never in a policy decision or as an identity, so the fragility of the parse is
// contained: if the format ever changes the id comes back zero and the snapshot falls
// back to the reporting goroutine.
func watchdogGoroutineID() uint64 {
	var buf [128]byte
	n := runtime.Stack(buf[:], false)
	return watchdogParseGoroutineID(string(buf[:n]))
}

// watchdogParseGoroutineID reads the id out of a stack header.
//
// The header is "goroutine <id> <extras> [<state>]:", where the extras field is a
// runtime-internal pointer that has appeared and changed shape across Go releases.
// The id is therefore read positionally as the second field and compared numerically
// elsewhere, rather than by prefix-matching a reconstructed header string: a prefix
// match that assumes the shape of the trailing fields silently matches nothing after a
// toolchain update, and the failure mode is a snapshot that is empty rather than one
// that is wrong.
func watchdogParseGoroutineID(header string) uint64 {
	line, _, _ := strings.Cut(header, "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "goroutine" {
		return 0
	}
	id, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// watchdogStackOf captures a stack snapshot. With a goroutine id it extracts that
// goroutine's frames from a full dump; with zero it returns the caller's own stack,
// which is the best evidence available when the offending goroutine is unknown.
func watchdogStackOf(gid uint64) string {
	if gid == 0 {
		return watchdogCurrentStack()
	}
	return watchdogTruncate(watchdogExtractStack(gid))
}

// watchdogCurrentStack captures the calling goroutine's stack. ksched uses it in the
// panic path, where the interesting frames are the ones unwinding.
func watchdogCurrentStack() string {
	buf := make([]byte, MaxWatchdogStackBytes)
	n := runtime.Stack(buf, false)
	return watchdogTruncate(string(buf[:n]))
}

// watchdogExtractStack pulls one goroutine's block out of a full dump. runtime.Stack
// with all=true is the only way to reach another goroutine's frames, and it stops the
// world briefly, so it runs once per detection and never on a sweep that found
// nothing.
func watchdogExtractStack(gid uint64) string {
	size := MaxWatchdogStackBytes
	for {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < size || size >= 1<<20 {
			return watchdogSelectGoroutine(string(buf[:n]), gid)
		}
		// The dump did not fit. Grow and retry rather than hand back a truncated
		// whole-process dump that may not contain the goroutine we asked for.
		size *= 2
	}
}

// watchdogSelectGoroutine returns the block whose header names gid.
func watchdogSelectGoroutine(dump string, gid uint64) string {
	for block := range strings.SplitSeq(dump, "\n\n") {
		if watchdogParseGoroutineID(block) == gid {
			return block
		}
	}
	// The goroutine already exited, which is itself the answer: it finished between
	// the sweep and the snapshot. Say so rather than returning some other
	// goroutine's frames and letting a reader attribute them to the wrong code.
	return fmt.Sprintf("goroutine %d is no longer running", gid)
}

// watchdogTruncate bounds a stack string to what the audit chain and the console are
// willing to hold.
func watchdogTruncate(s string) string {
	if len(s) <= MaxWatchdogStackBytes {
		return s
	}
	return s[:MaxWatchdogStackBytes] + "\n... truncated"
}

// resetWatchdog clears kwatchdog state for a fresh boot and stops the patrol. Called
// only from resetKernel.
//
// Stopping the loop matters as much as clearing the maps. A patrol left running from
// the previous boot would sweep an empty registry harmlessly, but a second patrol
// would also start when the new boot registers work, and two loops sweeping one
// registry means one of them finds nothing and an operator counting sweeps cannot
// tell which. A detector whose liveness depends on boot order is not a detector.
func resetWatchdog() {
	watchdogStartMu.Lock()
	if watchdogRunning.Swap(false) && watchdogStop != nil {
		close(watchdogStop)
	}
	watchdogStop = nil
	watchdogStartMu.Unlock()

	watchdogMu.Lock()
	watchdogEntries = map[int64]*watchdogEntry{}
	watchdogEvents = nil
	watchdogMu.Unlock()

	watchdogSeq.Store(0)
	watchdogEventSeq.Store(0)
	watchdogSweeps.Store(0)
	watchdogFound.Store(0)
}
