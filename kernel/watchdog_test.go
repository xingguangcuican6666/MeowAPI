package kernel_test

// Tests for kwatchdog, hang detection.
//
// kwatchdog has no operation of its own in the policy table, and that is deliberate: a
// module never asks the kernel to police it, so there is nothing to grant and no denial
// to write for "may I be watched". The subsystem is reached from inside the kernel by
// the subsystems that hold deadlines, and its module-visible surface is read-only - the
// events it recorded, the sweep and detection counters, the count of work under patrol.
//
// So the "grant" cases here are the two ends of what detection is allowed to do: it must
// end in a termination request for a module whose supervised work overran, and it must
// refuse to do the same to a kernel-owned pid. Everything else asserts the evidence the
// detection produces, because an unrecorded detection is an uninvestigable one.
//
// The subject of these tests is a deadline, so timing is unavoidable. No assertion
// compares two measured durations: each waits for an exact state the kernel will reach,
// so a slow machine makes the test slower and never makes it wrong.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// wdQuiet boots a kernel whose call ceiling is short enough that the sweep interval
// derived from it - and therefore a hang - resolves in tens of milliseconds.
func wdQuiet(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, sink := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 50})
	_ = sink
	return k
}

// wdHang spawns supervised work that ignores its cancellation, which is the only way to
// produce an abandoned run and therefore a detection. A job that returns when cancelled
// is recorded by ksched itself and never reaches the patrol.
func wdHang(t *testing.T, ctx kernel.SContext, label string, block <-chan struct{}) kernel.FD {
	t.Helper()
	fd, err := ctx.SyscallSchedSpawn(kernel.SchedJob{
		Label:         label,
		TimeoutMillis: 20,
		Fn: func(_ kernel.SContext, _ <-chan struct{}) {
			<-block
		},
	})
	require.NoError(t, err)
	return fd
}

// wdAwaitEvents waits until at least n watchdog events exist.
func wdAwaitEvents(t *testing.T, n int) []kernel.WatchdogEvent {
	t.Helper()
	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		events, _, _ := kernel.WatchdogSnapshot()
		return len(events) >= n
	}), "the watchdog never recorded %d events", n)
	events, _, _ := kernel.WatchdogSnapshot()
	return events
}

// TestWatchdogDetectsAnAbandonedRun is the detection path end to end: work the kernel
// was running for a module overran its deadline, the supervisor gave up on it, and the
// patrol - a third party - found it, named it, captured where it was stuck, and asked
// for the module to be terminated.
func TestWatchdogDetectsAnAbandonedRun(t *testing.T) {
	k := wdQuiet(t)
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	fd := wdHang(t, p.captured(), "stuck-in-a-provider-call", block)

	// ksched records the timeout first, with its own evidence.
	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedTimedOut, out.State)

	// The patrol then finds the same run, because the supervisor deliberately left
	// the registration in place: from the moment the kernel stopped accounting for
	// the goroutine, the patrol is the only party that can still see it.
	events := wdAwaitEvents(t, 1)

	var found *kernel.WatchdogEvent
	for i := range events {
		if events[i].PID == pid && events[i].Label == "stuck-in-a-provider-call" {
			found = &events[i]
		}
	}
	require.NotNil(t, found, "the patrol must name the offending run")
	assert.Equal(t, "job", found.Kind)
	assert.Positive(t, found.RunID, "the event must carry the run id an operator can correlate")
	assert.Positive(t, found.OverdueNanos, "the event must say how far past the deadline it was")
	assert.Greater(t, found.At, found.Deadline)
	assert.NotEmpty(t, found.Stack, "a detection without a stack snapshot is not evidence")
	assert.LessOrEqual(t, len(found.Stack), kernel.MaxWatchdogStackBytes)
	assert.Contains(t, found.Stack, "wdHang",
		"the snapshot must name the frames that were stuck, not just that something was")

	// Awaited rather than read straight after the event. The event is appended to
	// the retained list before the audit entry is written, so reading the chain the
	// instant the event appears would race the record that explains it.
	var sawAudit bool
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		for _, e := range kernel.AuditQuery(kernel.AuditFilter{}) {
			if strings.Contains(e.Msg, "watchdog detected a hang") {
				sawAudit = true
				assert.Equal(t, pid, e.Fields["pid"])
				assert.Equal(t, found.Label, e.Fields["label"])
				return true
			}
		}
		return false
	}), "a detection must land on the audit chain")
	assert.True(t, sawAudit)

	// The detection ends in a teardown request, and the request is honoured: the
	// module is gone. This is the whole point of detecting a hang in-process, where
	// the kernel cannot preempt the goroutine itself.
	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.SignalTerminated(pid)
	}), "a detected hang must end in the module being terminated")

	var stillLoaded bool
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			stillLoaded = true
		}
	}
	assert.False(t, stillLoaded)
	assert.Zero(t, kernel.FDCount(pid), "the teardown must reclaim the module's handles")
}

// TestWatchdogRefusesToTerminateKernelOwnedPids is the boundary on the destructive half.
// Init holds sched:spawn, so init can have work that overruns - and a detection there
// must not end the sequence that decides what code runs. The evidence is still recorded;
// only the teardown stops.
func TestWatchdogRefusesToTerminateKernelOwnedPids(t *testing.T) {
	k := wdQuiet(t)

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	fd := wdHang(t, k.InitContext(), "init-work-that-overran", block)

	out, err := k.InitContext().SyscallSchedWait(fd)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedTimedOut, out.State)

	events := wdAwaitEvents(t, 1)
	var found bool
	for _, e := range events {
		if e.PID == kernel.PID(1) && e.Label == "init-work-that-overran" {
			found = true
			assert.NotEmpty(t, e.Stack, "the evidence is recorded even when the teardown is refused")
		}
	}
	assert.True(t, found, "a detection against init must still be recorded")

	// Awaited rather than read straight after the event: the detection is recorded
	// before the termination decision is made, so reading the chain the instant the
	// event appears would race the audit entry that explains it.
	var sawRefusal bool
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial}) {
			if strings.Contains(e.Msg, "watchdog termination refused") {
				sawRefusal = true
				assert.Equal(t, kernel.PID(1), e.Fields["pid"])
				return true
			}
		}
		return false
	}), "refusing to tear down a kernel-owned pid is itself an audited decision")
	assert.True(t, sawRefusal)
	assert.False(t, kernel.SignalTerminated(kernel.PID(1)))

	var initRunning bool
	for _, r := range kernel.ProcTable() {
		if r.PID == 1 {
			assert.Equal(t, kernel.ProcRunning, r.State, "init must still be running")
			initRunning = true
		}
	}
	assert.True(t, initRunning)

	// And the kernel is still usable, which is what the refusal is for.
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)
	fd2, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "after-the-refusal", Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)
	out2, err := p.captured().SyscallSchedWait(fd2)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCompleted, out2.State)
	require.NoError(t, k.Unload(pid))
}

// TestWatchdogLeavesHealthyWorkAlone covers the other half of detection: work that
// finishes inside its deadline must never be reported. A detector that fires on healthy
// work trains operators to ignore it, and then it detects nothing.
func TestWatchdogLeavesHealthyWorkAlone(t *testing.T) {
	k := wdQuiet(t)
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn, kernel.OpSchedTimer)

	for i := range 20 {
		fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
			Label: "healthy-" + schedItoa(i),
			Fn:    func(kernel.SContext, <-chan struct{}) {},
		})
		require.NoError(t, err)
		out, err := p.captured().SyscallSchedWait(fd)
		require.NoError(t, err)
		require.Equal(t, kernel.SchedCompleted, out.State)
		require.NoError(t, p.captured().SyscallClose(fd))
	}

	fired := make(chan struct{}, 1)
	fd, err := p.captured().SyscallSchedTimer(kernel.TimerSpec{
		Label: "healthy-timer", DelayMillis: 5,
		Fn: func(kernel.SContext, <-chan struct{}) {
			select {
			case fired <- struct{}{}:
			default:
			}
		},
	})
	require.NoError(t, err)
	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatal("the timer never fired")
	}
	_, err = p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	require.NoError(t, p.captured().SyscallClose(fd))

	// Give a patrol several chances to run before asserting nothing was reported.
	_, sweeps, _ := kernel.WatchdogSnapshot()
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		_, s, _ := kernel.WatchdogSnapshot()
		return s > sweeps+3
	}), "the patrol must actually be running for this assertion to mean anything")

	events, _, detected := kernel.WatchdogSnapshot()
	assert.Zero(t, detected, "healthy work must never be detected as hung")
	assert.Empty(t, events)
	assert.Zero(t, kernel.WatchdogLive(), "finished work must leave the registry")

	var stillLoaded bool
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			stillLoaded = true
		}
	}
	assert.True(t, stillLoaded)
}

// TestWatchdogRecordsOneEventPerRun covers the registry's integrity. The patrol can run
// concurrently with itself - the background loop and a manual sweep - and one hang must
// produce one event and one teardown request, not two.
func TestWatchdogRecordsOneEventPerRun(t *testing.T) {
	k := wdQuiet(t)
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	fd := wdHang(t, p.captured(), "counted-once", block)
	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedTimedOut, out.State)

	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.SignalTerminated(pid)
	}))

	// Sweep repeatedly and concurrently. The entry is removed from the registry
	// before the patrol acts on it, so none of these may find it again.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				assert.Zero(t, kernel.WatchdogPatrol(),
					"an already-detected run must not be detected again")
			}
		}()
	}
	wg.Wait()

	var matching int
	events, _, detected := kernel.WatchdogSnapshot()
	for _, e := range events {
		if e.PID == pid && e.Label == "counted-once" {
			matching++
		}
	}
	assert.Equal(t, 1, matching, "one hang must produce exactly one event")
	assert.Equal(t, int64(1), detected)

	terminations := 0
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{}) {
		if strings.Contains(e.Msg, "kernel-initiated termination") && e.Fields["target"] == pid {
			terminations++
		}
	}
	assert.Equal(t, 1, terminations, "one hang must produce exactly one teardown request")
}

// TestWatchdogRegistryDoesNotLeak covers the ceiling property: detections clear the
// registry rather than accumulating entries forever, so a module that hangs repeatedly
// cannot grow kernel memory through the detector meant to catch it.
func TestWatchdogRegistryDoesNotLeak(t *testing.T) {
	k := wdQuiet(t)

	const hangs = 6
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	for i := range hangs {
		// A fresh module each time, because the previous one gets terminated.
		_, p := schedLoad(t, k, kernel.OpSchedSpawn)
		fd := wdHang(t, p.captured(), "leak-check-"+schedItoa(i), block)
		out, err := p.captured().SyscallSchedWait(fd)
		require.NoError(t, err)
		require.Equal(t, kernel.SchedTimedOut, out.State)
	}

	events := wdAwaitEvents(t, hangs)
	var seen int
	for _, e := range events {
		if strings.HasPrefix(e.Label, "leak-check-") {
			seen++
			assert.NotEmpty(t, e.Stack)
		}
	}
	assert.Equal(t, hangs, seen, "every abandoned run must be detected")

	// Once the teardowns land, the registry is empty again. An abandoned run keeps
	// its registration until the patrol acts on it, which is what makes the patrol
	// the last witness rather than a redundant one.
	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.WatchdogLive() == 0
	}), "detections must clear the registry; %d entries are still under patrol", kernel.WatchdogLive())

	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.WatchdogPatrol() == 0
	}), "a sweep after every detection must find nothing left")
}

// TestWatchdogPanicIsNotReportedAsAHang keeps the two failure modes distinct. A panic
// is caught by ksched, the run finishes, and its registration is released: reporting it
// as a hang would send a teardown request for a module that already cleaned up after
// itself, and would blur the difference between "it crashed" and "it never stopped".
func TestWatchdogPanicIsNotReportedAsAHang(t *testing.T) {
	k := wdQuiet(t)
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "panics-quickly",
		Fn:    func(kernel.SContext, <-chan struct{}) { panic("not a hang") },
	})
	require.NoError(t, err)

	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedPanicked, out.State)
	require.NotEmpty(t, out.Stack, "the panic path captures its own evidence")

	_, sweeps, _ := kernel.WatchdogSnapshot()
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		_, s, _ := kernel.WatchdogSnapshot()
		return s > sweeps+3
	}))

	events, _, detected := kernel.WatchdogSnapshot()
	assert.Empty(t, events)
	assert.Zero(t, detected, "a recovered panic is not a hang")
	assert.Zero(t, kernel.WatchdogLive())

	var stillLoaded bool
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			stillLoaded = true
		}
	}
	assert.True(t, stillLoaded, "a panicking run must not get its module terminated")
}

// TestWatchdogCancelIsNotReportedAsAHang is the same distinction for the cooperative
// case: a job that returns when its handle is closed is recorded by ksched and leaves
// nothing for the patrol to find.
func TestWatchdogCancelIsNotReportedAsAHang(t *testing.T) {
	k := wdQuiet(t)
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	returned := make(chan struct{})
	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "cooperative-cancel",
		Fn: func(_ kernel.SContext, done <-chan struct{}) {
			<-done
			close(returned)
		},
	})
	require.NoError(t, err)
	require.NoError(t, p.captured().SyscallClose(fd))

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the job never observed its cancellation")
	}

	_, sweeps, _ := kernel.WatchdogSnapshot()
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		_, s, _ := kernel.WatchdogSnapshot()
		return s > sweeps+3
	}))

	_, _, detected := kernel.WatchdogSnapshot()
	assert.Zero(t, detected)
	assert.Zero(t, kernel.WatchdogLive())
	assert.False(t, kernel.SignalTerminated(pid))
}

// TestWatchdogConcurrencyIsRaceFree is the concurrency path. Sweeps run from the patrol
// loop while registrations and releases happen from many goroutines at once, which is
// exactly the interleaving where a registry read outside its lock, or an entry released
// twice, shows up.
func TestWatchdogConcurrencyIsRaceFree(t *testing.T) {
	k := wdQuiet(t)
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn, kernel.OpSchedTimer, kernel.OpSignalSend)

	const goroutines = 8
	const perG = 20
	var wg sync.WaitGroup

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perG {
				fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
					Label: "concurrent-" + schedItoa(i),
					Fn:    func(kernel.SContext, <-chan struct{}) {},
				})
				if err != nil {
					continue
				}
				_, _ = p.captured().SyscallSchedWait(fd)
				_ = p.captured().SyscallClose(fd)
			}
		}()
	}

	// Manual sweeps alongside the background loop.
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				_ = kernel.WatchdogPatrol()
				_, _, _ = kernel.WatchdogSnapshot()
				_ = kernel.WatchdogLive()
			}
		}()
	}

	// And signals, so the handler registration path is exercised concurrently too.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sent := newSentinel(false)
		t.Cleanup(sent.release)
		require.NoError(t, p.captured().SyscallSignalHandle(sent.record))
		for range 50 {
			_ = p.captured().SyscallSignalSend(pid, kernel.SignalReload)
		}
		require.True(t, schedAwait(t, 10*time.Second, func() bool {
			return sent.count() == 50
		}))
	}()

	wg.Wait()

	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.WatchdogLive() == 0
	}), "concurrent healthy work must all leave the registry, %d still under patrol",
		kernel.WatchdogLive())

	events, sweeps, detected := kernel.WatchdogSnapshot()
	assert.Empty(t, events)
	assert.Zero(t, detected)
	assert.Positive(t, sweeps, "the patrol must have been running during the test")

	running, timers := kernel.SchedCount(pid)
	assert.Zero(t, running)
	assert.Zero(t, timers)
}

// TestWatchdogStateDoesNotSurviveRestart is the reset path. Retained events, counters and
// registrations from one boot are evidence about code that no longer exists, and pids
// restart at 1 - so a stale event would name a pid the new boot has given to a different
// module.
func TestWatchdogStateDoesNotSurviveRestart(t *testing.T) {
	k1 := wdQuiet(t)
	pid, p := schedLoad(t, k1, kernel.OpSchedSpawn)

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	fd := wdHang(t, p.captured(), "survives-nothing", block)
	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedTimedOut, out.State)

	_, sweeps1, _ := kernel.WatchdogSnapshot()
	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		events, _, _ := kernel.WatchdogSnapshot()
		return len(events) > 0 || kernel.WatchdogLive() > 0
	}), "the first boot must have watchdog state to clear")
	require.Positive(t, sweeps1)

	require.NoError(t, k1.Shutdown())

	events, sweeps, detected := kernel.WatchdogSnapshot()
	assert.Empty(t, events, "retained events must not survive a restart")
	assert.Zero(t, sweeps, "the sweep counter must not survive a restart")
	assert.Zero(t, detected)
	assert.Zero(t, kernel.WatchdogLive(), "no registration may survive into the next boot")
	assert.False(t, kernel.SignalTerminated(pid))

	k2, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "watchdog-test-2",
			Limits: kernel.BootLimits{CallTimeoutMillis: 50}},
	})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	// The patrol is live again in the new boot, which is the property that matters:
	// a detector that only runs in the boot it was started in is not a detector.
	_, p2 := schedLoad(t, k2, kernel.OpSchedSpawn)
	block2 := make(chan struct{})
	t.Cleanup(func() { close(block2) })
	fd2 := wdHang(t, p2.captured(), "detected-in-the-second-boot", block2)
	out2, err := p2.captured().SyscallSchedWait(fd2)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedTimedOut, out2.State)

	events2 := wdAwaitEvents(t, 1)
	var found bool
	for _, e := range events2 {
		if e.Label == "detected-in-the-second-boot" {
			found = true
			assert.NotEmpty(t, e.Stack)
			assert.Positive(t, e.Seq, "event numbering restarts with the boot")
		}
	}
	assert.True(t, found, "the patrol must detect hangs in a fresh boot")
}

// TestWatchdogStackIsBounded covers the size limit on the evidence itself. A full
// goroutine dump can be hundreds of kilobytes, and neither the audit chain nor the
// console retention is a place for one, so a bounded snapshot is what the kernel keeps.
func TestWatchdogStackIsBounded(t *testing.T) {
	k := wdQuiet(t)
	_, p := schedLoad(t, k, kernel.OpSchedSpawn)

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	fd := wdHang(t, p.captured(), "stack-bound", block)
	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedTimedOut, out.State)

	events := wdAwaitEvents(t, 1)
	for _, e := range events {
		assert.LessOrEqual(t, len(e.Stack), kernel.MaxWatchdogStackBytes,
			"a retained snapshot must respect the documented bound")
	}
	assert.LessOrEqual(t, len(out.Stack), kernel.MaxWatchdogStackBytes)
}
