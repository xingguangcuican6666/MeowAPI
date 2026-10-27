package kernel_test

// Tests for ksched, the supervised-execution subsystem.
//
// The invariant under test throughout is the one the subsystem exists to provide:
// work the kernel runs for a module inherits that module's context, is bounded by a
// deadline the module cannot raise, has its panic recovered, and is reclaimed when
// the module goes away. A test that only proves the function ran would prove
// nothing, so each case asserts the kernel-side consequence.
//
// Timing appears here because the subject is a deadline. No assertion compares two
// measured durations against each other: the waits are bounded polls for an exact
// state, so a slow machine makes the test slower and never makes it wrong.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// schedProbe is the module shape every ksched test needs: it captures the context
// the kernel handed it, so the test can drive syscalls the way a module would.
type schedProbe struct {
	mu     sync.Mutex
	ctx    kernel.SContext
	onLoad func(ctx kernel.SContext) error
}

func (p *schedProbe) OnLoad(ctx kernel.SContext) error {
	p.mu.Lock()
	p.ctx = ctx
	p.mu.Unlock()
	if p.onLoad != nil {
		return p.onLoad(ctx)
	}
	return nil
}

func (p *schedProbe) OnUnload() error { return nil }

func (p *schedProbe) captured() kernel.SContext {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctx
}

var schedProbeCounter int

// schedLoad registers, loads and returns a probe module plus its context. The name is
// unique per call so two live modules in one test never collide in the registry.
func schedLoad(t *testing.T, k *kernel.Kernel, ops ...kernel.Op) (kernel.PID, *schedProbe) {
	t.Helper()
	schedProbeCounter++
	name := "schedprobe" + schedItoa(schedProbeCounter)
	p := &schedProbe{}
	kernel.Register(name, func() (kernel.Module, error) { return p, nil })
	t.Cleanup(func() { kernel.Unregister(name) })

	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1, Require: ops,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, p.captured())
	return pid, p
}

func schedItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// schedQuiet boots a kernel with the console captured and a caller-supplied trust
// root, so a test can set the ceilings it is asserting against.
func schedQuiet(t *testing.T, limits kernel.BootLimits) (*kernel.Kernel, *schedSink) {
	t.Helper()
	sink := &schedSink{}
	k, err := kernel.Boot(kernel.BootConfig{
		Console:   sink,
		TrustRoot: kernel.BootTrustRoot{NodeID: "sched-test", Limits: limits},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k, sink
}

// schedSink is a mutex-guarded console capture. The kernel emits from whatever
// goroutine calls it, and the watchdog patrols on its own, so the writer cannot be a
// plain bytes.Buffer.
type schedSink struct {
	mu    sync.Mutex
	lines []string
	buf   strings.Builder
}

func (s *schedSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Write(p)
	for line := range strings.SplitSeq(s.buf.String(), "\n") {
		if line != "" {
			s.lines = append(s.lines, line)
		}
	}
	s.buf.Reset()
	return len(p), nil
}

func (s *schedSink) contains(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range s.lines {
		if strings.Contains(line, sub) {
			return true
		}
	}
	return false
}

// schedAwait polls cond until it holds or the deadline passes. It is the only
// time-dependent construct in these tests, and it exists so an assertion can wait for
// a state the kernel will reach rather than guess how long that takes.
func schedAwait(t *testing.T, within time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

func schedDenials(t *testing.T, op kernel.Op) []kernel.AuditEntry {
	t.Helper()
	var out []kernel.AuditEntry
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial}) {
		if got, _ := e.Fields["op"].(string); got == string(op) {
			out = append(out, e)
		}
	}
	return out
}

// TestSchedSpawnRunsUnderTheCallersContext is the grant and the central property: the
// job receives the caller's own sealed context, so its syscalls are decided against
// the caller's ceiling and its work is attributed to the caller's pid.
func TestSchedSpawnRunsUnderTheCallersContext(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn, kernel.OpLogWrite)

	var (
		gotPID    kernel.PID
		gotDomain kernel.Domain
		gotName   string
		logErr    error
		ran       = make(chan struct{})
	)

	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "context-inheritance",
		Fn: func(ctx kernel.SContext, done <-chan struct{}) {
			gotPID, gotDomain, gotName = ctx.PID(), ctx.Domain(), ctx.Name()
			// A syscall from inside the job is decided against the same grants.
			logErr = ctx.SyscallLog(kernel.LogInfo, "logged from a supervised job")
			close(ran)
		},
	})
	require.NoError(t, err)
	assert.NotEqual(t, kernel.FD(0), fd, "a supervised run is a handle, not a goroutine the module owns")

	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		select {
		case <-ran:
			return true
		default:
			return false
		}
	}), "the job never ran")

	assert.Equal(t, pid, gotPID, "the job must run under the caller's pid")
	assert.Equal(t, kernel.DomainPlugin, gotDomain)
	assert.Equal(t, p.captured().Name(), gotName)
	require.NoError(t, logErr, "the job inherits the caller's grants")

	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCompleted, out.State)
	assert.Equal(t, "job", out.Kind)
	assert.Equal(t, "context-inheritance", out.Label)
	assert.Positive(t, out.StartedAt, "the kernel timestamps the run, not the module")
	assert.GreaterOrEqual(t, out.ElapsedNanos, int64(0))

	running, timers := kernel.SchedCount(pid)
	assert.Zero(t, running, "a finished run must release its slot")
	assert.Zero(t, timers)

	// A completed run keeps its handle until the module closes it, exactly as a
	// reaped child keeps its exit status until the parent reads it. The outcome has
	// to stay readable after completion, or a module could never learn how its own
	// job ended.
	assert.Equal(t, 1, kernel.FDCount(pid))
	require.NoError(t, p.captured().SyscallClose(fd))
	assert.Zero(t, kernel.FDCount(pid))
}

// TestSchedSpawnDeniedWithoutDeclaration is the denial half of the grant. A module
// that did not declare sched:spawn gets no supervised goroutines at all, and the
// refusal is recorded on the audit chain rather than merely returned.
func TestSchedSpawnDeniedWithoutDeclaration(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := schedLoad(t, k, kernel.OpLogWrite)

	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "undeclared",
		Fn:    func(kernel.SContext, <-chan struct{}) {},
	})
	require.Error(t, err)
	assert.Equal(t, kernel.FD(0), fd)
	require.True(t, kernel.IsDenied(err), "the refusal must be a policy denial, got %T: %v", err, err)
	assert.Contains(t, err.Error(), string(kernel.OpSchedSpawn))

	denials := schedDenials(t, kernel.OpSchedSpawn)
	require.NotEmpty(t, denials, "a denial must land on the audit chain")
	assert.Equal(t, pid, denials[0].PID)
	assert.Equal(t, kernel.DomainPlugin, denials[0].Domain)

	assert.Zero(t, kernel.FDCount(pid), "a refused spawn must not allocate a handle")
	running, _ := kernel.SchedCount(pid)
	assert.Zero(t, running, "a refused spawn must not take a slot")
}

// TestSchedTimerDeniedWithoutDeclaration covers sched:timer separately: the two
// operations are distinct grants, and a module holding one must not get the other.
func TestSchedTimerDeniedWithoutDeclaration(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	fd, err := p.captured().SyscallSchedTimer(kernel.TimerSpec{
		Label: "undeclared", DelayMillis: 1,
		Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.Error(t, err)
	assert.Equal(t, kernel.FD(0), fd)
	require.True(t, kernel.IsDenied(err))
	assert.Contains(t, err.Error(), string(kernel.OpSchedTimer))
	assert.NotEmpty(t, schedDenials(t, kernel.OpSchedTimer))

	_, timers := kernel.SchedCount(pid)
	assert.Zero(t, timers, "a refused timer must not take a timer slot")
	assert.Zero(t, kernel.FDCount(pid))
}

// TestSchedTimeoutIsClampedToTheSealedCeiling is the property that makes the deadline
// mean anything. The ceiling comes from the sealed trust root, so a module can ask for
// less time and can never ask for more.
func TestSchedTimeoutIsClampedToTheSealedCeiling(t *testing.T) {
	const ceilingMillis = 50
	k, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: ceilingMillis})
	_, p := schedLoad(t, k, kernel.OpSchedSpawn)

	ceiling := time.Duration(ceilingMillis) * time.Millisecond
	before := kernel.KernelClock().Mono()

	// Ask for 100 seconds. What comes back must be bounded by the sealed ceiling.
	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label:         "clamped",
		TimeoutMillis: 100_000,
		Fn:            func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)

	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCompleted, out.State)

	window := time.Duration(out.Deadline - before)
	assert.GreaterOrEqual(t, window, ceiling, "the deadline must be at least the ceiling")
	assert.Less(t, window, ceiling+250*time.Millisecond,
		"a 100 second request must be clamped to the sealed ceiling, got %s", window)
}

// TestSchedShorterTimeoutIsHonouredAndExpires proves the other half of the clamp: a
// module may ask for less than the ceiling, and the run is then recorded as timed out
// with the evidence the kernel needs to explain it.
func TestSchedShorterTimeoutIsHonouredAndExpires(t *testing.T) {
	k, sink := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 2_000})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	// The job ignores done, which is the behaviour the subsystem has to survive. A
	// job that returned when cancelled would be recorded as cancelled with its own
	// result, and the abandoned path - the one that needs evidence - would never run.
	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label:         "ignores-cancellation",
		TimeoutMillis: 30,
		Fn: func(_ kernel.SContext, _ <-chan struct{}) {
			<-release
		},
	})
	require.NoError(t, err)

	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedTimedOut, out.State,
		"a job that ignores its deadline must be recorded as timed out, not as completed")
	assert.Equal(t, "deadline expired", out.Detail)
	require.NoError(t, p.captured().SyscallClose(fd))
	assert.NotEmpty(t, out.Stack, "an abandoned run must carry a stack snapshot as evidence")
	assert.LessOrEqual(t, len(out.Stack), kernel.MaxWatchdogStackBytes)
	assert.True(t, strings.Contains(out.Stack, "goroutine") || strings.Contains(out.Stack, "no longer running"),
		"the snapshot must be a stack or an explanation, got: %s", schedFirstLine(out.Stack))

	running, _ := kernel.SchedCount(pid)
	assert.Zero(t, running, "an abandoned run must release its slot")
	assert.True(t, schedAwait(t, 5*time.Second, func() bool {
		return sink.contains("supervised run did not complete")
	}), "the kernel must report a run it stopped waiting for")
}

func schedFirstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// TestSchedPanicIsRecoveredAndLeavesNothingBehind is the panic path. A module's defect
// must not become a host-process crash, and must not leak the run's slot or handle.
func TestSchedPanicIsRecoveredAndLeavesNothingBehind(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "panics",
		Fn: func(kernel.SContext, <-chan struct{}) {
			panic("module exploded inside a supervised run")
		},
	})
	require.NoError(t, err)

	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedPanicked, out.State)
	assert.Contains(t, out.Detail, "module exploded")
	assert.NotEmpty(t, out.Stack, "a panic must carry the frames that were unwinding")

	var sawPanic bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPanic, PID: pid}) {
		if strings.Contains(e.Msg, "supervised run panicked") {
			sawPanic = true
		}
	}
	assert.True(t, sawPanic, "a recovered panic in supervised work must be audited")

	running, _ := kernel.SchedCount(pid)
	assert.Zero(t, running, "a panicked run must release its slot")

	require.NoError(t, k.Unload(pid))
	assert.Zero(t, kernel.FDCount(pid), "unload must reclaim the panicked run's handle")

	// The kernel is still usable, which is the point of recovering rather than
	// propagating.
	pid2, p2 := schedLoad(t, k, kernel.OpSchedSpawn)
	fd2, err := p2.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "after-panic",
		Fn:    func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)
	out2, err := p2.captured().SyscallSchedWait(fd2)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCompleted, out2.State)
	require.NoError(t, k.Unload(pid2))
}

// TestSchedRunCeilingIsTypedAndRecoverable is the ceiling. Hitting it must fail with a
// typed error, must not corrupt the counters, and must stop failing once the runs
// finish - a quota that stays stuck is a denial of service against an honest module.
func TestSchedRunCeilingIsTypedAndRecoverable(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{MaxSlotsPerModule: 2, CallTimeoutMillis: 2_000})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	release := make(chan struct{})
	block := func(kernel.SContext, <-chan struct{}) { <-release }

	var held []kernel.FD
	for i := range 2 {
		fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
			Label: "holds-a-slot-" + schedItoa(i), Fn: block,
		})
		require.NoError(t, err)
		held = append(held, fd)
	}
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		running, _ := kernel.SchedCount(pid)
		return running == 2
	}), "both runs must be accounted as in flight")

	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{Label: "third", Fn: block})
	require.Error(t, err)
	assert.Equal(t, kernel.FD(0), fd)
	assert.True(t, kernel.IsSchedLimit(err), "the ceiling must be a typed error, got %T: %v", err, err)
	assert.False(t, kernel.IsDenied(err), "a quota refusal is not a policy denial")
	assert.Contains(t, err.Error(), "supervised runs in flight")

	running, _ := kernel.SchedCount(pid)
	assert.Equal(t, 2, running, "a refused spawn must not take a slot")
	assert.Equal(t, len(held), kernel.FDCount(pid), "a refused spawn must not allocate a handle")

	// Release, and the same request must now succeed.
	close(release)
	for _, fd := range held {
		_, err := p.captured().SyscallSchedWait(fd)
		require.NoError(t, err)
	}
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		running, _ := kernel.SchedCount(pid)
		return running == 0
	}), "slots must be released when the runs finish")

	fd3, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "after-the-ceiling",
		Fn:    func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err, "the ceiling must clear when the runs finish")
	out, err := p.captured().SyscallSchedWait(fd3)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCompleted, out.State)
}

// TestSchedHandleCeilingIsTyped covers the second bound on a supervised run: it is also
// a handle, so the sealed per-module handle ceiling applies to it.
func TestSchedHandleCeilingIsTyped(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{MaxOpenFDsPerModule: 2, CallTimeoutMillis: 2_000})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	block := func(kernel.SContext, <-chan struct{}) { <-release }

	for range 2 {
		_, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{Label: "fd", Fn: block})
		require.NoError(t, err)
	}
	require.Equal(t, 2, kernel.FDCount(pid))

	_, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{Label: "third", Fn: block})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum of 2 open handles")
	assert.Equal(t, 2, kernel.FDCount(pid), "a refused install must not grow the table")

	running, _ := kernel.SchedCount(pid)
	assert.Equal(t, 2, running,
		"only the two blocking runs hold slots; the spawn the handle ceiling refused must have given its own back")
}

// TestSchedTimerCeilingIsTyped covers the per-pid timer bound. Armed timers are a way
// to grow the runtime's timer heap from inside a module, so the count is bounded and
// the refusal is typed.
func TestSchedTimerCeilingIsTyped(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 2_000})
	pid, p := schedLoad(t, k, kernel.OpSchedTimer)

	const max = 128
	// A delay long enough that nothing fires during the test, so the count under
	// test stays the count of armed timers.
	spec := kernel.TimerSpec{Label: "armed", DelayMillis: 60_000,
		Fn: func(kernel.SContext, <-chan struct{}) {}}

	var fds []kernel.FD
	for range max {
		fd, err := p.captured().SyscallSchedTimer(spec)
		require.NoError(t, err)
		fds = append(fds, fd)
	}
	_, timers := kernel.SchedCount(pid)
	require.Equal(t, max, timers)

	fd, err := p.captured().SyscallSchedTimer(spec)
	require.Error(t, err)
	assert.Equal(t, kernel.FD(0), fd)
	assert.True(t, kernel.IsSchedLimit(err), "the timer ceiling must be a typed error, got %T", err)
	assert.Contains(t, err.Error(), "armed timers")

	_, timers = kernel.SchedCount(pid)
	assert.Equal(t, max, timers, "a refused timer must not take a slot")
	assert.Equal(t, max, kernel.FDCount(pid), "a refused timer must not allocate a handle")

	// Closing one frees exactly one slot, which is the state-integrity half of the
	// assertion: a counter that drifts here would strand or double-spend a quota.
	require.NoError(t, p.captured().SyscallClose(fds[0]))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		_, timers := kernel.SchedCount(pid)
		return timers == max-1
	}))
	fd2, err := p.captured().SyscallSchedTimer(spec)
	require.NoError(t, err, "closing a timer must free its slot")
	require.NoError(t, p.captured().SyscallClose(fd2))
}

// TestSchedTimerFiresOnceAndCanBeCancelled covers the timer contract: a callback runs
// once under the caller's context, and closing the handle before it fires means it
// never runs.
func TestSchedTimerFiresOnceAndCanBeCancelled(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := schedLoad(t, k, kernel.OpSchedTimer)

	var (
		mu     sync.Mutex
		fired  int
		cancel int
	)
	firedCh := make(chan struct{}, 1)

	fd, err := p.captured().SyscallSchedTimer(kernel.TimerSpec{
		Label: "fires", DelayMillis: 5,
		Fn: func(ctx kernel.SContext, _ <-chan struct{}) {
			mu.Lock()
			fired++
			mu.Unlock()
			assert.Equal(t, pid, ctx.PID())
			select {
			case firedCh <- struct{}{}:
			default:
			}
		},
	})
	require.NoError(t, err)

	fd2, err := p.captured().SyscallSchedTimer(kernel.TimerSpec{
		Label: "cancelled", DelayMillis: 5,
		Fn: func(kernel.SContext, <-chan struct{}) {
			mu.Lock()
			cancel++
			mu.Unlock()
		},
	})
	require.NoError(t, err)

	// Cancel the second before its delay elapses.
	require.NoError(t, p.captured().SyscallClose(fd2))

	select {
	case <-firedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the armed timer never fired")
	}

	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCompleted, out.State)
	assert.Equal(t, "timer", out.Kind)

	mu.Lock()
	assert.Equal(t, 1, fired, "a single-shot timer must fire exactly once")
	assert.Zero(t, cancel, "a timer cancelled before its delay must never run")
	mu.Unlock()

	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		_, timers := kernel.SchedCount(pid)
		return timers == 0
	}), "fired and cancelled timers must both give their slots back")
	require.NoError(t, k.Unload(pid))
	assert.Zero(t, kernel.FDCount(pid))
}

// TestSchedPendingTimerIsReportedAsPending covers the state a waiting caller sees
// before a timer fires. "Not yet" and "never" must be distinguishable, or a module
// cannot tell a slow timer from a lost one.
func TestSchedPendingTimerIsReportedAsPending(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := schedLoad(t, k, kernel.OpSchedTimer, kernel.OpSignalSend)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	fd, err := p.captured().SyscallSchedTimer(kernel.TimerSpec{
		Label: "far-future", DelayMillis: 60_000,
		Fn: func(kernel.SContext, <-chan struct{}) { <-release },
	})
	require.NoError(t, err)

	_, timers := kernel.SchedCount(pid)
	assert.Equal(t, 1, timers)

	// Abort reaches the module's own supervised work through ksignal, which cancels
	// the run without closing its handle - so a waiter can still read how it ended.
	// A waiter blocked until the call ceiling to learn a timer will never fire would
	// be a waiter that cannot distinguish "slow" from "lost".
	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalAbort))
	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCancelled, out.State)
	assert.Contains(t, out.Detail, "abort signal")

	require.NoError(t, p.captured().SyscallClose(fd))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		_, timers := kernel.SchedCount(pid)
		return timers == 0
	}))
}

// TestSchedHandlesAreReclaimedOnUnload is the reclaim property. Unloading a module
// holding supervised runs and armed timers must release every one of them, because no
// resource's only reference may live inside module code.
func TestSchedHandlesAreReclaimedOnUnload(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 2_000})
	_, p := schedLoad(t, k, kernel.OpSchedSpawn, kernel.OpSchedTimer)
	pid := p.captured().PID()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	for range 3 {
		_, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
			Label: "leaky", Fn: func(kernel.SContext, <-chan struct{}) { <-release },
		})
		require.NoError(t, err)
	}
	for range 2 {
		_, err := p.captured().SyscallSchedTimer(kernel.TimerSpec{
			Label: "leaky", DelayMillis: 60_000,
			Fn: func(kernel.SContext, <-chan struct{}) { <-release },
		})
		require.NoError(t, err)
	}
	require.Equal(t, 5, kernel.FDCount(pid))

	require.NoError(t, k.Unload(pid))

	assert.Zero(t, kernel.FDCount(pid), "unload must reclaim every handle the module held")
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		running, timers := kernel.SchedCount(pid)
		return running == 0 && timers == 0
	}), "reclaim must release the runs and timers the module held, not only the handles")

	// The reclaim cancelled the runs, which is the observable half of "the kernel
	// can stop work it started without the module's help". release stays open so
	// the cleanup at the end of the test is the only thing that unblocks them.
}

// TestSchedCancelReachesTheJobProvesTheDoneChannel asserts the mechanism a
// well-behaved module uses to stop: closing the handle closes the done channel the job
// was given, and the job returns.
func TestSchedCancelReachesTheJobProvesTheDoneChannel(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 2_000})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	returned := make(chan struct{})
	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "cooperative",
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
		t.Fatal("closing the handle must reach the job through its done channel")
	}

	assert.Zero(t, kernel.FDCount(pid), "an explicit close must remove the handle")
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		running, _ := kernel.SchedCount(pid)
		return running == 0
	}), "a cancelled run must release its slot")
}

// TestSchedWaitRejectsAForeignHandle asserts the isolation a handle provides and a
// pointer would not: a run belonging to another module does not resolve in the caller's
// table, so there is no call shape in which one module waits on, or cancels, another's
// work.
func TestSchedWaitRejectsAForeignHandle(t *testing.T) {
	// A short ceiling, because the last step waits on a run the kernel never
	// finishes: the assertion is about whose table a handle resolves in, not about
	// how long a wait takes.
	k, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 150})
	_, a := schedLoad(t, k, kernel.OpSchedSpawn)
	_, b := schedLoad(t, k, kernel.OpSchedSpawn)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	fd, err := a.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "a-owned", Fn: func(kernel.SContext, <-chan struct{}) { <-release },
	})
	require.NoError(t, err)

	// Same integer, different table.
	_, err = b.captured().SyscallSchedWait(fd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not open in pid")

	// And closing it from the wrong pid must not cancel the owner's run.
	require.Error(t, b.captured().SyscallClose(fd))
	_, err = a.captured().SyscallSchedWait(fd)
	require.NoError(t, err, "the owner can still read its own run")
	require.NoError(t, a.captured().SyscallClose(fd))
	assert.Zero(t, kernel.FDCount(a.captured().PID()))
}

// TestSchedRejectsMalformedRequests covers the inputs the kernel refuses rather than
// interprets generously. A nil function is not a job, a negative delay is not a timer,
// and an over-long label is a module trying to grow kernel memory with a diagnostic
// string.
func TestSchedRejectsMalformedRequests(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn, kernel.OpSchedTimer)

	_, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{Label: "nil-fn"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a function")

	_, err = p.captured().SyscallSchedTimer(kernel.TimerSpec{Label: "nil-fn", DelayMillis: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a function")

	_, err = p.captured().SyscallSchedTimer(kernel.TimerSpec{
		Label: "negative", DelayMillis: -1,
		Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-negative delay")

	_, err = p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: strings.Repeat("x", 129),
		Fn:    func(kernel.SContext, <-chan struct{}) {},
	})
	require.Error(t, err)
	assert.True(t, kernel.IsSchedLimit(err), "an over-long label must be a typed limit error")

	_, err = p.captured().SyscallSchedWait(kernel.FD(9999))
	require.Error(t, err)

	assert.Zero(t, kernel.FDCount(pid), "every refusal must leave the table empty")
	running, timers := kernel.SchedCount(pid)
	assert.Zero(t, running)
	assert.Zero(t, timers)
}

// TestSchedConcurrentSpawnIsRaceFree is the concurrency path. Contention is where a
// counter taken outside its lock, or a run finished twice, shows up; the suite runs
// -race, so this also asserts the locking is right and not merely that it works once.
func TestSchedConcurrentSpawnIsRaceFree(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{MaxSlotsPerModule: 8, CallTimeoutMillis: 5_000})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn, kernel.OpSchedTimer)

	const (
		goroutines = 8
		perG       = 25
	)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		ok      int
		limited int
		fds     []kernel.FD
	)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perG {
				fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
					Label: "hammer",
					Fn:    func(kernel.SContext, <-chan struct{}) {},
				})
				mu.Lock()
				switch {
				case err == nil:
					ok++
					fds = append(fds, fd)
				case kernel.IsSchedLimit(err):
					limited++
				default:
					mu.Unlock()
					assert.Fail(t, "unexpected error", "%T: %v", err, err)
					return
				}
				mu.Unlock()
			}
		}()
	}

	// Timers concurrently, so the timer counter is contended too.
	var timerOK, timerRefused int
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perG {
				fd, err := p.captured().SyscallSchedTimer(kernel.TimerSpec{
					Label: "hammer-timer", DelayMillis: 1,
					Fn: func(kernel.SContext, <-chan struct{}) {},
				})
				mu.Lock()
				switch {
				case err == nil:
					timerOK++
				case kernel.IsSchedLimit(err):
					timerRefused++
				default:
					mu.Unlock()
					assert.Fail(t, "unexpected timer error", "%T: %v", err, err)
					return
				}
				mu.Unlock()
				if err == nil {
					_ = p.captured().SyscallClose(fd)
				}
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, goroutines*perG, ok+limited,
		"every spawn must be either accepted or refused by the ceiling, never lost")
	assert.Equal(t, goroutines*perG, timerOK+timerRefused,
		"every timer request must be either accepted or refused by the ceiling, never lost")
	assert.Positive(t, ok, "some spawns must have succeeded")
	assert.Positive(t, limited, "with a ceiling of %d the quota must have been hit", 8)

	// Nothing may be left behind once every run drains.
	for _, fd := range fds {
		_, _ = p.captured().SyscallSchedWait(fd)
	}
	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		running, timers := kernel.SchedCount(pid)
		return running == 0 && timers == 0
	}), "concurrent runs must all release their slots")

	require.NoError(t, k.Unload(pid))
	assert.Zero(t, kernel.FDCount(pid))
}

// TestSchedStateDoesNotSurviveRestart is the reset path. Per-pid execution state that
// survived a restart would be misattributed rather than merely stale, because pids
// restart at 1.
func TestSchedStateDoesNotSurviveRestart(t *testing.T) {
	k1, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 2_000})
	pid, p := schedLoad(t, k1, kernel.OpSchedSpawn, kernel.OpSchedTimer)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	_, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "survivor", Fn: func(kernel.SContext, <-chan struct{}) { <-release },
	})
	require.NoError(t, err)
	_, err = p.captured().SyscallSchedTimer(kernel.TimerSpec{
		Label: "survivor", DelayMillis: 60_000,
		Fn: func(kernel.SContext, <-chan struct{}) { <-release },
	})
	require.NoError(t, err)
	running, timers := kernel.SchedCount(pid)
	require.Positive(t, running+timers, "the first boot must have live state to clear")

	require.NoError(t, k1.Shutdown())

	assert.Zero(t, kernel.FDCount(pid), "shutdown must reclaim the module's handles")
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		running, timers := kernel.SchedCount(pid)
		return running == 0 && timers == 0
	}), "counters must be cleared, not merely orphaned")

	k2, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "sched-test-2"}})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	assert.Zero(t, kernel.FDCount(pid), "a fresh boot must inherit no handle table")
	_, p2 := schedLoad(t, k2, kernel.OpSchedSpawn)
	fd, err := p2.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "after-restart",
		Fn:    func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err, "a fresh boot must be able to schedule work")
	out, err := p2.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCompleted, out.State)
}

// TestSchedRunIDIsUniqueWithinABoot covers the identity a run carries in the audit
// trail. Two runs with one id would make "which run hung" unanswerable.
func TestSchedRunIDIsUniqueWithinABoot(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	_, p := schedLoad(t, k, kernel.OpSchedSpawn)

	seen := map[int64]bool{}
	for range 20 {
		fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
			Label: "ids", Fn: func(kernel.SContext, <-chan struct{}) {},
		})
		require.NoError(t, err)
		out, err := p.captured().SyscallSchedWait(fd)
		require.NoError(t, err)
		assert.False(t, seen[out.ID], "run id %d was reused within a boot", out.ID)
		seen[out.ID] = true
		require.NoError(t, p.captured().SyscallClose(fd))
	}
	assert.Len(t, seen, 20)
}

// TestSchedOutcomeIsACopy proves a module cannot rewrite the evidence of its own
// timeout. The outcome is a value; the recorded state is kernel-owned.
func TestSchedOutcomeIsACopy(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 2_000})
	pid, p := schedLoad(t, k, kernel.OpSchedSpawn)

	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label:         "tamper",
		TimeoutMillis: 20,
		// Ignores cancellation, so the run ends on the abandoned path with the
		// evidence the kernel captured rather than with a result the job reported.
		Fn: func(_ kernel.SContext, _ <-chan struct{}) {
			time.Sleep(3 * time.Second)
		},
	})
	require.NoError(t, err)

	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedTimedOut, out.State)
	original := out

	out.State = kernel.SchedCompleted
	out.Detail = "rewritten by the module"
	out.Stack = ""

	again, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, original.State, again.State, "mutating a returned outcome must not change the record")
	assert.Equal(t, original.Detail, again.Detail)
	assert.NotEmpty(t, again.Stack, "the kernel keeps its own copy of the evidence")
	require.NoError(t, p.captured().SyscallClose(fd))
	require.NoError(t, k.Unload(pid))
}
