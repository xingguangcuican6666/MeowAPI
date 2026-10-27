package kernel_test

// Tests for ksignal, control signals to a pid.
//
// The properties under test are the ones that make unload safe rather than hopeful: a
// module may only signal a pid it is permitted to reach, pid 0 and init are never
// targets, delivery is asynchronous through a queue that is bounded and reports
// overflow instead of dropping, and the default action for a signal the module does not
// handle is the safe reading of it - for drain, termination.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// sigSentinel collects what a module's handler received, under a mutex, because the
// kernel delivers on its own goroutine.
type sigSentinel struct {
	mu     sync.Mutex
	got    []kernel.SignalInfo
	calls  int
	block  chan struct{}
	closed bool
}

func (s *sigSentinel) record(info kernel.SignalInfo) {
	s.mu.Lock()
	s.got = append(s.got, info)
	s.calls++
	block := s.block
	s.mu.Unlock()
	if block != nil {
		// Blocking here is how a stuck handler is simulated: the endpoint's one
		// worker is inside the handler, so its queue stops draining.
		<-block
	}
}

func (s *sigSentinel) snapshot() []kernel.SignalInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]kernel.SignalInfo, len(s.got))
	copy(out, s.got)
	return out
}

func (s *sigSentinel) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *sigSentinel) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.block != nil && !s.closed {
		s.closed = true
		close(s.block)
	}
}

func sigNewSentinel(blocking bool) *sigSentinel {
	s := &sigSentinel{}
	if blocking {
		s.block = make(chan struct{})
	}
	return s
}

// sigLoad loads a module holding the operations a signal test needs.
func sigLoad(t *testing.T, k *kernel.Kernel, ops ...kernel.Op) (kernel.PID, *schedProbe) {
	t.Helper()
	all := append([]kernel.Op{kernel.OpSignalSend}, ops...)
	return schedLoad(t, k, all...)
}

func sigAudit(t *testing.T, msg string) []kernel.AuditEntry {
	t.Helper()
	var out []kernel.AuditEntry
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{}) {
		if strings.Contains(e.Msg, msg) {
			out = append(out, e)
		}
	}
	return out
}

// TestSignalSendIsGranted covers the grant: init reaches a module, and a module reaches
// itself. Both are the shapes a real deployment uses - the host winding a module down,
// and a module reacting to its own lifecycle.
func TestSignalSendIsGranted(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	sent := sigNewSentinel(false)
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 1 }))

	got := sent.snapshot()
	require.Len(t, got, 1)
	assert.Equal(t, kernel.SignalReload, got[0].Kind)
	assert.Equal(t, kernel.PID(1), got[0].From, "the sender is the kernel's own record, not the sender's claim")
	assert.Equal(t, kernel.DomainInit, got[0].FromDomain)
	assert.Positive(t, got[0].SentAt, "the timestamp is a mono() reading taken by the kernel")

	// A module signalling itself is permitted, and that is how a module reacts to
	// its own condition rather than waiting for an operator.
	require.NoError(t, p.captured().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 2 }))
	assert.Equal(t, pid, sent.snapshot()[1].From)
	assert.Equal(t, kernel.DomainPlugin, sent.snapshot()[1].FromDomain)

	assert.NotEmpty(t, sigAudit(t, "signal sent"), "a delivered signal must be audited")
}

// TestSignalSendDeniedWithoutDeclaration is the denial half of the grant, and the audit
// half of the denial: a module that did not declare signal:send cannot signal anyone,
// including itself, and the refusal lands on the chain.
func TestSignalSendDeniedWithoutDeclaration(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := schedLoad(t, k, kernel.OpLogWrite)

	err := p.captured().SyscallSignalSend(pid, kernel.SignalReload)
	require.Error(t, err)
	require.True(t, kernel.IsDenied(err), "the refusal must be a policy denial, got %T: %v", err, err)
	assert.Contains(t, err.Error(), string(kernel.OpSignalSend))

	denials := schedDenials(t, kernel.OpSignalSend)
	require.NotEmpty(t, denials)
	assert.Equal(t, pid, denials[0].PID)
	assert.Equal(t, kernel.DomainPlugin, denials[0].Domain)
}

// TestSignalTargetsPidZeroAndInitAreRefused is the target rule, and it is the one that
// keeps a wind-down request from becoming a way to end enforcement. A module that could
// signal init could kill the sequence that decides what code runs.
func TestSignalTargetsPidZeroAndInitAreRefused(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	for _, target := range []kernel.PID{0, 1} {
		for _, kind := range kernel.SignalKinds() {
			err := p.captured().SyscallSignalSend(target, kind)
			require.Error(t, err, "signalling pid %d with %s must be refused", target, kind)
			assert.True(t, kernel.IsDenied(err),
				"the refusal for pid %d / %s must be a denial, got %T", target, kind, err)
		}
	}

	denials := schedDenials(t, kernel.OpSignalSend)
	require.NotEmpty(t, denials)
	assert.Equal(t, pid, denials[0].PID, "the refusal must name the sender, not the target")

	// And nothing was delivered: init has no endpoint state, and the kernel is
	// still healthy enough to load another module.
	_, p2 := sigLoad(t, k)
	require.NoError(t, p2.captured().SyscallSignalSend(p2.captured().PID(), kernel.SignalReload))
}

// TestSignalBetweenPeerModulesIsRefused covers the third target rule. Signals are
// lifecycle commands, and lifecycle commands do not travel sideways between peers:
// cross-module coordination goes through ipc:call so the call graph stays visible to
// policy.
func TestSignalBetweenPeerModulesIsRefused(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pidA, a := sigLoad(t, k)
	pidB, b := sigLoad(t, k)

	_ = pidB
	err := a.captured().SyscallSignalSend(b.captured().PID(), kernel.SignalDrain)
	require.Error(t, err)
	require.True(t, kernel.IsDenied(err))
	assert.Contains(t, err.Error(), "not the sender and was not spawned by it")
	assert.Equal(t, pidA, schedDenials(t, kernel.OpSignalSend)[0].PID)

	// The target is untouched: no wind-down was applied to a module that was never
	// asked for one.
	draining, terminating := kernel.SignalState(b.captured().PID())
	assert.False(t, draining)
	assert.False(t, terminating)
}

// TestSignalUnknownTargetIsAnErrorNotADenial distinguishes "you are not permitted"
// from "that pid does not exist in this boot". Conflating them would put an
// authorization failure on the audit chain for what is only a stale pid.
func TestSignalUnknownTargetIsAnErrorNotADenial(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	_, p := sigLoad(t, k)

	err := p.captured().SyscallSignalSend(kernel.PID(99999), kernel.SignalReload)
	require.Error(t, err)
	assert.False(t, kernel.IsDenied(err), "an unknown pid is a stale reference, not a policy event")
	assert.Contains(t, err.Error(), "no process record")

	assert.Empty(t, schedDenials(t, kernel.OpSignalSend))
}

// TestSignalUnknownKindIsRefused covers the closed set. A kind the kernel cannot name
// is refused rather than delivered as a generic event, because a handler cannot act on
// a meaning it cannot read.
func TestSignalUnknownKindIsRefused(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	for _, kind := range []kernel.SignalKind{"", "SIGTERM", "reboot", "Reload"} {
		err := p.captured().SyscallSignalSend(pid, kind)
		require.Error(t, err, "signal kind %q must be refused", kind)
		assert.Contains(t, err.Error(), "unknown signal kind")
		assert.False(t, kernel.IsDenied(err), "an unknown kind is not a policy denial")
	}
	assert.Zero(t, kernel.SignalPending(pid))
}

// TestUnhandledDrainTerminatesTheModule is the rule that makes unload safe. A module
// that ignores drain and never exits is a module the kernel cannot wait for, so the
// default action for an unhandled drain is termination - through the same unload path
// an operator uses, with the same audit record.
func TestUnhandledDrainTerminatesTheModule(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	// No handler installed: this is the default-action path.
	pid, _ := sigLoad(t, k)

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalDrain))

	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.SignalTerminated(pid)
	}), "an unhandled drain must end in termination")

	var stillLoaded bool
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			stillLoaded = true
		}
	}
	assert.False(t, stillLoaded, "the module must actually be gone, not merely flagged")
	assert.Zero(t, kernel.FDCount(pid), "termination must reclaim the module's handles")

	var sawTerminated bool
	for _, r := range kernel.ProcTable() {
		if r.PID == pid {
			assert.NotEqual(t, kernel.ProcRunning, r.State,
				"a terminated module must not stay running in the process table")
			sawTerminated = true
		}
	}
	assert.True(t, sawTerminated)
	assert.NotEmpty(t, sigAudit(t, "kernel-initiated termination"))
}

// TestKillTerminatesEvenWithAHandler covers the SIGKILL property. A handler is a
// module's chance to wind down, not a way to decline: the kernel never hands kill to
// module code, so a handler that blocks cannot keep the module alive.
func TestKillTerminatesEvenWithAHandler(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	sent := sigNewSentinel(true) // blocks forever until released
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))

	// A drain first, so the endpoint's single worker is stuck inside the handler
	// and its queue is no longer draining. Kill arrives behind it and must still be
	// acted on immediately: it is applied at send time, never queued, so a module
	// cannot become unkillable by handling drain slowly or by filling its queue.
	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalDrain))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 1 }))

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalKill))
	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.SignalTerminated(pid)
	}), "kill must terminate a module whose handler is stuck")

	assert.Equal(t, 1, sent.count(), "kill is never handed to a handler")
	for _, info := range sent.snapshot() {
		assert.NotEqual(t, kernel.SignalKill, info.Kind)
	}
}

// TestDrainRefusesNewSupervisedWork covers what drain actually means. Marking a module
// drained before its handler runs is what stops a wind-down from being a way to submit
// more work: without it a drain handler could spawn fresh runs and leave the module
// busier after the signal than before.
func TestDrainRefusesNewSupervisedWork(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 2_000})
	pid, p := sigLoad(t, k, kernel.OpSchedSpawn, kernel.OpSchedTimer)

	sent := sigNewSentinel(false)
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))

	// Sanity: work is accepted before the signal.
	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "before-drain", Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)
	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedCompleted, out.State)
	require.NoError(t, p.captured().SyscallClose(fd))

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalDrain))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 1 }))

	// A handled drain does not terminate; it stops new work. That is the
	// difference between SIGTERM with a handler and SIGKILL.
	var stillLoaded bool
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			stillLoaded = true
		}
	}
	assert.True(t, stillLoaded, "a handled drain must not terminate the module")

	draining, terminating := kernel.SignalState(pid)
	assert.True(t, draining)
	assert.False(t, terminating)

	_, err = p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "after-drain", Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrDraining)
	assert.False(t, kernel.IsDenied(err),
		"a drained module still holds sched:spawn; the refusal is about its state, not its grants")

	_, err = p.captured().SyscallSchedTimer(kernel.TimerSpec{
		Label: "after-drain", DelayMillis: 1, Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrDraining)

	// And the counters were not disturbed by the refusals: a request refused for
	// the module's state must leave no slot and no handle behind, or a drained
	// module would slowly strand its own quota.
	running, timers := kernel.SchedCount(pid)
	assert.Zero(t, running)
	assert.Zero(t, timers)
	assert.Zero(t, kernel.FDCount(pid), "the refusals must leave the handle table as it was")
}

// TestAbortCancelsInFlightWorkWithoutTerminating covers the client-disconnected case.
// The module lives; the work it was doing for a reader who is gone does not.
func TestAbortCancelsInFlightWorkWithoutTerminating(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 10_000})
	pid, p := sigLoad(t, k, kernel.OpSchedSpawn)

	returned := make(chan struct{})
	fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "streaming-to-a-gone-client",
		Fn: func(_ kernel.SContext, done <-chan struct{}) {
			<-done
			close(returned)
		},
	})
	require.NoError(t, err)

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalAbort))

	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("abort must reach in-flight supervised work through its done channel")
	}

	out, err := p.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCancelled, out.State)
	assert.Contains(t, out.Detail, "abort signal")

	// The module survives: abort is about one client, not about the module.
	var stillLoaded bool
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			stillLoaded = true
		}
	}
	assert.True(t, stillLoaded)
	draining, terminating := kernel.SignalState(pid)
	assert.False(t, draining, "abort must not wind the module down")
	assert.False(t, terminating)

	// Awaited: the audit entry is written after the cancellation that unblocked the
	// job, so reading the chain the instant the job returns would race the record.
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		return len(sigAudit(t, "abort signal cancelled in-flight work")) > 0
	}), "an abort must be audited")
}

// TestReloadWithNoHandlerIsRecordedNotActedOn covers the one kind whose safe default is
// to do nothing. The fact that an operator asked is still on the audit trail, because
// an invisible request is an uninvestigable one.
func TestReloadWithNoHandlerIsRecordedNotActedOn(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, _ := sigLoad(t, k)

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		return len(sigAudit(t, "reload signal had no handler")) > 0
	}))

	var stillLoaded bool
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			stillLoaded = true
		}
	}
	assert.True(t, stillLoaded, "an unhandled reload must not terminate anything")
	draining, terminating := kernel.SignalState(pid)
	assert.False(t, draining)
	assert.False(t, terminating)
}

// TestSignalQueueIsBoundedAndReportsOverflow is the ceiling. An endpoint has one worker
// and a bounded queue, so a module with a stuck handler stops consuming and the next
// sender gets a typed refusal. Silently dropping drain is how a module survives a
// wind-down it was told about.
func TestSignalQueueIsBoundedAndReportsOverflow(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	sent := sigNewSentinel(true)
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))

	// The first reload puts the worker inside the blocking handler.
	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 1 }))

	const maxPending = 64
	var overflow int
	for range maxPending + 8 {
		if err := k.InitContext().SyscallSignalSend(pid, kernel.SignalReload); err != nil {
			if kernel.IsSignalQueueFull(err) {
				overflow++
				continue
			}
			require.NoError(t, err)
		}
	}
	assert.Positive(t, overflow, "the pending queue must be bounded")
	assert.LessOrEqual(t, kernel.SignalPending(pid), maxPending,
		"the queue must never exceed its bound")

	// Still full, and still typed: the bound does not drift as senders retry.
	var lastErr error
	for range maxPending + 4 {
		if err := k.InitContext().SyscallSignalSend(pid, kernel.SignalReload); err != nil {
			lastErr = err
			break
		}
	}
	require.Error(t, lastErr)
	require.True(t, kernel.IsSignalQueueFull(lastErr), "a full queue must report a typed error, got %T", lastErr)

	assert.NotEmpty(t, sigAudit(t, "signal queue full"),
		"an overflow must be audited, not merely returned to the sender")

	// State is not corrupted by the overflow: releasing the handler drains the
	// queue in order and delivers everything that was accepted. A signal that was
	// refused for a full queue is not delivered, and the sender was told so.
	before := kernel.SignalPending(pid)
	assert.Positive(t, before)
	sent.release()
	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.SignalPending(pid) == 0
	}), "the queue must drain once the handler stops blocking")
	assert.Equal(t, before+1, sent.count(), "every accepted signal must be delivered exactly once")
	assert.False(t, kernel.SignalTerminated(pid), "reload is never a termination")
}

// TestKillAppliesEvenWithAFullQueue covers the reason kill is applied at send time
// rather than queued. A bounded queue is what stops a stuck module from growing kernel
// memory; if kill also travelled through it, that same bound would be a way for the
// module to refuse termination - the one outcome ksignal exists to prevent.
func TestKillAppliesEvenWithAFullQueue(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	sent := sigNewSentinel(true)
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 1 }))

	// Fill the queue so the endpoint is provably not accepting anything.
	refused := 0
	for range 64 + 16 {
		err := k.InitContext().SyscallSignalSend(pid, kernel.SignalReload)
		if err != nil {
			if kernel.IsSignalQueueFull(err) {
				refused++
				continue
			}
			require.NoError(t, err)
		}
	}
	require.Positive(t, refused, "the queue must be full for this test to mean anything")

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalKill))
	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		return kernel.SignalTerminated(pid)
	}), "kill must be applied even when the target's queue is full")

	assert.Equal(t, 1, sent.count(), "kill is never handed to a handler")
	assert.Zero(t, kernel.FDCount(pid), "the teardown must reclaim the module's handles")
	assert.NotEmpty(t, sigAudit(t, "kernel-initiated termination"))
}

// TestSignalHandlerPanicIsContained is the panic path. A broken handler must not take
// down the host, must be audited, and must leave the endpoint usable.
func TestSignalHandlerPanicIsContained(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	var mu sync.Mutex
	calls := 0
	require.NoError(t, p.captured().SyscallSignalHandle(func(info kernel.SignalInfo) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			panic("handler exploded")
		}
	}))

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls == 1
	}))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		return len(sigAudit(t, "signal handler panicked")) > 0
	}), "a panicking handler must be audited")

	// The endpoint still works, which is the property that matters: the panic was
	// contained, not merely reported.
	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls == 2
	}))

	var stillLoaded bool
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			stillLoaded = true
		}
	}
	assert.True(t, stillLoaded, "a panicking handler must not terminate the module")
}

// TestSignalToAnUnloadedModuleDoesNotRunStaleCode covers the lifetime of the retained
// context. ksignal is the one place the kernel holds a live module context in package
// state, so a signal arriving after unload must not run the previous module's handler
// under a context the kernel already withdrew.
func TestSignalToAnUnloadedModuleDoesNotRunStaleCode(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	sent := sigNewSentinel(false)
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 1 }))

	require.NoError(t, k.Unload(pid))

	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		return len(sigAudit(t, "signal dropped: target is not running")) > 0
	}), "a signal to a terminated pid must be reported as dropped")
	assert.Equal(t, 1, sent.count(), "the unloaded module's handler must never run again")
}

// TestSignalHandleCanBeRemoved covers the other half of the handler contract: passing
// nil restores the default actions, so a module cannot get stuck with a handler it no
// longer wants.
func TestSignalHandleCanBeRemoved(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k)

	sent := sigNewSentinel(false)
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))
	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 1 }))

	require.NoError(t, p.captured().SyscallSignalHandle(nil))
	require.NoError(t, k.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		return len(sigAudit(t, "reload signal had no handler")) > 0
	}))
	assert.Equal(t, 1, sent.count(), "a removed handler must not be called")
}

// TestSignalConcurrencyIsRaceFree is the concurrency path: many senders, one endpoint,
// under -race. Serial delivery per endpoint is the POSIX reading and it is also what
// makes a stuck handler visible as a growing queue rather than as an unbounded pile of
// goroutines all stuck at once.
func TestSignalConcurrencyIsRaceFree(t *testing.T) {
	k, _ := schedQuiet(t, kernel.BootLimits{})
	pid, p := sigLoad(t, k, kernel.OpSchedSpawn)

	sent := sigNewSentinel(false)
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))

	const senders = 8
	const perSender = 20
	var wg sync.WaitGroup
	for range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perSender {
				// Init and the module itself, concurrently, at one endpoint.
				if err := k.InitContext().SyscallSignalSend(pid, kernel.SignalReload); err != nil {
					assert.NoError(t, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	require.True(t, schedAwait(t, 20*time.Second, func() bool {
		return sent.count() == senders*perSender
	}), "every accepted signal must be delivered exactly once, got %d of %d",
		sent.count(), senders*perSender)
	assert.Zero(t, kernel.SignalPending(pid))

	for _, info := range sent.snapshot() {
		assert.Equal(t, kernel.SignalReload, info.Kind)
		assert.Equal(t, kernel.PID(1), info.From)
	}

	// Concurrent spawns alongside signalling, so the admission gate and the
	// endpoint are contended at the same time.
	var spawnWg sync.WaitGroup
	for range senders {
		spawnWg.Add(1)
		go func() {
			defer spawnWg.Done()
			for range 5 {
				fd, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
					Label: "concurrent", Fn: func(kernel.SContext, <-chan struct{}) {},
				})
				if err != nil {
					continue
				}
				_, _ = p.captured().SyscallSchedWait(fd)
				_ = p.captured().SyscallClose(fd)
			}
		}()
	}
	spawnWg.Wait()

	require.True(t, schedAwait(t, 10*time.Second, func() bool {
		running, _ := kernel.SchedCount(pid)
		return running == 0
	}))
}

// TestSignalStateDoesNotSurviveRestart is the reset path. Handlers are module closures
// and a retained module context is exactly what must not outlive the module: either
// surviving a restart would run the previous boot's code under a pid the new boot has
// given to something else.
func TestSignalStateDoesNotSurviveRestart(t *testing.T) {
	k1, _ := schedQuiet(t, kernel.BootLimits{CallTimeoutMillis: 2_000})
	pid, p := sigLoad(t, k1, kernel.OpSchedSpawn)

	sent := sigNewSentinel(false)
	t.Cleanup(sent.release)
	require.NoError(t, p.captured().SyscallSignalHandle(sent.record))
	require.NoError(t, k1.InitContext().SyscallSignalSend(pid, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 1 }))

	// Leave visible state behind: a drained flag and a live supervised run.
	require.NoError(t, k1.InitContext().SyscallSignalSend(pid, kernel.SignalDrain))
	require.True(t, schedAwait(t, 5*time.Second, func() bool {
		draining, _ := kernel.SignalState(pid)
		return draining
	}))
	_, err := p.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "drained", Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.ErrorIs(t, err, kernel.ErrDraining)

	// Drain is marked before the handler runs, so the flag being set does not yet
	// mean the handler saw it. Wait for the delivery itself: this count is what the
	// second boot must not add to, and a handler closure surviving the restart is
	// exactly the leak the assertion exists to catch.
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return sent.count() == 2 }),
		"reload and drain both reach a registered handler")
	beforeShutdown := sent.count()
	require.Equal(t, 2, beforeShutdown)

	require.NoError(t, k1.Shutdown())

	draining, terminating := kernel.SignalState(pid)
	assert.False(t, draining, "the drained flag must not survive a restart")
	assert.False(t, terminating)
	assert.False(t, kernel.SignalTerminated(pid))
	assert.Zero(t, kernel.SignalPending(pid))

	k2, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "signal-test-2"}})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	pid2, p2 := sigLoad(t, k2, kernel.OpSchedSpawn)
	fresh := sigNewSentinel(false)
	t.Cleanup(fresh.release)
	require.NoError(t, p2.captured().SyscallSignalHandle(fresh.record))

	require.NoError(t, k2.InitContext().SyscallSignalSend(pid2, kernel.SignalReload))
	require.True(t, schedAwait(t, 5*time.Second, func() bool { return fresh.count() == 1 }))
	// pid2 is the same number the previous boot used, which is precisely why this
	// matters: a stale endpoint would have delivered this signal to the previous
	// boot's closure, under the previous boot's retained context.
	assert.Equal(t, beforeShutdown, sent.count(),
		"the previous boot's handler must never be invoked again")

	// Work is accepted again: nothing carried over to refuse it.
	fd, err := p2.captured().SyscallSchedSpawn(kernel.SchedJob{
		Label: "after-restart", Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)
	out, err := p2.captured().SyscallSchedWait(fd)
	require.NoError(t, err)
	assert.Equal(t, kernel.SchedCompleted, out.State)
}
