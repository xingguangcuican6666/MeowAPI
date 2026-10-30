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

package channels

// These tests cover the half of kepoll that is not delivery mechanics: that a kernel fact
// actually produces an event.
//
// The distinction matters because the delivery half was already well covered - backlog bounds,
// drop counting, sequence numbering, subscription filtering, targeted delivery, reset - while
// seven of the eight names in the closed set had no production post site at all. A subscription
// to pipe.readable blocked until its deadline and returned ErrNoEvents, forever, and every
// existing test still passed because each one posted the event itself through the host handle.
// A test that supplies its own stimulus cannot detect the absence of the thing that is supposed
// to produce it.
//
// What each case here does is trigger the fact through the kernel's own path - send a signal,
// finish a supervised run, publish configuration, unload a module - and assert a subscriber
// hears about it without any test-side post. Removing the post site in the subsystem turns the
// corresponding case red.
//
// pipe.readable is not here. Its four post sites are in pipe.go and are owned by the kpeer
// work; this file covers the other six so the two halves can be landed independently.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// evSubscribe loads a module holding event:wait and returns its context plus a subscription
// handle for the given names.
//
// Any further operation is passed by the caller rather than granted here by default. A case
// that sends a signal declares signal:send and a case that spawns work declares sched:spawn,
// because the manifest is what narrows a grant, and a helper that over-grants would let a suite
// keep passing after it stopped needing an operation. The four denials that produced this
// comment were correct behaviour, not a test bug.
func evSubscribe(t *testing.T, k *kernel.Kernel, ops []kernel.Op,
	names ...kernel.KernelEventName) (kernel.PID, kernel.SContext, kernel.FD) {
	t.Helper()
	pid, m := chLoad(t, k, nil, append([]kernel.Op{kernel.OpEventWait}, ops...)...)
	fd, err := m.ctx.SyscallEventSubscribe(names)
	require.NoError(t, err)
	return pid, m.ctx, fd
}

// evWait drains one event with a bounded deadline. Every case here uses this rather than a
// bare SyscallEventWait so a missing post fails as an assertion and not as a test timeout.
func evWait(t *testing.T, ctx kernel.SContext, fd kernel.FD, want kernel.KernelEventName) kernel.Event {
	t.Helper()
	got, err := ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(3*time.Second))
	require.NoError(t, err,
		"waiting for %s: nothing arrived, so the kernel path that produces it is not posted", want)
	// One call returns the whole backlog, so the wanted name may be anywhere in it rather than
	// first. Searching the batch rather than taking got[0] is what makes this helper usable by
	// a case that triggers several facts.
	for _, e := range got {
		if e.Name == want {
			return e
		}
	}
	t.Fatalf("waited for %s and received %v instead", want, got)
	return kernel.Event{}
}

// TestADeliveredSignalIsAnEvent covers signal.delivered. The post is beside the audit record
// that says "signal sent", and after the enqueue, because a subscriber woken before the queue
// held the signal would see an event whose subject is not yet true.
func TestADeliveredSignalIsAnEvent(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, ctx, fd := evSubscribe(t, k, []kernel.Op{kernel.OpSignalSend}, kernel.EventSignalDelivered)
	defer func() { _ = k.Unload(pid) }()

	// Sent to itself, which signalPermitted allows for any domain and which needs no second
	// module: the point is that the kernel posts on delivery, not who the sender was.
	require.NoError(t, ctx.SyscallSignalSend(pid, kernel.SignalReload))

	e := evWait(t, ctx, fd, kernel.EventSignalDelivered)
	assert.Equal(t, pid, e.Subject, "the event is about the pid the signal went to")
	assert.Equal(t, string(kernel.SignalReload), e.Detail, "and carries the kind")
}

// TestDrainIsAnEventBeforeTermination covers draining, and the ordering half of it.
//
// The unhandled-drain default is termination, so a subscriber that only heard about the drain
// afterwards would hear about a module that is already being torn down. The post is above both
// delivery branches for that reason, and it is below the liveness check because posting beside
// markDraining fired the event for a target that was already gone - contradicting the audit
// line in the same dispatch that said the signal was dropped.
func TestDrainIsAnEventBeforeTermination(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, sub, fd := evSubscribe(t, k,
		[]kernel.Op{kernel.OpSignalSend, kernel.OpLogWrite}, kernel.EventDraining)
	defer func() { _ = k.Unload(pid) }()

	// A drain handler is installed so the module survives its own drain. The default action
	// for an unhandled drain is termination, and a termination unloads the module, which drops
	// every subscription it held - so without a handler this case would race the teardown
	// against its own EventWait and fail or pass on scheduling alone. That was this test's
	// first version, and it was flaky rather than wrong: the event was being posted and then
	// discarded with the subscription before anything read it.
	handled := make(chan struct{}, 4)
	require.NoError(t, sub.SyscallSignalHandle(func(kernel.SignalInfo) {
		handled <- struct{}{}
	}))

	require.NoError(t, sub.SyscallSignalSend(pid, kernel.SignalDrain))

	// Waited on in this goroutine rather than a background one. The event is posted before the
	// handler runs, and both happen in one dispatch, so by the time the handler signals there
	// is already a pending event and the wait returns it instead of racing for it.
	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("the drain handler never ran, so this case would not be testing a delivery")
	}

	e := evWait(t, sub, fd, kernel.EventDraining)
	assert.Equal(t, pid, e.Subject, "the event names the pid that entered drain")
	assert.Equal(t, string(kernel.SignalDrain), e.Detail)

	// The module is still loaded and still able to act, which is the property the ordering
	// exists to give a subscriber: it hears about the wind-down from a module that has not been
	// torn down yet, rather than about a pid that is already gone.
	require.NoError(t, sub.SyscallLog(kernel.LogInfo, "still alive after the drain event"))
}

// TestADrainToAGoneModuleIsNotAnEvent is the ordering case the post above exists to fix. The
// target's signal endpoint outlives its process record only briefly, but a drain that is
// dropped must not announce a wind-down that did not happen.
func TestADrainToAGoneModuleIsNotAnEvent(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	// The subscriber is a different module, so it survives the target's unload and can assert
	// what it did NOT receive.
	watchPID, watch, fd := evSubscribe(t, k, nil, kernel.EventDraining)
	defer func() { _ = k.Unload(watchPID) }()
	// The subscriber is a different module from the target, so it survives the target's unload
	// and can assert what it did not receive.

	targetPID, _ := chLoad(t, k, nil, kernel.OpEventWait)
	require.NoError(t, k.Unload(targetPID))

	// Init is the domain that reaches every module, so the host sends the drain. It may be
	// refused outright or queued and then dropped; either way it must not announce a
	// wind-down.
	err := k.InitContext().SyscallSignalSend(targetPID, kernel.SignalDrain)
	t.Logf("drain to an unloaded pid: err=%v", err)
	// Give a queued signal time to reach its dispatch, since the drop happens there and not
	// at send.
	time.Sleep(200 * time.Millisecond)

	// The watcher must not hear about a wind-down that never happened.
	_, waitErr := watch.SyscallEventWait(fd, kernel.KernelClock().Deadline(200*time.Millisecond))
	assert.ErrorIs(t, waitErr, kernel.ErrNoEvents,
		"a drain dropped for a target that is gone must not post draining")
}

// TestAFinishedRunIsAnEvent covers job.finished, posted from sched.finish - the one place that
// knows the terminal state, and reached by four different paths.
func TestAFinishedRunIsAnEvent(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, ctx, fd := evSubscribe(t, k, []kernel.Op{kernel.OpSchedSpawn}, kernel.EventJobFinished, kernel.EventDeadlinePassed)
	defer func() { _ = k.Unload(pid) }()

	// Subscribed BEFORE the work is spawned, which the ordering requires: a post that arrives
	// before the subscription exists is not delivered to it, and has never been.
	ran, err := ctx.SyscallSchedSpawn(kernel.SchedJob{
		Label: "wired",
		Fn:    func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)
	outcome, err := ctx.SyscallSchedWait(ran)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedCompleted, outcome.State)
	require.NoError(t, ctx.SyscallClose(ran))

	e := evWait(t, ctx, fd, kernel.EventJobFinished)
	assert.Equal(t, pid, e.Subject, "the event is about the pid whose run finished")
	assert.Equal(t, string(kernel.SchedCompleted), e.Detail, "and carries the terminal state")
}

// TestATimedOutRunIsBothEvents covers deadline.passed, and the reason one finish posts two
// names: job.finished says a run reached a terminal state, deadline.passed says the deadline
// expired unmet. A subscriber waiting only on the second gets the fact it asked for and not the
// four other terminal states it did not.
func TestATimedOutRunIsBothEvents(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, ctx, fd := evSubscribe(t, k, []kernel.Op{kernel.OpSchedSpawn}, kernel.EventJobFinished, kernel.EventDeadlinePassed)
	defer func() { _ = k.Unload(pid) }()

	// A run that ignores its cancellation, which is the only way to reach the timed-out state:
	// a job that returned when cancelled is recorded as cancelled instead, and the abandoned
	// path - the one that posts deadline.passed - would never run. The release channel is
	// closed by the cleanup below so the abandoned goroutine does not outlive the test.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	ran, err := ctx.SyscallSchedSpawn(kernel.SchedJob{
		Label:         "wired-timeout",
		TimeoutMillis: 30,
		Fn: func(kernel.SContext, <-chan struct{}) {
			<-release
		},
	})
	require.NoError(t, err)
	outcome, err := ctx.SyscallSchedWait(ran)
	require.NoError(t, err)
	require.Equal(t, kernel.SchedTimedOut, outcome.State,
		"the run must actually time out, or this case asserts nothing about deadline.passed")
	require.NoError(t, ctx.SyscallClose(ran))

	// Both names arrive from one dispatch, and they arrive in ONE call: EventWait drains the
	// whole pending backlog rather than returning one event, so waiting twice would time out on
	// the second wait even though both facts were posted. That batching is the subscription's
	// documented shape, and asserting it here is what keeps this case from being rewritten into
	// a loop that looks equivalent and is not.
	got, err := ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(5*time.Second))
	require.NoError(t, err)
	seen := map[kernel.KernelEventName]kernel.Event{}
	for _, e := range got {
		seen[e.Name] = e
	}
	require.Contains(t, seen, kernel.EventDeadlinePassed, "the expired deadline is posted")
	require.Contains(t, seen, kernel.EventJobFinished, "and so is the terminal state")
	assert.Equal(t, pid, seen[kernel.EventDeadlinePassed].Subject)
	assert.Equal(t, "wired-timeout", seen[kernel.EventDeadlinePassed].Detail,
		"the detail is the run label, which is what makes the event actionable")
}

// TestPublishedConfigurationIsAnEvent covers config.reloaded, which is broadcast rather than
// targeted because a published value is visible to every module holding metadata:read.
func TestPublishedConfigurationIsAnEvent(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	// metadata:read as well as event:wait, because this case asserts the published value is
	// readable by the time the event arrives, which is the ordering the post is placed for.
	pid, ctx, fd := evSubscribe(t, k, []kernel.Op{kernel.OpMetadataRead},
		kernel.EventConfigReloaded)
	defer func() { _ = k.Unload(pid) }()

	require.NoError(t, k.Publish("wired.key", "wired-value"))

	e := evWait(t, ctx, fd, kernel.EventConfigReloaded)
	assert.Equal(t, kernel.PID(0), e.Subject, "a published fact belongs to the kernel, not to a pid")
	assert.Equal(t, "wired.key", e.Detail, "the key rides in the detail so a subscriber knows what to re-read")

	// The value is readable by the time the event arrives, which is the ordering the post is
	// placed for: a subscriber woken by this event is meant to go and read the configuration.
	v, err := ctx.SyscallMetadataGet("wired.key")
	require.NoError(t, err, "the published value is readable after the event")
	assert.Equal(t, "wired-value", v)

	// And the value never rides in the event: configuration can carry a credential, and the
	// event path is readable by every subscriber.
	require.NoError(t, k.Publish("wired.secret", "sk-do-not-broadcast"))
	e = evWait(t, ctx, fd, kernel.EventConfigReloaded)
	assert.Equal(t, "wired.secret", e.Detail)
	assert.NotContains(t, e.Detail, "sk-do-not-broadcast")
}

// TestAnUnloadedModuleIsAPeerDisconnection covers the one event that was already wired, so this
// file pins it rather than assuming the other six are the only regressions possible.
func TestAnUnloadedModuleIsAPeerDisconnection(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	watchPID, watch, fd := evSubscribe(t, k, nil, kernel.EventPeerDisconnected)
	defer func() { _ = k.Unload(watchPID) }()

	gone, _ := chLoad(t, k, nil, kernel.OpLogWrite)
	require.NoError(t, k.Unload(gone))

	e := evWait(t, watch, fd, kernel.EventPeerDisconnected)
	assert.Equal(t, gone, e.Subject, "the event names the pid that is gone")
}

// TestAnUnpostedEventNeverArrives is the negative control for the whole file. Every case above
// triggers a real fact through a real kernel path; this one asserts that a name with no post
// site produces nothing, so a passing suite means the posts exist and not that the
// subscriptions are somehow always satisfied.
func TestAnUnpostedEventNeverArrives(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	// stream.aborted is the one closed-set name this file does not wire, and the reason is
	// file ownership rather than a judgement that it should not be posted. The site that knows
	// the fact is abortStream() in pipe.go, which latches the abort and broadcasts to both ends;
	// pipe.go is the other half of this kepoll work, and it owns pipe.readable too. Subscribing
	// to the name from here must therefore hear nothing.
	pid, ctx, fd := evSubscribe(t, k, []kernel.Op{kernel.OpSignalSend}, kernel.EventStreamAborted)
	defer func() { _ = k.Unload(pid) }()

	// Everything the other cases trigger, and still nothing on this name.
	require.NoError(t, ctx.SyscallSignalSend(pid, kernel.SignalReload))
	require.NoError(t, k.Publish("negative.control", "1"))

	_, err := ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(200*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrNoEvents,
		"a subscription to a name with no post site must hear nothing rather than everything")
}

// TestEveryClosedSetNameIsEitherPostedOrDocumented keeps the closed set honest. A name that no
// subsystem posts is a subscription that silently never fires, which is the defect this file
// exists to cover, and the way it stayed hidden is that nothing enumerated the set against the
// post sites.
//
// It asserts on the names rather than by scanning source, so the list below is the thing a
// reviewer reads: every name is either produced by a kernel path this file exercises, or is
// listed with the reason it is not.
func TestEveryClosedSetNameIsEitherPostedOrDocumented(t *testing.T) {
	posted := map[kernel.KernelEventName]string{
		kernel.EventSignalDelivered:  "signal.go, on delivery beside the audit record",
		kernel.EventDraining:         "signal.go, above both delivery branches and below the liveness check",
		kernel.EventJobFinished:      "sched.go, from finish, the one place that knows the terminal state",
		kernel.EventDeadlinePassed:   "sched.go, from finish when the state is timed out",
		kernel.EventConfigReloaded:   "boot.go, from Publish, which is what publishes configuration",
		kernel.EventPeerDisconnected: "module.go, on unload",
	}
	// Names in the closed set that no kernel path posts yet, each with the file that owns the
	// site and why the post is not here. Neither is a judgement that it should never be posted:
	// both sites live in pipe.go, so wiring them from this file would mean editing across a
	// boundary that is being worked in parallel. Adding a post site for one means removing it
	// from this map, which is the review question the map exists to force.
	unposted := map[kernel.KernelEventName]string{
		kernel.EventPipeReadable: "pipe.go owns the site: the wake-up broadcasts on close, write, " +
			"read and abort",
		kernel.EventStreamAborted: "pipe.go owns the site too: abortStream() is what latches the " +
			"abort and broadcasts to both ends. The abort already travels inline on a pipe chunk, " +
			"so a post is a second channel for one fact and has to be written where both are " +
			"visible, which is not this file",
	}

	for _, name := range kernel.KernelEvents() {
		where, isPosted := posted[name]
		why, isKnown := unposted[name]
		if isPosted {
			assert.NotEmpty(t, where, "%q is posted, and where matters to a reader", name)
			continue
		}
		assert.True(t, isKnown,
			"%q is in the closed set but is neither posted by a kernel path nor listed with the "+
				"file that owns its site: a subscription to it silently never fires, which is "+
				"exactly the defect this file covers", name)
		assert.NotEmpty(t, why,
			"%q has no post site, and naming the file that owns one is what keeps it pending "+
				"rather than forgotten", name)
	}
	assert.Len(t, posted, 6, "six of the eight names are posted by kernel paths")
	assert.Len(t, unposted, 2, "and two have their site in pipe.go, which this file does not edit")
}
