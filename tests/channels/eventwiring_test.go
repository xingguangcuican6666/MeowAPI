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
// finish a supervised run, publish configuration, unload a module, write to a pipe - and assert
// a subscriber hears about it without any test-side post. Removing the post site in the
// subsystem turns the corresponding case red.
//
// All eight names in the closed set are covered: six were wired from the kernel side in the
// commit that created this file, and the last two - pipe.readable and stream.aborted - have
// their sites in pipe.go and are covered here too. A subscription to any name in the set now
// hears the kernel; the enumeration test at the bottom asserts that stays true.

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

// TestASubscriptionHearsOnlyItsOwnName is the negative control for the whole file. Every other
// case triggers a real fact and asserts its name arrives; this one asserts that a subscription
// hears nothing when the facts triggered are other names'. Without it, a suite could pass
// because subscriptions are always satisfied - a filter that lets everything through would
// make every positive case green and would be a worse defect than a missing post.
//
// stream.aborted is the subscribed name and pipe facts are among the triggers, which is the
// sharpest version of the control: pipe.readable and stream.aborted are posted by the same
// file, two of them by the same function, so a subscription filter that confused one for the
// other is exactly the failure this rules out.
func TestASubscriptionHearsOnlyItsOwnName(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, ctx, fd := evSubscribe(t, k,
		[]kernel.Op{kernel.OpSignalSend, kernel.OpPipeOpen, kernel.OpPipeWrite},
		kernel.EventStreamAborted)
	defer func() { _ = k.Unload(pid) }()

	// Facts for four other names, and nothing for this one. No stream is aborted in this
	// test, so the subscription must stay empty.
	require.NoError(t, ctx.SyscallSignalSend(pid, kernel.SignalReload))
	require.NoError(t, k.Publish("negative.control", "1"))
	pipeFD, err := ctx.SyscallOpenPipe("negative-control", 0, kernel.PipeNonBlocking)
	require.NoError(t, err)
	_, err = ctx.SyscallPipeWrite(pipeFD, []byte("not an abort"), 0)
	require.NoError(t, err)

	_, err = ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(200*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrNoEvents,
		"a subscription must hear only its own names, not everything the kernel posts")
}

// TestAWrittenChunkIsAPipeReadableEvent covers pipe.readable's data half. The post is in
// write() after the chunk is on the queue, so a subscriber woken by the event is never woken
// ahead of the fact it names.
//
// The read after the wait is the property, not padding: it uses no deadline, so if the event
// could ever arrive before the chunk was readable - or if it were posted at a site where the
// pipe is not in fact readable - this call would block forever and the test would fail as a
// timeout. The event promises that a read returns immediately; the test holds it to that
// literally.
func TestAWrittenChunkIsAPipeReadableEvent(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, ctx, fd := evSubscribe(t, k,
		[]kernel.Op{kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead},
		kernel.EventPipeReadable)
	defer func() { _ = k.Unload(pid) }()

	pipeFD, err := ctx.SyscallOpenPipe("stream-events", 0, kernel.PipeBlocking)
	require.NoError(t, err)

	// Opening is not posting: nothing is readable yet, and a subscriber that heard
	// "readable" from an open would block on the first read.
	_, err = ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(100*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrNoEvents, "an open pipe is not a readable pipe")

	_, err = ctx.SyscallPipeWrite(pipeFD, []byte("chunk"), 0)
	require.NoError(t, err)

	e := evWait(t, ctx, fd, kernel.EventPipeReadable)
	assert.Equal(t, pid, e.Subject, "the event is about the pid that reads this pipe")
	assert.Equal(t, "stream-events", e.Detail, "the detail names the pipe, never its content")

	// Undeadlined: the event said readable, so this must return, not block.
	got, err := ctx.SyscallPipeRead(pipeFD, 0)
	require.NoError(t, err)
	assert.Equal(t, []byte("chunk"), got)
}

// TestAClosedPipeEndsTheStreamAsAnEvent covers pipe.readable's ended half: the name's contract
// is "has data or ended", and close is how a stream ends without an abort. A subscriber parked
// on events rather than on a blocking read learns the peer is done from the event, and the
// read below - again undeadlined - proves the event arrives only after the close is committed.
func TestAClosedPipeEndsTheStreamAsAnEvent(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, ctx, fd := evSubscribe(t, k,
		[]kernel.Op{kernel.OpPipeOpen, kernel.OpPipeRead}, kernel.EventPipeReadable)
	defer func() { _ = k.Unload(pid) }()

	pipeFD, err := ctx.SyscallOpenPipe("closing", 0, kernel.PipeBlocking)
	require.NoError(t, err)
	require.NoError(t, ctx.SyscallClose(pipeFD))

	e := evWait(t, ctx, fd, kernel.EventPipeReadable)
	assert.Equal(t, pid, e.Subject)
	assert.Equal(t, "closing", e.Detail)

	// The registry entry is gone with the close, so the fd no longer resolves; what the
	// ordering guarantees is that the event was posted after closed was set, the capacity
	// was released and the broadcast woke any blocked end. A read that had blocked here
	// would fail the test as a timeout rather than an assertion, which is the point of
	// leaving the deadline off everywhere in these cases.
	_, err = ctx.SyscallPipeRead(pipeFD, 0)
	assert.Error(t, err, "a closed pipe's fd is no longer a pipe")
}

// TestAnAbortIsAStreamAbortedEvent covers stream.aborted, and the deliberate second post it
// makes: abortStream ends the stream, and pipe.readable's contract is "has data or ended", so
// an abort posts both names. One is the fact a handler asks about (the client disconnected),
// the other keeps the readability promise (a read on this pipe now returns instead of
// blocking). A subscriber to either name hears the abort from the function that latches it.
func TestAnAbortIsAStreamAbortedEvent(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, ctx, fd := evSubscribe(t, k,
		[]kernel.Op{kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead},
		kernel.EventStreamAborted, kernel.EventPipeReadable)
	defer func() { _ = k.Unload(pid) }()

	pipeFD, err := ctx.SyscallOpenPipe("client-stream", 0, kernel.PipeNonBlocking)
	require.NoError(t, err)
	_, err = ctx.SyscallPipeWrite(pipeFD, []byte("partial"), 0)
	require.NoError(t, err)
	// Drain the write's readable event so the waits below see only the abort's posts.
	evWait(t, ctx, fd, kernel.EventPipeReadable)

	require.NoError(t, ctx.SyscallPipeAbort(pipeFD))

	// Asserted on the raw batch rather than through evWait because this fact produces two
	// events at once and evWait drains the whole backlog while searching for one name: a
	// missing pipe.readable post would be swallowed by a batch that still carried
	// stream.aborted. Both names must be in the batch the abort posts.
	got, err := ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(3*time.Second))
	require.NoError(t, err)
	names := map[kernel.KernelEventName]kernel.Event{}
	for _, e := range got {
		names[e.Name] = e
	}
	require.Contains(t, names, kernel.EventStreamAborted, "the abort is the fact the name exists for")
	require.Contains(t, names, kernel.EventPipeReadable,
		"and the same abort ends the stream, so the readability promise fires with it")

	e := names[kernel.EventStreamAborted]
	assert.Equal(t, pid, e.Subject, "the event names the pid whose stream was cancelled")
	assert.Equal(t, "client-stream", e.Detail, "and carries the pipe name, never content")

	// The same abort also promised readability - here meaning "a read returns", with the
	// answer being end-of-stream. Undeadlined, as in every case in this file.
	_, err = ctx.SyscallPipeRead(pipeFD, 0)
	assert.ErrorIs(t, err, kernel.ErrPipeClosed)

	// Latching means one post. A second abort is a no-op on the stream and must be a no-op
	// on the bus too, or a module that retries its cancellation would spam its own
	// subscription with facts that are all the same fact.
	require.NoError(t, ctx.SyscallPipeAbort(pipeFD))
	_, err = ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(200*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrNoEvents, "a latched abort posts once")
}

// TestAReadDoesNotAnnounceReadability pins the one broadcast in pipe.go that deliberately
// does NOT post. read() broadcasts to wake blocked writers - space freed is a writability
// fact, not a readability one. Posting pipe.readable there would tell a subscriber to come
// read a pipe that just had its data consumed: the subscriber's read would block, and the
// event bus's one promise - hear it and a read returns - would be false at the site that
// consumes data. The absence asserted here is the rule, not an oversight.
func TestAReadDoesNotAnnounceReadability(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, ctx, fd := evSubscribe(t, k,
		[]kernel.Op{kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead},
		kernel.EventPipeReadable)
	defer func() { _ = k.Unload(pid) }()

	pipeFD, err := ctx.SyscallOpenPipe("drained", 0, kernel.PipeNonBlocking)
	require.NoError(t, err)
	_, err = ctx.SyscallPipeWrite(pipeFD, []byte("one"), 0)
	require.NoError(t, err)
	evWait(t, ctx, fd, kernel.EventPipeReadable)

	got, err := ctx.SyscallPipeRead(pipeFD, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)
	require.Equal(t, []byte("one"), got)

	_, err = ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(200*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrNoEvents,
		"consuming data wakes writers; it must not announce a readability that just ended")
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
		kernel.EventPipeReadable: "pipe.go, at the three sites where a blocked read now returns: " +
			"write (data), Close and abortStream (ended) - and deliberately not at read()",
		kernel.EventStreamAborted: "pipe.go, from abortStream after the latch commits",
	}
	// Names in the closed set that no kernel path posts, each with the file that owns the site
	// and why the post is not here. The map is empty - every name has a post site, and the
	// cases above pin each one - but the loop below keeps requiring the enumeration, so a
	// future name added to the closed set fails here until it is either wired with a case of
	// its own or listed here with the reason it is not. That is the review question this test
	// exists to force: the way seven unwired names stayed hidden is that nothing ever
	// compared the set to the sites that produce it.
	unposted := map[kernel.KernelEventName]string{}

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
	assert.Len(t, posted, 8, "every name in the closed set is posted by a kernel path")
	assert.Empty(t, unposted, "and none is pending")
}
