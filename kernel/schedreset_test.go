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

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResetSchedDoesNotReenterItsOwnLock is the behavioural half of the lock-edge pin,
// and it exists because the source scan could not see this shape.
//
// schedMu is not reentrant. resetSched holds it while copying the pid list, then unlocks
// and calls cancelSchedWork, which reaches finish, which now calls releaseSlot BEFORE the
// completion signal - and releaseSlot takes schedMu. So if anyone ever moves that call
// inside the lock region - a one-line edit that reads like tidying - the goroutine
// deadlocks on itself. In production that is Shutdown hanging, and CI's -timeout only
// makes it look like a slow run.
//
// Measured: the source scan passes the mutant, the whole kernel package passes it, the
// whole supervision package passes it, and this probe fails in five seconds. It is the
// re-entrancy analogue of what receiptlock_test.go does for the deferred unlock: reach
// the shape from a test rather than hoping a suite wanders into it.
//
// The probe is bounded by a select, so the failure is REPORTED after five seconds with a
// message naming the cause - but it does not make the run cheap, and the header used to
// claim it did. A goroutine blocked forever inside a non-reentrant mutex wedges every
// later reader of that mutex, so the package still ends in "test timed out" and CI still
// pays its ten-minute ceiling. What the select buys is a diagnosis printed before the
// silence, which is the difference between a timeout an investigator can act on and one
// that says nothing at all.
func TestResetSchedDoesNotReenterItsOwnLock(t *testing.T) {
	const moduleName = "sched-reset-probe"
	Register(moduleName, func() (Module, error) { return &resetSchedProbe{}, nil })
	t.Cleanup(func() { Unregister(moduleName) })

	kc, err := Boot(BootConfig{Console: io.Discard,
		TrustRoot: BootTrustRoot{NodeID: "reset-sched-probe"}})
	require.NoError(t, err)
	// Shutdown is registered but skipped once the test has failed, because the failure
	// this test detects is a wedged schedMu and Shutdown calls resetSched. Measured: an
	// unconditional cleanup turned the deadlock into a hang that ran the whole package out
	// of time instead of reporting. It also matters in the passing case for a reason I
	// got wrong once: the kernel's boot guard is process-wide, so a test in this package
	// that boots and never shuts down makes every LATER test in the package fail with
	// "already booted" - measured as 9 unrelated tests in this package failing after this
	// one was added without it.
	defer func() {
		if t.Failed() {
			return
		}
		_ = kc.Shutdown()
	}()

	// A module holding sched:timer, so resetSched has a run to walk. A pending timer is
	// the shape that takes cancelSchedWork's `!started && timerSlot` branch and calls
	// finish directly, which is the path that reaches releaseSlot from inside the walk.
	pid, err := LoadModule(kc.InitContext(), Manifest{
		Name: moduleName, Version: "1",
		MinKernelAPI: KernelAPI, MaxKernelAPI: KernelAPI,
		Require: []Op{OpSchedTimer},
	})
	require.NoError(t, err)
	_ = pid

	_, err = SchedTimer(kc.InitContext().(*sContext), TimerSpec{
		Label: "pending-across-reset", DelayMillis: 600000,
		Fn: func(SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)

	running, timers := SchedCount(kc.InitContext().PID())
	require.Equal(t, 1, timers, "a pending timer must exist, or the walk has nothing to cancel")

	done := make(chan struct{})
	go func() {
		defer close(done)
		resetSched()
	}()

	select {
	case <-done:
		// Reached the end, which is the property. Anything left running is the timer this
		// test armed; resetSched cancelled it.
	case <-time.After(5 * time.Second):
		// t.Errorf rather than t.Fatalf so the deferred cleanup still runs - and return at
		// once, because the goroutine below is blocked holding schedMu and every assertion
		// after this point would block on the same mutex. Measured: continuing made the
		// failure a bare "test timed out" with the diagnosis buried above it.
		//
		// The package still cannot finish under this mutant, and that is inherent: a
		// goroutine blocked forever inside a non-reentrant mutex wedges every later reader
		// of it, and no test can undo that. What this test buys is the message naming the
		// cause, printed before the timeout, instead of a ten-minute silence.
		t.Errorf("resetSched deadlocked: it holds schedMu across a call that takes it again " +
			"(cancelSchedWork -> finish -> releaseSlot). Unlock before walking runs.")
		return
	}

	after, timersAfter := SchedCount(kc.InitContext().PID())
	assert.Zero(t, after, "the walk finished every run it found")
	assert.Zero(t, timersAfter)
	assert.Zero(t, running, "and there was nothing in flight to begin with")
}

// resetSchedProbe is a module that does nothing; the test is about what resetSched does
// around it.
type resetSchedProbe struct{}

func (*resetSchedProbe) OnLoad(SContext) error { return nil }
func (*resetSchedProbe) OnUnload() error       { return nil }
