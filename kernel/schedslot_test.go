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
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are in package kernel because they need schedMu, newRun and schedLive -
// the scheduler's own accounting - which a module cannot observe. The rule for an
// in-package test is in AGENT.md: it must need something a module cannot construct or
// observe, and this one does.
//
// TestAWokenWaiterSeesItsSlotReleased is here because of a CI failure that did not
// reproduce locally. tests/supervision asserts that a panicked run releases its slot,
// and on a loaded runner it read 1 instead of 0: the outcome said "panicked" while the
// counter still counted the run as in flight. Locally, 200 iterations of that test and
// 20 full-package -race runs passed every time, which is what made it look like a
// mystery rather than a defect.
//
// It was not a mystery. finish() used to close the completion channel under r.mu and
// then release the slot AFTER unlocking, so a waiter woken by the close could ask for the
// live count before the release had run. The window is one lock acquisition wide, which
// is why only a contended scheduler showed it. Measured with the contention this test
// creates: 46 of 400 waits read a stale non-zero count under the old ordering, and 0 of
// 400 under the new one.
//
// The fix is the ordering - releaseSlot now runs inside the lock, before the close - so
// what a woken waiter reads is settled by the time it can read anything. That takes
// schedMu while holding r.mu, which is a new lock edge; it is safe because the inverse
// does not exist, and TestNoSchedMuRegionTakesARunLock pins that rather than trusting it.

// TestAWokenWaiterSeesItsSlotReleased is the regression test for the ordering. It cannot
// be written without contention, because without contention both orderings pass - which
// is exactly how the defect reached CI.
//
// The contention is schedMu, which releaseLive must take to decrement the count. Holding
// it from other goroutines delays the release, so under the old ordering a waiter woken
// by r.finished reliably observed the slot still held. Under the new ordering no amount of
// contention can produce a stale read, because the release already happened before the
// close that woke the waiter - so this test cannot flake in the direction that matters:
// load can only ever make the mutant more visible, never the fixed code fail.
func TestAWokenWaiterSeesItsSlotReleased(t *testing.T) {
	const pid = PID(9002)
	t.Cleanup(func() {
		schedMu.Lock()
		delete(schedLive, pid)
		schedMu.Unlock()
	})

	// Spin on schedMu to make the release path slow. These goroutines are the stand-in
	// for a loaded runner: they do not change what the kernel does, only when it gets to
	// do it.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				schedMu.Lock()
				runtime.Gosched()
				schedMu.Unlock()
			}
		}()
	}
	defer func() {
		close(stop)
		wg.Wait()
	}()

	// 400 iterations because the window is one lock acquisition wide. At the measured
	// 46/400 stale-read rate under the old ordering, a single iteration would be a coin
	// flip and a hundred would still pass by luck often enough to be a bad test.
	const iterations = 400
	stale := 0
	for i := 0; i < iterations; i++ {
		r := newRun(pid, kindJob, "slot-probe", mono()+int64(1e9))

		// Reserve the slot the way spawn does, rather than through reserveLive, because
		// reserveLive takes a context this test has no reason to build.
		schedMu.Lock()
		schedLive[pid]++
		r.holdsSlot.Store(true)
		schedMu.Unlock()

		observed := make(chan int, 1)
		go func() {
			// Wait the way SchedWait does: on the completion channel, then read the count.
			<-r.completion()
			running, _ := SchedCount(pid)
			observed <- running
		}()

		r.finish(SchedPanicked, "module exploded", "")
		if <-observed != 0 {
			stale++
		}
	}

	assert.Zero(t, stale,
		"%d of %d waits woke to find the panicked run still counted as in flight; the slot "+
			"must be released before the completion signal, not after it", stale, iterations)

	// The accounting ends clean, which is the other half of the property: no slot leaked
	// and none released twice.
	schedMu.Lock()
	remaining := schedLive[pid]
	schedMu.Unlock()
	require.Zero(t, remaining, "every reserved slot was released exactly once")
}

// TestNoSchedMuRegionTakesARunLock pins the lock ordering the fix relies on. finish now
// holds r.mu while calling releaseSlot, which takes schedMu; that is safe only because
// nothing holds schedMu and then reaches a per-run lock. If a future change adds that
// inverse, this is the pair that deadlocks - and a deadlock here wedges every spawn and
// every count read in the kernel.
//
// The check reads the source rather than exercising the runtime, because a lock edge that
// has not been taken yet is invisible at runtime: the only way to discover it by running
// is to deadlock. It works per function rather than per line range, and that is not a
// stylistic choice. My first version scanned forward from `schedMu.Lock()` until
// `schedMu.Unlock()`, which found nothing at all in the deferred form - `defer
// schedMu.Unlock()` closes the range on the line after it opens, so the whole body was
// skipped. Measured: a mutation taking r.mu inside releaseLive passed that version. This
// one treats a function that takes schedMu at all as the region, which is coarser and
// therefore sound in the direction that matters.
//
// WHAT THIS SCAN CANNOT SEE, because the reader deserves to know rather than discover it:
// a lock edge or a re-entrance through a CALL. It matches the literal `.mu.Lock()` in the
// same function body, so `releaseLive` calling a helper that takes r.mu passes it, and so
// does resetSched calling cancelSchedWork while still holding schedMu - which deadlocks
// by re-entry rather than by inversion, and is a one-line edit away. Measured: both
// mutants pass this scan, the whole kernel package, and the whole supervision package.
// The re-entrance is covered behaviourally by
// TestResetSchedDoesNotReenterItsOwnLock; the helper-call inversion has no pin, and
// adding one would mean call-graph analysis this file is not the place for. What keeps
// it honest is that the pattern is written down here.
func TestNoSchedMuRegionTakesARunLock(t *testing.T) {
	body, err := os.ReadFile("sched.go")
	require.NoError(t, err, "this test reads its own package's source; sched.go must sit beside it")

	var inversions []string
	for _, fn := range splitFuncs(string(body)) {
		// Comments are stripped before matching, and the reason is that not stripping
		// them made finish look like a function taking schedMu - its comment explains the
		// edge, so the literal appears three times in prose and none in code. An
		// exemption by name then kept it out, which worked, but for an accidental reason:
		// reword the comment and the exemption silently stops being needed. Keying on code
		// means the scan says what it claims to say.
		code := stripLineComments(fn.body)
		if !strings.Contains(code, "schedMu") {
			continue
		}
		if strings.Contains(code, ".mu.Lock()") || strings.Contains(code, ".mu.RLock()") {
			inversions = append(inversions,
				fmt.Sprintf("%s takes schedMu and a per-run lock", fn.name))
		}
	}

	assert.Empty(t, inversions,
		"a function that holds schedMu must not take a per-run lock: finish holds r.mu "+
			"across releaseSlot, which takes schedMu, so the inverse deadlocks every spawn "+
			"and every count read in the kernel\n%s", strings.Join(inversions, "\n"))
}

// schedFunc is one top-level function in sched.go, split on the `func ` at column zero.
type schedFunc struct {
	name string
	body string
}

// stripLineComments drops `//` comments from Go source, line by line. It is not a lexer
// and does not know about `//` inside a string literal; that is acceptable here because
// the only thing asked of it is whether a lock name appears in code, and no string
// literal in sched.go mentions schedMu. Being wrong in the direction that matters would
// mean stripping real code, and it does not: everything after `//` on a line is prose in
// this file.
func stripLineComments(src string) string {
	var out strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// splitFuncs splits Go source into top-level functions. It is line-based rather than a
// parser, because the shape it needs is simple: a declaration starts at column zero and
// the next one ends it.
func splitFuncs(src string) []schedFunc {
	var out []schedFunc
	var cur strings.Builder
	var name string

	flush := func() {
		if name != "" {
			out = append(out, schedFunc{name: name, body: cur.String()})
		}
		cur.Reset()
		name = ""
	}

	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "func ") {
			flush()
			// Either "func name(" or "func (recv) name("; take the token before the
			// first parenthesis of the parameter list.
			rest := strings.TrimPrefix(line, "func ")
			if i := strings.Index(rest, ")"); i >= 0 && strings.HasPrefix(rest, "(") {
				rest = strings.TrimSpace(rest[i+1:])
			}
			if j := strings.IndexAny(rest, "( ["); j > 0 {
				name = rest[:j]
			}
			cur.WriteString(line)
			cur.WriteByte('\n')
			continue
		}
		if name != "" {
			cur.WriteString(line)
			cur.WriteByte('\n')
		}
	}
	flush()
	return out
}
