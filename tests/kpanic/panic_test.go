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

// Package kpanic tests the crash dump and ledger flush.
//
// The package is named kpanic rather than panic because panic is a predeclared
// identifier, and a package whose name shadows a builtin is legal but makes every
// reader check which one a call site means. The subsystem is kpanic throughout.
//
// Nothing here crashes the test binary. A test that panics to the top level or calls
// os.Exit kills the whole suite and every other package's results with it, so the
// flush is tested as a callable function and the top-level paths are tested in a
// subprocess where that is the only way to observe them.
package kpanic

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/internal/auditfile"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// panicCounter gives every test a unique module name, so a registration or a meter
// record left behind by an earlier test cannot be mistaken for this test's.
var panicCounter int

func panicNextName(prefix string) string {
	panicCounter++
	return prefix + harness.Itoa(panicCounter)
}

func panicBoot(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "node-panic"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// panicResetChain removes every notifier a test registered. Notifiers are package
// state and resetPanic is unexported, so this is the only way to keep one test's
// notifier from running during another test's flush - where it would report counts
// that belong to nobody.
func panicResetChain(t *testing.T) {
	t.Helper()
	for _, n := range kernel.PanicNotifiers() {
		kernel.PanicUnregister(n)
	}
	t.Cleanup(func() {
		for _, n := range kernel.PanicNotifiers() {
			kernel.PanicUnregister(n)
		}
	})
	kernel.PanicSetCrashWriter(nil)
}

// panicLoadModule loads a module and returns its context plus pid.
func panicLoadModule(t *testing.T, k *kernel.Kernel, prefix string) (kernel.SContext, kernel.PID) {
	t.Helper()
	name := panicNextName(prefix)
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpMeterRecord, kernel.OpUsageEmit},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, probe.Ctx)
	return probe.Ctx, pid
}

// ---------------------------------------------------------------------------
// The money half: unsettled metering must not vanish.

// TestFlushClosesEveryOpenMeterRequestAsAbandoned is the reason this subsystem
// exists. A request that was served and recorded but not closed is a billable fact
// that lives only in memory; if the process dies without closing it, the operator
// loses revenue and a mesh peer loses the settlement it was owed.
func TestFlushClosesEveryOpenMeterRequestAsAbandoned(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	k := panicBoot(t)
	ctx, _ := panicLoadModule(t, k, "panicmeter")

	const open = 5
	ids := make([]kernel.RequestID, 0, open)
	for range open {
		id, err := kernel.MeterOpen(ctx, kernel.TraceID("trace-panic"), "/v1/chat/completions")
		require.NoError(t, err)
		ids = append(ids, id)
	}
	require.Equal(t, open, kernel.MeterTotalsSnapshot().Open,
		"the requests must actually be open before the flush can close them")

	// One is closed normally, so the flush must not claim credit for work that was
	// already settled.
	_, err := kernel.MeterClose(ctx, ids[0], 200)
	require.NoError(t, err)

	kernel.PanicRegisterBuiltins()
	rec := kernel.PanicFlush("test: meter")

	var meter *kernel.PanicOutcome
	for i := range rec.Outcomes {
		if rec.Outcomes[i].Name == "meter" {
			meter = &rec.Outcomes[i]
		}
	}
	require.NotNil(t, meter, "the meter notifier must have run")
	assert.True(t, meter.Completed, "the meter flush completed: %s", meter.Detail)
	assert.Equal(t, open-1, meter.Saved, "every still-open request was closed and counted")
	assert.Zero(t, meter.Lost, "nothing was left open")
	assert.Zero(t, kernel.MeterTotalsSnapshot().Open, "the ledger holds no open request")

	// And the closed requests are marked abandoned rather than settled, because a
	// request the kernel closed on a dying process's behalf did not complete. That
	// distinction is what keeps a crash from looking like a successful settlement.
	assert.GreaterOrEqual(t, kernel.MeterTotalsSnapshot().Abandoned, int64(open-1),
		"the requests closed by the flush are recorded as abandoned")
}

// TestFlushWithNothingOpenSaysSo covers the empty case. A notifier that reports
// "saved 0" without saying why looks like a failure, and the detail is what
// distinguishes "there was nothing to save" from "saving did not work".
func TestFlushWithNothingOpenSaysSo(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	kernel.PanicRegisterBuiltins()
	rec := kernel.PanicFlush("test: empty")

	var meter *kernel.PanicOutcome
	for i := range rec.Outcomes {
		if rec.Outcomes[i].Name == "meter" {
			meter = &rec.Outcomes[i]
		}
	}
	require.NotNil(t, meter)
	assert.True(t, meter.Completed)
	assert.Zero(t, meter.Saved)
	assert.Contains(t, meter.Detail, "no open requests")
}

// ---------------------------------------------------------------------------
// Ordering, containment and the honesty of the record.

// TestNotifiersRunInRegistrationOrder pins the order, because it is load-bearing: a
// notifier that writes to the audit chain must run before the one that flushes the
// sink, or its own record is what gets lost.
func TestNotifiersRunInRegistrationOrder(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	var seen []string
	for _, n := range []string{"first", "second", "third"} {
		name := n
		require.NoError(t, kernel.PanicRegister(name, func() kernel.PanicOutcome {
			seen = append(seen, name)
			return kernel.PanicOutcome{Completed: true}
		}, time.Second))
	}
	assert.Equal(t, []string{"first", "second", "third"}, kernel.PanicNotifiers())

	rec := kernel.PanicFlush("test: order")
	assert.Equal(t, []string{"first", "second", "third"}, seen)

	got := make([]string, 0, len(rec.Outcomes))
	for _, o := range rec.Outcomes {
		got = append(got, o.Name)
	}
	assert.Equal(t, seen, got, "the record reports the order it ran in")
}

// TestAPanickingNotifierDoesNotStopTheRest is the containment property. A flush that
// aborts on its first failure saves nothing at all, and the failure is recorded
// rather than swallowed.
func TestAPanickingNotifierDoesNotStopTheRest(t *testing.T) {
	buf := harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	var ranAfter bool
	require.NoError(t, kernel.PanicRegister("explodes", func() kernel.PanicOutcome {
		panic("notifier exploded")
	}, time.Second))
	require.NoError(t, kernel.PanicRegister("after", func() kernel.PanicOutcome {
		ranAfter = true
		return kernel.PanicOutcome{Completed: true, Saved: 1}
	}, time.Second))

	rec := kernel.PanicFlush("test: panic in notifier")
	assert.True(t, ranAfter, "the notifier after a panicking one still ran")

	var exploded, after *kernel.PanicOutcome
	for i := range rec.Outcomes {
		switch rec.Outcomes[i].Name {
		case "explodes":
			exploded = &rec.Outcomes[i]
		case "after":
			after = &rec.Outcomes[i]
		}
	}
	require.NotNil(t, exploded)
	assert.False(t, exploded.Completed)
	assert.Contains(t, exploded.Detail, "panicked")
	assert.Contains(t, exploded.Detail, "notifier exploded")
	require.NotNil(t, after)
	assert.True(t, after.Completed)

	// The failure reached the console and the chain rather than only the returned
	// struct, because a flush on the way out of a process may leave no caller to read
	// that struct. A notifier that fails silently would make the dump look complete.
	assert.Contains(t, buf.String(), "panic notifier panicked")
	var sawNotifierPanic bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPanic}) {
		if e.Fields["notifier"] == "explodes" {
			sawNotifierPanic = true
		}
	}
	assert.True(t, sawNotifierPanic, "the panicking notifier is on the audit chain")
}

// TestAHangingNotifierIsAbandonedAfterItsBudget is the bound. A notifier that hangs
// must not hang the exit, and the abandonment is reported rather than hidden. The
// budget is short so this test is short; what it asserts is the mechanism, not a
// duration.
func TestAHangingNotifierIsAbandonedAfterItsBudget(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	require.NoError(t, kernel.PanicRegister("hangs", func() kernel.PanicOutcome {
		<-release
		return kernel.PanicOutcome{Completed: true}
	}, 20*time.Millisecond))
	require.NoError(t, kernel.PanicRegister("after", func() kernel.PanicOutcome {
		return kernel.PanicOutcome{Completed: true}
	}, time.Second))

	start := time.Now()
	rec := kernel.PanicFlush("test: hang")
	elapsed := time.Since(start)

	var hung, after *kernel.PanicOutcome
	for i := range rec.Outcomes {
		switch rec.Outcomes[i].Name {
		case "hangs":
			hung = &rec.Outcomes[i]
		case "after":
			after = &rec.Outcomes[i]
		}
	}
	require.NotNil(t, hung)
	assert.False(t, hung.Completed)
	assert.Contains(t, hung.Detail, "abandoned")
	require.NotNil(t, after)
	assert.True(t, after.Completed, "the flush continued past the abandoned notifier")

	assert.Less(t, elapsed, 5*time.Second,
		"the flush must not wait for a hung notifier; it took %s", elapsed)
}

// TestTheCauseIsRecordedBeforeTheOutcomeIsKnown is the ordering that makes a partial
// flush still useful. The reason, the boot identity and the stack go down first, so a
// flush that then dies leaves behind why it was running.
func TestTheCauseIsRecordedBeforeTheOutcomeIsKnown(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	before := len(kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPanic}))

	require.NoError(t, kernel.PanicRegister("dies", func() kernel.PanicOutcome {
		panic("flush died here")
	}, time.Second))
	kernel.PanicFlush("test: cause first")

	panics := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPanic})
	require.Greater(t, len(panics), before, "a flush writes to the chain")

	// Found by message rather than by position. A notifier may add its own record
	// between the two - a panicking one does - so an index-based assertion would break
	// on exactly the case this test is about. What is load-bearing is the order: the
	// cause is on the chain before anything that could fail has run.
	newRecords := panics[before:]
	begun, complete := -1, -1
	for i, e := range newRecords {
		switch {
		case begun < 0 && e.Msg == "kernel flush begun":
			begun = i
			assert.Equal(t, "test: cause first", e.Fields["reason"],
				"the cause record carries the reason it was given")
			assert.Contains(t, e.Fields, "stack_bytes")
			assert.Contains(t, e.Fields, "open_requests")
		case complete < 0 && e.Msg == "kernel flush complete":
			complete = i
		}
	}
	require.NotEqual(t, -1, begun, "the cause was recorded")
	require.NotEqual(t, -1, complete, "and the outcome was recorded")
	assert.Less(t, begun, complete,
		"the cause must be on the chain before the outcome, so a flush that dies partway still leaves the reason behind")
}

// TestTheRecordSaysWhatWasLostNotOnlyWhatWasSaved is the honesty property. A sink
// that cannot flush must be reported as not durable, because a write sitting in an OS
// buffer is not durable across a machine crash and an operator who believes otherwise
// will trust a chain that is missing its tail.
func TestTheRecordSaysWhatWasLostNotOnlyWhatWasSaved(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	// No sink installed: the chain is memory-only and dies with the process.
	kernel.PanicRegisterBuiltins()
	rec := kernel.PanicFlush("test: no sink")

	var sinkOut *kernel.PanicOutcome
	for i := range rec.Outcomes {
		if rec.Outcomes[i].Name == "audit-sink" {
			sinkOut = &rec.Outcomes[i]
		}
	}
	require.NotNil(t, sinkOut)
	assert.False(t, sinkOut.Completed, "a memory-only chain is not durable and must not claim to be")
	assert.Contains(t, sinkOut.Detail, "memory-only")
	assert.Positive(t, sinkOut.Lost, "the record counts what dies with the process")

	// No crash writer: the console half is honest the same way.
	var consoleOut *kernel.PanicOutcome
	for i := range rec.Outcomes {
		if rec.Outcomes[i].Name == "console" {
			consoleOut = &rec.Outcomes[i]
		}
	}
	require.NotNil(t, consoleOut)
	assert.False(t, consoleOut.Completed)
	assert.Contains(t, consoleOut.Detail, "no crash writer")
}

// TestAFlushWithADurableSinkReportsItselfDurable is the other half of the above. With
// a real file sink installed the audit half completes, and the file on disk holds the
// chain including the flush's own records.
func TestAFlushWithADurableSinkReportsItselfDurable(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)

	path := filepath.Join(t.TempDir(), "audit", "chain.jsonl")
	sink, err := auditfile.New(auditfile.Options{Path: path, SyncEvery: 1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-panic-sink"},
		AuditSink: sink,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	crashPath := filepath.Join(t.TempDir(), "crash.log")
	crashFile, err := os.Create(crashPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = crashFile.Close() })
	kernel.PanicSetCrashWriter(crashFile)

	kernel.PanicRegisterBuiltins()
	rec := kernel.PanicFlush("test: durable")

	var sinkOut, consoleOut *kernel.PanicOutcome
	for i := range rec.Outcomes {
		switch rec.Outcomes[i].Name {
		case "audit-sink":
			sinkOut = &rec.Outcomes[i]
		case "console":
			consoleOut = &rec.Outcomes[i]
		}
	}
	require.NotNil(t, sinkOut)
	assert.True(t, sinkOut.Completed, "a file sink with Flush is durable: %s", sinkOut.Detail)
	require.NotNil(t, consoleOut)
	assert.True(t, consoleOut.Completed, "a crash writer was installed: %s", consoleOut.Detail)

	// The file on disk holds the chain, and it still verifies. This is the property
	// that makes tools/auditverify's verdict meaningful after a crash.
	entries, err := auditfile.Read(path)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	segments, badSegment, badEntry := auditfile.VerifyFile(entries)
	assert.Equal(t, -1, badSegment, "segment %d entry %d does not verify", badSegment, badEntry)
	assert.Equal(t, -1, badEntry)
	assert.GreaterOrEqual(t, segments, 1)

	var sawFlush bool
	for _, e := range entries {
		if e.Kind == kernel.AuditPanic {
			sawFlush = true
		}
	}
	assert.True(t, sawFlush, "the flush's own records reached the durable file")

	// And the crash writer holds the console tail.
	require.NoError(t, crashFile.Sync())
	written, err := os.ReadFile(crashPath)
	require.NoError(t, err)
	assert.NotEmpty(t, written, "the console history was persisted to the crash writer")
}

// TestTheChainStillVerifiesAfterAFlush pins that saving evidence does not corrupt it.
// A crash dump that breaks the hash chain is worse than no crash dump, because it
// makes every earlier record unverifiable too.
func TestTheChainStillVerifiesAfterAFlush(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	kernel.PanicRegisterBuiltins()
	rec := kernel.PanicFlush("test: chain integrity")
	assert.True(t, rec.ChainVerified, "the chain must still verify after a flush")

	entries := kernel.AuditQuery(kernel.AuditFilter{})
	assert.Equal(t, -1, kernel.VerifyChain(entries, kernel.AuditGenesis))
}

// ---------------------------------------------------------------------------
// Registration, concurrency and reset.

// TestRegistrationRefusesWhatWouldMakeTheChainMeaningless covers the setter's own
// validation: an unnamed notifier cannot be reported on, and a negative budget is a
// request for something this file cannot give.
func TestRegistrationRefusesWhatWouldMakeTheChainMeaningless(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	ok := func() kernel.PanicOutcome { return kernel.PanicOutcome{Completed: true} }

	err := kernel.PanicRegister("", ok, time.Second)
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrPanicNotRegistered)

	err = kernel.PanicRegister("nilfn", nil, time.Second)
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrPanicNotRegistered)

	err = kernel.PanicRegister("negative", ok, -time.Second)
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrPanicNotRegistered)

	require.NoError(t, kernel.PanicRegister("dup", ok, time.Second))
	err = kernel.PanicRegister("dup", ok, time.Second)
	require.Error(t, err, "a duplicate name would make the report ambiguous")
	assert.ErrorIs(t, err, kernel.ErrPanicNotRegistered)

	// A zero budget takes the default rather than being refused, because "no opinion"
	// is a legitimate thing for a caller to have.
	require.NoError(t, kernel.PanicRegister("defaulted", ok, 0))
	assert.Contains(t, kernel.PanicNotifiers(), "defaulted")

	// Registering the builtins twice is idempotent, so a host can call it from init
	// and from main without the second call failing.
	kernel.PanicRegisterBuiltins()
	before := kernel.PanicNotifiers()
	kernel.PanicRegisterBuiltins()
	assert.Equal(t, before, kernel.PanicNotifiers(), "PanicRegisterBuiltins is idempotent")
}

// TestASecondConcurrentFlushDoesNotDoubleFlush pins the re-entrancy behaviour. A
// signal arriving during a panic unwind is a real path, and the second call must
// return immediately rather than queue behind a flush that may be the one that is
// hung.
func TestASecondConcurrentFlushDoesNotDoubleFlush(t *testing.T) {
	buf := harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	entered := make(chan struct{})
	// Released by sync.Once rather than by two close calls. The test body releases the
	// notifier explicitly, and a cleanup that also closed it would panic on a
	// double close - which, when it happens on an assertion failure, replaces the real
	// failure with an unrelated one.
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	require.NoError(t, kernel.PanicRegister("slow", func() kernel.PanicOutcome {
		close(entered)
		<-release
		return kernel.PanicOutcome{Completed: true}
	}, 5*time.Second))

	var first kernel.CrashRecord
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		first = kernel.PanicFlush("test: first")
	}()

	<-entered
	second := kernel.PanicFlush("test: second")

	assert.True(t, second.Concurrent, "the second call reports that it did nothing")
	assert.Empty(t, second.Outcomes, "and it ran no notifier")
	assert.Equal(t, "test: second", second.Reason)

	releaseOnce.Do(func() { close(release) })
	wg.Wait()
	assert.False(t, first.Concurrent)
	assert.Len(t, first.Outcomes, 1)

	// The refused second flush is still visible as a fault, because a flush that did
	// nothing is a fact an investigator should be able to see rather than infer.
	assert.Contains(t, buf.String(), "concurrent panic flush refused")
}

// TestFlushAfterShutdownDoesNotPanic covers the torn-down kernel. A flush is exactly
// the thing that runs when state is already partly gone, so it must not be the thing
// that panics.
func TestFlushAfterShutdownDoesNotPanic(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)

	k := panicBoot(t)
	ctx, _ := panicLoadModule(t, k, "panicgone")
	_, err := kernel.MeterOpen(ctx, kernel.TraceID("trace-panic"), "/v1/chat/completions")
	require.NoError(t, err)

	require.NoError(t, k.Shutdown())

	kernel.PanicRegisterBuiltins()
	require.NotPanics(t, func() {
		rec := kernel.PanicFlush("test: after shutdown")
		assert.False(t, rec.Concurrent)
		assert.Equal(t, int64(0), rec.BootID, "a torn-down kernel has no boot identity")
	})
}

// TestFlushWithNoKernelBootedDoesNotPanic is the other torn-down case: nothing was
// ever up, and a flush is still safe to call.
func TestFlushWithNoKernelBootedDoesNotPanic(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)

	kernel.PanicRegisterBuiltins()
	require.NotPanics(t, func() {
		rec := kernel.PanicFlush("test: never booted")
		assert.False(t, rec.Concurrent)
	})
}

// TestIdempotenceProducesOneCauseRecord pins that flushing twice does not corrupt the
// chain or double-count. Two flushes are two facts, so two cause records is correct;
// what must not happen is one flush producing two, or the second failing.
func TestIdempotenceProducesOneCauseRecord(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	kernel.PanicRegisterBuiltins()
	before := len(kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPanic}))

	first := kernel.PanicFlush("test: once")
	mid := len(kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPanic}))
	second := kernel.PanicFlush("test: twice")
	after := len(kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPanic}))

	assert.False(t, first.Concurrent)
	assert.False(t, second.Concurrent, "a completed flush releases the guard")
	assert.Equal(t, 2, mid-before, "one flush writes a cause record and an outcome record")
	assert.Equal(t, mid+2, after, "and the second flush writes its own pair")

	// The second flush reports nothing left to save, because the first already closed
	// everything. A flush that re-reported the same requests would double-count the
	// operator's revenue.
	var meter *kernel.PanicOutcome
	for i := range second.Outcomes {
		if second.Outcomes[i].Name == "meter" {
			meter = &second.Outcomes[i]
		}
	}
	require.NotNil(t, meter)
	assert.Zero(t, meter.Saved, "the second flush has nothing left to close")

	entries := kernel.AuditQuery(kernel.AuditFilter{})
	assert.Equal(t, -1, kernel.VerifyChain(entries, kernel.AuditGenesis))
}

// TestPanicLastFlushIsACopy pins that the retained record cannot be mutated through
// the accessor, which is the same discipline every other snapshot in this kernel
// follows.
func TestPanicLastFlushIsACopy(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	require.NoError(t, kernel.PanicRegister("one", func() kernel.PanicOutcome {
		return kernel.PanicOutcome{Completed: true, Saved: 3}
	}, time.Second))
	kernel.PanicFlush("test: last")

	got, ok := kernel.PanicLastFlush()
	require.True(t, ok)
	require.Len(t, got.Outcomes, 1)

	got.Outcomes[0].Saved = 999
	again, ok := kernel.PanicLastFlush()
	require.True(t, ok)
	assert.Equal(t, 3, again.Outcomes[0].Saved, "mutating a returned record must not reach kernel state")
}

// TestResetClearsTheEvidenceButKeepsTheChain pins both halves of resetPanic's
// contract, which are deliberately asymmetric.
//
// The previous boot's crash record must not survive, because PanicLastFlush reporting
// a crash from before the restart would make a fresh deployment look like one that had
// already failed. The notifier chain must survive, because Boot resets before it
// applies configuration, so clearing the chain there would mean a host that registered
// its notifiers before booting - the natural place - silently had no flush chain at
// all. Silent loss of the crash dump is the failure this subsystem exists to prevent.
func TestResetClearsTheEvidenceButKeepsTheChain(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)

	k := panicBoot(t)
	kernel.PanicRegisterBuiltins()
	chain := kernel.PanicNotifiers()
	require.NotEmpty(t, chain)

	kernel.PanicFlush("test: before restart")
	_, ok := kernel.PanicLastFlush()
	require.True(t, ok, "the flush left a record behind")

	require.NoError(t, k.Shutdown())

	_, ok = kernel.PanicLastFlush()
	assert.False(t, ok, "the previous boot's crash record does not survive a restart")

	k2 := panicBoot(t)
	_ = k2
	assert.Equal(t, chain, kernel.PanicNotifiers(),
		"the notifier chain survives, so a host that registered before booting is not silently unarmed")

	// And the guard was released: a flush interrupted by an exit must not leave the
	// next boot unable to flush at all.
	rec := kernel.PanicFlush("test: after restart")
	assert.False(t, rec.Concurrent, "the flush guard did not survive the restart")
	assert.Len(t, rec.Outcomes, len(chain))
}

// TestTheGuardReleasesAfterAFlush pins the re-entrancy guard's other half. A guard
// that never released would make every flush after the first a no-op, and the failure
// would look like "nothing to save" rather than "the guard is stuck".
func TestTheGuardReleasesAfterAFlush(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	kernel.PanicRegisterBuiltins()
	for i := range 3 {
		rec := kernel.PanicFlush("test: guard " + harness.Itoa(i))
		assert.False(t, rec.Concurrent, "flush %d ran for real", i)
		assert.NotEmpty(t, rec.Outcomes)
	}
}

// ---------------------------------------------------------------------------
// The top-level paths, in a subprocess. These cannot be tested in-process: a panic
// that reaches the top of a goroutine, or an os.Exit, ends the test binary.

// TestSubprocessRecoverFlushesOnTheWayOut proves the integration pattern the file
// documents actually works: a recover at the top level, a flush, a report, an exit.
// It runs the test binary as a child with an environment variable set, which is the
// standard way to observe a process ending without ending the suite.
func TestSubprocessRecoverFlushesOnTheWayOut(t *testing.T) {
	if os.Getenv("MEOWAPI_PANIC_SUBPROCESS") == "1" {
		panicSubprocessMain()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSubprocessRecoverFlushesOnTheWayOut")
	cmd.Env = append(os.Environ(), "MEOWAPI_PANIC_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()

	// The child exits non-zero on purpose: a process that caught a fatal panic is not
	// a process that succeeded.
	require.Error(t, err, "the subprocess must exit non-zero after a caught panic")
	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr))
	assert.NotZero(t, exitErr.ExitCode())

	text := string(out)
	assert.Contains(t, text, "kernel flush: reason=", "the crash report was printed")
	assert.Contains(t, text, "panic: subprocess exploded")
	assert.Contains(t, text, "meter", "the built-in notifiers ran")
	assert.Contains(t, text, "audit-sink")
}

// panicSubprocessMain is the child's whole program: boot, open a meter request,
// register the builtins, panic, recover, flush, report, exit non-zero.
func panicSubprocessMain() {
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-subprocess"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "boot failed:", err)
		os.Exit(2)
	}
	kernel.PanicRegisterBuiltins()

	defer func() {
		if r := recover(); r != nil {
			rec := kernel.PanicFlush(fmt.Sprintf("panic: %v", r))
			fmt.Fprint(os.Stderr, kernel.CrashReport(rec))
			_ = k.Shutdown()
			os.Exit(1)
		}
	}()

	panic("subprocess exploded")
}

// TestSubprocessExitSkipsDeferredWork documents the fact the integration notes turn
// on: os.Exit runs no deferred function, so a defer-based flush does not fire on the
// most common non-panic exit. Asserting it here keeps the note honest rather than
// merely plausible.
func TestSubprocessExitSkipsDeferredWork(t *testing.T) {
	if os.Getenv("MEOWAPI_EXIT_SUBPROCESS") == "1" {
		defer func() {
			fmt.Fprintln(os.Stderr, "DEFERRED RAN")
		}()
		fmt.Fprintln(os.Stderr, "EXITING")
		os.Exit(0)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSubprocessExitSkipsDeferredWork")
	cmd.Env = append(os.Environ(), "MEOWAPI_EXIT_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "the child exits zero: %s", out)

	text := string(out)
	assert.Contains(t, text, "EXITING")
	assert.NotContains(t, text, "DEFERRED RAN",
		"os.Exit skips deferred functions, which is why a flush must be called explicitly")
}

// ---------------------------------------------------------------------------
// Concurrency.

// TestConcurrentFlushesAndReadsUnderRace exercises the guard and the accessors from
// many goroutines at once. What is asserted is that exactly one flush does the work
// and that nothing races; the others report Concurrent.
func TestConcurrentFlushesAndReadsUnderRace(t *testing.T) {
	harness.QuietConsole(t)
	panicResetChain(t)
	panicBoot(t)

	require.NoError(t, kernel.PanicRegister("counted", func() kernel.PanicOutcome {
		return kernel.PanicOutcome{Completed: true, Saved: 1}
	}, time.Second))

	const goroutines = 24
	results := make(chan kernel.CrashRecord, goroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- kernel.PanicFlush("test: concurrent")
		}()
	}
	// Readers running alongside, because a flush and a snapshot are what a host does
	// at the same time in practice.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 20 {
				_ = kernel.PanicNotifiers()
				_, _ = kernel.PanicLastFlush()
			}
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	worked, refused := 0, 0
	for rec := range results {
		if rec.Concurrent {
			refused++
			assert.Empty(t, rec.Outcomes)
			continue
		}
		worked++
		assert.Len(t, rec.Outcomes, 1)
	}
	assert.Positive(t, worked, "at least one flush did the work")
	assert.Equal(t, goroutines, worked+refused, "every call returned exactly one record")
}
