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

package evidence

import (
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestClockIsMonotonic is the property every timeout, sliding window and token
// bucket in the kernel depends on. If Mono() can go backwards, a rate limiter can
// be made to grant forever and a deadline can be made never to arrive.
func TestClockIsMonotonic(t *testing.T) {
	var prev int64
	for i := range 20000 {
		_ = i
		now := kernel.KernelClock().Mono()
		assert.GreaterOrEqual(t, now, prev, "the monotonic clock must never go backwards")
		prev = now
	}
}

// TestClockConcurrentMonotonicity runs the same assertion under contention, which
// is where a clamp implemented without a lock would fail.
func TestClockConcurrentMonotonicity(t *testing.T) {
	results := make([][]int64, 8)
	done := make(chan int, 8)
	for g := range 8 {
		go func(g int) {
			s := make([]int64, 2000)
			for i := range s {
				s[i] = kernel.KernelClock().Mono()
			}
			results[g] = s
			done <- g
		}(g)
	}
	for range 8 {
		<-done
	}
	for g, s := range results {
		for i := 1; i < len(s); i++ {
			assert.GreaterOrEqual(t, s[i], s[i-1], "goroutine %d observed time going backwards", g)
		}
	}
}

// TestClockElapsedAndDeadline covers the helpers subsystems use, so a rate limiter
// or a watchdog written against them cannot get the sign backwards.
func TestClockElapsedAndDeadline(t *testing.T) {
	c := kernel.KernelClock()

	start := c.Mono()
	time.Sleep(2 * time.Millisecond)
	assert.Positive(t, c.Since(start), "elapsed time must be positive")
	assert.Positive(t, c.Elapsed(start))

	d := c.Deadline(1 * time.Nanosecond)
	time.Sleep(time.Millisecond)
	assert.True(t, c.Expired(d), "a deadline in the past must report expired")

	future := c.Deadline(time.Hour)
	assert.False(t, c.Expired(future))
}

// TestClockWallIsNotTheAuthority asserts the split between the two clocks. Wall
// time exists for records a human reads; Mono exists for decisions. A module gets
// both from SyscallNow and must not use Wall to measure.
func TestClockWallIsNotTheAuthority(t *testing.T) {
	w := kernel.KernelClock().Now()
	assert.WithinDuration(t, time.Now().UTC(), w, 2*time.Second)
	assert.Equal(t, time.UTC, w.Location(), "wall clock is normalized to UTC for records")
}

// TestModuleReadsKernelTime drives the syscall path, which is what a module
// actually uses.
func TestModuleReadsKernelTime(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	var got kernel.KernelTime
	harness.RegisterProbe(t, "clockreader", &harness.Probe{Load: func(ctx kernel.SContext) error {
		got = ctx.SyscallNow()
		return nil
	}})

	pid, err := k.Load(kernel.Manifest{
		Name: "clockreader", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	assert.Positive(t, got.Mono, "a module must get a usable monotonic reading")
	assert.False(t, got.Wall.IsZero())
	assert.WithinDuration(t, time.Now().UTC(), got.Wall, 5*time.Second)
}

// TestAuditChainVerifies is the tamper-evidence property. A chain that verifies
// proves nothing was edited between the first entry and the last.
func TestAuditChainVerifies(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	entries := kernel.AuditQuery(kernel.AuditFilter{})
	require.NotEmpty(t, entries, "loading a module must produce audit entries")

	assert.Equal(t, -1, kernel.VerifyChain(entries, kernel.AuditGenesis),
		"a freshly built chain must verify from genesis")

	// Every entry's own hash must recompute, which is what lets an external
	// auditor check a chain read from the sink without trusting the kernel.
	for _, e := range entries {
		assert.True(t, kernel.VerifyEntry(e), "seq %d hash must recompute", e.Seq)
	}

	_ = buf
}

// TestAuditChainDetectsTampering proves the chain is evidence rather than a log.
// Each mutation is the kind of thing an attacker with write access to the audit
// file would attempt, and each must be detected.
func TestAuditChainDetectsTampering(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	entries := kernel.AuditQuery(kernel.AuditFilter{})
	require.GreaterOrEqual(t, len(entries), 3, "need several entries to test splice detection")

	cases := []struct {
		name   string
		mutate func(e []kernel.AuditEntry) []kernel.AuditEntry
	}{
		{
			"rewrite a message",
			func(e []kernel.AuditEntry) []kernel.AuditEntry {
				out := append([]kernel.AuditEntry(nil), e...)
				out[1].Msg = "module loaded cleanly"
				return out
			},
		},
		{
			"change a pid",
			func(e []kernel.AuditEntry) []kernel.AuditEntry {
				out := append([]kernel.AuditEntry(nil), e...)
				out[1].PID = 999
				return out
			},
		},
		{
			"change the domain",
			func(e []kernel.AuditEntry) []kernel.AuditEntry {
				out := append([]kernel.AuditEntry(nil), e...)
				out[1].Domain = kernel.DomainKernel
				return out
			},
		},
		{
			"backdate the timestamp",
			func(e []kernel.AuditEntry) []kernel.AuditEntry {
				out := append([]kernel.AuditEntry(nil), e...)
				out[1].Time = 0
				return out
			},
		},
		{
			"change the kind",
			func(e []kernel.AuditEntry) []kernel.AuditEntry {
				out := append([]kernel.AuditEntry(nil), e...)
				out[1].Kind = kernel.AuditPolicy
				return out
			},
		},
		{
			"drop an entry",
			func(e []kernel.AuditEntry) []kernel.AuditEntry {
				out := append([]kernel.AuditEntry(nil), e...)
				return append(out[:1], out[2:]...)
			},
		},
		{
			"append an entry with no valid link",
			func(e []kernel.AuditEntry) []kernel.AuditEntry {
				out := append([]kernel.AuditEntry(nil), e...)
				return append(out, kernel.AuditEntry{
					Seq: int64(len(out)), Kind: kernel.AuditLoad, Msg: "forged",
					Prev: "0", Hash: "deadbeef",
				})
			},
		},
		{
			"swap two entries",
			func(e []kernel.AuditEntry) []kernel.AuditEntry {
				out := append([]kernel.AuditEntry(nil), e...)
				out[1], out[2] = out[2], out[1]
				return out
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tampered := c.mutate(entries)
			idx := kernel.VerifyChain(tampered, kernel.AuditGenesis)
			assert.NotEqual(t, -1, idx, "%s must be detected by chain verification", c.name)
		})
	}
}

// TestAuditChainLinksSequenceNumbers asserts the chain is contiguous, so a
// deleted entry is detectable even if an attacker recomputed every hash after it.
func TestAuditChainLinksSequenceNumbers(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	defer func() { _ = k.Shutdown() }()
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	entries := kernel.AuditQuery(kernel.AuditFilter{})
	require.NotEmpty(t, entries)
	assert.Equal(t, int64(0), entries[0].Seq, "the chain starts at sequence zero")
	for i := 1; i < len(entries); i++ {
		assert.Equal(t, entries[i-1].Seq+1, entries[i].Seq, "sequence numbers must be contiguous")
		assert.Equal(t, entries[i-1].Hash, entries[i].Prev, "each entry must link to its predecessor")
	}
}

// TestAuditQueryFilters asserts the filter fields work, since an investigation
// that cannot select by trace or pid is not usable.
func TestAuditQueryFilters(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	byPid := kernel.AuditQuery(kernel.AuditFilter{PID: pid})
	require.NotEmpty(t, byPid)
	for _, e := range byPid {
		assert.Equal(t, pid, e.PID)
	}

	byKind := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditLoad})
	require.NotEmpty(t, byKind, "a load must be audited")
	for _, e := range byKind {
		assert.Equal(t, kernel.AuditLoad, e.Kind)
	}

	limited := kernel.AuditQuery(kernel.AuditFilter{Limit: 2})
	assert.Len(t, limited, 2)

	future := kernel.AuditQuery(kernel.AuditFilter{Since: 1 << 40})
	assert.Empty(t, future)

	// The result is a copy, so mutating it cannot corrupt the chain.
	all := kernel.AuditQuery(kernel.AuditFilter{})
	require.NotEmpty(t, all)
	all[0].Msg = "tampered"
	all[0].Hash = "tampered"
	fresh := kernel.AuditQuery(kernel.AuditFilter{})
	assert.NotEqual(t, "tampered", fresh[0].Msg)
	assert.True(t, kernel.VerifyEntry(fresh[0]))
}

// TestAuditRecordsLifecycleAndDenials asserts the specific events an investigation
// needs are actually recorded: what loaded, what was refused, what escalated.
func TestAuditRecordsLifecycleAndDenials(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	// A successful load.
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	// diag deliberately trips metadata:write, which must appear as both a
	// denial and an escalation-class event.
	denials := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial})
	require.NotEmpty(t, denials, "every policy denial must reach the audit chain")
	for _, e := range denials {
		assert.NotEmpty(t, e.Hash)
		assert.True(t, kernel.VerifyEntry(e))
	}

	spawns := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditSpawn})
	require.NotEmpty(t, spawns, "context creation must be audited")

	loads := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditLoad})
	require.Len(t, loads, 1)
	assert.Equal(t, "diag", loads[0].Fields["module"])
	assert.Len(t, loads[0].Fields["digest"], 64, "the load record must carry the manifest digest")

	// A denied domain transition must be recorded as an escalation.
	_, err = k.InitContext().SyscallSpawn(kernel.DomainKernel, "escalate")
	require.Error(t, err)
	esc := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation})
	require.NotEmpty(t, esc, "a denied escalation attempt must be audited")

	// A rejected manifest must be recorded with the reason.
	_, err = k.Load(kernel.Manifest{
		Name: "bogus", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpMetadataWrite},
	})
	require.Error(t, err)
	rejects := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditReject})
	require.Len(t, rejects, 1)
	assert.Equal(t, "bogus", rejects[0].Fields["module"])
	assert.Contains(t, rejects[0].Fields["reason"], "not grantable")

	require.NoError(t, k.Unload(pid))
	unloads := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditUnload})
	require.Len(t, unloads, 1)
}

// TestAuditSinkReceivesEveryEntry proves an external auditor can reconstruct the
// chain from the sink alone, without access to kernel memory. This is what makes
// the chain usable after a crash.
func TestAuditSinkReceivesEveryEntry(t *testing.T) {
	var collected []kernel.AuditEntry
	sink := kernel.AuditSinkFunc(func(e kernel.AuditEntry) error {
		collected = append(collected, e)
		return nil
	})

	k, err := kernel.Boot(kernel.BootConfig{AuditSink: sink})
	require.NoError(t, err)

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid))

	headBeforeShutdown := kernel.AuditHead()
	require.NoError(t, k.Shutdown())

	require.NotEmpty(t, collected, "the sink must receive the chain")
	assert.Equal(t, -1, kernel.VerifyChain(collected, kernel.AuditGenesis),
		"the sink's copy must be a valid chain, from genesis, without kernel memory")

	// Shutdown writes the shutdown record and then flushes, so the chain continues
	// past shutdown with the flush's own records. That is a stronger proof of sink
	// liveness than the shutdown record being last would have been: entries were sunk
	// after the kernel had already said it was stopping, so the sink cannot have been
	// detached early.
	shutdownAt := -1
	for i, e := range collected {
		if e.Kind == kernel.AuditShutdown {
			shutdownAt = i
			break
		}
	}
	require.NotEqual(t, -1, shutdownAt, "the shutdown record reached the sink")
	require.GreaterOrEqual(t, shutdownAt, 1)
	assert.Equal(t, headBeforeShutdown, collected[shutdownAt-1].Hash,
		"the entry before shutdown must be the head the kernel reported")

	assert.Greater(t, len(collected), shutdownAt+1,
		"the flush that follows shutdown also reached the sink")
	for _, e := range collected[shutdownAt+1:] {
		assert.Equal(t, kernel.AuditPanic, e.Kind,
			"only the shutdown flush writes after the shutdown record")
	}
}

// TestAuditSinkFailureIsNotFatal asserts a broken sink degrades to a fault rather
// than taking the kernel down. Losing audit delivery is serious, but a kernel that
// dies because its log target is unwritable is worse, and the fault line plus the
// resulting gap in sequence numbers makes the loss detectable.
func TestAuditSinkFailureIsNotFatal(t *testing.T) {
	buf := harness.QuietConsole(t)
	calls := 0
	sink := kernel.AuditSinkFunc(func(kernel.AuditEntry) error {
		calls++
		return assert.AnError
	})

	k, err := kernel.Boot(kernel.BootConfig{AuditSink: sink})
	require.NoError(t, err, "a failing sink must not prevent boot")
	defer func() { _ = k.Shutdown() }()

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err, "a failing sink must not prevent loading")
	defer func() { _ = k.Unload(pid) }()

	assert.Positive(t, calls)
	assert.NotEmpty(t, harness.Faults(buf), "each sink failure must be recorded as a fault")

	// The in-memory chain is intact regardless of the sink.
	assert.Equal(t, -1, kernel.VerifyChain(kernel.AuditQuery(kernel.AuditFilter{}), kernel.AuditGenesis))
}

// TestAuditHeadAdvances asserts the head is a usable checkpoint anchor. It is not
// genesis after Boot, because booting is itself audited: the chain starts with the
// boot record and the spawn of init.
func TestAuditHeadAdvances(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	head0 := kernel.AuditHead()
	assert.NotEqual(t, kernel.AuditGenesis, head0,
		"booting writes audit entries, so a live chain does not head at genesis")
	assert.Len(t, head0, 64)

	entries := kernel.AuditQuery(kernel.AuditFilter{})
	require.NotEmpty(t, entries)
	assert.Equal(t, head0, entries[len(entries)-1].Hash,
		"the head must be the hash of the newest entry")
	assert.Equal(t, kernel.AuditBoot, entries[0].Kind, "the chain opens with the boot record")

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	head1 := kernel.AuditHead()
	assert.NotEqual(t, head0, head1, "the head must advance when entries are appended")
	assert.Len(t, head1, 64)

	retained, evicted := kernel.AuditLen()
	assert.Positive(t, retained)
	assert.Zero(t, evicted, "a short boot must not evict")
}

// TestAuditWindowIsConfigurableAndFloored covers the operator knob. The floor is
// the important half: a window of zero would discard every entry before anything
// could read it, which is not a smaller buffer but no audit trail.
func TestAuditWindowIsConfigurableAndFloored(t *testing.T) {
	harness.QuietConsole(t)

	k, err := kernel.Boot(kernel.BootConfig{AuditWindow: 24})
	require.NoError(t, err)
	assert.Equal(t, 24, kernel.AuditWindow())

	for range 200 {
		k.Publish("k", "v")
	}
	retained, evicted := kernel.AuditLen()
	assert.LessOrEqual(t, retained, 24, "the window must cap retained entries")
	assert.Positive(t, evicted, "eviction must be counted, not silent")
	assert.Equal(t, -1, kernel.VerifyChain(kernel.AuditQuery(kernel.AuditFilter{}),
		entries0Prev(t)), "the retained window must still be a valid chain")
	require.NoError(t, k.Shutdown())

	// A nonsense window is raised to the floor rather than honored.
	k2, err := kernel.Boot(kernel.BootConfig{AuditWindow: 0})
	require.NoError(t, err)
	assert.Equal(t, kernel.DefaultAuditWindow(), kernel.AuditWindow(),
		"zero means keep the default")
	require.NoError(t, k2.Shutdown())

	k3, err := kernel.Boot(kernel.BootConfig{AuditWindow: 1})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, kernel.AuditWindow(), kernel.MinAuditWindow(),
		"a window below the floor is raised to it")
	require.NoError(t, k3.Shutdown())
}

// entries0Prev returns the Prev of the oldest retained entry, which is the anchor
// a verifier splices a window onto.
func entries0Prev(t *testing.T) string {
	t.Helper()
	e := kernel.AuditQuery(kernel.AuditFilter{Limit: 1})
	require.NotEmpty(t, e)
	return e[0].Prev
}
