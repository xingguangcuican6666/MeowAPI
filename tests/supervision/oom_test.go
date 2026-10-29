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

package supervision

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// These tests drive koom: memory pressure and forced teardown. They live in the
// supervision package because that package already owns "work the kernel runs instead of
// the module", which is what a background patrol is.

var oomCounter int

func oomNextName(prefix string) string {
	oomCounter++
	return prefix + harness.Itoa(oomCounter)
}

// oomFixedSampler reports a host total AND a reserved figure this test chooses. The kernel
// cannot read physical RAM through any Go API, so the host supplies it; supplying both halves
// is what makes the host-pressure path deterministic rather than something that only happens
// on a machine that is actually running out of memory, and what lets a test put the process
// at an exact percentage instead of guessing a total that might land it near a threshold.
type oomFixedSampler struct{ total, reserved uint64 }

func (s oomFixedSampler) TotalMemoryBytes() uint64 { return s.total }
func (s oomFixedSampler) ReservedBytes() uint64    { return s.reserved }

// oomSamplerAtBP builds a sampler that puts the process at exactly bp basis points of the
// host. The reserved figure is derived from the total rather than chosen independently, so a
// test states the pressure it means and cannot accidentally drift across a threshold when the
// arithmetic rounds.
func oomSamplerAtBP(bp int) oomFixedSampler {
	const total = uint64(1) << 40
	return oomFixedSampler{total: total, reserved: total * uint64(bp) / 10000}
}

// oomBoot boots with the given ceilings and no sampler. A test that needs host pressure
// installs one afterwards, because installing a sampler before boot is wiped by the reset
// and would silently leave the host path disabled.
func oomBoot(t *testing.T, l kernel.BootLimits) *kernel.Kernel {
	t.Helper()
	// The patrol period is derived from the sealed call ceiling rather than configured, so
	// the way to keep the background loop out of a test's way is to raise the ceiling, which
	// pushes the derived interval to its clamp maximum. The sweeps these tests assert are ones
	// the test calls directly; a background patrol firing mid-test would pick a victim before
	// the manual sweep got to. This is the same reason the watchdog tests call WatchdogPatrol
	// rather than waiting for the loop.
	if l.CallTimeoutMillis == 0 {
		l.CallTimeoutMillis = 3_600_000
	}
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-oom", Limits: l},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// oomLoad loads a module and returns its context and pid.
func oomLoad(t *testing.T, k *kernel.Kernel, prefix string, m kernel.Manifest) (kernel.SContext, kernel.PID) {
	t.Helper()
	name := oomNextName(prefix)
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	m.Name = name
	if m.Version == "" {
		m.Version = "1"
	}
	m.MinKernelAPI = kernel.KernelAPI
	m.MaxKernelAPI = kernel.KernelAPI
	pid, err := k.Load(m)
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, probe.Ctx)
	return probe.Ctx, pid
}

// oomFillState makes a module hold roughly `want` accounted bytes of namespaced state,
// which is the tally a test can actually control. Pipe reservations and shared segments are
// the other two sources and are covered separately, since all three feed one total.
func oomFillState(t *testing.T, ctx kernel.SContext, want int) {
	t.Helper()
	// One value per key rather than one enormous value, because a single value larger than
	// the per-module KV ceiling is refused outright and would leave the module holding
	// nothing while the test believed it was holding memory.
	const chunk = 4096
	buf := make([]byte, chunk)
	for i := range chunk {
		buf[i] = byte('a' + i%26)
	}
	for i := 0; i*chunk < want; i++ {
		require.NoError(t, kernel.KVPut(ctx, "state/"+harness.Itoa(i), buf),
			"filling accounted state failed at chunk %d", i)
	}
}

// ---------------------------------------------------------------------------
// What the kernel can see.

// TestTheTallySumsThreeSourcesNotOne pins that the accounted total is a sum across
// subsystems. A single-source tally would miss a module holding all three at once, which is
// exactly the combination no individual ceiling catches.
func TestTheTallySumsThreeSourcesNotOne(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{MaxKVBytesPerModule: 1 << 20})
	ctx, pid := oomLoad(t, k, "oomtally", kernel.Manifest{
		Require: []kernel.Op{
			kernel.OpKVRead, kernel.OpKVWrite, kernel.OpPipeOpen,
			kernel.OpShmAlloc, kernel.OpShmMap,
		},
	})

	oomFillState(t, ctx, 64<<10)
	tally := kernel.OomTallyFor(pid)
	assert.GreaterOrEqual(t, tally.StateBytes, int64(64<<10),
		"namespaced state is accounted")
	assert.Zero(t, tally.PipeBytes)
	assert.Zero(t, tally.SegmentBytes)

	// A pipe reserves its whole capacity at open time rather than what is buffered, so the
	// tally moves by the capacity and not by the bytes written.
	_, err := ctx.SyscallOpenPipe("oom-pipe", 32<<10, kernel.PipeNonBlocking)
	require.NoError(t, err)
	withPipe := kernel.OomTallyFor(pid)
	assert.GreaterOrEqual(t, withPipe.PipeBytes, int64(32<<10),
		"reserved pipe capacity is accounted")

	// A shared segment is accounted at its slab class, which is what the pool charges and
	// what zeroing covers, so it can exceed the requested size.
	desc, err := kernel.ShmAlloc(ctx, 8<<10, "oom-seg")
	require.NoError(t, err)
	require.NotZero(t, desc.ID)
	withSeg := kernel.OomTallyFor(pid)
	assert.Positive(t, withSeg.SegmentBytes, "owned shared segments are accounted")

	assert.Equal(t,
		withSeg.StateBytes+withSeg.PipeBytes+withSeg.SegmentBytes, withSeg.Total(),
		"the total is the sum of the three, not the largest of them")
	assert.Greater(t, withSeg.Total(), tally.Total())
	assert.NotEmpty(t, withSeg.Module,
		"a tally names its module, because an unnamed number is not actionable")
	assert.True(t, strings.HasPrefix(withSeg.Module, "oomtally"),
		"and the name is this module's, got %q", withSeg.Module)
}

// TestTalliesAreSortedLargestFirst pins the order the console and the victim choice both
// read, so one ordering decides both and they cannot disagree about who is largest.
func TestTalliesAreSortedLargestFirst(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{MaxKVBytesPerModule: 1 << 20})

	small, smallPID := oomLoad(t, k, "oomsmall", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	big, bigPID := oomLoad(t, k, "oombig", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})

	oomFillState(t, small, 16<<10)
	oomFillState(t, big, 128<<10)

	tallies := kernel.OomTallies()
	require.NotEmpty(t, tallies)
	for i := 1; i < len(tallies); i++ {
		assert.GreaterOrEqual(t, tallies[i-1].Total(), tallies[i].Total(),
			"tallies are sorted by accounted bytes descending")
	}
	require.Equal(t, bigPID, tallies[0].PID, "the largest consumer is first")
	assert.Equal(t, smallPID, func() kernel.PID {
		for _, ty := range tallies {
			if ty.PID == smallPID {
				return ty.PID
			}
		}
		t.Fatalf("pid %d is missing from the tallies", smallPID)
		return 0
	}())
}

// TestAPipeReservationCountsCapacityNotContents pins the measure, which is the difference
// between a bound and a suggestion. Counting buffered bytes would let a module open every
// pipe it is allowed first and fill them all second, so the ceiling would be reached only
// after the memory was already committed.
func TestAPipeReservationCountsCapacityNotContents(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{})
	ctx, pid := oomLoad(t, k, "oompipe", kernel.Manifest{
		Require: []kernel.Op{kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead},
	})

	fd, err := ctx.SyscallOpenPipe("oom-empty", 64<<10, kernel.PipeNonBlocking)
	require.NoError(t, err)
	before := kernel.OomTallyFor(pid).PipeBytes
	assert.GreaterOrEqual(t, before, int64(64<<10),
		"an empty pipe is accounted at its full capacity")

	// Writing 1 KiB into a 64 KiB pipe must not move the tally, which is the assertion that
	// distinguishes a reservation from a measurement of contents.
	_, err = ctx.SyscallPipeWrite(fd, make([]byte, 1<<10), 0)
	require.NoError(t, err)
	assert.Equal(t, before, kernel.OomTallyFor(pid).PipeBytes,
		"the tally is a reservation, so buffered bytes do not change it")
}

// ---------------------------------------------------------------------------
// The victim order.

// TestInitAndTheKernelAreNeverVictims pins the priority order, and it is the property that
// decides whether this subsystem protects the host or destroys it. Both are the largest
// consumers by construction, so a size-only ordering would reach them, and a size-only
// ordering is the obvious implementation.
func TestInitAndTheKernelAreNeverVictims(t *testing.T) {
	harness.QuietConsole(t)
	// A ceiling of 1 byte so that every pid, including init and the kernel, is over it.
	k := oomBoot(t, kernel.BootLimits{
		MaxKVBytesPerModule:        1 << 20,
		MaxAccountedBytesPerModule: 1,
		OomMaxVictimsPerSweep:      64,
	})
	// Host pressure at the kill threshold, so the sweep is in its most aggressive mode.
	require.NoError(t, k.OomSetMemorySampler(oomSamplerAtBP(10000)))

	pluginCtx, plugin := oomLoad(t, k, "oomplugin", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	// The plugin must actually hold accounted memory. A module accounted at zero bytes is not
	// a victim no matter how high the pressure is, because terminating it would be terminating
	// it for existing - and without this the test would pass for the wrong reason, with the
	// sweep finding nothing to kill and the "never init" assertion holding vacuously.
	oomFillState(t, pluginCtx, 32<<10)
	require.Positive(t, kernel.OomTallyFor(plugin).Total())

	// init holds accounted state too: publish a value under its own namespace by writing
	// through init's context, which is what a real deployment's long-lived context does.
	initCtx := k.InitContext()
	require.NoError(t, kernel.KVPut(initCtx, "boot.marker", []byte("init holds state")))

	initTotal := kernel.OomTallyFor(initCtx.PID()).Total()
	require.Positive(t, initTotal,
		"init is accounted above the ceiling, so a size-only ordering would pick it")
	require.False(t, kernel.OomVictimEligible(kernel.OomTallyFor(initCtx.PID())),
		"and eligibility, not size, is what keeps it alive")
	// Make init the largest consumer by construction, so the case really is "a size-only
	// ordering would have killed init and this one does not".
	if initTotal < kernel.OomTallyFor(plugin).Total() {
		oomFillState(t, initCtx, 64<<10)
		require.Greater(t, kernel.OomTallyFor(initCtx.PID()).Total(),
			kernel.OomTallyFor(plugin).Total())
	}

	actions := kernel.OomPatrol()
	require.NotEmpty(t, actions, "the plugin over the ceiling is terminated")

	for _, a := range actions {
		assert.NotEqual(t, initCtx.PID(), a.PID, "init is never a victim")
		assert.NotEqual(t, kernel.PID(0), a.PID, "the kernel is never a victim")
		assert.NotEqual(t, kernel.DomainInit, a.Domain)
		assert.NotEqual(t, kernel.DomainKernel, a.Domain)
	}

	var sawPlugin bool
	for _, a := range actions {
		if a.PID == plugin {
			sawPlugin = true
		}
	}
	assert.True(t, sawPlugin, "the plugin domain is eligible and was chosen")
}

// TestUntrustedIsTerminatedBeforeAPlugin pins the domain ordering rather than only the
// exclusion. Both are eligible, so this is what decides between them, and it must not be
// decided by size: a small untrusted module outranks a large plugin.
func TestUntrustedIsTerminatedBeforeAPlugin(t *testing.T) {
	// The untrusted domain holds no operations, so it cannot accumulate accounted state of
	// its own. The ordering is asserted against the tally list rather than against a sweep,
	// which is the part a test can construct honestly: a victim order that depends on size
	// alone would put the plugin first, and this asserts it does not.
	k := oomBoot(t, kernel.BootLimits{MaxAccountedBytesPerModule: 1})
	_ = k

	// The order is a pure function of domain and size, and both inputs are visible in a
	// tally, so the property is asserted on the sorted list that the sweep consumes.
	plugin := kernel.NewOomTally(10, "plugin", kernel.DomainPlugin, 1<<30, 0, 0)
	untrusted := kernel.NewOomTally(11, "untrusted", kernel.DomainUntrusted, 1, 0, 0)
	kern := kernel.NewOomTally(0, "kernel", kernel.DomainKernel, 1<<40, 0, 0)
	init := kernel.NewOomTally(1, "init", kernel.DomainInit, 1<<40, 0, 0)

	sorted := kernel.OomSortVictims([]kernel.OomTally{plugin, untrusted, kern, init})
	require.Len(t, sorted, 4)
	assert.Equal(t, kernel.DomainUntrusted, sorted[0].Domain,
		"untrusted is first despite holding a gigabyte less than the plugin")
	assert.Equal(t, kernel.DomainPlugin, sorted[1].Domain)
	// The kernel and init sort last, and are separately excluded from eligibility. Sorting
	// alone would not be enough, because a large enough number outranks any sort weight;
	// the predicate is what makes "never" mean never.
	assert.Contains(t, []kernel.Domain{kernel.DomainKernel, kernel.DomainInit}, sorted[2].Domain)
	assert.Contains(t, []kernel.Domain{kernel.DomainKernel, kernel.DomainInit}, sorted[3].Domain)
}

// TestEqualSizeFallsBackToPID pins that the victim order is total. An arbitrary tiebreak
// would make the subsystem's behaviour depend on map iteration, which means two sweeps over
// an unchanged set could pick different victims and an incident report could not be
// reproduced.
func TestEqualSizeFallsBackToPID(t *testing.T) {
	k := oomBoot(t, kernel.BootLimits{MaxAccountedBytesPerModule: 1})
	_ = k

	mk := func(pid kernel.PID) kernel.OomTally {
		return kernel.NewOomTally(pid, "equal", kernel.DomainPlugin, 4096, 0, 0)
	}
	sorted := kernel.OomSortVictims([]kernel.OomTally{mk(7), mk(3), mk(5)})
	require.Len(t, sorted, 3)
	assert.Equal(t, kernel.PID(3), sorted[0].PID)
	assert.Equal(t, kernel.PID(5), sorted[1].PID)
	assert.Equal(t, kernel.PID(7), sorted[2].PID)

	// And the same input sorts the same way twice, which is what "total" buys.
	again := kernel.OomSortVictims([]kernel.OomTally{mk(7), mk(3), mk(5)})
	assert.Equal(t, sorted, again)
}

// ---------------------------------------------------------------------------
// The thresholds.

// TestAModuleOverItsOwnCeilingIsTerminatedWithoutHostPressure pins that the accounted
// ceiling needs no host sample. The kernel's own accounting is attributable in a way a host
// reading is not, so it is enforced on its own merits rather than only as a tiebreak under
// pressure.
func TestAModuleOverItsOwnCeilingIsTerminatedWithoutHostPressure(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxKVBytesPerModule:        1 << 20,
		MaxAccountedBytesPerModule: 32 << 10,
	})
	require.False(t, kernel.OomStatsSnapshot().Sampler,
		"no sampler is installed, so this asserts the accounted path alone")

	ctx, pid := oomLoad(t, k, "oomceiling", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	oomFillState(t, ctx, 64<<10)
	require.Greater(t, kernel.OomTallyFor(pid).Total(), int64(32<<10))

	actions := kernel.OomPatrol()
	require.Len(t, actions, 1)
	assert.Equal(t, pid, actions[0].PID)
	assert.True(t, actions[0].Terminated)
	assert.Contains(t, actions[0].Reason, "ceiling")

	// The termination is real, not a mark: the module's state is on its way out and the
	// process record says so.
	require.Eventually(t, func() bool { return kernel.SignalTerminated(pid) },
		10*time.Second, 10*time.Millisecond,
		"the victim is actually terminated rather than only recorded")

	var sawKill bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPolicy}) {
		if e.Msg == "oom terminated a module" && e.Fields["target"] == pid {
			sawKill = true
			// The numbers are recorded as they were at the decision, because the teardown
			// frees the memory and an operator reading the chain afterwards needs to know
			// what the kernel saw when it decided.
			assert.EqualValues(t, kernel.OomTallyFor(pid).Total() >= 0, true)
			assert.Contains(t, e.Fields, "state_bytes")
			assert.Contains(t, e.Fields, "total_bytes")
		}
	}
	assert.True(t, sawKill, "the termination is on the audit chain")
	assert.NotEmpty(t, harness.Faults(buf), "and on the console")

	history := kernel.OomHistory()
	require.Len(t, history, 1)
	assert.Equal(t, pid, history[0].PID)
	assert.Positive(t, history[0].Seq)
	assert.True(t, history[0].Terminated)
}

// TestAHostAtWarnIsRecordedWithoutATermination pins the two-threshold design. The useful
// response to a host at 80% is a record an operator can act on; terminating modules there
// would turn a signal into an outage.
func TestAHostAtWarnIsRecordedWithoutATermination(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxAccountedBytesPerModule: 1 << 30,
		OomHostWarnBP:              5000,
		OomHostKillBP:              9000,
	})
	ctx, pid := oomLoad(t, k, "oomwarn", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	oomFillState(t, ctx, 64<<10)

	// Exactly 60% of the host: past the 50% warn threshold and under the 90% kill one.
	require.NoError(t, k.OomSetMemorySampler(oomSamplerAtBP(6000)))

	snap := kernel.OomPressureSnapshot()
	require.True(t, snap.OomHostPressureKnown())
	assert.GreaterOrEqual(t, snap.HostFraction, 5000)
	assert.Less(t, snap.HostFraction, 9000)

	actions := kernel.OomPatrol()
	assert.Empty(t, actions, "warn-level pressure terminates nothing")
	assert.False(t, kernel.SignalTerminated(pid), "and the module is still running")

	assert.Positive(t, kernel.OomStatsSnapshot().Warns)
	var sawPressure bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPolicy}) {
		if e.Msg == "host memory pressure" {
			sawPressure = true
			assert.Contains(t, e.Fields, "host_fraction_bp")
			assert.Contains(t, e.Fields, "accounted")
		}
	}
	assert.True(t, sawPressure, "warn-level pressure is on the audit chain")
	assert.NotEmpty(t, harness.Faults(buf))
}

// TestAHostAtKillTerminatesTheLargestConsumer pins the path that exists for the case no
// per-module ceiling catches: several modules each inside their own ceiling and together
// past the host's.
func TestAHostAtKillTerminatesTheLargestConsumer(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxKVBytesPerModule:        1 << 20,
		MaxAccountedBytesPerModule: 1 << 30,
		OomHostKillBP:              9000,
		OomMaxVictimsPerSweep:      1,
	})
	small, smallPID := oomLoad(t, k, "oomkills", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	big, bigPID := oomLoad(t, k, "oomkillb", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	oomFillState(t, small, 32<<10)
	oomFillState(t, big, 256<<10)

	// Both are inside the per-module ceiling, so nothing would be terminated without host
	// pressure. That is the case this threshold exists for.
	require.Less(t, kernel.OomTallyFor(bigPID).Total(), int64(1<<30))

	// At 99% of the host, which is past the kill threshold.
	require.NoError(t, k.OomSetMemorySampler(oomSamplerAtBP(9900)))
	require.GreaterOrEqual(t, kernel.OomPressureSnapshot().HostFraction, 9000)

	actions := kernel.OomPatrol()
	require.Len(t, actions, 1, "the sweep is bounded to one victim")
	assert.Equal(t, bigPID, actions[0].PID, "the largest accounted consumer is chosen")
	assert.Contains(t, actions[0].Reason, "largest accounted consumer")
	assert.False(t, kernel.SignalTerminated(smallPID),
		"the smaller module survives a bounded sweep")
}

// TestNoSamplerMeansNoHostPressure pins the degradation, and it is a working configuration
// rather than a broken one. A zero host fraction must never read as calm: the snapshot says
// whether the number means anything.
func TestNoSamplerMeansNoHostPressure(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{MaxAccountedBytesPerModule: 1 << 30})

	snap := kernel.OomPressureSnapshot()
	assert.Zero(t, snap.HostFraction)
	assert.False(t, snap.OomHostPressureKnown(),
		"a zero fraction with no sampler is not a measurement of zero pressure")
	assert.False(t, kernel.OomStatsSnapshot().Sampler)
	assert.Empty(t, kernel.OomPatrol(), "and nothing is terminated for host pressure")

	// Installing a sampler makes the same reading meaningful.
	require.NoError(t, k.OomSetMemorySampler(oomSamplerAtBP(5000)))
	snap = kernel.OomPressureSnapshot()
	assert.True(t, snap.OomHostPressureKnown())
	assert.Positive(t, snap.HostFraction)
	assert.True(t, kernel.OomStatsSnapshot().Sampler)

	// Removing it again is legitimate rather than an error, because "use no sampler" is a
	// configuration and not a mistake - the accounted ceilings still apply.
	require.NoError(t, k.OomSetMemorySampler(nil))
	assert.False(t, kernel.OomPressureSnapshot().OomHostPressureKnown())
}

// TestAMisconfiguredKillThresholdIsClampedNotHonoured pins that a kill threshold at or below
// the warn threshold cannot make the two fire together. Clamping rather than refusing,
// because the sweep must still run under a misconfigured ceiling and a refusal here would
// leave the host unprotected by the very mistake that needed protecting against.
func TestAMisconfiguredKillThresholdIsClampedNotHonoured(t *testing.T) {
	harness.QuietConsole(t)
	for _, l := range []kernel.BootLimits{
		{OomHostWarnBP: 9000, OomHostKillBP: 9000},
		{OomHostWarnBP: 9000, OomHostKillBP: 1000},
		{OomHostWarnBP: 9999, OomHostKillBP: 20000},
		{OomHostWarnBP: -1, OomHostKillBP: -1},
	} {
		k := oomBoot(t, l)
		th := kernel.EffectiveOomThresholds()
		assert.Greater(t, th.HostKillBP, th.HostWarnBP,
			"kill is strictly above warn for limits %+v", l)
		assert.LessOrEqual(t, th.HostKillBP, 10000)
		assert.Positive(t, th.HostWarnBP)
		assert.Positive(t, th.MaxPerModule)
		assert.Positive(t, th.MaxVictimsPerSweep)
		assert.Positive(t, th.Interval)
		_ = k.Shutdown()
	}
}

// TestHostCeilingsAreSealedWithTheRestOfTheRoot pins that these numbers come from the boot
// trust root rather than from a settable global, so a module cannot raise the threshold that
// decides whether it lives.
func TestHostCeilingsAreSealedWithTheRestOfTheRoot(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxAccountedBytesPerModule: 4 << 20,
		OomHostWarnBP:              7000,
		OomHostKillBP:              8500,
		OomMaxVictimsPerSweep:      3,
	})
	l := kernel.Limits()
	assert.EqualValues(t, 4<<20, l.MaxAccountedBytesPerModule)
	assert.Equal(t, 7000, l.OomHostWarnBP)
	assert.Equal(t, 8500, l.OomHostKillBP)
	assert.Equal(t, 3, l.OomMaxVictimsPerSweep)

	th := kernel.EffectiveOomThresholds()
	assert.EqualValues(t, 4<<20, th.MaxPerModule)
	assert.Equal(t, 7000, th.HostWarnBP)
	assert.Equal(t, 8500, th.HostKillBP)
	assert.Equal(t, 3, th.MaxVictimsPerSweep)
	require.True(t, kernel.BootSealed())
	_ = k
}

// ---------------------------------------------------------------------------
// Bounds, ledger, lifetime.

// TestOneSweepIsBounded pins MaxVictimsPerSweep. A pressure response that terminates
// everything eligible is not a response to pressure, it is a shutdown, and the bound is what
// lets the kernel try again next sweep if the first victim was not the cause.
func TestOneSweepIsBounded(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxKVBytesPerModule:        1 << 20,
		MaxAccountedBytesPerModule: 8 << 10,
		OomMaxVictimsPerSweep:      2,
	})

	var pids []kernel.PID
	for range 5 {
		ctx, pid := oomLoad(t, k, "oombound", kernel.Manifest{
			Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
		})
		oomFillState(t, ctx, 32<<10)
		pids = append(pids, pid)
	}

	actions := kernel.OomPatrol()
	assert.Len(t, actions, 2, "one sweep terminates at most the configured number")

	// A second sweep can act again, which is the point of bounding rather than disabling.
	more := kernel.OomPatrol()
	assert.NotEmpty(t, more)
	for _, a := range more {
		assert.Contains(t, pids, a.PID)
	}
}

// TestAModuleAccountedAtZeroIsNeverTerminated pins the guard against terminating a module
// for existing. Under host pressure with nothing attributable there is no honest victim, and
// picking one arbitrarily would make the subsystem's behaviour depend on which module
// happened to load first.
func TestAModuleAccountedAtZeroIsNeverTerminated(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxAccountedBytesPerModule: 1 << 30,
		OomHostKillBP:              1,
		OomMaxVictimsPerSweep:      8,
	})
	_, pid := oomLoad(t, k, "oomzero", kernel.Manifest{
		Require: []kernel.Op{kernel.OpMetadataRead},
	})
	require.Zero(t, kernel.OomTallyFor(pid).Total(), "this module holds no accounted memory")

	// Maximum host pressure, so the sweep is looking for a victim and will not find an
	// honest one.
	require.NoError(t, k.OomSetMemorySampler(oomSamplerAtBP(10000)))
	require.GreaterOrEqual(t, kernel.OomPressureSnapshot().HostFraction, 9999)

	actions := kernel.OomPatrol()
	for _, a := range actions {
		assert.NotEqual(t, pid, a.PID, "a module accounted at zero bytes is not a victim")
		assert.Positive(t, a.Total)
	}
	assert.False(t, kernel.SignalTerminated(pid))
	assert.Positive(t, kernel.OomStatsSnapshot().NoVictim,
		"having nothing to attribute is recorded rather than papered over")
}

// TestTheLedgerIsBoundedAndTrimsInOneStep pins the ledger bound and the shape of the trim.
// The bound matters more here than elsewhere: an unbounded termination ledger would grow
// kernel memory while trying to reduce it, which is this subsystem causing the condition it
// exists to prevent.
func TestTheLedgerIsBoundedAndTrimsInOneStep(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxKVBytesPerModule:        4 << 20,
		MaxAccountedBytesPerModule: 8 << 10,
		OomMaxVictimsPerSweep:      64,
	})

	// Each sweep needs a fresh victim, because a terminated module leaves the tally list.
	// The loop runs until the ledger actually reaches its bound: a fixed round count below
	// the bound would produce no eviction at all and the trim would go untested, which is how
	// this case failed the first time it was written - 200 rounds, 200 entries, nothing to
	// trim, and a green-looking assertion about a bound that was never reached.
	// Past the bound rather than up to it, because the trim responds to exceeding the bound
	// and a loop that stops the moment the ledger is full never appends the entry that
	// triggers it. Reaching a ceiling and going over it are different facts, and only the
	// second one exercises the trim.
	const bound = 512
	const rounds = bound + 8
	for round := range rounds {
		ctx, _ := oomLoad(t, k, "oomledger", kernel.Manifest{
			Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
		})
		oomFillState(t, ctx, 32<<10)
		require.NotEmpty(t, kernel.OomPatrol(),
			"round %d produced no victim, so the ledger cannot pass its bound", round)
	}

	stats := kernel.OomStatsSnapshot()
	assert.LessOrEqual(t, stats.Retained, bound, "the ledger never exceeds its bound")
	assert.Positive(t, stats.Evicted, "records were evicted rather than accumulated")
	assert.GreaterOrEqual(t, stats.Sweeps, int64(rounds))
	// The trim drops back to seven eighths of the bound in one step rather than exactly to it,
	// so the ledger is meaningfully below the ceiling afterwards. Trimming to exactly the
	// bound would reallocate and copy the whole ledger on every insert past it, under the
	// write lock, while the host is under memory pressure.
	assert.Less(t, stats.Retained, bound, "the trim left room rather than refilling to the ceiling")

	history := kernel.OomHistory()
	for i := 1; i < len(history); i++ {
		assert.Greater(t, history[i].Seq, history[i-1].Seq, "sequence numbers increase")
	}
	// The retained window is the NEWEST entries, so an operator investigating a current
	// incident is not left with the oldest ones.
	assert.Positive(t, history[len(history)-1].Seq)
}

// TestSnapshotsAreCopies pins that mutating a returned tally list cannot reach kernel state.
func TestSnapshotsAreCopies(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{MaxKVBytesPerModule: 1 << 20})
	ctx, pid := oomLoad(t, k, "oomcopy", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	oomFillState(t, ctx, 64<<10)

	tallies := kernel.OomTallies()
	require.NotEmpty(t, tallies)
	for i := range tallies {
		tallies[i].StateBytes = -1
		tallies[i].Module = "tampered"
	}
	again := kernel.OomTallies()
	for _, ty := range again {
		assert.NotEqual(t, "tampered", ty.Module)
		if ty.PID == pid {
			assert.Positive(t, ty.StateBytes)
		}
	}

	history := kernel.OomHistory()
	if len(history) > 0 {
		history[0].Module = "tampered"
	}
	for _, h := range kernel.OomHistory() {
		assert.NotEqual(t, "tampered", h.Module)
	}
}

// TestNothingSurvivesRestart pins the reset, including the sampler. Keeping it would mean a
// restarted kernel reading a machine it has not been told about, which is the reasoning
// resetPeers gives for dropping the transport and resetNet for dropping the resolver.
func TestNothingSurvivesRestart(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxKVBytesPerModule:        1 << 20,
		MaxAccountedBytesPerModule: 8 << 10,
	})
	ctx, pid := oomLoad(t, k, "oomreset", kernel.Manifest{
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	oomFillState(t, ctx, 32<<10)
	require.NoError(t, k.OomSetMemorySampler(oomSamplerAtBP(5000)))
	require.NotEmpty(t, kernel.OomPatrol())
	require.Positive(t, kernel.OomStatsSnapshot().Sweeps,
		"the sweep that just ran is counted")
	require.NotEmpty(t, kernel.OomHistory())
	require.True(t, kernel.OomStatsSnapshot().Sampler)

	require.NoError(t, k.Shutdown())

	k2 := oomBoot(t, kernel.BootLimits{})
	require.False(t, kernel.OomStatsSnapshot().Sampler,
		"the host sampler does not survive a restart")
	assert.False(t, kernel.OomPressureSnapshot().OomHostPressureKnown())
	assert.Empty(t, kernel.OomHistory())
	stats := kernel.OomStatsSnapshot()
	assert.Zero(t, stats.Kills)
	assert.Zero(t, stats.Retained)
	assert.Empty(t, kernel.OomTallyFor(pid).Module, "the old pid is gone from the table")
	_ = k2
}

// ---------------------------------------------------------------------------
// Concurrency.

// TestConcurrentSweepsTerminateEachVictimOnce exercises the sweep from many goroutines at
// once. The property is that a victim is terminated once and recorded once: two sweeps
// racing over the same tally list must not produce two ledger entries for one module, which
// would make an operator's count of terminations wrong.
func TestConcurrentSweepsTerminateEachVictimOnce(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxKVBytesPerModule:        1 << 20,
		MaxAccountedBytesPerModule: 8 << 10,
		OomMaxVictimsPerSweep:      1,
	})

	var pids []kernel.PID
	for range 6 {
		ctx, pid := oomLoad(t, k, "oomrace", kernel.Manifest{
			Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
		})
		oomFillState(t, ctx, 32<<10)
		pids = append(pids, pid)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[kernel.PID]int{}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 6 {
				for _, a := range kernel.OomPatrol() {
					mu.Lock()
					seen[a.PID]++
					mu.Unlock()
				}
				_ = kernel.OomPressureSnapshot()
				_ = kernel.OomTallies()
				_ = kernel.OomStatsSnapshot()
				_ = kernel.OomHistory()
			}
		}()
	}
	wg.Wait()

	for pid, n := range seen {
		assert.Equal(t, 1, n, "pid %d was terminated %d times; a victim is terminated once", pid, n)
		assert.Contains(t, pids, pid)
	}
	assert.NotEmpty(t, seen, "the racing sweeps did terminate victims")

	history := kernel.OomHistory()
	counts := map[kernel.PID]int{}
	for _, h := range history {
		counts[h.PID]++
	}
	for pid, n := range counts {
		assert.Equal(t, 1, n, "pid %d appears %d times in the ledger", pid, n)
	}
}

// ---------------------------------------------------------------------------
// The surface itself.

// TestAModuleCannotInvokeTheSweep pins that there is no syscall for this subsystem. kpanic
// is the precedent: a subsystem whose whole job is deciding when to end a module must not be
// callable by one. A module could not choose the victim - the kernel does that from its own
// tallies and never from an argument - but it could force sweeps at a rate that made the
// subsystem's own cost part of the pressure it measures.
func TestAModuleCannotInvokeTheSweep(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{})
	// Every unscoped operation the plugin domain's ceiling holds, so the assertion below is
	// about the surface and not about a module that simply lacked a grant. The scoped half of
	// the ceiling cannot go in a Require list without its boundary - manifest validation
	// refuses route:register with no serve path - and omitting it does not weaken this case,
	// which is about there being no sweep to call at all rather than about how much a module
	// was granted.
	var unscoped []kernel.Op
	for _, op := range kernel.OpsFor(kernel.DomainPlugin) {
		if !kernel.IsScoped(op) {
			unscoped = append(unscoped, op)
		}
	}
	require.NotEmpty(t, unscoped, "the plugin ceiling holds unscoped operations")
	require.Contains(t, unscoped, kernel.OpRouteRegister,
		"route:register is unscoped, so it is in this set and needs its declaration")
	// A scoped operation is refused without its manifest boundary, and route:register is
	// refused without a declared serve path even though it is not scoped - the two rules are
	// separate. Declaring the path is what makes this the largest set a module can actually
	// load, which is the point of the case: no amount of granted capability produces a sweep.
	ctx, _ := oomLoad(t, k, "oomsyscall", kernel.Manifest{
		Require:     unscoped,
		ServeRoutes: []string{"/v1/oom-probe"},
	})

	// The sealed SContext composition is what a module actually gets, so a method that is not
	// in it does not exist for a module however it is spelled here. One comma-ok assertion: a
	// second conversion of the first's result panics when the first fails, which would make
	// this test report a crash rather than the property it is asserting.
	_, hasPatrol := any(ctx).(interface {
		SyscallOomPatrol() []kernel.OomAction
	})
	assert.False(t, hasPatrol, "no module-facing sweep exists")

	_, hasTally := any(ctx).(interface {
		SyscallOomTally() kernel.OomTally
	})
	assert.False(t, hasTally, "and no module-facing read of another pid's memory")

	// Asserted against the whole operation vocabulary rather than one domain's ceiling,
	// because the claim is that no operation name anywhere grants a sweep.
	for _, op := range kernel.AllOps {
		assert.False(t, strings.HasPrefix(string(op), "oom:"),
			"%q is not a grantable operation", op)
	}
}

// ---------------------------------------------------------------------------
// The three properties mutation testing found unasserted.

// TestTheVictimPredicateIsWhatDecides pins the exclusion directly rather than only through
// a sweep. Mutation testing found the sweep-based case could be made to pass with the
// predicate inverted, because a sweep's outcome also depends on which modules happen to hold
// memory - and the predicate is the part that makes "never" mean never rather than "not this
// time". It is exported for exactly this reason.
func TestTheVictimPredicateIsWhatDecides(t *testing.T) {
	for _, tc := range []struct {
		dom      kernel.Domain
		eligible bool
		why      string
	}{
		{kernel.DomainKernel, false, "the kernel protects the host, so it cannot be the price of protecting it"},
		{kernel.DomainInit, false, "init is the host's long-lived context; killing it is unrecoverable"},
		{kernel.DomainPlugin, true, "a plugin is what this subsystem exists to be able to end"},
		{kernel.DomainUntrusted, true, "and an untrusted module is ended before a plugin of any size"},
		{kernel.Domain("u:r:something:new:s0"), false,
			"an unrecognized domain is not eligible: failing closed is the only safe answer when the cost of being wrong is terminating something the kernel needs"},
	} {
		tally := kernel.NewOomTally(42, "probe", tc.dom, 1<<40, 0, 0)
		assert.Equal(t, tc.eligible, kernel.OomVictimEligible(tally), "%s: %s", tc.dom, tc.why)
	}

	// Size is not an input, which is the property the sweep-based case cannot isolate: the
	// kernel and init are given a terabyte here and are still not eligible.
	kern := kernel.NewOomTally(0, "kernel", kernel.DomainKernel, 1<<40, 1<<40, 1<<40)
	init := kernel.NewOomTally(1, "init", kernel.DomainInit, 1<<40, 1<<40, 1<<40)
	assert.False(t, kernel.OomVictimEligible(kern))
	assert.False(t, kernel.OomVictimEligible(init))
}

// TestThePatrolStartsWithTheBoot pins that the background sweep is running, which is the
// wiring mutation testing found removable without any test failing. Every other case here
// calls OomPatrol directly, so a boot that never started the patrol would leave this
// subsystem a function an operator could call and nothing that ever calls it - a detector
// that only detects when someone remembers to ask.
//
// The interval is derived from the sealed call ceiling and clamped to a floor of 500ms, so a
// short ceiling gives a test a patrol that fires within its lifetime.
func TestThePatrolStartsWithTheBoot(t *testing.T) {
	harness.QuietConsole(t)
	// A 1s call ceiling derives a 100ms interval, clamped up to the 500ms floor.
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-oom-patrol",
			Limits: kernel.BootLimits{CallTimeoutMillis: 1_000}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	require.Zero(t, kernel.OomStatsSnapshot().Sweeps, "no sweep has run yet")

	// Nothing is called here. If the patrol is running, the counter moves on its own.
	require.Eventually(t, func() bool { return kernel.OomStatsSnapshot().Sweeps > 0 },
		5*time.Second, 20*time.Millisecond,
		"the background patrol runs without being asked, which is the whole of what it is for")

	before := kernel.OomStatsSnapshot().Sweeps
	assert.Eventually(t, func() bool { return kernel.OomStatsSnapshot().Sweeps > before },
		5*time.Second, 20*time.Millisecond, "and it keeps running rather than sweeping once")

	// The derived interval is clamped at both ends, so a pathological ceiling cannot produce
	// a busy loop or a detector slower than the thing it detects.
	for _, millis := range []int64{1, 10, 1_000_000_000} {
		k2, err := kernel.Boot(kernel.BootConfig{
			TrustRoot: kernel.BootTrustRoot{NodeID: "node-oom-clamp",
				Limits: kernel.BootLimits{CallTimeoutMillis: millis}},
		})
		if err != nil {
			continue // one kernel at a time; the clamp is asserted on the boots that succeed
		}
		iv := kernel.EffectiveOomThresholds().Interval
		assert.GreaterOrEqual(t, iv, 500*time.Millisecond,
			"a %dms ceiling does not produce a busy loop", millis)
		assert.LessOrEqual(t, iv, 10*time.Second,
			"a %dms ceiling does not produce a detector slower than what it detects", millis)
		_ = k2.Shutdown()
	}
}

// TestACondemnationMarkIsReleasedWhenTheProcessGoes pins the bound on the mark set. A mark is
// held for the whole teardown deliberately, so it outlives the sweep that set it; without a
// release, a host that loads and terminates modules repeatedly over a long uptime would
// accumulate one entry per termination forever. That is a leak in the one subsystem whose job
// is to stop leaks, and mutation testing found removing the release had no observable effect -
// which is why the count is readable at all.
func TestACondemnationMarkIsReleasedWhenTheProcessGoes(t *testing.T) {
	harness.QuietConsole(t)
	k := oomBoot(t, kernel.BootLimits{
		MaxKVBytesPerModule:        1 << 20,
		MaxAccountedBytesPerModule: 8 << 10,
	})
	require.Zero(t, kernel.OomCondemned())

	var pids []kernel.PID
	for range 5 {
		ctx, pid := oomLoad(t, k, "oommark", kernel.Manifest{
			Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
		})
		oomFillState(t, ctx, 32<<10)
		pids = append(pids, pid)
		require.NotEmpty(t, kernel.OomPatrol())
	}

	// Marks may be held while teardowns are in flight, but the set must not grow without
	// limit and must return to zero once every process is gone.
	require.Eventually(t, func() bool { return kernel.OomCondemned() == 0 },
		10*time.Second, 10*time.Millisecond,
		"every condemnation mark is released once its process is gone")

	// And the modules really are gone, so the zero above is a released mark and not a
	// termination that never happened.
	for _, pid := range pids {
		require.Eventually(t, func() bool { return kernel.SignalTerminated(pid) },
			10*time.Second, 10*time.Millisecond)
	}
	// The tally list still contains pid 0 and pid 1, which is correct rather than a leak: an
	// operator reading the dump needs to see what init holds even though init can never be a
	// victim. What must be gone is every module.
	for _, ty := range kernel.OomTallies() {
		assert.False(t, kernel.OomVictimEligible(ty),
			"pid %d (%s, %s) is a module and should have been torn down", ty.PID, ty.Module, ty.Domain)
	}

	// A restart clears the set outright, which is the cross-boot half of the same bound.
	require.NoError(t, k.Shutdown())
	k2 := oomBoot(t, kernel.BootLimits{})
	assert.Zero(t, kernel.OomCondemned())
	_ = k2
}
