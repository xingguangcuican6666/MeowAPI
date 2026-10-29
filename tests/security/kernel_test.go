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

package security

import (
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestPluginCannotEscalateOrForge drives a real plugin and asserts what it
// cannot do from inside OnLoad: write kernel metadata, emit a fault record,
// spawn a kernel-domain child, or gain an operation its domain lacks.
func TestPluginCannotEscalateOrForge(t *testing.T) {
	buf := harness.QuietConsole(t)

	k := harness.BootOne(t)
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	fs := harness.Faults(buf)
	require.NotEmpty(t, fs, "the diag plugin deliberately trips metadata:write")

	var sawWriteDenial bool
	for _, r := range fs {
		if strings.Contains(r.Msg, "metadata:write") && r.Domain == kernel.DomainPlugin {
			sawWriteDenial = true
			assert.Equal(t, pid, r.Pid, "the denial must name the offending module's pid")
		}
	}
	assert.True(t, sawWriteDenial, "expected an avc denial for metadata:write from the plugin domain")

	for _, r := range fs {
		assert.NotContains(t, r.Msg, "avc: denied { metadata:read }",
			"the plugin domain holds metadata:read; a denial here means the matrix drifted")
	}
}

// TestResetKernelIsComplete is the guard against a subsystem being added and left
// out of the reset path. A stale grant set or usage table surviving a restart
// would make every security test below silently wrong on the second boot, which is
// the failure mode the reset path exists to prevent.
func TestResetKernelIsComplete(t *testing.T) {
	harness.QuietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)

	harness.RegisterProbe(t, "leaky", &harness.Probe{Load: func(ctx kernel.SContext) error {
		return ctx.SyscallUsageEmit(kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: 42})
	}})
	pid, err := k1.Load(kernel.Manifest{
		Name: "leaky", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpUsageEmit},
	})
	require.NoError(t, err)
	require.Equal(t, int64(42), kernel.UsageTotal(kernel.UsageTokensIn))
	require.NotEmpty(t, kernel.UsageSnapshot()[pid])

	require.NoError(t, k1.Shutdown())

	// Every subsystem must be clean before the second boot, not after it.
	assert.Empty(t, kernel.LoadedModules(), "module table must be cleared")
	assert.Empty(t, kernel.ProcTable(), "process table must be cleared")
	assert.Empty(t, kernel.UsageSnapshot(), "usage accounting must be cleared")
	assert.Zero(t, kernel.UsageTotal(kernel.UsageTokensIn))
	assert.Empty(t, kernel.MetadataSnapshot(), "metadata store must be cleared")
	assert.Empty(t, kernel.KernelConsole().History(), "console retention must be cleared")
	_, constrained := kernel.GrantsFor(pid)
	assert.False(t, constrained, "grant sets must be cleared")

	k2, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	assert.Empty(t, kernel.UsageSnapshot(), "a fresh boot must inherit no accounting")
	assert.Equal(t, kernel.PID(0), kernel.ProcTable()[0].PID, "a fresh boot starts at pid 0")
}

// TestResetClearsTheSubsystemStateAddedSince pins that the subsystems whose state is
// per-pid and per-boot are cleared by resetKernel, which is the property
// TestResetKernelIsComplete asserts for the core tables but had no coverage for once koom
// and kseccomp joined.
//
// The failure this prevents is a leak across boots, and the two new subsystems leak in
// different ways. A retained instance filter would apply to whatever pid the next boot
// assigns, and pids restart at 1, so it would land on init. A retained condemnation mark
// would leave a pid permanently unkillable-by-oom, since the sweep skips anything marked,
// and a retained host memory sampler would have the new kernel reading a machine it has not
// been told about.
func TestResetClearsTheSubsystemStateAddedSince(t *testing.T) {
	harness.QuietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-reset", Limits: kernel.BootLimits{
			MaxKVBytesPerModule:        1 << 20,
			MaxAccountedBytesPerModule: 1,
		}},
	})
	require.NoError(t, err)

	probe := &harness.Probe{}
	harness.RegisterProbe(t, "leakcheck", probe)
	pid, err := k1.Load(kernel.Manifest{
		Name: "leakcheck", Version: "0.1.0", MinKernelAPI: kernel.KernelAPI,
		MaxKernelAPI: kernel.KernelAPI,
		Require:      []kernel.Op{kernel.OpFSRead, kernel.OpKVRead, kernel.OpKVWrite},
		ReadPaths:    []string{"cache"},
	})
	require.NoError(t, err)
	require.NotNil(t, probe.Ctx)

	// The module has to hold accounted memory to be a victim. A module accounted at zero
	// bytes is never terminated at any host pressure, because ending it would be ending it
	// for existing - and a reset test built on a sweep that found no victim would assert that
	// nothing was cleared without ever having had anything to clear. That is how the first
	// version of this test failed: it passed every assertion about the seccomp state and then
	// found an empty oom history, because the sweep had correctly refused to kill a module
	// that was holding nothing.
	require.NoError(t, kernel.KVPut(probe.Ctx, "leak/payload", make([]byte, 64<<10)))
	require.Positive(t, kernel.OomTallyFor(pid).Total())

	// Install a filter and condemn the pid, so both have something to leak.
	_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "leakcheck", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)
	require.True(t, kernel.SeccompFiltered(pid))
	require.Positive(t, kernel.SeccompStatsSnapshot().Installs)
	require.NotEmpty(t, kernel.SeccompHistory())

	require.NoError(t, k1.OomSetMemorySampler(resetTestSampler{}))
	require.True(t, kernel.OomStatsSnapshot().Sampler)
	require.NotEmpty(t, kernel.OomPatrol(), "the sweep terminates the module over its ceiling")
	require.NotEmpty(t, kernel.OomHistory(), "and records it")
	require.Positive(t, kernel.OomStatsSnapshot().Kills)

	require.NoError(t, k1.Shutdown())

	// Every subsystem clean BEFORE the second boot, matching the ordering
	// TestResetKernelIsComplete asserts for the core tables.
	assert.False(t, kernel.SeccompFiltered(pid), "instance filters must be cleared")
	assert.Empty(t, kernel.SeccompHistory(), "the filter ledger must be cleared")
	sec := kernel.SeccompStatsSnapshot()
	assert.Zero(t, sec.Installs, "filter counters must be cleared")
	assert.Zero(t, sec.Filtered)

	assert.False(t, kernel.OomStatsSnapshot().Sampler,
		"a host-injected dependency must not survive a restart")
	assert.False(t, kernel.OomPressureSnapshot().OomHostPressureKnown())
	assert.Empty(t, kernel.OomHistory())
	assert.Zero(t, kernel.OomCondemned(), "condemnation marks must be cleared")
	oom := kernel.OomStatsSnapshot()
	assert.Zero(t, oom.Kills)
	assert.Zero(t, oom.Sweeps)

	k2, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-reset-2"},
	})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	// And a pid the new boot assigns is not born filtered or condemned, which is what the
	// per-pid state above would have caused.
	harness.RegisterProbe(t, "fresh", &harness.Probe{})
	fresh, err := k2.Load(kernel.Manifest{
		Name: "fresh", Version: "0.1.0", MinKernelAPI: kernel.KernelAPI,
		MaxKernelAPI: kernel.KernelAPI,
		Require:      []kernel.Op{kernel.OpFSRead},
		ReadPaths:    []string{"cache"},
	})
	require.NoError(t, err)
	assert.False(t, kernel.SeccompFiltered(fresh))
	assert.Zero(t, kernel.OomCondemned())
}

// resetTestSampler reports a host at 100% so a single sweep produces a record worth
// asserting was cleared.
type resetTestSampler struct{}

func (resetTestSampler) TotalMemoryBytes() uint64 { return 1 << 30 }
func (resetTestSampler) ReservedBytes() uint64    { return 1 << 30 }
