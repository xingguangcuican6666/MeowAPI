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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

// TestResetClearsWhatUnloadNeverTouches covers two entries in resetKernel that no test
// reached, because both clear state belonging to something the teardown path never unloads.
// Removing either left all 20 packages green; removing both together let a boot-2 module read
// boot-1's data root and boot-2's init read boot-1's key, with nothing on boot 2's chain.
//
// resetKVFS: a loaded module's namespace is also dropped by KVDropNamespace in UnloadModule,
// which is what tests/state asserts, so the reset looked redundant. It is not, because init is
// never in the handle's module list - boot.go appends only cfg.Modules - so unloadAll never
// walks it and nothing but the reset clears init's own keys. Both boots allocate init as pid 1,
// so that state is in the namespace the next boot's init reads.
//
// resetFS: data roots are keyed by module NAME rather than pid, deliberately, because a root is
// a deployment decision that outlives a boot and the host installs one before the module loads.
// That keying is exactly what makes the reset load-bearing: the next boot's module is looked up
// by the same name and finds the previous boot's directory. The refusal the kernel gives is "no
// data root is configured", which is a refusal rather than a fallback, and it is the only thing
// standing between a restarted module and a directory the previous boot chose.
func TestResetClearsWhatUnloadNeverTouches(t *testing.T) {
	harness.QuietConsole(t)

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "secret.txt"), []byte("BOOT-ONE"), 0o600))

	k1, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)

	// init's own namespace, which no unload reaches.
	require.NoError(t, kernel.KVPut(k1.InitContext(), "init.key", []byte("BOOT-ONE")))
	require.Positive(t, kernel.KVBytes(1))

	// A data root installed for a name that is not loaded in this boot, which is the shape
	// the host uses: the root is installed before the module loads.
	require.NoError(t, kernel.FSSetDataRoot("carrier", root))

	require.NoError(t, k1.Shutdown())

	assert.Zero(t, kernel.KVBytes(1), "init's namespace must not survive the shutdown")

	k2, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	// Asserted through the new boot's own handles rather than by inspecting the old ones:
	// the property is what a restarted kernel can reach, not what a dead one held.
	leaked, err := kernel.KVGet(k2.InitContext(), "init.key")
	assert.Error(t, err, "boot 2's init must not find boot 1's key")
	assert.Empty(t, leaked)

	probe := &harness.Probe{}
	harness.RegisterProbe(t, "carrier", probe)
	pid, err := k2.Load(kernel.Manifest{
		Name: "carrier", Version: "0.1.0", MinKernelAPI: kernel.KernelAPI,
		MaxKernelAPI: kernel.KernelAPI,
		Require:      []kernel.Op{kernel.OpFSRead},
		ReadPaths:    []string{"secret.txt"},
	})
	require.NoError(t, err, "the name is free again in a fresh boot")
	t.Cleanup(func() { _ = k2.Unload(pid) })

	_, err = kernel.FSReadFile(probe.Ctx, "secret.txt")
	assert.Error(t, err, "boot 2 must not inherit boot 1's data root")
	assert.Contains(t, err.Error(), "no data root is configured",
		"and the refusal is the one that says the root was never installed here")

	// Both are host-settable in the new boot, so the clear is not a permanent refusal. The
	// root goes on a different name rather than on the loaded one, because FSSetDataRoot
	// refuses to re-point a root while that module is live - the containment rule the
	// refusal exists to keep, and one this assertion must not trip over.
	require.NoError(t, kernel.FSSetDataRoot("next-carrier", t.TempDir()))
	require.NoError(t, kernel.KVPut(k2.InitContext(), "boot.two", []byte("v")))
	got, err := kernel.KVGet(k2.InitContext(), "boot.two")
	require.NoError(t, err)
	assert.Equal(t, "v", string(got))
}

// resetTestSampler reports a host at 100% so a single sweep produces a record worth
// asserting was cleared.
type resetTestSampler struct{}

func (resetTestSampler) TotalMemoryBytes() uint64 { return 1 << 30 }
func (resetTestSampler) ReservedBytes() uint64    { return 1 << 30 }

// ---------------------------------------------------------------------------
// The authority gate on the kernel handle.

// foreignKernelErr is what hostOnly returns. Compared by text because the sentinel is
// unexported, and the text is part of the contract: an operator reading an audit line needs
// to be able to tell "you are not the booted kernel" from "this kernel has shut down".
const foreignKernelErr = "kernel: not the booted kernel"

// foreignContextErr is errForeignContext, which is unexported. Compared by text for the same
// reason as the constant above, and because exporting a sentinel so a test can errors.Is it
// would widen the kernel's surface for a check the test can make without it.
const foreignContextErr = "kernel: context was not issued by this kernel"

// TestAZeroKernelCannotAct pins the gate on every exported Kernel method.
//
// A module is Go code in this address space importing this package. Every field of Kernel is
// unexported, so module code can write &kernel.Kernel{} and call any method on it. The zero
// value has a usable mutex and shutdown == false, so the shutdown check every method had
// passed for exactly the receiver it must refuse, and the method then acted on package state
// that is not scoped to the receiver at all. Verified before the gate existed: a zero Kernel
// could publish kernel metadata, install the console credential, remove the net resolver, and
// install a memory sampler reporting the host at 100% - which is how a module holding zero
// operations made the kernel terminate its largest plugin.
//
// This is not the containment limit AGENT.md documents. That limit is about a module acting
// OUTSIDE the kernel - its own socket, its own file read - which no field here can stop and
// which the gate does not claim to. What the gate stops is a module acting THROUGH the kernel
// with the kernel's authority, and having the kernel record the result as its own action.
//
// The list is asserted against the type by reflection, so a method added later without the
// gate fails here rather than shipping. That is the part that keeps this from being a
// regression test for the twenty methods that exist today.
func TestAZeroKernelCannotAct(t *testing.T) {
	harness.QuietConsole(t)

	k := harness.BootOne(t)
	require.NotNil(t, k, "the host holds the booted kernel")

	z := &kernel.Kernel{}

	// Each case is one method, with arguments that are valid enough to reach the gate. What
	// is asserted is not that the arguments are good but that the receiver is refused first:
	// a gate that ran after argument validation would let a caller learn something from the
	// error, and one that ran after the shutdown check would let a zero receiver through.
	cases := []struct {
		name string
		call func() error
	}{
		{"Publish", func() error { return z.Publish("forged.key", "forged") }},
		{"PostEvent", func() error {
			return z.PostEvent(kernel.EventJobFinished, 999, "forged")
		}},
		{"PostEventToPid", func() error {
			return z.PostEventToPid(kernel.EventPeerDisconnected, 1, 1, "forged")
		}},
		{"Load", func() error {
			_, err := z.Load(kernel.Manifest{Name: "forged", Version: "1"})
			return err
		}},
		{"Unload", func() error { return z.Unload(1) }},
		{"Shutdown", func() error { return z.Shutdown() }},
		{"InstallSecret", func() error {
			return z.InstallSecret(kernel.SecretSpec{Alias: "forged/a", Value: []byte("sk-x")})
		}},
		{"RevokeSecret", func() error { return z.RevokeSecret("forged/a") }},
		{"InstallConsoleCredential", func() error {
			return z.InstallConsoleCredential([]byte("forged-console-credential"))
		}},
		{"OomSetMemorySampler", func() error {
			return z.OomSetMemorySampler(forgedSampler{})
		}},
		{"NetSetResolver", func() error { return z.NetSetResolver(nil) }},
		{"PeerSetTransport", func() error { return z.PeerSetTransport(nil) }},
		{"PeerDial", func() error {
			_, err := z.PeerDial(kernel.PeerDialSpec{Endpoint: "forged.example"})
			return err
		}},
		{"PeerProbe", func() error { _, err := z.PeerProbe(1, 0); return err }},
		{"PeerForward", func() error {
			_, err := z.PeerForward(kernel.PeerForwardRequest{NodeID: "forged"})
			return err
		}},
		{"PeerAnnounce", func() error {
			return z.PeerAnnounce(kernel.PeerAnnouncement{NodeID: "forged"})
		}},
		{"PeerPeers", func() error { _, err := z.PeerPeers(); return err }},
		{"PeerDeliver", func() error {
			_, err := z.PeerDeliver("forged", kernel.PeerFrame{})
			return err
		}},
		{"AdjudicateSlash", func() error {
			_, err := z.AdjudicateSlash(kernel.SlashID("forged"))
			return err
		}},
		{"IssueReceipt", func() error {
			_, err := z.IssueReceipt(kernel.ReceiptSpec{})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err, "%s must refuse a receiver that is not the booted kernel", tc.name)
			assert.Equal(t, foreignKernelErr, err.Error(),
				"and the refusal must name the reason, so an operator can tell a forged handle "+
					"from a shut-down kernel")
		})
	}

	// Reflection over the exported method set, so the case list above cannot silently stop
	// covering the type. A method that is not in the list fails here, and the fix is to add a
	// case, not to widen this check. There are no exemptions: every exported method returns an
	// error and is in the list, or is InitContext, whose different shape is asserted below.
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.name] = true
	}

	t.Run("InitContext", func(t *testing.T) {
		// InitContext returns a bare SContext rather than (SContext, error), so it cannot
		// report a refusal and returns nil instead. What it must not return is the receiver's
		// initCtx field, because on a zero Kernel that is a nil *sContext and a typed nil
		// inside an interface is not nil: ctx == nil reads false, the comma-ok assertion every
		// syscall entry point makes succeeds with a nil pointer behind it, and the first
		// dereference panics. That turns "not issued by this kernel" into a crash, and a crash
		// is not distinguishable from a refusal by the module that caused it.
		//
		// Verified before the fix: TTYOpen, TTYWrite, KVGet, NetDial, PeerDial, EventWait,
		// SchedSpawn and SlashReport all panicked on it, and sched.go's recovery caught each
		// one, so the observable result was that a module could reliably terminate itself with
		// a nil dereference instead of receiving an error.
		ctx := z.InitContext()
		// Compared with == and not with assert.Nil, which reflects: reflect.IsNil reports true
		// for a typed nil too, so it cannot tell the fix from the bug the fix removes. The raw
		// comparison is also what a kernel entry point evaluates, which makes it the assertion
		// that matters here.
		assert.True(t, ctx == nil,
			"a foreign receiver gets an untyped nil, so ctx == nil reads true and every entry "+
				"point's !ok branch refuses it")
		assert.NotPanics(t, func() {
			_, err := kernel.TTYOpen(ctx)
			require.Error(t, err)
			assert.Equal(t, foreignContextErr, err.Error(),
				"and the refusal is the one that already means this context was not issued here")
		}, "a syscall receiving it is refused rather than crashing")

		// The booted kernel still hands out a working context, so the gate did not turn
		// InitContext into something that refuses everyone.
		require.NotNil(t, k.InitContext())
		assert.Equal(t, kernel.PID(1), k.InitContext().PID(),
			"and it is init's, which is what the host loads modules under")
	})
	covered["InitContext"] = true

	typ := reflect.TypeOf(z)
	for i := range typ.NumMethod() {
		name := typ.Method(i).Name
		assert.True(t, covered[name],
			"Kernel.%s is not covered by this test. If it acts on kernel state, add a case "+
				"asserting it refuses a zero receiver; if it is a read-only accessor like "+
				"InitContext, add it to the exemption above with the reason.", name)
	}

	// The gate did not break the host's own path.
	require.NoError(t, k.Publish("gate.check", "host"))
	v, ok := kernel.MetadataSnapshot()["gate.check"]
	require.True(t, ok)
	assert.Equal(t, "host", v)

	// And nothing the forged handle attempted took effect, which is the assertion that
	// distinguishes "refused" from "refused after doing it".
	assert.NotContains(t, kernel.MetadataSnapshot(), "forged.key")
	assert.False(t, kernel.OomStatsSnapshot().Sampler, "no forged memory sampler was installed")
	assert.Empty(t, kernel.OomHistory(), "and no module was terminated on its say-so")
	for _, info := range kernel.SecretInventory() {
		assert.NotEqual(t, "forged/a", info.Alias, "no forged secret was installed")
	}

	// The real kernel is still the real kernel afterwards: a gate that tripped on the booted
	// handle would be a gate that refuses everyone.
	assert.NotNil(t, k.InitContext())
	require.NoError(t, k.PostEvent(kernel.EventConfigReloaded, 0, "host-posted"))
}

// forgedSampler is what a module would install to lie about host memory: a total that makes
// the process look like it is using all of it, so koom terminates the largest plugin.
type forgedSampler struct{}

func (forgedSampler) TotalMemoryBytes() uint64 { return 1 << 20 }
func (forgedSampler) ReservedBytes() uint64    { return 1 << 20 }

// TestAContextRetainedAcrossShutdownCannotActOnTheNextBoot pins the retire in Shutdown,
// which no test covered: removing `k.initCtx.retire()` left all 20 packages green.
//
// What the retire stops is not the stale context acting on its own boot - that boot's state is
// gone, so most of what it could do lands nowhere. It is the stale context acting on the NEXT
// boot's state. Both boots allocate init as pid 1, and kvfs namespaces by module name, so a
// context retained from boot 1 writes into the same namespace boot 2's init reads. The process
// table really is fresh, which is what tests/identity asserts, and that is exactly why the gap
// stayed hidden: the table looks correct while the namespace accepts a write from a handle that
// belonged to a kernel that no longer exists.
//
// AGENT.md states the property - "A retired context returns kernel: context retired from every
// syscall. This is what makes the root context handoff irreversible in practice rather than only
// in intent" - and states it for Shutdown too, which is the reason this asserts both domains the
// stale context reaches for: per-pid state and the kernel's own metadata store.
func TestAContextRetainedAcrossShutdownCannotActOnTheNextBoot(t *testing.T) {
	harness.QuietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	stale := k1.InitContext()
	require.NotNil(t, stale)
	require.NoError(t, k1.Shutdown())

	k2, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err, "the boot guard is released by Shutdown")
	defer func() { _ = k2.Shutdown() }()
	fresh := k2.InitContext()
	require.NotNil(t, fresh)

	const retiredErr = "kernel: context retired"

	// Each stale call is asserted rather than required, so one missing retire reports every
	// refusal it should have caused instead of stopping at the first. They are independent
	// calls into independent subsystems, and the read-backs below are what make the failure
	// legible: without them a report would say "no error" three times and not say what the
	// stale handle got away with.
	refused := func(what string, err error) {
		t.Helper()
		assert.Error(t, err, "%s from a context retained across a shutdown must be refused", what)
		if err != nil {
			assert.Equal(t, retiredErr, err.Error(),
				"and %s is refused as retired, not as foreign: this kernel issued it", what)
		}
	}

	// Per-pid namespaced state, which is the one that crosses boots: both inits are pid 1 and
	// both are named "init", so the write lands in the namespace the fresh context reads.
	refused("a kvfs write", kernel.KVPut(stale, "stale.key", []byte("from a previous boot")))
	leaked, err := kernel.KVGet(fresh, "stale.key")
	assert.Error(t, err, "nothing reached the new boot's namespace")
	assert.Empty(t, leaked, "and boot 2 cannot read what boot 1's handle wrote")

	// The kernel's own metadata store, which is package state rather than per-pid state and so
	// is the other thing a stale handle would otherwise write into. Read back through the fresh
	// context rather than through MetadataSnapshot, because the snapshot exposes only published
	// entries and both inits are pid 1: a write the stale handle managed would land under the
	// same owner the fresh context reads, which is what makes the read-back a real assertion
	// instead of a check that would pass either way.
	refused("a metadata write", stale.SyscallMetadataSet("stale.metadata", "from a previous boot"))
	v, err := fresh.SyscallMetadataGet("stale.metadata")
	require.NoError(t, err, "reading metadata is init's own privilege and is not what is under test")
	assert.Nil(t, v, "nothing reached the new boot's metadata store")

	// A fault-level record is the highest-authority console write in the policy table, and a
	// stale handle is not allowed to add one to the new boot's chain either.
	refused("a fault-level log", stale.SyscallLog(kernel.LogFault, "a fault from a previous boot"))

	// The refusal is about the handle and not about the kernel being unusable: the fresh
	// context does all three things the stale one was refused.
	require.NoError(t, kernel.KVPut(fresh, "fresh.key", []byte("v")))
	got, err := kernel.KVGet(fresh, "fresh.key")
	require.NoError(t, err)
	assert.Equal(t, "v", string(got))

	require.NoError(t, fresh.SyscallMetadataSet("fresh.metadata", "v"))
	v, err = fresh.SyscallMetadataGet("fresh.metadata")
	require.NoError(t, err)
	assert.Equal(t, "v", v, "the new boot's own init can still write its metadata")

	require.NoError(t, fresh.SyscallLog(kernel.LogInfo, "the new boot logs"))
}

// TestARefusedInstallStillWipesTheCallersSecret covers the two methods on the kernel handle
// that take caller-owned credential bytes, against both refusals each can return.
//
// Both document that ownership transfers and the caller's slice is zeroed on return whether
// the call succeeded or was refused. Two refusal paths did not honour that: the authority gate
// and the shutdown check. They were added later than the contract, and each returns before
// reaching installSecret and installConsoleCredential, which are the functions that wipe on
// their own paths. A refusal that returns early is still a return, and the credential is still
// in the caller's heap: a host that read the value from an environment variable or a file now
// has a recoverable copy it believes the kernel took off its hands.
//
// The shutdown half was already covered for the console credential by
// tests/evidence/tty_test.go, and the gate half is what a mutation found missing - it is the
// regression the gate itself introduced, which is why the test lives beside the gate's other
// assertions rather than in either subsystem's suite.
func TestARefusedInstallStillWipesTheCallersSecret(t *testing.T) {
	harness.QuietConsole(t)

	// 32 bytes: inside the console credential's floor and ceiling, and a legal secret value.
	secret := func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte('a' + i%26)
		}
		return b
	}

	t.Run("a shut-down kernel", func(t *testing.T) {
		k := harness.BootOne(t)
		require.NoError(t, k.Shutdown())

		value := secret()
		err := k.InstallSecret(kernel.SecretSpec{Alias: "refused/secret", Value: value})
		require.Error(t, err)
		assert.Equal(t, make([]byte, 32), value,
			"a refused secret install must still wipe the caller's value")

		cred := secret()
		err = k.InstallConsoleCredential(cred)
		require.Error(t, err)
		assert.Equal(t, make([]byte, 32), cred,
			"a refused console credential must still wipe the caller's value")
	})

	t.Run("a handle that is not the booted kernel", func(t *testing.T) {
		z := &kernel.Kernel{}

		value := secret()
		err := z.InstallSecret(kernel.SecretSpec{Alias: "refused/secret", Value: value})
		require.Error(t, err)
		assert.Equal(t, foreignKernelErr, err.Error())
		assert.Equal(t, make([]byte, 32), value,
			"the authority gate is a refusal like any other, and the bytes are the caller's")

		cred := secret()
		err = z.InstallConsoleCredential(cred)
		require.Error(t, err)
		assert.Equal(t, foreignKernelErr, err.Error())
		assert.Equal(t, make([]byte, 32), cred,
			"and which check refused does not change what an unwiped credential means")
	})

	t.Run("the host path still installs and still wipes", func(t *testing.T) {
		k := harness.BootOne(t)

		value := secret()
		require.NoError(t, k.InstallSecret(kernel.SecretSpec{Alias: "wiped/ok", Value: value}))
		assert.Equal(t, make([]byte, 32), value, "an accepted install wipes too, as before")

		found := false
		for _, info := range kernel.SecretInventory() {
			if info.Alias == "wiped/ok" {
				found = true
			}
		}
		assert.True(t, found, "and the refusal above is not the wipe turning into a no-op")
	})
}

// TestOnlyTheBootedKernelCanAssertAKernelFact is the kepoll half of the same gate, asserted
// end to end rather than as a refusal: a subscriber must not be able to receive an event that
// no kernel subsystem observed.
//
// This is the property AGENT.md states for kepoll - that a peer's claim is never
// indistinguishable from a kernel fact - and it was false while PostEvent was a package
// function. The closed name set stops a module inventing a name; it does not stop a module
// using a real name to assert something untrue, and Event carries no origin field a
// subscriber could check.
func TestOnlyTheBootedKernelCanAssertAKernelFact(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	victim := &harness.Probe{}
	harness.RegisterProbe(t, "subscriber", victim)
	_, err := k.Load(kernel.Manifest{
		Name: "subscriber", Version: "1",
		MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpEventWait},
	})
	require.NoError(t, err)
	require.NotNil(t, victim.Ctx)

	fd, err := kernel.EventSubscribe(victim.Ctx, []kernel.KernelEventName{
		kernel.EventJobFinished, kernel.EventPeerDisconnected,
	})
	require.NoError(t, err)

	// A second module, granted nothing at all. It is ordinary in-process Go code like every
	// other module, so if posting were reachable it would reach it.
	forger := &harness.Probe{}
	harness.RegisterProbe(t, "forger", forger)
	fpid, err := k.Load(kernel.Manifest{
		Name: "forger", Version: "1",
		MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
	})
	require.NoError(t, err)
	granted, _ := kernel.GrantsFor(fpid)
	require.Empty(t, granted, "the forger holds no operation at all")

	// Its attempt to assert a kernel fact is refused at the handle, not by a policy check:
	// there is no operation to grant and no avc line to write.
	z := &kernel.Kernel{}
	assert.Equal(t, foreignKernelErr,
		z.PostEvent(kernel.EventJobFinished, 999, "forged-job").Error())

	// Nothing arrived. The wait is bounded so this cannot hang if the assertion is wrong.
	got, err := kernel.EventWait(victim.Ctx, fd,
		kernel.KernelClock().Deadline(150*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrNoEvents, "no forged fact reached the subscriber")
	assert.Empty(t, got)

	// And when the host does post, the subscriber receives it - so the refusal above is the
	// gate and not a subscription that never fires either way.
	require.NoError(t, k.PostEventToPid(kernel.EventJobFinished, victim.Ctx.PID(), 7, "real-job"))
	got, err = kernel.EventWait(victim.Ctx, fd,
		kernel.KernelClock().Deadline(2*time.Second))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, kernel.EventJobFinished, got[0].Name)
	assert.Equal(t, kernel.PID(7), got[0].Subject)
	assert.Equal(t, "real-job", got[0].Detail)
}
