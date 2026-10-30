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

package identity

import (
	"reflect"
	"testing"

	"github.com/xingguangcuican6666/MeowAPI/tests/harness"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestTrustRootSealsOnBoot is the whole point of kboot. Configuration that can be
// changed after modules start is configuration a compromised module can change, and
// a swapped cluster root key would make every later signature check verify against
// the attacker's key while still passing.
func TestTrustRootSealsOnBoot(t *testing.T) {
	harness.QuietConsole(t)

	require.False(t, kernel.BootSealed(), "an unbooted kernel has no sealed root")
	require.NoError(t, kernel.BootSet("pre.boot", "writable"))

	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: harness.BootTrust()})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	assert.True(t, kernel.BootSealed())

	v, ok := kernel.BootGet("node.id")
	assert.True(t, ok)
	assert.Equal(t, "node-test", v)

	v, ok = kernel.BootGet("extra.region")
	assert.True(t, ok)
	assert.Equal(t, "local", v)

	assert.Equal(t, []string{"root-key-a", "root-key-b"}, kernel.ClusterRootKeys())

	// Every write path is refused after sealing, including from the host process,
	// which is what "not even uid 0" means in the owner's description.
	assert.ErrorIs(t, kernel.BootSet("node.id", "attacker"), kernel.ErrBootSealed)
	assert.ErrorIs(t, kernel.BootSet("cluster.root.0", "attacker-key"), kernel.ErrBootSealed)
	assert.ErrorIs(t, kernel.BootSet("brand.new", "x"), kernel.ErrBootSealed)

	v, _ = kernel.BootGet("node.id")
	assert.Equal(t, "node-test", v, "a refused write must not change the value")
	v, _ = kernel.BootGet("cluster.root.0")
	assert.Equal(t, "root-key-a", v)
	_, ok = kernel.BootGet("brand.new")
	assert.False(t, ok)
}

// TestTrustRootIsSealedBeforeModulesRun proves the ordering guarantee. If sealing
// happened at the end of boot, a module loaded during boot could observe the
// unsealed root and the guarantee would depend on load order.
func TestTrustRootIsSealedBeforeModulesRun(t *testing.T) {
	harness.QuietConsole(t)

	var sealedDuringOnLoad bool
	var sawNodeID string
	var sawSigningKey bool

	kernel.Register("sealprobe", func() (kernel.Module, error) {
		return &harness.Probe{Load: func(ctx kernel.SContext) error {
			sealedDuringOnLoad = kernel.BootSealed()
			sawNodeID, _ = ctx.SyscallBootGet("node.id")
			// The signing key is not in the configuration map at all, so there is
			// no key to read. Assert several plausible names all miss.
			for _, k := range []string{
				"signing_key_pem", "SigningKeyPEM", "node.signing_key",
				"cluster.signing", "limits.signing_key",
			} {
				if _, ok := ctx.SyscallBootGet(k); ok {
					sawSigningKey = true
				}
			}
			for _, e := range ctx.SyscallBootAll() {
				if e.Value == "SECRET-KEY-MATERIAL" || e.Key == "signing_key_pem" {
					sawSigningKey = true
				}
			}
			return nil
		}}, nil
	})
	t.Cleanup(func() { kernel.Unregister("sealprobe") })

	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: harness.BootTrust(),
		Modules:   []kernel.Manifest{{Name: "sealprobe", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1}},
	})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	assert.True(t, sealedDuringOnLoad, "the root must already be sealed when the first module loads")
	assert.Equal(t, "node-test", sawNodeID)
	assert.False(t, sawSigningKey, "key material must not be reachable through the boot config")
}

// TestTrustRootDigestIsStableAndCoversConfig makes the digest usable as a
// deployment record: the same root hashes the same, and any change changes it.
func TestTrustRootDigestIsStableAndCoversConfig(t *testing.T) {
	harness.QuietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{TrustRoot: harness.BootTrust()})
	require.NoError(t, err)
	d1 := kernel.BootDigest()
	require.NoError(t, k1.Shutdown())
	assert.Len(t, d1, 64)

	k2, err := kernel.Boot(kernel.BootConfig{TrustRoot: harness.BootTrust()})
	require.NoError(t, err)
	assert.Equal(t, d1, kernel.BootDigest(), "the same root must hash identically across boots")
	require.NoError(t, k2.Shutdown())

	mutated := harness.BootTrust()
	mutated.ClusterRootKeys = []string{"root-key-a", "root-key-EVIL"}
	k3, err := kernel.Boot(kernel.BootConfig{TrustRoot: mutated})
	require.NoError(t, err)
	defer func() { _ = k3.Shutdown() }()
	assert.NotEqual(t, d1, kernel.BootDigest(),
		"swapping a cluster root key must change the digest, or the digest proves nothing")
}

// TestTrustRootValidationRejectsGarbage covers the failure modes that would
// otherwise produce a kernel with no identity.
func TestTrustRootValidationRejectsGarbage(t *testing.T) {
	harness.QuietConsole(t)

	cases := []struct {
		name string
		mut  func(*kernel.BootTrustRoot)
		want string
	}{
		{"empty node id", func(r *kernel.BootTrustRoot) { r.NodeID = "" }, "requires a node id"},
		{"empty cluster key", func(r *kernel.BootTrustRoot) {
			r.ClusterRootKeys = []string{"ok", ""}
		}, "empty cluster root key"},
		{"empty extra key", func(r *kernel.BootTrustRoot) { r.Extra = map[string]string{"": "v"} }, "empty extra key"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := harness.BootTrust()
			c.mut(&tr)
			// Boot substitutes "local" for an empty node id, so drive the loader
			// through Boot for the key cases and assert the outcome.
			k, err := kernel.Boot(kernel.BootConfig{TrustRoot: tr})
			if err == nil {
				if c.name == "empty node id" {
					// Documented behavior: an empty node id defaults to "local" so a
					// single-node deployment needs no configuration. Read it before
					// shutting down, because shutdown clears the root.
					v, ok := kernel.BootGet("node.id")
					require.NoError(t, k.Shutdown())
					require.True(t, ok)
					assert.Equal(t, "local", v)
					return
				}
				require.NoError(t, k.Shutdown())
				t.Fatalf("expected Boot to reject: %s", c.want)
			}
			assert.Contains(t, err.Error(), c.want)
			assert.False(t, kernel.BootSealed(), "a rejected root must not leave a sealed kernel")
		})
	}
}

// TestLimitsComeFromSealedRootAndHaveDefaults covers the quota source. A ceiling
// that comes from a module declaration or a mutable setting is not a ceiling.
func TestLimitsComeFromSealedRootAndHaveDefaults(t *testing.T) {
	harness.QuietConsole(t)

	k, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	d := kernel.Limits()
	assert.Positive(t, d.MaxModules)
	assert.Positive(t, d.MaxSlotsPerModule)
	assert.Positive(t, d.MaxTotalSlots)
	assert.Positive(t, d.MaxOpenFDsPerModule)
	assert.Positive(t, d.MaxSharedBytes)
	assert.Positive(t, d.MaxKVBytesPerModule)
	assert.Positive(t, d.CallTimeoutMillis)
	require.NoError(t, k.Shutdown())

	k2, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{
		NodeID: "n",
		Limits: kernel.BootLimits{MaxModules: 1, MaxOpenFDsPerModule: 2, MaxTotalSlots: 3},
	}})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	l := kernel.Limits()
	assert.Equal(t, 1, l.MaxModules)
	assert.Equal(t, 2, l.MaxOpenFDsPerModule)
	assert.Equal(t, 3, l.MaxTotalSlots)
	// Fields left at zero fall back to the defaults rather than to zero, because a
	// zero ceiling would refuse everything and look like a kernel bug.
	assert.Positive(t, l.MaxSharedBytes)
	assert.Positive(t, l.CallTimeoutMillis)

	// The returned struct is a copy, so mutating it cannot change the kernel.
	l.MaxModules = 9999
	assert.Equal(t, 1, kernel.Limits().MaxModules)
}

// TestModuleLimitIsEnforced proves the ceiling is applied at load time.
func TestModuleLimitIsEnforced(t *testing.T) {
	buf := harness.QuietConsole(t)

	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{
		NodeID: "n", Limits: kernel.BootLimits{MaxModules: 2},
	}})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	pid1, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid1) }()

	kernel.Register("second", func() (kernel.Module, error) { return &harness.NoopModule{}, nil })
	t.Cleanup(func() { kernel.Unregister("second") })
	pid2, err := k.Load(kernel.Manifest{Name: "second", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid2) }()

	kernel.Register("third", func() (kernel.Module, error) { return &harness.NoopModule{}, nil })
	t.Cleanup(func() { kernel.Unregister("third") })
	pid3, err := k.Load(kernel.Manifest{Name: "third", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.Error(t, err, "loading past MaxModules must be refused")
	assert.Contains(t, err.Error(), "module limit reached")
	assert.Equal(t, kernel.PID(0), pid3)
	assert.Len(t, kernel.LoadedModules(), 2)

	assert.NotEmpty(t, harness.Faults(buf), "a quota refusal must be visible as a fault")

	rejects := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditReject})
	require.NotEmpty(t, rejects, "a quota refusal must reach the audit chain")
	assert.Equal(t, "third", rejects[len(rejects)-1].Fields["module"])

	// Freeing a slot makes the ceiling available again, so it is a live quota and
	// not a one-way latch.
	require.NoError(t, k.Unload(pid2))
	pid3, err = k.Load(kernel.Manifest{Name: "third", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid3) }()
}

// TestBootConfigIsResetBetweenBoots covers the reset-path half of kboot: a restart
// must re-read its own root rather than inherit the previous one, and must not keep
// a previous boot's digest.
func TestBootConfigIsResetBetweenBoots(t *testing.T) {
	harness.QuietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{TrustRoot: harness.BootTrust()})
	require.NoError(t, err)
	d1 := kernel.BootDigest()
	require.NoError(t, k1.Shutdown())

	assert.False(t, kernel.BootSealed(), "shutdown must unseal so a restart can load its own root")
	assert.Empty(t, kernel.BootDigest())
	_, ok := kernel.BootGet("node.id")
	assert.False(t, ok, "the previous root must not survive a shutdown")
	assert.Empty(t, kernel.ClusterRootKeys())

	k2, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "different"}})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	v, ok := kernel.BootGet("node.id")
	require.True(t, ok)
	assert.Equal(t, "different", v)
	assert.NotEqual(t, d1, kernel.BootDigest())
	assert.Empty(t, kernel.ClusterRootKeys(), "the previous cluster roots must not carry over")
}

// TestBootAllIsACopySortedAndSecretFree pins the shape of the exported view.
func TestBootAllIsACopySortedAndSecretFree(t *testing.T) {
	harness.QuietConsole(t)

	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: harness.BootTrust()})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	all := kernel.BootAll()
	require.NotEmpty(t, all)

	for i := 1; i < len(all); i++ {
		assert.Less(t, all[i-1].Key, all[i].Key, "BootAll must be sorted by key")
	}
	for _, e := range all {
		assert.NotEqual(t, "SECRET-KEY-MATERIAL", e.Value,
			"key material must never appear in the configuration view")
		assert.NotContains(t, e.Key, "signing")
	}

	all[0].Value = "mutated"
	fresh := kernel.BootAll()
	assert.NotEqual(t, "mutated", fresh[0].Value, "BootAll must return copies")
}

// TestModuleReadsTrustRoot drives the syscall surface, which is what a module
// actually uses.
func TestModuleReadsTrustRoot(t *testing.T) {
	harness.QuietConsole(t)

	var nodeID, digest string
	var limits kernel.BootLimits
	var allCount int

	kernel.Register("rootreader", func() (kernel.Module, error) {
		return &harness.Probe{Load: func(ctx kernel.SContext) error {
			nodeID, _ = ctx.SyscallBootGet("node.id")
			digest = ctx.SyscallBootDigest()
			limits = ctx.SyscallBootLimits()
			allCount = len(ctx.SyscallBootAll())
			return nil
		}}, nil
	})
	t.Cleanup(func() { kernel.Unregister("rootreader") })

	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: harness.BootTrust()})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	pid, err := k.Load(kernel.Manifest{Name: "rootreader", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	assert.Equal(t, "node-test", nodeID)
	assert.Len(t, digest, 64)
	assert.Positive(t, limits.MaxModules)
	assert.Positive(t, allCount)
}

// TestEverySealedLimitIsAttestedByTheDigest is the test the digest's own documentation
// promises and nothing delivered.
//
// BootDigest is written into the AuditBoot chain record as trust_root_digest, and its
// comment says an operator records it so a later investigation can prove which root a
// kernel ran under. For that to be true, every value the operator sealed has to move the
// digest. The pre-existing TestTrustRootDigestIsStableAndCoversConfig is named "CoversConfig"
// but mutates only ClusterRootKeys, so the whole limits class was untested - and when koom
// added four limits, they were sealed and enforced but never digested. Two boots differing
// only in OomHostKillBP, that is "terminate a module at 95% of host memory" versus "at 50%",
// produced the same digest, and an investigator reading the chain could not tell them apart.
//
// It walks BootLimits by reflection rather than listing fields, which is the part that makes
// it worth more than a regression test for the four: the next limit anyone adds fails here
// until they also add it to loadBootConfig's values map. Listing the eleven fields by hand
// would pass today and silently stop covering the twelfth.
func TestEverySealedLimitIsAttestedByTheDigest(t *testing.T) {
	harness.QuietConsole(t)

	// digestOf boots with one mutated field and returns the resulting digest.
	digestOf := func(mutate func(*kernel.BootLimits)) string {
		tr := harness.BootTrust()
		mutate(&tr.Limits)
		k, err := kernel.Boot(kernel.BootConfig{TrustRoot: tr})
		require.NoError(t, err)
		d := kernel.BootDigest()
		require.NoError(t, k.Shutdown())
		return d
	}

	base := digestOf(func(*kernel.BootLimits) {})
	require.Len(t, base, 64)

	// A probe value that differs from the default for every field kind present in
	// BootLimits. Picking per kind rather than per field is what lets this stay a
	// reflection walk: a new field of an existing kind is covered automatically, and a new
	// KIND fails the switch below rather than being silently skipped.
	fields := reflect.TypeOf(kernel.BootLimits{})
	for i := range fields.NumField() {
		f := fields.Field(i)
		name := f.Name

		t.Run(name, func(t *testing.T) {
			mutated := digestOf(func(l *kernel.BootLimits) {
				v := reflect.ValueOf(l).Elem().Field(i)
				switch f.Type.Kind() {
				case reflect.Int:
					v.SetInt(int64(i) + 7)
				case reflect.Int64:
					v.SetInt(int64(i)*1024 + 4096)
				default:
					t.Fatalf("BootLimits.%s has kind %s, which this test does not know how to "+
						"mutate; extend the switch rather than skipping the field, because a "+
						"skipped field is a sealed limit nobody attests",
						name, f.Type.Kind())
				}
			})

			assert.NotEqual(t, base, mutated,
				"changing BootLimits.%s must change the trust root digest, or a deployment "+
					"record cannot prove which value this kernel was sealed with", name)
		})
	}

	// The default itself must be reachable and stable, so the mutations above are compared
	// against something real rather than against an accident.
	assert.Equal(t, base, digestOf(func(*kernel.BootLimits) {}),
		"the same root hashes identically")
}

// TestSealedLimitsAreReadableByAModuleWithoutAGrant pins the fact that the confidentiality
// comment in bootconfig.go used to claim and no longer does: limits are not secret.
//
// A module needs to know its own quotas to avoid hitting them, so Limits() and
// SyscallBootLimits() are deliberately ungated. This matters for the digest test above,
// because it is what makes copying those same numbers into the digested map safe: it reveals
// nothing that was not already readable. If that ever changes - if limits become gated - the
// reasoning in bootconfig.go's comment has to be revisited, and this test is what notices.
func TestSealedLimitsAreReadableByAModuleWithoutAGrant(t *testing.T) {
	harness.QuietConsole(t)

	tr := harness.BootTrust()
	tr.Limits.MaxAccountedBytesPerModule = 1234
	tr.Limits.OomHostKillBP = 4321
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: tr})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	// A module holding nothing at all still reads the ceilings, which is the point: there is
	// no capability to grant because there is nothing to protect.
	probe := &harness.Probe{}
	harness.RegisterProbe(t, "limitreader", probe)
	pid, err := k.Load(kernel.Manifest{
		Name: "limitreader", Version: "1",
		MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()
	require.NotNil(t, probe.Ctx)
	// GrantsFor's bool reports whether a grant set is RECORDED for the pid, not whether it is
	// empty, so the assertion that matters is on the set itself. A loaded module always has a
	// recorded set; this one declares nothing, so it holds nothing.
	granted, recorded := kernel.GrantsFor(pid)
	require.True(t, recorded, "a loaded module has a recorded grant set")
	assert.Empty(t, granted, "and this one was granted nothing")

	assert.EqualValues(t, 1234, probe.Ctx.SyscallBootLimits().MaxAccountedBytesPerModule)
	assert.Equal(t, 4321, probe.Ctx.SyscallBootLimits().OomHostKillBP)

	// And the digested copies are readable through the same ungated surface, so putting them
	// in the map leaked nothing.
	got, ok := probe.Ctx.SyscallBootGet("limits.oom_host_kill_bp")
	require.True(t, ok, "the limit is in the digested map")
	assert.Equal(t, "4321", got)
	assert.Equal(t, kernel.BootDigest(), probe.Ctx.SyscallBootDigest())
}
