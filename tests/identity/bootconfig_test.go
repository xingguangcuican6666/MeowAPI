package identity

import (
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"testing"

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
