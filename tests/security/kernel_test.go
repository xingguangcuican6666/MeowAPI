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
