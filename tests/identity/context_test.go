package identity

import (
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// TestDomainTransitionToKernelIsRefused asserts the privilege-escalation
// boundary: no context, at any domain, can spawn into u:r:kernel:s0.
func TestDomainTransitionToKernelIsRefused(t *testing.T) {
	harness.QuietConsole(t)

	k := harness.BootOne(t)
	ctx := k.InitContext()

	child, err := ctx.SyscallSpawn(kernel.DomainKernel, "escalate")
	require.Error(t, err, "spawning into the kernel domain must be refused")
	require.Nil(t, child)
	assert.True(t, kernel.IsDenied(err), "the refusal must be a policy denial, got %T: %v", err, err)
}

// TestContextExposesName asserts the diagnostic label a module can read about
// itself is the kernel's, not one the module chose.
func TestContextExposesName(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	assert.Equal(t, "init", k.InitContext().Name())

	harness.RegisterProbe(t, "named", &harness.Probe{Load: func(ctx kernel.SContext) error {
		nameResult = ctx.Name()
		return nil
	}})
	pid, err := k.Load(kernel.Manifest{
		Name: "named", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	assert.Equal(t, "named", nameResult)
}

var nameResult string
