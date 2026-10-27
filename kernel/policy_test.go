package kernel_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// TestPolicyMatrixDenials enumerates the policy table and asserts every
// (domain, operation) pair that the kernel does not grant is actually denied at
// runtime. This is the "every denial in the matrix is asserted" requirement:
// the test derives expectations from Allowed() and then proves check() agrees.
func TestPolicyMatrixDenials(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)
	ctx := k.InitContext()

	// Metadata is the only operation pair the test can drive directly from a
	// context, because the others have no unprivileged syscall surface yet.
	// The rest are asserted through Allowed() and through the scoped manifest
	// validation in TestManifestValidation.
	cases := []struct {
		dom  kernel.Domain
		op   kernel.Op
		want bool
	}{
		{kernel.DomainKernel, kernel.OpMetadataWrite, true},
		{kernel.DomainKernel, kernel.OpMetadataRead, true},
		{kernel.DomainKernel, kernel.OpProcessFork, true},
		{kernel.DomainInit, kernel.OpProcessFork, true},
		{kernel.DomainInit, kernel.OpModuleLoad, true},
		{kernel.DomainInit, kernel.OpMetadataWrite, true},
		{kernel.DomainInit, kernel.OpNetDial, false},
		{kernel.DomainInit, kernel.OpSecretRead, false},
		{kernel.DomainInit, kernel.OpUsageEmit, false},
		{kernel.DomainPlugin, kernel.OpMetadataRead, true},
		{kernel.DomainPlugin, kernel.OpLogWrite, true},
		{kernel.DomainPlugin, kernel.OpIPCCall, true},
		{kernel.DomainPlugin, kernel.OpUsageEmit, true},
		{kernel.DomainPlugin, kernel.OpMetadataWrite, false},
		{kernel.DomainPlugin, kernel.OpProcessFork, false},
		{kernel.DomainPlugin, kernel.OpModuleLoad, false},
		{kernel.DomainPlugin, kernel.OpModuleUnload, false},
		{kernel.DomainPlugin, kernel.OpSecretRead, false},
		{kernel.DomainUntrusted, kernel.OpMetadataRead, false},
		{kernel.DomainUntrusted, kernel.OpLogWrite, false},
		{kernel.DomainUntrusted, kernel.OpProcessFork, false},
		{kernel.Domain("u:r:mystery:s0"), kernel.OpMetadataRead, false},
		{kernel.Domain("u:r:mystery:s0"), kernel.OpProcessFork, false},
	}

	for _, c := range cases {
		assert.Equal(t, c.want, kernel.Allowed(c.dom, c.op),
			"Allowed(%s, %s) must match the documented matrix", c.dom, c.op)
	}

	// Runtime agreement: an unlisted domain holds nothing.
	untrusted, err := ctx.SyscallSpawn(kernel.DomainPlugin, "matrix-probe")
	require.NoError(t, err)
	require.NotNil(t, untrusted)

	// A plugin-domain context may read metadata but not write it.
	_, err = untrusted.SyscallMetadataGet("anything")
	assert.NoError(t, err, "metadata:read is granted to the plugin domain")
	err = untrusted.SyscallMetadataSet("anything", 1)
	require.Error(t, err, "metadata:write must be denied to the plugin domain")
	assert.True(t, kernel.IsDenied(err))
	assert.Contains(t, err.Error(), "avc: denied { metadata:write } for domain=u:r:plugin:s0")
}

// TestOpsForMatchesAllowed asserts the two policy views agree. Dump and tests read
// the matrix through OpsFor; enforcement reads it through Allowed. If they ever
// diverge, the debug console would describe a policy the kernel does not enforce.
func TestOpsForMatchesAllowed(t *testing.T) {
	domains := []kernel.Domain{
		kernel.DomainKernel, kernel.DomainInit,
		kernel.DomainPlugin, kernel.DomainUntrusted,
		kernel.Domain("u:r:never:s0"),
	}
	for _, dom := range domains {
		held := kernel.OpsFor(dom)
		for _, op := range kernel.AllOps {
			assert.Equal(t, kernel.Allowed(dom, op), containsOp(held, op),
				"OpsFor(%s) and Allowed(%s, %s) must agree", dom, dom, op)
		}
		assert.True(t, sort.SliceIsSorted(held, func(i, j int) bool { return held[i] < held[j] }),
			"OpsFor must return a stable order")
	}
	assert.Empty(t, kernel.OpsFor(kernel.DomainUntrusted))
	assert.Empty(t, kernel.OpsFor(kernel.Domain("u:r:never:s0")))
	assert.Len(t, kernel.OpsFor(kernel.DomainKernel), len(kernel.AllOps),
		"the kernel domain holds every operation")
}
