package evidence

import (
	"bytes"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestDumpIsReadOnlyAndComplete asserts the debug dump answers the three
// questions an operator asks: what is loaded, under which grants, what was
// denied.
func TestDumpIsReadOnlyAndComplete(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)

	// Manufacture a denial so the fault section is non-empty.
	probe := &harness.Probe{}
	probe.Load = func(ctx kernel.SContext) error {
		_, derr := ctx.SyscallMetadataGet("x")
		_ = derr
		return nil
	}
	harness.RegisterProbe(t, "dumper", probe)
	pid2, err := k.Load(kernel.Manifest{
		Name: "dumper", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, kernel.Dump(&out))
	text := out.String()

	assert.Contains(t, text, "=== MeowAPI kernel ===")
	assert.Contains(t, text, "--- process table ---")
	assert.Contains(t, text, "u:r:init:s0")
	assert.Contains(t, text, "--- loaded modules ---")
	assert.Contains(t, text, "diag")
	assert.Contains(t, text, "dumper")
	assert.Contains(t, text, "effective: (none)", "a module declaring nothing must show an empty effective set")
	assert.Contains(t, text, "--- policy ---")
	assert.Regexp(t, `u:r:untrusted:s0\s+\(none\)`, text)
	assert.Contains(t, text, "--- usage ---")
	assert.Contains(t, text, "--- faults")
	assert.Contains(t, text, "avc: denied")

	// The dump must not have changed anything.
	require.Len(t, kernel.LoadedModules(), 2)
	require.NoError(t, k.Unload(pid))
	require.NoError(t, k.Unload(pid2))

	assert.Error(t, kernel.Dump(nil), "a nil writer is a caller error")
}
