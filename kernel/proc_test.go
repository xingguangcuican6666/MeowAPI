package kernel_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestProcessTableRecordsProvenance asserts the audit trail carries what an
// investigation needs: parentage, domain, uid allocation, artifact and digest.
func TestProcessTableRecordsProvenance(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	var rec *kernel.ProcSnapshot
	tbl := kernel.ProcTable()
	for i := range tbl {
		if tbl[i].PID == pid {
			rec = &tbl[i]
		}
	}
	require.NotNil(t, rec)

	assert.Equal(t, kernel.DomainPlugin, rec.Domain)
	assert.Equal(t, kernel.PID(1), rec.PPID, "a module is spawned by init")
	assert.Equal(t, "diag", rec.Name)
	assert.Equal(t, "diag", rec.Artifact)
	assert.Len(t, rec.ManifestDigest, 64)
	assert.Equal(t, kernel.ProcRunning, rec.State)
	assert.GreaterOrEqual(t, int(rec.UID), 1000, "plugin uids come from the kernel's own counter")
	assert.False(t, rec.Created.IsZero())
}

// TestPIDsAreNeverReused proves the audit log cannot be confused: after an
// unload, the next load gets a new pid rather than recycling the old one.
func TestPIDsAreNeverReused(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid1, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid1))

	pid2, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid2) }()

	assert.Greater(t, int(pid2), int(pid1), "pids increase monotonically and are never reused")

	// Both records exist in the table: one terminated, one running.
	var terminated, running int
	for _, r := range kernel.ProcTable() {
		switch r.State {
		case kernel.ProcTerminated:
			terminated++
		case kernel.ProcRunning:
			running++
		}
	}
	assert.GreaterOrEqual(t, terminated, 1)
	assert.GreaterOrEqual(t, running, 3, "pid 0, init and the live module")
}
