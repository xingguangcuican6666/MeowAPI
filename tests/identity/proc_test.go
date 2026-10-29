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
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestProcessTableRecordsProvenance asserts the audit trail carries what an
// investigation needs: parentage, domain, uid allocation, artifact and digest.
func TestProcessTableRecordsProvenance(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

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
	harness.QuietConsole(t)
	k := harness.BootOne(t)

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
