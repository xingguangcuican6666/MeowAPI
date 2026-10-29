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

package evidence

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xingguangcuican6666/MeowAPI/tests/harness"

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

// TestDumpRendersEverySectionItDeclares pins the operator-facing section list.
//
// The list is written out here rather than read from dump.go, and that choice is the
// whole test. Deriving the expectation from the source would make the two agree by
// construction: delete a section from dump.go and the expectation shrinks with it, so
// the test stays green while the dump silently loses a subsystem. Verified that way,
// this test passes with the token accounting section removed.
//
// What an operator can see in a dump is a contract, so adding a subsystem without
// adding its section should fail here and make that a deliberate act. The reverse -
// a section rendering nothing - is caught by asserting the header appears in the
// output, and a section that panics fails the whole test.
func TestDumpRendersEverySectionItDeclares(t *testing.T) {
	harness.QuietConsole(t)
	harness.BootOne(t)

	// One entry per subsystem the kernel has state worth rendering. Sections whose
	// data is empty still render their header, because an operator reading a dump
	// cannot otherwise tell "empty" from "not implemented".
	sections := []string{
		"process table",
		"loaded modules",
		"usage",
		"policy",
		"admission",
		"cpu accounting",
		"channels",
		"routes",
		"memory pressure",
		"instance filters",
		"egress",
		"peers",
		"slashing",
		"shared memory",
		"tracing",
		"metering",
		"token accounting",
		"secrets",
		"receipts",
		"console",
		"supervision",
		"handles",
	}

	var out bytes.Buffer
	require.NoError(t, kernel.Dump(&out))
	text := out.String()

	for _, s := range sections {
		assert.Contains(t, text, "--- "+s,
			"the dump must render a %q section; an operator cannot otherwise see that state", s)
	}

	// The faults header carries a count, so it is matched separately.
	assert.Regexp(t, `--- faults \(\d+\) ---`, text)

	// And the sections appear in the order dump.go writes them, because a dump is read
	// top to bottom and a reordering that moved faults above the process table would
	// make the first thing an operator reads the least informative part.
	prev := -1
	for _, s := range sections {
		at := strings.Index(text, "--- "+s)
		require.NotEqual(t, -1, at, "%q is missing", s)
		assert.Greater(t, at, prev, "%q appears out of order", s)
		prev = at
	}
}
