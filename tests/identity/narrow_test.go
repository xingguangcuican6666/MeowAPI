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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// TestNarrowingRefusesOnTheNextCall is the property the whole knarrow design exists
// for: a withdrawal takes effect against a module that is ALREADY loaded, on its next
// syscall, with no reload.
//
// The assertion is on runtime behavior rather than on the table, because a narrowing
// the checks do not consult would pass a table-shaped test and refuse nothing. The
// module below holds log:write, calls it once to prove the grant, has it withdrawn,
// and must then be refused.
func TestNarrowingRefusesOnTheNextCall(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	probe := &harness.Probe{}
	harness.RegisterProbe(t, "narrow-probe", probe)
	pid, err := k.Load(kernel.Manifest{
		Name: "narrow-probe", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.NoError(t, err)
	require.NotZero(t, pid)
	ctx := probe.Ctx

	require.NoError(t, ctx.SyscallLog(kernel.LogInfo, "before the narrowing"),
		"the probe holds log:write before anything is withdrawn")

	require.NoError(t, k.NarrowPolicy(kernel.DomainPlugin, []kernel.Op{kernel.OpLogWrite}))

	err = ctx.SyscallLog(kernel.LogInfo, "after the narrowing")
	require.Error(t, err, "a withdrawn operation must be refused on the next call")
	assert.True(t, kernel.IsDenied(err), "and the refusal is a policy denial, not a generic error")

	// The narrowing is per DOMAIN and not per pid, which is what makes it a posture
	// rather than a per-module tweak: the ceiling query every caller uses reports it.
	assert.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpLogWrite),
		"the ceiling itself reports the withdrawal, which is what every caller consults")
}

// TestNarrowingIsMonotonic pins that there is no way back. Every attempt to widen -
// naming an operation the domain does not hold, naming the kernel domain, naming an
// empty batch - must be refused, and the refusals must leave the posture unchanged
// rather than half-applied.
func TestNarrowingIsMonotonic(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	require.NoError(t, k.NarrowPolicy(kernel.DomainPlugin, []kernel.Op{kernel.OpLogWrite}))
	require.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpLogWrite))

	cases := []struct {
		name string
		dom  kernel.Domain
		ops  []kernel.Op
	}{
		{"empty batch", kernel.DomainPlugin, nil},
		{"the kernel domain", kernel.DomainKernel, []kernel.Op{kernel.OpModuleLoad}},
		{"the untrusted domain", kernel.DomainUntrusted, []kernel.Op{kernel.OpLogWrite}},
		{"an operation the domain never held", kernel.DomainPlugin, []kernel.Op{kernel.OpModuleLoad}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Error(t, k.NarrowPolicy(c.dom, c.ops),
				"the call must be refused, or monotonicity is a convention rather than a property")
		})
	}

	// The refusals changed nothing: what was withdrawn stays withdrawn, and what was
	// not never became withdrawn.
	assert.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpLogWrite),
		"a refused call must not have re-granted anything")
	assert.True(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpMetadataRead),
		"an out-of-batch operation on the domain is untouched")
	assert.True(t, kernel.Allowed(kernel.DomainKernel, kernel.OpModuleLoad),
		"a refused narrowing of the kernel domain left its ceiling alone")
}

// TestNarrowingIsAllOrNothing pins the batch rule: one bad name means none of the good
// ones land. A partially applied narrowing is a posture nobody can describe, and the
// next operator to read it would have to reconstruct which half took effect.
func TestNarrowingIsAllOrNothing(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	err := k.NarrowPolicy(kernel.DomainPlugin, []kernel.Op{
		kernel.OpLogWrite,
		kernel.OpModuleLoad, // never held by the plugin domain
	})
	require.Error(t, err)
	assert.True(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpLogWrite),
		"the good name in a rejected batch must NOT have been applied")
}

// TestNarrowingIsIdempotent pins that running the same command twice is success rather
// than a failure: the posture asked for is the one in force, and an operator
// re-running a reload script should not see an error for it.
func TestNarrowingIsIdempotent(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	require.NoError(t, k.NarrowPolicy(kernel.DomainPlugin, []kernel.Op{kernel.OpLogWrite}))
	require.NoError(t, k.NarrowPolicy(kernel.DomainPlugin, []kernel.Op{kernel.OpLogWrite}),
		"a second withdrawal of the same operation is not an error")
	assert.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpLogWrite))

	// And the record says it once, not twice: the audit entry is written only for what
	// was actually added, so a re-run does not inflate the chain.
	withdrawn := kernel.PolicyNarrowing()[kernel.DomainPlugin]
	require.Len(t, withdrawn, 1)
	assert.Equal(t, kernel.OpLogWrite, withdrawn[0])
}

// TestNarrowingClearsOnShutdown pins the per-boot rule. A narrowing that survived a
// restart would be a decision nobody could see they had made.
func TestNarrowingClearsOnShutdown(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	require.NoError(t, k.NarrowPolicy(kernel.DomainPlugin, []kernel.Op{kernel.OpLogWrite}))
	require.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpLogWrite))

	require.NoError(t, k.Shutdown())

	assert.True(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpLogWrite),
		"the ceiling is the compiled table again after a shutdown")
	assert.Empty(t, kernel.PolicyNarrowing()[kernel.DomainPlugin],
		"and nothing is recorded as withdrawn")
}

// TestNarrowingSnapshotIsACopy pins that the reader cannot reach the live map. A
// caller that appended to the returned slice would otherwise be editing policy.
func TestNarrowingSnapshotIsACopy(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	require.NoError(t, k.NarrowPolicy(kernel.DomainPlugin, []kernel.Op{kernel.OpLogWrite}))
	// The operation appended is one the plugin domain DOES hold, because an operation
	// it never held would read as withdrawn for a reason that has nothing to do with
	// this bug - measured, that is what the first version of this assertion did.
	snap := kernel.PolicyNarrowing()
	snap[kernel.DomainPlugin] = append(snap[kernel.DomainPlugin], kernel.OpMetadataRead)

	assert.True(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpMetadataRead),
		"editing the returned slice changed the live policy")
	assert.Equal(t, []kernel.Op{kernel.OpLogWrite}, kernel.PolicyNarrowing()[kernel.DomainPlugin])
}

// TestNarrowingIsVisibleInTheOpsList pins that the view an operator reads agrees with
// the check the kernel makes.
//
// This is the defect the first version shipped: OpsFor read the compiled table
// directly, so after a narrowing `policy` printed log:write both as held and as
// withdrawn. A reader of that output concludes the withdrawal did nothing - the
// opposite of what the syscall actually does - and a policy view that disagrees with
// enforcement is worse than none.
func TestNarrowingIsVisibleInTheOpsList(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	require.Contains(t, kernel.OpsFor(kernel.DomainPlugin), kernel.OpLogWrite)
	withdrawn := kernel.OpLogWrite

	require.NoError(t, k.NarrowPolicy(kernel.DomainPlugin, []kernel.Op{withdrawn}))

	held := kernel.OpsFor(kernel.DomainPlugin)
	assert.NotContains(t, held, withdrawn,
		"the held list still names an operation the kernel refuses")
	assert.False(t, kernel.Allowed(kernel.DomainPlugin, withdrawn),
		"and the check agrees with the list, which is the property that matters")
	assert.True(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpMetadataRead),
		"a withdrawal removed exactly one operation and not the domain")

	// The withdrawal is per domain: init still holds what it held.
	assert.Contains(t, kernel.OpsFor(kernel.DomainInit), kernel.OpModuleLoad,
		"narrowing the plugin domain changed init's list")
}
