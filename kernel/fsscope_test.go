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

package kernel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are in package kernel because fsScopes has no exported reader, on
// purpose: a module must not be able to enumerate the boundaries it is held to. The
// probe in export_test.go is the only route, which is the same reason
// nilcontext_test.go lives here.
//
// What they cover is the delete path, which had no test at all. Removing
// ClearFSScope from UnloadModule left all 23 packages green, and the reason is worth
// stating: LoadModule calls SetFSScope unconditionally, so a stale scope is
// unreachable through the fs checks themselves - a loaded pid has its scope
// overwritten from its own manifest before any boundary is consulted. What remains
// observable, and what these assert, is residency.

// TestClearFSScopeDropsTheEntry pins the delete itself, without a boot.
func TestClearFSScopeDropsTheEntry(t *testing.T) {
	SetFSScope(4242, []string{"read-a", "read-b"}, []string{"write-a"})
	read, write := ProbeFSScopeFor(4242)
	require.Equal(t, []string{"read-a", "read-b"}, read)
	require.Equal(t, []string{"write-a"}, write)

	ClearFSScope(4242)
	read, write = ProbeFSScopeFor(4242)
	assert.Empty(t, read, "the read boundary goes with the pid")
	assert.Empty(t, write, "and so does the write boundary")
}

// TestClearFSScopeIsIdempotent pins that a second clear is a no-op rather than a
// panic or a resurrected entry. The unload path may run more than once for a pid that
// was already terminated, so this is a call shape that really occurs.
func TestClearFSScopeIsIdempotent(t *testing.T) {
	SetFSScope(4243, []string{"x"}, nil)
	ClearFSScope(4243)
	assert.NotPanics(t, func() { ClearFSScope(4243) }, "a repeat clear must be harmless")
	read, _ := ProbeFSScopeFor(4243)
	assert.Empty(t, read)
}

// TestUnloadDropsTheFSScope is the wiring half: the delete must be reached by a real
// unload, not only by a direct call. It asserts the scope is installed by the loader
// and gone after Unload, which is the two-line contract UnloadModule has carried in a
// comment since kv.go was written.
func TestUnloadDropsTheFSScope(t *testing.T) {
	k, err := Boot(BootConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	const name = "fsscope-probe"
	Register(name, func() (Module, error) { return &fsscopeProbe{}, nil })
	t.Cleanup(func() { Unregister(name) })

	pid, err := k.Load(Manifest{
		Name: name, Version: "1",
		MinKernelAPI: KernelAPI, MaxKernelAPI: KernelAPI,
		Require:   []Op{OpFSRead},
		ReadPaths: []string{"cache"},
	})
	require.NoError(t, err)

	read, _ := ProbeFSScopeFor(pid)
	require.Equal(t, []string{"cache"}, read, "the loader installs the declared boundary")

	require.NoError(t, k.Unload(pid))
	read, write := ProbeFSScopeFor(pid)
	assert.Empty(t, read, "unload must drop the read boundary, or nothing frees it but a shutdown")
	assert.Empty(t, write)
}

// fsscopeProbe is a module that does nothing: these tests are about what the loader
// and the unloader do around it.
type fsscopeProbe struct{}

func (*fsscopeProbe) OnLoad(SContext) error { return nil }
func (*fsscopeProbe) OnUnload() error       { return nil }
