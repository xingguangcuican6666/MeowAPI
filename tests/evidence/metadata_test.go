/*
Copyright (C) 2023-2026 xingguangcuican6666

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
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// TestMetadataIsScopedPerModule asserts the metadata store's two-tier model:
// kernel-published values are readable by any context holding metadata:read,
// while a context's own writes are private to it. This is stricter than the
// prototype, where a single global store was readable by every plugin, which
// made one plugin's state visible to all the others.
func TestMetadataIsScopedPerModule(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	reader := &harness.MetaReader{}
	kernel.Register("metareader", func() (kernel.Module, error) { return reader, nil })
	t.Cleanup(func() { kernel.Unregister("metareader") })

	// Published before the module loads, so its OnLoad can see it.
	k.Publish("kernel.boot.id", "test-boot")
	// A value owned by init, not published to modules.
	require.NoError(t, k.InitContext().SyscallMetadataSet("init.private", "secret"))

	pid, err := k.Load(kernel.Manifest{
		Name: "metareader", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpMetadataRead},
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	assert.Equal(t, "test-boot", reader.Published,
		"a kernel-published value must be readable under metadata:read")
	assert.Nil(t, reader.InitPrivate,
		"a module must not read metadata owned by another pid")
	assert.NoError(t, reader.Err)

	// The exported snapshot only ever exposes published entries, so a
	// diagnostic dump cannot leak a module's private state.
	snap := kernel.MetadataSnapshot()
	assert.Equal(t, "test-boot", snap["kernel.boot.id"])
	assert.NotContains(t, snap, "init.private")
}
