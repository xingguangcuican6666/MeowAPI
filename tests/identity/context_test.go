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
