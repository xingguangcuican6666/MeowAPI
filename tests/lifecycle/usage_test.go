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

package lifecycle

import (
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// TestUsageEmitAcceptsTokenCounts covers the kernel's half of the billing ABI:
// it counts quantities. Pricing is a module concern and appears nowhere here.
func TestUsageEmitAcceptsTokenCounts(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	harness.RegisterProbe(t, "billable", &harness.Probe{Load: func(ctx kernel.SContext) error {
		if err := ctx.SyscallUsageEmit(kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: 1200, Label: "gpt-x"}); err != nil {
			return err
		}
		if err := ctx.SyscallUsageEmit(kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: 300}); err != nil {
			return err
		}
		return ctx.SyscallUsageEmit(kernel.UsageFact{Kind: kernel.UsageTokensOut, Quantity: 77})
	}})

	pid, err := k.Load(kernel.Manifest{
		Name: "billable", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpUsageEmit},
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	snap := kernel.UsageSnapshot()
	require.Contains(t, snap, pid)
	assert.Equal(t, int64(1500), snap[pid].Total[kernel.UsageTokensIn])
	assert.Equal(t, int64(77), snap[pid].Total[kernel.UsageTokensOut])
	assert.Equal(t, int64(3), snap[pid].Events)
	assert.Equal(t, int64(1500), kernel.UsageTotal(kernel.UsageTokensIn))
	assert.Zero(t, kernel.UsageRejected())
}

// TestUsageEmitRejections covers the boundary the upstream project left open.
// Each case must be refused and counted, not accumulated.
func TestUsageEmitRejections(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	cases := []struct {
		name string
		fact kernel.UsageFact
		want string
	}{
		{"unknown kind", kernel.UsageFact{Kind: "tokens:free", Quantity: 1}, "unknown usage kind"},
		{"empty kind", kernel.UsageFact{Quantity: 1}, "unknown usage kind"},
		{"negative", kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: -1}, "negative quantity"},
		{"zero", kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: 0}, "zero quantity"},
		{"above ceiling", kernel.UsageFact{Kind: kernel.UsageRequests, Quantity: 1 << 21}, "exceeds the per-event ceiling"},
		{"label too long", kernel.UsageFact{
			Kind: kernel.UsageTokensIn, Quantity: 1, Label: strings.Repeat("x", 129),
		}, "label longer than"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fact := c.fact
			harness.RegisterProbe(t, "rejector", &harness.Probe{Load: func(ctx kernel.SContext) error {
				usageErr = ctx.SyscallUsageEmit(fact)
				return nil
			}})

			pid, err := k.Load(kernel.Manifest{
				Name: "rejector", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
				Require: []kernel.Op{kernel.OpUsageEmit},
			})
			require.NoError(t, err)
			defer func() { _ = k.Unload(pid) }()

			require.Error(t, usageErr)
			var ue *kernel.UsageError
			require.ErrorAs(t, usageErr, &ue, "rejections must be typed UsageError, got %T", usageErr)
			assert.Contains(t, usageErr.Error(), c.want)
			assert.Empty(t, kernel.UsageSnapshot()[pid],
				"a rejected fact must not be recorded")
		})
	}

	assert.Equal(t, int64(len(cases)), kernel.UsageRejected(),
		"every rejection must be counted")
}

var usageErr error

// TestUsageRequiresGrant asserts usage:emit is policy-checked like any other
// operation: a module that did not declare it cannot report billing facts.
func TestUsageRequiresGrant(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	harness.RegisterProbe(t, "nogrant", &harness.Probe{Load: func(ctx kernel.SContext) error {
		usageErr = ctx.SyscallUsageEmit(kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: 10})
		return nil
	}})

	pid, err := k.Load(kernel.Manifest{
		Name: "nogrant", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, usageErr)
	assert.True(t, kernel.IsDenied(usageErr))
	assert.Contains(t, usageErr.Error(), "usage:emit")
	assert.Empty(t, kernel.UsageSnapshot())
}

// TestUsageSnapshotIsACopy proves accounting cannot be mutated from outside the
// kernel through the snapshot a caller is handed.
func TestUsageSnapshotIsACopy(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	harness.RegisterProbe(t, "counter", &harness.Probe{Load: func(ctx kernel.SContext) error {
		return ctx.SyscallUsageEmit(kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: 5})
	}})
	pid, err := k.Load(kernel.Manifest{
		Name: "counter", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpUsageEmit},
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	snap := kernel.UsageSnapshot()
	snap[pid].Total[kernel.UsageTokensIn] = 999999
	delete(snap, pid)

	assert.Equal(t, int64(5), kernel.UsageTotal(kernel.UsageTokensIn),
		"mutating the snapshot must not change kernel accounting")
}

// TestUsageIsScopedPerModule asserts one module's usage cannot be attributed to
// another: totals are keyed by pid, and the pid is the kernel's, not a parameter.
func TestUsageIsScopedPerModule(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	for _, name := range []string{"ua", "ub"} {
		n := name
		harness.RegisterProbe(t, n, &harness.Probe{Load: func(ctx kernel.SContext) error {
			return ctx.SyscallUsageEmit(kernel.UsageFact{Kind: kernel.UsageTokensOut, Quantity: 10})
		}})
	}

	pidA, err := k.Load(kernel.Manifest{Name: "ua", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpUsageEmit}})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pidA) }()

	pidB, err := k.Load(kernel.Manifest{Name: "ub", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpUsageEmit}})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pidB) }()

	snap := kernel.UsageSnapshot()
	assert.Equal(t, int64(10), snap[pidA].Total[kernel.UsageTokensOut])
	assert.Equal(t, int64(10), snap[pidB].Total[kernel.UsageTokensOut])
	assert.Equal(t, int64(20), kernel.UsageTotal(kernel.UsageTokensOut))
}
