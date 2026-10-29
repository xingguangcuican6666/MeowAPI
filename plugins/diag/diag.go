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

// Package diag is the reference plugin: the smallest module that exercises the
// kernel contract end to end. It reads kernel-published metadata, writes its
// own, logs through the kernel console, and tears down cleanly.
//
// It exists to prove the plugin path works and to show a secondary author what
// a conforming module looks like. It is not a shipping feature.
package diag

import (
	"errors"
	"fmt"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

func init() {
	kernel.Register("diag", func() (kernel.Module, error) { return &diag{}, nil })
}

type diag struct {
	pid kernel.PID
}

func (d *diag) OnLoad(ctx kernel.SContext) error {
	d.pid = ctx.PID()

	// A plugin holds metadata:read but not metadata:write, so this write is a
	// denial. It is expected and demonstrates the policy, so the error is
	// logged rather than returned.
	if err := ctx.SyscallMetadataSet("diag.loaded", true); err != nil {
		if !kernel.IsDenied(err) {
			return err
		}
		_ = ctx.SyscallLog(kernel.LogDebug, fmt.Sprintf("metadata:write correctly denied: %v", err))
	}

	// Reading kernel-published metadata is allowed under metadata:read.
	if v, err := ctx.SyscallMetadataGet("kernel.boot.id"); err == nil && v != nil {
		_ = ctx.SyscallLog(kernel.LogInfo, fmt.Sprintf("boot id = %v", v))
	}

	// Report token counts. The kernel counts quantities and never prices them,
	// so this is the whole of the billing ABI from a module's side: declare a
	// kind the kernel knows, declare a quantity, and let a billing module read
	// the totals out of the snapshot.
	if err := ctx.SyscallUsageEmit(kernel.UsageFact{
		Kind: kernel.UsageTokensIn, Quantity: 128, Label: "diag:probe",
	}); err != nil {
		return err
	}
	if err := ctx.SyscallUsageEmit(kernel.UsageFact{
		Kind: kernel.UsageTokensOut, Quantity: 32, Label: "diag:probe",
	}); err != nil {
		return err
	}

	// An unknown kind is refused rather than accumulated, which is the point:
	// there is no default branch for a module to fall through into billing.
	if err := ctx.SyscallUsageEmit(kernel.UsageFact{
		Kind: kernel.UsageKind("tokens:free"), Quantity: 1,
	}); err == nil {
		return errors.New("expected the kernel to refuse an unknown usage kind")
	} else {
		_ = ctx.SyscallLog(kernel.LogDebug, fmt.Sprintf("unknown usage kind correctly refused: %v", err))
	}

	// A plugin may emit debug/info/warn/error but not fault; the kernel
	// rejects a fault-level log from an unprivileged domain.
	if err := ctx.SyscallLog(kernel.LogInfo, "diag plugin loaded"); err != nil {
		return err
	}
	return nil
}

func (d *diag) OnUnload() error {
	return nil
}

// Manifest is the declaration the kernel validates before this module runs. It
// requests only metadata:read, log:write and usage:emit - everything the plugin
// domain can hold - and no scoped capability, so it gets no network, no
// filesystem and no secrets.
func Manifest() kernel.Manifest {
	return kernel.Manifest{
		Name:         "diag",
		Version:      "0.1.0",
		MinKernelAPI: 1,
		MaxKernelAPI: 1,
		Require:      []kernel.Op{kernel.OpMetadataRead, kernel.OpLogWrite, kernel.OpUsageEmit},
	}
}
