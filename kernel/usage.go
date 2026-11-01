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
	"fmt"
	"github.com/xingguangcuican6666/MeowAPI/abi"
	"sync"
)

// UsageKind is abi.UsageKind: a module has to be able to name these, so
// they live in the package it compiles against (see abi/abi.go). The kernel
// re-exports them so this file and a module spell them identically.
type UsageKind = abi.UsageKind

const (
	UsageTokensIn  = abi.UsageTokensIn
	UsageTokensOut = abi.UsageTokensOut
	UsageRequests  = abi.UsageRequests
)

// usageSpec bounds one kind. Ceiling is per event, not per module: a single
// fact claiming more than this is nonsense or an attack, and the kernel refuses
// it instead of recording it.
type usageSpec struct {
	ceiling int64
}

var usageSpecs = map[UsageKind]usageSpec{
	UsageTokensIn:  {ceiling: 1 << 40},
	UsageTokensOut: {ceiling: 1 << 40},
	UsageRequests:  {ceiling: 1 << 20},
}

// UsageKinds lists the kinds the kernel accepts, for manifests, docs and tests.
func UsageKinds() []UsageKind {
	return []UsageKind{UsageTokensIn, UsageTokensOut, UsageRequests}
}

// UsageFact is abi.UsageFact: a module passes it to or receives it from the
// kernel, so the shape lives in the package the module compiles against.
type UsageFact = abi.UsageFact

const maxUsageLabelLen = 128

// UsageError reports a rejected usage fact.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return "kernel: usage rejected: " + e.Msg }

// UsageCounters holds one module's usage totals.
type UsageCounters struct {
	Total  map[UsageKind]int64 `json:"total"`
	Events int64               `json:"events"`
}

var (
	usageMu sync.Mutex
	usage   = map[PID]*UsageCounters{}
	// usageRejected counts refused facts, so a module flooding the kernel with
	// invalid usage is visible even though each refusal is cheap.
	usageRejected int64
)

// emitUsage validates and records one fact against a context. It is reached
// only through SyscallUsageEmit, which has already enforced usage:emit.
func emitUsage(ctx *sContext, f UsageFact) error {
	reject := func(format string, a ...any) error {
		msg := fmt.Sprintf(format, a...)
		usageMu.Lock()
		usageRejected++
		usageMu.Unlock()
		fault(ctx, "usage fact rejected", map[string]any{
			"module": ctx.name, "kind": string(f.Kind), "quantity": f.Quantity, "reason": msg,
		})
		return &UsageError{Msg: msg}
	}

	spec, known := usageSpecs[f.Kind]
	if !known {
		return reject("unknown usage kind %q", f.Kind)
	}
	if f.Quantity < 0 {
		return reject("negative quantity %d for %s", f.Quantity, f.Kind)
	}
	if f.Quantity == 0 {
		// A zero fact carries no information and would let a module inflate its
		// event count without limit.
		return reject("zero quantity for %s is not recorded", f.Kind)
	}
	if f.Quantity > spec.ceiling {
		return reject("quantity %d exceeds the per-event ceiling %d for %s",
			f.Quantity, spec.ceiling, f.Kind)
	}
	if len(f.Label) > maxUsageLabelLen {
		return reject("label longer than %d bytes", maxUsageLabelLen)
	}

	usageMu.Lock()
	defer usageMu.Unlock()

	c := usage[ctx.pid]
	if c == nil {
		c = &UsageCounters{Total: map[UsageKind]int64{}}
		usage[ctx.pid] = c
	}

	prev := c.Total[f.Kind]
	next := prev + f.Quantity
	// Saturating here would silently corrupt an accounting total, which is
	// worse than refusing the event. Overflow means the module is emitting
	// absurd volume, so the fact is rejected and recorded as such.
	if next < prev {
		usageRejected++
		fault(ctx, "usage accumulation overflowed", map[string]any{
			"module": ctx.name, "kind": string(f.Kind), "total": prev,
		})
		return &UsageError{Msg: fmt.Sprintf("accumulating %d into %d overflows int64", f.Quantity, prev)}
	}

	c.Total[f.Kind] = next
	c.Events++
	return nil
}

// UsageSnapshot returns per-pid usage totals. The returned maps are copies, so a
// caller cannot mutate kernel accounting through them.
func UsageSnapshot() map[PID]UsageCounters {
	usageMu.Lock()
	defer usageMu.Unlock()
	out := make(map[PID]UsageCounters, len(usage))
	for pid, c := range usage {
		totals := make(map[UsageKind]int64, len(c.Total))
		for k, v := range c.Total {
			totals[k] = v
		}
		out[pid] = UsageCounters{Total: totals, Events: c.Events}
	}
	return out
}

// UsageRejected reports how many facts the kernel has refused.
func UsageRejected() int64 {
	usageMu.Lock()
	defer usageMu.Unlock()
	return usageRejected
}

// UsageTotal sums one kind across all modules. Useful for the console dump and
// for an operator's health view; a module that needs per-route accounting keeps
// its own books, because the kernel does not interpret labels.
func UsageTotal(kind UsageKind) int64 {
	usageMu.Lock()
	defer usageMu.Unlock()
	var sum int64
	for _, c := range usage {
		sum += c.Total[kind]
	}
	return sum
}

// resetUsage clears accounting. Called by Boot and Shutdown under the boot
// guard.
func resetUsage() {
	usageMu.Lock()
	defer usageMu.Unlock()
	usage = map[PID]*UsageCounters{}
	usageRejected = 0
}

// SyscallMeter is abi.SyscallMeter. The kernel keeps the alias
// so it can still write the concrete methods on its own context type.
type SyscallMeter = abi.SyscallMeter

func (c *sContext) SyscallUsageEmit(f UsageFact) error {
	if err := c.syscall(OpUsageEmit); err != nil {
		return err
	}
	return emitUsage(c, f)
}
