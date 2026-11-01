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

package abi

// Kernel time. Mono is the only value a module may measure with.

import (
	"time"
)

// KernelTime is what a module gets from SyscallNow. Mono is the value to compute
// with; Wall is the value to print.
type KernelTime struct {
	// Mono is nanoseconds on the kernel's monotonic clock. Non-negative,
	// non-decreasing, and not forgeable.
	Mono int64 `json:"mono"`
	// Wall is UTC wall-clock time, for records a human reads. Never use it to
	// measure an interval: it can step backwards.
	Wall time.Time `json:"wall"`
}
