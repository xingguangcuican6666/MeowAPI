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

// The kernel console record: one line, always one JSON object.

import (
	"time"
)

// Record is one kernel console line. It is always emitted as a single JSON
// object so that faults stay greppable and machine-readable.
type Record struct {
	Time time.Time `json:"time"`
	// Mono is nanoseconds on the kernel's monotonic clock, counted from process start.
	// It is what a terminal-style rendering prefixes a line with, in place of the wall
	// clock: the monotonic clock is not rewindable and not forgeable by a module, while
	// a wall timestamp is the one field an operator cannot trust for ordering - and
	// "which of these happened first" is the question a log exists to answer.
	// Zero on a record constructed without it, and renderers must handle that.
	Mono   int64          `json:"mono,omitempty"`
	Level  Level          `json:"level"`
	Pid    PID            `json:"pid"`
	Domain Domain         `json:"domain,omitempty"`
	Msg    string         `json:"msg"`
	Fields map[string]any `json:"fields,omitempty"`
}
