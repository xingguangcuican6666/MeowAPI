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

// Supervised-work accounting.

// CPUStat is one pid's accounting, as an operator or a module sees it.
type CPUStat struct {
	PID       PID   `json:"pid"`
	WallNanos int64 `json:"wall_nanos"`
	// CPUNanos is an estimate derived from wall time and observed concurrency, not
	// a hardware counter. It is labeled as an estimate in every surface that shows
	// it, because a number presented as precise will be trusted as precise.
	CPUNanos  int64 `json:"cpu_nanos_estimate"`
	Calls     int64 `json:"calls"`
	Budget    int64 `json:"budget_nanos"`
	Exhausted bool  `json:"exhausted"`
}
