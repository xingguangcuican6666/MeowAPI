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

// The bounded usage fact a module emits.

// UsageFact is one usage event reported by a module.
type UsageFact struct {
	Kind     UsageKind `json:"kind"`
	Quantity int64     `json:"quantity"`
	// Label is an optional module-defined tag for the event, such as a model
	// name or a route. It is recorded for debugging and is never interpreted by
	// the kernel. Bounded so a module cannot use it to grow kernel memory.
	Label string `json:"label,omitempty"`
}
