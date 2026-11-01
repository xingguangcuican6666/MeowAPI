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

// The operator console: a bounded window of what the kernel has said.

// TTYWindow is one bounded read of console history.
//
// Base and Dropped exist because `since` cannot be a stable cursor. Console retention is
// bounded and drops the oldest record, so an index into history shifts whenever the
// buffer trims. A caller that treated `since` as "resume from line N" would silently skip
// or repeat lines after a trim and never know. Base is the index the first returned
// record occupied, and Dropped is the console's total eviction count, so a caller can
// detect that records were lost between two reads rather than assuming continuity it does
// not have.
type TTYWindow struct {
	// Base is the index into the console's history at the time of this read that the
	// first record in Records occupied.
	Base int `json:"base"`
	// Records are copies of the console lines, oldest first.
	Records []Record `json:"records"`
	// Dropped is how many console records have been evicted in total.
	Dropped int64 `json:"dropped"`
}
