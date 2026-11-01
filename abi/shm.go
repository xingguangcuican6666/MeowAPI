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

// Shared segments and their descriptors.

// ShmDescriptor describes an allocated segment to its owner. It carries no slice:
// the owner writes through ShmWrite and reads back through ShmRead.
type ShmDescriptor struct {
	// FD is the handle in the owner's own table. It is a capability: it resolves
	// only in that table, so it cannot be passed to another module to use.
	FD FD `json:"fd"`
	// ID names the segment kernel-wide. It is what a peer passes to ShmMap, and it
	// is not a capability on its own: the map still checks the owner's grant set.
	ID SHMID `json:"id"`
	// Size is the payload length the caller asked for, which may be smaller than
	// the slab class the pool reserved.
	Size int `json:"size"`
}

// ShmMapping describes a read-only mapping to the module that holds it.
type ShmMapping struct {
	// FD is the handle in the reader's own table.
	FD FD `json:"fd"`
	// ID is the segment the grant covered.
	ID SHMID `json:"id"`
	// Size is the payload length, so the reader can allocate a buffer before
	// copying without a second syscall.
	Size int `json:"size"`
	// Owner is the pid that allocated the segment. It is a diagnostic: knowing
	// who to blame for a payload is not a capability to read it.
	Owner PID `json:"owner"`
}
