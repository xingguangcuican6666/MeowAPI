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

// An immutable copy of a process table row.

import (
	"time"
)

// ProcSnapshot is an immutable copy of a process table row, safe to hand out.
// Callers get this rather than *ProcRecord so no one outside the table can
// mutate a live audit row.
type ProcSnapshot struct {
	PID            PID       `json:"pid"`
	UID            UID       `json:"uid"`
	Domain         Domain    `json:"domain"`
	Name           string    `json:"name"`
	PPID           PID       `json:"ppid"`
	Created        time.Time `json:"created"`
	Artifact       string    `json:"artifact,omitempty"`
	ManifestDigest string    `json:"manifest_digest,omitempty"`
	State          ProcState `json:"state"`
	Terminated     time.Time `json:"terminated,omitempty"`
}
