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

// The audit record a module reads back, and the filter it selects with.

// AuditEntry is one link in the audit chain.
//
// The chain is the tamper-evidence mechanism. Each entry carries Prev, the hash
// of the entry before it, and Hash, the hash of itself including Prev. Rewriting
// or deleting any entry invalidates every hash after it, so an edit is detectable
// rather than invisible. This is what makes the record evidence instead of a log:
// a log can be edited, a chain cannot be edited without being noticed.
type AuditEntry struct {
	Seq    int64          `json:"seq"`
	Time   int64          `json:"time"`
	Kind   AuditKind      `json:"kind"`
	PID    PID            `json:"pid"`
	Domain Domain         `json:"domain,omitempty"`
	Msg    string         `json:"msg"`
	Trace  string         `json:"trace,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
	Prev   string         `json:"prev"`
	Hash   string         `json:"hash"`
}

// AuditFilter selects entries. Zero values mean "no constraint on this field".
type AuditFilter struct {
	Kind  AuditKind
	PID   PID
	Trace string
	Since int64
	Limit int
}
