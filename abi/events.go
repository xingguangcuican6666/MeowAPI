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

// A posted kernel event and a subscription read.

// Event is one delivered notification.
type Event struct {
	// Name is from the closed kernel set.
	Name KernelEventName `json:"name"`
	// Seq is monotonic within one subscription, so a consumer can detect a gap and
	// know it missed something rather than assuming nothing happened.
	Seq int64 `json:"seq"`
	// At is the Mono() reading when the event was posted.
	At int64 `json:"at"`
	// Subject is the pid the event is about: the peer that disconnected, the job
	// that finished. Zero when the event is about the subscriber itself.
	Subject PID `json:"subject,omitempty"`
	// Detail carries a small kernel-chosen string, for example a pipe name. It is
	// never module-supplied content, so it cannot be used to smuggle a payload
	// through the event path.
	Detail string `json:"detail,omitempty"`
}
