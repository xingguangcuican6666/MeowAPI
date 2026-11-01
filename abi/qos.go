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

// One admission decision.

// QosDecision is the result of an admission attempt.
type QosDecision struct {
	// Admitted is whether the request may proceed.
	Admitted bool
	// RetryAfterMillis is how long the caller should wait before the bucket can
	// serve this request. Zero when admitted. It is computed from the deficit and
	// the refill rate, not guessed, so a client that honors it is not punished.
	RetryAfterMillis int64
	// Reason names the ceiling that refused, for logs and for the response body.
	Reason string
}
