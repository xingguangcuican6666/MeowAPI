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

// Reload, drain, kill: what is sent, what is handled, what a full queue refuses.

import (
	"fmt"
)

// SignalHandler is a module's own response to a signal. It runs supervised: under
// the module's context, inside the sealed call ceiling, with panics recovered and
// with kwatchdog registered. A handler that hangs is therefore reported and the
// module is still terminated, which is why a handler is not a way to survive a
// kill.
type SignalHandler func(info SignalInfo)

// SignalQueueError reports a signal refused because the target's pending queue is
// full. It is a distinct type so a caller can tell "the target is not keeping up"
// from "you are not permitted".
type SignalQueueError struct {
	Target PID
	Max    int
}

// SignalInfo is what a handler receives. From and FromDomain are the sender as the
// kernel knows it, not as the sender describes itself.
type SignalInfo struct {
	// Kind is the signal.
	Kind SignalKind `json:"kind"`
	// From is the sender's pid.
	From PID `json:"from"`
	// FromDomain is the sender's domain.
	FromDomain Domain `json:"from_domain"`
	// SentAt is a mono() reading taken when the kernel accepted the signal.
	SentAt int64 `json:"sent_at"`
}

// Error spells the refusal the way the kernel console does, so a message a module
// logs matches the one an operator greps for.
func (e *SignalQueueError) Error() string {
	return fmt.Sprintf("kernel: signal queue for pid %d is full (%d pending)", e.Target, e.Max)
}
