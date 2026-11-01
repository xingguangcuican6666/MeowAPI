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

// Supervised work: jobs, timers and their outcomes.

// SchedJob is one request for supervised execution.
type SchedJob struct {
	// Label names the run in the console, in the audit record and in a watchdog
	// event. It is a diagnostic string chosen by the module and is never
	// interpreted by the kernel, so it is length-bounded rather than trusted.
	Label string
	// TimeoutMillis bounds this run. Zero or negative means the sealed ceiling.
	// A value above the ceiling is clamped down: a module may ask for less time
	// than the trust root allows and may never ask for more, because a timeout
	// the timed-out party chooses is not a timeout.
	TimeoutMillis int64
	// Fn is the work. Nil is refused rather than scheduled.
	Fn SchedFunc
}

// TimerSpec is one request for a deferred callback.
//
// Timers are single-shot on purpose. A periodic timer is a way to keep creating
// work forever from one declaration, and the reviewable artifact - the manifest -
// would say nothing about the rate. A module that needs a period re-arms from
// inside the callback, which puts every period through the same ceiling, the same
// quota and the same accounting as the first one.
type TimerSpec struct {
	// Label names the timer in diagnostics.
	Label string
	// DelayMillis is how long to wait before firing. The fire time is a mono()
	// reading, so a wall-clock step - NTP, an operator changing the date, a VM
	// migration - cannot move a timer armed here. The runtime timer underneath is
	// only the wakeup mechanism.
	DelayMillis int64
	// Fn runs under the same supervision as a spawned job: the caller's context,
	// the ceiling timeout, panic recovery, watchdog registration.
	Fn SchedFunc
}

// SchedFunc is work a module asks the kernel to run.
//
// The context handed to it is the caller's own, so the job inherits the caller's
// pid, uid, domain and manifest grants. Every syscall it makes is decided against
// the same ceiling as one made from OnLoad: moving work onto a kernel goroutine
// buys a deadline and attribution, and buys no privilege.
//
// done is closed when the run's deadline expires, when the module closes the
// handle, when the module is signalled to stop, or when the kernel resets. A
// well-behaved job selects on it and returns promptly. A job that ignores it is
// not stopped - see the file header - but the run is then recorded as timed out,
// kwatchdog captures its stack, and the module is put forward for termination.
type SchedFunc func(ctx SContext, done <-chan struct{})

// SchedOutcome is what the kernel recorded about one run. It is always a copy:
// handing out the live record would let a module rewrite the evidence of its own
// timeout.
type SchedOutcome struct {
	// ID is the kernel-allocated run id, unique within a boot.
	ID int64 `json:"id"`
	// Label is the module's own diagnostic string.
	Label string `json:"label,omitempty"`
	// Kind is "job" or "timer".
	Kind string `json:"kind"`
	// State is the terminal state, or SchedRunning / SchedPending while live.
	State SchedState `json:"state"`
	// Detail explains a non-completed state: the panic value, "deadline
	// expired", "handle closed", "module terminated".
	Detail string `json:"detail,omitempty"`
	// StartedAt and ElapsedNanos are mono() readings taken by the kernel around
	// the module's function, so a module cannot report a duration shorter than
	// the one it actually occupied.
	StartedAt    int64 `json:"started_at,omitempty"`
	ElapsedNanos int64 `json:"elapsed_nanos,omitempty"`
	// Deadline is the mono() value at which the run was required to stop.
	Deadline int64 `json:"deadline,omitempty"`
	// Stack is a snapshot of the offending goroutine when the run timed out, was
	// abandoned or panicked. It is empty on a clean completion.
	Stack string `json:"stack,omitempty"`
}
