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

package kernel

import (
	"sync"
	"time"
)

// kclock is the kernel time authority (subsystem: kclock).
//
// Every subsystem that measures an interval - rate-limit windows, billing periods,
// timeouts, watchdog deadlines, trace spans - reads time from here and nowhere
// else. Two properties matter and both are enforced:
//
//   - Not rewindable. Mono() never returns a value smaller than one it already
//     returned. A sliding window, a token bucket and a timeout all break silently
//     if time can go backwards, and a wall clock can: NTP steps, an operator
//     changes the date, a VM migrates. Mono() is derived from the monotonic
//     reading Go attaches to time.Now(), so it is immune to wall-clock adjustment,
//     and it is additionally clamped so that no observation ever decreases.
//   - Not forgeable. A module cannot substitute its own clock, because the clock
//     is package-private state and no syscall exposes a setter. A module that
//     could set the time could extend its own rate-limit window, backdate a
//     billing period, or make a watchdog deadline never arrive.
//
// Wall-clock time is still available through Now(), because timestamps in an audit
// record have to mean something to a human. But nothing that makes a decision
// uses it.
type kernelClock struct {
	mu     sync.Mutex
	origin time.Time
	last   int64
}

var kclock = &kernelClock{origin: time.Now()}

// Mono returns nanoseconds since the clock's origin, guaranteed monotonic.
//
// This is the only value any subsystem may use for measuring elapsed time or
// scheduling. It is int64 nanoseconds from process start, so it wraps after
// roughly 292 years, which is not a practical concern and is documented rather
// than silently handled.
func (c *kernelClock) Mono() int64 {
	now := time.Since(c.origin).Nanoseconds()

	c.mu.Lock()
	defer c.mu.Unlock()
	if now <= c.last {
		// Defensive clamp. time.Since uses the monotonic reading so this should
		// not happen, but a subsystem that can be made to observe time going
		// backwards is a subsystem that can be made to misbehave, so the clamp
		// is cheap insurance and it is asserted by a test.
		c.last++
		return c.last
	}
	c.last = now
	return now
}

// Now returns wall-clock UTC time. For timestamps in records, never for
// measuring intervals or making deadline decisions.
func (c *kernelClock) Now() time.Time { return time.Now().UTC() }

// Since returns the elapsed nanoseconds from a Mono() reading taken earlier.
func (c *kernelClock) Since(start int64) int64 { return c.Mono() - start }

// Elapsed returns the elapsed duration from a Mono() reading.
func (c *kernelClock) Elapsed(start int64) time.Duration {
	return time.Duration(c.Since(start))
}

// Deadline returns the Mono() value at which a timeout starting now expires.
func (c *kernelClock) Deadline(after time.Duration) int64 {
	return c.Mono() + after.Nanoseconds()
}

// Expired reports whether a Mono() deadline has passed.
func (c *kernelClock) Expired(deadline int64) bool { return c.Mono() >= deadline }

// KernelTime is what a module gets from SyscallNow. Mono is the value to compute
// with; Wall is the value to print.
type KernelTime struct {
	// Mono is nanoseconds on the kernel's monotonic clock. Non-negative,
	// non-decreasing, and not forgeable.
	Mono int64 `json:"mono"`
	// Wall is UTC wall-clock time, for records a human reads. Never use it to
	// measure an interval: it can step backwards.
	Wall time.Time `json:"wall"`
}

// Clock is a handle on the kernel time authority. It is read-only: there is no
// setter anywhere, which is the entire point of the subsystem. A module that
// could set the time could extend its own rate-limit window, backdate a billing
// period, or make a watchdog deadline never arrive.
type Clock struct{ c *kernelClock }

// KernelClock returns the kernel time authority, for the host process, the console
// dump and tests. Subsystems inside the kernel use the package-level mono()
// instead, so that no code path can be handed a different clock.
func KernelClock() Clock { return Clock{c: kclock} }

// Mono returns nanoseconds on the kernel's monotonic clock.
func (c Clock) Mono() int64 { return c.c.Mono() }

// Now returns wall-clock UTC time, for records a human reads.
func (c Clock) Now() time.Time { return c.c.Now() }

// Since returns the nanoseconds elapsed from a Mono() reading.
func (c Clock) Since(start int64) int64 { return c.c.Since(start) }

// Elapsed returns the duration elapsed from a Mono() reading.
func (c Clock) Elapsed(start int64) time.Duration { return c.c.Elapsed(start) }

// Deadline returns the Mono() value at which a timeout starting now expires.
func (c Clock) Deadline(after time.Duration) int64 { return c.c.Deadline(after) }

// Expired reports whether a Mono() deadline has passed.
func (c Clock) Expired(deadline int64) bool { return c.c.Expired(deadline) }

// Mono is the package-level entry point every subsystem uses.
func mono() int64 { return kclock.Mono() }

// nowUTC is the package-level wall clock, for record timestamps only.
func nowUTC() time.Time { return kclock.Now() }

// SyscallClock is the time half of the syscall surface.
type SyscallClock interface {
	// SyscallNow returns kernel time. Mono is the only value a module may use to
	// measure an interval or a deadline; Wall is for records a human reads.
	// Requires no operation: a module that cannot read time cannot implement a
	// timeout, and there is nothing to gain by granting a forged clock.
	SyscallNow() KernelTime
}

func (c *sContext) SyscallNow() KernelTime {
	return KernelTime{Mono: mono(), Wall: nowUTC()}
}
