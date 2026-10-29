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
	"errors"
	"fmt"
	"sync"
)

// krlimit is concurrency admission (subsystem: krlimit, the analogue of a
// semaphore with a cgroup ceiling).
//
// A module acquires a slot before starting an in-flight operation and releases it
// when the operation ends. The kernel enforces two ceilings, both read from the
// sealed trust root: how many slots one module may hold, and how many the kernel
// may hand out in total. Neither is a constant a module can argue with and neither
// comes from a manifest, because a quota the quota-holder could raise is not a
// quota.
//
// A slot is an fd-table resource. That single decision carries the whole safety
// argument: when a module is unloaded, panics, hangs or is killed, the kernel walks
// its table and closes every slot it held. A module that dies holding slots cannot
// strand them, which is the failure mode that turns one broken adapter into a
// gateway-wide outage.

// ErrNoSlot is returned when the ceiling is reached. It is a distinct typed error
// rather than a generic one because the caller has to tell two situations apart:
// "busy, retry later" and "broken". A gateway that cannot distinguish them either
// hammers a saturated upstream or gives up on a transient spike.
var ErrNoSlot = errors.New("kernel: no slot available")

// slotResource is one held concurrency slot.
type slotResource struct {
	closedFlag
	pid   PID
	label string
}

func (s *slotResource) Kind() string { return "slot" }

// Close releases the slot back to both counters. Idempotent, because reclamation
// may run after an explicit release and must not double-free.
func (s *slotResource) Close() error {
	if !s.mark() {
		return errClosed
	}
	kslots.release(s.pid)
	return nil
}

// slotCounters holds the two live counters. Both are guarded by one mutex because a
// acquire has to check and increment them atomically: checking per-module and total
// under separate locks is a race that admits one slot past the ceiling.
type slotCounters struct {
	mu       sync.Mutex
	byPid    map[PID]int
	total    int
	refused  int64
	ceiling  int64
	released int64
}

var kslots = &slotCounters{byPid: map[PID]int{}}

func (s *slotCounters) release(pid PID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.byPid[pid]; n > 0 {
		s.byPid[pid] = n - 1
		if s.byPid[pid] == 0 {
			delete(s.byPid, pid)
		}
	}
	if s.total > 0 {
		s.total--
	}
	s.released++
}

// acquire checks both ceilings and reserves a slot, or refuses.
func (s *slotCounters) acquire(pid PID) error {
	lim := Limits()

	s.mu.Lock()
	defer s.mu.Unlock()

	if lim.MaxTotalSlots > 0 && s.total >= lim.MaxTotalSlots {
		s.refused++
		return fmt.Errorf("%w: kernel holds %d of %d slots", ErrNoSlot, s.total, lim.MaxTotalSlots)
	}
	if lim.MaxSlotsPerModule > 0 && s.byPid[pid] >= lim.MaxSlotsPerModule {
		s.refused++
		return fmt.Errorf("%w: pid %d holds %d of %d slots", ErrNoSlot, pid, s.byPid[pid], lim.MaxSlotsPerModule)
	}

	s.byPid[pid]++
	s.total++
	return nil
}

// SyscallLimit is the admission half of the syscall surface.
type SyscallLimit interface {
	// SyscallAcquireSlot reserves one concurrency slot and returns the handle that
	// owns it. Requires slot:acquire. Close the handle, or let the module unload, to
	// release it.
	SyscallAcquireSlot(label string) (FD, error)
	// SyscallSlots reports how many slots this context holds. It requires no
	// operation and never reports another pid's count.
	SyscallSlots() int
}

// AcquireSlot reserves one slot for a context. It is the function form for kernel
// subsystems that admit work on a module's behalf.
//
// The returned handle owns the slot: closing it releases the slot. A module that
// forgets to close is not a leak, because unload reclaims it.
func AcquireSlot(ctx SContext, label string) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	if err := c.syscall(OpSlotAcquire); err != nil {
		return noFD, err
	}
	return acquireSlot(c, label)
}

func acquireSlot(c *sContext, label string) (FD, error) {
	if err := kslots.acquire(c.pid); err != nil {
		// A refusal at the ceiling is an operator-visible event: it is either a leak
		// in a module or a limit set too low, and both need diagnosing afterwards.
		fault(c, "slot refused at ceiling", map[string]any{
			"module": c.name, "label": label, "error": err.Error(),
		})
		return noFD, err
	}

	fd, err := install(c.pid, &slotResource{pid: c.pid, label: label}, label)
	if err != nil {
		// The handle table is full, so give the slot back. Leaving it reserved
		// would leak admission capacity every time this path is hit.
		kslots.release(c.pid)
		return noFD, err
	}
	return fd, nil
}

// ReleaseSlot closes a slot handle. It is the explicit path; reclamation is the
// fallback.
func ReleaseSlot(ctx SContext, fd FD) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(""); err != nil {
		return err
	}
	e, err := lookup(c.pid, fd)
	if err != nil {
		return err
	}
	if e.kind != "slot" {
		return fmt.Errorf("kernel: fd %d is a %s, not a slot", fd, e.kind)
	}
	return closeFD(c.pid, fd)
}

// SlotStats is the admission view for the console dump and for an operator watching
// a saturation event.
type SlotStats struct {
	// PerPid is the live slot count for each pid holding at least one.
	PerPid map[PID]int `json:"per_pid"`
	// Total is the live count across the kernel.
	Total int `json:"total"`
	// PerModuleCeiling and TotalCeiling are the limits in force, copied from the
	// sealed trust root so the dump shows the numbers actually applied.
	PerModuleCeiling int `json:"per_module_ceiling"`
	TotalCeiling     int `json:"total_ceiling"`
	// Refused counts admissions denied at a ceiling since boot. A rising number
	// with a flat Total is saturation; a rising number with a rising Total is a
	// leak.
	Refused int64 `json:"refused"`
	// Released counts slots given back since boot.
	Released int64 `json:"released"`
}

// SlotStatsSnapshot copies the counters. It takes the lock once so the per-pid map
// and the total agree with each other, which a pair of separate reads would not.
func SlotStatsSnapshot() SlotStats {
	lim := Limits()
	kslots.mu.Lock()
	defer kslots.mu.Unlock()
	per := make(map[PID]int, len(kslots.byPid))
	for p, n := range kslots.byPid {
		per[p] = n
	}
	return SlotStats{
		PerPid:           per,
		Total:            kslots.total,
		PerModuleCeiling: lim.MaxSlotsPerModule,
		TotalCeiling:     lim.MaxTotalSlots,
		Refused:          kslots.refused,
		Released:         kslots.released,
	}
}

func (c *sContext) SyscallAcquireSlot(label string) (FD, error) {
	if err := c.syscall(OpSlotAcquire); err != nil {
		return noFD, err
	}
	return acquireSlot(c, label)
}

func (c *sContext) SyscallSlots() int {
	kslots.mu.Lock()
	defer kslots.mu.Unlock()
	return kslots.byPid[c.pid]
}

// resetSlots clears admission state. Called only from resetKernel.
//
// Live slots are not closed here on purpose: reclamation during unload already
// closed them, and closing them again here would double-decrement the counters for
// any resource whose Close raced the reset. Zeroing the map is both correct and
// idempotent.
func resetSlots() {
	kslots.mu.Lock()
	defer kslots.mu.Unlock()
	kslots.byPid = map[PID]int{}
	kslots.total = 0
	kslots.refused = 0
	kslots.released = 0
}
