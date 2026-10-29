/*
Copyright (C) 2023-2026 xingguangcuican6666

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
	"sync/atomic"
)

// FD is a kernel resource handle (subsystem: kfdtable).
//
// A module never receives a pointer to a kernel object. It receives an int, valid
// only inside its own pid's table. That has two consequences, and both are the
// reason this exists:
//
//   - No confused deputy. A handle cannot be handed to another module, because
//     the receiving module's table has no entry for it. Passing an object
//     reference would let a module lend capability it was granted, which is how a
//     narrowly-scoped plugin becomes an escape hatch for a broad one.
//   - Reclamation is complete. When a module is unloaded, panics, or is killed,
//     the kernel walks its table and closes everything in it. There is no resource
//     whose only reference lived inside the module.
//
// Handle numbers are allocated per pid from a counter that only increases, so a
// closed number is never reissued inside the same table: a module holding a stale
// number gets "not open" rather than silently addressing a different resource.
// Numbers do repeat across pids, which is correct and is the isolation property -
// pid A's handle 1 and pid B's handle 1 are unrelated resources, and neither can
// resolve the other's.
type FD int

// noFD is the zero value and is never valid.
const noFD FD = 0

// resource is anything the fd table can own. Close is called exactly once, on
// reclamation, and must be idempotent-safe because a module may also close
// explicitly first.
type resource interface {
	// Kind names the resource type for diagnostics: pipe, shm, lock, event,
	// socket, timer, span.
	Kind() string
	// Close releases the resource. It must tolerate being called on an
	// already-closed resource.
	Close() error
}

// fdEntry is one table row.
type fdEntry struct {
	fd       FD
	res      resource
	kind     string
	openedAt int64
	label    string
}

// fdTable is a per-pid handle table.
type fdTable struct {
	mu     sync.Mutex
	next   FD
	byFD   map[FD]*fdEntry
	byKind map[string]int
}

var (
	fdTablesMu sync.RWMutex
	fdTables   = map[PID]*fdTable{}
)

// fdTableFor returns a pid's table, creating it on first use.
func fdTableFor(pid PID) *fdTable {
	fdTablesMu.RLock()
	t, ok := fdTables[pid]
	fdTablesMu.RUnlock()
	if ok {
		return t
	}

	fdTablesMu.Lock()
	defer fdTablesMu.Unlock()
	if t, ok := fdTables[pid]; ok {
		return t
	}
	t = &fdTable{next: 1, byFD: map[FD]*fdEntry{}, byKind: map[string]int{}}
	fdTables[pid] = t
	return t
}

// install registers a resource and returns its handle. Every subsystem that hands
// a module something stateful goes through here rather than returning a pointer.
//
// The ceiling comes from the sealed trust root, so a module cannot raise it and
// neither can the code calling install. Returning an error rather than a bare FD is
// what forces every subsystem to handle exhaustion; a zero FD would be
// indistinguishable from "no handle" at the call site and would be silently stored.
func install(pid PID, res resource, label string) (FD, error) {
	t := fdTableFor(pid)

	t.mu.Lock()
	defer t.mu.Unlock()

	if max := Limits().MaxOpenFDsPerModule; len(t.byFD) >= max {
		// Reaching a ceiling is an operator-visible event, not just a caller
		// error: it is either a leak in a module or a limit set too low, and both
		// need to be diagnosable after the fact.
		fault(nil, "handle ceiling reached", map[string]any{
			"pid": pid, "max_open_fds_per_module": max, "open": len(t.byFD),
		})
		return noFD, fmt.Errorf("kernel: pid %d holds the maximum of %d open handles", pid, max)
	}

	fd := t.next
	t.next++
	kind := res.Kind()
	t.byFD[fd] = &fdEntry{fd: fd, res: res, kind: kind, openedAt: mono(), label: label}
	t.byKind[kind]++
	return fd, nil
}

// lookup resolves a handle within one pid. A handle from another pid's table does
// not resolve, which is the isolation property.
func lookup(pid PID, fd FD) (*fdEntry, error) {
	if fd <= noFD {
		return nil, fmt.Errorf("kernel: invalid fd %d", fd)
	}
	t := fdTableFor(pid)
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.byFD[fd]
	if !ok {
		return nil, fmt.Errorf("kernel: fd %d is not open in pid %d", fd, pid)
	}
	return e, nil
}

// close releases one handle. Closing an unknown handle is an error rather than a
// no-op, because a module double-closing is a defect worth seeing, unlike
// unloading an unknown pid during boot cleanup.
func closeFD(pid PID, fd FD) error {
	t := fdTableFor(pid)
	t.mu.Lock()
	e, ok := t.byFD[fd]
	if ok {
		delete(t.byFD, fd)
		t.byKind[e.kind]--
		if t.byKind[e.kind] <= 0 {
			delete(t.byKind, e.kind)
		}
	}
	t.mu.Unlock()

	if !ok {
		return fmt.Errorf("kernel: fd %d is not open in pid %d", fd, pid)
	}
	if err := e.res.Close(); err != nil {
		return fmt.Errorf("kernel: closing fd %d (%s): %w", fd, e.kind, err)
	}
	return nil
}

// FDInfo describes an open handle, for the console dump and diagnostics.
type FDInfo struct {
	FD       FD     `json:"fd"`
	Kind     string `json:"kind"`
	Label    string `json:"label,omitempty"`
	OpenedAt int64  `json:"opened_at"`
}

// FDList returns a pid's open handles, sorted by fd.
func FDList(pid PID) []FDInfo {
	t := fdTableFor(pid)
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]FDInfo, 0, len(t.byFD))
	for _, e := range t.byFD {
		out = append(out, FDInfo{FD: e.fd, Kind: e.kind, Label: e.label, OpenedAt: e.openedAt})
	}
	sortFDs(out)
	return out
}

func sortFDs(in []FDInfo) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j].FD < in[j-1].FD; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

// reclaimFDs closes everything a pid owns. Called on unload and on termination,
// which is the property that makes a crashed module leak nothing.
func reclaimFDs(pid PID) (closed int, errs []error) {
	t := fdTableFor(pid)

	t.mu.Lock()
	entries := make([]*fdEntry, 0, len(t.byFD))
	for _, e := range t.byFD {
		entries = append(entries, e)
	}
	t.byFD = map[FD]*fdEntry{}
	t.byKind = map[string]int{}
	t.mu.Unlock()

	sortFDEntries(entries)
	for _, e := range entries {
		closed++
		if err := closeResource(e); err != nil {
			errs = append(errs, fmt.Errorf("fd %d (%s): %w", e.fd, e.kind, err))
		}
	}
	return closed, errs
}

func sortFDEntries(in []*fdEntry) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j].fd < in[j-1].fd; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

// dropFDTable removes a pid's table entirely. Called only from resetKernel.
func dropFDTable(pid PID) {
	fdTablesMu.Lock()
	defer fdTablesMu.Unlock()
	delete(fdTables, pid)
}

func resetFDTables() {
	fdTablesMu.Lock()
	defer fdTablesMu.Unlock()
	fdTables = map[PID]*fdTable{}
}

// FDCount reports how many handles a pid holds, for the console dump and for a
// leak check in tests.
func FDCount(pid PID) int {
	t := fdTableFor(pid)
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byFD)
}

// errClosed is returned by a resource that has already been closed.
var errClosed = errors.New("kernel: resource closed")

// closedFlag is the shared once-only-close guard every resource embeds.
type closedFlag struct{ v atomic.Bool }

// mark returns true the first time it is called, false afterwards.
func (c *closedFlag) mark() bool { return !c.v.Swap(true) }
func (c *closedFlag) done() bool { return c.v.Load() }

// SyscallFD is the handle half of the syscall surface.
type SyscallFD interface {
	// SyscallClose releases a handle this context opened. Handles are per pid,
	// so a handle belonging to another module does not resolve here. Requires no
	// operation: closing what you opened is not a capability.
	SyscallClose(fd FD) error
	// SyscallFDs lists this context's open handles, for a module diagnosing its
	// own leaks. Requires no operation, and never exposes another pid's table.
	SyscallFDs() []FDInfo
}

func (c *sContext) SyscallClose(fd FD) error {
	if err := c.syscall(""); err != nil {
		return err
	}
	return closeFD(c.pid, fd)
}

func (c *sContext) SyscallFDs() []FDInfo {
	return FDList(c.pid)
}

// closeResource closes one resource, containing a panic so that a broken Close
// cannot strand the handles opened after it. Reclamation runs during unload, and a
// module that panics while being torn down is exactly the module whose resources
// most need closing.
func closeResource(e *fdEntry) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Close panicked: %v", r)
		}
	}()
	return e.res.Close()
}
