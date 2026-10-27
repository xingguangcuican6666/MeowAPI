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
// FDs are allocated per pid and never reused within a boot, so a stale FD from a
// previous module instance cannot accidentally address a live resource.
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
func install(pid PID, res resource, label string) FD {
	t := fdTableFor(pid)
	t.mu.Lock()
	defer t.mu.Unlock()

	fd := t.next
	t.next++
	kind := res.Kind()
	t.byFD[fd] = &fdEntry{fd: fd, res: res, kind: kind, openedAt: mono(), label: label}
	t.byKind[kind]++
	return fd
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
		if err := e.res.Close(); err != nil {
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
