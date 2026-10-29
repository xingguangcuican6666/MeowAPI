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

// This file exists only so the external test package (kernel_test) can exercise
// internals that are deliberately unreachable from module code. Nothing here is
// part of the ABI: it is not usable by a module, because a module imports the
// package as a client and gets only the exported API, while these helpers are
// compiled into the test binary alone.
//
// The fd table is the case that needs it. install() is package-private on purpose,
// since a handle is only meaningful inside the pid that owns it, and there is no
// syscall by which a module creates a bare handle - real handles come from real
// subsystems (pipes, shared buffers, locks, timers). Without this hook the
// table's isolation, ceiling and reclamation properties could not be tested until
// every one of those subsystems existed.

// testHandle is a trivial resource used by the fd table tests.
type testHandle struct {
	closedFlag
	label  string
	closed *int
}

func (h *testHandle) Kind() string { return "probe" }

func (h *testHandle) Close() error {
	if !h.mark() {
		return errClosed
	}
	if h.closed != nil {
		*h.closed++
	}
	return nil
}

// ProbeOpenHandle installs a probe resource in a context's fd table and returns its
// handle, exercising the real install path including the ceiling from the sealed
// trust root.
func ProbeOpenHandle(ctx SContext, label string) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	return install(c.pid, &testHandle{label: label}, label)
}

// ProbeOpenHandleCounted is ProbeOpenHandle with a close counter, so a test can
// assert that reclamation actually called Close rather than only dropping the
// table entry.
func ProbeOpenHandleCounted(ctx SContext, label string, closed *int) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	return install(c.pid, &testHandle{label: label, closed: closed}, label)
}

// ProbeLookupHandle resolves a handle inside one pid. It returns the resource kind
// rather than the resource, because handing the object out is exactly what the fd
// table exists to prevent.
func ProbeLookupHandle(pid PID, fd FD) (string, error) {
	e, err := lookup(pid, fd)
	if err != nil {
		return "", err
	}
	return e.kind, nil
}

// ProbeReclaimFDs walks a pid's table and closes everything in it, the same call
// unload makes.
func ProbeReclaimFDs(pid PID) (int, []error) { return reclaimFDs(pid) }

// ProbeMaxFDs reports the ceiling install enforces, read from the sealed trust root.
func ProbeMaxFDs() int { return Limits().MaxOpenFDsPerModule }

// panicHandle is a resource whose Close panics, used to prove that reclamation
// contains a broken Close rather than aborting and stranding later handles.
//
// Pointer receivers throughout: closedFlag embeds an atomic.Bool, which must not be
// copied, and go vet rightly refuses a value receiver on a type containing one.
type panicHandle struct{ closedFlag }

func (*panicHandle) Kind() string { return "probe" }
func (*panicHandle) Close() error { panic("probe Close panicked") }

// failingHandle is a resource whose Close returns a caller-supplied error.
type failingHandle struct {
	closedFlag
	err error
}

func (*failingHandle) Kind() string { return "probe" }
func (h *failingHandle) Close() error {
	if !h.mark() {
		return errClosed
	}
	return h.err
}

// ProbeOpenPanicHandle installs a resource that panics when closed.
func ProbeOpenPanicHandle(ctx SContext, label string) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	return install(c.pid, &panicHandle{}, label)
}

// ProbeOpenCountedHandle installs a resource that increments a counter on close,
// so a test can prove Close actually ran rather than only that the table shrank.
func ProbeOpenCountedHandle(ctx SContext, label string, closed *int) (FD, error) {
	return ProbeOpenHandleCounted(ctx, label, closed)
}

// ProbeOpenFailingHandle installs a resource whose Close returns err.
func ProbeOpenFailingHandle(ctx SContext, label string, err error) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	return install(c.pid, &failingHandle{err: err}, label)
}
