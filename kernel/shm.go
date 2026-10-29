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

// kshm and kslab: shared read-only buffers for large payloads, and the slab
// that recycles them.
//
// RESET: resetShm() must be added to resetKernel() in kernel/kernel.go.
//
// WIRING: the syscall entry points are plain functions here. The group interface
// and the *sContext methods that belong in kernel/context.go are in a comment
// block at the bottom of this file.
//
// What this answers to. shm_get/shmat with a read-only mapping, over a slab
// allocator that recycles fixed-size blocks. Two modules exchange a large
// payload - a prompt, a completion, a document - without either one holding a
// reference into the other's memory.
//
// The guarantee, and the honest limit of it. Go cannot map a page read-only into
// one goroutine and writable into another; there is no address-space mechanism to
// use in-process. What is enforced instead:
//
//   - The kernel owns the bytes. A module never receives the underlying slice,
//     on either side. The owner writes through a syscall that copies in, and a
//     reader reads through a syscall that copies out. There is no call shape in
//     which a reader obtains a writable alias, so a reader cannot rewrite a
//     prompt in flight.
//   - A granted segment is sealed. Once the owner grants it to a peer, no one can
//     write it again, the owner included. Without this the owner could rewrite a
//     payload after the reader had accepted it, which is the same attack from the
//     other side.
//   - A released buffer is zeroed before it can be reused. That is the kiommu
//     guarantee: a recycled buffer must not carry the previous tenant's prompt or
//     key. The slab recycles for allocation speed, and zeroing on release is what
//     makes recycling safe rather than a leak between tenants.
//
// The copies cost memory and time proportional to the payload. That is the price
// of the guarantee in-process, and it is stated rather than hidden: a future
// out-of-process or WASM tier can replace the copy with a real read-only mapping
// without changing this ABI, because the ABI already hands out bytes and not
// references.
package kernel

import (
	"fmt"
	"strings"
	"sync"
)

// SHMID names a shared segment kernel-wide. It is a name, not a capability: a
// module that learns an id it was not granted gets nothing from it, because
// ShmMap checks the owner's grant table rather than the caller's knowledge. That
// is the difference from an FD, which is a capability inside its own pid's table.
// Ids increase monotonically from 1 and are never reused within a boot, so a stale
// id cannot address a live segment.
type SHMID int64

// ShmError reports a malformed shared-buffer request. Distinct type, same reason
// as KVError: a caller must be able to tell a defect in its own call from a kernel
// failure without matching a message string.
type ShmError struct{ Msg string }

// Error renders the refusal with the shm prefix, so a log line names the subsystem
// without the reader having to open the code.
func (e *ShmError) Error() string { return "kernel: shm: " + e.Msg }

// ShmQuotaError is the typed ceiling error for the shared pool. The ceiling comes
// from the sealed trust root, so it is not a number a module can argue with, and
// recognising it as a type lets a module shed load instead of retrying forever.
type ShmQuotaError struct {
	// Owner is the module that asked. The pool ceiling is kernel-wide rather than
	// per module, so the refusal does not say whose allocation failed, and an
	// operator reading the error needs that.
	Owner PID `json:"owner"`
	// Size is the slab class the allocation would have occupied.
	Size int64 `json:"size"`
	// Limit is Limits().MaxSharedBytes.
	Limit int64 `json:"limit"`
	// InUse is what the pool already holds, live plus cached.
	InUse int64 `json:"in_use"`
}

// Error renders the class asked for, the pool level and the ceiling, which are the
// three numbers an operator needs to decide whether the pool is undersized or
// whether one module is over-allocating.
func (e *ShmQuotaError) Error() string {
	return fmt.Sprintf("kernel: shm: allocation of %d bytes by pid %d refused, pool holds %d of %d",
		e.Size, e.Owner, e.InUse, e.Limit)
}

// ShmDescriptor describes an allocated segment to its owner. It carries no slice:
// the owner writes through ShmWrite and reads back through ShmRead.
type ShmDescriptor struct {
	// FD is the handle in the owner's own table. It is a capability: it resolves
	// only in that table, so it cannot be passed to another module to use.
	FD FD `json:"fd"`
	// ID names the segment kernel-wide. It is what a peer passes to ShmMap, and it
	// is not a capability on its own: the map still checks the owner's grant set.
	ID SHMID `json:"id"`
	// Size is the payload length the caller asked for, which may be smaller than
	// the slab class the pool reserved.
	Size int `json:"size"`
}

// ShmMapping describes a read-only mapping to the module that holds it.
type ShmMapping struct {
	// FD is the handle in the reader's own table.
	FD FD `json:"fd"`
	// ID is the segment the grant covered.
	ID SHMID `json:"id"`
	// Size is the payload length, so the reader can allocate a buffer before
	// copying without a second syscall.
	Size int `json:"size"`
	// Owner is the pid that allocated the segment. It is a diagnostic: knowing
	// who to blame for a payload is not a capability to read it.
	Owner PID `json:"owner"`
}

// Shm resource kinds, as they appear in FDList and in the console dump. They are
// distinct so a dump shows which side of a shared buffer a module holds, which is
// the first question when investigating a leak between two modules.
const (
	shmKindOwner  = "shm"
	shmKindReader = "shmmap"
)

// maxShmLabelLen bounds the label a caller attaches to a segment. The label is
// rendered into the fd table, the console dump and fault records, so it is bounded
// rather than trusted, consistently with the usage fact label.
const maxShmLabelLen = 128

// shmMinClass is the smallest slab class. A tiny payload rounds up to it, which
// wastes memory the same way a real slab does; the alternative, one class per
// distinct size, is a cache that never hits.
const shmMinClass = 4096

// shmCachePerClass caps how many idle buffers one class retains, and
// shmCacheShare caps the idle cache as a fraction of the pool ceiling. Both exist
// because a cache that cannot be bounded is a second, unaccounted pool: idle
// buffers hold real memory, so they count against MaxSharedBytes and are evicted
// first when a live allocation needs the room.
const (
	shmCachePerClass = 8
	shmCacheShare    = 4
)

// shmSegment is one shared buffer. The kernel owns it for its whole life; nothing
// outside this package ever sees the data slice.
type shmSegment struct {
	id    SHMID
	owner PID
	label string

	// class is the slab size, which is what the pool accounts and what zeroing
	// covers. len(data) == class, and the usable payload is data[:size].
	class int64
	size  int

	// mu guards data and sealed. Writes happen only before sealing, so a reader
	// that arrives after a grant cannot observe a partial payload.
	mu     sync.Mutex
	data   []byte
	sealed bool

	// grants are the pids the owner authorised to map this segment. Guarded by
	// shmMu, not by mu: granting is a registry operation, not a data operation.
	grants map[PID]struct{}

	// refs counts live handles - the owner's plus every reader mapping. The
	// segment is zeroed and returned to the slab when it reaches zero.
	refs int
}

// shmPool is the whole subsystem: the live registry, the pool accounting and the
// slab cache.
type shmPool struct {
	mu      sync.Mutex
	nextID  SHMID
	live    map[SHMID]*shmSegment
	byOwner map[PID]map[SHMID]struct{}
	pool    int64
	cache   map[int64][][]byte
	cached  int64
	evicted int64
	allocs  int64
	reused  int64
	refused int64
	zeroed  int64
}

var kshm = &shmPool{
	nextID:  1,
	live:    map[SHMID]*shmSegment{},
	byOwner: map[PID]map[SHMID]struct{}{},
	cache:   map[int64][][]byte{},
}

// Lock order is kshm.mu then segment.mu, and never the reverse. Segment data
// copies happen under segment.mu while the registry is untouched, so a slow reader
// copying a large payload does not block an allocation.

// ShmAlloc allocates a shared buffer and returns a handle on it. Requires
// shm:alloc. The buffer is the caller's to fill, and filling it is part of this
// grant rather than a separate capability: an allocation the owner cannot write is
// useless, and a second operation for it would be a grant that means nothing on
// its own.
//
// The size is rounded up to a slab class, and the class is what counts against
// Limits().MaxSharedBytes. Accounting the requested size instead would let the
// pool hold more bytes than the ceiling names, because every allocation would
// under-report what the kernel actually reserved.
func ShmAlloc(ctx SContext, size int, label string) (ShmDescriptor, error) {
	c, err := shmContext(ctx, OpShmAlloc)
	if err != nil {
		return ShmDescriptor{}, err
	}
	if size <= 0 {
		return ShmDescriptor{}, &ShmError{Msg: fmt.Sprintf("size %d must be positive", size)}
	}
	if len(label) > maxShmLabelLen {
		return ShmDescriptor{}, &ShmError{Msg: fmt.Sprintf("label longer than %d bytes", maxShmLabelLen)}
	}
	if strings.IndexByte(label, 0) >= 0 {
		return ShmDescriptor{}, &ShmError{Msg: "label contains a NUL byte"}
	}

	class := shmClass(int64(size))

	data, err := kshm.take(c, class)
	if err != nil {
		return ShmDescriptor{}, err
	}

	seg := &shmSegment{
		owner: c.pid, label: label, class: class, size: size,
		data: data, grants: map[PID]struct{}{c.pid: {}}, refs: 1,
	}

	kshm.mu.Lock()
	seg.id = kshm.nextID
	kshm.nextID++
	kshm.live[seg.id] = seg
	if kshm.byOwner[c.pid] == nil {
		kshm.byOwner[c.pid] = map[SHMID]struct{}{}
	}
	kshm.byOwner[c.pid][seg.id] = struct{}{}
	kshm.allocs++
	kshm.mu.Unlock()

	fd, err := install(c.pid, &shmOwnerHandle{seg: seg}, label)
	if err != nil {
		// The handle could not be registered, so the segment must not survive: an
		// unreachable live segment is a leak the fd table cannot reclaim, because
		// reclamation walks handles. The owner reference this segment was created
		// with is the only one, so releasing it drops and scrubs the buffer.
		kshm.release(seg)
		return ShmDescriptor{}, err
	}
	return ShmDescriptor{FD: fd, ID: seg.id, Size: size}, nil
}

// ShmWrite copies payload bytes into a segment the caller owns. Requires
// shm:alloc, and refuses a sealed segment: sealing is what makes a granted buffer
// immutable for everyone, the owner included.
func ShmWrite(ctx SContext, fd FD, offset int, p []byte) (int, error) {
	c, err := shmContext(ctx, OpShmAlloc)
	if err != nil {
		return 0, err
	}
	seg, err := shmOwnerSegment(c, fd)
	if err != nil {
		return 0, err
	}

	seg.mu.Lock()
	defer seg.mu.Unlock()
	if seg.data == nil {
		// The handle resolved but the segment was released underneath this call,
		// which happens when a module closes an fd from one goroutine while
		// another writes through it. Refusing is the whole response: the kernel
		// must not panic because a module raced itself.
		return 0, errClosed
	}
	if seg.sealed {
		return 0, &ShmError{Msg: fmt.Sprintf("segment %d is sealed and cannot be written", seg.id)}
	}
	if offset < 0 || offset > seg.size {
		return 0, &ShmError{Msg: fmt.Sprintf("offset %d is outside segment %d of %d bytes", offset, seg.id, seg.size)}
	}
	n := copy(seg.data[offset:seg.size], p)
	return n, nil
}

// ShmRead copies payload bytes out of a segment, from either side. The owner uses
// it to read back what it wrote; a reader uses it as the only way to see the
// payload. Requires shm:map, because reading a shared buffer is mapping it, and
// the grant that authorises the map is the same fact that authorises the read.
//
// dst bounds the read: the kernel copies at most len(dst) bytes and reports how
// many. A caller that passes a short buffer gets a short read rather than an
// allocation it did not ask for.
func ShmRead(ctx SContext, fd FD, offset int, dst []byte) (int, error) {
	c, err := shmContext(ctx, OpShmMap)
	if err != nil {
		return 0, err
	}
	seg, err := shmAnySegment(c, fd)
	if err != nil {
		return 0, err
	}

	seg.mu.Lock()
	defer seg.mu.Unlock()
	if seg.data == nil {
		return 0, errClosed
	}
	if offset < 0 || offset > seg.size {
		return 0, &ShmError{Msg: fmt.Sprintf("offset %d is outside segment %d of %d bytes", offset, seg.id, seg.size)}
	}
	return copy(dst, seg.data[offset:seg.size]), nil
}

// ShmBytes returns a fresh copy of a segment's whole payload. It is the
// convenience form of ShmRead, and the copy is the point: the caller owns the
// result and the kernel keeps no alias to it, so a reader mutating its own copy
// cannot reach the segment.
func ShmBytes(ctx SContext, fd FD) ([]byte, error) {
	c, err := shmContext(ctx, OpShmMap)
	if err != nil {
		return nil, err
	}
	seg, err := shmAnySegment(c, fd)
	if err != nil {
		return nil, err
	}

	seg.mu.Lock()
	defer seg.mu.Unlock()
	if seg.data == nil {
		return nil, errClosed
	}
	out := make([]byte, seg.size)
	copy(out, seg.data[:seg.size])
	return out, nil
}

// ShmGrant authorises one peer to map a segment, and seals it. Requires shm:alloc
// on the owner's side; the peer needs shm:map to use the grant.
//
// Sealing is not incidental. A grant that left the buffer writable would let the
// owner change a payload after the peer had read and acted on it, which is the
// same integrity failure the read-only copy prevents, reached from the other side.
// A grant is therefore the moment the payload becomes a fact rather than a draft.
//
// The grant is recorded on the audit chain: it delegates access to another pid,
// and a delegation that leaves no trace cannot be investigated.
func ShmGrant(ctx SContext, fd FD, peer PID) error {
	c, err := shmContext(ctx, OpShmAlloc)
	if err != nil {
		return err
	}
	if peer == c.pid {
		// The owner is already in its own grant set. Granting to yourself is not
		// an error worth a denial, but it is a mistake worth seeing.
		return &ShmError{Msg: "a segment is already granted to its owner"}
	}
	if peer <= 0 {
		return &ShmError{Msg: fmt.Sprintf("peer pid %d is not a valid target", peer)}
	}
	seg, err := shmOwnerSegment(c, fd)
	if err != nil {
		return err
	}

	kshm.mu.Lock()
	if _, alive := kshm.live[seg.id]; !alive {
		kshm.mu.Unlock()
		return errClosed
	}
	seg.grants[peer] = struct{}{}
	seg.mu.Lock()
	seg.sealed = true
	seg.mu.Unlock()
	kshm.mu.Unlock()

	kaudit.record(AuditPolicy, c, "shared buffer granted", map[string]any{
		"module": c.name, "shm_id": int64(seg.id), "peer": peer, "size": seg.size,
	})
	return nil
}

// ShmMap maps a segment read-only into the caller's fd table. Requires shm:map and
// a grant from the segment's owner, which is checked against the owner's grant set
// and never against anything the caller supplies.
//
// The result is a handle, so the mapping is reclaimed with everything else the
// module holds: an unload, a panic or a failed load releases it, and releasing the
// last reference zeroes the buffer.
func ShmMap(ctx SContext, id SHMID, label string) (ShmMapping, error) {
	c, err := shmContext(ctx, OpShmMap)
	if err != nil {
		return ShmMapping{}, err
	}
	if len(label) > maxShmLabelLen {
		return ShmMapping{}, &ShmError{Msg: fmt.Sprintf("label longer than %d bytes", maxShmLabelLen)}
	}

	kshm.mu.Lock()
	seg, ok := kshm.live[id]
	if !ok {
		kshm.mu.Unlock()
		return ShmMapping{}, &ShmError{Msg: fmt.Sprintf("segment %d does not exist", id)}
	}
	if _, granted := seg.grants[c.pid]; !granted {
		kshm.mu.Unlock()
		return ShmMapping{}, shmRefuseGrant(c, id)
	}
	seg.refs++
	owner, size := seg.owner, seg.size
	kshm.mu.Unlock()

	fd, err := install(c.pid, &shmReaderHandle{seg: seg}, label)
	if err != nil {
		kshm.release(seg)
		return ShmMapping{}, err
	}
	return ShmMapping{FD: fd, ID: id, Size: size, Owner: owner}, nil
}

// ShmSize reports a segment's payload size from either handle, so a reader can
// allocate a buffer before copying. Requires shm:map.
func ShmSize(ctx SContext, fd FD) (int, error) {
	c, err := shmContext(ctx, OpShmMap)
	if err != nil {
		return 0, err
	}
	seg, err := shmAnySegment(c, fd)
	if err != nil {
		return 0, err
	}
	return seg.size, nil
}

// ShmSeal seals a segment without granting it to anyone. A module that has
// finished building a payload and intends to keep it uses this to make its own
// buffer immutable, so a later bug in the module cannot corrupt a payload it
// already handed downstream. Requires shm:alloc.
func ShmSeal(ctx SContext, fd FD) error {
	c, err := shmContext(ctx, OpShmAlloc)
	if err != nil {
		return err
	}
	seg, err := shmOwnerSegment(c, fd)
	if err != nil {
		return err
	}
	seg.mu.Lock()
	seg.sealed = true
	seg.mu.Unlock()
	return nil
}

// ShmPoolBytes reports how many bytes the shared pool holds, live plus cached in
// the slab. It is the number MaxSharedBytes bounds, exported for the console dump
// and for a leak check in tests; it reports a count and never a payload.
func ShmPoolBytes() int64 {
	kshm.mu.Lock()
	defer kshm.mu.Unlock()
	return kshm.pool
}

// ShmStats is the pool's diagnostic view.
type ShmStats struct {
	// Segments is how many buffers are live, that is, held by at least one handle.
	Segments int `json:"segments"`
	// PoolBytes is what the pool holds against MaxSharedBytes, live plus cached.
	PoolBytes int64 `json:"pool_bytes"`
	// CachedBytes is the idle part of PoolBytes, sitting in the slab.
	CachedBytes int64 `json:"cached_bytes"`
	// Allocations counts successful ShmAlloc calls this boot.
	Allocations int64 `json:"allocations"`
	// Reused counts allocations served from the slab rather than by a fresh
	// allocation, which is the only evidence that recycling happens at all.
	Reused int64 `json:"reused"`
	// Evictions counts cached buffers dropped to make room for a live one.
	Evictions int64 `json:"evictions"`
	// Refused counts allocations refused by the ceiling.
	Refused int64 `json:"refused"`
	// Zeroed counts buffers scrubbed on release, which is the kiommu guarantee
	// being kept rather than merely promised.
	Zeroed int64 `json:"zeroed"`
}

// ShmSnapshot returns the pool statistics. Every field is a count; no payload is
// reachable through it, so a diagnostic dump cannot leak what modules exchanged.
func ShmSnapshot() ShmStats {
	kshm.mu.Lock()
	defer kshm.mu.Unlock()
	return ShmStats{
		Segments: len(kshm.live), PoolBytes: kshm.pool, CachedBytes: kshm.cached,
		Allocations: kshm.allocs, Reused: kshm.reused, Evictions: kshm.evicted,
		Refused: kshm.refused, Zeroed: kshm.zeroed,
	}
}

// shmContext is the shared prologue, identical in shape to the kvfs one: assert
// the context is kernel-issued, run the liveness gate, then the policy gate.
func shmContext(ctx SContext, op Op) (*sContext, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if err := c.alive(); err != nil {
		return nil, err
	}
	if err := check(c, op); err != nil {
		return nil, err
	}
	return c, nil
}

// shmOwnerSegment resolves a handle the caller owns as an owner handle. A reader's
// mapping does not resolve here, which is what stops a reader from writing or
// granting a buffer it was only allowed to read.
func shmOwnerSegment(c *sContext, fd FD) (*shmSegment, error) {
	e, err := lookup(c.pid, fd)
	if err != nil {
		return nil, err
	}
	h, ok := e.res.(*shmOwnerHandle)
	if !ok {
		return nil, &ShmError{Msg: fmt.Sprintf("fd %d is a %s handle, not an owner handle", fd, e.kind)}
	}
	kshm.mu.Lock()
	_, alive := kshm.live[h.seg.id]
	kshm.mu.Unlock()
	if !alive {
		return nil, errClosed
	}
	return h.seg, nil
}

// shmAnySegment resolves either handle kind. Reads go through this, because the
// owner reading back its own payload and a peer reading a granted one are the same
// operation on the same bytes.
func shmAnySegment(c *sContext, fd FD) (*shmSegment, error) {
	e, err := lookup(c.pid, fd)
	if err != nil {
		return nil, err
	}
	switch h := e.res.(type) {
	case *shmOwnerHandle:
		return h.seg, nil
	case *shmReaderHandle:
		return h.seg, nil
	}
	return nil, &ShmError{Msg: fmt.Sprintf("fd %d is a %s handle, not a shared buffer", fd, e.kind)}
}

// shmRefuseGrant is what an ungranted map looks like. It is a denial rather than a
// plain error, because attempting to map a buffer you were not granted is an
// attempt to act beyond your grants, and that belongs on the audit chain.
func shmRefuseGrant(c *sContext, id SHMID) error {
	reason := fmt.Sprintf("segment %d is not granted to module %q", id, c.name)
	fault(c, "shared buffer map refused", map[string]any{
		"module": c.name, "shm_id": int64(id), "reason": reason,
	})
	kaudit.record(AuditEscalation, c, "denied ungranted shared buffer map", map[string]any{
		"module": c.name, "shm_id": int64(id),
	})
	return &DeniedError{Op: OpShmMap, Ctx: c, Reason: reason}
}

// shmOwnerHandle is the owner's fd-table resource. Close drops the owner's
// reference and withdraws every grant, so a peer cannot map a buffer whose owner
// has gone away.
type shmOwnerHandle struct {
	closedFlag
	seg *shmSegment
}

// Kind names the handle in the fd table and in the console dump.
func (h *shmOwnerHandle) Kind() string { return shmKindOwner }

func (h *shmOwnerHandle) Close() error {
	if !h.mark() {
		return errClosed
	}
	kshm.releaseOwner(h.seg)
	return nil
}

// shmReaderHandle is a reader's fd-table resource. Close drops one reference; the
// buffer survives until the last one goes.
type shmReaderHandle struct {
	closedFlag
	seg *shmSegment
}

// Kind names the handle in the fd table and in the console dump, distinctly from
// the owner's, so a dump shows which side of a shared buffer a module holds.
func (h *shmReaderHandle) Kind() string { return shmKindReader }

func (h *shmReaderHandle) Close() error {
	if !h.mark() {
		return errClosed
	}
	kshm.releaseReader(h.seg)
	return nil
}

// releaseOwner drops the owner's reference and withdraws the grants. Grants die
// with the owner rather than with the last reader: a peer that already mapped the
// buffer keeps its copy of the reference and may finish reading it, but no new
// mapping can be created for a buffer nobody owns.
func (p *shmPool) releaseOwner(seg *shmSegment) {
	p.mu.Lock()
	seg.grants = map[PID]struct{}{}
	if m := p.byOwner[seg.owner]; m != nil {
		delete(m, seg.id)
		if len(m) == 0 {
			delete(p.byOwner, seg.owner)
		}
	}
	p.mu.Unlock()
	p.release(seg)
}

func (p *shmPool) releaseReader(seg *shmSegment) { p.release(seg) }

// release drops one reference and, at zero, zeroes the buffer and either caches it
// in the slab or drops it for the collector.
//
// Zeroing happens here and nowhere else, which is the whole kiommu guarantee in one
// place: a buffer cannot return to the slab unscrubbed, because the only path into
// the slab goes through this function. The scrub covers the class size, not the
// requested payload size, so bytes written past a payload's own length in an
// earlier life are cleared too.
//
// The segment is removed from the live registry and from its owner's index before
// the scrub, under the pool lock, so no allocation and no map can reach it while it
// is being zeroed.
func (p *shmPool) release(seg *shmSegment) {
	p.mu.Lock()
	seg.refs--
	if seg.refs > 0 {
		p.mu.Unlock()
		return
	}
	delete(p.live, seg.id)
	p.dropOwnerIndexLocked(seg)
	p.mu.Unlock()

	// The scrub runs outside the registry lock. Nothing can reach this segment any
	// more, and zeroing a large buffer is the slowest part of a release, so doing
	// it under the pool lock would make one module's teardown stall every other
	// module's allocation.
	seg.mu.Lock()
	buf := seg.data
	clear(buf)
	seg.data = nil
	seg.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.zeroed++
	// The cache yields to demand. A cached buffer is memory the kernel holds for
	// speed alone, so it stays inside the pool accounting only while there is room
	// below the cache's own share of the ceiling; past that the class is handed
	// back and the pool shrinks.
	room := Limits().MaxSharedBytes/shmCacheShare - p.cached
	if len(buf) > 0 && len(p.cache[seg.class]) < shmCachePerClass && seg.class <= room {
		p.cache[seg.class] = append(p.cache[seg.class], buf)
		p.cached += seg.class
		return
	}
	p.pool -= seg.class
}

// dropOwnerIndexLocked removes a segment from its owner's index. Caller holds p.mu.
func (p *shmPool) dropOwnerIndexLocked(seg *shmSegment) {
	m := p.byOwner[seg.owner]
	if m == nil {
		return
	}
	delete(m, seg.id)
	if len(m) == 0 {
		delete(p.byOwner, seg.owner)
	}
}

// take obtains a class-sized buffer, from the slab if one is idle there and from
// the collector otherwise, keeping the pool inside MaxSharedBytes.
//
// An idle buffer is already counted in pool, because release leaves it there. So
// reuse moves bytes from cached to live and costs the pool nothing, while a fresh
// buffer is the only case that has to fit under the ceiling. Charging reuse again
// would make the ceiling bind twice on the same memory and refuse allocations the
// pool has room for.
func (p *shmPool) take(c *sContext, class int64) ([]byte, error) {
	limit := Limits().MaxSharedBytes

	buf, refused := p.reserve(c.pid, class, limit)
	if refused != nil {
		// The fault is emitted with no pool lock held. The console takes its own
		// lock, and a diagnostic path that has to acquire a subsystem lock is a
		// deadlock waiting for the day the console wants to report subsystem state.
		fault(c, "shared buffer allocation refused by quota", map[string]any{
			"module": c.name, "size": refused.Size, "limit": refused.Limit, "in_use": refused.InUse,
		})
		return nil, refused
	}
	return buf, nil
}

// reserve takes a class-sized buffer out of the pool, or returns the typed quota
// error explaining why it could not. It is split from take so the fault is emitted
// without the pool lock held.
func (p *shmPool) reserve(owner PID, class int64, limit int64) ([]byte, *ShmQuotaError) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if idle := p.cache[class]; len(idle) > 0 {
		// A cached buffer was zeroed on its way in, so reusing it does not carry the
		// previous tenant's bytes. That ordering is the whole guarantee: taking a
		// buffer that was not scrubbed on release would make the slab a leak
		// between modules.
		buf := idle[len(idle)-1]
		p.cache[class] = idle[:len(idle)-1]
		if len(p.cache[class]) == 0 {
			delete(p.cache, class)
		}
		p.cached -= class
		p.reused++
		return buf, nil
	}

	// Evict idle buffers before refusing a live one. The ceiling bounds how much
	// memory the pool holds, and the idle cache is the part of that holding nobody
	// is waiting on.
	for p.pool+class > limit && p.evictLocked() {
	}
	if p.pool+class > limit {
		err := &ShmQuotaError{Owner: owner, Size: class, Limit: limit, InUse: p.pool}
		p.refused++
		return nil, err
	}

	p.pool += class
	return make([]byte, class), nil
}

// evictLocked drops one idle buffer and reports whether it dropped anything, so
// the caller's eviction loop terminates when the cache is empty rather than
// spinning. Map order decides which class goes first, which is fine because any
// idle buffer is equally expendable. Caller holds p.mu.
func (p *shmPool) evictLocked() bool {
	for class, idle := range p.cache {
		if len(idle) == 0 {
			delete(p.cache, class)
			continue
		}
		p.cache[class] = idle[:len(idle)-1]
		if len(p.cache[class]) == 0 {
			delete(p.cache, class)
		}
		p.cached -= class
		p.pool -= class
		p.evicted++
		return true
	}
	return false
}

// shmClass rounds a requested size up to the next power of two at or above
// shmMinClass. Power-of-two classes are what make a slab cache hit: a class per
// distinct size would almost never find an idle buffer to reuse.
func shmClass(n int64) int64 {
	class := int64(shmMinClass)
	for class < n {
		class <<= 1
	}
	return class
}

// ShmDropNamespace withdraws every grant a module made and clears its owner
// index. It is the kernel-side half of an unload, called beside reclaimFDs.
//
// It deliberately does not touch reference counts. Each reference is owned by
// exactly one fd-table entry, so the handle walk is what drops them, and dropping
// them here as well would free a buffer twice if the two ran in the other order.
// What this function adds is the part the handle walk cannot know about: that a
// departing owner's grants must not survive it, because a peer mapping a buffer
// nobody owns is a mapping no one can revoke.
//
// It is therefore order-independent with reclaimFDs, which is the property that
// makes it safe to call from a teardown path that does not control the order.
func ShmDropNamespace(pid PID) {
	kshm.mu.Lock()
	defer kshm.mu.Unlock()
	for id := range kshm.byOwner[pid] {
		if seg, ok := kshm.live[id]; ok {
			seg.grants = map[PID]struct{}{}
		}
	}
	delete(kshm.byOwner, pid)
}

// resetShm clears the pool for a fresh boot. Buffers are not handed back to the
// slab here, they are dropped: a restart is the one moment where recycling speed
// is worth nothing and where carrying a previous boot's memory forward is worth
// refusing.
func resetShm() {
	kshm.mu.Lock()
	defer kshm.mu.Unlock()
	for _, seg := range kshm.live {
		seg.mu.Lock()
		clear(seg.data)
		seg.data = nil
		seg.mu.Unlock()
	}
	kshm.live = map[SHMID]*shmSegment{}
	kshm.byOwner = map[PID]map[SHMID]struct{}{}
	kshm.cache = map[int64][][]byte{}
	kshm.pool = 0
	kshm.cached = 0
	kshm.evicted = 0
	kshm.allocs = 0
	kshm.reused = 0
	kshm.refused = 0
	kshm.zeroed = 0
	kshm.nextID = 1
}

// ---------------------------------------------------------------------------
// Syscall wiring for the integrator. Add SyscallShm to the SContext group list in
// kernel/context.go, then paste the interface and methods beside the other groups.
//
//	type SyscallShm interface {
//		// SyscallShmAlloc allocates a shared buffer and returns a handle on it.
//		// Requires shm:alloc. The payload is written through SyscallShmWrite and
//		// never handed back as a slice.
//		SyscallShmAlloc(size int, label string) (ShmDescriptor, error)
//		// SyscallShmWrite copies bytes into a segment this context owns. Requires
//		// shm:alloc, and refuses a sealed segment.
//		SyscallShmWrite(fd FD, offset int, p []byte) (int, error)
//		// SyscallShmRead copies bytes out of a segment this context owns or was
//		// granted. Requires shm:map.
//		SyscallShmRead(fd FD, offset int, dst []byte) (int, error)
//		// SyscallShmBytes returns a fresh copy of a segment's whole payload.
//		// Requires shm:map.
//		SyscallShmBytes(fd FD) ([]byte, error)
//		// SyscallShmSize reports a segment's payload size. Requires shm:map.
//		SyscallShmSize(fd FD) (int, error)
//		// SyscallShmGrant authorises one peer to map a segment, and seals it.
//		// Requires shm:alloc.
//		SyscallShmGrant(fd FD, peer PID) error
//		// SyscallShmMap maps a granted segment read-only. Requires shm:map and a
//		// grant from the owner.
//		SyscallShmMap(id SHMID, label string) (ShmMapping, error)
//		// SyscallShmSeal makes this context's own segment immutable without
//		// granting it. Requires shm:alloc.
//		SyscallShmSeal(fd FD) error
//	}
//
//	func (c *sContext) SyscallShmAlloc(size int, label string) (ShmDescriptor, error) {
//		return ShmAlloc(c, size, label)
//	}
//	func (c *sContext) SyscallShmWrite(fd FD, offset int, p []byte) (int, error) {
//		return ShmWrite(c, fd, offset, p)
//	}
//	func (c *sContext) SyscallShmRead(fd FD, offset int, dst []byte) (int, error) {
//		return ShmRead(c, fd, offset, dst)
//	}
//	func (c *sContext) SyscallShmBytes(fd FD) ([]byte, error) { return ShmBytes(c, fd) }
//	func (c *sContext) SyscallShmSize(fd FD) (int, error)     { return ShmSize(c, fd) }
//	func (c *sContext) SyscallShmGrant(fd FD, peer PID) error { return ShmGrant(c, fd, peer) }
//	func (c *sContext) SyscallShmMap(id SHMID, label string) (ShmMapping, error) {
//		return ShmMap(c, id, label)
//	}
//	func (c *sContext) SyscallShmSeal(fd FD) error { return ShmSeal(c, fd) }
//
// UnloadModule in kernel/module.go must also call ShmDropNamespace(pid), beside
// the existing reclaimFDs(pid), so a segment's registry entry cannot outlive its
// owner.
// ---------------------------------------------------------------------------
