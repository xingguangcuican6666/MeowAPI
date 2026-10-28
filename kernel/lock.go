package kernel

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// klock: managed mutexes and read-write locks with mandatory timeouts (subsystem:
// klock, the analogue of a futex with a robustness flag).
//
// Why the kernel owns locks instead of letting modules use sync.Mutex: a mutex held
// by a module that dies is held forever. Every waiter behind it blocks until the
// process exits, and because the lock is invisible to the kernel there is nothing to
// report - the symptom is a gateway that stopped answering one route and a goroutine
// dump nobody can interpret. A kernel-managed lock has an owner pid, a deadline and
// a teardown path, so when the owner is unloaded the kernel releases the lock and
// wakes the waiters with a distinct error. Deadlock caused by a module that no
// longer exists becomes impossible by construction.
//
// Fairness is arrival order. Without it, one module hammering acquire can starve
// another that asked first, and the starved module's own deadline then fires, so the
// noisy module effectively controls the quiet one's latency. A FIFO queue removes
// that channel.
//
// An exclusive lock is NOT re-entrant, and every acquire goes through the queue. The
// kernel identifies a caller by pid and a pid is a module running many goroutines, so
// "the same pid already holds this" cannot tell a nested call on one goroutine from a
// second goroutine arriving concurrently. Granting the second one anyway hands one
// exclusive lock to two goroutines at once, which is not re-entrancy but the absence
// of mutual exclusion. A module that nests on one exclusive lock gets
// ErrLockTimeout at its deadline: a loud failure it can fix, rather than a silent
// hole that only appears under concurrency. Read locks may nest, because readers are
// concurrent by design and an extra read hold violates nothing.

// ErrLockTimeout is returned when the deadline passed before the lock was granted.
var ErrLockTimeout = errors.New("kernel: lock acquisition timed out")

// ErrLockOwnerGone is returned to waiters when the lock's owner was unloaded,
// panicked or terminated while holding it. It is distinct from a timeout because the
// correct responses differ: a timeout means retry or shed load, a dead owner means
// the work that was being serialized is gone and the waiter should fail its request
// rather than assume the critical section completed.
var ErrLockOwnerGone = errors.New("kernel: lock owner terminated")

// maxLocksPerModule bounds how many locks one module may hold at once.
const maxLocksPerModule = 256

// maxWaitersPerLock bounds the queue behind one lock, so a contended lock cannot
// become an unbounded goroutine pile.
const maxWaitersPerLock = 512

// lockState is one managed lock.
type lockState struct {
	mu sync.Mutex
	// cond wakes waiters. Every state change broadcasts, because a writer release
	// and a reader release are both relevant to both kinds of waiter.
	cond *sync.Cond

	name    string
	owner   PID
	held    bool
	readers map[PID]int
	// fifo is the arrival-ordered queue of waiting pids. Granting follows it, so
	// a module cannot starve another by retrying in a tight loop.
	fifo []PID
	// dead latches when the owner terminated while holding the lock. Waiters see
	// ErrLockOwnerGone rather than acquiring a lock whose critical section was
	// abandoned half-done.
	dead bool
	// taken and timedOut are counters for the operator.
	taken    int64
	timedOut int64
	fifoFull int64
}

func newLockState(name string) *lockState {
	l := &lockState{name: name, readers: map[PID]int{}}
	l.cond = sync.NewCond(&l.mu)
	return l
}

// lockRegistry indexes locks by name. Names are global, so two modules asking for
// "route-table" get the same lock, which is the point: they are serializing against
// each other.
type lockRegistry struct {
	mu    sync.RWMutex
	locks map[string]*lockState
	// held counts outstanding holds per pid per lock name, not a bool. A reader may
	// hold one name more than once, and a bool would lose the second hold on the
	// first release: unload would then walk a registry that no longer mentions it
	// and leave the lock held forever.
	held map[PID]map[string]int
}

var klocks = &lockRegistry{locks: map[string]*lockState{}, held: map[PID]map[string]int{}}

func (r *lockRegistry) get(name string) *lockState {
	r.mu.RLock()
	l, ok := r.locks[name]
	r.mu.RUnlock()
	if ok {
		return l
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if l, ok := r.locks[name]; ok {
		return l
	}
	l = newLockState(name)
	r.locks[name] = l
	return l
}

// LockHandle is the fd-table resource for a held lock. Closing it releases the lock.
type lockHandle struct {
	closedFlag
	name string
	pid  PID
}

// Kind names the resource for the fd table and the dump.
func (h *lockHandle) Kind() string { return "lock" }

// Close releases the lock. Idempotent, so reclamation during unload can run after an
// explicit release without double-releasing.
func (h *lockHandle) Close() error {
	if !h.mark() {
		return errClosed
	}
	klocks.release(h.name, h.pid)
	return nil
}

// acquire takes the lock for pid, waiting until deadline. exclusive requests a write
// lock; otherwise a read lock is taken, and multiple readers may hold it at once.
func (r *lockRegistry) acquire(ctx *sContext, name string, exclusive bool, deadline int64) (FD, error) {
	pid := ctx.pid
	l := r.get(name)

	l.mu.Lock()

	if l.dead {
		l.mu.Unlock()
		return noFD, fmt.Errorf("%w: lock %q", ErrLockOwnerGone, name)
	}

	// Per-module ceiling on distinct held locks. Checked before queueing, so a
	// module that leaks locks fails fast rather than occupying a queue slot.
	r.mu.RLock()
	heldCount := len(r.held[pid])
	r.mu.RUnlock()
	if heldCount >= maxLocksPerModule {
		l.mu.Unlock()
		// Attributed to the calling context rather than to nothing. A ceiling
		// refusal that reports pid 0 is a ceiling refusal an operator cannot act
		// on: the fault record has to say which module leaked its locks.
		fault(ctx, "lock ceiling reached", map[string]any{
			"pid": pid, "max_locks_per_module": maxLocksPerModule,
		})
		return noFD, fmt.Errorf("kernel: pid %d holds the maximum of %d locks", pid, maxLocksPerModule)
	}

	// There is deliberately no re-entrant shortcut here, and removing one is the
	// fix rather than a simplification.
	//
	// The kernel identifies a caller by pid. A pid is a module, and a module runs
	// many goroutines, so "the same pid already holds this" cannot distinguish a
	// nested call on one goroutine from a second goroutine arriving concurrently.
	// Granting the second one anyway - which is what a re-entrant branch does -
	// hands the same exclusive lock to two goroutines at once. That is not
	// re-entrancy, it is the absence of mutual exclusion, and it fails only under
	// concurrency, which is the one condition a lock exists for.
	//
	// So every acquire goes through the queue. A module whose call graph nests on
	// one exclusive lock gets ErrLockTimeout at its deadline instead of a grant: a
	// loud failure the author can fix by restructuring or by using a second lock
	// name. That is the same tradeoff POSIX makes for a recursive lock on a
	// non-recursive mutex, and it is only survivable because deadlines here are
	// mandatory rather than optional.
	//
	// A reader may still take a second hold on the same name, through the queue:
	// readers are concurrent by design, so an extra read hold violates nothing. It
	// queues rather than bypassing, so it cannot starve a writer waiting behind it.
	// The consequence is the classic one - a reader that re-acquires while a writer
	// waits will block until its deadline - and it is a real deadlock in the
	// module's own logic, surfaced rather than hidden.

	// Queue in arrival order. Appending before the wait loop rather than after a
	// failed attempt is what makes the order real: a waiter that retries in a tight
	// loop does not get to the front of a queue it has been standing in.
	l.fifo = append(l.fifo, pid)
	if len(l.fifo) > maxWaitersPerLock {
		l.fifo = l.fifo[:len(l.fifo)-1]
		l.fifoFull++
		l.mu.Unlock()
		return noFD, fmt.Errorf("kernel: lock %q has the maximum of %d waiters", name, maxWaitersPerLock)
	}

	for {
		canTake := false
		if l.dead {
			l.mu.Unlock()
			return noFD, fmt.Errorf("%w: lock %q", ErrLockOwnerGone, name)
		}
		if exclusive {
			canTake = !l.held && len(l.readers) == 0 && l.frontOfQueue(pid)
		} else {
			canTake = !l.held && l.frontOfQueue(pid)
		}
		if canTake {
			l.leaveQueue(pid)
			if exclusive {
				l.held = true
				l.owner = pid
			} else {
				l.readers[pid]++
			}
			l.taken++
			l.cond.Broadcast()
			l.mu.Unlock()

			r.recordHold(pid, name, 1)
			return r.install(name, pid)
		}

		if deadline > 0 && kclock.Expired(deadline) {
			l.leaveQueue(pid)
			l.timedOut++
			l.cond.Broadcast()
			l.mu.Unlock()
			return noFD, fmt.Errorf("%w: %q after %d waiters", ErrLockTimeout, name, len(l.fifo))
		}
		if deadline > 0 {
			waitWithDeadline(l.cond, deadline)
		} else {
			l.cond.Wait()
		}
	}
}

// frontOfQueue reports whether pid is the first un-served waiter.
//
// Returning false when another pid is ahead is the whole fairness guarantee. A
// waiter that is not in the queue at all - because it already left - returns true so
// its loop re-evaluates instead of waiting on a position it no longer holds.
func (l *lockState) frontOfQueue(pid PID) bool {
	if len(l.fifo) == 0 {
		return true
	}
	return l.fifo[0] == pid
}

func (l *lockState) leaveQueue(pid PID) {
	out := l.fifo[:0]
	left := false
	for _, w := range l.fifo {
		if w == pid && !left {
			left = true
			continue
		}
		out = append(out, w)
	}
	l.fifo = out
}

// install registers the lock handle in the owning pid's table. install already
// scopes the handle to that pid, which is what makes it untransferable.
func (r *lockRegistry) install(name string, pid PID) (FD, error) {
	return install(pid, &lockHandle{name: name, pid: pid}, name)
}

// release drops one hold of the lock by pid and wakes the next waiter.
func (r *lockRegistry) release(name string, pid PID) {
	r.mu.RLock()
	l, ok := r.locks[name]
	r.mu.RUnlock()
	if !ok {
		return
	}

	l.mu.Lock()
	if l.dead {
		l.mu.Unlock()
		return
	}
	if n := l.readers[pid]; n > 0 {
		l.readers[pid] = n - 1
		if l.readers[pid] == 0 {
			delete(l.readers, pid)
		}
	} else if l.held && l.owner == pid {
		l.held = false
		l.owner = 0
	} else {
		l.mu.Unlock()
		return
	}

	r.recordHold(pid, name, -1)

	l.cond.Broadcast()
	l.mu.Unlock()
}

// recordHold adjusts the outstanding-hold count for one pid and lock name by delta,
// dropping the entries when they reach zero so the registry does not grow without
// bound across a long run.
func (r *lockRegistry) recordHold(pid PID, name string, delta int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.held[pid]
	if delta > 0 && m == nil {
		m = map[string]int{}
		r.held[pid] = m
	}
	if m == nil {
		return
	}
	m[name] += delta
	if m[name] <= 0 {
		delete(m, name)
	}
	if len(m) == 0 {
		delete(r.held, pid)
	}
}

// releaseAll drops every lock a pid holds. Called from the unload path, so a module
// that dies holding locks cannot strand its waiters.
func (r *lockRegistry) releaseAll(pid PID) {
	r.mu.Lock()
	type hold struct {
		name string
		n    int
	}
	var holds []hold
	for n, count := range r.held[pid] {
		holds = append(holds, hold{n, count})
	}
	delete(r.held, pid)
	r.mu.Unlock()

	// Once per outstanding hold, not once per name: a holder that took the lock n
	// times must give it back n times, or the lock stays held by a pid that no
	// longer exists.
	for _, h := range holds {
		for range h.n {
			r.release(h.name, pid)
		}
	}
}

// markDead latches a lock whose owner terminated while holding it. Waiters get
// ErrLockOwnerGone rather than acquiring a lock whose critical section was
// abandoned, because the serialization they were waiting for did not complete.
func (r *lockRegistry) markDead(pid PID) {
	r.mu.Lock()
	names := make([]string, 0, len(r.held[pid]))
	for n := range r.held[pid] {
		names = append(names, n)
	}
	delete(r.held, pid)
	r.mu.Unlock()

	for _, n := range names {
		r.mu.RLock()
		l, ok := r.locks[n]
		r.mu.RUnlock()
		if !ok {
			continue
		}
		l.mu.Lock()
		l.dead = true
		l.held = false
		l.owner = 0
		delete(l.readers, pid)
		l.cond.Broadcast()
		l.mu.Unlock()

		kaudit.record(AuditEscalation, nil, "lock owner terminated while holding", map[string]any{
			"lock": n, "pid": pid,
		})
	}
}

// SyscallLock is the lock half of the syscall surface.
type SyscallLock interface {
	// SyscallLockTake acquires a named lock and returns the handle that owns it.
	// Requires lock:acquire. The deadline is mandatory: an untimed lock wait is
	// how a module turns a contended lock into an outage.
	SyscallLockTake(name string, exclusive bool, deadline int64) (FD, error)
	// SyscallLockRelease releases a lock handle this context holds.
	SyscallLockRelease(fd FD) error
}

// LockTake acquires a managed lock for a context.
func LockTake(ctx SContext, name string, exclusive bool, deadline int64) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	if err := c.syscall(OpLockTake); err != nil {
		return noFD, err
	}
	if name == "" {
		return noFD, errors.New("kernel: a lock requires a name")
	}
	if deadline <= 0 {
		// An untimed wait is refused rather than defaulted. A module that wants a
		// long wait asks for one explicitly, so the choice is visible in the code
		// that made it.
		return noFD, errors.New("kernel: lock acquisition requires a deadline on the monotonic clock")
	}
	return klocks.acquire(c, name, exclusive, deadline)
}

func (c *sContext) SyscallLockTake(name string, exclusive bool, deadline int64) (FD, error) {
	return LockTake(c, name, exclusive, deadline)
}

func (c *sContext) SyscallLockRelease(fd FD) error {
	if err := c.syscall(""); err != nil {
		return err
	}
	e, err := lookup(c.pid, fd)
	if err != nil {
		return err
	}
	if e.kind != "lock" {
		return fmt.Errorf("kernel: fd %d is a %s, not a lock", fd, e.kind)
	}
	return closeFD(c.pid, fd)
}

// LockInfo describes one lock for the dump. It reports ownership and queue depth,
// never what is being protected.
type LockInfo struct {
	Name     string `json:"name"`
	Held     bool   `json:"held"`
	Owner    PID    `json:"owner"`
	Readers  int    `json:"readers"`
	Waiters  int    `json:"waiters"`
	Dead     bool   `json:"dead"`
	Taken    int64  `json:"taken"`
	TimedOut int64  `json:"timed_out"`
}

// LockSnapshot lists every lock, sorted by name.
func LockSnapshot() []LockInfo {
	klocks.mu.RLock()
	names := make([]string, 0, len(klocks.locks))
	for n := range klocks.locks {
		names = append(names, n)
	}
	klocks.mu.RUnlock()
	sort.Strings(names)

	out := make([]LockInfo, 0, len(names))
	for _, n := range names {
		l := klocks.get(n)
		l.mu.Lock()
		out = append(out, LockInfo{
			Name: n, Held: l.held, Owner: l.owner, Readers: len(l.readers),
			Waiters: len(l.fifo), Dead: l.dead, Taken: l.taken, TimedOut: l.timedOut,
		})
		l.mu.Unlock()
	}
	return out
}

// resetLocks clears the registry. Called only from resetKernel.
func resetLocks() {
	klocks.mu.Lock()
	defer klocks.mu.Unlock()
	klocks.locks = map[string]*lockState{}
	klocks.held = map[PID]map[string]int{}
}
