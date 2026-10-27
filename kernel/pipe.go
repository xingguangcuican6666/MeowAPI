package kernel

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// kpipe is zero-trust streaming between modules (subsystem: kpipe, the analogue of
// a pipe or a Binder transaction).
//
// The isolation property is that data crosses as bytes and never as a Go value. A
// module that could hand another module a slice, a map or an interface would be
// handing it a live reference into its own heap: the receiver could retain it,
// mutate it after the sender moved on, or pass it onward to a third module that was
// never granted anything. Copying at both ends is what makes the boundary a
// boundary. The cost is a copy per chunk, which is the correct thing to pay.
//
// Both ends are fd-table resources, so unloading either module closes the pipe and
// the peer sees end-of-stream rather than blocking forever on a partner that no
// longer exists. That is the property that makes a hung adapter survivable.

// ErrPipeClosed is returned by reads and writes on a closed pipe. It is distinct
// from ErrNoSlot and from a policy denial so a streaming loop can tell "the peer is
// gone, finish the response" from "I am not allowed to do this".
var ErrPipeClosed = errors.New("kernel: pipe closed")

// ErrPipeFull is returned by a non-blocking write to a full pipe. A blocking write
// waits instead, up to the caller's deadline.
var ErrPipeFull = errors.New("kernel: pipe buffer full")

// PipeMode selects what a full buffer does.
type PipeMode int

const (
	// PipeBlocking makes a full write wait until space appears, the deadline
	// arrives, or the pipe closes. This is the mode a streaming response wants:
	// backpressure propagates to the producer instead of dropping its output.
	PipeBlocking PipeMode = iota
	// PipeNonBlocking makes a full write fail immediately with ErrPipeFull. This
	// is the mode a telemetry producer wants: losing a metric is better than
	// stalling a request.
	PipeNonBlocking
)

// defaultPipeBuffer is the byte ceiling per pipe when the opener does not set one.
// It is small on purpose: a pipe is a streaming channel, not a buffer for a whole
// response, and a module that needs more asks for more explicitly.
const defaultPipeBuffer = 64 * 1024

// maxPipeBuffer caps what an opener may request, so a module cannot allocate an
// arbitrarily large buffer per pipe and then open many pipes.
const maxPipeBuffer = 16 * 1024 * 1024

// maxPipesPerModule bounds how many pipes one module may hold open.
const maxPipesPerModule = 256

// pipeChunk is one queued message. It is always a fresh allocation, never a slice
// of a caller's buffer.
type pipeChunk struct {
	data []byte
	// aborted marks a stream-abort signal carried inline, so a reader learns the
	// client disconnected without needing a separate channel.
	aborted bool
}

// pipe is one duplex channel between two pids.
type pipe struct {
	mu sync.Mutex
	// cond signals both readers and writers. One condition variable is correct
	// here because every state change (data queued, data drained, closed, aborted)
	// is relevant to both sides.
	cond *sync.Cond

	name   string
	owner  PID
	peer   PID
	cap    int
	buf    int
	queue  []pipeChunk
	closed bool
	// abort is set by Abort and stays set: a stream that was cancelled stays
	// cancelled, because the alternative is a race where the abort is delivered
	// once and a slow reader misses it.
	abort bool

	// counters for the operator.
	written   int64
	readCount int64
	dropped   int64
	aborts    int64

	mode PipeMode
}

// Kind names the resource for the fd table.
func (p *pipe) Kind() string { return "pipe" }

// Close closes both ends. Idempotent, and safe to call from reclamation after an
// explicit close.
func (p *pipe) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errClosed
	}
	p.closed = true
	p.queue = nil
	p.mu.Unlock()

	// Drop the registry entry with the pipe. It is keyed by (pid, fd) and pids are
	// never reused, so an entry left behind is unreachable garbage that
	// PipeStatsSnapshot keeps reporting: an operator would see a pipe whose owner
	// has been gone since the last restart.
	kpipes.remove(p)

	// Broadcast outside the state change so every blocked reader and writer wakes
	// and sees closed rather than waiting on a condition that will never fire.
	p.cond.Broadcast()
	return nil
}

func newPipe(name string, owner, peer PID, capacity int, mode PipeMode) *pipe {
	if capacity <= 0 {
		capacity = defaultPipeBuffer
	}
	if capacity > maxPipeBuffer {
		capacity = maxPipeBuffer
	}
	p := &pipe{name: name, owner: owner, peer: peer, cap: capacity, mode: mode}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// write enqueues one chunk. It always copies, so the caller may reuse or free its
// buffer immediately and cannot be observed mutating data already in flight.
func (p *pipe) write(data []byte, deadline int64) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	// A single chunk larger than the whole buffer can never be admitted by a
	// blocking write, so refuse it up front rather than deadlocking until the
	// deadline.
	if len(data) > p.cap {
		return 0, fmt.Errorf("kernel: chunk of %d bytes exceeds the pipe capacity of %d", len(data), p.cap)
	}

	chunk := pipeChunk{data: append([]byte(nil), data...)}

	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		if p.closed {
			return 0, ErrPipeClosed
		}
		if p.abort {
			return 0, ErrPipeClosed
		}
		if p.buf+len(chunk.data) <= p.cap {
			p.queue = append(p.queue, chunk)
			p.buf += len(chunk.data)
			p.written++
			p.cond.Broadcast()
			return len(data), nil
		}
		if p.mode == PipeNonBlocking {
			p.dropped++
			return 0, ErrPipeFull
		}
		if deadline > 0 && kclock.Expired(deadline) {
			return 0, fmt.Errorf("%w: write deadline passed", ErrPipeFull)
		}
		if deadline > 0 {
			waitWithDeadline(p.cond, deadline)
		} else {
			p.cond.Wait()
		}
	}
}

// read dequeues one chunk and returns a copy, so the reader cannot hold a
// reference into the pipe's queue after the call returns.
func (p *pipe) read(deadline int64) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		if len(p.queue) > 0 {
			c := p.queue[0]
			p.queue = p.queue[1:]
			p.buf -= len(c.data)
			p.readCount++
			p.cond.Broadcast()
			if c.aborted {
				return nil, ErrPipeClosed
			}
			return append([]byte(nil), c.data...), nil
		}
		if p.abort {
			return nil, ErrPipeClosed
		}
		// Closed with nothing queued is end-of-stream, which a reader must be able
		// to distinguish from a transient empty buffer. io.EOF semantics.
		if p.closed {
			return nil, ErrPipeClosed
		}
		if deadline > 0 && kclock.Expired(deadline) {
			return nil, fmt.Errorf("%w: read deadline passed", ErrPipeClosed)
		}
		if deadline > 0 {
			waitWithDeadline(p.cond, deadline)
		} else {
			p.cond.Wait()
		}
	}
}

// abort signals that the stream should stop, for example because the client
// disconnected. It is latching and it wakes both ends.
func (p *pipe) abortStream() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	if p.abort {
		p.aborts++
		p.mu.Unlock()
		return
	}
	p.abort = true
	p.aborts++
	p.queue = nil
	p.buf = 0
	p.mu.Unlock()
	p.cond.Broadcast()
}

// PipeInfo describes an open pipe for the dump. It reports byte counts, never
// content, because a pipe carries prompts and completions.
type PipeInfo struct {
	FD       FD     `json:"fd"`
	Name     string `json:"name"`
	Owner    PID    `json:"owner"`
	Peer     PID    `json:"peer"`
	Cap      int    `json:"capacity"`
	Buffered int    `json:"buffered"`
	Queued   int    `json:"queued"`
	Written  int64  `json:"written"`
	Read     int64  `json:"read"`
	Dropped  int64  `json:"dropped"`
	Closed   bool   `json:"closed"`
	Aborted  bool   `json:"aborted"`
}

func (p *pipe) info(fd FD) PipeInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PipeInfo{
		FD: fd, Name: p.name, Owner: p.owner, Peer: p.peer, Cap: p.cap,
		Buffered: p.buf, Queued: len(p.queue), Written: p.written, Read: p.readCount,
		Dropped: p.dropped, Closed: p.closed, Aborted: p.abort,
	}
}

// pipeRegistry indexes open pipes so the console dump can list them and so a peer
// can be resolved by name without either module holding a reference to the other.
type pipeRegistry struct {
	mu    sync.RWMutex
	byFD  map[fdRef]*pipe
	count map[PID]int
}

type fdRef struct {
	pid PID
	fd  FD
}

var kpipes = &pipeRegistry{byFD: map[fdRef]*pipe{}, count: map[PID]int{}}

func (r *pipeRegistry) add(pid PID, fd FD, p *pipe) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byFD[fdRef{pid, fd}] = p
	r.count[pid]++
}

// remove drops every registry entry pointing at one pipe. It matches on the pipe
// rather than on an fd because the resource's Close does not know which fd it was
// installed under, and a peer may hold a second entry for the same pipe.
func (r *pipeRegistry) remove(p *pipe) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ref, cur := range r.byFD {
		if cur != p {
			continue
		}
		delete(r.byFD, ref)
		if r.count[ref.pid] > 0 {
			r.count[ref.pid]--
			if r.count[ref.pid] == 0 {
				delete(r.count, ref.pid)
			}
		}
	}
}

// removePID drops every pipe a pid registered, for the unload path. The fd table
// closes each resource, which removes its own entries; this is the backstop for a
// registry entry whose resource was never installed in a table, and it keeps the
// per-pid count from outliving the module.
func (r *pipeRegistry) removePID(pid PID) {
	// Collect under the lock, close outside it. Close calls remove, which locks the
	// same mutex, so closing here would deadlock the unload path on the first pipe.
	r.mu.Lock()
	var doomed []*pipe
	seen := map[*pipe]bool{}
	for ref, p := range r.byFD {
		if ref.pid != pid || seen[p] {
			continue
		}
		seen[p] = true
		doomed = append(doomed, p)
		delete(r.byFD, ref)
	}
	delete(r.count, pid)
	r.mu.Unlock()

	for _, p := range doomed {
		_ = p.Close()
	}
}

func (r *pipeRegistry) get(pid PID, fd FD) (*pipe, error) {
	r.mu.RLock()
	p, ok := r.byFD[fdRef{pid, fd}]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("kernel: fd %d is not an open pipe in pid %d", fd, pid)
	}
	return p, nil
}

// PipeStatsSnapshot lists every open pipe, for the dump.
func PipeStatsSnapshot() []PipeInfo {
	kpipes.mu.RLock()
	refs := make([]fdRef, 0, len(kpipes.byFD))
	pipes := make([]*pipe, 0, len(kpipes.byFD))
	for k, p := range kpipes.byFD {
		refs = append(refs, k)
		pipes = append(pipes, p)
	}
	kpipes.mu.RUnlock()

	out := make([]PipeInfo, 0, len(refs))
	for i := range refs {
		out = append(out, pipes[i].info(refs[i].fd))
	}
	sortPipeInfos(out)
	return out
}

func sortPipeInfos(in []PipeInfo) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && lessPipeInfo(in[j], in[j-1]); j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

func lessPipeInfo(a, b PipeInfo) bool {
	if a.Owner != b.Owner {
		return a.Owner < b.Owner
	}
	return a.FD < b.FD
}

// SyscallPipe is the pipe half of the syscall surface.
type SyscallPipe interface {
	// SyscallOpenPipe creates a pipe and returns the owner's handle. Requires
	// pipe:open. Capacity is clamped to the kernel maximum.
	SyscallOpenPipe(name string, capacity int, mode PipeMode) (FD, error)
	// SyscallPipeWrite enqueues one chunk, always as a copy. Requires pipe:write.
	SyscallPipeWrite(fd FD, data []byte, deadline int64) (int, error)
	// SyscallPipeRead dequeues one chunk, always as a copy. Requires pipe:read.
	SyscallPipeRead(fd FD, deadline int64) ([]byte, error)
	// SyscallPipeAbort signals the stream to stop, for a client disconnect.
	// Requires pipe:write. Latching: once aborted, a pipe stays aborted.
	SyscallPipeAbort(fd FD) error
	// SyscallPipeInfo describes a pipe this context owns, without its content.
	SyscallPipeInfo(fd FD) (PipeInfo, error)
}

// OpenPipe creates a pipe owned by ctx. The returned handle is valid only in ctx's
// table, which is what makes it untransferable.
func OpenPipe(ctx SContext, name string, capacity int, mode PipeMode) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	if err := c.syscall(OpPipeOpen); err != nil {
		return noFD, err
	}
	if name == "" {
		return noFD, errors.New("kernel: a pipe requires a name")
	}

	kpipes.mu.RLock()
	held := kpipes.count[c.pid]
	kpipes.mu.RUnlock()
	if held >= maxPipesPerModule {
		fault(c, "pipe ceiling reached", map[string]any{
			"module": c.name, "max_pipes_per_module": maxPipesPerModule,
		})
		return noFD, fmt.Errorf("kernel: pid %d holds the maximum of %d pipes", c.pid, maxPipesPerModule)
	}

	p := newPipe(name, c.pid, 0, capacity, mode)
	fd, err := install(c.pid, p, name)
	if err != nil {
		return noFD, err
	}
	kpipes.add(c.pid, fd, p)
	kconsole.Emit(LogDebug, c.pid, c.dom, "pipe opened", map[string]any{
		"name": name, "capacity": p.cap, "mode": mode,
	})
	return fd, nil
}

func (c *sContext) SyscallOpenPipe(name string, capacity int, mode PipeMode) (FD, error) {
	return OpenPipe(c, name, capacity, mode)
}

func (c *sContext) SyscallPipeWrite(fd FD, data []byte, deadline int64) (int, error) {
	if err := c.syscall(OpPipeWrite); err != nil {
		return 0, err
	}
	p, err := kpipes.get(c.pid, fd)
	if err != nil {
		return 0, err
	}
	if p.owner != c.pid && p.peer != c.pid {
		return 0, fmt.Errorf("kernel: pid %d may not write to fd %d", c.pid, fd)
	}
	return p.write(data, deadline)
}

func (c *sContext) SyscallPipeRead(fd FD, deadline int64) ([]byte, error) {
	if err := c.syscall(OpPipeRead); err != nil {
		return nil, err
	}
	p, err := kpipes.get(c.pid, fd)
	if err != nil {
		return nil, err
	}
	if p.owner != c.pid && p.peer != c.pid {
		return nil, fmt.Errorf("kernel: pid %d may not read from fd %d", c.pid, fd)
	}
	return p.read(deadline)
}

func (c *sContext) SyscallPipeAbort(fd FD) error {
	if err := c.syscall(OpPipeWrite); err != nil {
		return err
	}
	p, err := kpipes.get(c.pid, fd)
	if err != nil {
		return err
	}
	p.abortStream()
	kaudit.record(AuditRequest, c, "stream aborted", map[string]any{
		"pipe": p.name, "fd": fd,
	})
	return nil
}

func (c *sContext) SyscallPipeInfo(fd FD) (PipeInfo, error) {
	if err := c.syscall(""); err != nil {
		return PipeInfo{}, err
	}
	p, err := kpipes.get(c.pid, fd)
	if err != nil {
		return PipeInfo{}, err
	}
	return p.info(fd), nil
}

// DropPipesFor closes every pipe a pid registered and forgets it. Called from the
// unload path as a backstop: the fd table already closed each resource, which woke
// both ends, and this clears any registry entry that survived.
func DropPipesFor(pid PID) { kpipes.removePID(pid) }

// waitWithDeadline waits on a condition variable until it is signalled or the
// deadline passes. sync.Cond has no timed wait, so this parks a watcher goroutine
// that broadcasts when the deadline arrives, and exits on the first broadcast after
// it fires so the watcher cannot outlive the wait.
//
// The remaining time is `deadline - mono()`, not an Elapsed() reading. Elapsed
// measures how long has passed SINCE a mark, so applied to a future deadline it
// returns a negative duration: a timer armed with that fires immediately, the
// broadcast wakes nobody because the waiter has not parked yet, and the waiter then
// blocks with no one left to wake it. Getting the direction of that subtraction wrong
// turns every timed wait into a hang, which is why the arithmetic is spelled out
// rather than composed from clock helpers.
//
// This is the one place the kernel spends a goroutine per waiting caller. It is
// bounded by the concurrency ceilings (krlimit slots and the fd ceiling), which is
// why those ceilings are enforced before a module can reach a blocking wait.
func waitWithDeadline(cond *sync.Cond, deadline int64) {
	remaining := deadline - mono()
	if remaining < 0 {
		remaining = 0
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		timer := time.NewTimer(time.Duration(remaining) + time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			cond.Broadcast()
		case <-done:
		}
	}()

	cond.Wait()
}

// resetPipes clears the registry. Called only from resetKernel.
//
// Live pipes are not closed here: reclamation during unload already closed them and
// woke their waiters. Closing them again would be harmless but would also mask a
// reclamation bug, and a registry that still holds entries after a full unload cycle
// is the evidence of one.
func resetPipes() {
	kpipes.mu.Lock()
	defer kpipes.mu.Unlock()
	kpipes.byFD = map[fdRef]*pipe{}
	kpipes.count = map[PID]int{}
}
