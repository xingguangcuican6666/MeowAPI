package kernel_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// chProbe is a module that runs one callback under its own context and keeps the
// context, so a test can drive several calls after the load completes.
type chProbe struct {
	run func(kernel.SContext) error
	ctx kernel.SContext
}

func (m *chProbe) OnLoad(ctx kernel.SContext) error {
	m.ctx = ctx
	if m.run == nil {
		return nil
	}
	return m.run(ctx)
}
func (m *chProbe) OnUnload() error { return nil }

var chCounter int

// chLoad registers and loads a module with the given grants, returning its pid and
// instance.
func chLoad(t *testing.T, k *kernel.Kernel, run func(kernel.SContext) error, ops ...kernel.Op) (kernel.PID, *chProbe) {
	t.Helper()
	chCounter++
	name := "ch" + itoa(chCounter)
	m := &chProbe{run: run}
	kernel.Register(name, func() (kernel.Module, error) { return m, nil })
	defer kernel.Unregister(name)

	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: ops,
	})
	require.NoError(t, err)
	return pid, m
}

// ---------------------------------------------------------------------------
// kpipe

// TestPipeRequiresGrants is the denial half, and it covers all three operations
// because a grant with no denial test is an untested grant.
func TestPipeRequiresGrants(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	var openErr error
	pid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		_, err := ctx.SyscallOpenPipe("denied", 0, kernel.PipeNonBlocking)
		openErr = err
		return nil
	}, kernel.OpLogWrite)
	defer func() { _ = k.Unload(pid) }()

	// Once the open is denied there is no handle to write or read through, so the
	// assertion is on the open and on nothing else.
	require.Error(t, openErr)
	assert.True(t, kernel.IsDenied(openErr))
	assert.Contains(t, openErr.Error(), "pipe:open")
	assert.Contains(t, buf.String(), "avc: denied { pipe:open }")

	denials := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial})
	assert.NotEmpty(t, denials, "a denied open must reach the audit chain")
}

// TestPipeWriteAndReadRequireTheirOwnGrants covers the other two operations, each
// through a module that holds pipe:open but not the operation under test, so the
// denial names the operation that was actually missing.
func TestPipeWriteAndReadRequireTheirOwnGrants(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	var writeErr, readErr error
	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("grants", 0, kernel.PipeNonBlocking)
	require.NoError(t, err)

	_, writeErr = m.ctx.SyscallPipeWrite(fd, []byte("x"), 0)
	require.Error(t, writeErr)
	assert.True(t, kernel.IsDenied(writeErr))
	assert.Contains(t, writeErr.Error(), "pipe:write")

	_, readErr = m.ctx.SyscallPipeRead(fd, 0)
	require.Error(t, readErr)
	assert.True(t, kernel.IsDenied(readErr))
	assert.Contains(t, readErr.Error(), "pipe:read")

	assert.Contains(t, buf.String(), "avc: denied { pipe:write }")
	assert.Contains(t, buf.String(), "avc: denied { pipe:read }")
}

// TestPipeCarriesBytesNotReferences is the isolation property the whole design rests
// on. A module that could hand another module a slice would be handing it a live
// reference into its own heap.
func TestPipeCarriesBytesNotReferences(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	sent := []byte("original-payload")
	var got []byte
	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("copy-check", 0, kernel.PipeBlocking)
	require.NoError(t, err)

	n, err := m.ctx.SyscallPipeWrite(fd, sent, 0)
	require.NoError(t, err)
	assert.Equal(t, len(sent), n)

	// Mutating the sender's buffer after the write must not change what the reader
	// receives. This is the assertion that would fail if the pipe handed over a
	// slice instead of a copy.
	copy(sent, "MUTATED-MUTATED!")

	got, err = m.ctx.SyscallPipeRead(fd, 0)
	require.NoError(t, err)
	assert.Equal(t, "original-payload", string(got))

	// And mutating what the reader received must not affect the pipe either, which
	// is the same guarantee in the other direction.
	got[0] = 'X'
	_, err = m.ctx.SyscallPipeWrite(fd, []byte("second"), 0)
	require.NoError(t, err)
	second, err := m.ctx.SyscallPipeRead(fd, 0)
	require.NoError(t, err)
	assert.Equal(t, "second", string(second))
}

// TestPipeNonBlockingRefusesWhenFull covers the backpressure choice. A telemetry
// producer wants to lose a metric rather than stall a request, and that requires a
// refusal the caller can recognize.
func TestPipeNonBlockingRefusesWhenFull(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("small", 16, kernel.PipeNonBlocking)
	require.NoError(t, err)

	_, err = m.ctx.SyscallPipeWrite(fd, []byte("0123456789abcdef"), 0)
	require.NoError(t, err)

	// The buffer is exactly full, so the next write must fail rather than block.
	_, err = m.ctx.SyscallPipeWrite(fd, []byte("one more"), 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrPipeFull)

	info, err := m.ctx.SyscallPipeInfo(fd)
	require.NoError(t, err)
	assert.Equal(t, 16, info.Cap)
	assert.Equal(t, 16, info.Buffered)
	assert.Equal(t, int64(1), info.Dropped)
	assert.Equal(t, int64(1), info.Written)

	// Draining makes room again, which is what proves the accounting is real rather
	// than a latch that stayed set.
	got, err := m.ctx.SyscallPipeRead(fd, 0)
	require.NoError(t, err)
	assert.Equal(t, "0123456789abcdef", string(got))

	_, err = m.ctx.SyscallPipeWrite(fd, []byte("fits now"), 0)
	assert.NoError(t, err)
}

// TestPipeChunkLargerThanCapacityIsRefused covers the deadlock case. A blocking
// write of a chunk that can never fit would wait forever, so it must be refused up
// front rather than at the deadline.
func TestPipeChunkLargerThanCapacityIsRefused(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("tiny", 8, kernel.PipeBlocking)
	require.NoError(t, err)

	start := time.Now()
	_, err = m.ctx.SyscallPipeWrite(fd, []byte("0123456789abcdef"), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the pipe capacity")
	assert.Less(t, time.Since(start), time.Second,
		"an impossible write must be refused immediately, not at a deadline")
}

// TestPipeBlockingWriteWaitsForTheReader is the positive half of the mode: a
// streaming response wants backpressure to propagate to the producer rather than to
// drop its output.
func TestPipeBlockingWriteWaitsForTheReader(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("stream", 4, kernel.PipeBlocking)
	require.NoError(t, err)
	_, err = m.ctx.SyscallPipeWrite(fd, []byte("abcd"), 0)
	require.NoError(t, err)

	written := make(chan error, 1)
	go func() {
		_, err := m.ctx.SyscallPipeWrite(fd, []byte("efgh"), 0)
		written <- err
	}()

	select {
	case err := <-written:
		t.Fatalf("a blocking write to a full pipe must wait, but returned: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Reading one chunk unblocks the writer.
	got, err := m.ctx.SyscallPipeRead(fd, 0)
	require.NoError(t, err)
	assert.Equal(t, "abcd", string(got))

	select {
	case err := <-written:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the writer was not woken after the reader drained a chunk")
	}
}

// TestPipeDeadlineIsOnTheKernelClock covers the read side of deadlines.
func TestPipeDeadlineIsOnTheKernelClock(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeRead, kernel.OpPipeWrite)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("idle", 0, kernel.PipeBlocking)
	require.NoError(t, err)

	deadline := kernel.KernelClock().Deadline(30 * time.Millisecond)
	start := time.Now()
	_, err = m.ctx.SyscallPipeRead(fd, deadline)
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrPipeClosed)
	assert.Contains(t, err.Error(), "deadline passed")
	assert.GreaterOrEqual(t, time.Since(start), 30*time.Millisecond,
		"the read must actually wait for the deadline rather than fail immediately")
	assert.Less(t, time.Since(start), 2*time.Second)
}

// TestPipeAbortIsLatching covers client-disconnect handling. A cancellation that can
// be missed is not a cancellation.
func TestPipeAbortIsLatching(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("client-stream", 0, kernel.PipeNonBlocking)
	require.NoError(t, err)
	_, err = m.ctx.SyscallPipeWrite(fd, []byte("partial"), 0)
	require.NoError(t, err)

	require.NoError(t, m.ctx.SyscallPipeAbort(fd))

	// Buffered data is dropped, and every subsequent operation reports the end of
	// the stream rather than delivering a partial response to a client that is gone.
	_, err = m.ctx.SyscallPipeRead(fd, 0)
	assert.ErrorIs(t, err, kernel.ErrPipeClosed)
	_, err = m.ctx.SyscallPipeWrite(fd, []byte("more"), 0)
	assert.ErrorIs(t, err, kernel.ErrPipeClosed)

	// Aborting twice is not an error and does not resurrect the pipe.
	assert.NoError(t, m.ctx.SyscallPipeAbort(fd))
	info, err := m.ctx.SyscallPipeInfo(fd)
	require.NoError(t, err)
	assert.True(t, info.Aborted)
	assert.Zero(t, info.Buffered)

	// The abort is on the audit chain, because a cancelled stream is a billing fact.
	found := false
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditRequest}) {
		if e.Msg == "stream aborted" && e.Fields["pipe"] == "client-stream" {
			found = true
		}
	}
	assert.True(t, found, "an abort must reach the audit chain")
}

// TestPipeAbortWakesABlockedReader covers the hang the abort exists to prevent.
func TestPipeAbortWakesABlockedReader(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("hang", 0, kernel.PipeBlocking)
	require.NoError(t, err)

	readErr := make(chan error, 1)
	go func() {
		_, err := m.ctx.SyscallPipeRead(fd, 0)
		readErr <- err
	}()

	select {
	case <-readErr:
		t.Fatal("a blocking read on an empty pipe must wait")
	case <-time.After(50 * time.Millisecond):
	}

	require.NoError(t, m.ctx.SyscallPipeAbort(fd))

	select {
	case err := <-readErr:
		assert.ErrorIs(t, err, kernel.ErrPipeClosed,
			"the abort must wake the reader rather than leave it blocked forever")
	case <-time.After(2 * time.Second):
		t.Fatal("the blocked reader was not woken by the abort")
	}
}

// TestPipeHandlesArePerPid is the capability property: an integer is not a
// capability until it is scoped to a table.
func TestPipeHandlesArePerPid(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	ownerPid, owner := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(ownerPid) }()

	fd, err := owner.ctx.SyscallOpenPipe("mine", 0, kernel.PipeNonBlocking)
	require.NoError(t, err)

	thiefPid, thief := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(thiefPid) }()

	_, err = thief.ctx.SyscallPipeWrite(fd, []byte("forged"), 0)
	require.Error(t, err, "an integer from another module's table must not resolve")
	_, err = thief.ctx.SyscallPipeRead(fd, 0)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, kernel.ErrPipeClosed,
		"the failure must be that the handle does not exist here, not that the pipe ended")

	// The owner's pipe is untouched by the attempt.
	_, err = owner.ctx.SyscallPipeWrite(fd, []byte("still mine"), 0)
	require.NoError(t, err)
	got, err := owner.ctx.SyscallPipeRead(fd, 0)
	require.NoError(t, err)
	assert.Equal(t, "still mine", string(got))
}

// TestPipeClosedOnUnload covers the leak that matters: a module that dies must not
// leave a peer blocked forever.
func TestPipeClosedOnUnload(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	var fd kernel.FD
	ownerPid, owner := chLoad(t, k, func(ctx kernel.SContext) error {
		var err error
		fd, err = ctx.SyscallOpenPipe("doomed", 0, kernel.PipeBlocking)
		return err
	}, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)

	readErr := make(chan error, 1)
	go func() {
		_, err := owner.ctx.SyscallPipeRead(fd, 0)
		readErr <- err
	}()

	select {
	case <-readErr:
		t.Fatal("the read must block while the pipe is open and empty")
	case <-time.After(50 * time.Millisecond):
	}

	require.NoError(t, k.Unload(ownerPid))

	select {
	case err := <-readErr:
		assert.Error(t, err, "reclamation must close the pipe and wake the reader")
	case <-time.After(2 * time.Second):
		t.Fatal("unloading the owner did not wake the blocked reader")
	}

	st := kernel.PipeStatsSnapshot()
	for _, p := range st {
		assert.NotEqual(t, "doomed", p.Name, "an unloaded module's pipe must be gone")
	}
}

// TestPipeEmptyWriteAndClosedSink covers the degenerate inputs.
func TestPipeEmptyWriteAndClosedSink(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("degenerate", 0, kernel.PipeNonBlocking)
	require.NoError(t, err)

	// A zero-length write is a no-op, not a queued empty chunk that a reader would
	// then receive as a spurious event.
	n, err := m.ctx.SyscallPipeWrite(fd, nil, 0)
	require.NoError(t, err)
	assert.Zero(t, n)

	deadline := kernel.KernelClock().Deadline(20 * time.Millisecond)
	_, err = m.ctx.SyscallPipeRead(fd, deadline)
	assert.ErrorIs(t, err, kernel.ErrPipeClosed, "an empty pipe must not deliver a chunk")

	require.NoError(t, m.ctx.SyscallClose(fd))
	_, err = m.ctx.SyscallPipeWrite(fd, []byte("x"), 0)
	assert.Error(t, err, "a closed handle must not resolve")
	// A second close is an error rather than a silent no-op: the fd table's
	// documented contract is that a module double-closing is a defect worth seeing,
	// unlike reclamation, which must tolerate an already-closed resource.
	assert.Error(t, m.ctx.SyscallClose(fd), "a double close is reported, not swallowed")

	// A name is required: an unnamed pipe cannot be diagnosed from a dump.
	_, err = m.ctx.SyscallOpenPipe("", 0, kernel.PipeNonBlocking)
	assert.Error(t, err)
}

// TestPipeConcurrentWritersAreNotInterleaved covers the serialization guarantee. A
// torn chunk would be indistinguishable from corruption at the consumer.
func TestPipeConcurrentWritersAreNotInterleaved(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallOpenPipe("fanin", 1<<20, kernel.PipeBlocking)
	require.NoError(t, err)

	const writers, each = 8, 25
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range each {
				payload := []byte(strings.Repeat(string(rune('a'+w)), 32))
				_, err := m.ctx.SyscallPipeWrite(fd, payload, 0)
				assert.NoError(t, err)
				_ = i
			}
		}(w)
	}

	// Drain concurrently so the writers are not merely filling a buffer.
	received := make(chan string, writers*each)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range writers * each {
			b, err := m.ctx.SyscallPipeRead(fd, 0)
			if err != nil {
				return
			}
			received <- string(b)
		}
	}()

	wg.Wait()
	<-done
	close(received)

	count := 0
	for chunk := range received {
		count++
		require.Len(t, chunk, 32, "a chunk must arrive whole, never interleaved")
		first := chunk[0]
		for i := 1; i < len(chunk); i++ {
			assert.Equal(t, first, chunk[i], "every byte of a chunk must come from one writer")
		}
	}
	assert.Equal(t, writers*each, count)
}

// ---------------------------------------------------------------------------
// klock

// TestLockRequiresGrant is the denial half.
func TestLockRequiresGrant(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	var err error
	pid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		_, err = ctx.SyscallLockTake("shared", true, kernel.KernelClock().Deadline(time.Second))
		return nil
	}, kernel.OpLogWrite)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.Contains(t, err.Error(), "lock:acquire")
	assert.Contains(t, buf.String(), "avc: denied { lock:acquire }")
}

// TestLockSerializesTwoModules is the reason the kernel owns locks rather than
// letting modules use sync.Mutex.
func TestLockSerializesTwoModules(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	var mu sync.Mutex
	var order []string
	inCritical := 0
	overlapped := false

	work := func(who string) func(kernel.SContext) error {
		return func(ctx kernel.SContext) error {
			for range 20 {
				fd, err := ctx.SyscallLockTake("counter", true, kernel.KernelClock().Deadline(5*time.Second))
				if err != nil {
					return err
				}
				mu.Lock()
				inCritical++
				if inCritical > 1 {
					overlapped = true
				}
				order = append(order, who)
				mu.Unlock()

				time.Sleep(time.Millisecond)

				mu.Lock()
				inCritical--
				mu.Unlock()
				if err := ctx.SyscallLockRelease(fd); err != nil {
					return err
				}
			}
			return nil
		}
	}

	pidA, mA := chLoad(t, k, nil, kernel.OpLockTake)
	pidB, mB := chLoad(t, k, nil, kernel.OpLockTake)
	defer func() { _ = k.Unload(pidA); _ = k.Unload(pidB) }()

	var wg sync.WaitGroup
	for _, m := range []*chProbe{mA, mB} {
		wg.Add(1)
		go func(m *chProbe) {
			defer wg.Done()
			assert.NoError(t, work("x")(m.ctx))
		}(m)
	}
	wg.Wait()

	assert.False(t, overlapped, "the critical section must never hold two modules at once")
	assert.Len(t, order, 40)

	snap := kernel.LockSnapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, "counter", snap[0].Name)
	assert.False(t, snap[0].Held, "the lock must be released when every holder is done")
	assert.Equal(t, int64(40), snap[0].Taken)
	assert.Zero(t, snap[0].Waiters)
}

// TestLockIsReleasedWhenTheOwnerDies is the property a plain mutex cannot provide,
// and the one that stops a broken adapter becoming a gateway-wide outage.
func TestLockIsReleasedWhenTheOwnerDies(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	ownerPid, owner := chLoad(t, k, func(ctx kernel.SContext) error {
		_, err := ctx.SyscallLockTake("stranded", true, kernel.KernelClock().Deadline(time.Second))
		return err
	}, kernel.OpLockTake)

	waiterPid, waiter := chLoad(t, k, nil, kernel.OpLockTake)
	defer func() { _ = k.Unload(waiterPid) }()

	acquired := make(chan error, 1)
	go func() {
		fd, err := waiter.ctx.SyscallLockTake("stranded", true, kernel.KernelClock().Deadline(5*time.Second))
		if err == nil {
			_ = waiter.ctx.SyscallLockRelease(fd)
		}
		acquired <- err
	}()

	select {
	case <-acquired:
		t.Fatal("the waiter must block while the owner holds the lock")
	case <-time.After(50 * time.Millisecond):
	}

	// The owner dies without releasing. Its handle is reclaimed, and with it the lock.
	require.NoError(t, k.Unload(ownerPid))
	_ = owner

	select {
	case err := <-acquired:
		require.NoError(t, err, "a waiter must be woken when the lock's owner is unloaded")
	case <-time.After(3 * time.Second):
		t.Fatal("unloading the owner did not release the lock it held")
	}

	snap := kernel.LockSnapshot()
	require.Len(t, snap, 1)
	assert.False(t, snap[0].Held)
	assert.False(t, snap[0].Dead,
		"a clean unload releases the lock rather than condemning it, so the next holder gets it")
}

// TestLockDeadlineIsEnforced covers the mandatory-deadline rule. An untimed wait is
// how a module turns a contended lock into an outage.
func TestLockDeadlineIsEnforced(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	holderPid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		_, err := ctx.SyscallLockTake("contended", true, kernel.KernelClock().Deadline(time.Second))
		return err
	}, kernel.OpLockTake)
	defer func() { _ = k.Unload(holderPid) }()

	waiterPid, waiter := chLoad(t, k, nil, kernel.OpLockTake)
	defer func() { _ = k.Unload(waiterPid) }()

	// An untimed acquire is refused rather than defaulted, so the choice to wait a
	// long time is visible in the code that made it.
	_, err := waiter.ctx.SyscallLockTake("contended", true, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a deadline")

	start := time.Now()
	_, err = waiter.ctx.SyscallLockTake("contended", true, kernel.KernelClock().Deadline(40*time.Millisecond))
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrLockTimeout)
	assert.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond)
	assert.Less(t, time.Since(start), 2*time.Second)

	snap := kernel.LockSnapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, int64(1), snap[0].TimedOut)
	assert.Zero(t, snap[0].Waiters, "a timed-out waiter must leave the queue, not block the next arrival")
}

// TestLockTimeoutIsNotOwnerGone pins the distinction the two typed errors exist for.
// A timeout means retry or shed load; a dead owner means the serialized work never
// completed and the waiter should fail its request.
func TestLockTimeoutIsNotOwnerGone(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	holderPid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		_, err := ctx.SyscallLockTake("abandoned", true, kernel.KernelClock().Deadline(time.Second))
		return err
	}, kernel.OpLockTake)

	waiterPid, waiter := chLoad(t, k, nil, kernel.OpLockTake)
	defer func() { _ = k.Unload(waiterPid) }()

	_, timeoutErr := waiter.ctx.SyscallLockTake("abandoned", true, kernel.KernelClock().Deadline(30*time.Millisecond))
	require.ErrorIs(t, timeoutErr, kernel.ErrLockTimeout)
	assert.NotErrorIs(t, timeoutErr, kernel.ErrLockOwnerGone)

	// A kill, not a clean unload. UnloadModule gives locks up two different ways
	// depending on why the module is going, and only a forced termination means the
	// critical section was abandoned.
	require.NoError(t, kernel.SignalSend(k.InitContext(), holderPid, kernel.SignalKill))
	require.Eventually(t, func() bool { return kernel.SignalTerminated(holderPid) },
		3*time.Second, 5*time.Millisecond, "the kill must take effect")

	_, goneErr := waiter.ctx.SyscallLockTake("abandoned", true, kernel.KernelClock().Deadline(time.Second))
	assert.ErrorIs(t, goneErr, kernel.ErrLockOwnerGone,
		"a lock whose owner died holding it must report that, not silently hand over")
	assert.NotErrorIs(t, goneErr, kernel.ErrLockTimeout)

	snap := kernel.LockSnapshot()
	require.Len(t, snap, 1)
	assert.True(t, snap[0].Dead)

	escalations := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation})
	found := false
	for _, e := range escalations {
		if e.Msg == "lock owner terminated while holding" && e.Fields["lock"] == "abandoned" {
			found = true
		}
	}
	assert.True(t, found, "a condemned lock must reach the audit chain")
}

// TestLockIsReentrant covers the legitimate case where a module's call graph passes
// through the same lock twice.
func TestLockIsReentrant(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpLockTake)
	defer func() { _ = k.Unload(pid) }()

	deadline := kernel.KernelClock().Deadline(time.Second)
	fd1, err := m.ctx.SyscallLockTake("reentrant", true, deadline)
	require.NoError(t, err)

	fd2, err := m.ctx.SyscallLockTake("reentrant", true, deadline)
	require.NoError(t, err, "the same pid must be able to take a lock it already holds")
	assert.NotEqual(t, fd1, fd2, "each hold gets its own handle, so each release balances")

	require.NoError(t, m.ctx.SyscallLockRelease(fd2))
	require.NoError(t, m.ctx.SyscallLockRelease(fd1))

	snap := kernel.LockSnapshot()
	require.Len(t, snap, 1)
	assert.False(t, snap[0].Held, "two holds and two releases must balance")
	assert.Equal(t, int64(2), snap[0].Taken)
}

// TestReadLocksAreSharedButWriteLocksAreNot covers the two modes.
func TestReadLocksAreSharedButWriteLocksAreNot(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pidA, mA := chLoad(t, k, nil, kernel.OpLockTake)
	pidB, mB := chLoad(t, k, nil, kernel.OpLockTake)
	defer func() { _ = k.Unload(pidA); _ = k.Unload(pidB) }()

	deadline := kernel.KernelClock().Deadline(time.Second)
	r1, err := mA.ctx.SyscallLockTake("shared-read", false, deadline)
	require.NoError(t, err)
	r2, err := mB.ctx.SyscallLockTake("shared-read", false, deadline)
	require.NoError(t, err, "two readers must hold the same lock at once")

	snap := kernel.LockSnapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, 2, snap[0].Readers)
	assert.False(t, snap[0].Held)

	// A writer must wait for both readers, which is what makes it exclusive.
	_, err = mA.ctx.SyscallLockTake("shared-read", true, kernel.KernelClock().Deadline(30*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrLockTimeout, "a writer must not be granted while readers hold the lock")

	require.NoError(t, mA.ctx.SyscallLockRelease(r1))
	require.NoError(t, mB.ctx.SyscallLockRelease(r2))

	w, err := mA.ctx.SyscallLockTake("shared-read", true, deadline)
	require.NoError(t, err, "a writer must be granted once the readers are gone")
	snap = kernel.LockSnapshot()
	assert.True(t, snap[0].Held)
	assert.Equal(t, pidA, snap[0].Owner)
	assert.Zero(t, snap[0].Readers)
	require.NoError(t, mA.ctx.SyscallLockRelease(w))
}

// TestLockIsFIFO covers fairness. Without arrival order, one module hammering acquire
// starves another that asked first, and the starved module's deadline then fires - so
// the noisy module effectively controls the quiet one's latency.
func TestLockIsFIFO(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	holderPid, holder := chLoad(t, k, func(ctx kernel.SContext) error {
		_, err := ctx.SyscallLockTake("fifo", true, kernel.KernelClock().Deadline(time.Second))
		return err
	}, kernel.OpLockTake)
	defer func() { _ = k.Unload(holderPid) }()

	const waiters = 5
	var mu sync.Mutex
	var grantOrder []int
	ready := make(chan int, waiters)
	var wg sync.WaitGroup

	for w := range waiters {
		pid, m := chLoad(t, k, nil, kernel.OpLockTake)
		t.Cleanup(func() { _ = k.Unload(pid) })
		wg.Add(1)
		go func(w int, ctx kernel.SContext) {
			defer wg.Done()
			// Stagger the arrivals so queue order is unambiguous.
			time.Sleep(time.Duration(w) * 15 * time.Millisecond)
			ready <- w
			fd, err := ctx.SyscallLockTake("fifo", true, kernel.KernelClock().Deadline(5*time.Second))
			if err != nil {
				return
			}
			mu.Lock()
			grantOrder = append(grantOrder, w)
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			_ = ctx.SyscallLockRelease(fd)
		}(w, m.ctx)
	}

	// Wait until all five are queued, then release the holder.
	for range waiters {
		<-ready
	}
	require.NoError(t, k.Unload(holderPid))
	_ = holder
	wg.Wait()

	require.Len(t, grantOrder, waiters)
	for i := range grantOrder {
		assert.Equal(t, i, grantOrder[i], "grants must follow arrival order, not retry frequency")
	}
}

// TestLockCeilingIsPerModule covers the leak bound.
func TestLockCeilingIsPerModule(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	var firstErr error
	held := 0
	pid, m := chLoad(t, k, func(ctx kernel.SContext) error {
		for range 400 {
			_, err := ctx.SyscallLockTake("leak-"+itoa(held), true, kernel.KernelClock().Deadline(time.Second))
			if err != nil {
				firstErr = err
				return nil
			}
			held++
		}
		return nil
	}, kernel.OpLockTake)
	defer func() { _ = k.Unload(pid) }()
	_ = m

	require.Error(t, firstErr)
	assert.Contains(t, firstErr.Error(), "maximum of 256 locks")
	assert.Equal(t, 256, held, "the ceiling must be exactly the documented bound")
	assert.Contains(t, buf.String(), "lock ceiling reached")

	// Unload must give every one of them back, which is the property that makes the
	// ceiling a bound rather than a slow leak toward a dead gateway.
	require.NoError(t, k.Unload(pid))
	for _, l := range kernel.LockSnapshot() {
		assert.False(t, l.Held, "no lock may stay held after its owner is unloaded")
		assert.Zero(t, l.Owner)
	}
}

// TestLockHandleIsKindChecked covers the fd-table discipline from the lock side.
func TestLockHandleIsKindChecked(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	var releaseErr error
	pid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		pipeFD, err := ctx.SyscallOpenPipe("not-a-lock", 0, kernel.PipeNonBlocking)
		require.NoError(t, err)
		releaseErr = ctx.SyscallLockRelease(pipeFD)
		return nil
	}, kernel.OpLockTake, kernel.OpPipeOpen)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, releaseErr)
	assert.Contains(t, releaseErr.Error(), "not a lock")
}

// TestLockNameIsRequired covers the input validation. An unnamed lock cannot be
// diagnosed from a dump.
func TestLockNameIsRequired(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	var err error
	pid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		_, err = ctx.SyscallLockTake("", true, kernel.KernelClock().Deadline(time.Second))
		return nil
	}, kernel.OpLockTake)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a name")
}

// TestConcurrentLockAcquireIsRaceFree drives the lock from many goroutines under
// -race. The invariant is that the critical section never holds two of them.
func TestConcurrentLockAcquireIsRaceFree(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpLockTake)
	defer func() { _ = k.Unload(pid) }()

	const workers, each = 12, 15
	var (
		mu         sync.Mutex
		inside     int
		overlapped bool
		total      int
		wg         sync.WaitGroup
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				fd, err := m.ctx.SyscallLockTake("race", true, kernel.KernelClock().Deadline(10*time.Second))
				if err != nil {
					return
				}
				mu.Lock()
				inside++
				if inside > 1 {
					overlapped = true
				}
				total++
				mu.Unlock()
				mu.Lock()
				inside--
				mu.Unlock()
				_ = m.ctx.SyscallLockRelease(fd)
			}
		}()
	}
	wg.Wait()

	assert.False(t, overlapped)
	assert.Equal(t, workers*each, total)
	assert.False(t, kernel.LockSnapshot()[0].Held)
}

// ---------------------------------------------------------------------------
// kepoll

// TestEventRequiresGrant is the denial half.
func TestEventRequiresGrant(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	// Only the subscribe is attempted. The wait cannot be reached once the
	// subscription is denied, so capturing its error would capture a variable that
	// stays nil and assert nothing.
	var subErr error
	pid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		_, err := ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventDraining})
		subErr = err
		return nil
	}, kernel.OpLogWrite)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, subErr)
	assert.True(t, kernel.IsDenied(subErr))
	assert.Contains(t, subErr.Error(), "event:wait")
	assert.Contains(t, buf.String(), "avc: denied { event:wait }")
}

// TestEventNameSetIsClosed covers the rule that makes the event path trustworthy. A
// module may wait on a name; it may not invent one, or a peer's claim would be
// indistinguishable from a kernel fact.
func TestEventNameSetIsClosed(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	names := kernel.KernelEvents()
	require.NotEmpty(t, names)
	for _, n := range names {
		assert.True(t, kernel.IsKernelEvent(n))
	}
	assert.False(t, kernel.IsKernelEvent("made.up"))
	assert.False(t, kernel.IsKernelEvent(""))

	// Sorted, so the list is stable for documentation and diffs.
	for i := 1; i < len(names); i++ {
		assert.Less(t, names[i-1], names[i])
	}

	var subErr error
	pid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		_, subErr = ctx.SyscallEventSubscribe([]kernel.KernelEventName{"made.up"})
		return nil
	}, kernel.OpEventWait)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, subErr)
	assert.Contains(t, subErr.Error(), "not a kernel event name")

	// An empty subscription is refused rather than silently matching everything.
	var emptyErr error
	pid2, m2 := chLoad(t, k, func(ctx kernel.SContext) error { return nil }, kernel.OpEventWait)
	defer func() { _ = k.Unload(pid2) }()
	_, emptyErr = m2.ctx.SyscallEventSubscribe(nil)
	assert.Error(t, emptyErr)
	assert.Contains(t, emptyErr.Error(), "at least one event name")
}

// TestEventDeliveryIsScopedToSubscribers covers the routing.
func TestEventDeliveryIsScopedToSubscribers(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpEventWait)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventDraining})
	require.NoError(t, err)

	// Nothing has happened yet, so a short wait must time out rather than invent an
	// event.
	_, err = m.ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(20*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrNoEvents)

	// A kernel-side post arrives. Posted from the test rather than from a module,
	// because there is no syscall for it: that absence is the control.
	kernel.PostEvent(kernel.EventDraining, pid, "test-post")

	got, err := m.ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, kernel.EventDraining, got[0].Name)
	assert.Equal(t, pid, got[0].Subject)
	assert.Equal(t, "test-post", got[0].Detail)
	assert.Equal(t, int64(1), got[0].Seq, "sequence numbering starts at one per subscription")
	assert.Positive(t, got[0].At, "the post time comes from the kernel clock")

	// A second post gets the next sequence number, so a consumer can detect a gap.
	kernel.PostEvent(kernel.EventDraining, pid, "second")
	got, err = m.ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, int64(2), got[0].Seq)
}

// TestEventSubscriptionOnlyReceivesWhatItAskedFor covers the filter.
func TestEventSubscriptionOnlyReceivesWhatItAskedFor(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpEventWait)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventStreamAborted})
	require.NoError(t, err)

	kernel.PostEvent(kernel.EventConfigReloaded, pid, "not wanted")
	kernel.PostEvent(kernel.EventStreamAborted, pid, "wanted")

	got, err := m.ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, kernel.EventStreamAborted, got[0].Name)
	assert.Equal(t, "wanted", got[0].Detail)
}

// TestEventBacklogIsBoundedAndDropsOldest covers the memory-safety property. An
// unbounded queue behind a slow consumer is a leak whose timing the consumer
// controls.
func TestEventBacklogIsBoundedAndDropsOldest(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpEventWait)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventConfigReloaded})
	require.NoError(t, err)

	st := kernel.EventStatsSnapshot()
	require.Positive(t, st.MaxPendingPerSubscription)
	bound := st.MaxPendingPerSubscription

	// Post well past the bound without draining.
	for i := range bound + 50 {
		kernel.PostEvent(kernel.EventConfigReloaded, pid, "e"+itoa(i))
	}

	pending, dropped, err := m.ctx.SyscallEventPending(fd)
	require.NoError(t, err)
	assert.Equal(t, bound, pending, "the backlog must stop at the bound")
	assert.Equal(t, 50, dropped, "every event past the bound must be counted, not silently lost")

	got, err := m.ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)
	require.Len(t, got, bound)
	// Oldest dropped, newest kept: the newest event is the one a consumer can still
	// act on.
	assert.Equal(t, "e50", got[0].Detail)
	assert.Equal(t, "e"+itoa(bound+49), got[len(got)-1].Detail)

	stats := kernel.EventStatsSnapshot()
	assert.Equal(t, int64(50), stats.Dropped)
	_ = buf
}

// TestEventPostWakesABlockedWaiter covers the reason this exists instead of polling.
func TestEventPostWakesABlockedWaiter(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpEventWait)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventPeerDisconnected})
	require.NoError(t, err)

	got := make(chan []kernel.Event, 1)
	go func() {
		ev, err := m.ctx.SyscallEventWait(fd, 0)
		if err == nil {
			got <- ev
		}
	}()

	select {
	case <-got:
		t.Fatal("an untimed wait with nothing pending must block")
	case <-time.After(50 * time.Millisecond):
	}

	kernel.PostEvent(kernel.EventPeerDisconnected, pid, "wakeup")

	select {
	case ev := <-got:
		require.Len(t, ev, 1)
		assert.Equal(t, "wakeup", ev[0].Detail)
	case <-time.After(2 * time.Second):
		t.Fatal("a post must wake a blocked waiter")
	}
}

// TestEventSubscriptionIsDroppedOnUnload covers the leak: a dead module must stop
// accumulating a backlog nobody will read.
func TestEventSubscriptionIsDroppedOnUnload(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpEventWait)
	fd, err := m.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventConfigReloaded})
	require.NoError(t, err)
	_ = fd

	before := kernel.EventStatsSnapshot()
	assert.Equal(t, 1, before.Subscriptions)

	require.NoError(t, k.Unload(pid))

	after := kernel.EventStatsSnapshot()
	assert.Zero(t, after.Subscriptions, "unloading must drop the subscription")

	// A post afterwards reaches nobody and does not resurrect the backlog.
	kernel.PostEvent(kernel.EventConfigReloaded, pid, "after unload")
	assert.Equal(t, after.Posts+1, kernel.EventStatsSnapshot().Posts)
	assert.Zero(t, kernel.EventStatsSnapshot().Pending)
}

// TestEventSubscriptionCeilingIsPerModule covers the bound.
func TestEventSubscriptionCeilingIsPerModule(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	var ceilingErr error
	opened := 0
	pid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		for range 100 {
			_, err := ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventDraining})
			if err != nil {
				ceilingErr = err
				return nil
			}
			opened++
		}
		return nil
	}, kernel.OpEventWait)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, ceilingErr)
	assert.Contains(t, ceilingErr.Error(), "maximum of 64 event subscriptions")
	assert.Equal(t, 64, opened)
	assert.Contains(t, buf.String(), "event subscription refused")
}

// TestEventHandleIsKindChecked covers the fd discipline.
func TestEventHandleIsKindChecked(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	var waitErr, pendingErr error
	pid, _ := chLoad(t, k, func(ctx kernel.SContext) error {
		pipeFD, err := ctx.SyscallOpenPipe("not-a-subscription", 0, kernel.PipeNonBlocking)
		require.NoError(t, err)
		_, waitErr = ctx.SyscallEventWait(pipeFD, kernel.KernelClock().Deadline(10*time.Millisecond))
		_, _, pendingErr = ctx.SyscallEventPending(pipeFD)
		return nil
	}, kernel.OpEventWait, kernel.OpPipeOpen)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, waitErr)
	assert.Contains(t, waitErr.Error(), "not an event subscription")
	require.Error(t, pendingErr)
	assert.Contains(t, pendingErr.Error(), "not an event subscription")
}

// TestUndefinedEventNameIsAFault covers the kernel-side defect case. A subsystem that
// posts a name nobody defined would otherwise produce a subscription that never
// fires, with nothing to explain why.
func TestUndefinedEventNameIsAFault(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)
	defer func() { _ = k.Shutdown() }()

	before := len(faults(buf))
	kernel.PostEvent("not.a.kernel.event", 0, "x")
	assert.Greater(t, len(faults(buf)), before,
		"posting an undefined event name must be a visible kernel defect, not a silent no-op")
	assert.Contains(t, buf.String(), "undefined kernel event name")
}

// TestEventPostToPidIsTargeted covers the narrow delivery path.
func TestEventPostToPidIsTargeted(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pidA, mA := chLoad(t, k, nil, kernel.OpEventWait)
	pidB, mB := chLoad(t, k, nil, kernel.OpEventWait)
	defer func() { _ = k.Unload(pidA); _ = k.Unload(pidB) }()

	fdA, err := mA.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventJobFinished})
	require.NoError(t, err)
	fdB, err := mB.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventJobFinished})
	require.NoError(t, err)

	kernel.PostEventToPid(kernel.EventJobFinished, pidA, pidB, "only for A")

	got, err := mA.ctx.SyscallEventWait(fdA, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "only for A", got[0].Detail)

	_, err = mB.ctx.SyscallEventWait(fdB, kernel.KernelClock().Deadline(20*time.Millisecond))
	assert.ErrorIs(t, err, kernel.ErrNoEvents, "a targeted post must not reach other subscribers")
}

// TestEventDetailIsBounded covers the injection surface. A detail string is written
// into audit lines and console output verbatim, so an unbounded one is a way to
// smuggle content into a log.
func TestEventDetailIsBounded(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, m := chLoad(t, k, nil, kernel.OpEventWait)
	defer func() { _ = k.Unload(pid) }()

	fd, err := m.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventConfigReloaded})
	require.NoError(t, err)

	huge := strings.Repeat("x", 4096)
	kernel.PostEvent(kernel.EventConfigReloaded, pid, huge)

	got, err := m.ctx.SyscallEventWait(fd, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.LessOrEqual(t, len(got[0].Detail), 128, "the detail must be truncated to the bound")
}

// TestEventResetsAcrossRestart is the reset-path assertion.
func TestEventResetsAcrossRestart(t *testing.T) {
	quietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k1.Shutdown() })

	pid, m := chLoad(t, k1, nil, kernel.OpEventWait)
	_, err = m.ctx.SyscallEventSubscribe([]kernel.KernelEventName{kernel.EventDraining})
	require.NoError(t, err)
	kernel.PostEvent(kernel.EventDraining, pid, "before")
	require.GreaterOrEqual(t, kernel.EventStatsSnapshot().Subscriptions, 1)
	require.NoError(t, k1.Shutdown())

	st := kernel.EventStatsSnapshot()
	assert.Zero(t, st.Subscriptions, "subscriptions must not survive a shutdown")
	assert.Zero(t, st.Posts, "the post counter resets with the boot")
	assert.Zero(t, st.Pending)

	k2, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()
	assert.Zero(t, kernel.EventStatsSnapshot().Subscriptions)
}

// TestLocksAndPipesResetAcrossRestart covers the reset path for both channel
// subsystems in one boot cycle.
func TestLocksAndPipesResetAcrossRestart(t *testing.T) {
	quietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k1.Shutdown() })

	pid, m := chLoad(t, k1, func(ctx kernel.SContext) error {
		_, err := ctx.SyscallOpenPipe("survivor-pipe", 0, kernel.PipeNonBlocking)
		if err != nil {
			return err
		}
		_, err = ctx.SyscallLockTake("survivor-lock", true, kernel.KernelClock().Deadline(time.Second))
		return err
	}, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpLockTake)
	_ = pid

	require.NotEmpty(t, kernel.PipeStatsSnapshot())
	require.NotEmpty(t, kernel.LockSnapshot())
	require.NoError(t, k1.Shutdown())

	assert.Empty(t, kernel.PipeStatsSnapshot(), "pipes must not survive a shutdown")
	assert.Empty(t, kernel.LockSnapshot(), "locks must not survive a shutdown")
	assert.Zero(t, kernel.SlotStatsSnapshot().Total)

	k2, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()

	// And the second boot can take the same names, which is what "reset" means to a
	// module author rather than to the kernel.
	pid2, m2 := chLoad(t, k2, nil, kernel.OpPipeOpen, kernel.OpLockTake)
	defer func() { _ = k2.Unload(pid2) }()
	_, err = m2.ctx.SyscallOpenPipe("survivor-pipe", 0, kernel.PipeNonBlocking)
	assert.NoError(t, err)
	_, err = m2.ctx.SyscallLockTake("survivor-lock", true, kernel.KernelClock().Deadline(time.Second))
	assert.NoError(t, err)
	_ = m
}
