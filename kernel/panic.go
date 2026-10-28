package kernel

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// kpanic: crash dump and ledger flush (subsystem: kpanic).
//
// What it is for. Everything else in this kernel can be reconstructed after a
// restart. Two things cannot.
//
// Unsettled metering is money. A request that was served and recorded in kmeter but
// not yet closed is a billable fact that exists only in memory. If the process dies,
// the operator loses revenue and a mesh peer loses the receipt it would have been
// settled against. The asymmetry is what makes this a security concern rather than a
// reliability one: a module that can cause a crash at a chosen moment can erase its
// own bill. That is a billing bypass, and it is why this file exists.
//
// The audit chain is the evidence. A hash-chained log whose tail never reached disk
// looks exactly like one truncated by an attacker, and tools/auditverify exists to
// detect tampering. An unflushed tail makes a clean shutdown indistinguishable from a
// malicious one, so the flush is not merely durability; it is what makes the
// verifier's verdict mean anything.
//
// What it is not. There is no JVM here and no ShutdownHook, and Go gives less than
// one expects. Deferred functions do not run on os.Exit or on a normal return from
// main, so a defer-based flush does not fire on the two most common exits. recover()
// cannot catch a runtime fatal error - concurrent map writes, stack exhaustion,
// deadlock detection - and cannot catch a panic in another goroutine at all. The
// only paths this file can actually serve are the ones the host calls into: an
// explicit flush, a recover in the host's own top level, or a signal handler the host
// installs. Those hooks are reported at the bottom of this file rather than wired
// here, because a library that installs a signal handler is a side effect on a
// process that did not ask for one.
//
// There is no syscall surface. A module that could trigger a kernel crash dump could
// erase evidence, which is the attack this defends against. The absence of a
// SyscallPanic group is the control, not an omission.

// PanicNotifier is one step of the flush. It reports what it achieved and whether it
// completed; a notifier that returns an error does not stop the ones after it,
// because a flush that aborts on its first failure saves nothing at all.
type PanicNotifier func() PanicOutcome

// PanicOutcome is one notifier's honest report. Completed is false when the notifier
// was abandoned for exceeding its budget or panicked, and Detail says which.
type PanicOutcome struct {
	Name      string `json:"name"`
	Completed bool   `json:"completed"`
	Saved     int    `json:"saved"`
	Lost      int    `json:"lost"`
	Detail    string `json:"detail,omitempty"`
	Nanos     int64  `json:"nanos"`
}

// CrashRecord is the final state of one flush. It is returned to the caller and
// written to the audit chain, and it says what was saved and what was not: a crash
// dump that claims completeness it does not have is worse than none, because an
// operator will trust it.
type CrashRecord struct {
	Reason   string         `json:"reason"`
	BootID   int64          `json:"boot_id"`
	Mono     int64          `json:"mono"`
	Stack    string         `json:"stack,omitempty"`
	Outcomes []PanicOutcome `json:"outcomes"`
	Saved    int            `json:"saved"`
	Lost     int            `json:"lost"`
	// Concurrent is true when a second flush was already running and this call
	// returned immediately rather than double-flushing.
	Concurrent bool `json:"concurrent,omitempty"`
	// ChainVerified reports whether the audit chain still verifies after the flush.
	// A crash dump that corrupts the chain is worse than no crash dump.
	ChainVerified bool `json:"chain_verified"`
}

// ErrPanicNotRegistered is what registering a notifier under an empty name, or with
// no budget, returns. Both would make the ordering or the bound meaningless.
var ErrPanicNotRegistered = errors.New("kernel: panic notifier not registered")

// panicBudget is the default per-notifier budget. It is small on purpose: a flush
// runs on the way out of a dying process, and a notifier that needs longer than this
// is not saving anything, it is delaying the exit.
const panicBudget = 2 * time.Second

// panicStackBytes bounds the captured stack, following watchdog.go's byte bound. An
// unbounded stack from a deep recursion is how a crash dump becomes the thing that
// exhausts the memory the process is already short of.
const panicStackBytes = 8192

type panicState struct {
	mu        sync.Mutex
	notifiers []panicEntry
	// flushing is a compare-and-swap, not a mutex: a second flush arriving during
	// the first must return immediately rather than queue behind it, because the
	// first may be the one that is hung.
	flushing atomic.Bool
	last     *CrashRecord
}

type panicEntry struct {
	name   string
	fn     PanicNotifier
	budget time.Duration
}

var kpanic = panicState{}

// PanicRegister adds a notifier to the flush chain, in registration order. Order is
// the caller's responsibility and matters: a notifier that writes to the audit chain
// must run before the one that flushes the sink, or its own record is what gets lost.
//
// A zero budget takes panicBudget. A negative one is refused rather than clamped,
// because a caller asking for no time bound is asking for something this file cannot
// give and should be told.
func PanicRegister(name string, fn PanicNotifier, budget time.Duration) error {
	if name == "" {
		return fmt.Errorf("%w: a notifier needs a name", ErrPanicNotRegistered)
	}
	if fn == nil {
		return fmt.Errorf("%w: notifier %q has no function", ErrPanicNotRegistered, name)
	}
	if budget < 0 {
		return fmt.Errorf("%w: notifier %q has a negative budget", ErrPanicNotRegistered, name)
	}
	if budget == 0 {
		budget = panicBudget
	}
	kpanic.mu.Lock()
	defer kpanic.mu.Unlock()
	for _, e := range kpanic.notifiers {
		if e.name == name {
			return fmt.Errorf("%w: %q is already registered", ErrPanicNotRegistered, name)
		}
	}
	kpanic.notifiers = append(kpanic.notifiers, panicEntry{name: name, fn: fn, budget: budget})
	return nil
}

// PanicUnregister removes a notifier by name. It exists for tests and for a host that
// tears down a subsystem; a flush chain that could only grow would make every
// registered notifier permanent.
func PanicUnregister(name string) {
	kpanic.mu.Lock()
	defer kpanic.mu.Unlock()
	out := kpanic.notifiers[:0]
	for _, e := range kpanic.notifiers {
		if e.name != name {
			out = append(out, e)
		}
	}
	kpanic.notifiers = out
}

// PanicNotifiers reports the registered names in the order they will run.
func PanicNotifiers() []string {
	kpanic.mu.Lock()
	defer kpanic.mu.Unlock()
	out := make([]string, 0, len(kpanic.notifiers))
	for _, e := range kpanic.notifiers {
		out = append(out, e.name)
	}
	return out
}

// PanicFlush runs the flush chain and returns what it achieved. It is safe to call
// from a recover in the host's top level, from a signal handler, or from Shutdown.
//
// Two records go on the audit chain rather than one. The first carries the reason,
// the boot identity and the stack, and it is written before any notifier runs so
// that a flush which then dies still leaves the cause behind. The second carries the
// outcome, and the sink is flushed again after it, so the counts describe everything
// except that final record itself - which is stated in the record rather than left
// for a reader to discover.
//
// A second concurrent call returns immediately with Concurrent set. It does not wait
// and does not double-flush, because the first call may be the one that is hung and
// the exit must not block on it.
func PanicFlush(reason string) CrashRecord {
	if !kpanic.flushing.CompareAndSwap(false, true) {
		rec := CrashRecord{Reason: reason, Concurrent: true, Mono: mono()}
		fault(nil, "concurrent panic flush refused", map[string]any{"reason": reason})
		return rec
	}
	defer kpanic.flushing.Store(false)

	rec := CrashRecord{
		Reason: reason,
		Mono:   mono(),
		BootID: panicBootID(),
		Stack:  panicStack(),
	}

	// The cause goes down first. A flush that dies partway still leaves behind the
	// reason it was running, which is the fact an investigator needs most.
	kaudit.record(AuditPanic, nil, "kernel flush begun", map[string]any{
		"reason": reason, "boot_id": rec.BootID, "stack_bytes": len(rec.Stack),
		"open_requests": panicOpenRequests(),
	})

	for _, e := range panicSnapshotNotifiers() {
		rec.Outcomes = append(rec.Outcomes, panicRunOne(e))
	}
	for _, o := range rec.Outcomes {
		rec.Saved += o.Saved
		rec.Lost += o.Lost
	}

	// The outcome record, then one more flush so it reaches the sink too.
	kaudit.record(AuditPanic, nil, "kernel flush complete", map[string]any{
		"reason": reason, "saved": rec.Saved, "lost": rec.Lost,
		"notifiers": len(rec.Outcomes),
	})
	rec.ChainVerified = panicVerifyChain()
	panicFlushSink()

	kpanic.mu.Lock()
	kpanic.last = &rec
	kpanic.mu.Unlock()
	return rec
}

// PanicLastFlush reports the most recent completed flush, or nil. It exists so a host
// that survives a flush - because it caught the panic rather than exiting - can
// report what was saved.
func PanicLastFlush() (CrashRecord, bool) {
	kpanic.mu.Lock()
	defer kpanic.mu.Unlock()
	if kpanic.last == nil {
		return CrashRecord{}, false
	}
	out := *kpanic.last
	out.Outcomes = append([]PanicOutcome(nil), kpanic.last.Outcomes...)
	return out, true
}

// panicRunOne runs one notifier under its budget, containing both a panic and a hang.
//
// The hang case needs a goroutine, and that is a real cost: an abandoned notifier
// keeps running after the flush returns, because nothing in Go can stop a goroutine
// that will not stop itself. The alternative is a flush that blocks forever on the
// first stuck notifier and saves nothing after it, which is worse. The abandonment is
// recorded rather than hidden.
func panicRunOne(e panicEntry) PanicOutcome {
	start := mono()
	out := PanicOutcome{Name: e.name}

	done := make(chan PanicOutcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Recorded here as well as returned, for the same reason the hang case
				// is: a flush on the way out of a dying process may have no caller left
				// to read the returned record, and a notifier that failed silently would
				// make the dump look complete when one of its steps was not.
				stack := make([]byte, panicStackBytes)
				n := runtime.Stack(stack, false)
				fault(nil, "panic notifier panicked", map[string]any{
					"notifier": e.name, "panic": fmt.Sprint(r),
					"stack_bytes": n,
				})
				kaudit.record(AuditPanic, nil, "panic notifier panicked", map[string]any{
					"notifier": e.name, "panic": fmt.Sprint(r),
				})
				done <- PanicOutcome{
					Name: e.name, Detail: fmt.Sprintf("panicked: %v", r),
					Nanos: mono() - start,
				}
			}
		}()
		o := e.fn()
		o.Name = e.name
		o.Nanos = mono() - start
		done <- o
	}()

	timer := time.NewTimer(e.budget)
	defer timer.Stop()

	select {
	case o := <-done:
		out = o
		out.Nanos = mono() - start
	case <-timer.C:
		out.Completed = false
		out.Detail = fmt.Sprintf("abandoned after %s", e.budget)
		fault(nil, "panic notifier abandoned", map[string]any{
			"notifier": e.name, "budget": e.budget.String(),
		})
	}
	return out
}

func panicSnapshotNotifiers() []panicEntry {
	kpanic.mu.Lock()
	defer kpanic.mu.Unlock()
	return append([]panicEntry(nil), kpanic.notifiers...)
}

// panicBootID identifies this boot, from the audit chain's own boot record. It is
// read rather than cached so a flush after a restart reports the new boot's identity
// and not the previous one's.
func panicBootID() int64 {
	entries := AuditQuery(AuditFilter{Kind: AuditBoot, Limit: 1})
	if len(entries) == 0 {
		return 0
	}
	return entries[0].Time
}

// panicStack captures the calling goroutine's stack, bounded. A bound matters because
// the process may be dying from exhaustion, and a dump that allocates without limit
// is a dump that does not complete.
func panicStack() string {
	buf := make([]byte, panicStackBytes)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// ---------------------------------------------------------------------------
// The three built-in notifiers. They are registered by panicRegisterBuiltins, which
// the host calls once; they are functions rather than methods because a flush runs
// when the kernel's own structures may be partly torn down, and reaching through a
// Kernel handle would add a nil check to every path.

// panicCloseMeter closes every open meter request as abandoned. This is the money
// half of the flush: a request that was served must not vanish because the process
// died before it was closed.
//
// It reuses meter.go's own teardown rather than reimplementing it. closeRequestsFor
// is per pid, so this walks the process table and calls it for each live pid, which
// keeps one implementation of "close a request as abandoned" in the tree.
func panicCloseMeter() PanicOutcome {
	out := PanicOutcome{Name: "meter", Completed: true}
	before := panicOpenRequests()
	if before == 0 {
		out.Detail = "no open requests"
		return out
	}
	for _, p := range ProcTable() {
		if p.State == ProcTerminated || p.State == ProcRejected {
			continue
		}
		closeRequestsFor(p.PID)
	}
	after := panicOpenRequests()
	out.Saved = before - after
	out.Lost = after
	if after > 0 {
		out.Completed = false
		out.Detail = fmt.Sprintf("%d requests remained open", after)
	}
	return out
}

// panicOpenRequests counts requests kmeter still holds open.
func panicOpenRequests() int {
	kmeter.mu.RLock()
	defer kmeter.mu.RUnlock()
	return len(kmeter.open)
}

// panicFlushSink tells the audit sink to persist what it holds.
//
// The sink interface exposes only WriteAudit, so a flush is attempted through an
// optional interface rather than by widening AuditSink. Widening it would force every
// sink implementation in the tree to grow a method, and most have nothing to flush.
// internal/auditfile.Sink has Flush; a sink that does not is reported as such rather
// than silently assumed durable, because a write sitting in an OS buffer is not
// durable across a machine crash and an operator who believes otherwise will trust a
// chain that is missing its tail.
func panicFlushSink() PanicOutcome {
	out := PanicOutcome{Name: "audit-sink", Completed: true}

	// AuditLen reports retained and evicted under the audit lock, so the counts here
	// are the ones the chain itself would give a reader rather than a second view of
	// the same state that could disagree with it.
	retained, evicted := AuditLen()

	kaudit.mu.Lock()
	sink := kaudit.sink
	kaudit.mu.Unlock()

	if sink == nil {
		out.Completed = false
		out.Lost = retained
		out.Detail = "no sink installed; the chain is memory-only and dies with the process"
		return out
	}
	f, ok := sink.(interface{ Flush() error })
	if !ok {
		out.Completed = false
		out.Detail = "the installed sink has no Flush method; durability is the sink's own business"
		return out
	}
	if err := f.Flush(); err != nil {
		out.Completed = false
		out.Detail = "flush failed: " + err.Error()
		return out
	}
	out.Saved = retained
	out.Lost = int(evicted)
	out.Detail = fmt.Sprintf("retained=%d evicted=%d", retained, evicted)
	return out
}

// panicFlushConsole writes the retained console history, including every fault, to a
// durable writer if the host installed one.
//
// It is honest about a limit it cannot fix: console retention is bounded and drops
// the oldest records, so on a long-running process the earliest faults are already
// gone from History() before this runs. The dump is a tail, not a transcript, and the
// outcome says how much was dropped.
func panicFlushConsole() PanicOutcome {
	out := PanicOutcome{Name: "console", Completed: true}
	history := kconsole.History()
	dropped := kconsole.Dropped()
	out.Saved = len(history)
	out.Lost = int(dropped)
	if dropped > 0 {
		out.Detail = fmt.Sprintf("%d records were dropped by retention before this flush", dropped)
	}

	w := panicConsoleWriter()
	if w == nil {
		out.Completed = false
		if out.Detail == "" {
			out.Detail = "no crash writer installed; the console history was not persisted"
		}
		return out
	}
	for _, r := range history {
		if _, err := fmt.Fprintf(w, "%s\n", r.Msg); err != nil {
			out.Completed = false
			out.Detail = "crash writer failed: " + err.Error()
			return out
		}
	}
	if f, ok := w.(interface{ Sync() error }); ok {
		_ = f.Sync()
	}
	return out
}

// panicConsoleWriter is the host-installed destination for a crash dump. It is
// deliberately separate from the console's own output: the console goes wherever the
// operator pointed it, which may be a terminal that is already gone, while a crash
// dump should go somewhere that survives.
var panicCrashWriter atomic.Pointer[io.Writer]

// PanicSetCrashWriter installs the destination for the console half of a crash dump.
// The host calls it; nothing in this file reaches for os.Stderr by default, because a
// default that writes to a terminal nobody is watching is a default that looks like
// durability and is not.
func PanicSetCrashWriter(w io.Writer) {
	if w == nil {
		panicCrashWriter.Store(nil)
		return
	}
	panicCrashWriter.Store(&w)
}

func panicConsoleWriter() io.Writer {
	p := panicCrashWriter.Load()
	if p == nil {
		return nil
	}
	return *p
}

// panicVerifyChain checks the chain still verifies after the flush, which is the
// property that makes the flush worth doing: a crash dump that corrupts the evidence
// it was saving is worse than no crash dump.
//
// The genesis hash is the expected predecessor of the first entry, and the in-memory
// window may have evicted its head, so a chain whose oldest retained entry is not the
// boot record cannot be verified from the front. In that case the answer is reported
// as unverified rather than as verified, because "I could not check" and "it checks
// out" are different facts and conflating them is how a truncated chain gets called
// intact.
func panicVerifyChain() bool {
	entries := AuditQuery(AuditFilter{})
	if len(entries) == 0 {
		return true
	}
	if entries[0].Prev != AuditGenesis {
		return false
	}
	return VerifyChain(entries, AuditGenesis) == -1
}

// PanicRegisterBuiltins installs the three notifiers in the order that matters: the
// meter first, because it writes the records the sink flush then persists; the sink
// second; the console last, since it is the least likely to matter and the most
// likely to fail on a host that installed no writer.
//
// It is idempotent, so a host can call it from init and from main without the second
// call failing on a duplicate name.
func PanicRegisterBuiltins() {
	for _, b := range []struct {
		name string
		fn   PanicNotifier
	}{
		{"meter", panicCloseMeter},
		{"audit-sink", panicFlushSink},
		{"console", panicFlushConsole},
	} {
		// The only error a duplicate name can produce here, so it is ignored rather
		// than reported: a host calling this twice is asking for the builtins once.
		_ = PanicRegister(b.name, b.fn, panicBudget)
	}
}

// resetPanic clears the previous boot's evidence and releases the flush guard.
//
// It deliberately does NOT clear the notifier chain, and the reasoning is worth
// stating because the opposite choice looks tidier. Clearing them would mean a host
// that registered its chain before calling Boot - the natural place, next to the rest
// of its setup - would silently have no flush chain at all, because Boot resets before
// it applies configuration. Silent loss of the crash dump is the exact failure this
// subsystem exists to prevent, and it would be invisible until the first crash.
//
// The cost of keeping them is that a notifier may read state from a boot that has
// ended. That cost is bounded: the builtins read global kernel state at call time
// rather than closing over anything, so they describe whichever boot is live, and a
// host notifier that does close over stale state still runs under its budget and
// reports honestly in its outcome. A notifier reporting stale numbers is a worse
// dump; a chain that was never registered is no dump.
//
// What must be cleared is the record of the previous boot, because PanicLastFlush
// reporting a crash from before the restart would make a fresh deployment look like
// one that had already failed, and the guard, because a flush interrupted by an exit
// would otherwise leave the next boot unable to flush at all.
func resetPanic() {
	kpanic.mu.Lock()
	kpanic.last = nil
	kpanic.mu.Unlock()
	kpanic.flushing.Store(false)
}

// CrashReport renders a flush for a human, one line per notifier. It exists because
// the structured record is what the chain holds and the operator standing over a dead
// gateway needs the other thing.
func CrashReport(r CrashRecord) string {
	var b []byte
	b = append(b, fmt.Sprintf("kernel flush: reason=%q boot=%d saved=%d lost=%d chain-verified=%t\n",
		r.Reason, r.BootID, r.Saved, r.Lost, r.ChainVerified)...)
	if r.Concurrent {
		b = append(b, "  (a flush was already running; this call did nothing)\n"...)
		return string(b)
	}
	for _, o := range r.Outcomes {
		state := "ok"
		if !o.Completed {
			state = "INCOMPLETE"
		}
		b = append(b, fmt.Sprintf("  %-12s %-10s saved=%-5d lost=%-5d %s\n",
			o.Name, state, o.Saved, o.Lost, o.Detail)...)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// INTEGRATION. Nothing below is wired, because every hook is in a file this one does
// not own and the ordering is a decision the host should make deliberately.
//
// 1. kernel.go, in resetKernel(), first, before the accounting block. Done. It goes
//    first because a flush triggered during the rest of the teardown must not find
//    the subsystems it reads already gone.
//
// 2. boot.go, in Shutdown, after the AuditShutdown record and before resetKernel:
//
//	PanicRegisterBuiltins()
//	PanicFlush("clean shutdown")
//
//    Shutdown is the planned exit and the one place a flush is guaranteed to have a
//    live kernel to read. Without it a clean shutdown loses exactly what a crash
//    loses, which makes the crash path look like the only one that matters.
//
// 3. main.go, in the host binary, around the top level:
//
//	kernel.PanicRegisterBuiltins()
//	kernel.PanicSetCrashWriter(crashFile)
//	defer func() {
//	    if r := recover(); r != nil {
//	        rec := kernel.PanicFlush(fmt.Sprintf("panic: %v", r))
//	        fmt.Fprint(os.Stderr, kernel.CrashReport(rec))
//	        os.Exit(1)
//	    }
//	}()
//
//    This catches a panic in the main goroutine only. A panic in any other goroutine
//    takes the process down and cannot be recovered from anywhere; the mitigation for
//    that is ksched, which runs module work under a kernel-recovered goroutine.
//
// 4. main.go, for signals. This is a host decision rather than a library one, which
//    is why it is reported and not installed: a package that calls signal.Notify
//    changes the behaviour of a process that did not ask it to, and two packages
//    doing it will fight over the same channel.
//
//	sig := make(chan os.Signal, 1)
//	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
//	go func() {
//	    <-sig
//	    rec := kernel.PanicFlush("signal")
//	    fmt.Fprint(os.Stderr, kernel.CrashReport(rec))
//	    os.Exit(1)
//	}()
//
//    SIGKILL and SIGSTOP cannot be caught and nothing here helps with them. A
//    machine losing power loses whatever the sink had not yet synced, which is why
//    internal/auditfile syncs on a count rather than only on close.
//
// 5. internal/auditfile needs no change. Its Sink already has Flush and Close, and
//    panicFlushSink reaches them through an optional interface, so a sink without
//    them is reported as not durable rather than assumed to be.
