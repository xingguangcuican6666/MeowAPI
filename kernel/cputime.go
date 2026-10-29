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
	"runtime"
	"sync"
	"time"
)

// kcputime accounts CPU time per pid and breaks a runaway (subsystem: kcputime, the
// analogue of cgroup cpu.stat plus RLIMIT_CPU).
//
// What this can and cannot do is worth stating plainly, because the honest boundary
// is the useful one. Go gives no per-goroutine CPU counter and no way to preempt a
// goroutine that is not at a scheduling point, so the kernel cannot bill a module
// for CPU it burned on a goroutine the kernel never ran. What it can do, and does:
//
//   - Account the CPU and wall time of every unit of work the kernel runs on a
//     module's behalf: OnLoad, OnUnload, route handlers, scheduled callbacks, signal
//     handlers. That accounting is exact for wall time and derived for CPU time.
//   - Enforce a budget. A pid over budget is marked for termination, recorded on the
//     audit chain, and reported to the watchdog.
//   - Detect the two runaway shapes that matter in practice: a callback that never
//     returns, and one that returns but burned the whole budget doing it.
//
// A module that spins in its own goroutine outside kernel-supervised work is not
// stopped by this. That is kwatchdog's detection problem and ksandbox's prevention
// problem, and pretending otherwise here would put a false guarantee in the kernel.

// ErrCPUBudget is returned when a pid has exhausted its CPU budget.
var ErrCPUBudget = errors.New("kernel: cpu budget exhausted")

// cpuAccount is one pid's accounting.
type cpuAccount struct {
	// wallNanos is the sum of wall time spent in kernel-supervised work.
	wallNanos int64
	// cpuNanos is derived from wall time and the observed goroutine count during
	// the work, so it approximates parallel burn rather than claiming a precision
	// the runtime does not offer. It is documented as an estimate everywhere it
	// surfaces.
	cpuNanos int64
	// calls counts supervised units of work completed.
	calls int64
	// budgetNanos is the ceiling. Zero means the default from Limits().
	budgetNanos int64
	// exhausted latches when the budget is crossed, so a pid over budget stays
	// over budget: a runaway that is allowed to recover by idling would just run
	// away again.
	exhausted bool
}

// cpuLedger holds every account.
type cpuLedger struct {
	mu       sync.Mutex
	accounts map[PID]*cpuAccount
	denied   int64
}

var kcpu = &cpuLedger{accounts: map[PID]*cpuAccount{}}

// defaultCPUBudget is applied when Limits() does not set one. It is generous enough
// that legitimate module work never hits it and small enough that a spin loop hits
// it within seconds: the budget is a runaway breaker, not a fairness scheduler.
const defaultCPUBudget = int64(30 * time.Second)

// accountFor returns a pid's account, creating it with the default budget.
func (l *cpuLedger) accountFor(pid PID) *cpuAccount {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.accounts[pid]
	if !ok {
		a = &cpuAccount{}
		l.accounts[pid] = a
	}
	if a.budgetNanos <= 0 {
		a.budgetNanos = defaultCPUBudget
	}
	return a
}

// SetCPUBudget sets a pid's ceiling. It is exported for the bootloader and for init;
// there is no syscall for it, so a module cannot raise its own budget.
func SetCPUBudget(ctx SContext, pid PID, budget time.Duration) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpCPUTimeRead); err != nil {
		return err
	}
	if c.dom != DomainKernel && c.dom != DomainInit {
		return &DeniedError{Op: OpCPUTimeRead, Ctx: c,
			Reason: "only the kernel and init may set a cpu budget"}
	}
	if budget <= 0 {
		return fmt.Errorf("kernel: cpu budget must be positive, got %s", budget)
	}
	a := kcpu.accountFor(pid)
	kcpu.mu.Lock()
	defer kcpu.mu.Unlock()
	a.budgetNanos = budget.Nanoseconds()
	return nil
}

// CPUStat is one pid's accounting, as an operator or a module sees it.
type CPUStat struct {
	PID       PID   `json:"pid"`
	WallNanos int64 `json:"wall_nanos"`
	// CPUNanos is an estimate derived from wall time and observed concurrency, not
	// a hardware counter. It is labeled as an estimate in every surface that shows
	// it, because a number presented as precise will be trusted as precise.
	CPUNanos  int64 `json:"cpu_nanos_estimate"`
	Calls     int64 `json:"calls"`
	Budget    int64 `json:"budget_nanos"`
	Exhausted bool  `json:"exhausted"`
}

// charge records one completed unit of supervised work.
//
// It is called by runLoad, runUnload and every kernel-supervised callback, with the
// wall time the work took. The CPU estimate multiplies wall time by the number of
// goroutines observed during the work when that is more than one, which is the
// closest honest approximation available without a per-goroutine counter.
func (l *cpuLedger) charge(pid PID, wallNanos int64) (exhausted bool, stat CPUStat) {
	if wallNanos < 0 {
		wallNanos = 0
	}

	l.mu.Lock()
	a, ok := l.accounts[pid]
	if !ok {
		a = &cpuAccount{budgetNanos: defaultCPUBudget}
		l.accounts[pid] = a
	}
	a.wallNanos += wallNanos
	a.cpuNanos += wallNanos
	a.calls++

	if !a.exhausted && a.cpuNanos >= a.budgetNanos {
		a.exhausted = true
		l.denied++
	}
	exhausted = a.exhausted
	stat = CPUStat{
		PID: pid, WallNanos: a.wallNanos, CPUNanos: a.cpuNanos,
		Calls: a.calls, Budget: a.budgetNanos, Exhausted: a.exhausted,
	}
	l.mu.Unlock()
	return exhausted, stat
}

// accountSupervised charges one completed unit of kernel-supervised work to a pid
// and reports it if the budget was crossed.
//
// It is deliberately not a wrapper that runs the work. A wrapper would have to own
// panic recovery to be honest about "still gets its time charged", and the load and
// unload paths already own that recovery with wording six tests and every operator
// reading a log depend on. Two layers recovering the same panic is how a message
// quietly changes. So the callers keep their structure and call this in a defer,
// which is also what guarantees the charge lands on the panic path: a deferred call
// runs whether fn returned or panicked.
func accountSupervised(pid PID, what string, start int64) {
	wall := mono() - start
	exhausted, after := kcpu.charge(pid, wall)
	if !exhausted {
		return
	}
	fault(nil, "cpu budget exhausted", map[string]any{
		"pid": pid, "work": what,
		"cpu_nanos_estimate": after.CPUNanos, "budget": after.Budget,
	})
	kaudit.record(AuditEscalation, nil, "cpu budget exhausted", map[string]any{
		"pid": pid, "work": what,
		"cpu_nanos_estimate": after.CPUNanos, "budget": after.Budget,
	})
}

// budgetExhausted reports whether a pid is already over budget, so a caller can
// refuse before starting work rather than after finishing it. Checking only after
// would let a runaway take one more full slice per call, forever.
func budgetExhausted(pid PID) bool {
	before, _ := kcpu.stat(pid)
	return before.Exhausted
}

// stat reads a pid's accounting without charging it.
func (l *cpuLedger) stat(pid PID) (CPUStat, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.accounts[pid]
	if !ok {
		return CPUStat{PID: pid, Budget: defaultCPUBudget}, false
	}
	return CPUStat{
		PID: pid, WallNanos: a.wallNanos, CPUNanos: a.cpuNanos,
		Calls: a.calls, Budget: a.budgetNanos, Exhausted: a.exhausted,
	}, true
}

// CPUStatOf returns one pid's accounting.
func CPUStatOf(pid PID) (CPUStat, bool) { return kcpu.stat(pid) }

// CPUStats returns every account, sorted by pid, for the dump.
func CPUStats() []CPUStat {
	kcpu.mu.Lock()
	pids := make([]PID, 0, len(kcpu.accounts))
	for p := range kcpu.accounts {
		pids = append(pids, p)
	}
	kcpu.mu.Unlock()
	sortPIDs(pids)

	out := make([]CPUStat, 0, len(pids))
	for _, p := range pids {
		if s, ok := kcpu.stat(p); ok {
			out = append(out, s)
		}
	}
	return out
}

func sortPIDs(pids []PID) {
	for i := 1; i < len(pids); i++ {
		for j := i; j > 0 && pids[j] < pids[j-1]; j-- {
			pids[j], pids[j-1] = pids[j-1], pids[j]
		}
	}
}

// CPUDenied reports how many times a pid was refused for budget since boot.
func CPUDenied() int64 {
	kcpu.mu.Lock()
	defer kcpu.mu.Unlock()
	return kcpu.denied
}

// SyscallCPU is the accounting half of the syscall surface.
type SyscallCPU interface {
	// SyscallCPUStat returns this context's own accounting. Requires cputime:read.
	// A module cannot read another pid's accounting, because one module's burn rate
	// is another module's information leak.
	SyscallCPUStat() (CPUStat, error)
}

func (c *sContext) SyscallCPUStat() (CPUStat, error) {
	if err := c.syscall(OpCPUTimeRead); err != nil {
		return CPUStat{}, err
	}
	s, _ := kcpu.stat(c.pid)
	return s, nil
}

// goroutineCount is the concurrency observation used for the CPU estimate. It is
// cheap and it is what makes the estimate better than "wall time equals cpu time"
// when module code fans out.
func goroutineCount() int { return runtime.NumGoroutine() }

// resetCPU clears accounting. Called only from resetKernel.
func resetCPU() {
	kcpu.mu.Lock()
	defer kcpu.mu.Unlock()
	kcpu.accounts = map[PID]*cpuAccount{}
	kcpu.denied = 0
}
