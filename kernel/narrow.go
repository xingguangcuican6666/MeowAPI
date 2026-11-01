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
	"fmt"
	"sync"

	"github.com/xingguangcuican6666/MeowAPI/abi"
)

// knarrow: the runtime policy change, and the only shape of one that is safe.
//
// policy.go's rules table is compiled in, and it stays the ceiling. What this file
// adds is a set of operations WITHDRAWN from a domain while the kernel is running,
// which can only ever grow. The asymmetry is the whole design:
//
//   - A refusal can be added at any time. Every check asks "does the ceiling hold
//     this, and has it been withdrawn", so a withdrawal takes effect on the next
//     call, against a module that is already loaded, with no reload and no window.
//   - A grant cannot. There is no entry point that removes an operation from the
//     withdrawn set, and the set is never exposed as a mutable map. A policy an
//     attacker can widen is not a policy, and the console credential - the thing an
//     operator presents to reach this - is a secret rather than a proof that the
//     kernel's own ceiling should move.
//
// This is the form tty.go's POLICY NOTE identified as the safe one and left to the
// owner; the owner then chose tightening-only. What that note ruled out was a
// full-table apply, and it still is ruled out: nothing here can name an operation
// the compiled table does not already hold, and nothing here can add one back.
//
// Per boot, not persisted. A narrowing is a decision made about a running kernel,
// and a decision that survived a restart would be one nobody could see they had made.
// resetKernel clears it with the grants, and a boot that wants the narrower posture
// installs it again through the same call.

// narrowMu guards narrowed. It is a separate lock from grantsMu because the two are
// read on different paths - Allowed is called by manifest validation and by the
// per-call check, GrantsFor only by the latter - and sharing one lock would make
// every policy decision serialize behind a grant read.
var (
	narrowMu sync.RWMutex
	narrowed = map[Domain]map[Op]struct{}{}
)

// narrowedIn reports whether op has been withdrawn from dom.
func narrowedIn(dom Domain, op Op) bool {
	narrowMu.RLock()
	defer narrowMu.RUnlock()
	set, ok := narrowed[dom]
	if !ok {
		return false
	}
	_, ok = set[op]
	return ok
}

// Narrowed reports whether an operation has been withdrawn from a domain at runtime.
// It is exported for the console and for the dump, which have to be able to show an
// operator what posture the kernel is in rather than only the table it was built with.
func Narrowed(dom Domain, op Op) bool { return narrowedIn(dom, op) }

// PolicyNarrowing returns a copy of everything withdrawn this boot, sorted by domain
// and then by operation. A copy, so a caller cannot reach the live map.
func PolicyNarrowing() map[Domain][]Op {
	narrowMu.RLock()
	defer narrowMu.RUnlock()

	out := make(map[Domain][]Op, len(narrowed))
	for dom, set := range narrowed {
		if len(set) == 0 {
			continue
		}
		ops := make([]Op, 0, len(set))
		for op := range set {
			ops = append(ops, op)
		}
		sortOps(ops)
		out[dom] = ops
	}
	return out
}

// narrowableDomains are the domains a runtime narrowing may name.
//
// The kernel domain is deliberately absent. Its operations are the ones the boot
// sequence itself needs - module load, fork, the console - and a narrowing there
// would not tighten the system against a module, it would break the kernel's own
// ability to run. The failure would arrive later and somewhere else, which is the
// worst kind of policy change. An operator who wants the kernel to do less changes
// the compiled table, which is reviewed.
var narrowableDomains = map[Domain]bool{
	DomainInit:   true,
	DomainPlugin: true,
}

// NarrowPolicy withdraws operations from a domain for the rest of the boot.
//
// It is a method on the handle and not a free function for the reason
// InstallConsoleCredential is: Boot refuses a second call, every field of Kernel is
// unexported, and a module never receives the handle. A value that cannot be
// obtained cannot be used, which is a structural gate rather than a check someone
// has to remember to write.
//
// Every operation named must be one the domain holds TODAY and has not already had
// withdrawn. Naming one it does not hold is refused rather than ignored, because the
// two failures an operator makes here are a typo and a wrong domain, and silently
// accepting either leaves the operator believing a policy is in force that is not.
//
// All-or-nothing: if any name in the batch is refused, none is applied. A partially
// applied narrowing is a posture nobody can describe, and the next operator to read
// it would have to reconstruct which half landed.
func (k *Kernel) NarrowPolicy(dom Domain, ops []Op) error {
	if err := k.hostOnly(); err != nil {
		return err
	}
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return fmt.Errorf("kernel: already shut down")
	}

	if len(ops) == 0 {
		return fmt.Errorf("kernel: NarrowPolicy needs at least one operation")
	}
	if !narrowableDomains[dom] {
		return fmt.Errorf("kernel: domain %q cannot be narrowed at runtime; "+
			"the kernel's own operations and the untrusted domain are not policy an "+
			"operator adjusts while the kernel runs", dom)
	}

	// Checked before anything is applied, so a batch containing one bad name changes
	// nothing. The ceiling check is against the compiled table, not against the
	// already-narrowed view: withdrawing something twice is a no-op an operator may
	// reach by re-running a command, and refusing it would make the call
	// non-idempotent for no gain.
	for _, op := range ops {
		if !ceilingAllows(dom, op) {
			return fmt.Errorf("kernel: %s does not hold %s, so there is nothing to withdraw",
				dom, op)
		}
		if narrowedIn(dom, op) {
			continue
		}
	}

	narrowMu.Lock()
	set, ok := narrowed[dom]
	if !ok {
		set = map[Op]struct{}{}
		narrowed[dom] = set
	}
	added := make([]Op, 0, len(ops))
	for _, op := range ops {
		if _, already := set[op]; already {
			continue
		}
		set[op] = struct{}{}
		added = append(added, op)
	}
	narrowMu.Unlock()

	if len(added) == 0 {
		// Every name was already withdrawn. Reported as success because the posture
		// the caller asked for is the one in force, and a second run of the same
		// command should not read as a failure.
		return nil
	}

	sortOps(added)
	kaudit.record(AuditPolicy, k.initCtx, "policy narrowed at runtime", map[string]any{
		"domain": dom, "withdrawn": opStrings(added),
	})
	kconsole.Emit(LogWarn, 0, DomainKernel, "policy narrowed at runtime", map[string]any{
		"domain": dom, "withdrawn": opStrings(added),
	})
	return nil
}

// resetNarrowing clears the withdrawn set for a fresh boot. Called only from
// resetKernel, in the grants block, because the two together are "what a context may
// do" and a boot that kept one without the other would be a posture with no name.
func resetNarrowing() {
	narrowMu.Lock()
	defer narrowMu.Unlock()
	narrowed = map[Domain]map[Op]struct{}{}
}

// compile-time assertion that the alias this file names is the abi one. Kept because
// a future refactor that gives kernel its own Op type would make NarrowPolicy's
// signature drift from the interface a console calls through.
var _ abi.Op = Op("")
