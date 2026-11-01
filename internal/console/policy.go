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

package console

import (
	"fmt"
	"strings"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// `policy` and `harden`: the runtime half of the policy surface.
//
// What can be changed while the kernel runs is only ever a WITHDRAWAL. The compiled
// rules table stays the ceiling, and there is no command here that grants anything -
// kernel.NarrowPolicy has no inverse and the kernel exports none. That asymmetry is
// what makes a live policy edit safe enough to expose at a console at all: the worst
// an authenticated operator can do with it is make the kernel refuse more.
//
// The status half is deliberately readable without authentication. An operator who
// cannot see the posture has no way to notice it was narrowed by someone else, and
// knowing that plugin:dial was withdrawn is not a capability.

// policyReport renders what each domain holds and what has been withdrawn.
func (d *Daemon) policyReport() string {
	withdrawn := kernel.PolicyNarrowing()
	var b strings.Builder
	b.WriteString("domain            holds (compiled ceiling minus any withdrawal)\n")
	for _, dom := range []kernel.Domain{
		kernel.DomainKernel, kernel.DomainInit, kernel.DomainPlugin, kernel.DomainUntrusted,
	} {
		held := kernel.OpsFor(dom)
		if len(held) == 0 {
			fmt.Fprintf(&b, "%-17s (none)\n", dom)
			continue
		}
		fmt.Fprintf(&b, "%-17s %s\n", dom, strings.Join(opNames(held), " "))
		// Printed indented under the domain it applies to, because a withdrawal is a
		// fact about that domain and a separate table would make a reader join two
		// lists to learn one posture.
		if ops := withdrawn[dom]; len(ops) > 0 {
			fmt.Fprintf(&b, "%-17s   withdrawn: %s\n", "", strings.Join(opNames(ops), " "))
		}
	}
	b.WriteString("\nwithdrawals last for this boot only; the compiled table is the ceiling and\n" +
		"`harden` can only remove, never add\n")
	return b.String()
}

// harden withdraws operations from a domain.
//
// The domain is required rather than defaulted. Guessing that an operator meant the
// plugin domain would mean a typo withdraws the wrong posture, and a policy change
// whose target was inferred is one nobody can review afterwards.
//
// Every failure message names what the operator should do instead, because the two
// mistakes here are a misspelled operation and a domain that cannot be narrowed, and
// both are recoverable if the message says so and neither is if it says "invalid".
func (d *Daemon) harden(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: harden <domain> <operation>...  (try `policy` for the list)")
	}

	dom := domainFromName(args[0])
	if dom == "" {
		return "", fmt.Errorf("%q is not a domain this console can narrow; "+
			"the names are init and plugin", args[0])
	}

	ops := make([]kernel.Op, 0, len(args)-1)
	var unknown []string
	for _, name := range args[1:] {
		op, ok := operationFromName(name)
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if !kernel.Allowed(dom, op) {
			// Distinguished from "unknown operation" on purpose: naming an operation
			// the domain does not hold means the operator and the kernel disagree
			// about the current posture, which is worth saying rather than reporting
			// as a typo.
			return "", fmt.Errorf("%s does not hold %s, so there is nothing to withdraw "+
				"(see `policy`)", dom, op)
		}
		ops = append(ops, op)
	}
	if len(unknown) > 0 {
		return "", fmt.Errorf("not an operation name: %s", strings.Join(unknown, ", "))
	}

	if err := d.kernel.NarrowPolicy(dom, ops); err != nil {
		return "", err
	}
	return fmt.Sprintf("withdrew %s from %s for the rest of this boot\n",
		strings.Join(opNames(ops), " "), dom), nil
}

// domainFromName maps what an operator types to a domain. Only the two narrowable
// ones are here: the kernel's own operations and the untrusted domain are not policy
// an operator adjusts while the kernel runs.
func domainFromName(name string) kernel.Domain {
	switch strings.ToLower(name) {
	case "init":
		return kernel.DomainInit
	case "plugin", "plugins", "module", "modules":
		return kernel.DomainPlugin
	default:
		return ""
	}
}

// operationFromName resolves an operation by its exact string. Exact rather than
// prefix-matching: `harden plugin fs` would otherwise withdraw every fs operation at
// once, which is a much larger decision than the one the operator typed.
func operationFromName(name string) (kernel.Op, bool) {
	for _, op := range kernel.OpsFor(kernel.DomainPlugin) {
		if string(op) == name {
			return op, true
		}
	}
	for _, op := range kernel.OpsFor(kernel.DomainInit) {
		if string(op) == name {
			return op, true
		}
	}
	return "", false
}

func opNames(ops []kernel.Op) []string {
	out := make([]string, len(ops))
	for i, o := range ops {
		out[i] = string(o)
	}
	return out
}
