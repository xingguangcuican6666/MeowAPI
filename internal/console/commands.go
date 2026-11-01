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
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/xingguangcuican6666/MeowAPI/abi"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// The command table.
//
// A command is a name, one line of help, an authority requirement and a body. The
// table is dynamic in the sense the owner asked for: a component dropped into
// root/bin contributes commands at load time and they appear in `help` for every
// session, with no rebuild and no edit to this file. The builtins below are the
// ones the kernel needs to be operable at all, and they are registered first so a
// component cannot replace one - see Register's refusal.
//
// The authority model is two-layered and both layers matter. A command marked
// Privileged needs an authenticated session, which is this package's own check
// against the shadow record. A command that then performs a kernel act goes
// through ktty's syscalls, which re-check the operation and the console credential
// INSIDE the kernel and put the act on the audit chain. The first layer answers
// "is a human at this keyboard who knows the password"; the second answers "may
// this pid do this". Neither substitutes for the other, and a command that only
// had the first would be a privilege the audit trail never saw.

// maxCommandNameLen and maxHelpLen bound what a component may contribute. A table
// an operator reads is a surface, and an unbounded string in it is a place to hide
// a payload - the same reasoning keyring.go gives for bounding an alias.
const (
	maxCommandNameLen = 32
	maxHelpLen        = 200
	maxCommands       = 256
)

// Builtin is a command defined by this package rather than contributed by a
// component. The body takes the session, so it can print progressively, ask for a
// password, or request a shutdown - things a component's command must not do,
// which is why a component's signature is narrower (see abi.Command).
type Builtin struct {
	Name string
	Help string
	// Privileged commands need an authenticated session.
	Privileged bool
	// Run returns text to print, or an error. A nil error with empty text prints
	// nothing, which is how a command that already wrote its own output says so.
	Run func(s *Session, args []string) (string, error)
}

// entry is one row of the table, whichever kind it came from.
type entry struct {
	name       string
	help       string
	privileged bool
	builtin    *Builtin
	// module is set for a contributed command: the context it runs under and the
	// operation its session must hold.
	module *moduleCommand
}

// moduleCommand is a component's contribution, with the context it runs under.
type moduleCommand struct {
	cmd abi.Command
	// ctx is the context the component was loaded with, captured at registration
	// and never re-read: the command runs with the component's own authority, the
	// same rule a route dispatch follows.
	ctx kernel.SContext
	// pid names the component, for `help -v` and for removal on unload.
	pid kernel.PID
}

// Table is the command registry. It is safe for concurrent use because sessions
// run concurrently and a load can add a command while another session is listing.
type Table struct {
	mu      sync.RWMutex
	entries map[string]*entry
	order   []string
}

// NewTable returns a table holding the builtins.
func NewTable(builtins []Builtin) *Table {
	t := &Table{entries: map[string]*entry{}}
	for i := range builtins {
		b := builtins[i]
		// A malformed builtin is a programming error in this package, not operator
		// input, so it is skipped rather than surfaced at runtime - and the skip is
		// loud in tests, which construct the table and check its length.
		if err := t.addBuiltin(b); err != nil {
			continue
		}
	}
	return t
}

func (t *Table) addBuiltin(b Builtin) error {
	if err := validateName(b.Name); err != nil {
		return err
	}
	if len(b.Help) > maxHelpLen {
		return fmt.Errorf("help for %q is %d bytes, above the ceiling %d", b.Name, len(b.Help), maxHelpLen)
	}
	if t.entries[b.Name] != nil {
		return fmt.Errorf("%q is already registered", b.Name)
	}
	if len(t.entries) >= maxCommands {
		return fmt.Errorf("the command table is full at %d entries", maxCommands)
	}
	t.entries[b.Name] = &entry{name: b.Name, help: b.Help, privileged: b.Privileged, builtin: &b}
	t.order = append(t.order, b.Name)
	return nil
}

// Register adds a component's commands. It is called by the loader after the
// kernel has accepted the component, so the commands it registers are already
// attributable to a pid on the audit chain.
//
// Every command in the batch is validated before any is added, and the batch is
// all-or-nothing. A component that contributes nine valid commands and one whose
// name collides with a builtin gets none of them, and the error says which. The
// alternative - adding the good ones and reporting the bad one - leaves a
// component half-registered, which is the state that is hardest to reason about
// afterwards and easiest to mistake for a working load.
func (t *Table) Register(ctx kernel.SContext, pid kernel.PID, cmds []abi.Command) error {
	if ctx == nil {
		return errors.New("a command registration needs the context it runs under")
	}
	if len(cmds) == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	pending := make([]*entry, 0, len(cmds))
	for _, c := range cmds {
		if err := validateName(c.Name); err != nil {
			return fmt.Errorf("pid %d: %w", pid, err)
		}
		if len(c.Help) > maxHelpLen {
			return fmt.Errorf("pid %d: help for %q is %d bytes, above the ceiling %d",
				pid, c.Name, len(c.Help), maxHelpLen)
		}
		if c.Run == nil {
			return fmt.Errorf("pid %d: command %q has no body", pid, c.Name)
		}
		if existing := t.entries[c.Name]; existing != nil {
			if existing.builtin != nil {
				return fmt.Errorf("pid %d: %q is a kernel builtin and cannot be replaced", pid, c.Name)
			}
			return fmt.Errorf("pid %d: %q is already registered by pid %d", pid, c.Name, existing.module.pid)
		}
		if c.Requires != "" && !holdsOp(ctx, c.Requires) {
			return fmt.Errorf("pid %d: command %q requires %s, which this component does not hold",
				pid, c.Name, c.Requires)
		}
		if len(t.entries)+len(pending) >= maxCommands {
			return fmt.Errorf("pid %d: the command table is full at %d entries", pid, maxCommands)
		}
		mc := &moduleCommand{cmd: c, ctx: ctx, pid: pid}
		pending = append(pending, &entry{
			name: c.Name, help: c.Help, privileged: c.Requires != "", module: mc,
		})
	}

	for _, e := range pending {
		t.entries[e.name] = e
		t.order = append(t.order, e.name)
	}
	return nil
}

// holdsOp reports whether a context's own grants include op. It asks the kernel
// rather than trusting the component: GrantsFor returns the effective set after
// manifest narrowing, which is the set that will actually be checked when the
// command runs.
//
// A context that is not manifest-constrained - init - holds its domain ceiling,
// and that is reported as "constrained == false", meaning every operation its
// domain allows. Such a context is never the one registering a component's
// commands, but handling it explicitly keeps the check from refusing by accident.
func holdsOp(ctx kernel.SContext, op abi.Op) bool {
	ops, constrained := kernel.GrantsFor(ctx.PID())
	if !constrained {
		return kernel.Allowed(ctx.Domain(), op)
	}
	for _, o := range ops {
		if o == op {
			return true
		}
	}
	return false
}

// Unregister removes every command a pid contributed. Called on unload, so a
// component that goes away takes its commands with it: leaving them would mean
// `help` offering a command whose body lives in an unmapped .so.
func (t *Table) Unregister(pid kernel.PID) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	removed := 0
	for name, e := range t.entries {
		if e.module != nil && e.module.pid == pid {
			delete(t.entries, name)
			removed++
		}
	}
	if removed > 0 {
		out := t.order[:0]
		for _, n := range t.order {
			if t.entries[n] != nil {
				out = append(out, n)
			}
		}
		t.order = out
	}
	return removed
}

// Lookup finds a command by name.
func (t *Table) Lookup(name string) (*entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[name]
	return e, ok
}

// Names returns the registered command names in registration order.
func (t *Table) Names() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, len(t.order))
	copy(out, t.order)
	return out
}

// Len reports how many commands are registered, for the ceiling test.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

// validateName is the shape rule for a command name. It is checked here and not
// left to the operator's shell because the name is what a session looks up: a
// name with a space could never be typed, and a name with a leading control byte
// would collide with the protocol.
func validateName(name string) error {
	if name == "" {
		return errors.New("a command name must not be empty")
	}
	if len(name) > maxCommandNameLen {
		return fmt.Errorf("command name %q is %d bytes, above the ceiling %d",
			truncate(name), len(name), maxCommandNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == ':'
		if !ok {
			return fmt.Errorf("command name %q contains %q; a name is lowercase letters, "+
				"digits, '-', '_' and ':'", truncate(name), string(c))
		}
	}
	return nil
}

// Help renders the table for an operator. Sorting is by name rather than
// registration order because an operator scanning for a word reads alphabetically,
// while registration order is what `Names` keeps for a stable dump.
func (t *Table) Help(s *Session) string {
	t.mu.RLock()
	names := make([]string, 0, len(t.entries))
	byName := make(map[string]*entry, len(t.entries))
	for n, e := range t.entries {
		names = append(names, n)
		byName[n] = e
	}
	t.mu.RUnlock()
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("commands:\n")
	width := 0
	for _, n := range names {
		if len(n) > width {
			width = len(n)
		}
	}
	for _, n := range names {
		e := byName[n]
		mark := " "
		if e.privileged {
			mark = "*"
		}
		fmt.Fprintf(&b, "  %s %-*s  %s\n", mark, width, n, e.help)
	}
	b.WriteString("\n  * needs this session to be authenticated\n")
	if !s.authenticated.Load() {
		b.WriteString("  you are not authenticated; run `auth` first\n")
	}
	return b.String()
}

// Builtins is the kernel's own command set. The order here is the order `help`
// would show if it were not sorted, and it is roughly the order an operator meets
// them: orient, look, act, leave.
func Builtins(d *Daemon) []Builtin {
	return []Builtin{
		{
			Name: "help",
			Help: "list commands, or `help <name>` for one",
			Run: func(s *Session, args []string) (string, error) {
				if len(args) == 0 {
					return d.table.Help(s), nil
				}
				e, ok := d.table.Lookup(args[0])
				if !ok {
					return "", fmt.Errorf("no command named %q", args[0])
				}
				auth := "no"
				if e.privileged {
					auth = "yes"
				}
				return fmt.Sprintf("%s\n  %s\n  authenticated session required: %s\n",
					e.name, e.help, auth), nil
			},
		},
		{
			Name: "auth",
			Help: "authenticate this session with the operator password",
			Run: func(s *Session, args []string) (string, error) {
				if s.authenticated.Load() {
					return "this session is already authenticated\n", nil
				}
				if err := s.authenticate(); err != nil {
					return "", err
				}
				return "authenticated\n", nil
			},
		},
		{
			Name: "whoami",
			Help: "show this session's identity and authority",
			Run: func(s *Session, args []string) (string, error) {
				state := "unauthenticated"
				if s.authenticated.Load() {
					state = "authenticated"
				}
				return fmt.Sprintf("session %d, %s, connected to pid %d\n",
					s.id, state, d.PID()), nil
			},
		},
		{
			Name: "status",
			Help: "kernel, module, console and usage summary",
			Run: func(s *Session, args []string) (string, error) {
				return d.status(), nil
			},
		},
		{
			Name: "ps",
			Help: "the process table",
			// Privileged: it is a read, but it is a read of every pid's identity and
			// manifest digest, and ktty gates it on the console credential for the
			// same reason. Going through TTYProcessTable keeps the read on the audit
			// chain rather than making it a free look.
			Privileged: true,
			Run: func(s *Session, args []string) (string, error) {
				rows, err := d.processTable()
				if err != nil {
					return "", err
				}
				var b strings.Builder
				b.WriteString("pid   uid    ppid  domain            name            state\n")
				for _, r := range rows {
					fmt.Fprintf(&b, "%-5d %-6d %-5d %-17s %-15s %s\n",
						r.PID, r.UID, r.PPID, r.Domain, r.Name, r.State)
				}
				return b.String(), nil
			},
		},
		{
			Name: "ls",
			Help: "loaded modules and their effective grants",
			Run: func(s *Session, args []string) (string, error) {
				modules := kernel.LoadedModules()
				if len(modules) == 0 {
					return "no modules are loaded\n", nil
				}
				var b strings.Builder
				for _, m := range modules {
					fmt.Fprintf(&b, "pid %-4d %-16s v%-8s %d operation(s)\n",
						m.PID, m.Name, m.Manifest.Version, len(m.Effective))
					if len(args) > 0 && args[0] == "-v" {
						for _, op := range m.Effective {
							fmt.Fprintf(&b, "    %s\n", op)
						}
					}
				}
				if len(args) == 0 {
					b.WriteString("\n  `ls -v` lists each module's operations\n")
				}
				return b.String(), nil
			},
		},
		{
			Name: "log",
			Help: "console history; `log -f` follows, `log -n N` sets the count",
			Run: func(s *Session, args []string) (string, error) {
				return d.logCommand(s, args)
			},
		},
		{
			Name: "audit",
			Help: "recent audit entries; `audit -n N` sets the count",
			Run: func(s *Session, args []string) (string, error) {
				return d.auditCommand(args)
			},
		},
		{
			Name: "dump",
			Help: "a read-only rendering of kernel state",
			Run: func(s *Session, args []string) (string, error) {
				var b strings.Builder
				if err := kernel.Dump(&b); err != nil {
					return "", err
				}
				return b.String(), nil
			},
		},
		{
			Name: "bin",
			Help: "list the components in root/bin and whether each is loaded",
			Run: func(s *Session, args []string) (string, error) {
				return d.binCommand(), nil
			},
		},
		{
			Name:       "load",
			Help:       "load a component from root/bin by name",
			Privileged: true,
			Run: func(s *Session, args []string) (string, error) {
				if len(args) != 1 {
					return "", errors.New("usage: load <name>")
				}
				pid, err := d.loadComponent(args[0])
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("loaded %q as pid %d\n", args[0], pid), nil
			},
		},
		{
			Name:       "unload",
			Help:       "unload a module by pid",
			Privileged: true,
			Run: func(s *Session, args []string) (string, error) {
				if len(args) != 1 {
					return "", errors.New("usage: unload <pid>")
				}
				var pid kernel.PID
				if _, err := fmt.Sscanf(args[0], "%d", &pid); err != nil {
					return "", fmt.Errorf("%q is not a pid", args[0])
				}
				if err := d.unload(pid); err != nil {
					return "", err
				}
				return fmt.Sprintf("unloaded pid %d\n", pid), nil
			},
		},
		{
			Name:       "reload",
			Help:       "re-scan root/bin and reload what changed",
			Privileged: true,
			Run: func(s *Session, args []string) (string, error) {
				return d.reloadComponents()
			},
		},
		{
			Name:       "harden",
			Help:       "withdraw operations from a domain for the rest of this boot: harden <domain> <op>...",
			Privileged: true,
			Run: func(s *Session, args []string) (string, error) {
				return d.harden(args)
			},
		},
		{
			Name: "policy",
			Help: "show the operation set each domain holds, and what was withdrawn",
			Run: func(s *Session, args []string) (string, error) {
				return d.policyReport(), nil
			},
		},
		{
			Name: "passwd",
			Help: "set or change the operator password",
			Run: func(s *Session, args []string) (string, error) {
				return "", s.changePassword()
			},
		},
		{
			Name: "quit",
			Help: "close this session; the kernel keeps running",
			Run: func(s *Session, args []string) (string, error) {
				s.closeRequested = true
				return "", nil
			},
		},
		{
			Name:       "poweroff",
			Help:       "shut the kernel down and stop the daemon",
			Privileged: true,
			Run: func(s *Session, args []string) (string, error) {
				s.poweroffRequested = true
				return "shutting down\n", nil
			},
		},
	}
}
