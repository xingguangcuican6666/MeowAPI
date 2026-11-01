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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"plugin"
	"sort"
	"strings"
	"sync"

	"github.com/xingguangcuican6666/MeowAPI/abi"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// Component discovery: root/bin is a directory, and what is in it is what the
// console can run.
//
// The owner's requirement was that dropping a file into ./root/bin/xxx adds a
// command, with no rebuild. That is what this file does, and the shape of it is
// forced by two facts about Go plugins rather than chosen:
//
//   - A .so is loaded with plugin.Open, and the symbols it exports are looked up
//     by name. There is no init-time registration path available to it, because
//     the thing that would call kernel.Register is the kernel package, and a
//     component that imports the kernel is invalidated by every kernel change -
//     the exact problem the abi package exists to solve. So the component exports
//     DATA (a manifest, a command slice) and the host registers it.
//   - plugin.Open on a path that failed before can hang the process forever.
//     Measured, not assumed: a .so whose init() panics fails the first Open with
//     a recoverable error and hangs the second one indefinitely. So a path that
//     failed once is remembered and never opened again, for the lifetime of the
//     daemon.
//
// One check that is deliberately absent: the file's execute bit. It looks like the
// obvious thing to require and it is not the thing that matters - plugin.Open calls
// dlopen, which needs the file to be readable and a valid ELF, and does not consult
// the mode. Measured on a 0644 .so, which `go build -buildmode=plugin` produces by
// default: it opens and its symbols resolve. Refusing it would refuse every
// component built the normal way, and the note an operator would read would name a
// permission that has no bearing on whether the load works.
//
// What is also true: loading a .so is not isolation. The
// component runs in this process with this process's privileges, and a component
// that calls os.Exit or starts its own goroutines is outside anything the kernel
// can reach. The kernel's authority model still holds for what the component does
// THROUGH the kernel - its commands run under its own pid's grants - and that is
// the boundary being enforced here.

// The symbol names a component exports. Both live in abi so a component and the
// host cannot disagree about the spelling, and so a mismatch is a compile error in
// the component rather than a silent "no commands found".
const (
	// ManifestSymbol exports the component's declaration as *abi.Manifest. A
	// pointer rather than a value because plugin.Lookup returns a symbol address
	// and a value symbol's type assertion is easy to get subtly wrong across a
	// plugin boundary.
	ManifestSymbol = "MeowAPIManifest"
	// CommandsSymbol exports the component's commands as *[]abi.Command.
	CommandsSymbol = abi.CommandSymbol
	// pluginExtension is what discovery looks for. A file in root/bin without it
	// is reported by `bin` as unrecognized rather than silently ignored, because
	// an operator who dropped a .o or a shell script there deserves to be told.
	pluginExtension = ".so"
)

// component is one discovered file, loaded or not.
type component struct {
	// name is the manifest name, which is what the kernel registry keys on.
	name string
	// path is absolute, resolved at discovery time. A relative path would mean a
	// component's identity changed when the daemon's working directory did.
	path string
	// digest identifies the file's contents, so `reload` can tell "changed" from
	// "same file, still loaded" without trusting mtime.
	digest string
	// pid is set once loaded, and cleared on unload.
	pid kernel.PID
	// loaded reports whether the kernel holds it right now.
	loaded bool
	// failed records a load attempt that did not succeed. A path in this state is
	// never opened again - see the plugin.Open note above.
	failed bool
	// reason is why it failed, for `bin` and for the daemon log.
	reason string
	// commands is how many it contributed, for `bin`.
	commands int
}

// components is the discovery table.
type components struct {
	mu     sync.Mutex
	dir    string
	byPath map[string]*component
	// byName maps a manifest name to the path that provided it, so a second file
	// claiming the same name is refused rather than silently shadowing the first.
	byName map[string]string
}

func newComponents(dir string) *components {
	return &components{
		dir:    dir,
		byPath: map[string]*component{},
		byName: map[string]string{},
	}
}

// scan reads the directory and returns what is in it, newest state merged into the
// existing table. A file that disappeared is dropped from the table only if it is
// not loaded; a loaded component whose file was deleted stays, because unloading
// it is a decision for an operator rather than a consequence of an rm.
func (c *components) scan() ([]*component, []string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", c.dir, err)
	}

	var notes []string
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(c.dir, e.Name())
		abs, err := filepath.Abs(path)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: cannot resolve: %v", e.Name(), err))
			continue
		}
		if !strings.HasSuffix(e.Name(), pluginExtension) {
			notes = append(notes, fmt.Sprintf("%s: not a %s file; ignored", e.Name(), pluginExtension))
			continue
		}
		seen[abs] = true

		digest, err := fileDigest(abs)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}

		existing := c.byPath[abs]
		if existing != nil {
			if existing.digest != digest {
				// Contents changed under a loaded component. Reported and left
				// alone: reloading it silently would mean the operator's `ls`
				// showed a pid whose code is not the code on disk, and the audit
				// chain would have no record of the swap.
				notes = append(notes, fmt.Sprintf("%s: contents changed since it was read; run `reload`",
					e.Name()))
				existing.digest = digest
			}
			continue
		}
		c.byPath[abs] = &component{path: abs, digest: digest}
	}

	for path, comp := range c.byPath {
		if seen[path] || comp.loaded {
			continue
		}
		delete(c.byPath, path)
		if comp.name != "" && c.byName[comp.name] == path {
			delete(c.byName, comp.name)
		}
	}

	out := make([]*component, 0, len(c.byPath))
	for _, comp := range c.byPath {
		out = append(out, comp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, notes, nil
}

// fileDigest hashes a component so "changed" is a fact about contents rather than
// a guess from mtime. A build that preserves mtime, or a clock that moved, would
// make an mtime check report the wrong answer in both directions.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// load opens one component, registers its factory, loads it through the kernel and
// registers its commands. It is the only place plugin.Open is called.
//
// The retry rule is narrower than "never open twice", which is what the first version
// of this enforced and which refused to reload a component that had merely been
// unloaded. Measured: plugin.Open on a path that already succeeded returns the same
// handle and does not re-run its init, so opening it again is safe. What is unsafe,
// measured separately, is a second Open on a path whose first Open FAILED - that one
// hangs the calling goroutine forever. `failed` is therefore the flag, set on every
// failure path below and never cleared for the life of the process.
func (c *components) load(k moduleLoader, table *Table, comp *component) error {
	c.mu.Lock()
	if comp.failed {
		reason := comp.reason
		c.mu.Unlock()
		return fmt.Errorf("%s failed before and was not retried: %s", filepath.Base(comp.path), reason)
	}
	if comp.loaded {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	fail := func(err error) error {
		c.mu.Lock()
		comp.failed = true
		comp.reason = err.Error()
		c.mu.Unlock()
		return err
	}

	p, err := openPlugin(comp.path)
	if err != nil {
		return fail(fmt.Errorf("opening the component: %w", err))
	}

	sym, err := p.Lookup(ManifestSymbol)
	if err != nil {
		return fail(fmt.Errorf("the component exports no %s symbol: %w", ManifestSymbol, err))
	}
	manifestPtr, ok := sym.(*abi.Manifest)
	if !ok {
		return fail(fmt.Errorf("%s must be a *abi.Manifest, and the component exports a %T",
			ManifestSymbol, sym))
	}
	manifest := *manifestPtr

	// The manifest is validated by the kernel on load, but the name is needed
	// here first: it is the registry key, and two files claiming one name is a
	// collision the kernel would report as an opaque "already loaded".
	if manifest.Name == "" {
		return fail(errors.New("the component's manifest has no name"))
	}

	c.mu.Lock()
	if other, taken := c.byName[manifest.Name]; taken && other != comp.path {
		c.mu.Unlock()
		return fail(fmt.Errorf("the name %q is already provided by %s",
			manifest.Name, filepath.Base(other)))
	}
	comp.name = manifest.Name
	c.mu.Unlock()

	// Commands are read BEFORE the load, so a component with a malformed table is
	// refused without having been given a pid. Registering them after OnLoad would
	// mean a component that is already running holds commands nobody validated.
	var cmds []abi.Command
	if sym, err := p.Lookup(CommandsSymbol); err == nil {
		cmdsPtr, ok := sym.(*[]abi.Command)
		if !ok {
			return fail(fmt.Errorf("%s must be a *[]abi.Command, and the component exports a %T",
				CommandsSymbol, sym))
		}
		cmds = *cmdsPtr
	}
	// A component with no commands is legal: it may exist to serve a route or to
	// be dispatched to. What is not legal is a command that fails validation, and
	// Table.Register is all-or-nothing so a partial registration cannot happen.

	// shim is the Module the kernel loads. Its OnLoad is where the component's
	// context becomes available, and it is the only moment the commands can be
	// registered under that context - before it there is no pid to attribute them
	// to, and after it the load has already been recorded.
	shim := &componentModule{cmds: cmds, table: table, path: comp.path}
	kernel.Register(manifest.Name, func() (kernel.Module, error) { return shim, nil })
	// Unregistered on every exit path below, because a factory left in the registry
	// names a component that is not loaded and would make a later `load` of a
	// different file with the same name silently build this one.
	defer func() {
		if !comp.loaded {
			kernel.Unregister(manifest.Name)
		}
	}()

	pid, err := k.LoadModule(manifest)
	if err != nil {
		shim.err = err
		return fail(fmt.Errorf("the kernel refused the component: %w", err))
	}
	if shim.err != nil {
		// OnLoad failed. The kernel has already unwound the load, so the pid is
		// gone; what is left is to report why.
		return fail(fmt.Errorf("the component's OnLoad failed: %w", shim.err))
	}

	c.mu.Lock()
	comp.pid = pid
	comp.loaded = true
	comp.commands = shim.registered
	c.byName[manifest.Name] = comp.path
	c.mu.Unlock()
	return nil
}

// forget unloads a pid that the Daemon unloaded, clearing its discovery entry.
//
// The kernel's Unload is the authority and has already run by the time this is
// called; what would otherwise be wrong is the DISCOVERY table, which is this
// package's own bookkeeping. Without this, `bin` keeps saying "loaded as pid N" for
// a pid the kernel no longer has and `load` refuses with "already loaded" - measured,
// that is exactly what happened before this existed.
//
// An unloaded component may be loaded again. plugin.Open on a path that already
// succeeded returns the same handle and does not re-run its init - measured - so the
// only thing a reload has to get right is the KERNEL side, which is k.Load giving it
// a fresh pid and a fresh context. `failed` stays false so `load` will try again.
func (c *components) forget(pid kernel.PID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for path, comp := range c.byPath {
		if !comp.loaded || comp.pid != pid {
			continue
		}
		comp.loaded = false
		comp.pid = 0
		comp.commands = 0
		if comp.name != "" && c.byName[comp.name] == path {
			delete(c.byName, comp.name)
		}
		return
	}
}

// openPlugin calls plugin.Open with a panic shield, and the shield is not
// defensive habit - it is load-bearing.
//
// A component whose init() panics does not fail Open with an error; it unwinds
// THROUGH Open into this process. Measured, and the stack is worth recording because
// the effect is not obvious from the API: plugin.open runs the shared object's
// initialisers inline, so their panic is this goroutine's panic. Without the recover
// below, one bad .so in root/bin takes the whole daemon down at startup - every
// module with it - which turns a directory an operator drops files into into a way
// to stop the kernel.
//
// What the recover does NOT fix is the follow-up: a .so that panicked this way hangs
// a SECOND plugin.Open on the same path forever. Measured on a component whose init
// panics - the first Open returns the panic through here, the second never returns.
// So the caller records the path in comp.failed and never opens it again. The two
// halves go together: shielding the panic without remembering the path just moves the
// hang to the next attempt.
func openPlugin(path string) (p *plugin.Plugin, err error) {
	defer func() {
		if r := recover(); r != nil {
			p = nil
			err = fmt.Errorf("the component panicked while being opened: %v", r)
		}
	}()
	return plugin.Open(path)
}

// componentModule is the Module shim the kernel loads on a component's behalf.
type componentModule struct {
	cmds  []abi.Command
	table *Table
	path  string

	mu         sync.Mutex
	registered int
	err        error
}

// OnLoad captures the component's context and registers its commands under it.
//
// The context is not stored anywhere the component can reach: it is passed to
// Table.Register, which copies it into each command entry, and the component's own
// code never sees it unless the component kept a copy of what it was handed -
// which the contract in AGENT.md forbids and which the kernel's retirement rule
// makes inert after unload anyway.
func (m *componentModule) OnLoad(ctx kernel.SContext) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cmds) == 0 {
		return nil
	}
	pid := ctx.PID()
	if err := m.table.Register(ctx, pid, m.cmds); err != nil {
		// Returning the error makes the load fail, which is the right outcome: a
		// component whose commands were refused should not be running with a
		// half-registered table.
		m.err = err
		return err
	}
	m.registered = len(m.cmds)
	return nil
}

// OnUnload removes the component's commands. It runs under a hard kernel timeout,
// so it does no I/O.
func (m *componentModule) OnUnload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registered = 0
	return nil
}

// discoverComponents scans root/bin and loads what it finds. Called at startup and
// by `reload`.
func (d *Daemon) discoverComponents() {
	if d.bin == nil {
		d.bin = newComponents(d.BinDir())
	}
	found, notes, err := d.bin.scan()
	if err != nil {
		d.logf("scanning %s: %v", d.BinDir(), err)
		return
	}
	for _, n := range notes {
		d.logf("root/bin: %s", n)
	}
	for _, comp := range found {
		if comp.loaded || comp.failed {
			continue
		}
		if err := d.bin.load(kernelLoader{d.kernel}, d.table, comp); err != nil {
			d.logf("component %s: %v", filepath.Base(comp.path), err)
			continue
		}
		d.logf("component %s loaded as pid %d with %d command(s)",
			filepath.Base(comp.path), comp.pid, comp.commands)
	}
}

// binCommand renders the discovery table.
func (d *Daemon) binCommand() string {
	if d.bin == nil {
		d.bin = newComponents(d.BinDir())
	}
	found, notes, err := d.bin.scan()
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", d.BinDir())
	if err != nil {
		fmt.Fprintf(&b, "  cannot be read: %v\n", err)
		return b.String()
	}
	if len(found) == 0 && len(notes) == 0 {
		b.WriteString("  empty; drop a .so here and run `reload`\n")
		return b.String()
	}
	for _, comp := range found {
		state := "not loaded"
		switch {
		case comp.loaded:
			state = fmt.Sprintf("loaded as pid %d, %d command(s)", comp.pid, comp.commands)
		case comp.failed:
			state = "refused: " + comp.reason
		}
		name := comp.name
		if name == "" {
			name = "(unread)"
		}
		fmt.Fprintf(&b, "  %-24s %-14s %s\n", filepath.Base(comp.path), name, state)
	}
	for _, n := range notes {
		fmt.Fprintf(&b, "  note: %s\n", n)
	}
	return b.String()
}

// loadComponent loads one component by the name an operator typed, which may be a
// base name ("foo"), a name with the extension ("foo.so") or a manifest name.
//
// The path is resolved against BinDir and only against BinDir. An argument is
// never treated as a path, so `load ../../etc/something` cannot reach outside the
// directory: the operator's shell is not a trust boundary the daemon inherits, and
// a command that took a path would be a command that read whatever the session
// could name.
func (d *Daemon) loadComponent(arg string) (kernel.PID, error) {
	if d.bin == nil {
		d.bin = newComponents(d.BinDir())
	}
	if strings.ContainsRune(arg, filepath.Separator) || arg == "." || arg == ".." {
		return 0, fmt.Errorf("%q must name a file in %s, not a path", arg, d.BinDir())
	}

	found, notes, err := d.bin.scan()
	if err != nil {
		return 0, err
	}
	for _, n := range notes {
		d.logf("root/bin: %s", n)
	}

	want := arg
	if !strings.HasSuffix(want, pluginExtension) {
		withExt := arg + pluginExtension
		want = withExt
	}

	for _, comp := range found {
		base := filepath.Base(comp.path)
		if base != want && base != arg && comp.name != arg {
			continue
		}
		if comp.loaded {
			return comp.pid, fmt.Errorf("%s is already loaded as pid %d", base, comp.pid)
		}
		if err := d.bin.load(consoleLoader{d}, d.table, comp); err != nil {
			return 0, err
		}
		d.logf("component %s loaded as pid %d with %d command(s)", base, comp.pid, comp.commands)
		return comp.pid, nil
	}
	return 0, fmt.Errorf("no component named %q in %s; try `bin`", arg, d.BinDir())
}

// reloadComponents re-scans the directory and reports what changed.
//
// It does not unload anything. A reload that swapped running code out from under
// live sessions would be a restart wearing a smaller name, and the honest
// sequence is `unload <pid>` then `load <name>`, which puts both acts on the audit
// chain separately. What reload does is pick up files that appeared and report
// files whose contents changed, so an operator who replaced a .so is told to
// unload and load rather than left believing the swap took effect.
func (d *Daemon) reloadComponents() (string, error) {
	if d.bin == nil {
		d.bin = newComponents(d.BinDir())
	}
	before := map[string]bool{}
	for _, comp := range d.bin.snapshot() {
		before[comp.path] = comp.loaded
	}

	d.discoverComponents()

	var b strings.Builder
	after := d.bin.snapshot()
	loadedNow := 0
	for _, comp := range after {
		if !comp.loaded {
			continue
		}
		loadedNow++
		if !before[comp.path] {
			fmt.Fprintf(&b, "loaded %s as pid %d with %d command(s)\n",
				filepath.Base(comp.path), comp.pid, comp.commands)
		}
	}
	if loadedNow == 0 {
		b.WriteString("nothing is loaded\n")
	} else if b.Len() == 0 {
		fmt.Fprintf(&b, "nothing changed; %d component(s) still loaded\n", loadedNow)
	}
	for _, comp := range after {
		if comp.failed && !before[comp.path] {
			fmt.Fprintf(&b, "refused %s: %s\n", filepath.Base(comp.path), comp.reason)
		}
	}
	return b.String(), nil
}

// snapshot copies the table under the lock, so a render cannot race a load.
func (c *components) snapshot() []*component {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*component, 0, len(c.byPath))
	for _, comp := range c.byPath {
		cp := *comp
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}
