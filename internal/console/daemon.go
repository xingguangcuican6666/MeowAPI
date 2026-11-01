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
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// Daemon is the process that owns a booted kernel.
//
// Its lifetime is the kernel's lifetime, and that is the point: closing a terminal
// closes a Session, not a Daemon. The daemon stops for exactly two reasons - a
// signal, or `poweroff` typed into an authenticated session - and both go through
// the same stop path so there is one place that shuts the kernel down.

// Options configures a daemon before it boots.
type Options struct {
	// Root is the state directory: the socket, the shadow file and root/bin all
	// live under it. Empty means the per-user defaults, which is what an operator
	// running the binary with no flags gets.
	Root string
	// Socket overrides the socket path. When it is empty the default under Root
	// is used; when it is set, that exact path is used, which is what makes
	// `-socket /tmp/x.sock` work for a test or a second instance.
	Socket string
	// BinDir overrides where components are discovered. Empty means Root/bin.
	BinDir string
	// CredentialPath overrides the shadow file location. Empty means Root/shadow.
	CredentialPath string
	// LogWriter receives the daemon's own operational log. Nil means stderr.
	// This is NOT the kernel console, which has its own sink; it is the daemon's
	// view of sessions, loads and stops.
	LogWriter io.Writer
	// Boot is the kernel configuration the daemon boots with.
	Boot kernel.BootConfig
	// Modules are loaded during startup, after the kernel boots and before the
	// first session can attach.
	Modules []kernel.Manifest
}

// Daemon holds one kernel and every attached session.
type Daemon struct {
	opts Options

	kernel *kernel.Kernel
	init   kernel.SContext

	// ttyFD is init's console handle, opened once at startup. Every privileged
	// act goes through it, so the daemon holds one handle rather than opening one
	// per command - and ktty's ceiling is one handle per pid, which makes opening
	// a second one an error rather than a choice.
	ttyFD kernel.FD

	table *Table

	// bin is the component discovery table for root/bin. Created lazily so a
	// daemon that never looks at the directory never stats it.
	bin *components

	credentials *CredentialStore

	listener net.Listener

	// credInstalled records whether the kernel has the console credential. It is
	// installed lazily, the first time a session authenticates against a record,
	// because a credential cannot be installed before the kernel boots and should
	// not be installed when no record exists.
	credMu        sync.Mutex
	credInstalled bool

	mu       sync.Mutex
	sessions map[*Session]struct{}
	nextID   int64

	stopping atomic.Bool
	stopOnce sync.Once
	stopped  chan struct{}
	// stopErr is written once inside stopOnce and read after stopped closes, so
	// the happens-before edge is the channel close rather than a lock.
	stopErr error

	log *log.Logger
}

// New builds a daemon without booting it.
func New(opts Options) *Daemon {
	d := &Daemon{
		opts:     opts,
		sessions: map[*Session]struct{}{},
		stopped:  make(chan struct{}),
	}
	d.log = log.New(opts.LogWriter, "", log.LstdFlags)
	if d.log.Writer() == nil {
		d.log = log.New(os.Stderr, "", log.LstdFlags)
	}
	d.table = NewTable(Builtins(d))
	if p := opts.CredentialPath; p != "" {
		d.credentials = NewCredentialStore(p)
	} else if r := d.root(); r != "" {
		d.credentials = NewCredentialStore(filepath.Join(r, "shadow"))
	}
	return d
}

func (d *Daemon) root() string { return d.opts.Root }

func (d *Daemon) logf(format string, args ...any) { d.log.Printf(format, args...) }

// PID reports the daemon's own process id, for `whoami` and for the banner.
func (d *Daemon) PID() int { return os.Getpid() }

// SocketPath reports where this daemon listens.
func (d *Daemon) SocketPath() string {
	if d.opts.Socket != "" {
		return d.opts.Socket
	}
	return SocketPath(d.opts.Root)
}

// BinDir reports where components are discovered.
func (d *Daemon) BinDir() string {
	if d.opts.BinDir != "" {
		return d.opts.BinDir
	}
	if r := d.opts.Root; r != "" {
		return filepath.Join(r, "bin")
	}
	// The owner's spelling is ./root/bin relative to where the binary runs, and
	// that is the default: a directory in the working tree, so dropping a .so in
	// is a file operation and not a configuration one.
	return filepath.Join("root", "bin")
}

// Start boots the kernel, opens the console handle, binds the socket and serves
// until stopped. It returns the error that ended it, or nil after a clean stop.
//
// The order is load-bearing in one place: the socket is bound BEFORE modules are
// loaded. A component whose load hangs would otherwise leave the daemon
// unreachable with no way to inspect what it was doing, and `status` is exactly
// the command an operator needs at that moment.
func (d *Daemon) Start() error {
	ln, err := Listen(d.SocketPath())
	if err != nil {
		return err
	}
	d.listener = &Listener{Listener: ln, path: d.SocketPath()}
	d.logf("listening on %s (pid %d)", d.SocketPath(), os.Getpid())

	k, err := kernel.Boot(d.opts.Boot)
	if err != nil {
		_ = d.listener.Close()
		return fmt.Errorf("booting the kernel: %w", err)
	}
	d.kernel = k
	d.init = k.InitContext()

	if err := d.openConsole(); err != nil {
		_ = k.Shutdown()
		_ = d.listener.Close()
		return err
	}

	if err := d.publishBootFacts(); err != nil {
		_ = k.Shutdown()
		_ = d.listener.Close()
		return err
	}

	startup := kernelLoader{k}
	for _, m := range d.opts.Modules {
		if _, err := startup.LoadModule(m); err != nil {
			// A static module failing to load is a startup failure, not a
			// degraded start: it was named in the configuration, and a gateway
			// missing its own adapter is worse than one that refuses to come up.
			_ = k.Shutdown()
			_ = d.listener.Close()
			return fmt.Errorf("loading %q: %w", m.Name, err)
		}
	}

	// Components from root/bin are discovered after the static modules, and a
	// failure there is logged rather than fatal. The reason is the asymmetry: a
	// static module is configuration the operator wrote, while a .so in root/bin is
	// whatever is on disk, and refusing to start because one dropped-in component
	// is broken would make the directory a denial-of-service against the kernel.
	d.discoverComponents()

	go d.accept()

	<-d.stopped
	return d.stopErr
}

// accept runs the connection loop.
func (d *Daemon) accept() {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			if d.stopping.Load() {
				return
			}
			// A transient accept error must not end the daemon: it would turn one
			// failed connection into a dead kernel. Logged and continued.
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				d.logf("accept: %v", err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
			d.logf("accept failed, stopping: %v", err)
			d.Stop(fmt.Errorf("the console listener failed: %w", err))
			return
		}
		d.handle(conn)
	}
}

// maxSessions bounds how many terminals may be attached at once. A local user can
// open connections without limit, and each one is a goroutine plus a buffer; the
// bound turns that into a refusal at the door rather than an unbounded heap.
const maxSessions = 16

func (d *Daemon) handle(conn net.Conn) {
	d.mu.Lock()
	if d.stopping.Load() {
		d.mu.Unlock()
		_ = conn.Close()
		return
	}
	full := len(d.sessions) >= maxSessions
	d.nextID++
	id := d.nextID
	s := &Session{id: id, conn: conn, d: d, reader: newBoundedReader(conn)}
	if !full {
		d.sessions[s] = struct{}{}
	}
	d.mu.Unlock()

	if full {
		_ = s.write(fmt.Sprintf("the console is full at %d sessions; try again later\n", maxSessions))
		_ = conn.Close()
		return
	}

	d.logf("session %d attached", id)
	go s.serve()
}

func (d *Daemon) forget(s *Session) {
	d.mu.Lock()
	delete(d.sessions, s)
	d.mu.Unlock()
	d.logf("session %d closed", s.id)
}

// Sessions reports how many terminals are attached.
func (d *Daemon) Sessions() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sessions)
}

// openConsole takes init's single console handle.
//
// init holds tty:open, so this is a legal open, and it is done once at startup
// rather than per command because ktty allows exactly one handle per pid. Every
// privileged command below passes this fd, and the credential passed alongside it
// is checked inside the kernel - the daemon holding a handle is not the same thing
// as the daemon being authorised, which is the distinction that keeps a compromised
// host process from being a compromised kernel.
func (d *Daemon) openConsole() error {
	fd, err := kernel.TTYOpen(d.init)
	if err != nil {
		return fmt.Errorf("opening the kernel console: %w", err)
	}
	d.ttyFD = fd
	return nil
}

// publishBootFacts records what an attached session can read back.
func (d *Daemon) publishBootFacts() error {
	facts := map[string]string{
		"kernel.boot.id":     fmt.Sprintf("boot-%d", time.Now().Unix()),
		"kernel.console.pid": strconv.Itoa(os.Getpid()),
		"kernel.socket":      d.SocketPath(),
		"kernel.bin.dir":     d.BinDir(),
	}
	keys := make([]string, 0, len(facts))
	for k := range facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := d.kernel.Publish(k, facts[k]); err != nil {
			return fmt.Errorf("publishing %s: %w", k, err)
		}
	}
	return nil
}

// credentialSet reports whether a shadow record exists.
func (d *Daemon) credentialSet() bool {
	if d.credentials == nil {
		return false
	}
	_, err := d.credentials.Load()
	return err == nil
}

// passwordChecker returns a verification function for the current record.
//
// It returns a closure rather than the record itself so the hash does not travel
// further than the comparison, and it re-reads the store on each call so a rotation
// in another session takes effect immediately.
func (d *Daemon) passwordChecker() (func(string) bool, error) {
	if d.credentials == nil {
		return nil, errors.New("no credential store is configured")
	}
	cred, err := d.credentials.Load()
	if err != nil {
		return nil, err
	}
	d.ensureKernelCredential()
	return cred.Check, nil
}

// ensureKernelCredential installs the console credential in the kernel the first
// time a session authenticates.
//
// The credential the kernel holds is derived from the shadow record rather than
// being the password itself: what ktty needs is a secret a module cannot read, and
// a derived value is as good for that as the plaintext and better everywhere else,
// because it means the daemon never has to keep a plaintext around to pass to a
// syscall. Rotation reinstalls, and InstallConsoleCredential wipes the buffer it is
// given, so the derived bytes do not outlive the call.
func (d *Daemon) ensureKernelCredential() {
	d.credMu.Lock()
	defer d.credMu.Unlock()
	if d.credInstalled || d.credentials == nil || d.kernel == nil {
		return
	}
	cred, err := d.credentials.Load()
	if err != nil {
		return
	}
	derived := cred.deriveForKernel()
	if err := d.kernel.InstallConsoleCredential(derived); err != nil {
		d.logf("installing the console credential in the kernel: %v", err)
		return
	}
	d.credInstalled = true
}

// kernelCredential returns a fresh copy of the derived credential for one
// privileged call. The kernel wipes what it is given, so each call needs its own
// buffer - passing a shared slice would leave the second call holding zeroes.
func (d *Daemon) kernelCredential() ([]byte, error) {
	if d.credentials == nil {
		return nil, errors.New("no credential store is configured")
	}
	cred, err := d.credentials.Load()
	if err != nil {
		if errors.Is(err, ErrNoCredential) {
			return nil, errors.New("no operator password is set")
		}
		return nil, err
	}
	d.ensureKernelCredential()
	if !d.credInstalled {
		return nil, errors.New("the kernel does not hold a console credential")
	}
	return cred.deriveForKernel(), nil
}

// The moduleLoader interface is what every LOAD and UNLOAD path goes through, and it
// has exactly two implementations below.
//
// It exists so that the privileged path is the only one a session can reach. The
// unprivileged Kernel.Load is used once, at startup, for the modules the daemon was
// configured with - a decision made before any session existed, under the process's
// own authority. Everything an operator triggers goes through consoleLoader, which
// presents the console credential to ktty inside the kernel, so the load is gated on
// the credential AND recorded on the audit chain with the provenance the loader cannot
// know. That is the two-layer model the file header describes, and without this
// interface the second layer was missing for `load` and `unload`: they called
// Kernel.Load, which checks only hostOnly - measured, and it is why this type exists.
type moduleLoader interface {
	LoadModule(m kernel.Manifest) (kernel.PID, error)
	UnloadModule(pid kernel.PID) error
}

// kernelLoader is the daemon's own authority: init's context through the handle. It is
// used for the startup manifest list and for nothing a session can ask for.
type kernelLoader struct{ k *kernel.Kernel }

func (l kernelLoader) LoadModule(m kernel.Manifest) (kernel.PID, error) { return l.k.Load(m) }
func (l kernelLoader) UnloadModule(pid kernel.PID) error                { return l.k.Unload(pid) }

// consoleLoader is an operator's authority: the credential is presented to ktty, the
// operation and the credential are both re-checked inside the kernel, and the act lands
// on the audit chain before the caller sees a result.
type consoleLoader struct{ d *Daemon }

func (l consoleLoader) LoadModule(m kernel.Manifest) (kernel.PID, error) {
	cred, err := l.d.kernelCredential()
	if err != nil {
		return 0, err
	}
	return kernel.TTYLoadModule(l.d.init, l.d.ttyFD, cred, m)
}

func (l consoleLoader) UnloadModule(pid kernel.PID) error {
	cred, err := l.d.kernelCredential()
	if err != nil {
		return err
	}
	return kernel.TTYUnloadModule(l.d.init, l.d.ttyFD, cred, pid)
}

// processTable reads the process table through ktty, so the read is on the audit
// chain.
func (d *Daemon) processTable() ([]kernel.ProcSnapshot, error) {
	cred, err := d.kernelCredential()
	if err != nil {
		return nil, err
	}
	return kernel.TTYProcessTable(d.init, d.ttyFD, cred)
}

// unload removes a module through the console loader, so the unload is gated on the
// credential inside the kernel and recorded with its provenance.
func (d *Daemon) unload(pid kernel.PID) error {
	// The name is read BEFORE the unload, because after it the module is not in
	// LoadedModules and there is no other way to ask what was just removed. It is
	// needed to unregister the factory.
	name := moduleName(pid)
	// Commands first, then the module: a command whose body lives in an unloaded
	// component is a dangling function pointer, and calling it would fault the
	// daemon. Removing them before the unload means there is no window in which
	// `help` offers one.
	removed := d.table.Unregister(pid)
	loader := consoleLoader{d}
	if err := loader.UnloadModule(pid); err != nil {
		// Putting them back is not possible - the kernel refused the unload, and a
		// command body that lives in a component the kernel still holds is still
		// callable - but re-registering would mean re-entering Table.Register with
		// a context this function does not have. So the honest outcome is a failed
		// command with a message saying what state it is in, rather than a command
		// that silently disappeared.
		d.logf("unloading pid %d failed after %d command(s) were dropped: %v", pid, removed, err)
		return err
	}
	if d.bin != nil {
		d.bin.forget(pid)
	}
	// The factory goes too, so a later load of a different file with the same name
	// cannot silently build this one instead.
	if name != "" {
		kernel.Unregister(name)
	}
	d.logf("unloaded pid %d (%d command(s) removed)", pid, removed)
	return nil
}

// status renders the summary an operator asks for first.
func (d *Daemon) status() string {
	var b strings.Builder
	fmt.Fprintf(&b, "daemon   pid %d, socket %s\n", os.Getpid(), d.SocketPath())
	fmt.Fprintf(&b, "kernel   api %d, audit head %s\n", kernel.KernelAPI, kernel.AuditHead())
	fmt.Fprintf(&b, "sessions %d attached (of %d)\n", d.Sessions(), maxSessions)

	modules := kernel.LoadedModules()
	fmt.Fprintf(&b, "modules  %d loaded, %d registered\n", len(modules), len(kernel.Registered()))
	for _, m := range modules {
		fmt.Fprintf(&b, "           pid %-4d %-16s v%s\n", m.PID, m.Name, m.Manifest.Version)
	}

	fmt.Fprintf(&b, "usage    tokens:in=%d tokens:out=%d requests=%d rejected=%d\n",
		kernel.UsageTotal(kernel.UsageTokensIn),
		kernel.UsageTotal(kernel.UsageTokensOut),
		kernel.UsageTotal(kernel.UsageRequests),
		kernel.UsageRejected())

	retained, evicted := kernel.AuditLen()
	fmt.Fprintf(&b, "audit    %d entries retained, %d evicted\n", retained, evicted)

	tty := kernel.TTYStatsSnapshot()
	fmt.Fprintf(&b, "console  %d handle(s), credential installed: %t, %d read(s), %d write(s), %d refusal(s)\n",
		tty.Open, tty.Credential, tty.Reads, tty.Writes, tty.Refused)

	fmt.Fprintf(&b, "commands %d registered\n", d.table.Len())
	if d.credentials == nil {
		b.WriteString("password no credential store is configured\n")
	} else {
		state := "not set"
		if d.credentialSet() {
			state = "set (" + d.credentials.Path() + ")"
		}
		fmt.Fprintf(&b, "password %s\n", state)
	}
	fmt.Fprintf(&b, "bin      %s\n", d.BinDir())
	return b.String()
}

// auditCommand renders recent audit entries.
func (d *Daemon) auditCommand(args []string) (string, error) {
	n := 20
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-n" {
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 1 {
				return "", fmt.Errorf("%q is not a count", args[i+1])
			}
			if v > 500 {
				v = 500
			}
			n = v
		}
	}
	// The whole window is read and the tail is taken, because AuditQuery is
	// oldest-first and its Limit truncates from the FRONT. Asking it for n entries
	// therefore returns the OLDEST n, which is the opposite of what `audit -n`
	// promises - measured on a live daemon: `audit -n 6` showed the boot records and
	// none of the load and unload a moment before it. The window is bounded by the
	// console's retention setting, so reading it whole is bounded too.
	entries := kernel.AuditQuery(kernel.AuditFilter{})
	if len(entries) == 0 {
		return "the audit window is empty\n", nil
	}
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%-6d %-9s %-16s %s  %s\n",
			e.Seq, e.Kind, e.Domain, e.Msg, e.Hash[:12])
	}
	return b.String(), nil
}

// RequestPoweroff asks the daemon to stop because an operator typed `poweroff`.
//
// The stop runs on its own goroutine rather than in the session that asked, so that
// session can finish printing "shutting down" and return to its own teardown while
// the kernel unwinds. A synchronous stop from inside a session would close that
// session's connection from under the command body that requested it.
//
// The id is recorded rather than ignored: the log line saying who stopped the kernel
// is the difference between an operator's decision and a mystery.
//
// Two sessions requesting a poweroff at once produce one stop, because Stop is
// guarded by stopOnce; the second goroutine returns immediately and the first
// recorded cause is the one in the log.
func (d *Daemon) RequestPoweroff(sessionID int64) {
	d.logf("session %d requested a poweroff", sessionID)
	go d.Stop(nil)
}

// Stop ends the daemon. It is safe to call from a signal handler, from a session,
// or twice; the first call wins and the rest return at once.
//
// cause is the error Start returns, and nil means "stopped on request, which is a
// success". A signal and a typed `poweroff` are both requests, so both pass nil;
// a listener that failed passes its error, so the exit status says the daemon died
// rather than that it was asked to stop.
func (d *Daemon) Stop(cause error) {
	d.stopOnce.Do(func() {
		d.stopping.Store(true)
		if cause == nil {
			d.logf("stopping on request")
		} else {
			d.logf("stopping: %v", cause)
		}

		// Sessions are closed before the kernel shuts down, so none of them is
		// mid-command when the state under it goes away.
		d.mu.Lock()
		sessions := make([]*Session, 0, len(d.sessions))
		for s := range d.sessions {
			sessions = append(sessions, s)
		}
		d.mu.Unlock()
		for _, s := range sessions {
			_ = s.write(control(ctrlBye, "the daemon is stopping"))
			_ = s.conn.Close()
		}

		if d.listener != nil {
			_ = d.listener.Close()
		}
		if d.kernel != nil {
			if err := d.kernel.Shutdown(); err != nil {
				d.logf("kernel shutdown reported: %v", err)
				if cause == nil {
					cause = err
				}
			}
		}
		d.stopErr = cause
		close(d.stopped)
	})
}

// Stopped returns a channel closed when the daemon has finished stopping.
func (d *Daemon) Stopped() <-chan struct{} { return d.stopped }

// Stopping reports whether a stop has been requested.
func (d *Daemon) Stopping() bool { return d.stopping.Load() }

// stopErr is written once inside stopOnce and read after stopped closes, so the
// happens-before edge is the channel close rather than a lock.
var _ = fmt.Sprint

// banner is what a session sees first.
func banner(d *Daemon) string {
	return fmt.Sprintf("MeowAPI kernel %d, daemon pid %d\n"+
		"type `help` for commands, `quit` to leave (the kernel keeps running)\n",
		kernel.KernelAPI, os.Getpid())
}

// moduleName reports a loaded module's manifest name, or "" if there is none.
func moduleName(pid kernel.PID) string {
	for _, m := range kernel.LoadedModules() {
		if m.PID == pid {
			return m.Name
		}
	}
	return ""
}
