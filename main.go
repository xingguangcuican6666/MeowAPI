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

// MeowAPI boots a microkernel and puts an operator at a console.
//
// Running it with no flags does what an operator expects from a daemon: if a kernel
// is already running, this process attaches to it; if not, one is started detached
// and then attached to. Closing the terminal ends the attachment and nothing else.
// The kernel stops for a SIGTERM, a SIGINT, or `poweroff` typed into an
// authenticated session.
//
// -once keeps the old one-shot behaviour - boot, print a report, shut down - which
// is what CI runs and what a script that wants a single kernel lifetime wants.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xingguangcuican6666/MeowAPI/internal/auditfile"
	"github.com/xingguangcuican6666/MeowAPI/internal/console"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag" // its init() registers the diag module
)

// options is every flag, in one struct so the three modes cannot disagree about
// what a flag means.
type options struct {
	once      bool
	daemon    bool
	socket    string
	root      string
	binDir    string
	textMode  bool
	logLevel  string
	dumpState bool
	auditPath string
	crashPath string
}

func parseFlags() *options {
	o := &options{}
	flag.BoolVar(&o.once, "once", false,
		"boot, print one report and shut down (no daemon, no console)")
	flag.BoolVar(&o.daemon, "daemon", false,
		"run the kernel in the foreground as a daemon; this is what the started daemon uses")
	flag.StringVar(&o.socket, "socket", "",
		"the console socket path; defaults to a per-user path under -root")
	flag.StringVar(&o.root, "root", "",
		"the state directory: socket, shadow file and root/bin. Defaults to ./root")
	flag.StringVar(&o.binDir, "bin", "",
		"where components are discovered; defaults to <root>/bin")
	flag.BoolVar(&o.textMode, "text", false,
		"render the kernel console as aligned text instead of JSON")
	flag.StringVar(&o.logLevel, "log-level", "debug",
		"minimum console severity: debug, info, warn, error")
	flag.BoolVar(&o.dumpState, "dump", false,
		"print a kernel state dump before shutting down (-once)")
	flag.StringVar(&o.auditPath, "audit", "",
		"append the sealed audit chain to this JSON Lines file (created with 0600)")
	flag.StringVar(&o.crashPath, "crash", "",
		"append the console tail and flush outcome to this file at every exit")
	flag.Parse()
	return o
}

// root defaults to ./root, the directory the owner named. It is created on demand
// rather than at flag-parse time, so `-once` in a scratch directory does not leave
// a tree behind.
func (o *options) rootDir() string {
	if o.root != "" {
		return o.root
	}
	return filepath.Join(".", "root")
}

func (o *options) socketPath() string {
	if o.socket != "" {
		return o.socket
	}
	return console.SocketPath(o.rootDir())
}

func main() {
	o := parseFlags()

	var err error
	switch {
	case o.once:
		err = runOnce(o)
	case o.daemon:
		err = runDaemon(o)
	default:
		err = runClient(o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "meowapi:", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// The singleton: attach, or start a daemon and then attach.

// daemonStartTimeout bounds how long a launcher waits for the daemon it started to
// accept connections. A daemon that boots a kernel, loads modules and discovers
// components does all of that before it can be attached to, so this is generous
// rather than tight - but it is not infinite, because a daemon that never comes up
// must produce an error the operator can read rather than a hung terminal.
const daemonStartTimeout = 30 * time.Second

// runClient is the default. It attaches to a running daemon, starting one if
// necessary.
//
// The probe-then-start sequence is not a race that needs a lock, and it is worth
// saying why: if two terminals launch at the same instant, both may see no daemon
// and both may try to start one. Exactly one wins the socket bind - unix-domain
// listen on a bound path fails with EADDRINUSE, which the kernel's socket table
// enforces - and the loser's daemon exits having printed nothing useful, while both
// clients then attach to the winner. The alternative, a lock file, would be a lock
// whose staleness has to be guessed after a crash.
func runClient(o *options) error {
	path := o.socketPath()

	if err := console.Probe(path); err == nil {
		return console.Attach(path)
	}

	fmt.Fprintf(os.Stderr, "no kernel is running; starting one\n")
	if err := startDaemon(o); err != nil {
		return err
	}
	if err := waitForSocket(path, daemonStartTimeout); err != nil {
		return err
	}
	return console.Attach(path)
}

// startDaemon re-executes this binary with -daemon, detached from this terminal.
//
// Setsid is what makes "closing the terminal does not kill the kernel" true rather
// than incidental. Without it the daemon stays in the terminal's process group, so
// a hangup or a Ctrl-C at the shell reaches it; with it, the daemon has its own
// session and its own group, and the only things that reach it are an explicit
// signal and the socket.
//
// stdio goes to a log file under the root directory rather than to /dev/null,
// because a daemon that starts and immediately fails needs somewhere to have said
// so, and the operator's next command is going to be "why is nothing listening".
func startDaemon(o *options) error {
	exe, err := os.Executable()
	if err != nil {
		// Fall back to the interpreter's own idea of the path, which is what
		// `go run` leaves behind; a real installed binary always resolves.
		exe = os.Args[0]
	}

	root := o.rootDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", root, err)
	}
	logPath := filepath.Join(root, "daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening %s: %w", logPath, err)
	}

	args := []string{"-daemon", "-root", root}
	if o.socket != "" {
		args = append(args, "-socket", o.socket)
	}
	if o.binDir != "" {
		args = append(args, "-bin", o.binDir)
	}
	if o.textMode {
		args = append(args, "-text")
	}
	if o.logLevel != "" {
		args = append(args, "-log-level", o.logLevel)
	}
	if o.auditPath != "" {
		args = append(args, "-audit", o.auditPath)
	}
	if o.crashPath != "" {
		args = append(args, "-crash", o.crashPath)
	}

	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir, _ = os.Getwd()

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("starting the daemon: %w", err)
	}
	// Released rather than waited on. Wait would block until the daemon exits,
	// which is the opposite of detached; Release leaves it running and returns.
	// The pid is read BEFORE Release, because Release clears it: afterwards
	// cmd.Process.Pid is -1, which is what the first version of this printed.
	pid := cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("detaching the daemon: %w", err)
	}
	// Closed here rather than deferred, because the child has its own copy of the
	// descriptor after the fork and this one is not needed again.
	_ = logFile.Close()

	fmt.Fprintf(os.Stderr, "daemon pid %d, log %s\n", pid, logPath)
	return nil
}

// waitForSocket polls until the daemon accepts a connection.
//
// Polling rather than watching the filesystem: the path appears when bind happens,
// but a socket file that exists is not yet a socket that accepts, and the daemon
// binds before it boots the kernel. The probe that matters is the connect.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	interval := 50 * time.Millisecond
	for {
		if err := console.Probe(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the daemon did not accept connections on %s within %s; "+
				"check the daemon log under %s", path, timeout, filepath.Dir(path))
		}
		time.Sleep(interval)
		if interval < 500*time.Millisecond {
			interval *= 2
		}
	}
}

// ---------------------------------------------------------------------------
// The daemon: boot the kernel, serve the socket, stop on a signal or on poweroff.

// runDaemon is the -daemon path. It does not return until the kernel has stopped.
func runDaemon(o *options) error {
	opts := console.Options{
		Root:    o.rootDir(),
		Socket:  o.socket,
		BinDir:  o.binDir,
		Boot:    bootConfig(o, os.Stderr),
		Modules: []kernel.Manifest{diag.Manifest()},
	}

	// The daemon's own log goes to stderr, which startDaemon redirected to a file.
	// A daemon attached to a terminal by hand gets it on the terminal instead, which
	// is the right behaviour for the foreground case.
	opts.LogWriter = os.Stderr

	// The audit sink is opened here rather than passed through Options, because its
	// lifetime belongs to the process: it must be closed on the way out, including
	// on the panic path, and Options cannot express that.
	var sink *auditfile.Sink
	if o.auditPath != "" {
		s, err := auditfile.New(auditfile.Options{Path: o.auditPath})
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		sink = s
		opts.Boot.AuditSink = s
	}

	crashFile, err := openCrashFile(o.crashPath)
	if err != nil {
		return err
	}
	if crashFile != nil {
		defer func() { _ = crashFile.Close() }()
		kernel.PanicSetCrashWriter(crashFile)
		defer kernel.PanicSetCrashWriter(nil)
	}
	kernel.PanicRegisterBuiltins()

	d := console.New(opts)

	// A stop has exactly two sources and both arrive here: a signal, and a session
	// that ran `poweroff`. The channel join is what makes them one path, so the
	// kernel is shut down once, by one function, whichever asked.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	// SIGHUP is in that list and its presence is deliberate and worth a sentence,
	// because the usual advice is to ignore it. Ignoring it is right for a daemon
	// whose controlling terminal went away - which is why startDaemon detaches with
	// Setsid, so there is no terminal to go away. What is left is an operator
	// sending SIGHUP by hand, which is the conventional "reload or stop" signal,
	// and treating it as a stop is the honest reading of an explicit request rather
	// than a guess at an accidental one.

	// A poweroff typed into a session calls d.RequestPoweroff, which stops the
	// daemon from its own goroutine, so this one only has to notice signals.
	go func() {
		for sig := range signals {
			// Logged as the reason and stopped with a nil error, and the
			// distinction is not cosmetic: a clean stop on request exits 0, so a
			// supervisor does not record a failure for an operator's decision. A
			// stop that happened because something broke still carries its error
			// out of Start.
			fmt.Fprintf(os.Stderr, "stopping on %s\n", sig)
			d.Stop(nil)
			return
		}
	}()

	err = d.Start()
	if err != nil {
		return err
	}
	if sink != nil {
		if err := verifyTrail(o.auditPath); err != nil {
			return err
		}
	}
	return nil
}

func openCrashFile(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the crash dump: %w", err)
	}
	return f, nil
}

func bootConfig(o *options, w io.Writer) kernel.BootConfig {
	format := kernel.FormatJSON
	if o.textMode {
		format = kernel.FormatText
	}
	return kernel.BootConfig{
		LogFormat: format,
		LogLevel:  kernel.Level(o.logLevel),
		Console:   w,
	}
}

// verifyTrail reads back the audit file and checks every boot segment. A daemon
// that stops having written a broken chain is a daemon that should say so, which
// is why this is on the exit path rather than left to the operator.
func verifyTrail(path string) error {
	entries, err := auditfile.Read(path)
	if err != nil {
		return fmt.Errorf("reading back the audit chain: %w", err)
	}
	segs, badSeg, badEntry := auditfile.VerifyFile(entries)
	if badSeg != -1 {
		return fmt.Errorf("audit chain broken in boot segment %d at entry %d (%d entries, %d segments)",
			badSeg, badEntry, len(entries), segs)
	}
	fmt.Printf("audit chain verified: %s (%d entries across %d boot(s), head %s)\n",
		filepath.Base(path), len(entries), segs, kernel.AuditHead())
	return nil
}

// ---------------------------------------------------------------------------
// The one-shot report: what -once does, and what CI has always exercised.

// crashHandler catches a panic in the main goroutine, flushes what can still be
// saved, and exits non-zero.
//
// It catches only the main goroutine. A panic in any other goroutine takes the
// process down and cannot be recovered from anywhere, which is why module work runs
// under kernel.SchedSpawn: that path recovers inside the kernel and cannot reach
// here. What this protects is the gateway's own main-loop code.
//
// os.Exit runs no deferred function, so the audit sink and the crash file are closed
// explicitly rather than left to their defers. A flush whose records sit in a bufio
// writer that is never closed is a flush that saved nothing, and the same is true of
// a crash report written to a buffer nobody syncs.
//
// Shutdown has already run by the time this does, so the flush here finds a torn-down
// kernel and reports that honestly rather than claiming to have saved the boot's
// state. What it still saves is the reason and the stack, which is the part that
// cannot be reconstructed afterwards.
func crashHandler(crashFile *os.File, sink *auditfile.Sink) {
	r := recover()
	if r == nil {
		return
	}
	rec := kernel.PanicFlush(fmt.Sprintf("panic: %v", r))
	report := kernel.CrashReport(rec) + "\n" + rec.Stack + "\n"

	fmt.Fprint(os.Stderr, report)
	if crashFile != nil {
		_, _ = crashFile.WriteString(report)
		_ = crashFile.Sync()
		_ = crashFile.Close()
	}
	if sink != nil {
		_ = sink.Close()
	}
	os.Exit(1)
}

func runOnce(o *options) error {
	cfg := bootConfig(o, nil)

	var sink *auditfile.Sink
	if o.auditPath != "" {
		s, err := auditfile.New(auditfile.Options{Path: o.auditPath})
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		sink = s
		cfg.AuditSink = s
	}

	// Registered before Boot, and the ordering matters: Boot resets kernel state
	// before applying configuration, and resetPanic deliberately keeps notifiers, so
	// a chain registered first is the one that survives. PanicRegisterBuiltins is
	// idempotent, so the one Shutdown performs internally adds no second set.
	kernel.PanicRegisterBuiltins()

	var crashFile *os.File
	if o.crashPath != "" {
		f, err := openCrashFile(o.crashPath)
		if err != nil {
			return err
		}
		crashFile = f
		defer func() { _ = f.Close() }()
		kernel.PanicSetCrashWriter(f)
		defer kernel.PanicSetCrashWriter(nil)
	}

	k, err := kernel.Boot(cfg)
	if err != nil {
		return err
	}
	// Registered in this order so that on a panic the deferred calls run Shutdown
	// first and the crash handler second. That is backwards from what it looks like:
	// Shutdown is the one that must run while the kernel is live, and a recover() in
	// a deferred function only sees a panic that is still unwinding when that
	// function runs, which it is. The crash handler is therefore the outermost defer.
	defer func() { crashHandler(crashFile, sink) }()
	defer func() { _ = k.Shutdown() }()

	// Published before any module loads, so a module reading it in OnLoad sees it.
	if err := k.Publish("kernel.boot.id", fmt.Sprintf("boot-%d", time.Now().Unix())); err != nil {
		return fmt.Errorf("publishing the boot id: %w", err)
	}

	if _, err := k.Load(diag.Manifest()); err != nil {
		return err
	}

	fmt.Println("kernel booted")
	for _, m := range kernel.LoadedModules() {
		fmt.Printf("module %q v%s pid=%d effective=%v\n", m.Name, m.Manifest.Version, m.PID, m.Effective)
	}
	fmt.Println("process table:")
	for _, r := range kernel.ProcTable() {
		fmt.Printf("  pid=%-3d uid=%-5d ppid=%-3d domain=%-16s name=%-14s state=%s\n",
			r.PID, r.UID, r.PPID, r.Domain, r.Name, r.State)
	}
	fmt.Printf("usage: tokens:in=%d tokens:out=%d requests=%d (rejected facts: %d)\n",
		kernel.UsageTotal(kernel.UsageTokensIn),
		kernel.UsageTotal(kernel.UsageTokensOut),
		kernel.UsageTotal(kernel.UsageRequests),
		kernel.UsageRejected())

	if o.dumpState {
		fmt.Println()
		if err := kernel.Dump(os.Stdout); err != nil {
			return err
		}
	}

	if sink != nil {
		if err := sink.Flush(); err != nil {
			return err
		}
		return verifyTrail(o.auditPath)
	}
	return nil
}
