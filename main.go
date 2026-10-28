package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xingguangcuican6666/MeowAPI/internal/auditfile"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag" // its init() registers the diag module
)

func main() {
	var (
		textMode  = flag.Bool("text", false, "render the kernel console as aligned text instead of JSON")
		logLevel  = flag.String("log-level", "debug", "minimum console severity: debug, info, warn, error")
		dumpState = flag.Bool("dump", false, "print a kernel state dump before shutting down")
		auditPath = flag.String("audit", "", "append the sealed audit chain to this JSON Lines file (created with 0600)")
		crashPath = flag.String("crash", "", "append the console tail and flush outcome to this file at every exit, clean or not")
	)
	flag.Parse()

	if err := run(*textMode, *logLevel, *dumpState, *auditPath, *crashPath); err != nil {
		fmt.Fprintln(os.Stderr, "meowapi:", err)
		os.Exit(1)
	}
}

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

func run(textMode bool, logLevel string, dumpState bool, auditPath, crashPath string) error {
	format := kernel.FormatJSON
	if textMode {
		format = kernel.FormatText
	}

	cfg := kernel.BootConfig{
		LogFormat: format,
		LogLevel:  kernel.Level(logLevel),
	}

	// The audit chain spills to disk when a path is given. This is the operator
	// copy: it survives the bounded in-memory window and the process itself, and
	// it can be re-verified later without the kernel.
	var sink *auditfile.Sink
	if auditPath != "" {
		s, err := auditfile.New(auditfile.Options{Path: auditPath})
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		sink = s
		cfg.AuditSink = s
	}

	// The crash flush chain is registered before Boot, and the ordering is worth a
	// sentence because it is the kind of thing that looks arbitrary. Boot resets kernel
	// state before applying configuration, so a chain registered before Boot is the one
	// that survives a reset that keeps notifiers - which resetPanic does, deliberately,
	// so that a host setting up its crash handling before booting is not silently
	// unarmed by the boot it was setting up for. PanicRegisterBuiltins is idempotent, so
	// the one Shutdown performs internally does not add a second set.
	kernel.PanicRegisterBuiltins()

	// The crash file is opened here and held open for the process lifetime. Opening it
	// at crash time instead would mean asking a dying process to perform a filesystem
	// operation, which is exactly when it is most likely to fail.
	//
	// It is appended rather than truncated, and it is written on a clean exit as well as
	// a crash, because Shutdown flushes too. A clean run leaves the console tail there,
	// which is the record of what the gateway did before it stopped; a crash leaves that
	// plus the reason and the stack. Overwriting would destroy the previous run's tail,
	// which is the one an investigation following a restart needs.
	var crashFile *os.File
	if crashPath != "" {
		f, err := os.OpenFile(crashPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("opening the crash dump: %w", err)
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
	// Shutdown is the one that must run while the kernel is live, and a recover() in a
	// deferred function only sees a panic that is still unwinding when that function
	// runs, which it is. The crash handler is therefore the outermost defer.
	defer func() { crashHandler(crashFile, sink) }()
	defer func() { _ = k.Shutdown() }()

	// Publish a boot fact before loading anything. Any module holding
	// metadata:read sees it in OnLoad, and no module can overwrite it, because
	// metadata:write is not grantable to the plugin domain. Ordering matters:
	// a module loaded during Boot would read this key before it existed.
	k.Publish("kernel.boot.id", fmt.Sprintf("boot-%d", time.Now().Unix()))

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

	if dumpState {
		fmt.Println()
		if err := kernel.Dump(os.Stdout); err != nil {
			return err
		}
	}

	// Verify the audit trail we just wrote, if we wrote one. Doing it here makes
	// the integrity of the trail a property the operator sees on every run rather
	// than something to remember to check later.
	if sink != nil {
		if err := sink.Flush(); err != nil {
			return err
		}
		entries, err := auditfile.Read(auditPath)
		if err != nil {
			return fmt.Errorf("reading back the audit chain: %w", err)
		}
		// The file accumulates across restarts, so it holds one chain per boot
		// rather than a single chain. VerifyFile checks each segment from its own
		// genesis, which keeps tampering detectable without treating a restart as
		// a broken link.
		segs, badSeg, badEntry := auditfile.VerifyFile(entries)
		if badSeg != -1 {
			return fmt.Errorf("audit chain broken in boot segment %d at entry %d (%d entries, %d segments)",
				badSeg, badEntry, len(entries), segs)
		}
		fmt.Printf("audit chain verified: %s (%d entries across %d boot(s), head %s)\n",
			filepath.Base(auditPath), len(entries), segs, kernel.AuditHead())
	}
	return nil
}
