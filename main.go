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
	)
	flag.Parse()

	if err := run(*textMode, *logLevel, *dumpState, *auditPath); err != nil {
		fmt.Fprintln(os.Stderr, "meowapi:", err)
		os.Exit(1)
	}
}

func run(textMode bool, logLevel string, dumpState bool, auditPath string) error {
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

	k, err := kernel.Boot(cfg)
	if err != nil {
		return err
	}
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
