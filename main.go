package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag" // its init() registers the diag module
)

func main() {
	var (
		textMode  = flag.Bool("text", false, "render the kernel console as aligned text instead of JSON")
		logLevel  = flag.String("log-level", "debug", "minimum console severity: debug, info, warn, error")
		dumpState = flag.Bool("dump", false, "print a kernel state dump before shutting down")
	)
	flag.Parse()

	if err := run(*textMode, *logLevel, *dumpState); err != nil {
		fmt.Fprintln(os.Stderr, "meowapi:", err)
		os.Exit(1)
	}
}

func run(textMode bool, logLevel string, dumpState bool) error {
	format := kernel.FormatJSON
	if textMode {
		format = kernel.FormatText
	}

	k, err := kernel.Boot(kernel.BootConfig{
		LogFormat: format,
		LogLevel:  kernel.Level(logLevel),
	})
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
	return nil
}
