package kernel

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
)

// BootConfig describes one boot.
type BootConfig struct {
	// Modules are loaded in order during init. A failure aborts the boot and
	// everything already loaded is unloaded, newest first.
	Modules []Manifest
	// Console redirects the kernel console sink. Nil keeps stderr.
	Console io.Writer
	// LogFormat selects JSON or text rendering. Empty keeps JSON, which is the
	// right default for anything machine-read; use FormatText for a terminal.
	LogFormat Format
	// LogLevel sets the minimum severity reaching the sink. Empty keeps debug,
	// meaning nothing is filtered. Faults are retained in history regardless.
	LogLevel Level
	// AuditSink receives every sealed audit entry as it is written. It is the
	// operator's copy of the chain, and it is the only way to reconstruct the
	// trail after the in-memory window evicts an entry or the process dies.
	// Installing a sink is a bootloader privilege: a module cannot redirect the
	// audit trail to a sink it controls.
	AuditSink AuditSink
	// AuditWindow is how many audit entries stay queryable in memory. Zero keeps
	// the default. Values below the floor are raised to it, because a window of
	// zero is not a smaller buffer but no audit trail.
	AuditWindow int
	// TrustRoot is the sealed boot configuration: node identity, cluster root
	// keys, this node's signing key, and the resource ceilings every subsystem
	// enforces. It is loaded and sealed before init is spawned, so nothing that
	// runs later can have observed it unsealed, and no caller can change it
	// afterwards. The zero value yields the default ceilings and a node id of
	// "local", which is enough for a single-node deployment and for tests.
	TrustRoot BootTrustRoot
}

// Kernel is the handle returned by a successful boot. It is the only reference
// to kernel state that leaves package kernel, and it carries no context: every
// operation on it is performed by the kernel on the caller's behalf, so there
// is nothing here a caller can misuse to gain privilege.
type Kernel struct {
	initCtx   *sContext
	modules   []PID
	shutdown  bool
	shutdownM sync.Mutex
}

// Boot starts the kernel. The sequence is fixed and mirrors the prototype:
//
//  1. Assert the boot has not already happened. A second call is a fault, not
//     a silent no-op: sync.Once would swallow it and leave the caller
//     believing the kernel came up.
//  2. Reset accounting, so a kernel started after Shutdown behaves identically
//     to a first boot rather than inheriting a stale process table.
//  3. Construct the context manager state and hand off the root context
//     exactly once.
//  4. Spawn init in u:r:init:s0 and retire the root context immediately. This
//     is the privilege drop: no long-lived code holds u:r:kernel:s0, so a
//     compromised module cannot inherit kernel-domain authority through init.
//  5. Load the configured modules from the init context.
//
// Any panic on this path is reported through the kernel console before it
// propagates. A boot panic is never swallowed.
func Boot(cfg BootConfig) (k *Kernel, err error) {
	if !booted.CompareAndSwap(false, true) {
		fault(nil, "Panic: Re-entrant or duplicate boot attempt detected!", nil)
		return nil, errors.New("kernel: already booted")
	}

	// Everything below either returns a live kernel or resets the guard so a
	// corrected boot can be attempted.
	defer func() {
		if r := recover(); r != nil {
			fault(nil, "Panic: kernel boot faulted", map[string]any{"recover": fmt.Sprint(r)})
			kaudit.record(AuditPanic, nil, "kernel boot faulted", map[string]any{"recover": fmt.Sprint(r)})
			resetKernel()
			booted.Store(false)
			panic(r)
		}
		if err != nil {
			resetKernel()
			booted.Store(false)
		}
	}()

	// Reset first, then apply configuration. The order matters: configuration
	// comes from this BootConfig, so a leftover sink or window from a previous
	// boot would be operator state the caller did not ask for. Resetting first
	// makes every boot start from the same defaults regardless of history.
	resetKernel()

	if cfg.Console != nil {
		kconsole.SetOutput(cfg.Console)
	}
	if cfg.LogFormat != "" {
		kconsole.SetFormat(cfg.LogFormat)
	}
	if cfg.LogLevel != "" {
		kconsole.SetLevel(cfg.LogLevel)
	}
	if cfg.AuditWindow > 0 {
		kaudit.setWindow(cfg.AuditWindow)
	}
	kaudit.setSink(cfg.AuditSink)

	// The trust root is sealed here, before any context exists, so no code that
	// runs later can have read it unsealed and no code at all can write it.
	trustRoot := cfg.TrustRoot
	if trustRoot.NodeID == "" {
		trustRoot.NodeID = "local"
	}
	if err := loadBootConfig(trustRoot); err != nil {
		return nil, fmt.Errorf("kernel: invalid boot trust root: %w", err)
	}

	root, err := kscm.handoffRootContext()
	if err != nil {
		return nil, err
	}

	// The boot record is the first link in the audit chain, so it is written
	// before init is spawned. A chain that opened with the spawn would leave the
	// fact that a boot happened at all unattributed.
	kaudit.record(AuditBoot, root, "kernel booting", map[string]any{
		"kernel_api": KernelAPI, "modules_requested": len(cfg.Modules),
		"trust_root_digest": BootDigest(), "node_id": trustRoot.NodeID,
	})

	spawned, err := root.SyscallSpawn(DomainInit, "init")
	if err != nil {
		return nil, fmt.Errorf("kernel: cannot spawn init: %w", err)
	}
	initCtx := spawned.(*sContext)
	// Retire the root context the instant init exists. Anything still holding
	// it gets errRetired from every syscall.
	root.retire()

	kconsole.Emit(LogInfo, initCtx.pid, initCtx.dom, "init started", map[string]any{
		"kernel_api": KernelAPI,
	})

	k = &Kernel{initCtx: initCtx}

	for _, m := range cfg.Modules {
		pid, err := LoadModule(initCtx, m)
		if err != nil {
			// Unwind newest-first, then report the original cause. A partial
			// boot is worse than a failed boot.
			k.unloadAll()
			return nil, fmt.Errorf("kernel: boot aborted while loading %q: %w", m.Name, err)
		}
		k.modules = append(k.modules, pid)
	}

	kconsole.Emit(LogInfo, initCtx.pid, initCtx.dom, "boot complete", map[string]any{
		"modules": len(k.modules),
	})
	return k, nil
}

// InitContext is the init sequence's own context. It is exposed so the host
// process (main) can load additional modules after boot, for example from a
// configuration file or an admin command.
//
// It holds module:load and module:unload, which is deliberately more than a
// plugin gets and less than the kernel had. Nothing else should ever need it;
// prefer Kernel.Load and Kernel.Unload.
func (k *Kernel) InitContext() SContext { return k.initCtx }

// Load loads a module into the running kernel.
func (k *Kernel) Load(m Manifest) (PID, error) {
	k.shutdownM.Lock()
	done := k.shutdown
	k.shutdownM.Unlock()
	if done {
		return 0, errors.New("kernel: already shut down")
	}
	pid, err := LoadModule(k.initCtx, m)
	if err != nil {
		return 0, err
	}
	k.shutdownM.Lock()
	k.modules = append(k.modules, pid)
	k.shutdownM.Unlock()
	return pid, nil
}

// Unload removes a module from the running kernel.
func (k *Kernel) Unload(pid PID) error {
	k.shutdownM.Lock()
	defer k.shutdownM.Unlock()
	if k.shutdown {
		return errors.New("kernel: already shut down")
	}
	if err := UnloadModule(k.initCtx, pid); err != nil {
		return err
	}
	out := k.modules[:0]
	for _, p := range k.modules {
		if p != pid {
			out = append(out, p)
		}
	}
	k.modules = out
	return nil
}

// Publish records a value in the kernel's own metadata namespace (owner pid 0).
// Any context holding metadata:read can see published values; a module's own
// writes stay private to it. This is how the kernel hands configuration and
// boot facts to modules without widening the policy.
func (k *Kernel) Publish(key string, value any) {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return
	}

	kmeta.publish(key, value)
	kconsole.Emit(LogDebug, 0, DomainKernel, "published kernel metadata", map[string]any{"key": key})
	// Publishing changes state every module holding metadata:read can see, so it
	// is audited. The value is deliberately not recorded: configuration can carry
	// a credential, and the audit trail is readable by anything holding
	// audit:read.
	kaudit.record(AuditPolicy, k.initCtx, "published kernel metadata", map[string]any{"key": key})
}

// Shutdown unloads every module newest-first and releases the boot guard.
// After Shutdown the kernel can be booted again, which is what makes the
// security invariants testable.
func (k *Kernel) Shutdown() error {
	k.shutdownM.Lock()
	if k.shutdown {
		k.shutdownM.Unlock()
		return nil
	}
	k.shutdown = true
	k.shutdownM.Unlock()

	err := k.unloadAll()
	kaudit.record(AuditShutdown, k.initCtx, "kernel shutting down", map[string]any{
		"unload_error": errString(err),
	})
	k.initCtx.retire()
	resetKernel()
	booted.Store(false)

	if err != nil {
		return err
	}
	return nil
}

func (k *Kernel) unloadAll() error {
	k.shutdownM.Lock()
	pids := make([]PID, len(k.modules))
	copy(pids, k.modules)
	k.modules = nil
	k.shutdownM.Unlock()

	sort.Slice(pids, func(i, j int) bool { return pids[i] > pids[j] })

	var firstErr error
	for _, pid := range pids {
		if err := UnloadModule(k.initCtx, pid); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
