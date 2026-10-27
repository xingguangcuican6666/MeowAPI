package kernel

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Module is the lifecycle contract a plugin implements. It is the whole of the
// ABI alongside SContext and Manifest: two methods, no fields, no optional
// interfaces, and no way to reach kernel state except through the context.
//
// OnLoad receives the context the kernel spawned for this module. The module must
// not retain it after OnUnload returns, must not pass it to another module, and
// must not stash it in package-level state. OnUnload is called under a hard
// timeout and with panics recovered, so neither a hung nor a broken module can
// take the kernel down.
type Module interface {
	OnLoad(ctx SContext) error
	OnUnload() error
}

// Factory builds a Module. The kernel calls it once per load, never at
// registration time.
type Factory func() (Module, error)

// unloadTimeout bounds OnUnload. A module that hangs during unload is abandoned
// rather than waited on forever.
const unloadTimeout = 10 * time.Second

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register publishes a module factory under a name. Modules call it from a
// package-level init function, so importing a module package makes it loadable:
//
//	import _ "github.com/xingguangcuican6666/MeowAPI/plugins/diag"
//
// Registration is not loading. A registered module runs no code beyond its
// factory until the kernel loads it, and only ever under a context the kernel
// allocated.
//
// A duplicate name panics rather than overwriting. Two factories under one name
// is a supply-chain defect - whichever loads second silently replaces the first -
// and it must fail at init, loudly, not resolve to whichever package happened to
// be linked last.
func Register(name string, f Factory) {
	if name == "" {
		panic("kernel: Register with empty module name")
	}
	if f == nil {
		panic("kernel: Register with nil factory for " + name)
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic("kernel: duplicate module registration for " + name)
	}
	registry[name] = f
}

// Unregister removes a module factory. It exists for tests that register a probe
// module; production code registers once from init and never unregisters. A
// loaded module is unaffected, because the registry maps names to factories, not
// to live instances.
func Unregister(name string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, name)
}

// Registered returns the sorted names of registered modules.
func Registered() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// LoadedModule is a live module record. The Module instance is unexported: a
// caller of LoadedModules gets the facts about a module and no handle to it, so
// there is no way to call OnUnload directly and bypass the policy check.
type LoadedModule struct {
	PID      PID
	Name     string
	Manifest Manifest
	// Effective is what the module was actually granted after validation: the
	// manifest request narrowed to the domain ceiling.
	Effective []Op
	module    Module
}

var (
	modulesMu sync.Mutex
	modules   = map[PID]*LoadedModule{}
	byName    = map[string]PID{}
)

// LoadModule validates a manifest, spawns a context for the module, builds it and
// calls OnLoad. Any failure unwinds everything allocated, and the process table
// keeps a rejected record naming the module and the reason.
//
// The order of these steps is the control. Validation happens before the registry
// lookup and before any context exists, so a module whose declaration is
// unacceptable never gets a pid. Grants are installed before OnLoad, so a module
// cannot act on the domain ceiling during its own initialization. A half-loaded
// module is worse than no module, so every failure path goes through the same
// abandon function rather than three copies of the cleanup.
//
// The caller context must hold module:load. In practice that is init.
func LoadModule(ctx SContext, m Manifest) (PID, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return 0, errors.New("kernel: LoadModule requires a kernel-issued context")
	}
	if err := check(c, OpModuleLoad); err != nil {
		return 0, err
	}

	if err := m.Validate(); err != nil {
		// Record the rejection under the untrusted domain, so the process table
		// shows that something was refused rather than merely that nothing
		// happened. An invisible refusal is an uninvestigable one.
		var rejectedPID PID
		if rejected, spawnErr := kscm.spawn(c, DomainUntrusted, m.Name); spawnErr == nil {
			kscm.setArtifact(rejected.pid, m.Name, m.Digest(), ProcRejected)
			rejectedPID = rejected.pid
		}
		fault(c, "module rejected before load", map[string]any{"module": m.Name, "reason": err.Error()})
		kaudit.record(AuditReject, c, "module manifest rejected", map[string]any{
			"module": m.Name, "version": m.Version, "digest": m.Digest(),
			"reason": err.Error(), "rejected_pid": rejectedPID,
		})
		return 0, err
	}

	registryMu.RLock()
	factory, found := registry[m.Name]
	registryMu.RUnlock()
	if !found {
		return 0, fmt.Errorf("kernel: no module registered under %q", m.Name)
	}

	modulesMu.Lock()
	pid, live := byName[m.Name]
	modulesMu.Unlock()
	if live {
		return 0, fmt.Errorf("kernel: module %q already loaded at pid %d", m.Name, pid)
	}

	child, err := kscm.spawn(c, DomainPlugin, m.Name)
	if err != nil {
		return 0, err
	}

	effective := effectiveOps(m)
	digest := m.Digest()

	// Grants go in before any module code runs.
	setGrants(child.pid, effective)

	// abandon is the single unwind path. Every failure below returns through it,
	// so the cleanup cannot drift between branches.
	abandon := func(reason string, err error) error {
		clearGrants(child.pid)
		kscm.setArtifact(child.pid, m.Name, digest, ProcRejected)
		fault(child, reason, map[string]any{"module": m.Name, "error": err.Error()})
		return err
	}

	inst, err := factory()
	if err != nil {
		return 0, abandon("module factory failed",
			fmt.Errorf("kernel: factory for %q failed: %w", m.Name, err))
	}
	if inst == nil {
		return 0, abandon("module factory returned nil",
			fmt.Errorf("kernel: factory for %q returned a nil module", m.Name))
	}

	if err := runLoad(inst, child); err != nil {
		// Give the module a chance to release what it took, then abandon. The
		// unload error is deliberately ignored: the load failure is the one that
		// matters, and runUnload already recovered any panic.
		runUnload(inst)
		return 0, abandon("module OnLoad failed",
			fmt.Errorf("kernel: OnLoad for %q failed: %w", m.Name, err))
	}

	kscm.setArtifact(child.pid, m.Name, digest, ProcRunning)

	modulesMu.Lock()
	modules[child.pid] = &LoadedModule{
		PID: child.pid, Name: m.Name, Manifest: m,
		Effective: effective, module: inst,
	}
	byName[m.Name] = child.pid
	modulesMu.Unlock()

	kconsole.Emit(LogInfo, child.pid, child.dom, "module loaded", map[string]any{
		"module": m.Name, "version": m.Version, "digest": digest, "ops": len(effective),
	})
	kaudit.record(AuditLoad, child, "module loaded", map[string]any{
		"module": m.Name, "version": m.Version, "digest": digest,
		"effective": opStrings(effective), "ppid": c.pid,
	})
	return child.pid, nil
}

// effectiveOps is the manifest request narrowed to what the domain can hold.
// Scoped operations survive as-is; their scope is enforced per call, not here.
func effectiveOps(m Manifest) []Op {
	out := make([]Op, 0, len(m.Require))
	for _, op := range m.Require {
		if scopedOps[op] || Allowed(DomainPlugin, op) {
			out = append(out, op)
		}
	}
	sortOps(out)
	return out
}

// UnloadModule calls OnUnload under a timeout and closes the record. Unloading an
// unknown pid is a no-op, matching the prototype, because a boot path that unwinds
// a partial failure must not itself fail.
//
// The record is terminated rather than deleted, and it keeps a rejected state if
// it already had one, so the audit trail never loses the difference between a
// module that ran and one the kernel refused.
func UnloadModule(ctx SContext, pid PID) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errors.New("kernel: UnloadModule requires a kernel-issued context")
	}
	if err := check(c, OpModuleUnload); err != nil {
		return err
	}

	modulesMu.Lock()
	rec := modules[pid]
	delete(modules, pid)
	if rec != nil {
		delete(byName, rec.Name)
	}
	modulesMu.Unlock()

	if rec == nil {
		return nil
	}

	err := runUnload(rec.module)
	clearGrants(pid)
	// Reclaim every handle the module opened. This is the property that makes a
	// crashed or hung module leak nothing: no resource's only reference lives
	// inside module code, so walking the table closes all of them.
	closed, reclaimErrs := reclaimFDs(pid)
	kscm.terminate(pid)
	kaudit.record(AuditUnload, c, "module unloaded", map[string]any{
		"module": rec.Name, "pid": pid, "fds_reclaimed": closed,
		"error": errString(err),
	})
	if err != nil {
		fault(c, "module OnUnload failed", map[string]any{"module": rec.Name, "error": err.Error()})
		return err
	}
	for _, re := range reclaimErrs {
		fault(c, "fd reclaim failed during unload", map[string]any{"module": rec.Name, "error": re.Error()})
	}
	kconsole.Emit(LogInfo, pid, DomainPlugin, "module unloaded", map[string]any{
		"module": rec.Name, "fds_reclaimed": closed,
	})
	return nil
}

// runLoad calls OnLoad with panics recovered.
//
// OnLoad runs synchronously and without a deadline, unlike OnUnload: a module may
// legitimately need to dial a provider, read configuration or warm a cache during
// setup, and an arbitrary timeout would only teach module authors to move that
// work into a goroutine the kernel cannot see. What the kernel does guarantee is
// that a panic here cannot abort the host process. Crash containment is a
// property of the kernel, so it applies to both lifecycle methods; recovering one
// and not the other would leave the load path - the one running untrusted code for
// the first time - as the crash vector.
func runLoad(m Module, ctx *sContext) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("OnLoad panicked: %v", r)
		}
	}()
	return m.OnLoad(ctx)
}

// runUnload calls OnUnload with a hard deadline and with panics recovered. The
// kernel does not block on module code and does not let module code abort it.
func runUnload(m Module) error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("OnUnload panicked: %v", r)
			}
		}()
		done <- m.OnUnload()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(unloadTimeout):
		return fmt.Errorf("OnUnload exceeded %s", unloadTimeout)
	}
}

// LoadedModules returns a snapshot of live module records, sorted by pid.
func LoadedModules() []LoadedModule {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	out := make([]LoadedModule, 0, len(modules))
	for _, rec := range modules {
		cp := *rec
		cp.module = nil
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// resetModules clears the module table. Called only from resetKernel. It does not
// clear grants: resetKernel owns the ordering of subsystem resets, so each
// subsystem resets exactly itself.
func resetModules() {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	modules = map[PID]*LoadedModule{}
	byName = map[string]PID{}
}

func opStrings(ops []Op) []string {
	out := make([]string, 0, len(ops))
	for _, o := range ops {
		out = append(out, string(o))
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
