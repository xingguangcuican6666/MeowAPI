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
	// ctx is the sealed context this module was spawned with. The kernel keeps it
	// so a dispatch through kservice can run the handler under the handler's own
	// authority instead of the caller's. It is never handed to a module: the only
	// context a module ever sees is the one passed to its own OnLoad.
	ctx *sContext
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
	count := len(modules)
	modulesMu.Unlock()
	if live {
		return 0, fmt.Errorf("kernel: module %q already loaded at pid %d", m.Name, pid)
	}
	// The ceiling comes from the sealed trust root rather than from a constant or
	// a module declaration, because a quota the loaded code could raise is not a
	// quota.
	if max := Limits().MaxModules; count >= max {
		err := fmt.Errorf("kernel: module limit reached (%d live modules)", max)
		fault(c, "module load refused by quota", map[string]any{"module": m.Name, "max_modules": max})
		kaudit.record(AuditReject, c, "module limit reached", map[string]any{
			"module": m.Name, "max_modules": max, "live": count,
		})
		return 0, err
	}

	child, err := kscm.spawn(c, DomainPlugin, m.Name)
	if err != nil {
		return 0, err
	}

	effective := effectiveOps(m)
	digest := m.Digest()

	// Grants go in before any module code runs.
	setGrants(child.pid, effective)

	// So do the scopes the grants are meaningless without. A scoped operation is
	// granted by its manifest boundary rather than by the domain ceiling, so a
	// module holding fs:read with no installed path boundary has a capability the
	// kernel has no boundary to enforce against, and a module holding secret:use
	// with no installed prefix sees no alias at all.
	//
	// Both subsystems document this exact hook and neither could call it themselves:
	// only the loader has a validated manifest in hand, and only the loader
	// allocates the pid. Installing here rather than later matters because OnLoad
	// runs below - a module that needs a credential or a file during
	// initialization would otherwise fail closed, and the failure would look
	// exactly like a misconfigured prefix rather than like an unwired hook.
	//
	// The scopes are per pid and pids are never reused, so nothing is needed in the
	// abandon closure: a rejected load leaves scopes that no later module can reach,
	// and resetKernel clears both registries wholesale.
	SetFSScope(child.pid, m.ReadPaths, m.WritePaths)
	setSecretScope(child.pid, m.SecretPrefixes)

	// abandon is the single unwind path. Every failure below returns through it,
	// so the cleanup cannot drift between branches.
	abandon := func(reason string, err error) error {
		clearGrants(child.pid)
		// A module that fails during OnLoad may already have opened handles. The
		// table is walked here exactly as it is on unload, so a failed load leaks
		// nothing either.
		reclaimFDs(child.pid)
		kscm.setArtifact(child.pid, m.Name, digest, ProcRejected)
		fault(child, reason, map[string]any{"module": m.Name, "error": err.Error()})
		kaudit.record(AuditReject, child, reason, map[string]any{
			"module": m.Name, "error": err.Error(),
		})
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
		runUnload(inst, child.pid)
		return 0, abandon("module OnLoad failed",
			fmt.Errorf("kernel: OnLoad for %q failed: %w", m.Name, err))
	}

	kscm.setArtifact(child.pid, m.Name, digest, ProcRunning)

	modulesMu.Lock()
	modules[child.pid] = &LoadedModule{
		PID: child.pid, Name: m.Name, Manifest: m,
		Effective: effective, module: inst, ctx: child,
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

	err := runUnload(rec.module, pid)
	clearGrants(pid)

	// Locks this pid held cannot stay held, but how they are given up depends on why
	// the module is going away.
	//
	// A clean unload means OnUnload ran, so whatever the module was serializing
	// finished: release the lock and let the next waiter in.
	//
	// A forced termination - a kill signal, the drain default action, a watchdog
	// detection - means the critical section was abandoned half-done. Handing the
	// lock to the next waiter there would tell it the work it was waiting for
	// completed, which is a lie, and the waiter would then act on a half-updated
	// resource. So the lock is condemned instead and waiters receive
	// ErrLockOwnerGone, which is a different error precisely because it calls for a
	// different response.
	//
	// This runs before handle reclamation, not after: a lock handle's Close releases
	// its lock, so by the time the table was walked the registry entry would be gone
	// and condemnation would have nothing left to condemn. markDead latches first and
	// release() is a no-op on a dead lock, so the two paths compose.
	//
	// The flag read here is `terminating`, not `terminated`. ksignal stores
	// `terminated` after UnloadModule returns, so reading it from inside the unload
	// path would always see false and every forced teardown would quietly take the
	// clean-release branch, which is the branch that lies to the waiter.
	if _, condemned := SignalState(pid); condemned {
		klocks.markDead(pid)
	} else {
		klocks.releaseAll(pid)
	}

	// Reclaim every handle the module opened. This is the property that makes a
	// crashed or hung module leak nothing: no resource's only reference lives
	// inside module code, so walking the table closes all of them.
	closed, reclaimErrs := reclaimFDs(pid)
	// Drop the namespaces this pid owned. Handles are reclaimed above, but kvfs,
	// the fs scope and kshm keep registries keyed by pid that no handle owns, and a
	// pid is never reused: leaving them would make every load-and-unload cycle leak
	// state that nothing can ever reach again.
	KVDropNamespace(pid)
	ClearFSScope(pid)
	ShmDropNamespace(pid)
	// Subscriptions are dropped, so a dead module stops accumulating a backlog.
	kevents.dropAll(pid)
	// Live spans are ended and marked abandoned, so a module that dies mid-request
	// still leaves a record of the stage it was in instead of vanishing from the
	// trace with no end time.
	dropSpansFor(pid)
	// Pipes this module registered are dropped from the registry. The fd table
	// closed the resources above; this clears the index so a snapshot does not keep
	// reporting a pipe whose owner has been gone since the last restart.
	DropPipesFor(pid)
	// Console handles held by this pid are dropped for the same reason. No module can
	// hold one today, because tty:open is refused to the plugin domain and init never
	// reaches UnloadModule, so this is a backstop rather than a live path: if the
	// console is ever opened to another domain, reclamation is already correct
	// instead of silently leaking a registry entry for a session that is gone.
	dropTTYsFor(pid)
	// Routes this module served are unregistered, so a call cannot resolve to a
	// handler whose module is gone.
	unregisterRoutesFor(pid)
	// Open meter requests are closed and marked abandoned, so a module that dies
	// mid-request does not leave an entry open forever quietly eating the ledger's
	// ceiling.
	closeRequestsFor(pid)
	// Tell anyone waiting on this pid that it is gone. Posted before the process
	// record closes so a peer learns from the event rather than from a failed call.
	// The detail is the module's own name, read from the process table while the
	// record is still open.
	PostEvent(EventPeerDisconnected, pid, nameForPID(pid))
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
// runLoad calls OnLoad with panic containment and CPU accounting.
//
// The recover is here rather than in a shared wrapper so the panic wording stays
// "OnLoad panicked", which is what an operator greps for and what the tests assert.
// The deferred charge runs on the panic path too, so a module that panics still pays
// for the time it burned.
func runLoad(m Module, ctx *sContext) (err error) {
	if budgetExhausted(ctx.pid) {
		return fmt.Errorf("%w: pid %d refused OnLoad", ErrCPUBudget, ctx.pid)
	}
	start := mono()
	defer accountSupervised(ctx.pid, "OnLoad", start)
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("OnLoad panicked: %v", r)
		}
	}()
	return m.OnLoad(ctx)
}

// runUnload calls OnUnload with a hard deadline and with panics recovered. The
// kernel does not block on module code and does not let module code abort it.
// runUnload calls OnUnload on its own goroutine, bounded by unloadTimeout and with
// panic containment. The goroutine is the kernel's, so ksched and kwatchdog can
// account for it, and the timeout is what makes unloading a hung module survivable
// rather than a decision to abandon the process.
//
// A refusal for budget is deliberately absent here. Unload is teardown: refusing to
// run it would leave the module's handles, locks, routes and subscriptions behind,
// which is worse than letting an over-budget module clean up after itself.
func runUnload(m Module, pid PID) error {
	start := mono()
	defer accountSupervised(pid, "OnUnload", start)

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

// nameForPID reads a pid's label from the process table. It returns an empty string
// for a pid with no record, which is correct for an event about a module that never
// got far enough to be named.
func nameForPID(pid PID) string {
	for _, r := range ProcTable() {
		if r.PID == pid {
			return r.Name
		}
	}
	return ""
}

// moduleContextOf returns the sealed context a live module was spawned with, or nil
// when no such module is loaded. kservice uses it to run a route handler under the
// handler's own authority rather than the caller's, which is the line that makes the
// route table a security boundary instead of a convenience.
//
// It is package-private on purpose: nothing outside the kernel may obtain another
// module's context, and a module never receives one but its own.
func moduleContextOf(pid PID) *sContext {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	rec, ok := modules[pid]
	if !ok {
		return nil
	}
	// A retired or missing context means the module is being torn down, so a
	// dispatch to it must fail rather than run against a context whose syscalls
	// are all refused.
	if rec.ctx == nil || rec.ctx.retired.Load() {
		return nil
	}
	return rec.ctx
}

// manifestOf returns the manifest a live module was loaded under, or false when the
// module is gone. Route declarations are read through here so a handler's authority
// comes from what was reviewed at load time and not from anything mutable later.
func manifestOf(pid PID) (Manifest, bool) {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	rec, ok := modules[pid]
	if !ok {
		return Manifest{}, false
	}
	return rec.Manifest, true
}
