// Package kernel is the MeowAPI microkernel. It boots, assigns security
// contexts, enforces a mandatory access control policy, loads and unloads
// modules, counts base usage, and writes to the kernel console. Everything else
// in MeowAPI is a module.
//
// The ABI a module author programs against is three things:
//
//   - Module: the lifecycle contract, OnLoad and OnUnload.
//   - SContext: the sealed handle a module receives in OnLoad, and the only way
//     to reach a syscall. It cannot be forged or borrowed.
//   - Manifest: the declaration of what a module needs, validated before any
//     module code runs and enforced at every call.
//
// The kernel provides no business behavior. It does not route, does not talk to
// a provider, does not price anything and does not hold a secret. It defines the
// operations, bounds what each module may ask for, counts what modules report,
// and records what happened.
//
// # File map
//
//	kernel.go      this document, the ABI version, and the one reset path
//	context.go     PID/UID/Domain, the sealed SContext, syscall entry points
//	policy.go      operations, domain rules, grant narrowing, check(), denials
//	proc.go        pid/uid allocation and the append-only process table
//	metadata.go    the per-owner kernel key-value store
//	boot.go        the boot guard, Boot, Kernel, Shutdown, the sealed boot config
//	module.go      the Module contract, the registry, load and unload
//	manifest.go    Manifest, validation, host/path/operation scope rules
//	clock.go       kclock: the monotonic time authority every deadline reads
//	audit.go       kaudit: the hash-chained record of what the kernel did
//	fdtable.go     kfdtable: per-pid integer handles for every kernel resource
//	bootconfig.go  kboot: the sealed trust root and the resource ceilings
//	usage.go       the usage ABI: kinds, ceilings, per-pid accounting
//	console.go     the kernel console: records, formats, levels, retention
//	dump.go        a read-only rendering of kernel state for debugging
//
// Subsystems are named after the OS primitive they answer to, and the name is
// part of the vocabulary: kclock, kaudit, kfdtable, kmeter, kqos, krlimit,
// kkeyring, knet, kpipe, kvfs, ksched, ksignal, ktrace, kcrypto, kreceipt,
// kpeer, kslashing. Each one is a separate file with its own lock and its own
// reset, and none of them may reach another except through the kernel's own
// calls. See AGENT.md for the full subsystem list and what each one must
// guarantee.
//
// # Invariants
//
// Every syscall routes through check() in policy.go; there is no path around it.
// Nothing at any domain can spawn into u:r:kernel:s0. The root context is
// retired the instant init exists, so no long-lived code holds the kernel
// domain. Pids and uids are allocated by the kernel and never reused within a
// boot. The process table is append-only and keeps rejected loads distinct from
// terminated ones. A manifest narrows the domain ceiling and can never widen it.
// The kernel package imports nothing outside the standard library, and CI fails
// if that changes.
package kernel

// KernelAPI is the kernel ABI version a module's manifest is checked against.
// Bump it when the ABI changes in a way an existing module could notice, and
// widen the supported range in the same change rather than breaking every
// module at once.
const KernelAPI = 1

// resetKernel clears every kernel subsystem in a fixed order. It is the single
// reset path, called by Boot before it starts accounting and by Shutdown after
// it stops, so a restarted kernel is indistinguishable from a first-booted one.
//
// Each subsystem owns its own reset and knows nothing about the others. This
// function is the only place that knows the full list, which is deliberate: a
// reset scattered across subsystems is how a stale process table survives a
// restart and makes the security invariants untestable.
//
// The order matters and is the reverse of construction: stop accounting usage
// and grants before the process table that names them goes away, and clear the
// console last so the shutdown's own records are still visible until the end.
//
// Callers hold the boot guard, so this cannot race with a live kernel.
// resetKernel returns every subsystem to its pre-boot state.
//
// The ordering is not arbitrary and there are three rules behind it:
//
//  1. Accounting before grants. A subsystem that counted work must be cleared
//     before the grants that authorized it, so a stray late charge cannot land in
//     a table that no longer has a policy behind it.
//  2. Execution before the handle table. ksched, ksignal and kwatchdog hold
//     references to handles and to running work; clearing them first means their
//     cancellation paths see a consistent registry, and clearing the fd table
//     afterwards drops what is left without a subsystem still pointing at it.
//  3. Secrets before the trust root. kkeyring and kreceipt hold material derived
//     from the sealed root, so they are wiped first: a restarted kernel must never
//     coexist with a stale keyring, even for the instant between the two resets.
//
// The console is cleared last so a reset can still report itself.
func resetKernel() {
	// Accounting and admission.
	resetUsage()
	resetSlots()
	resetQos()
	resetCPU()

	// Module state and shared memory.
	resetKVFS()
	resetFSScopes()
	// resetFS clears where the data roots are; resetFSScopes above clears what each
	// pid may touch inside one. Both must be empty before a new boot installs its
	// own, because a root surviving a restart would point a fresh module at a
	// directory the previous boot chose.
	resetFS()
	resetShm()

	// Channels and coordination. Locks before the fd table they hand out handles
	// through, and before signals, because a lock release can wake a waiter that is
	// about to be terminated.
	resetPipes()
	resetLocks()
	resetEvents()
	resetTraces()
	resetRoutes()
	resetPeers()
	resetMeter()

	// Crypto caches hold parsed key material, so they go with the secrets.
	resetCrypto()

	// Execution: the watchdog first, so a patrol in flight stops noticing work
	// that the two below are about to forget.
	resetWatchdog()
	resetSched()
	resetSignals()

	// Grants and the module registry, then the handle table they reference.
	resetGrants()
	resetModules()
	resetFDTables()

	// Identity and evidence.
	kmeta.reset()
	kscm.reset()
	kaudit.reset()
	resetSlashing()

	// Secrets, then the root they derive from. The console credential is
	// host-installed credential material, so it is wiped with the secrets and before
	// the root it was installed under: an operator session's console key must not
	// survive the operator's decision to restart.
	resetTTYs()
	resetKeyring()
	resetReceipts()
	kboot.reset()

	kconsole.reset()
}
