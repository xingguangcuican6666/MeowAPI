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
	// The flush chain goes first, because a flush triggered during the rest of this
	// teardown must not find the subsystems it reads already gone. It clears the
	// previous boot's crash record and releases the guard; the notifiers themselves
	// survive, for the reason resetPanic gives.
	resetPanic()

	// Accounting and admission.
	resetUsage()
	resetSlots()
	resetQos()
	resetCPU()

	// Module state and shared memory.
	//
	// resetKVFS looks redundant next to KVDropNamespace in UnloadModule, and a test
	// that loads a module, shuts down and asserts an empty namespace passes without
	// it - the unload already dropped that namespace. What only this clears is INIT's:
	// init is never appended to the handle's module list, so unloadAll never walks it,
	// and pids restart at 1 with each boot. Without the reset, a key init wrote in one
	// boot is readable by the next boot's init, with nothing on that boot's chain to
	// say so. tests/security's TestResetClearsWhatUnloadNeverTouches pins that half.
	resetKVFS()
	// resetFSScopes is the one entry in this list that no test in tests/ can pin, and
	// the reason is structural rather than an oversight: LoadModule calls SetFSScope
	// unconditionally, so any pid that reaches an fs check has its scope overwritten
	// from its own manifest first, and a scope surviving from a previous boot is
	// unreachable through every exported observation. Measured under its removal: a
	// boot-2 module was still refused the path the host had widened into boot 1's
	// same-numbered pid.
	//
	// It is not a residency guard either, on the normal path, and saying otherwise
	// would be the second false claim here. With every module loaded through the
	// handle, Shutdown's unloadAll drops each scope via ClearFSScope, so the map
	// measures zero after shutdown with or without this reset - measured at three
	// modules then one, giving 0 and 0 in both cases. What it does clear is scopes
	// belonging to pids Shutdown never unloads: a module loaded by the free LoadModule
	// function rather than the handle, or one whose unload failed. Those entries are
	// held for a pid that will not be reused, and nothing but this reset frees them.
	//
	// So: a leak guard for an edge of the unload path, and a containment guard if any
	// future path grants fs access without going through the loader. Do not delete it
	// on the grounds that nothing tests it.
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
	// resetNet before resetFDs: the pool holds fds, and closing them goes through the fd
	// table, so that table must still be intact when the pool is drained.
	resetNet()
	resetPeers()
	resetMeter()
	// Token accounting goes with metering: the measurement exists to corroborate the
	// report, so a ledger surviving a restart would compare this boot's reports against
	// last boot's numbers. The strictness setting is deployment configuration and
	// survives, for the reason resetTokenizer gives.
	resetTokenizer()
	// Instance filters die with their pids, and pids restart at 1 on a fresh boot, so a
	// stale filter would land on init.
	resetSeccomp()

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
	// resetOom after resetModules: a late sweep that started a termination would otherwise
	// have no module table left to tear down against.
	resetOom()
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
