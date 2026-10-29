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

package kernel

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Op is a policy operation, spelled class:permission so denials read like
// SELinux and so a policy table can be reviewed by anyone who knows it.
//
// The class names are the kernel subsystems. Adding an operation means adding a
// capability, which is a trust-root change and needs owner approval.
type Op string

const (
	// Core context and lifecycle.
	OpMetadataRead  Op = "metadata:read"
	OpMetadataWrite Op = "metadata:write"
	OpProcessFork   Op = "process:fork"
	OpModuleLoad    Op = "module:load"
	OpModuleUnload  Op = "module:unload"
	// ipc:bind and ipc:call are reserved and gate nothing. No syscall checks either
	// one; the live module-to-module mechanism is kservice's route:register and
	// route:call. They stay declared because they are granted to two domains and a
	// manifest in the wild may require one, so removing them is a policy surface
	// change rather than a cleanup. Do not add a check against them without first
	// deciding what they mean, because a check nobody reasoned about is a refusal
	// nobody can diagnose.
	OpIPCBind  Op = "ipc:bind"
	OpIPCCall  Op = "ipc:call"
	OpLogWrite Op = "log:write"

	// kaudit: the tamper-evident record. Distinct from log:write, because an
	// audit entry is evidence and a log line is commentary.
	OpAuditAppend Op = "audit:append"
	OpAuditRead   Op = "audit:read"

	// kmeter and ktokenizer: usage accounting and the kernel's own token count.
	OpUsageEmit   Op = "usage:emit"
	OpMeterRecord Op = "meter:record"
	OpMeterRead   Op = "meter:read"
	OpTokenCount  Op = "token:count"

	// kreceipt: signed settlement records.
	OpReceiptIssue  Op = "receipt:issue"
	OpReceiptVerify Op = "receipt:verify"

	// kqos and krlimit: admission and concurrency.
	OpQosAdmit    Op = "qos:admit"
	OpSlotAcquire Op = "slot:acquire"

	// kpipe, kshm, klock, kepoll: resource handles.
	OpPipeOpen  Op = "pipe:open"
	OpPipeWrite Op = "pipe:write"
	OpPipeRead  Op = "pipe:read"
	OpShmAlloc  Op = "shm:alloc"
	OpShmMap    Op = "shm:map"
	OpLockTake  Op = "lock:acquire"
	OpEventWait Op = "event:wait"

	// kservice: the route table.
	OpRouteRegister Op = "route:register"
	OpRouteCall     Op = "route:call"

	// knet, kpeer, kslashing: controlled egress and the node mesh.
	OpNetDial         Op = "net:dial"
	OpNetListen       Op = "net:listen"
	OpPeerDial        Op = "peer:dial"
	OpPeerAnnounce    Op = "peer:announce"
	OpSlashReport     Op = "slash:report"
	OpSlashAdjudicate Op = "slash:adjudicate"

	// kvfs: namespaced state and bounded file access.
	OpKVRead  Op = "kv:read"
	OpKVWrite Op = "kv:write"
	OpFSRead  Op = "fs:read"
	OpFSWrite Op = "fs:write"

	// kkeyring and kcrypto: secret custody and primitives.
	OpSecretRead   Op = "secret:read"
	OpSecretUse    Op = "secret:use"
	OpCryptoRandom Op = "crypto:random"
	OpCryptoHash   Op = "crypto:hash"
	OpCryptoSign   Op = "crypto:sign"
	OpCryptoVerify Op = "crypto:verify"

	// ksched, ksignal, kwatchdog, koom, kcputime: execution control.
	OpSchedSpawn  Op = "sched:spawn"
	OpSchedTimer  Op = "sched:timer"
	OpSignalSend  Op = "signal:send"
	OpCPUTimeRead Op = "cputime:read"

	// ktrace and ktty: observability.
	OpTraceSpan Op = "trace:span"
	OpTTYOpen   Op = "tty:open"
)

// AllOps is the complete operation set, in declaration order. Tests and the
// console dump enumerate this rather than restating it.
var AllOps = []Op{
	OpMetadataRead, OpMetadataWrite, OpProcessFork,
	OpModuleLoad, OpModuleUnload, OpIPCBind, OpIPCCall, OpLogWrite,
	OpAuditAppend, OpAuditRead,
	OpUsageEmit, OpMeterRecord, OpMeterRead, OpTokenCount,
	OpReceiptIssue, OpReceiptVerify,
	OpQosAdmit, OpSlotAcquire,
	OpPipeOpen, OpPipeWrite, OpPipeRead, OpShmAlloc, OpShmMap, OpLockTake, OpEventWait,
	OpRouteRegister, OpRouteCall,
	OpNetDial, OpNetListen, OpPeerDial, OpPeerAnnounce, OpSlashReport, OpSlashAdjudicate,
	OpKVRead, OpKVWrite, OpFSRead, OpFSWrite,
	OpSecretRead, OpSecretUse, OpCryptoRandom, OpCryptoHash, OpCryptoSign, OpCryptoVerify,
	OpSchedSpawn, OpSchedTimer, OpSignalSend, OpCPUTimeRead,
	OpTraceSpan, OpTTYOpen,
}

// rules is the domain ceiling. It is compiled into the kernel on purpose: a
// policy an attacker can write to is not a policy.
//
// Domains not listed here hold nothing.
//
// The plugin ceiling encodes three deliberate refusals, and each one is the
// reason a subsystem can be trusted:
//
//   - secret:read is absent. A module never receives a plaintext credential. It
//     gets secret:use, under which the kernel applies the secret on the module's
//     behalf and returns only the result. That is the whole point of kkeyring.
//   - crypto:sign and receipt:issue are absent. Both require node key material.
//     A module that could sign could forge a settlement receipt for work it never
//     did, and kslashing would then be arbitrating between two forgeries.
//   - audit:append is absent. A module writes to the console with log:write; the
//     kernel writes the audit chain. If a module could append, it could fabricate
//     evidence of its own good behavior.
var rules = map[Domain]map[Op]struct{}{
	DomainKernel: opSet(AllOps...),
	// DomainInit is the boot and service-bringup sequence. It is deliberately
	// NOT a near-copy of the kernel domain. Init is long-lived and is the thing
	// the host process talks to, so every operation it holds is an operation that
	// survives the privilege drop. The prototype gave init the root context and
	// thereby the whole kernel domain; that is the mistake this list avoids.
	//
	// What init gets is what it needs to bring services up and supervise them:
	// spawn and load, the service bus, admission, scheduling, signals, and the
	// audit and metadata record of doing so.
	//
	// What init does NOT get, and why each refusal matters:
	//   - secret:read / secret:use: credential custody is a kernel service. Init
	//     has no reason to hold a plaintext key, and a long-lived holder of one is
	//     a long-lived exposure of it.
	//   - crypto:sign / receipt:issue: both need node key material. If init could
	//     sign, anything that compromised init could mint settlement receipts.
	//   - net:dial / net:listen / peer:dial: egress belongs to the network
	//     subsystem acting for a module under that module's manifest, not to the
	//     boot sequence.
	//   - slash:adjudicate: mesh governance must not be reachable from the same
	//     context that decides what code runs.
	//   - usage:emit / meter:record: init does not serve traffic, so it has no
	//     usage to report.
	//   - audit:append is granted but audit kinds describing kernel decisions are
	//     still refused to every non-kernel domain inside the syscall.
	DomainInit: opSet(
		OpProcessFork, OpModuleLoad, OpModuleUnload,
		OpMetadataRead, OpMetadataWrite, OpLogWrite,
		OpAuditAppend, OpAuditRead,
		OpRouteRegister, OpRouteCall, OpSlotAcquire, OpQosAdmit,
		OpSchedSpawn, OpSchedTimer, OpSignalSend, OpCPUTimeRead,
		OpMeterRead, OpTokenCount, OpReceiptVerify, OpTraceSpan,
		OpKVRead, OpKVWrite, OpTTYOpen,
	),
	DomainPlugin: opSet(
		// Identity and diagnostics.
		OpMetadataRead, OpLogWrite, OpIPCCall, OpTraceSpan, OpCPUTimeRead,
		// Accounting: a module reports, it never prices or settles.
		OpUsageEmit, OpMeterRecord, OpMeterRead, OpTokenCount, OpReceiptVerify,
		// Resources, all handle-mediated.
		OpPipeOpen, OpPipeWrite, OpPipeRead, OpShmAlloc, OpShmMap, OpLockTake, OpEventWait,
		OpSlotAcquire, OpQosAdmit, OpSchedSpawn, OpSchedTimer, OpSignalSend,
		// Service surface.
		OpRouteRegister, OpRouteCall,
		// Namespaced state, scope-enforced per call.
		OpKVRead, OpKVWrite,
		// Secrets by use only, never by read.
		OpSecretUse,
		// Crypto without key material.
		OpCryptoRandom, OpCryptoHash, OpCryptoVerify,
		// Mesh participation, not mesh governance.
		OpSlashReport,
	),
	DomainUntrusted: {},
}

func opSet(list ...Op) map[Op]struct{} {
	m := make(map[Op]struct{}, len(list))
	for _, o := range list {
		m[o] = struct{}{}
	}
	return m
}

// Allowed reports whether a domain holds an operation, ignoring manifest
// narrowing. It is the ceiling. The decision is granted().
func Allowed(dom Domain, op Op) bool {
	set, ok := rules[dom]
	if !ok {
		return false
	}
	_, ok = set[op]
	return ok
}

// OpsFor returns the sorted operations a domain holds.
func OpsFor(dom Domain) []Op {
	set := rules[dom]
	out := make([]Op, 0, len(set))
	for o := range set {
		out = append(out, o)
	}
	sortOps(out)
	return out
}

func sortOps(ops []Op) {
	sort.Slice(ops, func(i, j int) bool { return ops[i] < ops[j] })
}

// grants holds the effective operation set per pid for manifest-constrained
// contexts. It is what makes a manifest a control rather than documentation.
//
// Domains that are not manifest-constrained (kernel, init) are absent, so absence
// means "the ceiling applies unchanged". A module that declares nothing gets an
// empty set and can do nothing at all.
var (
	grantsMu sync.RWMutex
	grants   = map[PID]map[Op]struct{}{}
)

func setGrants(pid PID, ops []Op) {
	set := make(map[Op]struct{}, len(ops))
	for _, o := range ops {
		set[o] = struct{}{}
	}
	grantsMu.Lock()
	defer grantsMu.Unlock()
	grants[pid] = set
}

func clearGrants(pid PID) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	delete(grants, pid)
}

func resetGrants() {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	grants = map[PID]map[Op]struct{}{}
}

// enforcedScopedOps are the scoped operations that already have per-call boundary
// enforcement implemented in the subsystem that owns them. Membership here is a claim
// about code that exists, not about an operation that ought to be grantable, and the
// distinction is a security boundary rather than a bookkeeping one.
//
// A scoped operation absent from the plugin domain's ceiling is refused at the ceiling
// before its declared boundary is ever consulted, which makes it unreachable from any
// module even when its manifest declares it correctly. That is the right outcome while
// the enforcement is missing and the wrong outcome once it exists, so the pass-through
// below is gated on this set: an operation enters it only when a per-call check is in
// the tree, and it leaves the set if that check is ever removed.
//
// Passing through an operation with no per-call enforcement would turn its manifest
// declaration into an unbounded grant, because the declaration would be the only thing
// deciding and nothing would check the call against it. peer:dial, net:dial and
// net:listen are scoped in manifest.go and deliberately absent here for exactly that
// reason: their subsystems do not yet enforce a declared boundary per call.
var enforcedScopedOps = map[Op]bool{
	OpFSRead:    true, // kv.go: FSCheckRead consults the manifest's ReadPaths
	OpFSWrite:   true, // kv.go: FSCheckWrite consults the manifest's WritePaths
	OpSecretUse: true, // keyring.go: secretPrefixesFor and aliasInScope per call
	OpPeerDial:  true, // peer.go: peerEndpointAllowed consults the manifest's AllowedHosts
	OpNetDial:   true, // net.go: NetHostAllowed consults the manifest's AllowedHosts
	OpNetListen: true, // net.go: netListen matches the manifest's ListenAddr exactly
}

// OpSecretRead is scoped in manifest.go and deliberately absent here: it must stay
// unreachable from a module at any scope, because no module sees a plaintext credential
// and that refusal is the point of kkeyring rather than an omission in it.
//
// OpNetDial and OpNetListen were absent for the same reason - no per-call check against
// the declared boundary existed - and joined once net.go provided one. What makes the
// pass-through safe there is that the check is against a declaration a reviewer signed,
// and that it refuses when the declaration cannot be consulted: a context with no live
// manifest gets "no declared network boundary" rather than a permit.

// granted is the effective decision: the domain ceiling, then the module's own
// declaration. The reason distinguishes "your domain lacks this", which only a
// kernel change fixes, from "you forgot to declare it", which the module author
// fixes.
//
// One exception, and it is the reason scoped operations work at all. An operation in
// moduleScopedOps is deliberately absent from rules[DomainPlugin] - a capability every
// module held by default would be an unbounded capability - so applying the ceiling to
// it would refuse it twice, and the second refusal is the one that sticks: the declared
// scope would never be consulted and the operation would be unreachable from any
// module. For those, and only in the plugin domain, the declaration decides.
//
// That is still not a widening. The operation remains refused to every module whose
// manifest does not declare it; declaring it requires declaring its boundary, because
// manifest.Validate() rejects net:dial with no allowed host, fs:read with no read path
// and an empty secret prefix as a read-all grant; and the per-call scope enforcement in
// the owning subsystem still runs afterwards. A context with no manifest behind it - one
// init spawned directly - has no boundary to enforce against, so it is refused rather
// than passed through, which is what keeps this from becoming an unbounded grant.
func granted(ctx *sContext, op Op) (ok bool, reason string) {
	byDeclaration := false
	if !Allowed(ctx.dom, op) {
		if !(IsScoped(op) && enforcedScopedOps[op] && ctx.dom == DomainPlugin) {
			return false, ""
		}
		byDeclaration = true
	}
	grantsMu.RLock()
	set, constrained := grants[ctx.pid]
	grantsMu.RUnlock()
	if !constrained {
		if byDeclaration {
			return false, fmt.Sprintf("%s is scope-enforced and this context has no manifest scope", op)
		}
		return true, ""
	}
	if _, declared := set[op]; declared {
		return true, ""
	}
	return false, fmt.Sprintf("%s is not declared in the manifest for module %q", op, ctx.name)
}

// GrantsFor returns a copy of a pid's effective operation set, and whether that
// pid is manifest-constrained at all.
func GrantsFor(pid PID) ([]Op, bool) {
	grantsMu.RLock()
	defer grantsMu.RUnlock()
	set, ok := grants[pid]
	if !ok {
		return nil, false
	}
	out := make([]Op, 0, len(set))
	for o := range set {
		out = append(out, o)
	}
	sortOps(out)
	return out, true
}

// DeniedError is a policy denial. The canonical line keeps the prototype's format
// so faults stay greppable across releases:
//
//	avc: denied { <op> } for domain=<domain> pid=<pid>
type DeniedError struct {
	Op     Op
	Ctx    *sContext
	Reason string
}

func (e *DeniedError) Error() string {
	base := fmt.Sprintf("avc: denied { %s } for null context", e.Op)
	if e.Ctx != nil {
		base = fmt.Sprintf("avc: denied { %s } for domain=%s pid=%d", e.Op, e.Ctx.dom, e.Ctx.pid)
	}
	if e.Reason == "" {
		return base
	}
	return base + ": " + e.Reason
}

// IsDenied reports whether err is a policy denial.
func IsDenied(err error) bool {
	var d *DeniedError
	return errors.As(err, &d)
}

// DenialReason returns the manifest-narrowing reason on a denial, or "" when the
// denial came from the domain ceiling.
func DenialReason(err error) string {
	var d *DeniedError
	if errors.As(err, &d) {
		return d.Reason
	}
	return ""
}

// check is the single policy decision point. Every syscall routes through it and
// nothing in the kernel reaches a subsystem around it.
//
// A denial is fatal to the operation, never to the process, and is always written
// to the audit chain as well as the console.
func check(ctx *sContext, op Op) error {
	if ctx == nil {
		d := &DeniedError{Op: op}
		fault(nil, d.Error(), nil)
		kaudit.record(AuditDenial, nil, d.Error(), nil)
		return d
	}
	ok, reason := granted(ctx, op)
	if ok {
		return nil
	}
	d := &DeniedError{Op: op, Ctx: ctx, Reason: reason}
	var fields map[string]any
	if reason != "" {
		fields = map[string]any{"reason": reason}
	}
	fault(ctx, d.Error(), fields)
	kaudit.record(AuditDenial, ctx, d.Error(), map[string]any{"op": string(op), "reason": reason})
	return d
}
