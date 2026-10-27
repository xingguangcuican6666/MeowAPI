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
	OpIPCBind       Op = "ipc:bind"
	OpIPCCall       Op = "ipc:call"
	OpLogWrite      Op = "log:write"

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

// granted is the effective decision: the domain ceiling, then the module's own
// declaration. The reason distinguishes "your domain lacks this", which only a
// kernel change fixes, from "you forgot to declare it", which the module author
// fixes.
func granted(ctx *sContext, op Op) (ok bool, reason string) {
	if !Allowed(ctx.dom, op) {
		return false, ""
	}
	grantsMu.RLock()
	set, constrained := grants[ctx.pid]
	grantsMu.RUnlock()
	if !constrained {
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
