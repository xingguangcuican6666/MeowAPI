package abi

// The context a module receives in OnLoad, and the syscall groups it is composed of.
//
// SContext is deliberately NOT sealed here, and the absence is worth a paragraph because
// it looks like a weakening. The interface used to carry an unexported `sealed()`
// method, which made it impossible to implement outside package kernel. That method
// cannot be written here: a type in package kernel cannot gain a promoted method from a
// type in package abi, and exporting an embeddable seal is worse than useless - measured,
// a module can embed it and satisfy the interface itself.
//
// What actually keeps a context unforgeable is not the interface. Every kernel entry
// point resolves its argument with a type assertion against the kernel's own unexported
// struct, so a value a module builds never resolves and is refused. That check was always
// the real gate, and moving the interface here does not touch it: a module can name
// abi.SContext in its own signatures, and still cannot produce one the kernel accepts.

// SContext is the only view of a security context a module ever sees, and the
// only way it reaches a syscall.
//
// The implementing struct lives in package kernel, is unexported, and its fields
// are unreachable, so a module cannot read or mutate an identity. No kernel entry
// point takes a context as a parameter besides these methods, so there is no call
// shape in which a module acts as another.
//
// The unforgeability itself is enforced by the kernel, not by the interface: any
// value a module builds fails the type assertion the kernel entry point performs
// against its own struct, and is refused as a foreign context. The interface can
// be implemented from outside only in the sense that a module can declare its own
// type with these methods; such a value never reaches a syscall.
//
// This is the Go substitute for the prototype's StackWalker caller check. Java
// needed runtime stack inspection because every class shares one classloader
// namespace; here the kernel holds the only concrete type, and refusing an unknown
// one is a single assertion rather than a walk. Do not port the stack walk as the
// primary control.
//
// The syscall surface is composed of per-subsystem groups, each declared in the
// file that implements it. A new subsystem adds its own group interface and its
// own methods on *sContext, and lists the group here; it does not rewrite this
// file. Keeping the groups separate is what lets two subsystems be written at
// once without either touching the other's code, and it makes the syscall surface
// of any one subsystem readable in one place.
type SContext interface {
	// Identity is what a module may learn about itself.
	Identity

	// Every group below is declared here rather than beside the subsystem that
	// implements it, because a module has to name a group to take one as a
	// parameter and this is the only package it can see. The METHODS that satisfy
	// them stay in the kernel, one file per subsystem, next to the policy checks
	// and the state they touch. A new subsystem adds its group here and its
	// methods there, and touches no other subsystem.
	SyscallClock
	SyscallMeta
	SyscallLog
	SyscallAudit
	SyscallProc
	SyscallMeter
	SyscallFD
	SyscallBoot

	SyscallLimit
	SyscallQos
	SyscallCPU
	SyscallPipe
	SyscallShm
	SyscallKV
	SyscallCrypto
	SyscallKeyring
	SyscallReceipt
	SyscallSched
	SyscallSignal
	SyscallLock
	SyscallEvent
	SyscallTrace
	SyscallRoute
	SyscallFS
	SyscallNet
	SyscallPeer
	SyscallRequest
	SyscallTokenizer
	SyscallSeccomp
	SyscallSlashing
	SyscallTTY
}

// SyscallAudit is the audit half of the syscall surface.
type SyscallAudit interface {
	// SyscallAuditRead queries the audit chain. Requires audit:read.
	SyscallAuditRead(f AuditFilter) ([]AuditEntry, error)
	// SyscallAuditAppend attaches a note to a request trace. Requires
	// audit:append, which the plugin domain does not hold by default, and
	// kernel-only kinds are refused even to a holder.
	SyscallAuditAppend(kind AuditKind, trace, msg string, fields map[string]any) (AuditEntry, error)
}

// SyscallBoot is the trust-root half of the syscall surface. Every method is a
// read; there is no write, because there is nothing to write to after sealing.
type SyscallBoot interface {
	// SyscallBootGet reads one sealed trust root entry. It never returns key
	// material.
	SyscallBootGet(key string) (string, bool)
	// SyscallBootAll returns the whole trust root, sorted by key.
	SyscallBootAll() []BootConfigValue
	// SyscallBootLimits returns the effective resource ceilings.
	SyscallBootLimits() BootLimits
	// SyscallBootDigest returns the hash of the sealed trust root.
	SyscallBootDigest() string
}

// SyscallClock is the time half of the syscall surface.
type SyscallClock interface {
	// SyscallNow returns kernel time. Mono is the only value a module may use to
	// measure an interval or a deadline; Wall is for records a human reads.
	// Requires no operation: a module that cannot read time cannot implement a
	// timeout, and there is nothing to gain by granting a forged clock.
	SyscallNow() KernelTime
}

// SyscallLog is the console half of the syscall surface.
type SyscallLog interface {
	// SyscallLog writes to the kernel console. Requires log:write. A context
	// outside the kernel and init domains may not emit fault records, because
	// the fault stream is the kernel's own audit trail.
	SyscallLog(level Level, msg string) error
}

// SyscallCrypto is the primitives half of the syscall surface. Key material does
// not cross this boundary in either direction: a module asks for a signature and
// receives the signature, never the key.
type SyscallCrypto interface {
	// SyscallCryptoRandom returns n cryptographically secure random bytes from
	// crypto/rand. Requires crypto:random.
	SyscallCryptoRandom(n int) ([]byte, error)
	// SyscallCryptoRandomHex returns n random bytes as 2n lowercase hex
	// characters, for tokens and nonces. Requires crypto:random.
	SyscallCryptoRandomHex(n int) (string, error)
	// SyscallCryptoHash digests data with a kernel-approved algorithm and returns
	// the hex digest. Requires crypto:hash.
	SyscallCryptoHash(algo HashAlgo, data []byte) (string, error)
	// SyscallCryptoSign signs msg with this node's key and returns only the
	// signature. Requires crypto:sign, which no module domain holds.
	SyscallCryptoSign(msg []byte) (Signature, error)
	// SyscallCryptoVerify checks a signature against one named verification key
	// and reports only the verdict. Requires crypto:verify.
	SyscallCryptoVerify(key string, msg, sig []byte) (bool, error)
	// SyscallCryptoVerifyCluster checks a signature against the sealed cluster
	// roots and reports the verdict with the matching key id. Requires
	// crypto:verify.
	SyscallCryptoVerifyCluster(msg, sig []byte) (bool, string, error)
}

// SyscallKeyring is the secret-custody half of the syscall surface. No method here
// hands a plaintext credential to a module: the module names an alias and an action,
// the kernel applies the secret and returns the result.
type SyscallKeyring interface {
	// SyscallSecretAliases lists the aliases visible to this context, narrowed to
	// the secret prefixes the manifest declared. Requires secret:use.
	SyscallSecretAliases() ([]string, error)
	// SyscallSecretUse applies a custodied secret on this context's behalf and
	// returns only the result. Requires secret:use, scoped by prefix.
	SyscallSecretUse(alias string, action SecretAction, data []byte) (SecretResult, error)
	// SyscallSecretRead returns a plaintext credential. Requires secret:read,
	// which no module domain holds.
	SyscallSecretRead(alias string) ([]byte, error)
	// SyscallSecretRegister takes custody of a credential. Requires secret:read.
	SyscallSecretRegister(spec SecretSpec) error
	// SyscallSecretRevoke destroys a custodied credential. Requires secret:read.
	SyscallSecretRevoke(alias string) error
}

// SyscallReceipt is the settlement half of the syscall surface. A module may verify
// any receipt and take custody of one; only a context holding receipt:issue may mint
// one, and no module domain does.
type SyscallReceipt interface {
	// SyscallReceiptIssue mints and signs one settlement receipt. Requires
	// receipt:issue, which is held by the kernel domain alone.
	SyscallReceiptIssue(spec ReceiptSpec) (Receipt, error)
	// SyscallReceiptVerify recomputes a receipt's canonical encoding and checks
	// its signature against the sealed cluster roots. Requires receipt:verify.
	SyscallReceiptVerify(r Receipt) (ReceiptVerdict, error)
	// SyscallReceiptOpen verifies a receipt and returns a per-pid handle to the
	// verdict. Requires receipt:verify.
	SyscallReceiptOpen(r Receipt) (FD, ReceiptVerdict, error)
}

// SyscallKV is the namespaced-state half of the syscall surface. Keys are scoped by
// owner pid, so one module cannot read or write another's state.
type SyscallKV interface {
	// SyscallKVGet reads one value from this module's namespace. Requires
	// kv:read. The returned slice is a copy the caller owns.
	SyscallKVGet(key string) ([]byte, error)
	// SyscallKVPut stores one value in this module's namespace. Requires
	// kv:write. The value is copied in, and a write over the per-module ceiling
	// is refused with a *KVQuotaError.
	SyscallKVPut(key string, value []byte) error
	// SyscallKVDelete removes one key. Requires kv:write.
	SyscallKVDelete(key string) error
	// SyscallKVKeys lists this module's own keys, sorted. Requires kv:read.
	SyscallKVKeys() ([]string, error)
}

// SyscallShm is the shared-buffer half of the syscall surface. The kernel owns the
// bytes and never hands out the underlying slice on either side, so there is no call
// shape in which a reader obtains a writable alias into a prompt in flight.
type SyscallShm interface {
	// SyscallShmAlloc allocates a shared buffer and returns a descriptor for it.
	// Requires shm:alloc. The payload is written through SyscallShmWrite and
	// never handed back as a slice.
	SyscallShmAlloc(size int, label string) (ShmDescriptor, error)
	// SyscallShmWrite copies bytes into a segment this context owns. Requires
	// shm:alloc, and refuses a sealed segment.
	SyscallShmWrite(fd FD, offset int, p []byte) (int, error)
	// SyscallShmRead copies bytes out of a segment this context owns or was
	// granted. Requires shm:map.
	SyscallShmRead(fd FD, offset int, dst []byte) (int, error)
	// SyscallShmBytes returns a fresh copy of a segment's whole payload. Requires
	// shm:map.
	SyscallShmBytes(fd FD) ([]byte, error)
	// SyscallShmSize reports a segment's payload size. Requires shm:map.
	SyscallShmSize(fd FD) (int, error)
	// SyscallShmGrant authorises one peer to map a segment, and seals it. Requires
	// shm:alloc.
	SyscallShmGrant(fd FD, peer PID) error
	// SyscallShmMap maps a granted segment read-only. Requires shm:map and a grant
	// from the owner.
	SyscallShmMap(id SHMID, label string) (ShmMapping, error)
	// SyscallShmSeal makes this context's own segment immutable without granting
	// it. Requires shm:alloc.
	SyscallShmSeal(fd FD) error
}

// SyscallCPU is the accounting half of the syscall surface.
type SyscallCPU interface {
	// SyscallCPUStat returns this context's own accounting. Requires cputime:read.
	// A module cannot read another pid's accounting, because one module's burn rate
	// is another module's information leak.
	SyscallCPUStat() (CPUStat, error)
}

// SyscallEvent is the event half of the syscall surface.
type SyscallEvent interface {
	// SyscallEventSubscribe registers interest in a set of kernel event names and
	// returns the handle that owns the subscription. Requires event:wait. Closing
	// the handle unsubscribes.
	SyscallEventSubscribe(names []KernelEventName) (FD, error)
	// SyscallEventWait blocks until an event is pending on a subscription this
	// context owns, or the deadline passes. Requires event:wait.
	SyscallEventWait(fd FD, deadline int64) ([]Event, error)
	// SyscallEventPending reports how many events are queued and how many were
	// dropped, without blocking. Requires no operation, and only for this
	// context's own subscriptions.
	SyscallEventPending(fd FD) (pending int, dropped int, err error)
}

// SyscallFD is the handle half of the syscall surface.
type SyscallFD interface {
	// SyscallClose releases a handle this context opened. Handles are per pid,
	// so a handle belonging to another module does not resolve here. Requires no
	// operation: closing what you opened is not a capability.
	SyscallClose(fd FD) error
	// SyscallFDs lists this context's open handles, for a module diagnosing its
	// own leaks. Requires no operation, and never exposes another pid's table.
	SyscallFDs() []FDInfo
}

// SyscallFS is the module-facing half of this surface. Wiring it needs two lines:
// SyscallFS in the SContext composition in context.go, and resetFS() in resetKernel()
// next to resetFSScopes(). Until then the exported package-level functions above are
// the surface, and they are what the tests call.
type SyscallFS interface {
	// SyscallFSRead reads one file. Requires fs:read, a configured data root, and a
	// path inside the manifest's ReadPaths.
	SyscallFSRead(rel string) ([]byte, error)
	// SyscallFSWrite writes one file atomically. Requires fs:write and a path
	// inside the manifest's WritePaths.
	SyscallFSWrite(rel string, data []byte) error
	// SyscallFSList lists a directory, sorted. Requires fs:read.
	SyscallFSList(rel string) ([]string, error)
	// SyscallFSStat reports size and directory flag. Requires fs:read.
	SyscallFSStat(rel string) (FSInfo, error)
	// SyscallFSDelete removes one file. Requires fs:write.
	SyscallFSDelete(rel string) error
}

// SyscallLock is the lock half of the syscall surface.
type SyscallLock interface {
	// SyscallLockTake acquires a named lock and returns the handle that owns it.
	// Requires lock:acquire. The deadline is mandatory: an untimed lock wait is
	// how a module turns a contended lock into an outage.
	SyscallLockTake(name string, exclusive bool, deadline int64) (FD, error)
	// SyscallLockRelease releases a lock handle this context holds.
	SyscallLockRelease(fd FD) error
}

// SyscallMeta is the metadata half of the syscall surface.
type SyscallMeta interface {
	// SyscallMetadataGet reads a key. Requires metadata:read. A module sees its
	// own entries and kernel-published ones, never another module's.
	SyscallMetadataGet(key string) (any, error)
	// SyscallMetadataSet writes a key. Requires metadata:write, which no module
	// domain holds.
	SyscallMetadataSet(key string, value any) error
}

// SyscallMeter is the request-metering half of the syscall surface. usage.go's
// SyscallMeter group covers the pid totals; this one covers the per-request view.
// Both are named SyscallMeter* by prefix, and the two groups are distinct interfaces
// so a subsystem can be wired without editing the other's file.
type SyscallRequest interface {
	// SyscallMeterOpen starts metering one request and returns the kernel-assigned
	// id. Requires meter:record.
	SyscallMeterOpen(trace TraceID, route string) (RequestID, error)
	// SyscallMeterAdd records a validated usage fact against an open request this
	// context owns. Requires meter:record.
	SyscallMeterAdd(id RequestID, f UsageFact) error
	// SyscallMeterClose finishes a request and returns its record. Requires
	// meter:record.
	SyscallMeterClose(id RequestID, status int) (MeterRecord, error)
	// SyscallMeterGet reads one record by id. Requires meter:read.
	SyscallMeterGet(id RequestID) (MeterRecord, error)
	// SyscallMeterQuery returns retained records matching a filter, newest first.
	// Requires meter:read.
	SyscallMeterQuery(f MeterFilter) []MeterRecord
}

// SyscallNet is the module-facing half of this subsystem. Every method is a thin wrapper
// over the corresponding package function, which does the policy check first.
type SyscallNet interface {
	// SyscallNetDial opens one outbound connection. Requires net:dial, a host inside the
	// manifest's AllowedHosts, and a resolved address the deployment permits.
	SyscallNetDial(spec NetSpec) (NetDialResult, error)
	// SyscallNetWrite sends bytes over an open socket under a mandatory deadline.
	SyscallNetWrite(fd FD, data []byte) (int, error)
	// SyscallNetRead receives bytes under a mandatory deadline and a kernel ceiling.
	SyscallNetRead(fd FD, limit int) ([]byte, error)
	// SyscallNetRelease returns a socket to the pool instead of closing it.
	SyscallNetRelease(fd FD) error
	// SyscallNetClose closes a socket without pooling it.
	SyscallNetClose(fd FD) error
	// SyscallNetListen binds the declared listen address. Requires net:listen.
	SyscallNetListen(address string) (FD, error)
	// SyscallNetAccept takes one inbound connection under a mandatory deadline.
	SyscallNetAccept(fd FD) (FD, error)
	// SyscallNetCloseListener closes a listener.
	SyscallNetCloseListener(fd FD) error
	// SyscallNetSockets lists this module's open sockets.
	SyscallNetSockets() []NetInfo
}

// SyscallPeer is the mesh half of the syscall surface. Key material does not cross it
// in either direction, and no method here accepts a frame from a caller: inbound
// frames arrive only through the host handle, so a module cannot inject one and have
// the kernel treat it as a peer's claim.
type SyscallPeer interface {
	// SyscallPeerDial proves a peer's identity and opens a session handle. Requires
	// peer:dial, which only the kernel domain holds.
	SyscallPeerDial(spec PeerDialSpec) (PeerSession, error)
	// SyscallPeerAnnounce publishes one signed discovery record. Requires
	// peer:announce.
	SyscallPeerAnnounce(a PeerAnnouncement) error
	// SyscallPeerProbe measures one round trip on the monotonic clock. Requires
	// peer:dial.
	SyscallPeerProbe(fd FD, deadline int64) (PeerLatency, error)
	// SyscallPeerForward sends one request to a peer node and returns its reply.
	// Requires peer:dial.
	SyscallPeerForward(req PeerForwardRequest) (PeerForwardResult, error)
	// SyscallPeerPeers lists the mesh table. Requires peer:dial.
	SyscallPeerPeers() ([]PeerInfo, error)
}

// SyscallPipe is the pipe half of the syscall surface.
type SyscallPipe interface {
	// SyscallOpenPipe creates a pipe and returns the owner's handle. Requires
	// pipe:open. Capacity is clamped to the kernel maximum.
	SyscallOpenPipe(name string, capacity int, mode PipeMode) (FD, error)
	// SyscallPipeWrite enqueues one chunk, always as a copy. Requires pipe:write.
	SyscallPipeWrite(fd FD, data []byte, deadline int64) (int, error)
	// SyscallPipeRead dequeues one chunk, always as a copy. Requires pipe:read.
	SyscallPipeRead(fd FD, deadline int64) ([]byte, error)
	// SyscallPipeAbort signals the stream to stop, for a client disconnect.
	// Requires pipe:write. Latching: once aborted, a pipe stays aborted.
	SyscallPipeAbort(fd FD) error
	// SyscallPipeInfo describes a pipe this context owns, without its content.
	SyscallPipeInfo(fd FD) (PipeInfo, error)
}

// SyscallProc is the process half of the syscall surface.
type SyscallProc interface {
	// SyscallSpawn creates a child context. Requires process:fork, and the
	// target domain must be permitted by the transition rule.
	SyscallSpawn(dom Domain, name string) (SContext, error)
}

// SyscallQos is the admission half of the syscall surface.
type SyscallQos interface {
	// SyscallQosAdmit asks whether a request may proceed, costing the given number
	// of tokens. Requires qos:admit. The time is read from the kernel clock, never
	// from the caller.
	SyscallQosAdmit(cost int64) (QosDecision, error)
}

// SyscallLimit is the admission half of the syscall surface.
type SyscallLimit interface {
	// SyscallAcquireSlot reserves one concurrency slot and returns the handle that
	// owns it. Requires slot:acquire. Close the handle, or let the module unload, to
	// release it.
	SyscallAcquireSlot(label string) (FD, error)
	// SyscallSlots reports how many slots this context holds. It requires no
	// operation and never reports another pid's count.
	SyscallSlots() int
}

// SyscallSched is the supervised-execution half of the syscall surface.
type SyscallSched interface {
	// SyscallSchedSpawn asks the kernel to run a function under the caller's own
	// context, a deadline clamped to the sealed ceiling, and panic recovery, and
	// returns a handle to the run. Requires sched:spawn.
	SyscallSchedSpawn(job SchedJob) (FD, error)
	// SyscallSchedTimer arms a single-shot callback after a delay measured on
	// mono(). Requires sched:timer. Closing the returned handle cancels it.
	SyscallSchedTimer(spec TimerSpec) (FD, error)
	// SyscallSchedWait blocks until a run reaches a terminal state and returns a
	// copy of its outcome. Requires no operation, and the handle resolves only
	// inside the caller's own pid.
	SyscallSchedWait(fd FD) (SchedOutcome, error)
}

// SyscallSeccomp is the module-facing half, and it is one method.
//
// A module may learn that it is filtered and nothing more. The contents are withheld for
// the same reason SeccompSnapshotFor refuses a self-read: a module that can read its filter
// knows exactly what it is restricted from, and a module that can modify it makes the
// subsystem a formality. Knowing that a filter exists is useful - a module can shed load or
// report its own confinement - so the boolean is granted and the rules are not.
//
// There is no Op for this in policy.go and none is needed: the answer is about the caller's
// own pid and reveals nothing about anybody else, so the liveness check c.syscall("")
// performs is the whole of the gate.
type SyscallSeccomp interface {
	// SyscallSeccompFiltered reports whether an instance filter is installed on the
	// caller's own pid.
	SyscallSeccompFiltered() (bool, error)
}

// SyscallRoute is the routing half of the syscall surface.
type SyscallRoute interface {
	// SyscallRouteRegister serves a path from this module. Requires route:register
	// and a manifest declaration of that exact path. A second registration of the
	// same path is refused rather than replacing the first.
	SyscallRouteRegister(path string, h RouteHandler) error
	// SyscallRouteCall dispatches one call. Requires route:call. The handler runs
	// under its own context and its own grants, never under the caller's.
	SyscallRouteCall(req RouteRequest) (RouteResponse, error)
	// SyscallRoutes lists the paths this module serves. Requires no operation, and
	// never lists another module's routes.
	SyscallRoutes() []string
}

// SyscallSignal is the signal half of the syscall surface.
type SyscallSignal interface {
	// SyscallSignalSend delivers a signal to a pid. Requires signal:send, and the
	// target must be permitted by the rules in ksignal: never pid 0, never init,
	// and for a plugin only itself or a pid it spawned. Delivery is asynchronous
	// through a bounded per-pid queue.
	SyscallSignalSend(target PID, kind SignalKind) error
	// SyscallSignalHandle installs the caller's own signal handler, replacing any
	// previous one. Requires no operation: it can only narrow the caller's own
	// response to a signal, never widen what the caller may do.
	SyscallSignalHandle(h SignalHandler) error
}

// SyscallSlashing is the mesh-governance half of the syscall surface.
//
// Filing and deciding are separate operations with separate grants and no context holds
// both, which is the property that makes the ledger trustworthy: a reporter cannot write
// its own verdict, and the party that writes verdicts does not serve traffic and
// therefore never sees a peer's receipts.
type SyscallSlashing interface {
	// SyscallSlashReport files a fraud proof. Requires slash:report.
	SyscallSlashReport(p SlashProof) (SlashID, error)
	// SyscallSlashAdjudicate decides one filed proof. Requires slash:adjudicate,
	// which no live context holds.
	SyscallSlashAdjudicate(id SlashID) (SlashRecord, error)
	// SyscallSlashRecords lists decided and pending proofs. Requires slash:report.
	SyscallSlashRecords(f SlashFilter) ([]SlashRecord, error)
}

// SyscallTokenizer is the module-facing half of this surface. It is read-and-report
// only: there is no way for a module to set the strictness of the check applied to its
// own reports, and no way for it to overwrite a measurement.
type SyscallTokenizer interface {
	// SyscallTokenCount measures bytes the caller already holds. Requires token:count.
	SyscallTokenCount(data []byte) (TokenMeasurement, error)
	// SyscallTokenCheckUsage compares a reported token quantity against a measurement
	// of the bytes that produced it. Requires token:count.
	SyscallTokenCheckUsage(kind UsageKind, reported int64, data []byte) (TokenCheck, error)
}

// SyscallTrace is the tracing half of the syscall surface.
type SyscallTrace interface {
	// SyscallTraceOpen starts a span and returns the handle that owns it plus the
	// ids the kernel assigned. Requires trace:span. The ids are not forgeable: a
	// module cannot supply its own trace id or span id.
	SyscallTraceOpen(spec SpanSpec) (FD, TraceID, SpanID, error)
	// SyscallTraceEnd closes a span this context owns and returns its record.
	SyscallTraceEnd(fd FD) (Span, error)
	// SyscallTraceMark records a bounded attribute on a live span.
	SyscallTraceMark(fd FD, key, value string) error
	// SyscallTraceQuery returns finished spans matching a filter, newest first.
	// Requires trace:span, and never returns another pid's live span.
	SyscallTraceQuery(f TraceFilter) []Span
}

// SyscallTTY is the operator console half of the syscall surface.
//
// Reading through it needs no credential because it hands back nothing an operator could
// not already see on the console. The privileged acts need one, and no method here returns
// it: the credential crosses the boundary inward only, is wiped on every path, and the
// only observable outcome of presenting it is a permitted action or a refusal that does not
// distinguish wrong from missing.
type SyscallTTY interface {
	// SyscallTTYOpen opens a console handle. Requires tty:open.
	SyscallTTYOpen() (FD, error)
	// SyscallTTYRead returns a bounded window of console history through one handle.
	// Requires tty:open.
	SyscallTTYRead(fd FD, since int) (TTYWindow, error)
	// SyscallTTYWrite emits one console line. Requires log:write.
	SyscallTTYWrite(fd FD, level Level, msg string) error
	// SyscallTTYLoadModule loads a module on the operator's behalf. Requires
	// tty:open and the console credential.
	SyscallTTYLoadModule(fd FD, credential []byte, m Manifest) (PID, error)
	// SyscallTTYUnloadModule unloads a module on the operator's behalf. Requires
	// tty:open and the console credential.
	SyscallTTYUnloadModule(fd FD, credential []byte, pid PID) error
	// SyscallTTYProcessTable reads the process table. Requires tty:open and the
	// console credential.
	SyscallTTYProcessTable(fd FD, credential []byte) ([]ProcSnapshot, error)
}

// SyscallMeter is the accounting half of the syscall surface.
type SyscallMeter interface {
	// SyscallUsageEmit reports one usage fact. Requires usage:emit. The kernel
	// validates the kind and quantity before recording anything; an unknown kind
	// or an out-of-range quantity is refused rather than accumulated. The kernel
	// counts quantities and never prices them.
	SyscallUsageEmit(f UsageFact) error
}
