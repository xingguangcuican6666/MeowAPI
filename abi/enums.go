package abi

// Closed enumerations a module has to be able to name. The values are the
// contract; the rules about which of them a module may produce are the kernel's.

// AuditKind classifies an audit event. The set is closed: an unknown kind is
// rejected rather than recorded as a generic event, because a classification the
// kernel cannot name is one it cannot later query.
type AuditKind string

const (
	// AuditBoot and AuditShutdown bracket one kernel lifetime.
	AuditBoot     AuditKind = "boot"
	AuditShutdown AuditKind = "shutdown"
	// AuditSpawn and AuditExit are process birth and death.
	AuditSpawn AuditKind = "spawn"
	AuditExit  AuditKind = "exit"
	// AuditDenial is an avc denial. Every denial in the kernel lands here.
	AuditDenial AuditKind = "denial"
	// AuditEscalation is any attempt to widen privilege: spawning into a more
	// privileged domain, emitting a fault record, requesting a non-grantable
	// operation.
	AuditEscalation AuditKind = "escalation"
	// AuditLoad, AuditUnload and AuditReject are module lifecycle events.
	AuditLoad   AuditKind = "load"
	AuditUnload AuditKind = "unload"
	AuditReject AuditKind = "reject"
	// AuditRequest brackets one client request, linking every event that carries
	// its trace id.
	AuditRequest AuditKind = "request"
	// AuditUsage and AuditSettle are accounting events.
	AuditUsage  AuditKind = "usage"
	AuditSettle AuditKind = "settle"
	// AuditSecret records the use of a credential. Never its value.
	AuditSecret AuditKind = "secret"
	// AuditPanic records an unrecovered fault in kernel or module code.
	AuditPanic AuditKind = "panic"
	// AuditPolicy records a policy-relevant kernel action such as publishing
	// configuration or sealing the trust root.
	AuditPolicy AuditKind = "policy"
	// AuditPeer and AuditSlash record mesh events.
	AuditPeer  AuditKind = "peer"
	AuditSlash AuditKind = "slash"
)

// UsageKind names a quantity the kernel counts. The kernel counts quantities;
// it never prices them. Pricing, rating, tiering and settlement belong to
// modules, which is why no kind here carries a unit price, a ratio or a
// discount, and why UsageFact has no such field. The absence is the control.
//
// The set is closed on purpose. An unknown kind is rejected rather than
// accumulated under a default branch: the upstream project this one forked from
// let a plugin-supplied usage fact fall through an unbounded default case into
// settlement, which turned a declaration into a billing multiplier.
type UsageKind string

const (
	// UsageTokensIn counts prompt tokens consumed.
	UsageTokensIn UsageKind = "tokens:in"
	// UsageTokensOut counts completion tokens produced.
	UsageTokensOut UsageKind = "tokens:out"
	// UsageRequests counts completed requests.
	UsageRequests UsageKind = "requests:count"
)

// SignalKind is one of the four things the kernel can say to a module. The set is
// closed: an unnamed kind is refused rather than delivered as a generic event,
// because a handler cannot act on a meaning it cannot read.
type SignalKind string

const (
	// SignalReload asks a module to re-read its configuration. The analogue is
	// SIGHUP. Default action: none, recorded.
	SignalReload SignalKind = "reload"
	// SignalDrain asks a module to stop accepting new work and finish what is in
	// flight. The analogue is SIGTERM. Default action: terminate, because a
	// module that ignores drain and never exits makes unload unsafe.
	SignalDrain SignalKind = "drain"
	// SignalKill asks a module to stop now. The analogue is SIGKILL. Default
	// action: terminate. There is no way to ignore it: the kernel performs the
	// teardown itself.
	SignalKill SignalKind = "kill"
	// SignalAbort reports that the client behind some in-flight work went away.
	// It cancels the module's supervised runs so a stream stops being produced
	// for a reader that is gone. Default action: cancel in-flight work, do not
	// terminate.
	SignalAbort SignalKind = "abort"
)

// SpanKind names what a span measures. The set is closed so an operator's dashboard
// can group by it without discovering new values in production.
type SpanKind string

const (
	// SpanRequest is the whole request, opened by the entry module.
	SpanRequest SpanKind = "request"
	// SpanRoute is a dispatch through the kernel route table.
	SpanRoute SpanKind = "route"
	// SpanModule is time inside one module's own work.
	SpanModule SpanKind = "module"
	// SpanUpstream is time waiting on a provider or another node. This is the span
	// that separates "our code is slow" from "the network is slow".
	SpanUpstream SpanKind = "upstream"
	// SpanTimeToFirstToken is the interval from request start to the first token
	// of a streamed completion. It is its own kind rather than a generic span
	// because it is the number a streaming gateway is judged on.
	SpanTimeToFirstToken SpanKind = "ttft"
	// SpanSettle is billing settlement.
	SpanSettle SpanKind = "settle"
)

// SlashKind names what a proof claims. The set is closed and an unknown kind is
// refused rather than defaulted, because a default branch is where an unspecified
// accusation becomes an accepted one.
type SlashKind string

const (
	// SlashEquivocation claims two receipts from one node under one sequence number
	// that disagree. This is the strongest finding: both signatures are valid, so
	// nothing but comparing them reveals the contradiction.
	SlashEquivocation SlashKind = "equivocation"
	// SlashSequenceGap claims a node's sequence has a hole. The honest limit is part
	// of the definition: a gap proves the missing receipt was ISSUED, because
	// issuance is gap-free under one lock. It does not prove dishonest withholding
	// rather than loss in transit, so this kind is recorded as weaker evidence than
	// equivocation and an operator should weight it accordingly.
	SlashSequenceGap SlashKind = "sequence-gap"
	// SlashEmptyContent claims a receipt settles prompt tokens against a prompt whose
	// hash is the digest of empty input. The contradiction is internal to one signed
	// receipt, which is what makes it checkable without any cross-node state.
	SlashEmptyContent SlashKind = "empty-content"
)

// PeerFrameKind names what a frame carries. The set is closed and an unknown kind is
// refused rather than defaulted, because a default branch is where an unspecified
// frame becomes an accepted one - the specific hole usage.go exists to close.
type PeerFrameKind string

const (
	PeerFrameHandshake      PeerFrameKind = "handshake"
	PeerFrameHandshakeReply PeerFrameKind = "handshake-reply"
	PeerFrameProbe          PeerFrameKind = "probe"
	PeerFrameProbeReply     PeerFrameKind = "probe-reply"
	PeerFrameAnnounce       PeerFrameKind = "announce"
	PeerFrameForward        PeerFrameKind = "forward"
	PeerFrameForwardReply   PeerFrameKind = "forward-reply"
	PeerFrameGoodbye        PeerFrameKind = "goodbye"
)

// HashAlgo names a digest algorithm the kernel will apply. The set is closed and an
// unknown algorithm is refused rather than defaulted, because a default branch is
// where a downgrade to a weaker digest would hide.
type HashAlgo string

const (
	// HashSHA256 is the digest for hashes that cross a node boundary.
	HashSHA256 HashAlgo = "sha256"
	// HashSHA384 exists for callers whose protocol fixes it.
	HashSHA384 HashAlgo = "sha384"
	// HashSHA512 exists for callers whose protocol fixes it.
	HashSHA512 HashAlgo = "sha512"
)

// SchedState is the state of a supervised run. The set is closed, because a state
// the kernel cannot name is one an operator cannot later query.
type SchedState string

const (
	// SchedRunning is a run the kernel has started and not finished.
	SchedRunning SchedState = "running"
	// SchedCompleted is a run whose function returned before any deadline.
	SchedCompleted SchedState = "completed"
	// SchedTimedOut is a run whose deadline expired and whose function did not
	// return within the grace period. The kernel stopped waiting for it; the
	// goroutine may still be running, which is the limit documented above.
	SchedTimedOut SchedState = "timed_out"
	// SchedPanicked is a run whose function panicked. The panic was recovered by
	// the kernel, so it never reached the host process.
	SchedPanicked SchedState = "panicked"
	// SchedCancelled is a run the kernel asked to stop - handle closed, module
	// signalled, kernel reset - that did not return in time.
	SchedCancelled SchedState = "cancelled"
	// SchedPending is an armed timer that has not fired.
	SchedPending SchedState = "pending"
)

// ProcState is the lifecycle state of a process table record.
type ProcState string

const (
	// ProcRunning is a live context.
	ProcRunning ProcState = "running"
	// ProcTerminated is a context that ran and stopped.
	ProcTerminated ProcState = "terminated"
	// ProcRejected is a context the kernel refused to run, for example a module
	// whose manifest failed validation. It never becomes terminated: "the kernel
	// refused this" and "this ran and stopped" are different facts, and an audit
	// needs both.
	ProcRejected ProcState = "rejected"
)

// SecretAction names what the kernel should do with a custodied secret. The set is
// closed; an unknown action is refused rather than defaulted, because a default
// branch here would be a way to ask for "whatever returns the value".
type SecretAction string

const (
	// SecretActionSign returns an HMAC-SHA256 over the supplied data, keyed with
	// the secret. data must be non-empty.
	SecretActionSign SecretAction = "sign"
	// SecretActionMatch compares the supplied data against the secret in constant
	// time and returns only the verdict. data must be non-empty.
	SecretActionMatch SecretAction = "match"
	// SecretActionHeader seals the rendered header value into a handle owned by the
	// calling pid. data, when non-empty, is the destination host the value is bound
	// to; the binding is recorded so the network layer can refuse to send a
	// credential to a host it was not requested for.
	SecretActionHeader SecretAction = "header"
)

// PipeMode selects what a full buffer does.
type PipeMode int

const (
	// PipeBlocking makes a full write wait until space appears, the deadline
	// arrives, or the pipe closes. This is the mode a streaming response wants:
	// backpressure propagates to the producer instead of dropping its output.
	PipeBlocking PipeMode = iota
	// PipeNonBlocking makes a full write fail immediately with ErrPipeFull. This
	// is the mode a telemetry producer wants: losing a metric is better than
	// stalling a request.
	PipeNonBlocking
)

// TokenVerdict is the kernel's opinion about one reported quantity.
type TokenVerdict int

const (
	// TokenConsistent means the report is within tolerance of the measurement.
	TokenConsistent TokenVerdict = iota
	// TokenSuspicious means the report differs from the measurement by more than the
	// tolerance allows but is still arithmetically possible. It is a signal to look
	// at, not proof of anything.
	TokenSuspicious
	// TokenImpossible means the report cannot be produced by an honest tokenizer:
	// below the structural floor, above the absurd ceiling, or not positive.
	TokenImpossible
)

// KernelEventName identifies a kind of thing that can happen. The set is closed and
// declared here so a module cannot mint one.
type KernelEventName string

const (
	// EventPipeReadable fires when a pipe this module reads from has data or ended.
	EventPipeReadable KernelEventName = "pipe.readable"
	// EventPeerDisconnected fires when a peer module was unloaded or terminated.
	EventPeerDisconnected KernelEventName = "peer.disconnected"
	// EventDeadlinePassed fires when a registered deadline expired unmet.
	EventDeadlinePassed KernelEventName = "deadline.passed"
	// EventJobFinished fires when a supervised run reached a terminal state.
	EventJobFinished KernelEventName = "job.finished"
	// EventStreamAborted fires when a stream this module serves was cancelled.
	EventStreamAborted KernelEventName = "stream.aborted"
	// EventSignalDelivered fires when a signal arrived for this pid.
	EventSignalDelivered KernelEventName = "signal.delivered"
	// EventDraining fires when this pid entered drain.
	EventDraining KernelEventName = "draining"
	// EventConfigReloaded fires when the kernel published new configuration.
	EventConfigReloaded KernelEventName = "config.reloaded"
)

// VerifierPolicy is the load-time appraisal posture for module manifests.
//
// The set is closed. There is deliberately no auto mode as a selectable
// value: a posture that silently followed the key list at call time would let
// a change to that list move enforcement without anyone deciding to. The
// derivation from the trust root happens only when the host has chosen
// nothing, and VerifierPolicyExplicit reports which case is in force.
type VerifierPolicy string

const (
	// VerifierOff performs no appraisal. Every manifest is admitted, the
	// ledger is not written and nothing is audited, because off means the
	// operator asked for silence and a record of not checking is noise on the
	// chain.
	VerifierOff VerifierPolicy = "off"
	// VerifierAudit admits every manifest and records the outcome of every
	// appraisal on the audit chain and in the ledger, with a fault for each
	// signature that is absent or invalid. It is how an operator gathers the
	// evidence that enforce will not refuse a legitimate module before turning
	// enforce on.
	VerifierAudit VerifierPolicy = "audit"
	// VerifierEnforce refuses a module whose manifest has no valid signature
	// from a trusted cluster root key, before any module code runs.
	VerifierEnforce VerifierPolicy = "enforce"
)

// VerifierFindingCode names one class of advisory finding. The set is closed so a
// reviewer can enumerate it and so tooling matches on the class rather than on
// message text.
type VerifierFindingCode string

const (
	// VerifierFindingUnreachableOp: the manifest requests a scoped operation that
	// Validate passes through but no module domain holds, so every call would
	// be denied. Validate refuses this for unscoped operations and skips the
	// ceiling check for scoped ones, which is the gap this finding covers.
	VerifierFindingUnreachableOp VerifierFindingCode = "unreachable-op"
	// VerifierFindingDeadScope: a scope field is populated but the manifest does not
	// request the operation it bounds. The declaration never takes effect,
	// which means the manifest was edited without review or a request was
	// removed without removing its boundary.
	VerifierFindingDeadScope VerifierFindingCode = "dead-scope"
	// VerifierFindingMissingScope: a scoped operation is requested with no boundary
	// declared where Validate does not require one. The module loads and every
	// scoped call is then refused, which reads as a kernel bug rather than as
	// an incomplete declaration.
	VerifierFindingMissingScope VerifierFindingCode = "missing-scope"
	// VerifierFindingWeakScope: one declared scope subsumes another, so the broader entry
	// governs and the narrower one is decoration. None of these are invalid;
	// all of them are where a widened declaration hides.
	VerifierFindingWeakScope VerifierFindingCode = "weak-scope"
	// VerifierFindingPrivateHost: an allowed host is a numeric address in
	// loopback, private, link-local, multicast, unspecified or documentation
	// space. validateHost refuses loopback by name only, so a numeric 127.0.0.1
	// clears validation; this layer parses addresses, which validation does not.
	VerifierFindingPrivateHost VerifierFindingCode = "private-host"
	// VerifierFindingPathForm: a declared path does not survive cleaning unchanged, or
	// two spellings clean onto one grant. Both are legal; both are how a grant
	// reads narrower in review than it behaves.
	VerifierFindingPathForm VerifierFindingCode = "path-form"
	// VerifierFindingRouteForm: one declared serve route nests with another, so a
	// prefix-dispatching caller resolves one through the other. Routes are the
	// surface other modules call, and a shadow-prone declaration is a review
	// item even when it is valid.
	VerifierFindingRouteForm VerifierFindingCode = "route-form"
	// VerifierFindingListenForm: a listen address that does not parse as host:port, leaves
	// the port to the stack, or binds every interface. Validate requires only
	// that it be non-empty.
	VerifierFindingListenForm VerifierFindingCode = "listen-form"
	// VerifierFindingIdentityForm: an identity string carrying characters with special
	// meaning in the console, the audit log or the digest pipeline. Validate
	// bounds the name's separators and never reads the version, and a version
	// containing a newline writes a second log line when it is printed.
	VerifierFindingIdentityForm VerifierFindingCode = "identity-form"
)

// RequestID identifies one billable request. The kernel assigns it.
type RequestID string

// SHMID names a shared segment kernel-wide. It is a name, not a capability: a
// module that learns an id it was not granted gets nothing from it, because
// ShmMap checks the owner's grant table rather than the caller's knowledge. That
// is the difference from an FD, which is a capability inside its own pid's table.
// Ids increase monotonically from 1 and are never reused within a boot, so a stale
// id cannot address a live segment.
type SHMID int64

// TraceID identifies one request across every module that touched it.
type TraceID string

// SpanID identifies one stage inside a trace.
type SpanID string

// SlashID identifies one filed proof. It is the digest of the proof's canonical
// encoding, so two reporters filing identical evidence converge on one case rather than
// opening two.
type SlashID string
