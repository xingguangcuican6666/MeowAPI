package abi

import "time"

// The data types a module passes to and from the kernel: the shapes of
// syscall arguments and results. They are here so a module can declare a
// handler or read a result without importing the kernel.

// AuditEntry is one link in the audit chain.
//
// The chain is the tamper-evidence mechanism. Each entry carries Prev, the hash
// of the entry before it, and Hash, the hash of itself including Prev. Rewriting
// or deleting any entry invalidates every hash after it, so an edit is detectable
// rather than invisible. This is what makes the record evidence instead of a log:
// a log can be edited, a chain cannot be edited without being noticed.
type AuditEntry struct {
	Seq    int64          `json:"seq"`
	Time   int64          `json:"time"`
	Kind   AuditKind      `json:"kind"`
	PID    PID            `json:"pid"`
	Domain Domain         `json:"domain,omitempty"`
	Msg    string         `json:"msg"`
	Trace  string         `json:"trace,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
	Prev   string         `json:"prev"`
	Hash   string         `json:"hash"`
}

// AuditFilter selects entries. Zero values mean "no constraint on this field".
type AuditFilter struct {
	Kind  AuditKind
	PID   PID
	Trace string
	Since int64
	Limit int
}

// BootConfigValue is one entry in the trust root.
type BootConfigValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// BootLimits are the resource ceilings the kernel enforces. They come from the
// trust root rather than from module configuration, because a quota a module could
// raise is not a quota.
type BootLimits struct {
	// MaxModules caps how many modules may be live at once.
	MaxModules int `json:"max_modules"`
	// MaxSlotsPerModule caps concurrent in-flight operations for one module.
	MaxSlotsPerModule int `json:"max_slots_per_module"`
	// MaxTotalSlots caps concurrency across the kernel.
	MaxTotalSlots int `json:"max_total_slots"`
	// MaxOpenFDsPerModule caps handles one module may hold at once.
	MaxOpenFDsPerModule int `json:"max_open_fds_per_module"`
	// MaxSharedBytes caps the shared buffer pool (kshm and kslab).
	MaxSharedBytes int64 `json:"max_shared_bytes"`
	// MaxKVBytesPerModule caps one module's namespaced state.
	MaxKVBytesPerModule int64 `json:"max_kv_bytes_per_module"`
	// CallTimeoutMillis bounds a single synchronous module call.
	CallTimeoutMillis int64 `json:"call_timeout_millis"`

	// The five fields below are koom's, and adding them widens the trust root, which is a
	// kboot change rather than a subsystem's. They are here rather than package constants for
	// a reason worth stating, because the distinction decides the question for the next
	// subsystem author too:
	//
	// A resource CEILING belongs in the sealed root. It is operator policy about how much of
	// the machine one tenant may take, it differs per deployment - a 512MiB container and a
	// 512GiB host need different numbers - and the comment above this struct gives the rule:
	// a quota a module could raise is not a quota. MaxKVBytesPerModule, MaxSharedBytes and
	// MaxOpenFDsPerModule are already here on exactly that basis, and
	// MaxAccountedBytesPerModule is the same class of number rather than a new one.
	//
	// A subsystem's own SHAPE does not. koom's ledger bound is a package constant
	// (maxOomHistory) the way kslashing's and kpeer's are, and its patrol interval is derived
	// from the sealed call ceiling the way watchdogInterval is. Neither is something an
	// operator should have to get right, and both would be a second knob for a decision
	// already made elsewhere.
	//
	// MaxAccountedBytesPerModule caps the memory the KERNEL handed one module: its
	// namespaced state, its reserved pipe capacity and the shared segments it owns. It is
	// a sum across three subsystems rather than a fourth ceiling on one of them, and the
	// combination is what it is for - a module inside every individual ceiling can still
	// exceed this by holding all three at once. What it cannot see is a module's own heap,
	// which no kernel accounting reaches; oom.go says so where it matters.
	MaxAccountedBytesPerModule int64 `json:"max_accounted_bytes_per_module"`
	// OomHostWarnBP and OomHostKillBP are the host-pressure thresholds in basis points,
	// measured against what the process has reserved from the OS. At warn the sweep records
	// and escalates; at kill it terminates. Two thresholds rather than one because the
	// useful response to a host at 80% is a record an operator can act on.
	OomHostWarnBP int `json:"oom_host_warn_bp"`
	OomHostKillBP int `json:"oom_host_kill_bp"`
	// OomMaxVictimsPerSweep bounds one sweep. A pressure response that terminates
	// everything eligible is not a response to pressure, it is a shutdown, and bounding it
	// lets the kernel try again next sweep if the first victim was not the cause.
	OomMaxVictimsPerSweep int `json:"oom_max_victims_per_sweep"`
}

// CPUStat is one pid's accounting, as an operator or a module sees it.
type CPUStat struct {
	PID       PID   `json:"pid"`
	WallNanos int64 `json:"wall_nanos"`
	// CPUNanos is an estimate derived from wall time and observed concurrency, not
	// a hardware counter. It is labeled as an estimate in every surface that shows
	// it, because a number presented as precise will be trusted as precise.
	CPUNanos  int64 `json:"cpu_nanos_estimate"`
	Calls     int64 `json:"calls"`
	Budget    int64 `json:"budget_nanos"`
	Exhausted bool  `json:"exhausted"`
}

// Event is one delivered notification.
type Event struct {
	// Name is from the closed kernel set.
	Name KernelEventName `json:"name"`
	// Seq is monotonic within one subscription, so a consumer can detect a gap and
	// know it missed something rather than assuming nothing happened.
	Seq int64 `json:"seq"`
	// At is the Mono() reading when the event was posted.
	At int64 `json:"at"`
	// Subject is the pid the event is about: the peer that disconnected, the job
	// that finished. Zero when the event is about the subscriber itself.
	Subject PID `json:"subject,omitempty"`
	// Detail carries a small kernel-chosen string, for example a pipe name. It is
	// never module-supplied content, so it cannot be used to smuggle a payload
	// through the event path.
	Detail string `json:"detail,omitempty"`
}

// FDInfo describes an open handle, for the console dump and diagnostics.
type FDInfo struct {
	FD       FD     `json:"fd"`
	Kind     string `json:"kind"`
	Label    string `json:"label,omitempty"`
	OpenedAt int64  `json:"opened_at"`
}

// FSInfo is what FSStat reports: the two facts a module needs and no more. It
// deliberately omits timestamps and permissions, which a module has no use for and
// which would render host-side details the boundary was meant to keep out.
type FSInfo struct {
	Size  int64 `json:"size"`
	IsDir bool  `json:"is_dir"`
}

// Identity is what a context can report about itself. Every field is set by the
// kernel at spawn time; none of it is chosen by the module.
type Identity interface {
	// PID returns the context's process id.
	PID() PID
	// UID returns the context's kernel-allocated owner id.
	UID() UID
	// Domain returns the context's security domain.
	Domain() Domain
	// Name returns the module name this context was spawned for, or "init" and
	// "kernel" for the two kernel-owned contexts. It is a diagnostic label
	// chosen by the kernel, never by the module.
	Name() string
}

// KernelTime is what a module gets from SyscallNow. Mono is the value to compute
// with; Wall is the value to print.
type KernelTime struct {
	// Mono is nanoseconds on the kernel's monotonic clock. Non-negative,
	// non-decreasing, and not forgeable.
	Mono int64 `json:"mono"`
	// Wall is UTC wall-clock time, for records a human reads. Never use it to
	// measure an interval: it can step backwards.
	Wall time.Time `json:"wall"`
}

// MeterFilter selects retained records to query.
type MeterFilter struct {
	// Route narrows to one path. Empty means any.
	Route string
	// PID narrows to the module that served the request. Zero means any.
	PID PID
	// Caller narrows to the module that asked. Zero means any.
	Caller PID
	// Trace narrows to one request's trace.
	Trace TraceID
	// Abandoned returns only records the kernel closed at teardown.
	Abandoned bool
	// Since returns only records opened at or after this Mono() reading.
	Since int64
	// Limit caps the result, newest first.
	Limit int
}

// MeterRecord is one request's facts. Every field is an observation.
type MeterRecord struct {
	// ID is kernel-assigned and unguessable.
	ID RequestID `json:"id"`
	// Trace links the request to its spans in ktrace. Like RouteRequest.Trace it is
	// a correlation id the caller may propagate, and it carries no authority: the
	// pid that served the request and the pid that asked are both kernel-assigned,
	// so the ledger cannot be misattributed by choosing a label.
	Trace TraceID `json:"trace,omitempty"`
	// Route is the path that served it, when the request came through kservice.
	Route string `json:"route,omitempty"`
	// PID is the module that served it, kernel-assigned.
	PID PID `json:"pid"`
	// Module is that module's name, for logs.
	Module string `json:"module,omitempty"`
	// Caller is the module that asked, when the call crossed a route.
	//
	// It identifies a local context, not an originating party. A request forwarded
	// in from another mesh node is dispatched by kpeer under init's context, so
	// Caller reads as init's pid. Nothing about a MeterRecord says whether the work
	// was local or inbound, and that is deliberate rather than an oversight: adding
	// an origin field would let a module attribute its own traffic to somewhere
	// else, and a field a module can influence is not evidence. The distinction
	// lives on the audit chain, where kpeer records "peer forward accepted" with
	// the sending node's id before dispatch, so an investigator can join the two by
	// trace id. Code that reads Caller as "the module that decided to make this
	// request" is wrong for inbound traffic and should join on the chain instead.
	Caller PID `json:"caller,omitempty"`
	// Opened and Closed are Mono() readings. The interval is measured on the
	// kernel clock so an NTP step cannot change a billable duration.
	Opened int64 `json:"opened"`
	Closed int64 `json:"closed,omitempty"`
	// Tokens and Requests are the usage facts recorded against this request. They
	// are the same closed kinds usage.go enforces, so a meter record cannot carry a
	// quantity the kernel refused to count.
	TokensIn  int64 `json:"tokens_in,omitempty"`
	TokensOut int64 `json:"tokens_out,omitempty"`
	Requests  int64 `json:"requests,omitempty"`
	// Status is the handler's own result code, recorded as reported. The kernel
	// does not interpret it.
	Status int `json:"status,omitempty"`
	// Abandoned marks a request the kernel closed at module teardown because the
	// module never closed it. Its duration is a lower bound, and saying so is what
	// keeps the number honest.
	Abandoned bool `json:"abandoned,omitempty"`
	// Settled marks a record whose facts were handed to a settlement receipt, so a
	// second settlement of the same request is visible.
	Settled bool `json:"settled,omitempty"`
}

// NetDialResult is what a successful dial reports. The Address field is the point: it is
// the address that was validated and dialed, so an operator reading the audit record can
// see that the name resolved somewhere permitted rather than take the name's word for it.
type NetDialResult struct {
	FD      FD     `json:"fd"`
	Host    string `json:"host"`
	Address string `json:"address"`
	RTT     int64  `json:"rtt_nanos"`
	Pooled  bool   `json:"pooled"`
}

// NetInfo describes one open socket, for a snapshot.
type NetInfo struct {
	FD       FD     `json:"fd"`
	PID      PID    `json:"pid"`
	Remote   string `json:"remote"`
	Label    string `json:"label,omitempty"`
	Pooled   bool   `json:"pooled"`
	OpenedAt int64  `json:"opened_at"`
	RTT      int64  `json:"rtt_nanos"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// NetSpec is one dial request. Host and Port are what the module names; Address is what
// the kernel fills in after resolution and validation, and it is the address that gets
// dialed.
type NetSpec struct {
	// Host is the hostname to dial. It must appear in the module's AllowedHosts.
	Host string `json:"host"`
	// Port is the TCP port. Zero means the scheme's default, which is a decision the
	// kernel makes rather than the caller, so a module cannot dial an arbitrary port by
	// omitting one.
	Port int `json:"port"`
	// Scheme is "tcp" or "tcp4"/"tcp6". Anything else is refused: this subsystem does
	// not dial UDP or unix sockets, and a scheme the caller chooses freely is a scheme
	// the allowlist was never reviewed against.
	Scheme string `json:"scheme"`
	// Label is an operator-visible description. Bounded, and never interpreted.
	Label string `json:"label,omitempty"`
}

// PeerAnnouncement is one signed discovery record. Announcements must be signed by a
// cluster root: an unsigned announcement is a route hijack, and whoever can reach
// the transport could then poison the peer table.
type PeerAnnouncement struct {
	Version  int    `json:"version"`
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"`
	KeyID    string `json:"key_id"`
	// Seq is per-announcer and gap-free, so a suppressed announcement is visible
	// as a gap rather than as silence.
	Seq int64 `json:"seq"`
	// Epoch is the announcer's boot identity. Without it a peer that restarts and
	// begins numbering from 1 again is indistinguishable from one replaying a
	// captured announcement, and the honest peer is refused forever. See
	// peerAcceptSeq for the rule and its stated limit.
	Epoch int64 `json:"epoch,omitempty"`
	// TTLNanos is converted to mono()+ttl at ingest and never compared against a
	// wall clock.
	TTLNanos  int64  `json:"ttl_nanos"`
	Signature []byte `json:"signature"`
}

// PeerDialSpec is what a dial asks for.
type PeerDialSpec struct {
	// Endpoint is the address the host transport understands. It is compared
	// against the endpoint inside the peer's signed handshake.
	Endpoint string `json:"endpoint"`
	// TimeoutMillis is clamped by sched.go's callCeiling, so a dial cannot outlast
	// the sealed call timeout. A timeout the timed-out party chooses is not a
	// timeout.
	TimeoutMillis int64 `json:"timeout_millis,omitempty"`
	// Label is an operator-chosen diagnostic name, length-bounded because it is
	// stored in the table and copied into audit lines.
	Label string `json:"label,omitempty"`
}

// PeerForwardRequest is one outbound cross-node call.
type PeerForwardRequest struct {
	NodeID        string  `json:"node_id"`
	Route         string  `json:"route"`
	Method        string  `json:"method,omitempty"`
	Trace         TraceID `json:"trace,omitempty"`
	Payload       []byte  `json:"payload,omitempty"`
	Hops          int64   `json:"hops,omitempty"`
	TimeoutMillis int64   `json:"timeout_millis,omitempty"`
}

// PeerForwardResult is the peer's reply. The payload was bounded at ingress, so a
// reply too large to accept is refused rather than truncated.
type PeerForwardResult struct {
	Status   int               `json:"status"`
	Payload  []byte            `json:"payload,omitempty"`
	Header   map[string]string `json:"header,omitempty"`
	RTTNanos int64             `json:"rtt_nanos"`
	Trace    TraceID           `json:"trace,omitempty"`
}

// Receipt is one signed settlement record. Every field except Signature is covered
// by the signature through the canonical encoding, and every field is set by the
// kernel: the node id and the sequence number come from the sealed trust root and
// the ledger, the elapsed time from mono(), and the two content hashes are computed
// by the kernel unless the issuer supplies a precomputed digest.
//
// A receipt is public data. It is meant to leave the node, to be handed to a client
// and to be compared against a peer's copy by kslashing, so nothing here is secret
// and there is no path by which verifying one discloses key material.
type Receipt struct {
	// Version is the canonical encoding version.
	Version int `json:"version"`
	// NodeID is the issuing node, from the sealed trust root. It is inside the
	// signature, so a receipt cannot be replayed as another node's.
	NodeID string `json:"node_id"`
	// Seq is the per-node sequence number: monotonic, gap-free, starting at 1.
	Seq int64 `json:"seq"`
	// Trace is the request trace id, if the issuer supplied one. It links the
	// receipt to the audit entries for the same request.
	Trace string `json:"trace,omitempty"`
	// Route is a label for the model or route that served the request.
	Route string `json:"route,omitempty"`
	// PID is the module whose work this settles.
	PID PID `json:"pid"`
	// PromptHash and CompletionHash are sha256 hex digests of the request and the
	// response. They are what two nodes compare to agree that they served the same
	// content, so a peer that truncated a completion is caught by the digest and
	// not by a length check.
	PromptHash     string `json:"prompt_hash"`
	CompletionHash string `json:"completion_hash"`
	// TokensIn and TokensOut are the settled token counts.
	TokensIn  int64 `json:"tokens_in"`
	TokensOut int64 `json:"tokens_out"`
	// ElapsedNanos is the service time measured on the kernel's monotonic clock.
	// A wall clock is not used: it can step backwards, and a settlement record
	// with a negative duration is a record nobody can reason about.
	ElapsedNanos int64 `json:"elapsed_nanos"`
	// IssuedMono is the monotonic reading at issue time, so a receipt can be
	// ordered against the audit chain, which is stamped the same way.
	IssuedMono int64 `json:"issued_mono"`
	// IssuedWall is the wall-clock issue time in Unix nanoseconds, for humans and
	// for cross-node comparisons where monotonic readings are meaningless.
	IssuedWall int64 `json:"issued_wall"`
	// KeyID identifies the signing key as a short digest of its public half, so a
	// verifier can select a cluster root without being told which one.
	KeyID string `json:"key_id"`
	// Signature is the ed25519 signature over the canonical payload.
	Signature []byte `json:"signature"`
}

// ReceiptSpec is what an issuer supplies. The fields the kernel owns - node id,
// sequence number, key id, issue timestamps - are absent on purpose: an issuer that
// could choose them could choose someone else's node id or a sequence number that
// hides a gap.
type ReceiptSpec struct {
	// PID is the module whose work this settles. Zero means the calling context's
	// own pid.
	PID PID
	// Trace and Route are labels. Both are length-bounded because they are stored
	// in every receipt the node keeps a copy of.
	Trace string
	Route string
	// Prompt and Completion are the content the hashes are computed from. They may
	// be empty, for example when the issuer already holds digests.
	Prompt     []byte
	Completion []byte
	// PromptHash and CompletionHash, when set, are used verbatim instead of being
	// computed from the byte slices above. They must be 64 lowercase hex
	// characters. This exists for a streamed completion, where the issuer digested
	// each chunk as it arrived and no longer holds the whole body; supplying them
	// is the issuer's claim, and it is inside the signature either way.
	PromptHash     string
	CompletionHash string
	// TokensIn and TokensOut are the counts to settle. They are cross-checked
	// against the kernel's own accounting: see validateTokens.
	TokensIn  int64
	TokensOut int64
	// StartedMono is a mono() reading taken when the work began. Zero means the
	// work is being settled at issue time, so the elapsed time is zero. When Request
	// names a kmeter record, that record's own measurement wins.
	StartedMono int64
	// Request optionally names the kmeter request being settled. When it is set, the
	// token counts and the elapsed time come from the kernel's own meter record for
	// that request rather than from the issuer's claim, and the record must belong to
	// the pid being settled. This is the strongest form of the cross-check: there is
	// nothing for the issuer to claim.
	Request RequestID
}

// ReceiptVerdict is the outcome of a verification. It is a struct rather than a bool
// because a false verdict has reasons, and a fraud proof needs the reason and not
// only the conclusion.
type ReceiptVerdict struct {
	// Valid is true only when the structure is acceptable and the signature
	// verifies against a sealed cluster root.
	Valid bool `json:"valid"`
	// Digest is the receipt's canonical digest, present whether or not it
	// verified, so a refused receipt can still be named in a dispute.
	Digest string `json:"digest"`
	// KeyID is the cluster root that matched, or empty when none did.
	KeyID string `json:"key_id,omitempty"`
	// Reason explains a refusal. It is empty on a valid receipt.
	Reason string `json:"reason,omitempty"`
	// Structural is true when the receipt was rejected for its shape rather than
	// for its signature. A structural failure is a protocol or version mismatch;
	// a signature failure with a well-formed receipt is what a fraud proof claims.
	Structural bool `json:"structural,omitempty"`
}

// RouteRequest is one inbound call. The payload crosses as bytes, never as a Go
// value, so a caller cannot hand a handler a live reference into its own heap.
type RouteRequest struct {
	// Path is the normalized route that was matched.
	Path string `json:"path"`
	// CallerPID is who asked. It is kernel-assigned and cannot be forged, so a
	// handler may make a decision based on it.
	CallerPID PID `json:"caller_pid"`
	// CallerModule is the caller's registered name, for logs.
	CallerModule string `json:"caller_module,omitempty"`
	// Trace is a correlation id. The caller may propagate one it was given, which
	// is how a trace crosses a module boundary at all: without it the caller's span
	// tree and the handler's could never be joined. It carries no authority. Every
	// field in the audit record that identifies who did what - CallerPID, the
	// handler's pid - is kernel-assigned, so a caller that invents a trace id
	// mislabels its own correlation and cannot attribute anything to anyone else.
	// A fresh span opened by the handler gets its id from ktrace, not from here.
	Trace TraceID `json:"trace,omitempty"`
	// Method is a verb the caller chose, for a REST-shaped surface. It is not
	// part of the route key: two modules cannot serve the same path with different
	// methods, because that would make the table's uniqueness rule a lie.
	Method string `json:"method,omitempty"`
	// Payload is a copy of the caller's bytes.
	Payload []byte `json:"payload,omitempty"`
}

// RouteResponse is one outbound reply.
type RouteResponse struct {
	// Status is the handler's own code. The kernel does not interpret it.
	Status int `json:"status"`
	// Payload is copied out to the caller, so the handler may reuse its buffer.
	Payload []byte `json:"payload,omitempty"`
	// Header carries small string pairs, for a provider-shaped response.
	Header map[string]string `json:"header,omitempty"`
}

// Span is one finished or live interval. It is a value type: a module gets a copy
// and cannot reach the kernel's record through it.
type Span struct {
	Trace  TraceID  `json:"trace"`
	Span   SpanID   `json:"span"`
	Parent SpanID   `json:"parent,omitempty"`
	Kind   SpanKind `json:"kind"`
	Name   string   `json:"name"`
	PID    PID      `json:"pid"`
	Module string   `json:"module,omitempty"`
	Start  int64    `json:"start"`
	End    int64    `json:"end,omitempty"`
	// Abandoned is set when the kernel closed the span during unload because the
	// module never ended it. An abandoned span's duration is a lower bound on the
	// real one, and marking it is what keeps that number honest.
	Abandoned bool `json:"abandoned,omitempty"`
	// Attrs are kernel-recorded facts about the span, never module-supplied
	// content, so a module cannot smuggle a payload through the trace.
	Attrs map[string]string `json:"attrs,omitempty"`
}

// SpanSpec describes a span to open.
//
// There is deliberately no Trace field. A module cannot name the trace it belongs
// to, because a module-chosen id is a module-chosen identity for a request: it could
// collide with another request's timeline, corrupting both, or be chosen to attach
// this module's work to a request it never served. The id comes from one of two
// places and both are the kernel: a fresh span from crypto/rand, a child span
// inherited from the parent the kernel already resolved. Propagation across a module
// boundary is therefore through Parent, which is checked against the process table,
// rather than through a string the caller controls.
type SpanSpec struct {
	// Parent is the enclosing span, empty for a root span. It must be a span this
	// pid can see, so a module cannot attach its work to another module's timeline
	// and inherit that module's attribution.
	Parent SpanID
	Kind   SpanKind
	Name   string
}
