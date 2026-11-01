package abi

import (
	"fmt"
	"time"
)

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

// PipeInfo describes an open pipe for the dump. It reports byte counts, never
// content, because a pipe carries prompts and completions.
type PipeInfo struct {
	FD       FD     `json:"fd"`
	Name     string `json:"name"`
	Owner    PID    `json:"owner"`
	Peer     PID    `json:"peer"`
	Cap      int    `json:"capacity"`
	Buffered int    `json:"buffered"`
	Queued   int    `json:"queued"`
	Written  int64  `json:"written"`
	Read     int64  `json:"read"`
	Dropped  int64  `json:"dropped"`
	Closed   bool   `json:"closed"`
	Aborted  bool   `json:"aborted"`
}

// QosDecision is the result of an admission attempt.
type QosDecision struct {
	// Admitted is whether the request may proceed.
	Admitted bool
	// RetryAfterMillis is how long the caller should wait before the bucket can
	// serve this request. Zero when admitted. It is computed from the deficit and
	// the refill rate, not guessed, so a client that honors it is not punished.
	RetryAfterMillis int64
	// Reason names the ceiling that refused, for logs and for the response body.
	Reason string
}

// SchedJob is one request for supervised execution.
type SchedJob struct {
	// Label names the run in the console, in the audit record and in a watchdog
	// event. It is a diagnostic string chosen by the module and is never
	// interpreted by the kernel, so it is length-bounded rather than trusted.
	Label string
	// TimeoutMillis bounds this run. Zero or negative means the sealed ceiling.
	// A value above the ceiling is clamped down: a module may ask for less time
	// than the trust root allows and may never ask for more, because a timeout
	// the timed-out party chooses is not a timeout.
	TimeoutMillis int64
	// Fn is the work. Nil is refused rather than scheduled.
	Fn SchedFunc
}

// SecretResult is what a module receives. No field of it is, or can be turned into,
// the credential.
type SecretResult struct {
	// Alias echoes the alias the request named, so a caller doing several uses in a
	// row can match results to requests.
	Alias string `json:"alias"`
	// Action echoes the action performed.
	Action SecretAction `json:"action"`
	// FD is a handle to the sealed header value, for SecretActionHeader only. It is
	// valid only inside this pid's table, and only the kernel can open it.
	FD FD `json:"fd,omitempty"`
	// Header names the header the sealed value belongs in, for SecretActionHeader
	// only. The name is not a secret; the value is.
	Header string `json:"header,omitempty"`
	// MAC is the keyed digest, for SecretActionSign only. It is omitted from JSON
	// because a rendered result belongs on the wire, not in a log line.
	MAC []byte `json:"-"`
	// Match is the comparison verdict, for SecretActionMatch only.
	Match bool `json:"match,omitempty"`
}

// SecretSpec describes one credential handed to the keyring. It is the only shape in
// which a secret enters the kernel, so every field a reviewer needs to see is named
// rather than inferred from a string.
type SecretSpec struct {
	// Alias names the credential. Modules ask for it by this name and never by
	// value. It must fall inside the prefixes the asking module declared.
	Alias string
	// Header is the HTTP header the credential belongs in, for example
	// "Authorization" or "x-api-key". Empty means "Authorization". The module does
	// not choose this: which header a credential goes into is part of the
	// credential's own definition, and letting a caller pick it would let a module
	// put a bearer token into a header an upstream logs.
	Header string
	// Scheme is prepended to the credential when rendering the header value, for
	// example "Bearer ". Empty renders the credential bare, which is what an
	// x-api-key style header requires.
	Scheme string
	// Value is the credential. The keyring copies it and then zeroes the caller's
	// slice, so ownership transfers on return. See InstallSecret.
	Value []byte
}

// ShmDescriptor describes an allocated segment to its owner. It carries no slice:
// the owner writes through ShmWrite and reads back through ShmRead.
type ShmDescriptor struct {
	// FD is the handle in the owner's own table. It is a capability: it resolves
	// only in that table, so it cannot be passed to another module to use.
	FD FD `json:"fd"`
	// ID names the segment kernel-wide. It is what a peer passes to ShmMap, and it
	// is not a capability on its own: the map still checks the owner's grant set.
	ID SHMID `json:"id"`
	// Size is the payload length the caller asked for, which may be smaller than
	// the slab class the pool reserved.
	Size int `json:"size"`
}

// ShmMapping describes a read-only mapping to the module that holds it.
type ShmMapping struct {
	// FD is the handle in the reader's own table.
	FD FD `json:"fd"`
	// ID is the segment the grant covered.
	ID SHMID `json:"id"`
	// Size is the payload length, so the reader can allocate a buffer before
	// copying without a second syscall.
	Size int `json:"size"`
	// Owner is the pid that allocated the segment. It is a diagnostic: knowing
	// who to blame for a payload is not a capability to read it.
	Owner PID `json:"owner"`
}

// Signature is a detached signature plus the metadata needed to select a
// verification key. The key id is a digest of the public key rather than the key,
// so a signature can be routed to the right root without carrying key material.
type Signature struct {
	// Algo is the signing algorithm. Only ed25519 is implemented.
	Algo string `json:"algo"`
	// KeyID identifies the verification key as a short digest of it.
	KeyID string `json:"key_id"`
	// Bytes is the raw signature.
	Bytes []byte `json:"bytes"`
}

// TimerSpec is one request for a deferred callback.
//
// Timers are single-shot on purpose. A periodic timer is a way to keep creating
// work forever from one declaration, and the reviewable artifact - the manifest -
// would say nothing about the rate. A module that needs a period re-arms from
// inside the callback, which puts every period through the same ceiling, the same
// quota and the same accounting as the first one.
type TimerSpec struct {
	// Label names the timer in diagnostics.
	Label string
	// DelayMillis is how long to wait before firing. The fire time is a mono()
	// reading, so a wall-clock step - NTP, an operator changing the date, a VM
	// migration - cannot move a timer armed here. The runtime timer underneath is
	// only the wakeup mechanism.
	DelayMillis int64
	// Fn runs under the same supervision as a spawned job: the caller's context,
	// the ceiling timeout, panic recovery, watchdog registration.
	Fn SchedFunc
}

// UsageFact is one usage event reported by a module.
type UsageFact struct {
	Kind     UsageKind `json:"kind"`
	Quantity int64     `json:"quantity"`
	// Label is an optional module-defined tag for the event, such as a model
	// name or a route. It is recorded for debugging and is never interpreted by
	// the kernel. Bounded so a module cannot use it to grow kernel memory.
	Label string `json:"label,omitempty"`
}

// PeerInfo is one row of the mesh table, for the dump and for an operator answering
// "which nodes does this one trust right now".
type PeerInfo struct {
	NodeID       string `json:"node_id"`
	KeyID        string `json:"key_id,omitempty"`
	Endpoint     string `json:"endpoint"`
	Label        string `json:"label,omitempty"`
	OpenedMono   int64  `json:"opened_mono"`
	LastRTTNanos int64  `json:"last_rtt_nanos"`
	Samples      int64  `json:"samples"`
	Timeouts     int64  `json:"timeouts"`
	Forwarded    int64  `json:"forwarded"`
	Refused      int64  `json:"refused"`
	Closed       bool   `json:"closed"`
}

// PeerLatency is one peer's measured responsiveness. Every field is a mono()
// reading or a count derived from one, and none of them is ever rendered as a human
// timestamp.
type PeerLatency struct {
	RTTNanos  int64 `json:"rtt_nanos"`
	EWMANanos int64 `json:"ewma_nanos"`
	Samples   int64 `json:"samples"`
	LastMono  int64 `json:"last_mono"`
	Timeouts  int64 `json:"timeouts"`
}

// PeerSession is the snapshot a dial returns. It carries no private material: no
// nonce, no signature, no key.
type PeerSession struct {
	FD           FD     `json:"fd"`
	NodeID       string `json:"node_id"`
	KeyID        string `json:"key_id"`
	Endpoint     string `json:"endpoint"`
	Label        string `json:"label,omitempty"`
	Seq          int64  `json:"seq"`
	LatencyNanos int64  `json:"latency_nanos"`
	OpenedMono   int64  `json:"opened_mono"`
}

// RouteHandler serves one path. It runs on the handler module's own goroutine and
// under the handler module's own context, which is the whole point of the design.
type RouteHandler func(ctx SContext, req RouteRequest) (RouteResponse, error)

// SchedFunc is work a module asks the kernel to run.
//
// The context handed to it is the caller's own, so the job inherits the caller's
// pid, uid, domain and manifest grants. Every syscall it makes is decided against
// the same ceiling as one made from OnLoad: moving work onto a kernel goroutine
// buys a deadline and attribution, and buys no privilege.
//
// done is closed when the run's deadline expires, when the module closes the
// handle, when the module is signalled to stop, or when the kernel resets. A
// well-behaved job selects on it and returns promptly. A job that ignores it is
// not stopped - see the file header - but the run is then recorded as timed out,
// kwatchdog captures its stack, and the module is put forward for termination.
type SchedFunc func(ctx SContext, done <-chan struct{})

// SchedOutcome is what the kernel recorded about one run. It is always a copy:
// handing out the live record would let a module rewrite the evidence of its own
// timeout.
type SchedOutcome struct {
	// ID is the kernel-allocated run id, unique within a boot.
	ID int64 `json:"id"`
	// Label is the module's own diagnostic string.
	Label string `json:"label,omitempty"`
	// Kind is "job" or "timer".
	Kind string `json:"kind"`
	// State is the terminal state, or SchedRunning / SchedPending while live.
	State SchedState `json:"state"`
	// Detail explains a non-completed state: the panic value, "deadline
	// expired", "handle closed", "module terminated".
	Detail string `json:"detail,omitempty"`
	// StartedAt and ElapsedNanos are mono() readings taken by the kernel around
	// the module's function, so a module cannot report a duration shorter than
	// the one it actually occupied.
	StartedAt    int64 `json:"started_at,omitempty"`
	ElapsedNanos int64 `json:"elapsed_nanos,omitempty"`
	// Deadline is the mono() value at which the run was required to stop.
	Deadline int64 `json:"deadline,omitempty"`
	// Stack is a snapshot of the offending goroutine when the run timed out, was
	// abandoned or panicked. It is empty on a clean completion.
	Stack string `json:"stack,omitempty"`
}

// SignalHandler is a module's own response to a signal. It runs supervised: under
// the module's context, inside the sealed call ceiling, with panics recovered and
// with kwatchdog registered. A handler that hangs is therefore reported and the
// module is still terminated, which is why a handler is not a way to survive a
// kill.
type SignalHandler func(info SignalInfo)

// SignalQueueError reports a signal refused because the target's pending queue is
// full. It is a distinct type so a caller can tell "the target is not keeping up"
// from "you are not permitted".
type SignalQueueError struct {
	Target PID
	Max    int
}

// TokenMeasurement is what the kernel computed about one byte slice. It holds no
// reference to the input, so a caller that reuses or mutates its buffer afterwards
// cannot change anything the kernel recorded.
type TokenMeasurement struct {
	// Bytes is the length of the measured input.
	Bytes int `json:"bytes"`
	// CodePoints is the number of UTF-8 code points, counting each invalid byte as
	// one. It is not a token estimate; it is the denominator the ratios work on.
	CodePoints int `json:"code_points"`
	// Estimate is the kernel's deterministic approximation. See tokenEstimateModel
	// for exactly how it is derived; it is integer arithmetic only, so it cannot
	// differ between platforms or runs.
	Estimate int64 `json:"estimate"`
	// Floor is the structural lower bound. A report below it is provably wrong for a
	// tokenizer whose pre-tokenizer does not merge across whitespace or across a
	// letter/digit/punctuation class change - which is what the GPT-2 family regex
	// does, and every major provider's tokenizer is in that family. SentencePiece
	// unigram models can merge across those boundaries in principle, so the floor is
	// conditional on the tokenizer family rather than universal, and TokenStrictFloor
	// exists to let a deployment say which assumption it is making.
	Floor int64 `json:"floor"`
	// Runs is the count of pre-tokenizer runs the floor is derived from, exposed so a
	// reader can check the arithmetic rather than take the number on faith.
	Runs int `json:"runs"`
	// Invalid is the number of bytes that were not valid UTF-8. A tokenizer still has
	// to emit something for them, and an input that is mostly invalid is a different
	// shape of input from prose, so the count is reported rather than folded in.
	Invalid int `json:"invalid"`
	// Whitespace is counted separately because it is not ratio'd: in this tokenizer
	// family it attaches to a neighbouring token rather than becoming one. Reporting it
	// is what lets a reader see why an input's estimate is lower than its byte count
	// suggests.
	Whitespace int `json:"whitespace"`
}

// TraceFilter selects spans to query.
type TraceFilter struct {
	// Trace narrows to one request. Empty means any.
	Trace TraceID
	// Kind narrows to one span kind. Empty means any.
	Kind SpanKind
	// PID narrows to one module. Zero means any.
	PID PID
	// Abandoned, when true, returns only spans the kernel closed at teardown. This
	// is the query that finds modules that leak work.
	Abandoned bool
	// MinNanos returns only spans at least this long, for finding slow stages.
	MinNanos int64
	// Limit caps the result, newest first.
	Limit int
}

// ProcSnapshot is an immutable copy of a process table row, safe to hand out.
// Callers get this rather than *ProcRecord so no one outside the table can
// mutate a live audit row.
type ProcSnapshot struct {
	PID            PID       `json:"pid"`
	UID            UID       `json:"uid"`
	Domain         Domain    `json:"domain"`
	Name           string    `json:"name"`
	PPID           PID       `json:"ppid"`
	Created        time.Time `json:"created"`
	Artifact       string    `json:"artifact,omitempty"`
	ManifestDigest string    `json:"manifest_digest,omitempty"`
	State          ProcState `json:"state"`
	Terminated     time.Time `json:"terminated,omitempty"`
}

// SignalInfo is what a handler receives. From and FromDomain are the sender as the
// kernel knows it, not as the sender describes itself.
type SignalInfo struct {
	// Kind is the signal.
	Kind SignalKind `json:"kind"`
	// From is the sender's pid.
	From PID `json:"from"`
	// FromDomain is the sender's domain.
	FromDomain Domain `json:"from_domain"`
	// SentAt is a mono() reading taken when the kernel accepted the signal.
	SentAt int64 `json:"sent_at"`
}

// SlashFilter selects ledger records. Zero values mean no constraint on that field.
type SlashFilter struct {
	Kind    SlashKind
	NodeID  string
	Verdict SlashVerdict
	// Since returns only records filed at or after this Mono() reading.
	Since int64
	Limit int
}

// SlashProof is one accusation. The reporter supplies the receipts and the kind of
// claim; everything else - whether the receipts verify, whether they actually
// contradict, who is accused - is recomputed by the kernel.
//
// That division is the control. A reporter that could set the verdict would be writing
// its own evidence, and a reporter that could name the accused node without supplying a
// receipt signed by it could accuse anyone.
type SlashProof struct {
	// Kind is the claim. It must be one of the closed set.
	Kind SlashKind `json:"kind"`
	// NodeID is the node being accused. Every receipt in the proof must carry this
	// node id, and every receipt's signature must verify, so the accusation cannot
	// be pointed at a node that signed nothing here.
	NodeID string `json:"node_id"`
	// Receipts are the evidence. At least one is required, and for equivocation
	// exactly two are compared.
	Receipts []Receipt `json:"receipts"`
	// Note is an optional operator-readable statement from the reporter. It is
	// length-bounded and line-break-free because it is copied into audit fields.
	Note string `json:"note,omitempty"`
}

// SlashRecord is one case in the ledger.
type SlashRecord struct {
	ID      SlashID      `json:"id"`
	Kind    SlashKind    `json:"kind"`
	NodeID  string       `json:"node_id"`
	Verdict SlashVerdict `json:"verdict"`
	// Reporters are the pids that filed this proof, in the order they arrived. It is
	// a list rather than a single pid because two independent reporters filing the
	// same evidence is materially stronger than one, and collapsing them would throw
	// that away.
	Reporters []PID `json:"reporters"`
	// FiledMono and DecidedMono are monotonic readings.
	FiledMono   int64 `json:"filed_mono"`
	DecidedMono int64 `json:"decided_mono,omitempty"`
	// Finding is the kernel's conclusion, present once decided.
	Finding SlashFinding `json:"finding"`
	// Note echoes the first reporter's note, for an operator reading the ledger.
	Note string `json:"note,omitempty"`
}

// TokenCheck is the result of comparing one report against one measurement. It is a
// value rather than an error because the comparison succeeding is the normal case and
// a disagreement is a finding, not a failure.
type TokenCheck struct {
	Measurement TokenMeasurement `json:"measurement"`
	Reported    int64            `json:"reported"`
	Verdict     TokenVerdict     `json:"verdict"`
	// Reason says which rule produced the verdict. It is populated for every verdict
	// including TokenConsistent, because "consistent" without a reason is a number a
	// reader has to re-derive to trust.
	Reason string `json:"reason"`
}

// TTYWindow is one bounded read of console history.
//
// Base and Dropped exist because `since` cannot be a stable cursor. Console retention is
// bounded and drops the oldest record, so an index into history shifts whenever the
// buffer trims. A caller that treated `since` as "resume from line N" would silently skip
// or repeat lines after a trim and never know. Base is the index the first returned
// record occupied, and Dropped is the console's total eviction count, so a caller can
// detect that records were lost between two reads rather than assuming continuity it does
// not have.
type TTYWindow struct {
	// Base is the index into the console's history at the time of this read that the
	// first record in Records occupied.
	Base int `json:"base"`
	// Records are copies of the console lines, oldest first.
	Records []Record `json:"records"`
	// Dropped is how many console records have been evicted in total.
	Dropped int64 `json:"dropped"`
}

// Record is one kernel console line. It is always emitted as a single JSON
// object so that faults stay greppable and machine-readable.
type Record struct {
	Time   time.Time      `json:"time"`
	Level  Level          `json:"level"`
	Pid    PID            `json:"pid"`
	Domain Domain         `json:"domain,omitempty"`
	Msg    string         `json:"msg"`
	Fields map[string]any `json:"fields,omitempty"`
}

// SlashFinding is what the kernel concluded. It is separate from the proof because the
// proof is the accusation and the finding is the decision, and conflating them is how a
// reporter's characterization ends up being read as a verdict.
type SlashFinding struct {
	// Kind echoes the claim that was decided.
	Kind SlashKind `json:"kind"`
	// Established is true when the recomputation confirmed the claim.
	Established bool `json:"established"`
	// Reason explains the conclusion either way. An unproven finding carries the
	// reason it failed, which is what tells an operator whether the accusation was
	// wrong or merely unsupported.
	Reason string `json:"reason"`
	// Digests names the receipts the decision rests on, so a dispute can be
	// re-examined without the original proof object.
	Digests []string `json:"digests,omitempty"`
	// MissingSeqs lists the sequence numbers a gap finding proved were issued. Empty
	// for every other kind.
	MissingSeqs []int64 `json:"missing_seqs,omitempty"`
}

// SlashVerdict is the state of one filed proof.
type SlashVerdict string

const (
	// SlashPending is a proof that has been filed and not yet decided.
	SlashPending SlashVerdict = "pending"
	// SlashConfirmed means the kernel recomputed the claim from the receipts and it
	// holds. This is the verdict an operator acts on.
	SlashConfirmed SlashVerdict = "confirmed"
	// SlashUnproven means the claim did not hold. It is NOT a statement that the
	// accused node is honest: the receipts may have been insufficient, or the
	// reporter may have mischaracterized them.
	SlashUnproven SlashVerdict = "unproven"
)

// SlashStats are the ledger counters.
//
// Refused is a single counter for every kind of refusal, on the same reasoning
// keyring.go gives for making an out-of-scope alias and an unknown alias
// indistinguishable: a reporter that could tell which of its proofs were rejected for
// shape and which for duplication could probe the ledger's contents.
type SlashStats struct {
	Pending   int   `json:"pending"`
	Confirmed int64 `json:"confirmed"`
	Unproven  int64 `json:"unproven"`
	Filed     int64 `json:"filed"`
	// Corroborated counts proofs a second reporter added itself to.
	Corroborated  int64 `json:"corroborated"`
	Refused       int64 `json:"refused"`
	Records       int   `json:"records"`
	RecordEvicted int64 `json:"record_evicted"`
	MaxRecords    int   `json:"max_records"`
}

// Error spells the refusal the way the kernel console does, so a message a module
// logs matches the one an operator greps for.
func (e *SignalQueueError) Error() string {
	return fmt.Sprintf("kernel: signal queue for pid %d is full (%d pending)", e.Target, e.Max)
}
