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

// kpeer: the node-exchange layer (subsystem: kpeer, the analogue of BGP for
// reachability plus WireGuard for identity, with neither one's sockets).
//
// SYSCALL WIRING FOR THE INTEGRATOR.
//
// The exported functions below are the implementation; paste this block into
// kernel/context.go to expose them as syscalls.
//
// 1. Add the group to the SContext interface's group list, next to SyscallRoute:
//
//	SyscallPeer
//
// 2. Add the group interface and the methods:
//
//	// SyscallPeer is the mesh half of the syscall surface. Key material does not
//	// cross it in either direction, and no method here accepts a frame from a
//	// caller: inbound frames arrive only through the host handle.
//	type SyscallPeer interface {
//	    // SyscallPeerDial proves a peer's identity and opens a session handle.
//	    // Requires peer:dial, which only the kernel domain holds.
//	    SyscallPeerDial(spec PeerDialSpec) (PeerSession, error)
//	    // SyscallPeerAnnounce publishes one signed discovery record. Requires
//	    // peer:announce.
//	    SyscallPeerAnnounce(a PeerAnnouncement) error
//	    // SyscallPeerProbe measures one round trip on the monotonic clock.
//	    // Requires peer:dial.
//	    SyscallPeerProbe(fd FD, deadline int64) (PeerLatency, error)
//	    // SyscallPeerForward sends one request to a peer node and returns its
//	    // reply. Requires peer:dial.
//	    SyscallPeerForward(req PeerForwardRequest) (PeerForwardResult, error)
//	    // SyscallPeerPeers lists the mesh table. Requires peer:dial.
//	    SyscallPeerPeers() ([]PeerInfo, error)
//	}
//
//	func (c *sContext) SyscallPeerDial(spec PeerDialSpec) (PeerSession, error) {
//	    return PeerDial(c, spec)
//	}
//	func (c *sContext) SyscallPeerAnnounce(a PeerAnnouncement) error { return PeerAnnounce(c, a) }
//	func (c *sContext) SyscallPeerProbe(fd FD, deadline int64) (PeerLatency, error) {
//	    return PeerProbe(c, fd, deadline)
//	}
//	func (c *sContext) SyscallPeerForward(req PeerForwardRequest) (PeerForwardResult, error) {
//	    return PeerForward(c, req)
//	}
//	func (c *sContext) SyscallPeerPeers() ([]PeerInfo, error) { return PeerPeers(c) }
//
// 3. Add resetPeers() to resetKernel() in kernel/kernel.go, in the "Channels and
//    coordination" block immediately after resetRoutes(): a peer session holds a
//    handle in the fd table and a route dispatch may have been forwarded through
//    it, so the mesh is torn down with the other coordination state and before
//    resetFDTables() drops the handles it references.
//
// 4. Optional, and dump.go is the integrator's call: a "--- peers ---" section
//    reading PeerTableSnapshot() and PeerStatsSnapshot(), modelled on the routes
//    and secrets sections. Both are read-only and grant no privilege.
//
// POLICY NOTE the integrator must read before wiring peer:dial to any live domain.
//
// kernel/policy.go grants peer:dial and peer:announce to the kernel domain alone.
// DomainInit holds neither - its row says egress belongs to the network subsystem
// acting for a module under that module's manifest, not to the boot sequence - and
// DomainPlugin holds neither. boot.go retires the pid 0 root context the instant
// init exists, so after boot no live context can pass the prologue for either op.
//
// Both syscalls exist anyway and both run the full prologue, because the op is the
// named gate and widening it must be a policy change rather than a code change. The
// reachable path is the host handle, mirroring Kernel.IssueReceipt and
// Kernel.InstallSecret: Kernel.PeerSetTransport, Kernel.PeerDial, Kernel.PeerProbe,
// Kernel.PeerForward, Kernel.PeerPeers and Kernel.PeerDeliver. They perform no
// policy check because no live context could pass one, and they add no capability
// the host did not already have - the host supplied BootTrustRoot.SigningKeyPEM and
// ClusterRootKeys, so it holds both halves of the mesh's trust outright.
//
// If the owner wants a module to help discovery, the change is to add
// OpPeerAnnounce to the DomainPlugin row of kernel/policy.go. That is a trust-root
// change needing owner approval. It is reported here rather than made.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The guarantee this file provides is that every fact about another node in this
// kernel's mesh was proved by a signature that verifies against the sealed cluster
// roots, and every measurement of another node was taken on the kernel's monotonic
// clock. A node id in the peer table is not a claim a transport made; it is a claim
// a key signed and this node checked. A latency in the peer table is not a
// wall-clock difference, so an NTP step, an operator changing the date or a VM
// migration cannot make a probe lie, cannot age an announcement out early, and
// cannot make a dead peer look alive.
//
// Cross-node forwarding preserves service.go's boundary. A request arriving from
// another node is dispatched into the local route table under a context this kernel
// allocated, and the handler still runs under its own grants, so a remote caller
// cannot borrow the authority of whoever accepted its frame.
//
// What this is not. It is not a transport and it is not a confidentiality boundary.
// kpeer performs no socket I/O: the host injects a PeerTransport, and kpeer owns
// identity, sequencing, latency, ceilings and evidence. A handshake proves who is on
// the other end; it does not encrypt what crosses. A deployment needing secrecy gets
// it from the transport, and describing kpeer as providing it would describe a
// boundary that does not exist.
//
// It is also not a liveness oracle. An honest peer that is partitioned is
// indistinguishable from a dead one, and this file reports both as a failed probe
// rather than guessing. And it is not an address-space control: a module that dials
// a peer itself with net.Dial never comes through here, which is a review and
// signing concern, exactly as keyring.go and kv.go state for their own limits.
//
// The honest limit on timeouts: a transport that ignores its deadline holds one
// inflight slot until it returns. The kernel times every wait itself and returns
// ErrPeerTimeout to the caller at the deadline, but it cannot abort host code, so
// what the bound actually guarantees is that a wedged transport saturates
// maxPeerInflightPerPeer and then refuses further calls rather than growing without
// limit.

// PeerVersion is the encoding version this kernel issues and accepts. A frame from
// another version is refused rather than reinterpreted, because the meaning of a
// field is part of what the signature covers: a verifier that guessed at an unknown
// layout would be signing off on a record it did not read.
const PeerVersion = 1

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

// PeerFrameKinds lists the frame kinds the kernel accepts, sorted.
func PeerFrameKinds() []PeerFrameKind {
	out := []PeerFrameKind{
		PeerFrameHandshake, PeerFrameHandshakeReply, PeerFrameProbe, PeerFrameProbeReply,
		PeerFrameAnnounce, PeerFrameForward, PeerFrameForwardReply, PeerFrameGoodbye,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func knownPeerFrameKind(k PeerFrameKind) bool {
	for _, want := range PeerFrameKinds() {
		if k == want {
			return true
		}
	}
	return false
}

// PeerFrame is one unit of exchange with a peer. Body is opaque JSON the kernel
// built; the kernel never hands a module a live slice of it, and at ingress the body
// is bounded before it is decoded.
type PeerFrame struct {
	Kind PeerFrameKind `json:"kind"`
	// Seq is kernel-assigned per session and monotonic, so a peer can detect a gap
	// and know it missed a frame rather than assuming nothing happened.
	Seq  int64  `json:"seq"`
	Body []byte `json:"body,omitempty"`
}

// PeerTransport is the host's byte mover. kpeer does no I/O, so the host supplies
// this and kpeer owns everything above it: identity, sequencing, latency, ceilings
// and evidence.
//
// The contract the host must honour, stated because kpeer cannot enforce any of it:
// respect the absolute mono() deadline, do not retain the frame slice past the call,
// and do not panic. Every call is recovered and independently timed by the kernel,
// because that code is the host's and a panicking transport must not take the kernel
// down.
type PeerTransport interface {
	// Send delivers one frame without waiting for a reply.
	Send(endpoint string, frame PeerFrame, deadline int64) error
	// Exchange delivers one frame and returns the reply.
	Exchange(endpoint string, frame PeerFrame, deadline int64) (PeerFrame, error)
}

// PeerHandshake is one signed identity claim. Both nonces are inside the signature,
// which is the whole of the replay resistance: a captured handshake replayed later
// carries a nonce this node already saw.
type PeerHandshake struct {
	// Version is refused when it is not PeerVersion.
	Version int `json:"version"`
	// NodeID is the claimed identity, from the peer's own sealed trust root.
	NodeID string `json:"node_id"`
	// KeyID is a short ed25519 key digest, a selector for which cluster root to
	// try rather than key material.
	KeyID string `json:"key_id"`
	// Initiator is the node id that minted NonceA, so the two legs of a handshake
	// cannot be crossed.
	Initiator string `json:"initiator"`
	// NonceA and NonceB are 32 random bytes each, both signed.
	NonceA []byte `json:"nonce_a"`
	NonceB []byte `json:"nonce_b"`
	// Endpoint is where the peer is reachable. It is inside the signature AND
	// compared against the endpoint this node dialed, because a signature over a
	// field nobody checks binds nothing.
	Endpoint string `json:"endpoint"`
	// Epoch is the announcer's boot identity, so a peer that restarted is
	// distinguishable from a peer replaying an old claim. It is inside the
	// signature: an epoch a peer could rewrite would let it reset the sequence
	// baseline at will, which is the whole control the field exists to support.
	Epoch int64 `json:"epoch,omitempty"`
	// WallNanos is diagnostic only and deliberately not signed. Replay resistance
	// comes from the nonces; a signed wall clock is a claim this node cannot
	// verify and would only ever be used to argue about skew.
	WallNanos int64 `json:"wall_nanos,omitempty"`
	// Signature is the ed25519 signature over the canonical payload.
	Signature []byte `json:"signature"`
}

// PeerVerdict is the outcome of verifying a peer's claim. It is a struct rather than
// a bool because a false verdict has reasons, and kslashing needs the reason and not
// only the conclusion.
type PeerVerdict struct {
	// Trusted is true only when the shape is acceptable and the signature verifies
	// against a sealed cluster root.
	Trusted bool `json:"trusted"`
	// NodeID and KeyID echo what was claimed, present whether or not it verified,
	// so a refused claim can still be named in a dispute.
	NodeID string `json:"node_id"`
	KeyID  string `json:"key_id,omitempty"`
	// Reason explains a refusal. Empty on a trusted verdict.
	Reason string `json:"reason,omitempty"`
	// Structural is true when the claim was rejected for its shape rather than for
	// its signature. A structural failure is a protocol or version mismatch; a
	// signature failure on a well-formed claim is the only class that is evidence
	// of dishonesty.
	Structural bool `json:"structural,omitempty"`
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

// peerProbeBody is one probe frame's payload. It is package-private because nothing
// outside this kernel needs to construct one, and it is a struct rather than a map so
// the wire shape is named and reviewable.
type peerProbeBody struct {
	Version int    `json:"version"`
	NodeID  string `json:"node_id"`
	Seq     int64  `json:"seq"`
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

// PeerEnvelope is the cross-node envelope.
//
// PayloadHash is what the signature covers, not Payload. Signing the digest rather
// than the body is forced rather than chosen: verifyAgainstClusterRoots refuses an
// input above maxCryptoInputBytes (1 MiB) while a forwarded payload may legally be
// maxCallPayloadBytes (8 MiB), so signing the whole envelope would fail at the crypto
// ceiling for any payload over 1 MiB. The digest binds the payload just as firmly and
// stays inside the ceiling.
type PeerEnvelope struct {
	Version     int    `json:"version"`
	FromNode    string `json:"from_node"`
	ToNode      string `json:"to_node"`
	Route       string `json:"route"`
	Method      string `json:"method,omitempty"`
	Trace       string `json:"trace,omitempty"`
	Hops        int64  `json:"hops"`
	Seq         int64  `json:"seq"`
	KeyID       string `json:"key_id"`
	PayloadHash string `json:"payload_hash"`
	Payload     []byte `json:"payload,omitempty"`
	Signature   []byte `json:"signature"`
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

// PeerEvent is one entry in the mesh event ledger. The ledger exists because
// successful probes deliberately write no audit record - at one probe per second
// over a full mesh a per-probe record would evict the real evidence out of the
// in-memory window - so the samples have to live somewhere an operator can read.
type PeerEvent struct {
	Kind   string `json:"kind"`
	NodeID string `json:"node_id"`
	Seq    int64  `json:"seq"`
	Mono   int64  `json:"mono"`
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

// PeerStats are the mesh counters. MaxPeers is reported so an operator reading the
// dump can tell whether a refusal means the mesh is too big or the bound is too
// small, which is why EventStats reports its bound the same way.
type PeerStats struct {
	Peers          int   `json:"peers"`
	Announced      int64 `json:"announced"`
	Accepted       int64 `json:"accepted"`
	Refused        int64 `json:"refused"`
	Probes         int64 `json:"probes"`
	ProbeTimeouts  int64 `json:"probe_timeouts"`
	Forwarded      int64 `json:"forwarded"`
	ForwardRefused int64 `json:"forward_refused"`
	Events         int   `json:"events"`
	EventEvicted   int64 `json:"event_evicted"`
	MaxPeers       int   `json:"max_peers"`
}

// PeerError reports a refused mesh operation. It is a distinct type so a caller can
// tell "the kernel will not" from "the kernel could not", and so hitting a ceiling
// is not mistaken for a policy denial: a gateway answers 429 for saturation and 403
// for denial, and conflating them makes a capacity problem look like an attack.
type PeerError struct {
	Msg string
	Err error
}

func (e *PeerError) Error() string {
	if e.Err == nil {
		return "kernel: peer refused: " + e.Msg
	}
	return "kernel: peer refused: " + e.Msg + ": " + e.Err.Error()
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *PeerError) Unwrap() error { return e.Err }

// Mesh sentinels. Each one names a distinct outcome so a caller can branch on the
// reason rather than on message text.
var (
	// ErrPeerLimit is the sentinel for every mesh ceiling.
	ErrPeerLimit = errors.New("kernel: peer limit reached")
	// ErrPeerUnknown names a node this kernel has no session with.
	ErrPeerUnknown = errors.New("kernel: unknown peer")
	// ErrPeerGone is returned by a waiter whose session closed underneath it.
	ErrPeerGone = errors.New("kernel: peer session closed")
	// ErrPeerTimeout means the deadline passed before the peer answered.
	ErrPeerTimeout = errors.New("kernel: peer exchange timed out")
	// ErrPeerUntrusted means a claim was well formed but no sealed cluster root
	// verified it. This is the class kslashing treats as evidence.
	ErrPeerUntrusted = errors.New("kernel: peer identity not trusted")
	// ErrPeerLoop bounds relaying. A frame addressed elsewhere is refused rather
	// than forwarded, because being an open relay by default is how a mesh becomes
	// an amplification target.
	ErrPeerLoop = errors.New("kernel: peer frame is not addressed to this node")
	// ErrPeerNoTransport means the host has not injected a PeerTransport.
	ErrPeerNoTransport = errors.New("kernel: no peer transport installed")
)

func peerErr(format string, a ...any) error {
	return &PeerError{Msg: fmt.Sprintf(format, a...)}
}

func peerLimit(err error, format string, a ...any) error {
	return &PeerError{Msg: fmt.Sprintf(format, a...), Err: err}
}

// Mesh ceilings. They are package constants rather than BootLimits fields because
// adding a field to the sealed trust root is a change owned by kboot, and a
// subsystem must not widen the struct it reads.
const (
	// maxPeers bounds the whole table. On full the table REFUSES rather than
	// evicting the oldest peer: silently dropping a peer to make room for an
	// announcer is how an attacker evicts the honest mesh, and a refusal is
	// visible while an eviction is not.
	maxPeers = 256
	// maxPeerNodeIDLen and maxPeerEndpointLen bound the two identifiers. Both are
	// copied into audit lines and console output, so any rune at or below 0x20 or
	// at or above 0x7f is refused: an identifier carrying a newline can forge a
	// log line, which is the control keyring.go's validAlias and service.go's
	// normalizeRoutePath both apply.
	maxPeerNodeIDLen   = 128
	maxPeerEndpointLen = 256
	maxPeerLabelLen    = 128
	// maxPeerNonceBytes is the nonce length. A shorter nonce is not unguessable
	// and a longer one buys nothing.
	maxPeerNonceBytes = 32
	// maxPeerHandshakeBytes bounds a signed handshake payload, borrowed from
	// kcrypto so a signed payload can never exceed what verification will accept.
	maxPeerHandshakeBytes = maxCryptoInputBytes
	// maxPeerFrameBytes bounds one inbound frame body BEFORE it is decoded. Without
	// it PeerDeliver would json.Unmarshal host-fed bytes of any size, which is the
	// same pin-the-kernel's-memory hole maxCallPayloadBytes closes in service.go.
	maxPeerFrameBytes = maxCryptoInputBytes
	// maxPeerPayloadBytes bounds a forwarded payload in either direction, borrowed
	// from kservice because the payload ends up in a route call and the two
	// ceilings must not disagree. Bounding only the outbound side would let a peer
	// return a reply of any size and have this kernel allocate and hold it.
	maxPeerPayloadBytes = maxCallPayloadBytes
	// maxPeerInflightPerPeer and maxPeerInflightTotal bound concurrent host
	// transport calls. The bound is enforced BEFORE a blocking wait is reachable,
	// which is what makes one wrapper goroutine per in-flight call affordable.
	maxPeerInflightPerPeer = 16
	maxPeerInflightTotal   = 256
	// maxPeerLatencySamples and maxRetainedPeerEvents are the two ledgers that use
	// the seven-eighths one-step trim.
	maxPeerLatencySamples = 64
	maxRetainedPeerEvents = 4096
	// maxPeerHops bounds relaying depth should the owner ever enable it.
	maxPeerHops = 8
	// maxPeerReplays bounds the per-peer nonce window. Unbounded would be a leak
	// whose growth an attacker controls. The honest cost is stated rather than
	// hidden: a replay older than the window is not caught.
	maxPeerReplays = 256
	// maxPeerAnnounceTTLNanos bounds one announcement's lifetime, so a peer cannot
	// install a table entry that outlives every restart of itself.
	maxPeerAnnounceTTLNanos = int64(24 * time.Hour)
)

// MaxPeers reports the mesh table ceiling.
func MaxPeers() int { return maxPeers }

// peerConn is one live session with one peer.
//
// It carries its own mutex and cond, the same shape pipe.go and lock.go use for a
// resource that has waiters: a registry lock plus a per-resource lock, because a
// blocked probe must not hold the whole mesh table hostage while it waits.
type peerConn struct {
	mu   sync.Mutex
	cond *sync.Cond

	nodeID   string
	keyID    string
	endpoint string
	label    string
	fd       FD
	closed   bool

	// closedCh is closed exactly once, on the same transition that sets closed.
	//
	// It exists because a cleanup path must not depend on the cooperation of the
	// thing it is cleaning up. A probe or forward parked inside the host's Exchange
	// cannot be woken by a cond.Broadcast - no broadcast reaches into host code - so
	// closing the session would otherwise leave the caller waiting for its deadline
	// while the session it was measuring is already gone. This channel is the third
	// case in every wait below, and it is what makes "closing a session ends its
	// in-flight calls" true rather than approximately true.
	//
	// The wrapper goroutine running Exchange is NOT abortable and keeps running until
	// the host returns; the file header states that limit plainly. What this buys is
	// that the caller returns immediately and its inflight slot is released at that
	// return, so a wedged transport cannot hold a slot hostage past the close.
	closedCh chan struct{}

	nextSeq  int64
	samples  []int64
	ewma     int64
	lastRTT  int64
	timeouts int64

	forwarded int64
	refused   int64

	openedMono int64
	// lastSampleMono is the mono() reading at which the most recent RTT was
	// measured. It is stored rather than re-read when latency is reported, because
	// a latency whose timestamp is "whenever someone asked" cannot be compared
	// against another peer's.
	lastSampleMono int64
	inflight       int

	// replays is the bounded nonce window. A nonce this node has already seen is a
	// replay, and remembering all of them forever would be a leak whose growth the
	// peer controls, so the window is bounded and the cost is stated in the
	// ceiling's comment.
	replays map[string]struct{}
	replayQ []string
}

func newPeerConn(nodeID, keyID, endpoint, label string, fd FD) *peerConn {
	c := &peerConn{
		nodeID:     nodeID,
		keyID:      keyID,
		endpoint:   endpoint,
		label:      label,
		fd:         fd,
		nextSeq:    1,
		openedMono: mono(),
		replays:    map[string]struct{}{},
		closedCh:   make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// peerTable is the mesh registry. Its mutex is kpeer's one subsystem lock; the
// per-connection locks above are resources inside it, not a second subsystem.
type peerTable struct {
	mu     sync.RWMutex
	byNode map[string]*peerConn
	// seq is the per-peer outbound frame counter used for frames sent outside a
	// session, so an announcement cannot reuse a session's numbering.
	seq map[string]int64
	// seen is the highest (epoch, seq) accepted from each announcer, which is what
	// makes a replay or a rewind detectable across calls.
	seen map[string]peerSeqState
	// epoch is this node's own boot identity, captured once per boot.
	epoch int64

	events       []PeerEvent
	eventEvicted int64

	announced int64
	accepted  int64
	refused   int64

	probes         int64
	probeTimeouts  int64
	forwarded      int64
	forwardRefused int64

	inflightTotal int

	transport  PeerTransport
	forwardCtx *sContext
}

// peerSeqState is the highest claim accepted from one announcer.
type peerSeqState struct {
	epoch int64
	seq   int64
}

var kpeers = &peerTable{
	byNode: map[string]*peerConn{},
	seq:    map[string]int64{},
	seen:   map[string]peerSeqState{},
}

// recordEvent appends one mesh event and trims in one step.
//
// It trims in batches rather than one record at a time, for the reason kmeter's
// trimLocked states: trimming exactly to the bound makes every insert past the
// ceiling reallocate and copy the whole ledger under the write lock, which is O(n)
// per event forever and lands as a throughput cliff precisely when the mesh is
// busiest. Dropping back to seven eighths makes the cost amortized constant.
func (t *peerTable) recordEvent(kind, nodeID string, seq int64) {
	t.mu.Lock()
	t.events = append(t.events, PeerEvent{Kind: kind, NodeID: nodeID, Seq: seq, Mono: mono()})
	if len(t.events) > maxRetainedPeerEvents {
		keep := maxRetainedPeerEvents - maxRetainedPeerEvents/8
		if len(t.events) > keep {
			over := len(t.events) - keep
			t.eventEvicted += int64(over)
			t.events = append([]PeerEvent(nil), t.events[over:]...)
		}
	}
	t.mu.Unlock()
}

// PeerEvents returns a copy of the mesh event ledger, oldest first.
func PeerEvents() []PeerEvent {
	kpeers.mu.RLock()
	defer kpeers.mu.RUnlock()
	out := make([]PeerEvent, len(kpeers.events))
	copy(out, kpeers.events)
	return out
}

// peerNodeID validates one node identifier. The rune filter is the log-forgery
// control: a node id reaches audit lines and console output verbatim, and an id
// carrying a newline can forge a log line.
func peerNodeID(id string) error {
	if id == "" {
		return peerErr("empty peer node id")
	}
	if len(id) > maxPeerNodeIDLen {
		return peerErr("peer node id of %d bytes exceeds the ceiling %d", len(id), maxPeerNodeIDLen)
	}
	for _, r := range id {
		if r <= 0x20 || r >= 0x7f {
			return peerErr("peer node id %q contains a control or non-ASCII character", id)
		}
	}
	return nil
}

// peerEndpoint validates one endpoint string. It does NOT reuse manifest.go's
// validateHost, and the reason is a policy difference rather than an oversight:
// validateHost refuses loopback because it bounds what a MODULE may dial, and a
// module dialing its own host is a loopback escape. A mesh endpoint names another
// node in the same cluster, and same-host peers are the normal case in a
// single-machine cluster and in every test. The control that matters here is the
// same one - no control characters, no embedded credentials, bounded length - and
// widening loopback is reported to the integrator rather than decided here.
func peerEndpoint(ep string) error {
	if ep == "" {
		return peerErr("empty peer endpoint")
	}
	if len(ep) > maxPeerEndpointLen {
		return peerErr("peer endpoint of %d bytes exceeds the ceiling %d", len(ep), maxPeerEndpointLen)
	}
	for _, r := range ep {
		if r <= 0x20 || r >= 0x7f {
			return peerErr("peer endpoint %q contains a control or non-ASCII character", ep)
		}
	}
	if strings.ContainsAny(ep, "\n\r") {
		return peerErr("peer endpoint %q contains a line break", ep)
	}
	return nil
}

// peerLabel validates an operator-chosen diagnostic label.
//
// It is deliberately looser than peerNodeID and peerEndpoint, and the difference is
// the reason the three are separate functions. A label is prose an operator typed -
// "peer one", "us-east fallback" - and refusing a space in it would make the field
// useless for its only purpose. What it must not carry is a line break, which is the
// same rule receipt.go applies to its Trace and Route labels.
//
// The rune filter on the identifiers is stricter because an identifier is a key: it
// indexes the mesh table, appears in the avc-shaped fault lines, and is compared for
// equality by peers. A label is none of those.
func peerLabel(label string) error {
	if len(label) > maxPeerLabelLen {
		return peerErr("peer label of %d bytes exceeds the ceiling %d", len(label), maxPeerLabelLen)
	}
	if strings.ContainsAny(label, "\n\r") {
		return peerErr("peer label %q contains a line break", label)
	}
	return nil
}

// peerTransport returns the injected transport, or a typed refusal. The lookup takes
// the registry read lock and copies the interface value out, because the hard rule
// of this file is that the transport is NEVER called under kpeers.mu or conn.mu: a
// host transport that blocks would otherwise freeze discovery, probing and
// forwarding for every peer at once.
func peerTransport() (PeerTransport, error) {
	kpeers.mu.RLock()
	t := kpeers.transport
	kpeers.mu.RUnlock()
	if t == nil {
		return nil, &PeerError{Msg: "no peer transport is installed", Err: ErrPeerNoTransport}
	}
	return t, nil
}

// peerExchange runs one host transport call under a kernel-owned deadline.
//
// This is the timeout mechanism, and it is a wrapper goroutine plus a select rather
// than waitWithDeadline. waitWithDeadline bounds a goroutine parked on a sync.Cond;
// it cannot bound a goroutine blocked inside host code, because no Broadcast from
// this kernel can return it. So the call runs on its own goroutine and the caller
// selects between its result and a timer armed from the deadline.
//
// The cost is one goroutine per in-flight call, which is exactly what
// waitWithDeadline already pays, and it is affordable because the inflight bounds are
// enforced before this function is reachable. The honest limit: a transport that
// ignores its deadline keeps its goroutine and its slot until it returns. The kernel
// cannot abort host code, so what the bound guarantees is saturation-then-refusal,
// not cancellation.
//
// The goroutine recovers, because that code is the host's and a panicking transport
// must not take the kernel down.
//
// abort is an optional channel that ends the wait early, and the only thing that can
// end it other than the transport answering or the deadline passing. Callers that hold a
// session pass its closedCh so that closing the session ends its in-flight calls; the
// handshake path has no session yet and passes nil, which blocks forever and therefore
// never fires.
func peerExchange(ctx *sContext, t PeerTransport, endpoint string, frame PeerFrame, deadline int64, abort <-chan struct{}) (PeerFrame, error) {
	type result struct {
		frame PeerFrame
		err   error
	}
	// Buffered at one so the wrapper never blocks on a send nobody reads, which is
	// what would leak the goroutine when the deadline wins the race.
	done := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fault(ctx, "peer transport panicked", map[string]any{
					"endpoint": endpoint, "panic": fmt.Sprint(r),
				})
				kaudit.record(AuditPanic, ctx, "peer transport panicked", map[string]any{
					"endpoint": endpoint, "panic": fmt.Sprint(r),
				})
				done <- result{err: fmt.Errorf("kernel: peer transport panicked: %v", r)}
			}
		}()
		got, err := t.Exchange(endpoint, frame, deadline)
		done <- result{frame: got, err: err}
	}()

	remaining := deadline - mono()
	if remaining < 0 {
		remaining = 0
	}
	timer := time.NewTimer(time.Duration(remaining))
	defer timer.Stop()

	select {
	case res := <-done:
		return res.frame, res.err
	case <-timer.C:
		return PeerFrame{}, &PeerError{
			Msg: fmt.Sprintf("exchange with %q did not answer by the deadline", endpoint),
			Err: ErrPeerTimeout,
		}
	case <-abort:
		return PeerFrame{}, &PeerError{
			Msg: fmt.Sprintf("session with %q closed during the exchange", endpoint),
			Err: ErrPeerGone,
		}
	}
}

// peerSend is the fire-and-forget half, with the same deadline and recovery shape.
func peerSend(ctx *sContext, t PeerTransport, endpoint string, frame PeerFrame, deadline int64, abort <-chan struct{}) error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fault(ctx, "peer transport panicked", map[string]any{
					"endpoint": endpoint, "panic": fmt.Sprint(r),
				})
				done <- fmt.Errorf("kernel: peer transport panicked: %v", r)
			}
		}()
		done <- t.Send(endpoint, frame, deadline)
	}()

	remaining := deadline - mono()
	if remaining < 0 {
		remaining = 0
	}
	timer := time.NewTimer(time.Duration(remaining))
	defer timer.Stop()

	select {
	case err := <-done:
		return err
	case <-timer.C:
		return &PeerError{
			Msg: fmt.Sprintf("send to %q did not complete by the deadline", endpoint),
			Err: ErrPeerTimeout,
		}
	case <-abort:
		return &PeerError{
			Msg: fmt.Sprintf("session with %q closed during the send", endpoint),
			Err: ErrPeerGone,
		}
	}
}

// reserveInflight takes one inflight slot for a peer, refusing when either bound is
// full. The reservation happens BEFORE any blocking wait is reachable, which is what
// makes the wrapper goroutine in peerExchange affordable.
func reserveInflight(ctx *sContext, c *peerConn) error {
	kpeers.mu.Lock()
	if kpeers.inflightTotal >= maxPeerInflightTotal {
		kpeers.mu.Unlock()
		fault(ctx, "peer inflight ceiling reached", map[string]any{
			"node_id": c.nodeID, "max_peer_inflight_total": maxPeerInflightTotal,
		})
		return peerLimit(ErrPeerLimit, "the mesh holds the maximum of %d in-flight exchanges",
			maxPeerInflightTotal)
	}
	kpeers.inflightTotal++
	kpeers.mu.Unlock()

	c.mu.Lock()
	if c.inflight >= maxPeerInflightPerPeer {
		c.mu.Unlock()
		kpeers.mu.Lock()
		kpeers.inflightTotal--
		kpeers.mu.Unlock()
		fault(ctx, "peer inflight ceiling reached", map[string]any{
			"node_id": c.nodeID, "max_peer_inflight_per_peer": maxPeerInflightPerPeer,
		})
		return peerLimit(ErrPeerLimit, "peer %q holds the maximum of %d in-flight exchanges",
			c.nodeID, maxPeerInflightPerPeer)
	}
	c.inflight++
	c.mu.Unlock()
	return nil
}

func releaseInflight(c *peerConn) {
	c.mu.Lock()
	c.inflight--
	c.mu.Unlock()

	kpeers.mu.Lock()
	kpeers.inflightTotal--
	kpeers.mu.Unlock()
}

// peerPayload writes one canonical field the way receipt.go's receiptPayload does.
//
// Each field is a netstring-style length prefix, name and value. The lengths are what
// make the encoding unambiguous: with bare separators, a handshake with node id "a"
// and endpoint "b|c" would encode identically to one with node id "a|b" and endpoint
// "c", and a forger could re-split fields across a boundary without breaking the
// signature. Length prefixing removes that class of forgery outright, and it is the
// reason this file does not sign a JSON rendering instead: JSON key order is not
// canonical, so two nodes would produce different bytes for the same claim.
func peerField(b *bytes.Buffer, name, value string) {
	b.WriteString(strconv.Itoa(len(name)))
	b.WriteByte(':')
	b.WriteString(name)
	b.WriteByte('=')
	b.WriteString(strconv.Itoa(len(value)))
	b.WriteByte(':')
	b.WriteString(value)
	b.WriteByte(';')
}

func peerNum(b *bytes.Buffer, name string, v int64) {
	peerField(b, name, strconv.FormatInt(v, 10))
}

// PeerHandshakePayload is the canonical encoding of a handshake, and it is the only
// thing the signature covers. The field order is part of the encoding and must not
// change without bumping PeerVersion: a reordering makes every handshake from an
// older node fail verification here, which is the correct outcome but is a protocol
// break and not a refactor.
func PeerHandshakePayload(h PeerHandshake) []byte {
	var b bytes.Buffer
	peerNum(&b, "version", int64(h.Version))
	peerField(&b, "node_id", h.NodeID)
	peerField(&b, "key_id", h.KeyID)
	peerField(&b, "initiator", h.Initiator)
	peerField(&b, "nonce_a", hex.EncodeToString(h.NonceA))
	peerField(&b, "nonce_b", hex.EncodeToString(h.NonceB))
	peerField(&b, "endpoint", h.Endpoint)
	peerNum(&b, "epoch", h.Epoch)
	return b.Bytes()
}

// PeerAnnouncePayload is the canonical encoding of an announcement. Wall-clock and
// TTL values are inside the signature because they are what makes an announcement
// expire, and an expiry a peer could rewrite would be no expiry at all.
func PeerAnnouncePayload(a PeerAnnouncement) []byte {
	var b bytes.Buffer
	peerNum(&b, "version", int64(a.Version))
	peerField(&b, "node_id", a.NodeID)
	peerField(&b, "endpoint", a.Endpoint)
	peerField(&b, "key_id", a.KeyID)
	peerNum(&b, "seq", a.Seq)
	peerNum(&b, "epoch", a.Epoch)
	peerNum(&b, "ttl_nanos", a.TTLNanos)
	return b.Bytes()
}

// PeerForwardDigest returns the sha256 hex digest of one forward envelope's canonical
// encoding. This is what the signature covers; see PeerForward for why the payload is
// bound by digest rather than signed directly.
func PeerForwardDigest(f PeerEnvelope) []byte {
	var b bytes.Buffer
	peerNum(&b, "version", int64(f.Version))
	peerField(&b, "from_node", f.FromNode)
	peerField(&b, "to_node", f.ToNode)
	peerField(&b, "route", f.Route)
	peerField(&b, "method", f.Method)
	peerField(&b, "trace", f.Trace)
	peerNum(&b, "hops", f.Hops)
	peerNum(&b, "seq", f.Seq)
	peerField(&b, "key_id", f.KeyID)
	peerField(&b, "payload_hash", f.PayloadHash)
	return b.Bytes()
}

// VerifyPeerHandshake checks one handshake against the sealed cluster roots and
// reports only the verdict.
//
// It is the read-only half, exported for the same reason ReceiptPayload is: a peer
// implementation in another language can be checked against this kernel's own bytes,
// which is the only way to find an encoding disagreement before it costs a dispute.
// kslashing and the host use it; the mutating half is PeerDial.
//
// A configuration failure - no roots at all, no parsable root - is returned as an
// ERROR rather than as a false verdict, copying kreceipt's rule verbatim. Unverifiable
// is not invalid: reporting a conclusion the node cannot reach would either excuse a
// forgery or accuse an honest peer, and only the second one gets noticed.
func VerifyPeerHandshake(h PeerHandshake) (PeerVerdict, error) {
	structural := func(reason string) PeerVerdict {
		return PeerVerdict{NodeID: h.NodeID, KeyID: h.KeyID, Reason: reason, Structural: true}
	}

	if h.Version != PeerVersion {
		return structural(fmt.Sprintf("unsupported peer version %d, this kernel issues %d",
			h.Version, PeerVersion)), nil
	}
	if err := peerNodeID(h.NodeID); err != nil {
		return structural(err.Error()), nil
	}
	if err := peerEndpoint(h.Endpoint); err != nil {
		return structural(err.Error()), nil
	}
	if len(h.NonceA) != maxPeerNonceBytes || len(h.NonceB) != maxPeerNonceBytes {
		return structural(fmt.Sprintf("handshake nonces must be %d bytes each, got %d and %d",
			maxPeerNonceBytes, len(h.NonceA), len(h.NonceB))), nil
	}
	if len(h.Signature) == 0 {
		return structural("handshake carries no signature"), nil
	}

	payload := PeerHandshakePayload(h)
	if len(payload) > maxPeerHandshakeBytes {
		return structural(fmt.Sprintf("handshake payload of %d bytes exceeds the ceiling %d",
			len(payload), maxPeerHandshakeBytes)), nil
	}

	ok, keyID, err := verifyAgainstClusterRoots(payload, h.Signature)
	if err != nil {
		return PeerVerdict{NodeID: h.NodeID, KeyID: h.KeyID}, err
	}
	if !ok {
		return PeerVerdict{
			NodeID: h.NodeID, KeyID: h.KeyID,
			Reason: "no sealed cluster root verifies this handshake",
		}, nil
	}
	return PeerVerdict{Trusted: true, NodeID: h.NodeID, KeyID: keyID}, nil
}

// VerifyPeerAnnouncement checks one announcement the same way. An announcement that
// does not verify is refused rather than stored, because the peer table is the set of
// nodes this kernel will forward work to, and an unsigned entry in it is a hijack.
func VerifyPeerAnnouncement(a PeerAnnouncement) (PeerVerdict, error) {
	structural := func(reason string) PeerVerdict {
		return PeerVerdict{NodeID: a.NodeID, KeyID: a.KeyID, Reason: reason, Structural: true}
	}

	if a.Version != PeerVersion {
		return structural(fmt.Sprintf("unsupported peer version %d, this kernel issues %d",
			a.Version, PeerVersion)), nil
	}
	if err := peerNodeID(a.NodeID); err != nil {
		return structural(err.Error()), nil
	}
	if err := peerEndpoint(a.Endpoint); err != nil {
		return structural(err.Error()), nil
	}
	if a.Seq <= 0 {
		return structural(fmt.Sprintf("announcement sequence %d is not a valid sequence number", a.Seq)), nil
	}
	if a.TTLNanos <= 0 || a.TTLNanos > maxPeerAnnounceTTLNanos {
		return structural(fmt.Sprintf("announcement ttl %d ns is outside (0, %d]",
			a.TTLNanos, maxPeerAnnounceTTLNanos)), nil
	}
	if len(a.Signature) == 0 {
		return structural("announcement carries no signature"), nil
	}

	payload := PeerAnnouncePayload(a)
	if len(payload) > maxPeerHandshakeBytes {
		return structural(fmt.Sprintf("announcement payload of %d bytes exceeds the ceiling %d",
			len(payload), maxPeerHandshakeBytes)), nil
	}

	ok, keyID, err := verifyAgainstClusterRoots(payload, a.Signature)
	if err != nil {
		return PeerVerdict{NodeID: a.NodeID, KeyID: a.KeyID}, err
	}
	if !ok {
		return PeerVerdict{
			NodeID: a.NodeID, KeyID: a.KeyID,
			Reason: "no sealed cluster root verifies this announcement",
		}, nil
	}
	return PeerVerdict{Trusted: true, NodeID: a.NodeID, KeyID: keyID}, nil
}

// PeerDial proves one peer's identity and opens a session handle for it. Requires
// peer:dial.
//
// The handshake is a two-leg exchange so neither side can replay a captured one. This
// node mints NonceA and sends it; the peer mints NonceB and signs both along with its
// own identity, key id and endpoint. Signing both nonces is what makes the reply
// unusable elsewhere: it is bound to this exchange and to this node.
//
// The peer's signed Endpoint is compared against the endpoint this node dialed, and a
// mismatch is refused. Signing a field nobody compares binds nothing, and the attack
// the comparison stops is a real one: an attacker who can redirect traffic could
// otherwise present a handshake captured from a different address.
func PeerDial(ctx SContext, spec PeerDialSpec) (PeerSession, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return PeerSession{}, errForeignContext
	}
	if err := c.syscall(OpPeerDial); err != nil {
		return PeerSession{}, err
	}
	// The declared boundary is enforced here, per call, on the syscall path. This
	// check is what makes peer:dial safe to reach from a module at all: without it the
	// manifest's declaration would be the only thing deciding and nothing would compare
	// the call against it, which is an unbounded grant wearing a reviewed manifest's
	// clothes.
	//
	// It is on the wrapper rather than inside peerDial because the host path acts under
	// init, which is not in the module table and has no manifest of its own. The host
	// supplied the transport and sealed the cluster roots, so it is the authority here
	// for the reason stated in the policy note at the top of this file.
	if err := peerEndpointAllowed(c, spec.Endpoint); err != nil {
		return PeerSession{}, err
	}
	// The instance filter narrows the endpoint's HOST, which is the part the declaration
	// is expressed in, rather than the whole endpoint string. Filtering the endpoint would
	// make a filter's pattern depend on the transport's spelling of ports and schemes, and
	// the same narrowing written for one transport would silently not apply under another.
	if err := SeccompAllow(c, OpPeerDial, peerHostOf(spec.Endpoint)); err != nil {
		return PeerSession{}, err
	}
	return peerDial(c, spec)
}

func peerDial(ctx *sContext, spec PeerDialSpec) (PeerSession, error) {
	if err := peerEndpoint(spec.Endpoint); err != nil {
		return PeerSession{}, err
	}
	if err := peerLabel(spec.Label); err != nil {
		return PeerSession{}, err
	}
	t, err := peerTransport()
	if err != nil {
		return PeerSession{}, err
	}

	nodeID, err := peerOwnNodeID()
	if err != nil {
		return PeerSession{}, err
	}
	nonceA, err := randomBytes(maxPeerNonceBytes)
	if err != nil {
		return PeerSession{}, err
	}

	deadline := mono() + callCeiling(spec.TimeoutMillis).Nanoseconds()
	open := PeerHandshake{
		Version: PeerVersion, NodeID: nodeID, Initiator: nodeID,
		NonceA: nonceA, Endpoint: spec.Endpoint, Epoch: peerEpoch(),
		WallNanos: nowUTC().UnixNano(),
	}
	body, err := json.Marshal(open)
	if err != nil {
		return PeerSession{}, fmt.Errorf("kernel: cannot encode handshake: %w", err)
	}

	seq := peerNextSeq(nodeID)
	// No session exists yet, so there is nothing to be closed underneath this call.
	reply, err := peerExchange(ctx, t, spec.Endpoint,
		PeerFrame{Kind: PeerFrameHandshake, Seq: seq, Body: body}, deadline, nil)
	if err != nil {
		return PeerSession{}, err
	}
	if reply.Kind != PeerFrameHandshakeReply {
		return PeerSession{}, peerErr("peer answered a handshake with frame kind %q", reply.Kind)
	}
	if len(reply.Body) > maxPeerFrameBytes {
		return PeerSession{}, peerLimit(ErrPeerLimit,
			"handshake reply of %d bytes exceeds the ceiling %d", len(reply.Body), maxPeerFrameBytes)
	}

	var h PeerHandshake
	if err := json.Unmarshal(reply.Body, &h); err != nil {
		return PeerSession{}, peerErr("handshake reply does not decode: %v", err)
	}

	// The two legs must belong to the same exchange. A reply carrying a different
	// NonceA is either a replay or a crossed connection, and accepting it would let
	// a captured handshake stand in for a live one.
	if !constantTimeEqualBytes(h.NonceA, nonceA) {
		peerRefuseHandshake(ctx, h.NodeID, spec.Endpoint, "reply does not carry this dial's nonce")
		return PeerSession{}, peerErr("handshake reply does not carry this dial's nonce")
	}
	if h.Initiator != nodeID {
		peerRefuseHandshake(ctx, h.NodeID, spec.Endpoint, "reply names a different initiator")
		return PeerSession{}, peerErr("handshake reply names initiator %q, want %q", h.Initiator, nodeID)
	}
	if h.Endpoint != spec.Endpoint {
		peerRefuseHandshake(ctx, h.NodeID, spec.Endpoint, "signed endpoint does not match the dialed one")
		return PeerSession{}, peerErr("peer signed endpoint %q but was dialed at %q", h.Endpoint, spec.Endpoint)
	}
	if h.NodeID == nodeID {
		peerRefuseHandshake(ctx, h.NodeID, spec.Endpoint, "peer claims this node's own identity")
		return PeerSession{}, peerErr("peer claims this node's own identity %q", nodeID)
	}

	verdict, err := VerifyPeerHandshake(h)
	if err != nil {
		fault(ctx, "cannot verify peer handshake", map[string]any{
			"node_id": h.NodeID, "endpoint": spec.Endpoint, "error": err.Error(),
		})
		return PeerSession{}, err
	}
	if !verdict.Trusted {
		if verdict.Structural {
			peerRefuseHandshake(ctx, h.NodeID, spec.Endpoint, verdict.Reason)
			return PeerSession{}, peerErr("handshake refused: %s", verdict.Reason)
		}
		// A well-formed claim no root verifies is the dishonest case, and it is
		// recorded as an escalation rather than as a protocol fact: a node that
		// cannot prove the identity it claims is attempting to widen what this node
		// trusts. That is the same split keyring.go makes between an out-of-scope
		// alias and a typo. The nonce and the signature are never recorded - the
		// nonce is the replay-resistance value and the chain is readable by anything
		// holding audit:read.
		fault(ctx, "peer handshake failed verification", map[string]any{
			"node_id": h.NodeID, "key_id_claimed": h.KeyID, "endpoint": spec.Endpoint,
			"reason": verdict.Reason,
		})
		kaudit.record(AuditEscalation, ctx, "peer handshake failed verification", map[string]any{
			"node_id": h.NodeID, "key_id_claimed": h.KeyID, "endpoint": spec.Endpoint,
			"reason": verdict.Reason,
		})
		kpeers.mu.Lock()
		kpeers.refused++
		kpeers.mu.Unlock()
		return PeerSession{}, &PeerError{
			Msg: fmt.Sprintf("peer %q is not trusted: %s", h.NodeID, verdict.Reason),
			Err: ErrPeerUntrusted,
		}
	}

	if err := peerNodeID(verdict.NodeID); err != nil {
		return PeerSession{}, err
	}

	kpeers.mu.Lock()
	if _, live := kpeers.byNode[verdict.NodeID]; !live && len(kpeers.byNode) >= maxPeers {
		kpeers.mu.Unlock()
		fault(ctx, "peer table ceiling reached", map[string]any{
			"node_id": verdict.NodeID, "max_peers": maxPeers,
		})
		return PeerSession{}, peerLimit(ErrPeerLimit,
			"the mesh holds the maximum of %d peers", maxPeers)
	}
	kpeers.accepted++
	kpeers.mu.Unlock()

	conn := newPeerConn(verdict.NodeID, verdict.KeyID, spec.Endpoint, spec.Label, noFD)
	fd, err := install(ctx.pid, &peerHandle{conn: conn}, "peer:"+verdict.NodeID)
	if err != nil {
		// install reports its own ceiling fault against a nil context, so the
		// attributed fault is emitted here first: a refusal an operator cannot
		// attribute to a module is a refusal nobody can act on. lock.go and pipe.go
		// both do this for the same reason.
		fault(ctx, "cannot open a peer handle", map[string]any{
			"node_id": verdict.NodeID, "error": err.Error(),
		})
		kpeers.mu.Lock()
		kpeers.accepted--
		kpeers.mu.Unlock()
		return PeerSession{}, peerLimit(ErrPeerLimit,
			"cannot open a peer handle for %q: %v", verdict.NodeID, err)
	}
	conn.fd = fd

	kpeers.mu.Lock()
	kpeers.byNode[verdict.NodeID] = conn
	kpeers.mu.Unlock()

	kaudit.record(AuditPeer, ctx, "peer handshake completed", map[string]any{
		"node_id": verdict.NodeID, "key_id": verdict.KeyID, "endpoint": spec.Endpoint,
		"initiator": nodeID, "label": spec.Label,
	})
	kpeers.recordEvent("handshake", verdict.NodeID, seq)

	return PeerSession{
		FD: fd, NodeID: verdict.NodeID, KeyID: verdict.KeyID,
		Endpoint: spec.Endpoint, Label: spec.Label, Seq: seq, OpenedMono: conn.openedMono,
	}, nil
}

// peerRefuseHandshake records one structural refusal. It is a peer fact rather than
// an escalation: a malformed frame is a protocol disagreement, and calling it an
// attack would train an operator to ignore the escalation stream.
func peerRefuseHandshake(ctx *sContext, nodeID, endpoint, reason string) {
	kpeers.mu.Lock()
	kpeers.refused++
	kpeers.mu.Unlock()
	fault(ctx, "peer handshake refused", map[string]any{
		"node_id": nodeID, "endpoint": endpoint, "reason": reason, "structural": true,
	})
	kaudit.record(AuditPeer, ctx, "peer handshake refused", map[string]any{
		"node_id": nodeID, "endpoint": endpoint, "reason": reason, "structural": true,
	})
}

// peerEndpointAllowed enforces one dial against the boundary the caller declared.
//
// The rule is kv.go's, applied to endpoints: a context whose manifest declares a
// boundary is checked against it, and a context with no manifest behind it has no
// boundary to enforce against, so it is refused rather than passed through. That
// refusal is what keeps this from becoming an unbounded grant.
//
// The domain matters here in one specific way. A context with no manifest behind it has
// no boundary to enforce against, and the honest outcome is a refusal rather than a
// pass-through - otherwise the absence of a declaration would be the widest grant of
// all. The kernel domain is the one exception, and it is unreachable rather than
// privileged: its ceiling is AllOps and its only holder is the pid 0 root context that
// boot retires the instant init exists, so nothing long-lived runs under it.
func peerEndpointAllowed(ctx *sContext, endpoint string) error {
	if ctx.dom == DomainKernel {
		return nil
	}
	manifest, live := manifestOf(ctx.pid)
	if !live {
		return peerScopeRefused(ctx, endpoint, "this context has no declared peer boundary")
	}
	host := peerHostOf(endpoint)
	for _, allowed := range manifest.AllowedHosts {
		if allowed == "" {
			// An empty entry would match everything, so it is skipped rather than
			// honoured. keyring.go's aliasInScope skips an empty prefix for the same
			// reason, and manifest validation already refuses an empty host.
			continue
		}
		if host == allowed || endpoint == allowed {
			return nil
		}
	}
	return peerScopeRefused(ctx, endpoint,
		fmt.Sprintf("%q is outside the declared allowed_hosts boundary", endpoint))
}

// peerHostOf splits an endpoint into the host part a manifest declares. An endpoint is
// what the host transport understands, so it may carry a port, a scheme or a path;
// AllowedHosts carries bare hostnames because that is what validateHost accepts. Parsing
// here is what lets the two be compared without either one loosening its own rules.
func peerHostOf(endpoint string) string {
	h := endpoint
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	if i := strings.IndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	return h
}

// peerScopeRefused records a boundary violation as an escalation, following kv.go's
// fsScopeRefused. Reaching for an endpoint outside the declared boundary is an attempt
// to act beyond a grant, and it is audited rather than only faulted because a module
// probing its own boundary is evidence about the module.
func peerScopeRefused(ctx *sContext, endpoint, reason string) error {
	fault(ctx, "peer endpoint outside declared boundary", map[string]any{
		"module": ctx.name, "op": string(OpPeerDial), "endpoint": endpoint, "reason": reason,
	})
	kaudit.record(AuditEscalation, ctx, "peer endpoint outside declared boundary", map[string]any{
		"module": ctx.name, "op": string(OpPeerDial), "endpoint": endpoint,
	})
	return &DeniedError{Op: OpPeerDial, Ctx: ctx, Reason: reason}
}

// peerEpoch returns this node's boot identity, captured once per boot and cleared by
// resetPeers.
//
// It is the boot audit record's mono timestamp, which is verifierBootID's source: written
// once by Boot before anything else, different between boots because mono() never repeats a
// reading, and cleared by kaudit's own reset. A peer's epoch therefore changes exactly when
// that peer restarts, which is what makes a restarting peer distinguishable from a
// replaying one.
//
// The honest limit, stated because the control is only as strong as this: the epoch is the
// LOCAL boot's identity, so it correctly tags what THIS node announces. A REMOTE peer's
// epoch is whatever that peer put in its signed announcement, and this node cannot verify
// it is a real boot boundary rather than a number the peer chose. What the epoch buys is
// that a peer which restarts and renumbers from 1 is accepted again - the honest case that
// a bare sequence check would refuse forever - while a peer replaying a captured
// announcement under an unchanged epoch and sequence is still refused. A peer that
// deliberately increments its epoch on a replay is not caught here, and cannot be by a
// mechanism the peer itself feeds; catching that needs the transport to attest liveness,
// which is out of scope for kpeer.
func peerEpoch() int64 {
	kpeers.mu.Lock()
	defer kpeers.mu.Unlock()
	if kpeers.epoch != 0 {
		return kpeers.epoch
	}
	entries := AuditQuery(AuditFilter{Kind: AuditBoot, Limit: 1})
	if len(entries) == 0 {
		// No boot record is visible, which is either a kernel that is down or a chain
		// window too small to hold it. mono() is never zero for a live kernel, so fall
		// back to it: a distinct-enough identity that does not collide with 0, which
		// is reserved for "not captured yet".
		kpeers.epoch = mono()
		return kpeers.epoch
	}
	kpeers.epoch = entries[0].Time
	return kpeers.epoch
}

// peerAcceptSeq decides whether one announcement's (epoch, seq) may be accepted, and
// records it if so.
//
// The rule, and the reason each branch exists:
//
//   - A higher epoch is always accepted and resets the sequence baseline. That is the
//     honest restart: the peer came back and began numbering from 1 again, and refusing
//     it would strand a legitimate peer forever.
//   - Within one epoch, seq must strictly increase. Equal or lower is a replay or a
//     rewind and is refused, because accepting it would let a captured announcement
//     reinsert a stale endpoint.
//   - The first claim from a peer is accepted at whatever epoch and seq it carries.
//
// It returns (accepted, reason). The caller records the escalation and the audit entry,
// because this function holds the registry lock and must not also write evidence.
func peerAcceptSeq(ctx *sContext, nodeID string, epoch, seq int64) (bool, string) {
	kpeers.mu.Lock()
	defer kpeers.mu.Unlock()

	prev, seen := kpeers.seen[nodeID]
	if seen {
		switch {
		case epoch > prev.epoch:
			// A newer boot. Accept and reset the baseline.
		case epoch < prev.epoch:
			return false, fmt.Sprintf(
				"announcement epoch %d is older than %d already accepted from %q",
				epoch, prev.epoch, nodeID)
		case seq <= prev.seq:
			return false, fmt.Sprintf(
				"announcement sequence %d is not after %d already seen from %q in epoch %d",
				seq, prev.seq, nodeID, epoch)
		}
	}
	kpeers.seen[nodeID] = peerSeqState{epoch: epoch, seq: seq}
	return true, ""
}

// peerOwnNodeID reads this node's identity from the sealed trust root.// peerOwnNodeID reads this node's identity from the sealed trust root. An empty id is
// an error rather than a fallback, for the reason receipt.go gives for a missing
// signing key: a mesh participant that silently invents an identity produces
// handshakes that look complete and verify nowhere.
func peerOwnNodeID() (string, error) {
	nodeID, _ := BootGet("node.id")
	if nodeID == "" {
		return "", errors.New("kernel: the sealed trust root declares no node id")
	}
	return nodeID, nil
}

// peerNextSeq takes the next outbound sequence number for one peer.
func peerNextSeq(nodeID string) int64 {
	kpeers.mu.Lock()
	defer kpeers.mu.Unlock()
	seq := kpeers.seq[nodeID]
	if seq <= 0 {
		seq = 1
	}
	kpeers.seq[nodeID] = seq + 1
	return seq
}

// peerHandle is the fd-table resource for one live session.
type peerHandle struct {
	closedFlag
	conn *peerConn
}

// Kind names the resource for the fd table and the console dump. It is a constant,
// which install() requires because it caches the value at install time.
func (h *peerHandle) Kind() string { return "peer" }

// Close ends the session and wakes anyone parked on it.
//
// The broadcast happens outside conn.mu, which is the shape pipe.go's Close uses:
// mutating state under the lock and then waking waiters after releasing it, so every
// parked probe or forward re-evaluates and sees closed instead of parking forever.
// Without it, unloading a module that held a peer session would strand its own
// in-flight exchange.
func (h *peerHandle) Close() error {
	if !h.mark() {
		return errClosed
	}
	h.conn.close("handle closed", true)
	return nil
}

// peerSession resolves one session handle inside the calling pid, kind-checked.
//
// The kind check is what makes a handle unforgeable across subsystems: using a pipe
// handle where a peer session is expected fails with "not a peer" rather than being
// reinterpreted. The concrete assertion is used rather than the e.kind comparison
// because the conn is needed, copying receipt.go's ReceiptHandle. done() is checked
// after the assertion because lookup returns a live entry and a concurrent close can
// win the race.
func peerSession(c *sContext, fd FD) (*peerConn, error) {
	entry, err := lookup(c.pid, fd)
	if err != nil {
		return nil, err
	}
	h, ok := entry.res.(*peerHandle)
	if !ok {
		return nil, fmt.Errorf("kernel: fd %d is a %s, not a peer", fd, entry.kind)
	}
	if h.done() {
		return nil, errClosed
	}
	return h.conn, nil
}

// close ends a session. goodbye is sent only when the caller asks for it and only
// when the transport is still installed, and a failure to send one on a live session
// is a fault while a failure during a deliberate reset is not.
//
// That distinction is the reason goodbye is a parameter. resetPeers drops the
// transport as part of tearing down the mesh, so a goodbye sent from the reset path
// could never arrive; emitting a fault per session there would bury the fault stream
// in noise on every routine shutdown of a full mesh, which is the exact failure the
// fault-level rule exists to prevent.
func (c *peerConn) close(reason string, goodbye bool) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	nodeID, endpoint := c.nodeID, c.endpoint
	lastRTT, probes, forwarded := c.lastRTT, len(c.samples), c.forwarded
	c.mu.Unlock()

	// Waking waiters comes first, before the goodbye send, because a goodbye is
	// allowed to take up to peerGoodbyeTimeout and a caller parked on a dead session
	// should not have to wait for courtesy traffic to somebody else.
	close(c.closedCh)

	if goodbye {
		kpeers.mu.RLock()
		t := kpeers.transport
		kpeers.mu.RUnlock()
		if t != nil {
			frame := PeerFrame{Kind: PeerFrameGoodbye, Seq: peerNextSeq(nodeID)}
			deadline := mono() + peerGoodbyeTimeout().Nanoseconds()
			// abort is nil here on purpose: this session's closedCh is already
			// closed, and passing it would make the goodbye fail instantly.
			if err := peerSend(nil, t, endpoint, frame, deadline, nil); err != nil {
				fault(nil, "peer goodbye failed", map[string]any{
					"node_id": nodeID, "endpoint": endpoint, "error": err.Error(),
				})
			}
		}
	}

	// Removed from the registry after the state change and outside both locks,
	// because close re-enters the registry and mutating one map while holding
	// another is how a teardown deadlocks.
	kpeers.mu.Lock()
	if live, ok := kpeers.byNode[nodeID]; ok && live == c {
		delete(kpeers.byNode, nodeID)
	}
	kpeers.mu.Unlock()

	// Broadcast last, outside the state mutex, so a waiter wakes to observe closed.
	c.cond.Broadcast()

	kaudit.record(AuditPeer, nil, "peer session closed", map[string]any{
		"node_id": nodeID, "endpoint": endpoint, "reason": reason,
		"last_rtt_nanos": lastRTT, "probes": probes, "forwarded": forwarded,
	})
	kpeers.recordEvent("closed", nodeID, 0)
}

// peerGoodbyeTimeout bounds one goodbye send. It is short on purpose: a goodbye is
// courtesy, and a session teardown must not block on a peer that is already gone.
func peerGoodbyeTimeout() time.Duration { return 2 * time.Second }

// PeerProbe measures one round trip to a peer and returns the updated latency.
// Requires peer:dial.
//
// The deadline is mandatory and is an absolute mono() reading, copying klock's rule
// rather than inventing one: an untimed wait is how a module turns one unreachable
// peer into a hung goroutine, and a wall-clock deadline is a deadline an NTP step can
// move. The measurement itself is mono()-based for the same reason - a probe timed
// against the wall clock reports a negative or enormous latency the moment the clock
// steps, and a scheduler that trusted it would route around a healthy node.
func PeerProbe(ctx SContext, fd FD, deadline int64) (PeerLatency, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return PeerLatency{}, errForeignContext
	}
	if err := c.syscall(OpPeerDial); err != nil {
		return PeerLatency{}, err
	}
	return peerProbe(c, fd, deadline)
}

func peerProbe(ctx *sContext, fd FD, deadline int64) (PeerLatency, error) {
	if deadline <= 0 {
		return PeerLatency{}, errors.New(
			"kernel: a peer probe requires a deadline on the monotonic clock")
	}
	conn, err := peerSession(ctx, fd)
	if err != nil {
		return PeerLatency{}, err
	}
	t, err := peerTransport()
	if err != nil {
		return PeerLatency{}, err
	}

	conn.mu.Lock()
	if conn.closed {
		conn.mu.Unlock()
		return PeerLatency{}, &PeerError{
			Msg: fmt.Sprintf("session with %q is closed", conn.nodeID), Err: ErrPeerGone,
		}
	}
	nodeID, endpoint := conn.nodeID, conn.endpoint
	abort := conn.closedCh
	seq := conn.nextSeq
	conn.nextSeq++
	conn.mu.Unlock()

	if err := reserveInflight(ctx, conn); err != nil {
		return PeerLatency{}, err
	}
	defer releaseInflight(conn)

	start := mono()
	// The probe body carries only what a peer needs to answer: the sender's
	// identity and the sequence number the reply is matched on. It is deliberately
	// not a handshake, and it is not signed: a probe measures reachability and
	// latency, and an answer to one asserts nothing this node would act on.
	body, err := json.Marshal(peerProbeBody{Version: PeerVersion, NodeID: nodeID, Seq: seq})
	if err != nil {
		return PeerLatency{}, fmt.Errorf("kernel: cannot encode probe: %w", err)
	}

	kpeers.mu.Lock()
	kpeers.probes++
	kpeers.mu.Unlock()

	reply, err := peerExchange(ctx, t, endpoint,
		PeerFrame{Kind: PeerFrameProbe, Seq: seq, Body: body}, deadline, abort)
	rtt := mono() - start

	conn.mu.Lock()
	if err != nil {
		// A session closed underneath the probe is local teardown, not a peer that
		// failed to answer, so it is not counted against the peer's timeout total.
		gone := errors.Is(err, ErrPeerGone)
		if !gone {
			conn.timeouts++
		}
		timeouts := conn.timeouts
		conn.mu.Unlock()

		if !gone {
			kpeers.mu.Lock()
			kpeers.probeTimeouts++
			kpeers.mu.Unlock()
		}

		// A timed-out probe is recorded and a successful one is not. At one probe per
		// second across a full mesh a per-probe audit record would evict the real
		// evidence out of the in-memory window, and the audit chain is evidence rather
		// than telemetry; the samples live in the event ledger instead. A timeout is
		// the exception because it is the fact an operator investigates.
		//
		// A session that closed underneath the probe is neither: it is local teardown
		// the operator caused, not a fact about the peer, so it is not counted as a
		// timeout and writes no record.
		if errors.Is(err, ErrPeerTimeout) {
			fault(ctx, "peer probe timed out", map[string]any{
				"node_id": nodeID, "deadline_nanos": deadline, "timeouts": timeouts,
			})
			kaudit.record(AuditPeer, ctx, "peer probe timed out", map[string]any{
				"node_id": nodeID, "deadline_nanos": deadline, "timeouts": timeouts,
			})
			kpeers.recordEvent("probe-timeout", nodeID, seq)
		}
		return PeerLatency{}, err
	}
	if reply.Kind != PeerFrameProbeReply {
		conn.mu.Unlock()
		return PeerLatency{}, peerErr("peer answered a probe with frame kind %q", reply.Kind)
	}

	conn.recordSample(rtt)
	latency := conn.latencyLocked()
	conn.mu.Unlock()

	kpeers.recordEvent("probe", nodeID, seq)
	return latency, nil
}

// recordSample stores one RTT and updates the moving average. Caller holds c.mu.
//
// The sample ledger uses the same seven-eighths one-step trim as kmeter and ktrace.
// Trimming one record per insert would copy the whole ledger under the lock on every
// probe past the ceiling, which is O(n) per probe forever on the hottest path in the
// subsystem.
func (c *peerConn) recordSample(rtt int64) {
	c.samples = append(c.samples, rtt)
	if len(c.samples) > maxPeerLatencySamples {
		keep := maxPeerLatencySamples - maxPeerLatencySamples/8
		if len(c.samples) > keep {
			c.samples = append([]int64(nil), c.samples[len(c.samples)-keep:]...)
		}
	}
	c.lastRTT = rtt
	c.lastSampleMono = mono()
	if c.ewma == 0 {
		c.ewma = rtt
		return
	}
	// One eighth weight, the standard smoothing choice: enough history that one slow
	// probe does not reroute the mesh, enough recency that a genuinely degraded peer
	// is visible within a handful of samples.
	c.ewma += (rtt - c.ewma) / 8
}

func (c *peerConn) latencyLocked() PeerLatency {
	return PeerLatency{
		RTTNanos: c.lastRTT, EWMANanos: c.ewma, Samples: int64(len(c.samples)),
		LastMono: c.lastSampleMono, Timeouts: c.timeouts,
	}
}

// PeerLatencyOf reports one peer's measured responsiveness. It takes no context and
// performs no policy check, which puts it in the family of ProcTable, LockSnapshot,
// RouteTable and SecretInventory: read-only observability that grants no privilege,
// for the console dump and for the host.
func PeerLatencyOf(nodeID string) (PeerLatency, bool) {
	kpeers.mu.RLock()
	conn, ok := kpeers.byNode[nodeID]
	kpeers.mu.RUnlock()
	if !ok {
		return PeerLatency{}, false
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.latencyLocked(), true
}

// PeerTableSnapshot returns the mesh table, sorted by node id.
func PeerTableSnapshot() []PeerInfo {
	kpeers.mu.RLock()
	conns := make([]*peerConn, 0, len(kpeers.byNode))
	for _, c := range kpeers.byNode {
		conns = append(conns, c)
	}
	kpeers.mu.RUnlock()

	sort.Slice(conns, func(i, j int) bool { return conns[i].nodeID < conns[j].nodeID })

	out := make([]PeerInfo, 0, len(conns))
	for _, c := range conns {
		c.mu.Lock()
		out = append(out, PeerInfo{
			NodeID: c.nodeID, KeyID: c.keyID, Endpoint: c.endpoint, Label: c.label,
			OpenedMono: c.openedMono, LastRTTNanos: c.lastRTT, Samples: int64(len(c.samples)),
			Timeouts: c.timeouts, Forwarded: c.forwarded, Refused: c.refused, Closed: c.closed,
		})
		c.mu.Unlock()
	}
	return out
}

// PeerStatsSnapshot returns the mesh counters.
func PeerStatsSnapshot() PeerStats {
	kpeers.mu.RLock()
	defer kpeers.mu.RUnlock()
	return PeerStats{
		Peers: len(kpeers.byNode), Announced: kpeers.announced, Accepted: kpeers.accepted,
		Refused: kpeers.refused, Probes: kpeers.probes, ProbeTimeouts: kpeers.probeTimeouts,
		Forwarded: kpeers.forwarded, ForwardRefused: kpeers.forwardRefused,
		Events: len(kpeers.events), EventEvicted: kpeers.eventEvicted, MaxPeers: maxPeers,
	}
}

// PeerForward sends one request to a peer node and returns its reply. Requires
// peer:dial.
//
// The envelope is signed over a digest of its canonical encoding, and the digest
// covers the payload hash rather than the payload: see PeerEnvelope for why. What that
// buys is that a peer cannot alter the route, the hop count or the payload of a
// forwarded request without invalidating the signature, which is the property that
// makes a cross-node request attributable to the node that sent it.
func PeerForward(ctx SContext, req PeerForwardRequest) (PeerForwardResult, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return PeerForwardResult{}, errForeignContext
	}
	if err := c.syscall(OpPeerDial); err != nil {
		return PeerForwardResult{}, err
	}
	return peerForward(c, req)
}

func peerForward(ctx *sContext, req PeerForwardRequest) (PeerForwardResult, error) {
	if err := peerNodeID(req.NodeID); err != nil {
		return PeerForwardResult{}, err
	}
	if len(req.Payload) > maxPeerPayloadBytes {
		return PeerForwardResult{}, peerLimit(ErrPeerLimit,
			"forward payload of %d bytes exceeds the ceiling %d", len(req.Payload), maxPeerPayloadBytes)
	}
	if req.Hops > maxPeerHops {
		return PeerForwardResult{}, peerErr("forward hop count %d exceeds the ceiling %d",
			req.Hops, maxPeerHops)
	}

	kpeers.mu.RLock()
	conn, ok := kpeers.byNode[req.NodeID]
	t := kpeers.transport
	kpeers.mu.RUnlock()

	if !ok {
		return PeerForwardResult{}, &PeerError{
			Msg: fmt.Sprintf("no session with node %q", req.NodeID), Err: ErrPeerUnknown,
		}
	}
	if t == nil {
		return PeerForwardResult{}, &PeerError{
			Msg: "no peer transport is installed", Err: ErrPeerNoTransport,
		}
	}

	conn.mu.Lock()
	if conn.closed {
		conn.mu.Unlock()
		return PeerForwardResult{}, &PeerError{
			Msg: fmt.Sprintf("session with %q is closed", conn.nodeID), Err: ErrPeerGone,
		}
	}
	endpoint, keyID := conn.endpoint, conn.keyID
	abort := conn.closedCh
	seq := conn.nextSeq
	conn.nextSeq++
	conn.mu.Unlock()

	nodeID, err := peerOwnNodeID()
	if err != nil {
		return PeerForwardResult{}, err
	}

	fwd := PeerEnvelope{
		Version: PeerVersion, FromNode: nodeID, ToNode: req.NodeID,
		Route: req.Route, Method: req.Method, Trace: string(req.Trace),
		Hops: req.Hops + 1, Seq: seq, KeyID: keyID,
		PayloadHash: sha256Sum(req.Payload), Payload: req.Payload,
	}
	// The signature is produced through the kernel's own signing path, so the
	// private key never enters this function's frame and never crosses a syscall
	// boundary. A caller gets a signed envelope, not the key that signed it.
	sig, err := signWithNodeKey(ctx, PeerForwardDigest(fwd))
	if err != nil {
		return PeerForwardResult{}, err
	}
	fwd.Signature = sig.Bytes

	body, err := json.Marshal(fwd)
	if err != nil {
		return PeerForwardResult{}, fmt.Errorf("kernel: cannot encode forward: %w", err)
	}
	if len(body) > maxPeerFrameBytes {
		return PeerForwardResult{}, peerLimit(ErrPeerLimit,
			"forward frame of %d bytes exceeds the ceiling %d", len(body), maxPeerFrameBytes)
	}

	if err := reserveInflight(ctx, conn); err != nil {
		return PeerForwardResult{}, err
	}
	defer releaseInflight(conn)

	deadline := mono() + callCeiling(req.TimeoutMillis).Nanoseconds()

	kaudit.record(AuditPeer, ctx, "peer forward sent", map[string]any{
		"node_id": req.NodeID, "route": req.Route, "bytes": len(req.Payload),
		"trace": string(req.Trace), "hops": fwd.Hops,
	})

	start := mono()
	reply, err := peerExchange(ctx, t, endpoint,
		PeerFrame{Kind: PeerFrameForward, Seq: seq, Body: body}, deadline, abort)
	rtt := mono() - start
	if err != nil {
		peerRefuseForward(ctx, req.NodeID, req.Route, err.Error(), fwd.Hops)
		return PeerForwardResult{}, err
	}
	if reply.Kind != PeerFrameForwardReply {
		peerRefuseForward(ctx, req.NodeID, req.Route,
			fmt.Sprintf("peer answered with frame kind %q", reply.Kind), fwd.Hops)
		return PeerForwardResult{}, peerErr("peer answered a forward with frame kind %q", reply.Kind)
	}
	// The reply is bounded at ingress for the same reason the request is. Bounding
	// only the outbound side would let a peer return a response of any size and have
	// this kernel allocate and hold it, which with maxPeerInflightPerPeer in flight
	// per peer is an attacker-controlled memory pin behind a valid signature.
	if len(reply.Body) > maxPeerPayloadBytes {
		peerRefuseForward(ctx, req.NodeID, req.Route,
			fmt.Sprintf("reply of %d bytes exceeds the ceiling %d", len(reply.Body), maxPeerPayloadBytes),
			fwd.Hops)
		return PeerForwardResult{}, peerLimit(ErrPeerLimit,
			"forward reply of %d bytes exceeds the ceiling %d", len(reply.Body), maxPeerPayloadBytes)
	}

	var resp RouteResponse
	if len(reply.Body) > 0 {
		if err := json.Unmarshal(reply.Body, &resp); err != nil {
			peerRefuseForward(ctx, req.NodeID, req.Route,
				fmt.Sprintf("reply does not decode: %v", err), fwd.Hops)
			return PeerForwardResult{}, peerErr("forward reply does not decode: %v", err)
		}
	}

	conn.mu.Lock()
	conn.forwarded++
	conn.recordSample(rtt)
	conn.mu.Unlock()

	kpeers.mu.Lock()
	kpeers.forwarded++
	kpeers.mu.Unlock()
	kpeers.recordEvent("forward", req.NodeID, seq)

	return PeerForwardResult{
		Status: resp.Status, Payload: resp.Payload, Header: resp.Header,
		RTTNanos: rtt, Trace: req.Trace,
	}, nil
}

// peerRefuseForward records one refused forward. A refusal whose cause was a failed
// signature additionally writes an escalation, because that is the dishonest class;
// every other refusal is a mesh fact.
func peerRefuseForward(ctx *sContext, nodeID, route, reason string, hops int64) {
	kpeers.mu.Lock()
	kpeers.forwardRefused++
	kpeers.mu.Unlock()
	fault(ctx, "peer forward refused", map[string]any{
		"node_id": nodeID, "route": route, "reason": reason, "hops": hops,
	})
	kaudit.record(AuditPeer, ctx, "peer forward refused", map[string]any{
		"node_id": nodeID, "route": route, "reason": reason, "hops": hops,
	})
}

// PeerAnnounce publishes one signed discovery record. Requires peer:announce.
//
// The record is verified before it is stored, and an announcement that does not
// verify against a sealed cluster root is refused. The peer table is the set of nodes
// this kernel will forward work to, so an unsigned or wrongly-signed entry in it is
// not a discovery convenience but a hijack: whoever can reach the transport could
// otherwise insert an address and receive forwarded requests.
func PeerAnnounce(ctx SContext, a PeerAnnouncement) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpPeerAnnounce); err != nil {
		return err
	}
	return peerAnnounce(c, a)
}

func peerAnnounce(ctx *sContext, a PeerAnnouncement) error {
	kpeers.mu.Lock()
	kpeers.announced++
	kpeers.mu.Unlock()

	verdict, err := VerifyPeerAnnouncement(a)
	if err != nil {
		fault(ctx, "cannot verify peer announcement", map[string]any{
			"node_id": a.NodeID, "endpoint": a.Endpoint, "error": err.Error(),
		})
		return err
	}
	if !verdict.Trusted {
		kpeers.mu.Lock()
		kpeers.refused++
		kpeers.mu.Unlock()
		kind := AuditPeer
		if !verdict.Structural {
			// A well-formed announcement no root verifies is an attempt to insert a
			// node this cluster does not trust, which is an escalation rather than a
			// protocol disagreement.
			kind = AuditEscalation
			fault(ctx, "peer announcement failed verification", map[string]any{
				"node_id": a.NodeID, "key_id_claimed": a.KeyID, "endpoint": a.Endpoint,
				"reason": verdict.Reason,
			})
		}
		kaudit.record(kind, ctx, "peer announcement refused", map[string]any{
			"node_id": a.NodeID, "endpoint": a.Endpoint, "seq": a.Seq,
			"ttl_nanos": a.TTLNanos, "reason": verdict.Reason, "structural": verdict.Structural,
		})
		if !verdict.Structural {
			return &PeerError{
				Msg: fmt.Sprintf("announcement from %q is not trusted: %s", a.NodeID, verdict.Reason),
				Err: ErrPeerUntrusted,
			}
		}
		return peerErr("announcement refused: %s", verdict.Reason)
	}

	nodeID, err := peerOwnNodeID()
	if err != nil {
		return err
	}
	if a.NodeID == nodeID {
		return peerErr("announcement claims this node's own identity %q", nodeID)
	}

	// The (epoch, seq) pair is checked for replay and rewind rather than merely
	// stored. A captured announcement replayed under an unchanged epoch is refused; a
	// peer that genuinely restarted announces a newer epoch and is accepted with its
	// baseline reset. See peerAcceptSeq for the exact rule and its stated limit.
	accepted, reason := peerAcceptSeq(ctx, a.NodeID, a.Epoch, a.Seq)
	if !accepted {
		kpeers.mu.Lock()
		kpeers.refused++
		kpeers.mu.Unlock()
		fault(ctx, "peer announcement sequence rewound", map[string]any{
			"node_id": a.NodeID, "seq": a.Seq, "epoch": a.Epoch, "reason": reason,
		})
		kaudit.record(AuditEscalation, ctx, "peer announcement sequence rewound", map[string]any{
			"node_id": a.NodeID, "seq": a.Seq, "epoch": a.Epoch, "reason": reason,
		})
		return peerErr("announcement refused: %s", reason)
	}

	kaudit.record(AuditPeer, ctx, "peer announced", map[string]any{
		"node_id": a.NodeID, "endpoint": a.Endpoint, "key_id": verdict.KeyID,
		"seq": a.Seq, "epoch": a.Epoch, "ttl_nanos": a.TTLNanos,
	})
	kpeers.recordEvent("announce", a.NodeID, a.Seq)
	return nil
}

// PeerPeers lists the mesh table. Requires peer:dial.
//
// It deliberately names an operation rather than passing "": the nine-entry budget
// for unprivileged syscalls is spent, and that budget exists because each of those
// nine can only act on state the caller owns. The peer table is not the caller's
// state - it is mesh state every caller would see identically, and it is a map of the
// deployment's internal topology, so reading it is a capability.
func PeerPeers(ctx SContext) ([]PeerInfo, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if err := c.syscall(OpPeerDial); err != nil {
		return nil, err
	}
	return PeerTableSnapshot(), nil
}

// Host-handle methods.
//
// They exist because peer:dial and peer:announce are kernel-domain-only and the pid 0
// context that holds them is retired the instant init exists, so after boot no live
// context can pass the prologue. This mirrors Kernel.IssueReceipt and
// Kernel.InstallSecret rather than widening the policy: the host supplied the signing
// key and the cluster roots, so it already holds both halves of the mesh's trust
// outright and this adds no capability it did not have. Each one performs no policy
// check because there is no context to check, and each delegates to the same
// implementation the syscall uses, so there is one code path to review.

// PeerSetTransport installs the host's byte mover. A nil transport is an error rather
// than a silent unset, because the alternative leaves the mesh looking configured
// while every dial fails with a refusal nobody asked for.
//
// The transport is dropped by resetPeers rather than kept across a restart, matching
// kaudit.reset dropping its sink: host configuration does not survive a boot, and a
// restarted kernel that inherited the previous boot's transport would send frames
// under a node identity it has not re-read yet. A host that reuses one *Kernel across
// Shutdown and Boot must install the transport again after each boot.
func (k *Kernel) PeerSetTransport(t PeerTransport) error {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return errors.New("kernel: already shut down")
	}
	if t == nil {
		return errors.New("kernel: a nil peer transport is not installable")
	}
	kpeers.mu.Lock()
	kpeers.transport = t
	// The forwarding context is init's. A request arriving from another node is
	// dispatched into the local route table under a context this kernel allocated,
	// and init is the long-lived local context the host talks to. It is not a
	// privilege escalation and it is not the caller's: service.go re-resolves the
	// handler's own context at dispatch, so the handler still runs under its own
	// grants. The consequence worth stating is that CallerPID on a forwarded request
	// is init's pid, so anything reading MeterRecord.Caller must not assume it
	// identifies the requesting module for remote traffic.
	kpeers.forwardCtx = k.initCtx
	kpeers.mu.Unlock()

	kaudit.record(AuditPolicy, k.initCtx, "peer transport installed", nil)
	return nil
}

// PeerDial proves a peer's identity from the host process.
func (k *Kernel) PeerDial(spec PeerDialSpec) (PeerSession, error) {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return PeerSession{}, errors.New("kernel: already shut down")
	}
	return peerDial(k.initCtx, spec)
}

// PeerProbe measures one round trip from the host process.
func (k *Kernel) PeerProbe(fd FD, deadline int64) (PeerLatency, error) {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return PeerLatency{}, errors.New("kernel: already shut down")
	}
	return peerProbe(k.initCtx, fd, deadline)
}

// PeerForward sends one cross-node request from the host process.
func (k *Kernel) PeerForward(req PeerForwardRequest) (PeerForwardResult, error) {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return PeerForwardResult{}, errors.New("kernel: already shut down")
	}
	return peerForward(k.initCtx, req)
}

// PeerAnnounce publishes one discovery record from the host process.
func (k *Kernel) PeerAnnounce(a PeerAnnouncement) error {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return errors.New("kernel: already shut down")
	}
	return peerAnnounce(k.initCtx, a)
}

// PeerPeers lists the mesh table from the host process.
func (k *Kernel) PeerPeers() ([]PeerInfo, error) {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return nil, errors.New("kernel: already shut down")
	}
	return PeerTableSnapshot(), nil
}

// PeerDeliver is the ONLY inbound path for unsolicited frames.
//
// It is a method on the handle rather than a free function so that a module cannot
// inject a frame and have the kernel treat it as a peer's claim: a module never
// receives a *Kernel, and Boot refuses a second call, so module code cannot obtain
// one. That is the same reasoning events.go gives for having no post syscall, and it
// is load-bearing here in a way it is not there - an injectable frame is a forgeable
// mesh fact, and a forged announcement or forward is how remote work gets attributed
// to a node that never sent it.
//
// The frame body is bounded before it is decoded. Without that bound this call would
// json.Unmarshal host-fed bytes of any size, which is the same pin-the-kernel's-memory
// hole maxCallPayloadBytes closes in service.go, and unlike the syscall side there is
// no sealed quota in front of it.
func (k *Kernel) PeerDeliver(from string, frame PeerFrame) (PeerFrame, error) {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return PeerFrame{}, errors.New("kernel: already shut down")
	}
	return peerDeliver(k.initCtx, from, frame)
}

func peerDeliver(ctx *sContext, from string, frame PeerFrame) (PeerFrame, error) {
	if !knownPeerFrameKind(frame.Kind) {
		// An unknown kind is refused and never defaulted. This is the branch usage.go
		// exists to warn about: a default case here is where an unspecified frame
		// becomes an accepted one.
		peerRefuseForward(ctx, from, "", fmt.Sprintf("unknown frame kind %q", frame.Kind), 0)
		return PeerFrame{}, peerErr("unknown peer frame kind %q", frame.Kind)
	}
	if len(frame.Body) > maxPeerFrameBytes {
		peerRefuseForward(ctx, from, "", fmt.Sprintf(
			"frame body of %d bytes exceeds the ceiling %d", len(frame.Body), maxPeerFrameBytes), 0)
		return PeerFrame{}, peerLimit(ErrPeerLimit,
			"inbound frame body of %d bytes exceeds the ceiling %d", len(frame.Body), maxPeerFrameBytes)
	}

	switch frame.Kind {
	case PeerFrameProbe:
		return peerDeliverProbe(ctx, from, frame)
	case PeerFrameForward:
		return peerDeliverForward(ctx, from, frame)
	case PeerFrameAnnounce:
		var a PeerAnnouncement
		if err := json.Unmarshal(frame.Body, &a); err != nil {
			return PeerFrame{}, peerErr("announcement frame does not decode: %v", err)
		}
		if err := peerAnnounce(ctx, a); err != nil {
			return PeerFrame{}, err
		}
		return PeerFrame{}, nil
	case PeerFrameGoodbye:
		peerDeliverGoodbye(ctx, from)
		return PeerFrame{}, nil
	case PeerFrameHandshake, PeerFrameHandshakeReply,
		PeerFrameProbeReply, PeerFrameForwardReply:
		// Replies and handshake opens belong to an outbound exchange this node
		// started, and arriving here means the transport delivered one to the wrong
		// place. Accepting it would let a peer answer a question nobody asked.
		return PeerFrame{}, peerErr("frame kind %q is not accepted unsolicited", frame.Kind)
	}
	return PeerFrame{}, peerErr("unhandled peer frame kind %q", frame.Kind)
}

// peerDeliverProbe answers one inbound probe. The answer asserts nothing about this
// node beyond "it is alive", so it is not signed and no policy decision is made.
func peerDeliverProbe(ctx *sContext, from string, frame PeerFrame) (PeerFrame, error) {
	var body peerProbeBody
	if len(frame.Body) > 0 {
		if err := json.Unmarshal(frame.Body, &body); err != nil {
			return PeerFrame{}, peerErr("probe frame does not decode: %v", err)
		}
	}
	reply, err := json.Marshal(peerProbeBody{Version: PeerVersion, NodeID: from, Seq: body.Seq})
	if err != nil {
		return PeerFrame{}, fmt.Errorf("kernel: cannot encode probe reply: %w", err)
	}
	kpeers.recordEvent("probe-inbound", from, frame.Seq)
	return PeerFrame{Kind: PeerFrameProbeReply, Seq: frame.Seq, Body: reply}, nil
}

// peerDeliverGoodbye closes the local session with the peer that sent it. A goodbye
// from a node with no session is a no-op rather than an error, because the two
// teardown orders are both legitimate and a shutdown race should not read as a fault.
func peerDeliverGoodbye(ctx *sContext, from string) {
	kpeers.mu.RLock()
	conn, ok := kpeers.byNode[from]
	kpeers.mu.RUnlock()
	if !ok {
		return
	}
	conn.close("peer said goodbye", false)
}

// peerDeliverForward verifies one inbound cross-node request and dispatches it into
// the local route table.
//
// Verification happens before anything derived from the envelope reaches an audit
// record, and the string fields are validated at ingest. That ordering is the
// log-forgery control: a correctly-signed envelope from a trusted peer can still carry
// a route or trace containing a newline or a control rune, and those are written into
// audit fields verbatim. keyring.go's validAlias and service.go's normalizeRoutePath
// apply the same filter for the same reason, and applying it only after the first
// audit write would leave the hole open.
func peerDeliverForward(ctx *sContext, from string, frame PeerFrame) (PeerFrame, error) {
	var env PeerEnvelope
	if err := json.Unmarshal(frame.Body, &env); err != nil {
		return PeerFrame{}, peerErr("forward frame does not decode: %v", err)
	}

	if env.Version != PeerVersion {
		peerRefuseForward(ctx, from, env.Route, fmt.Sprintf(
			"unsupported peer version %d", env.Version), env.Hops)
		return PeerFrame{}, peerErr("unsupported peer version %d, this kernel issues %d",
			env.Version, PeerVersion)
	}
	if err := peerNodeID(env.FromNode); err != nil {
		peerRefuseForward(ctx, from, "", err.Error(), env.Hops)
		return PeerFrame{}, err
	}
	if err := peerRouteField(env.Route); err != nil {
		peerRefuseForward(ctx, env.FromNode, "", err.Error(), env.Hops)
		return PeerFrame{}, err
	}
	if err := peerTraceField(env.Trace); err != nil {
		peerRefuseForward(ctx, env.FromNode, env.Route, err.Error(), env.Hops)
		return PeerFrame{}, err
	}
	if err := peerMethodField(env.Method); err != nil {
		peerRefuseForward(ctx, env.FromNode, env.Route, err.Error(), env.Hops)
		return PeerFrame{}, err
	}

	// Relaying is refused, and that is the default rather than an omission. An
	// envelope addressed to another node would make this one an open relay, which is
	// how a mesh becomes an amplification target: the traffic is attributed to a node
	// that has no policy relationship with either end. maxPeerHops exists so the owner
	// can enable multi-hop later; enabling it is a policy decision, not a code tweak.
	nodeID, err := peerOwnNodeID()
	if err != nil {
		return PeerFrame{}, err
	}
	if env.ToNode != nodeID {
		peerRefuseForward(ctx, env.FromNode, env.Route,
			fmt.Sprintf("addressed to %q, not to this node", env.ToNode), env.Hops)
		return PeerFrame{}, &PeerError{
			Msg: fmt.Sprintf("forward is addressed to %q, not to this node %q", env.ToNode, nodeID),
			Err: ErrPeerLoop,
		}
	}
	if env.Hops > maxPeerHops {
		peerRefuseForward(ctx, env.FromNode, env.Route,
			fmt.Sprintf("hop count %d exceeds the ceiling %d", env.Hops, maxPeerHops), env.Hops)
		return PeerFrame{}, peerErr("forward hop count %d exceeds the ceiling %d", env.Hops, maxPeerHops)
	}
	if len(env.Payload) > maxPeerPayloadBytes {
		peerRefuseForward(ctx, env.FromNode, env.Route, fmt.Sprintf(
			"payload of %d bytes exceeds the ceiling %d", len(env.Payload), maxPeerPayloadBytes), env.Hops)
		return PeerFrame{}, peerLimit(ErrPeerLimit,
			"forward payload of %d bytes exceeds the ceiling %d", len(env.Payload), maxPeerPayloadBytes)
	}
	if sha256Sum(env.Payload) != env.PayloadHash {
		peerRefuseForward(ctx, env.FromNode, env.Route, "payload does not match its signed digest", env.Hops)
		return PeerFrame{}, peerErr("forward payload does not match its signed digest")
	}

	ok, keyID, err := verifyAgainstClusterRoots(PeerForwardDigest(env), env.Signature)
	if err != nil {
		// Unverifiable is not invalid. Returning a verdict this node cannot reach
		// would either excuse a forgery or accuse an honest peer, so a configuration
		// failure is an error and is reported as one.
		fault(ctx, "cannot verify inbound forward", map[string]any{
			"node_id": env.FromNode, "route": env.Route, "error": err.Error(),
		})
		return PeerFrame{}, err
	}
	if !ok {
		fault(ctx, "inbound forward failed verification", map[string]any{
			"node_id": env.FromNode, "key_id_claimed": env.KeyID, "route": env.Route,
		})
		kaudit.record(AuditEscalation, ctx, "inbound forward failed verification", map[string]any{
			"node_id": env.FromNode, "key_id_claimed": env.KeyID, "route": env.Route,
		})
		peerRefuseForward(ctx, env.FromNode, env.Route,
			"no sealed cluster root verifies this forward", env.Hops)
		return PeerFrame{}, &PeerError{
			Msg: fmt.Sprintf("forward from %q is not trusted", env.FromNode), Err: ErrPeerUntrusted,
		}
	}

	// Accepted, and recorded before the dispatch so the mesh fact and the dispatch
	// fact are separately attributable. RouteCall then writes its own AuditRequest
	// under the handler's context; this record is not a duplicate of it.
	kaudit.record(AuditPeer, ctx, "peer forward accepted", map[string]any{
		"node_id": env.FromNode, "key_id": keyID, "route": env.Route,
		"bytes": len(env.Payload), "trace": env.Trace, "hops": env.Hops,
	})
	kpeers.recordEvent("forward-inbound", env.FromNode, env.Seq)

	kpeers.mu.RLock()
	forwardCtx := kpeers.forwardCtx
	kpeers.mu.RUnlock()
	if forwardCtx == nil {
		return PeerFrame{}, peerErr("no forwarding context is installed; call PeerSetTransport")
	}

	// RouteCall re-checks route:call under forwardCtx and re-resolves the handler's
	// own context at dispatch, so this does not lend init's authority to the handler.
	//
	// CallerPID and CallerModule are deliberately not set here. RouteCall assigns both
	// from the calling context itself, because a caller-supplied identity would be
	// forgeable, and that is correct: it means a forwarded request reaches a handler
	// looking exactly like a local one from init. The consequence is worth stating
	// plainly rather than hiding - a handler CANNOT tell mesh traffic from local
	// traffic from the request alone. Mesh provenance lives on the audit chain in the
	// "peer forward accepted" record, which carries the sending node's id and is
	// written before the dispatch. Anything that needs to distinguish the two reads the
	// chain or the Trace, not CallerModule.
	resp, err := RouteCall(forwardCtx, RouteRequest{
		Path: env.Route, Trace: TraceID(env.Trace), Method: env.Method, Payload: env.Payload,
	})
	if err != nil {
		return PeerFrame{}, err
	}

	body, err := json.Marshal(resp)
	if err != nil {
		return PeerFrame{}, fmt.Errorf("kernel: cannot encode forward reply: %w", err)
	}
	if len(body) > maxPeerPayloadBytes {
		// Refused rather than truncated. A truncated reply is a wrong answer that
		// looks like a right one, and the caller cannot tell which it received.
		return PeerFrame{}, peerLimit(ErrPeerLimit,
			"forward reply of %d bytes exceeds the ceiling %d", len(body), maxPeerPayloadBytes)
	}

	kpeers.mu.Lock()
	kpeers.forwarded++
	kpeers.mu.Unlock()
	return PeerFrame{Kind: PeerFrameForwardReply, Seq: frame.Seq, Body: body}, nil
}

// peerRouteField validates an inbound route before it reaches an audit record.
// Length and charset are checked here; the absolute-path shape is enforced by
// RouteCall's normalizeRoutePath, and duplicating that check would mean two places to
// keep in agreement about what a path is.
func peerRouteField(route string) error {
	if route == "" {
		return peerErr("forward carries no route")
	}
	if len(route) > maxRoutePathLen {
		return peerErr("forward route of %d bytes exceeds the ceiling %d", len(route), maxRoutePathLen)
	}
	for _, r := range route {
		if r <= 0x20 || r >= 0x7f {
			return peerErr("forward route %q contains a control or non-ASCII character", route)
		}
	}
	return nil
}

// peerTraceField validates an inbound trace id. It must be exactly the shape
// ktrace mints - 32 lowercase hex characters - because a remote-chosen correlation id
// that could carry a newline could forge a log line, and one of arbitrary length could
// be stored in every record it touches.
func peerTraceField(trace string) error {
	if trace == "" {
		return nil
	}
	if len(trace) != traceIDBytes*2 {
		return peerErr("forward trace of %d bytes is not %d hex characters",
			len(trace), traceIDBytes*2)
	}
	for _, r := range trace {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isHex {
			return peerErr("forward trace %q is not lowercase hex", trace)
		}
	}
	return nil
}

// peerMethodField validates an inbound verb. It is remote-controlled data that lands in
// an audit field, so it gets the identifier filter rather than the label rule: unlike a
// label an operator typed, a method is chosen by a peer.
func peerMethodField(method string) error {
	if len(method) > maxPeerLabelLen {
		return peerErr("forward method of %d bytes exceeds the ceiling %d", len(method), maxPeerLabelLen)
	}
	for _, r := range method {
		if r <= 0x20 || r >= 0x7f {
			return peerErr("forward method %q contains a control or non-ASCII character", method)
		}
	}
	return nil
}

// resetPeers drops the mesh. Called only from resetKernel.
//
// Sessions are collected under the lock and closed outside it, because close
// re-enters the registry and broadcasting to a waiter from inside the lock is how a
// reset deadlocks - pipe.go's removePID comment spells the same rule out.
//
// The goodbye is suppressed on this path deliberately. The transport is dropped as
// part of the teardown, so a goodbye sent from here could never arrive, and emitting a
// fault per session would bury the fault stream on every routine shutdown of a full
// mesh. That is the failure the fault-level rule exists to prevent.
//
// Live sessions ARE closed here, which diverges from resetPipes. The reason is that
// the host path installs sessions into init's table and init never goes through
// UnloadModule, so reclamation would not otherwise reach them.
func resetPeers() {
	kpeers.mu.Lock()
	conns := make([]*peerConn, 0, len(kpeers.byNode))
	for _, c := range kpeers.byNode {
		conns = append(conns, c)
	}
	kpeers.byNode = map[string]*peerConn{}
	kpeers.seq = map[string]int64{}
	kpeers.seen = map[string]peerSeqState{}
	kpeers.epoch = 0
	kpeers.events = nil
	kpeers.eventEvicted = 0
	kpeers.announced, kpeers.accepted, kpeers.refused = 0, 0, 0
	kpeers.probes, kpeers.probeTimeouts = 0, 0
	kpeers.forwarded, kpeers.forwardRefused = 0, 0
	kpeers.inflightTotal = 0
	kpeers.transport = nil
	kpeers.forwardCtx = nil
	kpeers.mu.Unlock()

	for _, c := range conns {
		c.close("kernel reset", false)
	}
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

func (c *sContext) SyscallPeerDial(spec PeerDialSpec) (PeerSession, error) {
	return PeerDial(c, spec)
}
func (c *sContext) SyscallPeerAnnounce(a PeerAnnouncement) error { return PeerAnnounce(c, a) }
func (c *sContext) SyscallPeerProbe(fd FD, deadline int64) (PeerLatency, error) {
	return PeerProbe(c, fd, deadline)
}
func (c *sContext) SyscallPeerForward(req PeerForwardRequest) (PeerForwardResult, error) {
	return PeerForward(c, req)
}
func (c *sContext) SyscallPeerPeers() ([]PeerInfo, error) { return PeerPeers(c) }
