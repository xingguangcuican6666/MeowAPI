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

package abi

// Mesh frames, dial specs and the session and latency readings.

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
