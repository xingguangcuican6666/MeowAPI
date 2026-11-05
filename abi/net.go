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

import "errors"

// Controlled egress: what a module declares, what a dial returns.

// ErrNetPeerClosed is what a read returns when the peer ended the connection, as opposed
// to the read failing for another reason.
//
// It exists because the two are different facts about the world and a module cannot
// otherwise tell them apart. SyscallNetRead reports a peer close as an error rather than
// as a zero-length read with no error, which is the right call for a socket syscall and
// the wrong one for a caller framing messages: "the vendor hung up" ends a
// close-delimited response cleanly, while "the read timed out" or "the connection was
// reset" means whatever bytes arrived are all there will ever be. Without a sentinel the
// only way to distinguish them is to match the error's text, and text is not a contract:
// rewording a message in the kernel would silently turn every adapter's clean-end
// handling into its failure handling.
//
// It is not io.EOF, and a module cannot test for that instead. io.EOF is the standard
// library's own value and the kernel's error is not it, because exposing io would make a
// module's import of this package a dependency on how the kernel happens to read sockets
// today.
//
// What the sentinel does NOT buy is a truncation check, and the limit is worth stating
// because it looks like one. Measured against both a plaintext and a TLS-terminated
// socket: a peer that sends a whole TLS record and then closes TCP reports io.EOF, whether
// or not it sent close_notify, so a peer that stops mid-message at a record boundary is
// indistinguishable from one that finished. A peer that tears a RECORD reports
// io.ErrUnexpectedEOF instead, which is not this sentinel and so reaches the caller as a
// plain failure. The framing above the transport is therefore what decides whether a
// response is whole: HTTPResponse.Truncated reports a Content-Length that was not
// satisfied or a chunked body with no terminating zero chunk, and that is the check to
// make before trusting a body, not the classification of the close.
var ErrNetPeerClosed = errors.New("abi: net: the peer closed the connection")

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
	// TLS asks the kernel to terminate TLS on this connection, so that what the module
	// reads and writes through the returned FD is application data rather than handshake
	// records.
	//
	// It is a field of the dial rather than a scheme, because Scheme describes the
	// transport this stack is willing to open and its allowlist was reviewed against
	// that meaning; adding "tls" there would make one field answer two questions and
	// leave a reviewer reading `scheme: tcp` unsure whether the bytes are encrypted.
	//
	// The module never holds a TLS connection and cannot configure one. The server name
	// is the Host it declared, the certificate is validated against that name, the
	// minimum version and the cipher suites are the kernel's choice, and ALPN is pinned
	// to HTTP/1.1 so the framing a module writes is the framing the peer agreed to.
	// There is no skip-verification switch anywhere in this ABI: a kernel that offered
	// one would offer a module a way to be intercepted, and the switch would live in
	// host configuration the module cannot read, so the failure would be invisible from
	// inside. A deployment behind an intercepting proxy installs that proxy's root.
	TLS bool `json:"tls,omitempty"`
}
