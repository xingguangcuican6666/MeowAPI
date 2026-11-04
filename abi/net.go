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

// Controlled egress: what a module declares, what a dial returns.

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
