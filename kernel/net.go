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
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// knet: the controlled egress stack (subsystem: knet).
//
// What it is for. Every outbound connection a module makes is a chance to reach
// somewhere the operator did not approve: the cloud metadata endpoint at
// 169.254.169.254, another tenant's internal service, a loopback port belonging to the
// host, or an attacker's own server carrying data out. knet is the sanctioned path:
// allowlisted by the module's own signed declaration, address-validated after
// resolution, pooled, deadline-bounded, attributed to a pid, audited, and reclaimed when
// the module is unloaded.
//
// What it is not, stated plainly because AGENT.md requires it. This is a mandatory
// access control kernel, not a sandbox. An in-process module can call net.Dial from the
// standard library and nothing here stops it, because a Go function call is not a
// syscall the kernel mediates. What knet provides is that the sanctioned path is the
// only one that is allowlisted, bounded, attributed and audited - and that a module
// which goes around it leaves the audit chain without an egress record, which is itself
// the evidence. A deployment that needs real containment runs modules out of process or
// in a WASM tier, which AGENT.md defers as an open decision.
//
// The load-bearing control is the one that is easy to get wrong: hostname matching is
// not SSRF protection. A name can resolve to a private address, and a name can resolve
// to a different address between the check and the dial. So this file resolves first,
// validates every resolved address, and then dials an address it has already validated -
// with a second check inside the dialer's Control hook on the socket address the kernel
// is actually about to use. The Control check is what closes the rebinding window; the
// pre-check is what produces a readable refusal before a socket is opened.

// netError reports a refusal from this file's own surface, for the cases that are
// neither a policy denial nor an address refusal: a bad spec, a closed pool, a handle
// that is not a socket.
type netError struct{ Msg string }

func (e *netError) Error() string { return "kernel: net: " + e.Msg }

func netErr(format string, args ...any) error {
	return &netError{Msg: fmt.Sprintf(format, args...)}
}

// ErrNetAddressBlocked is what a dial to a refused address returns. It is a sentinel
// rather than only a message because it is the one refusal a caller should treat
// differently: retrying is pointless, the address will not become permitted, and a
// caller that sees this is either misconfigured or probing.
var ErrNetAddressBlocked = errors.New("kernel: net: the resolved address is in a blocked range")

// ErrNetHostNotAllowed is what a dial to an undeclared host returns. Distinct from
// ErrNetAddressBlocked because the two have different fixes: one is a declaration the
// module author did not make, the other is an address the deployment refuses no matter
// what any module declares.
var ErrNetHostNotAllowed = errors.New("kernel: net: the host is outside the declared boundary")

// netDialTimeout and netIOTimeout bound one dial and one read or write. They come from
// documented constants clamped by the sealed CallTimeoutMillis ceiling rather than from
// the caller, because a bound the dialing module supplies is not a bound: an unbounded
// dial is how one module holds a kernel worker indefinitely.
const (
	netDialTimeout = 5 * time.Second
	netIOTimeout   = 30 * time.Second
)

// maxNetConnsPerPID bounds one module's open sockets, and maxNetListenersPerPID bounds
// its listeners. Both are kernel constants: a ceiling a module could raise would not
// bound anything.
//
// They are separate from the fd table's MaxOpenFDsPerModule rather than redundant with
// it, because the two bound different scarcities. The fd ceiling bounds handles of any
// kind, so a module holding 64 pipes uses its whole allowance and opens no socket; a
// module holding 64 sockets has exhausted a resource that reaches outside the process.
// The general ceiling cannot express that distinction, and reporting a per-module socket
// bound this file did not enforce would tell an operator something false.
const (
	maxNetConnsPerPID     = 64
	maxNetListenersPerPID = 4
)

// maxNetListenersTotal bounds listeners across the kernel. A listener holds a port, and
// ports are a host resource a module does not get to exhaust; the per-module bound above
// is what stops one module from taking the whole allowance.
const maxNetListenersTotal = 32

// netMaxRecordBytes bounds what one read returns. A module asking for an unbounded read
// of a response it provoked is a way to exhaust kernel memory using the kernel's own
// socket.
const netMaxRecordBytes = 4 << 20

// maxNetHistory bounds the retained egress ledger.
const maxNetHistory = 2048

// netConn is one pooled or open socket, as an fd-table resource. It is reclaimed by
// reclaimFDs on unload, which is what makes a module that dies mid-request leak no
// descriptor.
type netConn struct {
	mu       sync.Mutex
	conn     net.Conn
	pid      PID
	remote   string
	addr     net.IP
	label    string
	closed   bool
	pooled   bool
	openedAt int64
	lastRTT  int64
	bytesIn  int64
	bytesOut int64
	// grant is the operation this socket was created under: OpNetDial for an outbound
	// connection, OpNetListen for an accepted one. Closing and I/O are gated on it rather
	// than on a fixed operation, because a listener-only module must be able to close what
	// it accepted. Requiring net:dial there would leak a descriptor for the life of the
	// module, and requiring both everywhere would make an outbound-only module declare a
	// listen address it never binds.
	grant Op
}

// Kind names the resource for the fd table and for the kind check that stops a module
// using a pipe handle as a socket.
func (n *netConn) Kind() string { return "socket" }

// Close releases the socket. It tolerates being called on an already-closed resource,
// because reclaimFDs and an explicit close can both arrive.
func (n *netConn) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	c := n.conn
	n.conn = nil
	n.mu.Unlock()

	netDropPooled(n)
	if c == nil {
		return nil
	}
	if err := c.Close(); err != nil {
		return fmt.Errorf("kernel: net: closing a socket: %w", err)
	}
	return nil
}

// netLive returns the underlying connection, or an error naming what happened. A socket
// closed by an unload must not be handed back to a caller as though it were usable.
func (n *netConn) netLive() (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.conn == nil {
		return nil, netErr("this socket is closed")
	}
	return n.conn, nil
}

// netListener is one bound listener, also an fd-table resource.
type netListener struct {
	mu     sync.Mutex
	l      net.Listener
	pid    PID
	addr   string
	closed bool
}

func (n *netListener) Kind() string { return "listener" }

func (n *netListener) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	l := n.l
	n.l = nil
	n.mu.Unlock()

	netState.mu.Lock()
	netState.listeners--
	netState.mu.Unlock()

	if l == nil {
		return nil
	}
	if err := l.Close(); err != nil {
		return fmt.Errorf("kernel: net: closing a listener: %w", err)
	}
	return nil
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

// netLedgerEntry is one egress record. Its fields mirror NetRecord exactly, so the
// snapshot is a conversion rather than a field-by-field copy that could drift.
type netLedgerEntry struct {
	Seq     int64  `json:"seq"`
	PID     PID    `json:"pid"`
	Module  string `json:"module,omitempty"`
	Host    string `json:"host"`
	Address string `json:"address,omitempty"`
	Outcome string `json:"outcome"`
	At      int64  `json:"at"`
}

type netLedger struct {
	mu        sync.Mutex
	entries   []netLedgerEntry
	seq       int64
	evicted   int64
	dialed    int64
	refused   int64
	blocked   int64
	listeners int
}

var netState = netLedger{}

// netPrivateAllowed is the host's opt-in for private ranges. It exists because operators
// do run internal providers, and refusing 10/8 unconditionally would push them to
// disable the whole subsystem rather than grant one range. The opt-in is host-side, never
// module-side: a module that could allowlist 169.254.169.254 for itself has defeated the
// control.
type netPrivateState struct {
	mu      sync.RWMutex
	nets    []*net.IPNet
	enabled bool
}

var netPrivate = netPrivateState{}

// NetAllowPrivateRanges installs the host's opt-in for specific private ranges, given as
// CIDR strings. It replaces any previous set, because accumulating opt-ins across a
// process lifetime is how a deployment ends up permitting ranges nobody approved.
//
// Call it AFTER Boot and before loading modules. Boot runs resetKernel, which clears this
// along with every other piece of kernel state, so a range configured before booting is
// silently gone by the time a module dials. It belongs in BootConfig beside TrustRoot so
// the ordering cannot be gotten wrong; until it is there, this is the contract, and
// NetPrivateRanges is how a deployment checks it was applied.
//
// Loopback, link-local and the metadata address are refused even when named here, and the
// refusal is not a policy question: 169.254.169.254 is the cloud metadata endpoint and
// 127.0.0.1 is the host itself, and a deployment that needs either has a different
// problem than this subsystem solves.
func NetAllowPrivateRanges(cidrs []string) error {
	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return netErr("%q is not a CIDR range: %v", c, err)
		}
		if netRangeIsNeverAllowed(n) {
			return netErr("%q covers loopback, link-local or the metadata address, which no opt-in can permit", c)
		}
		parsed = append(parsed, n)
	}

	netPrivate.mu.Lock()
	netPrivate.nets = parsed
	netPrivate.enabled = len(parsed) > 0
	netPrivate.mu.Unlock()

	// Audited with the ranges named, because this is a widening of what every module can
	// reach and an investigator needs to know it happened and when.
	kaudit.record(AuditPolicy, nil, "private egress ranges configured", map[string]any{
		"ranges": cidrs, "count": len(parsed),
	})
	fault(nil, "private egress ranges configured", map[string]any{"ranges": cidrs})
	return nil
}

// NetPrivateRanges reports the host's current opt-in, as CIDR strings, sorted.
func NetPrivateRanges() []string {
	netPrivate.mu.RLock()
	defer netPrivate.mu.RUnlock()
	out := make([]string, 0, len(netPrivate.nets))
	for _, n := range netPrivate.nets {
		out = append(out, n.String())
	}
	sort.Strings(out)
	return out
}

// netRangeIsNeverAllowed refuses the ranges no opt-in may cover.
func netRangeIsNeverAllowed(n *net.IPNet) bool {
	for _, probe := range []string{"127.0.0.1", "::1", "169.254.169.254", "169.254.0.1", "0.0.0.0"} {
		if ip := net.ParseIP(probe); ip != nil && n.Contains(ip) {
			return true
		}
	}
	// A range wider than a /8 covering private space is not an opt-in, it is a surrender.
	if ones, bits := n.Mask.Size(); bits > 0 && ones < 8 {
		return true
	}
	return false
}

// netAddressAllowed is the address decision, and it is the heart of this file. It is a
// pure function of an IP and the host's configuration so it can be tested directly
// against every range that matters, without opening a socket.
func netAddressAllowed(ip net.IP) error {
	if ip == nil {
		return netErr("the host did not resolve to an address")
	}
	// The cloud metadata address is checked FIRST, ahead of the general ranges, because
	// it is link-local and so the general test would catch it and the specific message
	// would never be produced. Naming it matters: an operator reading "blocked: link-local"
	// for 169.254.169.254 learns that a range was refused, while "blocked: the cloud
	// metadata endpoint" tells them a module tried to read instance credentials, which is
	// a different incident with a different response. The ordering is what makes that
	// message reachable rather than dead code.
	if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return fmt.Errorf("%w: %s is the cloud metadata endpoint", ErrNetAddressBlocked, ip)
	}

	// Unspecified, loopback, link-local and multicast are refused outright. The
	// unspecified address is included because dialing 0.0.0.0 reaches the host's own
	// listeners on some stacks, which is loopback by another name.
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return fmt.Errorf("%w: %s is loopback, link-local, multicast or unspecified", ErrNetAddressBlocked, ip)
	}

	if !ip.IsPrivate() {
		return nil
	}

	netPrivate.mu.RLock()
	defer netPrivate.mu.RUnlock()
	if !netPrivate.enabled {
		return fmt.Errorf("%w: %s is private and no private range is configured", ErrNetAddressBlocked, ip)
	}
	for _, n := range netPrivate.nets {
		if n.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is private and outside the configured ranges", ErrNetAddressBlocked, ip)
}

// NetHostAllowed reports whether a host is inside a module's declared boundary. It is
// exported because knet is not the only place an egress decision is made: kpeer dials
// mesh endpoints under the same declaration, and two implementations of "is this host
// permitted" will disagree.
//
// An empty AllowedHosts permits nothing, which is deny-by-default and matches
// validateHost's comment in manifest.go.
func NetHostAllowed(pid PID, host string) error {
	if host == "" {
		return netErr("a dial needs a host")
	}
	manifest, live := manifestOf(pid)
	if !live {
		// Not live means the caller has no declaration to check against. That includes
		// the host's own init path, which has no manifest, so init is handled by the
		// caller rather than exempted here: exempting a domain inside this function
		// would make the boundary depend on who is asking rather than on what was
		// declared.
		return netErr("this context has no declared network boundary")
	}
	host = netNormalizeHost(host)
	for _, allowed := range manifest.AllowedHosts {
		if allowed == "" {
			// An empty entry would match everything, so it is skipped rather than
			// honoured. keyring.go's aliasInScope skips an empty prefix for the same
			// reason, and manifest validation already refuses an empty host.
			continue
		}
		if host == netNormalizeHost(allowed) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q is not declared in allowed_hosts", ErrNetHostNotAllowed, host)
}

// netNormalizeHost lowercases and strips a trailing dot, so "Example.COM." and
// "example.com" are the same host. DNS is case-insensitive and a trailing dot is the
// fully-qualified spelling of the same name; treating them as different would let a
// module reach an undeclared host by respelling a declared one.
func netNormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	return h
}

// netCheckSpec validates a dial request before anything is resolved. It is deliberately
// narrow: a scheme the allowlist was never reviewed against is a scheme this file does
// not dial.
func netCheckSpec(s NetSpec) error {
	if s.Host == "" {
		return netErr("a dial needs a host")
	}
	if strings.ContainsAny(s.Host, "/@?#") {
		return netErr("host %q must be a bare hostname, without scheme, port, path, userinfo or fragment", s.Host)
	}
	// An IP literal is refused rather than resolved. The declaration is a list of
	// hostnames, so a module dialing an address is dialing something no reviewer saw,
	// and resolving an IP literal to itself would let an address pass a hostname check.
	if net.ParseIP(s.Host) != nil {
		return netErr("host %q is an address, and the declared boundary is a list of hostnames", s.Host)
	}
	if s.Port < 0 || s.Port > 65535 {
		return netErr("port %d is not a port", s.Port)
	}
	switch s.Scheme {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return netErr("scheme %q is not dialable here; this stack dials TCP only", s.Scheme)
	}
	if len(s.Label) > maxUsageLabelLen {
		return netErr("label of %d bytes exceeds the ceiling %d", len(s.Label), maxUsageLabelLen)
	}
	if strings.ContainsAny(s.Label, "\n\r") {
		return netErr("a label must not contain a newline")
	}
	return nil
}

// netRecord writes one egress record to the bounded ledger.
func netRecord(pid PID, module, host, address, outcome string) {
	netState.mu.Lock()
	netState.seq++
	netState.entries = append(netState.entries, netLedgerEntry{
		Seq: netState.seq, PID: pid, Module: module, Host: host,
		Address: address, Outcome: outcome, At: mono(),
	})
	switch {
	case outcome == "dialed":
		netState.dialed++
	case strings.HasPrefix(outcome, "blocked"):
		netState.blocked++
	default:
		netState.refused++
	}
	// Trim after the insert, the way kmeter's ledger does. Trimming before it cannot
	// work: at exactly the bound the ledger is still within it, so the trim is a no-op
	// and the insert takes it one past the ceiling on every dial afterwards.
	netState.trimLocked()
	netState.mu.Unlock()
}

// netTrimLocked drops the ledger back to seven eighths of its bound in ONE step. Caller
// holds netState.mu.
//
// Trimming exactly to the bound would reallocate and copy the whole ledger on every
// insert past the ceiling, under the write lock, which is a quadratic cost on the hot
// path of every outbound request.
func (l *netLedger) trimLocked() {
	if len(l.entries) <= maxNetHistory {
		return
	}
	keep := maxNetHistory - maxNetHistory/8
	if len(l.entries) <= keep {
		return
	}
	over := len(l.entries) - keep
	l.evicted += int64(over)
	l.entries = append([]netLedgerEntry(nil), l.entries[over:]...)
}

// NetDial opens one outbound connection. Requires net:dial, a declared host, and a
// resolved address that the deployment permits.
//
// The order is the control and each step has a reason:
//
//  1. The policy gate. Without it nothing else matters.
//  2. The spec check, before any DNS query, because resolving a host this file will not
//     dial anyway is a query an attacker could use to probe a resolver.
//  3. The declared-boundary check, before resolution, for the same reason and because
//     the declaration is what a reviewer signed.
//  4. Resolution, then validation of EVERY resolved address. A name with two A records,
//     one public and one private, is refused: dialing the first valid one would make the
//     answer depend on resolver ordering, which the module's counterparty controls.
//  5. A dial to the validated literal address, with a Control hook that re-checks the
//     socket address the kernel is about to use. Step 4 and step 5 are separated by a
//     DNS TTL, and a hostile resolver can return a public address first and a private one
//     second. The Control check is what makes the window close rather than merely
//     narrow.
func NetDial(ctx SContext, spec NetSpec) (NetDialResult, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return NetDialResult{}, errForeignContext
	}
	if err := c.syscall(OpNetDial); err != nil {
		return NetDialResult{}, err
	}
	return netDial(c, spec)
}

func netDial(c *sContext, spec NetSpec) (NetDialResult, error) {
	if err := netCheckSpec(spec); err != nil {
		netRefuse(c, spec.Host, "", "refused: "+err.Error())
		return NetDialResult{}, err
	}
	if err := NetHostAllowed(c.pid, spec.Host); err != nil {
		// A dial to an undeclared host is an attempt to act beyond a grant, so it is
		// escalated rather than only faulted: a module probing its own boundary is
		// evidence about the module.
		netEscalate(c, spec.Host, "", "host outside the declared boundary")
		netRefuse(c, spec.Host, "", "refused: host not declared")
		// Returned as the sentinel carrying the denial, not as a denial carrying the
		// sentinel in its Reason string. DeniedError has no Unwrap, so flattening the
		// cause into a message would make errors.Is unable to see which of the two
		// refusals this was - and telling "you may not dial at all" apart from "that
		// host is not yours" is the whole point of having two sentinels.
		return NetDialResult{}, fmt.Errorf("%w: %w", err,
			&DeniedError{Op: OpNetDial, Ctx: c, Reason: err.Error()})
	}

	// The instance filter runs AFTER the manifest boundary, never before. The layers are
	// ceiling, scope, filter, and a filter consulted first would have its answer stand in
	// for a declaration that was never checked - which is the widening the filter exists to
	// be unable to do. See seccomp.go for the ordering rule.
	if err := SeccompAllow(c, OpNetDial, spec.Host); err != nil {
		netRefuse(c, spec.Host, "", "refused: outside the instance filter")
		return NetDialResult{}, err
	}

	// Pooled connections are returned before resolution, because a socket already open to
	// a validated address needs no second decision. The pool is keyed on the resolved
	// address rather than the name, so a name that starts resolving somewhere else does
	// not inherit a connection to where it used to point.
	if pooled, found := netTakePooled(c.pid, spec.Host, spec.Port); found {
		netRecord(c.pid, c.name, spec.Host, pooled.address, "dialed: pooled")
		return NetDialResult{
			FD: pooled.fd, Host: spec.Host, Address: pooled.address, Pooled: true,
			RTT: pooled.rtt,
		}, nil
	}

	port := spec.Port
	if port == 0 {
		// The kernel chooses the default rather than the caller, so a module cannot reach
		// an arbitrary port by omitting one.
		port = 443
	}

	addrs, err := netLookup(netRootContext(), netNormalizeHost(spec.Host))
	if err != nil {
		netRefuse(c, spec.Host, "", "refused: resolution failed")
		return NetDialResult{}, netErr("resolving %q failed: %v", spec.Host, err)
	}
	if len(addrs) == 0 {
		netRefuse(c, spec.Host, "", "refused: no addresses")
		return NetDialResult{}, netErr("%q resolved to no address", spec.Host)
	}

	// EVERY resolved address is validated, and one refusal refuses the dial. Accepting
	// the first permitted address would make the outcome depend on resolver ordering,
	// which is controlled by whoever runs the authoritative server for that name.
	for _, a := range addrs {
		if aerr := netAddressAllowed(a.IP); aerr != nil {
			netEscalate(c, spec.Host, a.IP.String(), aerr.Error())
			netRefuse(c, spec.Host, a.IP.String(), "blocked: "+aerr.Error())
			return NetDialResult{}, aerr
		}
	}

	target := net.JoinHostPort(addrs[0].IP.String(), strconv.Itoa(port))
	start := mono()

	dialer := &net.Dialer{
		Timeout: netClampedTimeout(netDialTimeout, c),
		// Control runs after the kernel has chosen a socket address and before it
		// connects. Re-checking here is the difference between narrowing the rebinding
		// window and closing it: whatever address the dialer is actually about to use is
		// validated, not whatever the resolver returned a moment earlier.
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, herr := net.SplitHostPort(address)
			if herr != nil {
				return netErr("the dialer produced an unparseable address %q", address)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return netErr("the dialer produced a non-literal address %q", host)
			}
			if cerr := netAddressAllowed(ip); cerr != nil {
				netEscalate(c, spec.Host, ip.String(), "control hook: "+cerr.Error())
				return cerr
			}
			return nil
		},
	}

	scheme := spec.Scheme
	if scheme == "" {
		scheme = "tcp"
	}
	raw, err := dialer.DialContext(netRootContext(), scheme, target)
	if err != nil {
		// A Control-hook refusal arrives wrapped, so the sentinel is preserved for the
		// caller and the record says which step refused.
		if errors.Is(err, ErrNetAddressBlocked) {
			netRefuse(c, spec.Host, target, "blocked at dial")
			return NetDialResult{}, err
		}
		netRefuse(c, spec.Host, target, "refused: dial failed")
		return NetDialResult{}, netErr("dialing %s failed: %v", target, err)
	}
	rtt := mono() - start

	if n := netSocketCount(c.pid); n >= maxNetConnsPerPID {
		// Closed after the dial succeeded rather than refused before it, which costs one
		// connection and is the honest order: the address was permitted, so the refusal is
		// about this module's own consumption rather than about where it asked to go.
		_ = raw.Close()
		err := netErr("this module holds %d sockets, at the ceiling %d", n, maxNetConnsPerPID)
		fault(c, "egress refused at the per-module socket ceiling", map[string]any{
			"module": c.name, "host": spec.Host, "sockets": n, "ceiling": maxNetConnsPerPID,
		})
		netRefuse(c, spec.Host, target, "refused: socket ceiling")
		return NetDialResult{}, err
	}

	conn := &netConn{
		conn: raw, pid: c.pid, remote: target, addr: addrs[0].IP,
		label: spec.Label, openedAt: mono(), lastRTT: rtt, grant: OpNetDial,
	}
	fd, err := install(c.pid, conn, netLabelFor(spec, target))
	if err != nil {
		_ = raw.Close()
		netRefuse(c, spec.Host, target, "refused: "+err.Error())
		return NetDialResult{}, err
	}

	netRecord(c.pid, c.name, spec.Host, target, "dialed")
	kaudit.record(AuditPeer, c, "egress dial", map[string]any{
		"module": c.name, "host": spec.Host, "address": target, "rtt_nanos": rtt,
	})
	return NetDialResult{FD: fd, Host: spec.Host, Address: target, RTT: rtt}, nil
}

// netSocketCount counts the sockets a pid holds, from the fd table's own kind index
// rather than from a counter this file maintains. Counting here as well would give two
// numbers that could disagree, and the one an operator can check against FDList is the
// one that should decide.
func netSocketCount(pid PID) int {
	n := 0
	for _, f := range FDList(pid) {
		if f.Kind == "socket" {
			n++
		}
	}
	return n
}

// netListenerCount counts the listeners a pid holds, the same way and for the same
// reason.
func netListenerCount(pid PID) int {
	n := 0
	for _, f := range FDList(pid) {
		if f.Kind == "listener" {
			n++
		}
	}
	return n
}

// netLabelFor builds the fd-table label. It is operator-visible text, so it carries the
// host and the address actually dialed: a label naming only the host would hide the fact
// that a name resolved somewhere unexpected.
func netLabelFor(spec NetSpec, target string) string {
	if spec.Label == "" {
		return spec.Host + " -> " + target
	}
	return spec.Label + " " + spec.Host + " -> " + target
}

// NetResolver resolves a hostname to addresses. The host installs one, following the same
// shape as PeerTransport: an I/O dependency the kernel cannot supply itself is injected
// by the party that owns the process, and the default is the system resolver.
//
// The reason this is an injection point rather than a direct call is a threat, not
// testability, though it buys both. A hostile resolver is the attacker in a DNS rebinding
// attack, and the refusal that closes the rebinding window - validating the socket address
// inside the dialer's Control hook - is worthless if it cannot be exercised against a name
// that resolves somewhere forbidden. With the resolver injectable, that refusal is tested
// against exactly the adversary it was written for.
type NetResolver interface {
	// LookupIPAddr resolves one hostname. It must return every address the name has:
	// net.go validates all of them and refuses the dial if any is blocked, so a resolver
	// that returns only its favourite answer turns that check into a formality.
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// netSystemResolver is the default: the Go resolver over the platform's configuration.
type netSystemResolver struct{}

func (netSystemResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

type netResolverState struct {
	mu sync.RWMutex
	r  NetResolver
}

var netResolver = netResolverState{r: netSystemResolver{}}

// NetSetResolver installs the host's resolver. A nil resolver restores the system default
// rather than being refused, because "use the platform resolver" is a legitimate
// configuration and not a mistake; kpeer refuses a nil transport instead, and the
// difference is that a peer transport has no sensible default while a resolver does.
func (k *Kernel) NetSetResolver(r NetResolver) error {
	if err := k.hostOnly(); err != nil {
		return err
	}
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return errors.New("kernel: already shut down")
	}
	netResolver.mu.Lock()
	defer netResolver.mu.Unlock()
	if r == nil {
		netResolver.r = netSystemResolver{}
		return nil
	}
	netResolver.r = r
	kaudit.record(AuditPolicy, nil, "egress resolver installed", map[string]any{
		"resolver": fmt.Sprintf("%T", r),
	})
	return nil
}

// netLookup resolves through the installed resolver.
func netLookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	netResolver.mu.RLock()
	r := netResolver.r
	netResolver.mu.RUnlock()
	if r == nil {
		r = netSystemResolver{}
	}
	return r.LookupIPAddr(ctx, host)
}

// netRootContext is the context resolution and dialing run under. It carries no deadline
// and no cancellation, deliberately: the bound is the dialer's Timeout, which
// netClampedTimeout derives from the sealed ceiling, and a second deadline from a
// different source would make the effective bound whichever fired first. Nothing
// caller-supplied reaches this, so a module cannot cancel its own dial to hide a refusal.
func netRootContext() context.Context { return context.Background() }

// netClampedTimeout bounds a wait by the sealed ceiling. A module cannot lengthen it, and
// a deployment that sealed a short ceiling gets short dials.
func netClampedTimeout(want time.Duration, c *sContext) time.Duration {
	ceiling := Limits().CallTimeoutMillis
	if ceiling <= 0 {
		return want
	}
	max := time.Duration(ceiling) * time.Millisecond
	if want > max {
		return max
	}
	return want
}

// netRefuse records a refusal and faults it with the caller's context, never nil. A
// refusal attributed to nobody is a refusal an operator cannot act on.
func netRefuse(c *sContext, host, address, outcome string) {
	fault(c, "egress refused", map[string]any{
		"module": c.name, "host": host, "address": address, "outcome": outcome,
	})
	netRecord(c.pid, c.name, host, address, outcome)
}

// netEscalate records an attempt to reach past a grant. It is separate from netRefuse
// because the two answer different questions: a refusal says what did not happen, an
// escalation says what the module tried.
func netEscalate(c *sContext, host, address, reason string) {
	kaudit.record(AuditEscalation, c, "egress outside the declared boundary", map[string]any{
		"module": c.name, "op": string(OpNetDial), "host": host,
		"address": address, "reason": reason,
	})
}

// ---------------------------------------------------------------------------
// The connection pool.

// netPoolKey identifies a pooled socket. It is the resolved address, not the hostname,
// for the reason NetDial gives: a name that starts resolving somewhere else must not
// inherit a connection to where it used to point.
type netPoolKey struct {
	pid     PID
	address string
}

type netPoolEntry struct {
	conn *netConn
	fd   FD
	// address is the host:port this socket is connected to, copied from the conn at
	// pool time so a caller can report what it was handed without reaching into the
	// socket.
	address string
	rtt     int64
	idledAt int64
}

type netPoolState struct {
	mu     sync.Mutex
	byKey  map[netPoolKey][]*netPoolEntry
	byConn map[*netConn]*netPoolEntry
	byPid  map[PID]int
	total  int
}

var netPool = netPoolState{
	byKey:  map[netPoolKey][]*netPoolEntry{},
	byConn: map[*netConn]*netPoolEntry{},
	byPid:  map[PID]int{},
}

// maxNetPooledPerPID bounds one module's idle sockets. An idle socket still holds a
// descriptor on the far side, so an unbounded pool is a way to hold a provider's
// connection table open from a module that is doing no work.
const maxNetPooledPerPID = 8

// NetRelease returns a socket to the pool instead of closing it. Requires net:dial,
// because the socket was opened under that grant and returning it is part of the same
// operation rather than a new one.
//
// A socket whose owner has changed hands is closed rather than pooled. Pooling is keyed
// on pid, so a socket handed to another module - which this kernel does not do today, but
// a future grant might - must not be returned to a pool the new owner can draw from.
func NetRelease(ctx SContext, fd FD) error {
	// contextOf rather than a bare assertion: netSocketForOp resolves the fd through
	// netSocketFor, which reads c.pid before it reaches c.syscall.
	c, err := contextOf(ctx)
	if err != nil {
		return err
	}
	conn, err := netSocketForOp(c, fd)
	if err != nil {
		return err
	}
	if conn.pid != c.pid {
		_ = closeFD(c.pid, fd)
		return netErr("this socket belongs to another pid and is closed rather than pooled")
	}

	netPool.mu.Lock()
	if netPool.byPid[c.pid] >= maxNetPooledPerPID {
		netPool.mu.Unlock()
		// Closed rather than refused: the caller's intent was to stop using the socket,
		// and failing that intent because the pool is full would leave the descriptor
		// open, which is the opposite of what a bounded pool is for.
		_ = closeFD(c.pid, fd)
		netRecord(c.pid, c.name, conn.remote, conn.remote, "released: pool full, closed")
		return nil
	}
	key := netPoolKey{pid: c.pid, address: conn.remote}
	pooled := &netPoolEntry{
		conn: conn, fd: fd, address: conn.remote, rtt: conn.lastRTT, idledAt: mono(),
	}
	netPool.byKey[key] = append(netPool.byKey[key], pooled)
	netPool.byConn[conn] = pooled
	netPool.byPid[c.pid]++
	netPool.total++
	conn.pooled = true
	netPool.mu.Unlock()

	netRecord(c.pid, c.name, conn.remote, conn.remote, "released: pooled")
	return nil
}

// netTakePooled draws a socket from the pool. The address is re-validated on the way out,
// because a host opt-in can be narrowed between the release and the reuse and a socket to
// a now-refused range must not be handed back.
func netTakePooled(pid PID, host string, port int) (netPoolEntry, bool) {
	if port == 0 {
		port = 443
	}
	netPool.mu.Lock()
	defer netPool.mu.Unlock()

	// One pass to find the key, then one action. Ranging and mutating in the same loop
	// would leave the iteration visiting keys this call has already decided about, and
	// closing an fd while holding the pool lock is what the two-phase shape avoids.
	var (
		chosen    netPoolKey
		takeable  []*netPoolEntry
		stale     netPoolKey
		staleList []*netPoolEntry
	)
	// One decision per key and no early exit, so the loop cannot leave a variable set by
	// an iteration it then abandoned.
	for key, entries := range netPool.byKey {
		if key.pid != pid || len(entries) == 0 {
			continue
		}
		if portFromAddress(key.address) != port {
			continue
		}
		hostOnly, _, err := net.SplitHostPort(key.address)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(hostOnly); ip != nil && netAddressAllowed(ip) == nil {
			chosen, takeable = key, entries
			continue
		}
		// The range this socket points into is no longer permitted, which happens when a
		// host opt-in is narrowed between the release and the reuse. The entry is dropped
		// rather than left idle, because a pooled socket to a refused range is a socket
		// that will be handed back to a caller later.
		stale, staleList = key, entries
	}

	if len(staleList) > 0 {
		delete(netPool.byKey, stale)
		netPool.byPid[pid] -= len(staleList)
		netPool.total -= len(staleList)
		for _, e := range staleList {
			delete(netPool.byConn, e.conn)
		}
		// Closed outside the lock: closeFD takes the fd table's lock, and nesting it
		// inside the pool lock would fix an order across two subsystems for no benefit.
		netPool.mu.Unlock()
		for _, e := range staleList {
			_ = closeFD(pid, e.fd)
		}
		netPool.mu.Lock()
		return netPoolEntry{}, false
	}
	if len(takeable) == 0 {
		return netPoolEntry{}, false
	}

	entries := takeable
	taken := entries[len(entries)-1]
	rest := entries[:len(entries)-1]
	if len(rest) == 0 {
		delete(netPool.byKey, chosen)
	} else {
		netPool.byKey[chosen] = rest
	}
	delete(netPool.byConn, taken.conn)
	netPool.byPid[pid]--
	netPool.total--
	taken.conn.pooled = false
	return *taken, true
}

// portFromAddress reads the port out of a host:port string, or -1.
func portFromAddress(address string) int {
	_, p, err := net.SplitHostPort(address)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return -1
	}
	return n
}

// netDropPooled removes a socket from the pool when it is closed by any path, including
// reclaimFDs on unload. Without it a closed socket would stay drawable.
func netDropPooled(conn *netConn) {
	netPool.mu.Lock()
	defer netPool.mu.Unlock()
	entry, ok := netPool.byConn[conn]
	if !ok {
		return
	}
	delete(netPool.byConn, conn)
	key := netPoolKey{pid: conn.pid, address: conn.remote}
	entries := netPool.byKey[key]
	out := entries[:0]
	for _, e := range entries {
		if e != entry {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		delete(netPool.byKey, key)
	} else {
		netPool.byKey[key] = out
	}
	if netPool.byPid[conn.pid] > 0 {
		netPool.byPid[conn.pid]--
	}
	if netPool.total > 0 {
		netPool.total--
	}
}

// netDropAllFor closes and forgets every pooled socket a pid holds. Called on unload,
// beside the other per-pid drops, so a module that dies leaves no idle socket behind.
func netDropAllFor(pid PID) {
	netPool.mu.Lock()
	var doomed []*netPoolEntry
	for key, entries := range netPool.byKey {
		if key.pid != pid {
			continue
		}
		doomed = append(doomed, entries...)
		delete(netPool.byKey, key)
	}
	for _, e := range doomed {
		delete(netPool.byConn, e.conn)
	}
	netPool.byPid[pid] = 0
	netPool.total -= len(doomed)
	netPool.mu.Unlock()

	for _, e := range doomed {
		_ = closeFD(pid, e.fd)
	}
}

// ---------------------------------------------------------------------------
// I/O over an open socket.

// NetWrite sends bytes over an open socket under a mandatory deadline. Requires
// net:dial, because the socket exists under that grant.
func NetWrite(ctx SContext, fd FD, data []byte) (int, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return 0, errForeignContext
	}
	conn, err := netSocketForOp(c, fd)
	if err != nil {
		return 0, err
	}
	raw, err := conn.netLive()
	if err != nil {
		return 0, err
	}
	if len(data) > netMaxRecordBytes {
		return 0, netErr("a write of %d bytes exceeds the ceiling %d", len(data), netMaxRecordBytes)
	}
	if err := raw.SetWriteDeadline(time.Now().Add(netClampedTimeout(netIOTimeout, c))); err != nil {
		return 0, netErr("setting a write deadline failed: %v", err)
	}
	n, err := raw.Write(data)
	conn.mu.Lock()
	conn.bytesOut += int64(n)
	conn.mu.Unlock()
	if err != nil {
		return n, netErr("writing to %s failed: %v", conn.remote, err)
	}
	return n, nil
}

// NetRead receives bytes under a mandatory deadline and a size ceiling. Requires
// net:dial.
//
// The ceiling is a kernel constant rather than a caller-supplied length, because the
// caller is the module: an unbounded read of a response the module itself provoked is a
// way to exhaust kernel memory using the kernel's own socket.
func NetRead(ctx SContext, fd FD, limit int) ([]byte, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	conn, err := netSocketForOp(c, fd)
	if err != nil {
		return nil, err
	}
	raw, err := conn.netLive()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > netMaxRecordBytes {
		return nil, netErr("a read limit of %d is outside 1..%d", limit, netMaxRecordBytes)
	}
	if err := raw.SetReadDeadline(time.Now().Add(netClampedTimeout(netIOTimeout, c))); err != nil {
		return nil, netErr("setting a read deadline failed: %v", err)
	}
	buf := make([]byte, limit)
	n, err := raw.Read(buf)
	conn.mu.Lock()
	conn.bytesIn += int64(n)
	conn.mu.Unlock()
	if n > 0 && err != nil && !errors.Is(err, net.ErrClosed) {
		// Bytes arrived and the connection then failed. Returning both is honest; the
		// caller decides whether a partial read is useful.
		return buf[:n], netErr("reading from %s failed after %d bytes: %v", conn.remote, n, err)
	}
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil, netErr("this socket is closed")
		}
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return nil, netErr("reading from %s timed out after %s", conn.remote, netClampedTimeout(netIOTimeout, c))
		}
		return nil, netErr("reading from %s failed: %v", conn.remote, err)
	}
	return buf[:n], nil
}

// netSocketFor looks up an fd, kind-checks it, and gates the operation on the grant this
// socket was created under. The kind check is what stops a module passing a pipe handle
// here and getting a socket's behaviour on a pipe's resource; the grant check is what
// lets a listener-only module close what it accepted without also declaring net:dial.
func netSocketFor(c *sContext, fd FD) (*netConn, error) {
	// Guarded here rather than at each caller, for the reason fsRootFor gives: lookup takes
	// c.pid, and every socket operation reaches it through this function.
	if c == nil {
		return nil, errForeignContext
	}
	entry, err := lookup(c.pid, fd)
	if err != nil {
		return nil, err
	}
	conn, ok := entry.res.(*netConn)
	if !ok {
		return nil, netErr("fd %d is a %s, not a socket", fd, entry.kind)
	}
	if conn.pid != c.pid {
		return nil, netErr("fd %d belongs to another pid", fd)
	}
	return conn, nil
}

// netSocketForOp is netSocketFor plus the policy check for the grant that created this
// socket. Socket operations route through it rather than calling c.syscall with a fixed
// operation, so the gate matches the resource instead of the call site.
func netSocketForOp(c *sContext, fd FD) (*netConn, error) {
	conn, err := netSocketFor(c, fd)
	if err != nil {
		return nil, err
	}
	if err := c.syscall(conn.grant); err != nil {
		return nil, err
	}
	return conn, nil
}

// NetClose closes a socket without pooling it.
func NetClose(ctx SContext, fd FD) error {
	// contextOf for the reason NetRelease gives.
	c, err := contextOf(ctx)
	if err != nil {
		return err
	}
	if _, err := netSocketForOp(c, fd); err != nil {
		return err
	}
	return closeFD(c.pid, fd)
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

// NetSockets lists the sockets a pid holds, sorted by fd. It is a copy.
func NetSockets(pid PID) []NetInfo {
	out := make([]NetInfo, 0, 4)
	for _, f := range FDList(pid) {
		if f.Kind != "socket" {
			continue
		}
		entry, err := lookup(pid, f.FD)
		if err != nil {
			continue
		}
		conn, ok := entry.res.(*netConn)
		if !ok {
			continue
		}
		conn.mu.Lock()
		out = append(out, NetInfo{
			FD: f.FD, PID: pid, Remote: conn.remote, Label: conn.label,
			Pooled: conn.pooled, OpenedAt: conn.openedAt, RTT: conn.lastRTT,
			BytesIn: conn.bytesIn, BytesOut: conn.bytesOut,
		})
		conn.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FD < out[j].FD })
	return out
}

// NetStats is the subsystem's totals.
type NetStats struct {
	Dialed    int64 `json:"dialed"`
	Refused   int64 `json:"refused"`
	Blocked   int64 `json:"blocked"`
	Pooled    int   `json:"pooled"`
	Listeners int   `json:"listeners"`
	Retained  int   `json:"retained"`
	Evicted   int64 `json:"evicted"`
	MaxPerPID int   `json:"max_per_pid"`
	MaxPooled int   `json:"max_pooled"`
}

// NetStatsSnapshot returns the totals, for a status path and for dump.go.
func NetStatsSnapshot() NetStats {
	netState.mu.Lock()
	defer netState.mu.Unlock()
	netPool.mu.Lock()
	pooled := netPool.total
	netPool.mu.Unlock()
	return NetStats{
		Dialed: netState.dialed, Refused: netState.refused, Blocked: netState.blocked,
		Pooled: pooled, Listeners: netState.listeners,
		Retained: len(netState.entries), Evicted: netState.evicted,
		MaxPerPID: maxNetConnsPerPID, MaxPooled: maxNetPooledPerPID,
	}
}

// NetRecord is one egress record, for a snapshot.
type NetRecord struct {
	Seq     int64  `json:"seq"`
	PID     PID    `json:"pid"`
	Module  string `json:"module,omitempty"`
	Host    string `json:"host"`
	Address string `json:"address,omitempty"`
	Outcome string `json:"outcome"`
	At      int64  `json:"at"`
}

// NetHistory returns retained egress records, oldest first, as copies.
func NetHistory() []NetRecord {
	netState.mu.Lock()
	defer netState.mu.Unlock()
	out := make([]NetRecord, 0, len(netState.entries))
	for _, e := range netState.entries {
		out = append(out, NetRecord(e))
	}
	return out
}

// NetAddressAllowed exposes the address decision for a caller that has already resolved a
// name. kpeer uses it, and so do tests: it is the whole of the SSRF control in one place,
// and a second implementation of "is this address permitted" would eventually disagree
// with this one.
func NetAddressAllowed(ip net.IP) error { return netAddressAllowed(ip) }

// ---------------------------------------------------------------------------
// Listeners.

// NetListen binds one listener. Requires net:listen and an address inside the module's
// declared ListenAddr.
//
// The declaration is compared exactly rather than by prefix or by port alone, because a
// declaration of "127.0.0.1:8080" reviewed by an operator is not a declaration of
// "0.0.0.0:8080", and binding the latter is binding every interface on the host.
func NetListen(ctx SContext, address string) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	if err := c.syscall(OpNetListen); err != nil {
		return noFD, err
	}
	return netListen(c, address)
}

func netListen(c *sContext, address string) (FD, error) {
	if address == "" {
		netRefuse(c, "", "", "refused: an empty listen address")
		return noFD, netErr("a listen address is required")
	}
	manifest, live := manifestOf(c.pid)
	if !live {
		netRefuse(c, address, "", "refused: no declared listen address")
		return noFD, netErr("this context has no declared listen address")
	}
	if manifest.ListenAddr != address {
		// Escalated, because binding an address nobody declared is an attempt to widen a
		// grant rather than a mistake about a hostname.
		netEscalate(c, address, "", "listen address outside the declaration")
		netRefuse(c, address, "", "refused: listen address not declared")
		return noFD, &DeniedError{
			Op: OpNetListen, Ctx: c,
			Reason: fmt.Sprintf("%q is not the declared listen address %q", address, manifest.ListenAddr),
		}
	}

	if n := netListenerCount(c.pid); n >= maxNetListenersPerPID {
		err := netErr("this module holds %d listeners, at the ceiling %d", n, maxNetListenersPerPID)
		fault(c, "listen refused at the per-module listener ceiling", map[string]any{
			"module": c.name, "address": address, "listeners": n,
			"ceiling": maxNetListenersPerPID,
		})
		netRefuse(c, address, "", "refused: listener ceiling")
		return noFD, err
	}

	netState.mu.Lock()
	if netState.listeners >= maxNetListenersTotal {
		netState.mu.Unlock()
		netRefuse(c, address, "", "refused: kernel listener ceiling")
		return noFD, netErr("the kernel is at its ceiling of %d listeners", maxNetListenersTotal)
	}
	netState.mu.Unlock()

	l, err := net.Listen("tcp", address)
	if err != nil {
		netRefuse(c, address, "", "refused: bind failed")
		return noFD, netErr("binding %s failed: %v", address, err)
	}

	netState.mu.Lock()
	if netState.listeners >= maxNetListenersTotal {
		netState.mu.Unlock()
		_ = l.Close()
		netRefuse(c, address, "", "refused: kernel listener ceiling")
		return noFD, netErr("the kernel is at its ceiling of %d listeners", maxNetListenersTotal)
	}
	netState.listeners++
	netState.mu.Unlock()

	// The address the kernel actually bound, which for a declaration of port 0 is not the
	// address that was requested. An operator who cannot see which port is listening
	// cannot see what is reachable, so the label, the record and the audit entry all
	// carry this rather than the request. The declaration check above is against the
	// requested string, which is what a reviewer signed; this is about reporting the
	// result.
	bound := address
	if la := l.Addr(); la != nil {
		bound = la.String()
	}

	res := &netListener{l: l, pid: c.pid, addr: bound}
	fd, err := install(c.pid, res, "listen "+bound)
	if err != nil {
		_ = l.Close()
		netState.mu.Lock()
		netState.listeners--
		netState.mu.Unlock()
		netRefuse(c, address, "", "refused: "+err.Error())
		return noFD, err
	}

	netRecord(c.pid, c.name, bound, bound, "listening")
	kaudit.record(AuditPolicy, c, "listener bound", map[string]any{
		"module": c.name, "declared": address, "bound": bound,
	})
	return fd, nil
}

// NetAccept takes one inbound connection from a listener. Requires net:listen.
//
// An accepted connection is NOT address-validated, and that is deliberate rather than an
// oversight: the peer chose its own source address, and refusing a connection because the
// client is behind a private network would refuse most real clients. What bounds an
// accepted connection is the listener's declared address, which an operator reviewed, and
// the deadline and size ceiling every read and write carries.
func NetAccept(ctx SContext, fd FD) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	if err := c.syscall(OpNetListen); err != nil {
		return noFD, err
	}
	entry, err := lookup(c.pid, fd)
	if err != nil {
		return noFD, err
	}
	l, ok := entry.res.(*netListener)
	if !ok {
		return noFD, netErr("fd %d is a %s, not a listener", fd, entry.kind)
	}
	l.mu.Lock()
	if l.closed || l.l == nil {
		l.mu.Unlock()
		return noFD, netErr("this listener is closed")
	}
	listener := l.l
	l.mu.Unlock()

	if err := netSetAcceptDeadline(listener, netClampedTimeout(netDialTimeout, c)); err != nil {
		return noFD, err
	}
	raw, err := listener.Accept()
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return noFD, netErr("accepting on %s timed out", l.addr)
		}
		return noFD, netErr("accepting on %s failed: %v", l.addr, err)
	}

	if n := netSocketCount(c.pid); n >= maxNetConnsPerPID {
		_ = raw.Close()
		err := netErr("this module holds %d sockets, at the ceiling %d", n, maxNetConnsPerPID)
		fault(c, "accept refused at the per-module socket ceiling", map[string]any{
			"module": c.name, "listener": l.addr, "sockets": n, "ceiling": maxNetConnsPerPID,
		})
		netRefuse(c, l.addr, raw.RemoteAddr().String(), "refused: socket ceiling")
		return noFD, err
	}

	conn := &netConn{
		conn: raw, pid: c.pid, remote: raw.RemoteAddr().String(),
		label: "accepted on " + l.addr, openedAt: mono(), grant: OpNetListen,
	}
	out, err := install(c.pid, conn, conn.label)
	if err != nil {
		_ = raw.Close()
		return noFD, err
	}
	netRecord(c.pid, c.name, l.addr, conn.remote, "accepted")
	return out, nil
}

// netSetAcceptDeadline bounds one Accept so an idle listener cannot hold a kernel-run
// goroutine indefinitely. A listener type that cannot carry a deadline is refused rather
// than accepted without one, because an unbounded accept is the hang this exists to
// prevent.
func netSetAcceptDeadline(l net.Listener, d time.Duration) error {
	type deadlineSetter interface {
		SetDeadline(time.Time) error
	}
	s, ok := l.(deadlineSetter)
	if !ok {
		return netErr("this listener cannot carry a deadline, so accepting on it would be unbounded")
	}
	if err := s.SetDeadline(time.Now().Add(d)); err != nil {
		return netErr("setting an accept deadline failed: %v", err)
	}
	return nil
}

// NetCloseListener closes a listener.
func NetCloseListener(ctx SContext, fd FD) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpNetListen); err != nil {
		return err
	}
	entry, err := lookup(c.pid, fd)
	if err != nil {
		return err
	}
	if _, ok := entry.res.(*netListener); !ok {
		return netErr("fd %d is a %s, not a listener", fd, entry.kind)
	}
	return closeFD(c.pid, fd)
}

// ---------------------------------------------------------------------------
// Reset.

// resetNet closes every socket and listener and clears the ledger and the pool. It also
// clears the private-range opt-in, and that is a decision worth stating: the opt-in is
// host configuration for a deployment, and a fresh boot is a fresh deployment. Keeping it
// would let a range approved for one boot persist into a boot whose operator never
// approved it, which is the same reasoning resetPanic gives for clearing the previous
// boot's crash record.
func resetNet() {
	netPool.mu.Lock()
	doomed := make([]*netPoolEntry, 0, netPool.total)
	for _, entries := range netPool.byKey {
		doomed = append(doomed, entries...)
	}
	netPool.byKey = map[netPoolKey][]*netPoolEntry{}
	netPool.byConn = map[*netConn]*netPoolEntry{}
	netPool.byPid = map[PID]int{}
	netPool.total = 0
	netPool.mu.Unlock()
	for _, e := range doomed {
		_ = e.conn.Close()
	}

	netState.mu.Lock()
	netState.entries = nil
	netState.seq = 0
	netState.evicted = 0
	netState.dialed = 0
	netState.refused = 0
	netState.blocked = 0
	netState.listeners = 0
	netState.mu.Unlock()

	netPrivate.mu.Lock()
	netPrivate.nets = nil
	netPrivate.enabled = false
	netPrivate.mu.Unlock()

	// The resolver goes back to the system default. A stub installed for one boot that
	// survived into the next would resolve every name through the previous deployment's
	// mapping, which is the same reasoning that clears the private-range opt-in above.
	netResolver.mu.Lock()
	netResolver.r = netSystemResolver{}
	netResolver.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Syscall surface.

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

func (c *sContext) SyscallNetDial(spec NetSpec) (NetDialResult, error) { return NetDial(c, spec) }

func (c *sContext) SyscallNetWrite(fd FD, data []byte) (int, error) { return NetWrite(c, fd, data) }

func (c *sContext) SyscallNetRead(fd FD, limit int) ([]byte, error) { return NetRead(c, fd, limit) }

func (c *sContext) SyscallNetRelease(fd FD) error { return NetRelease(c, fd) }

func (c *sContext) SyscallNetClose(fd FD) error { return NetClose(c, fd) }

func (c *sContext) SyscallNetListen(address string) (FD, error) { return NetListen(c, address) }

func (c *sContext) SyscallNetAccept(fd FD) (FD, error) { return NetAccept(c, fd) }

func (c *sContext) SyscallNetCloseListener(fd FD) error { return NetCloseListener(c, fd) }

func (c *sContext) SyscallNetSockets() []NetInfo { return NetSockets(c.pid) }

// ---------------------------------------------------------------------------
// INTEGRATION. Nothing below is wired except what this file does itself.
//
// 1. context.go: SyscallNet joins the SContext composition.
//
// 2. kernel.go: resetNet() joins resetKernel(), in the channels-and-coordination block
//    beside resetRoutes and resetPeers, since a socket is a reachability resource like a
//    route. It must run BEFORE resetFDs, because the pool holds fds and closing them
//    through the fd table needs that table still intact.
//
// 3. module.go: netDropAllFor(pid) belongs beside DropPipesFor(pid) and dropTTYsFor(pid)
//    in the unload path, so a module that dies leaves no idle socket behind. Without it
//    reclaimFDs still closes the descriptors, but the pool would keep entries naming
//    sockets that are gone.
//
// 4. policy.go: OpNetDial and OpNetListen are in scopedOps and deliberately absent from
//    enforcedScopedOps, so today they are refused at the domain ceiling and unreachable.
//    This file now provides the per-call check that was missing - NetHostAllowed against
//    the manifest's AllowedHosts, and an exact match against ListenAddr - so both can
//    join enforcedScopedOps:
//
//	OpNetDial:   true, // net.go: NetHostAllowed consults the manifest's AllowedHosts
//	OpNetListen: true, // net.go: netListen matches the manifest's ListenAddr exactly
//
//    That is a policy surface change and belongs to whoever owns policy.go, which is why
//    it is reported rather than made.
//
// 5. dump.go should render NetStatsSnapshot and NetSockets under a "--- egress ---"
//    heading beside the peers section, since both describe reachability.
//
// 6. The private-range opt-in is host configuration and belongs in BootConfig beside
//    TrustRoot, sealed at boot like the rest. NetAllowPrivateRanges is the setter and can
//    be called from Boot once bootconfig applies its configuration; until then the host
//    calls it directly before loading modules, which is what main.go would do.
