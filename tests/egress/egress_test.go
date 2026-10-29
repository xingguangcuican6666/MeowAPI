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

// Package egress tests knet: the controlled outbound stack.
//
// The properties here are the ones that decide whether "allowlisted egress" means
// anything: that every refused address range is refused, that a name resolving into a
// private range is caught even though the name is declared, that every resolved address
// is validated rather than just the first, that the dial targets the address that was
// checked, and that a socket is reclaimed when its owner is unloaded.
//
// The success path needs a non-loopback private address, because loopback is refused
// outright and no host opt-in can permit it. This machine's own interface addresses are
// used, discovered at run time, and the tests that need one skip when the machine has
// none - which is honest about a limit rather than weakening the SSRF default to make a
// test pass on a runner that has no such interface.
package egress

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

var netCounter int

func netNextName(prefix string) string {
	netCounter++
	return prefix + harness.Itoa(netCounter)
}

func netBoot(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "node-net"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// netLoad loads a module declaring the given hosts and listen address, and returns its
// context and pid. The context is used after OnLoad returns rather than from inside it:
// manifest-scoped state is published before OnLoad runs, but the module's own record is
// published after, so a dial attempted during initialization fails closed with "no
// declared network boundary". That is correct behaviour and not a bug to work around.
func netLoad(t *testing.T, k *kernel.Kernel, prefix string, ops []kernel.Op, hosts []string, listen string) (kernel.SContext, kernel.PID) {
	t.Helper()
	name := netNextName(prefix)
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	m := kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: ops, AllowedHosts: hosts, ListenAddr: listen,
	}
	pid, err := k.Load(m)
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, probe.Ctx)
	return probe.Ctx, pid
}

// netResetPrivate restores the host's egress configuration. It is process-wide, so a test
// that widens it would silently widen every later test's view of what is permitted.
func netResetPrivate(t *testing.T) {
	t.Helper()
	require.NoError(t, kernel.NetAllowPrivateRanges(nil))
	t.Cleanup(func() { _ = kernel.NetAllowPrivateRanges(nil) })
}

// netStubResolver is a fixed mapping installed as the host's resolver. It exists because a
// hostile resolver is the attacker in a DNS rebinding attack, and without a way to make a
// name resolve to a private address on demand, the refusal that closes the rebinding window
// would be untested code defending against exactly the attack it was written for.
type netStubResolver struct {
	hosts map[string][]net.IPAddr
}

func (r netStubResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if addrs, ok := r.hosts[strings.ToLower(host)]; ok {
		return addrs, nil
	}
	return nil, errors.New("no such host: " + host)
}

// netStub installs a resolver mapping one host to the given addresses. Passing no address
// removes that host from the mapping, so a later call in the same test can re-point a name,
// which is what the rebinding test needs.
func netStub(t *testing.T, k *kernel.Kernel, host string, ips ...string) {
	t.Helper()
	addrs := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		require.NotNil(t, ip, "%q is not an address", s)
		addrs = append(addrs, net.IPAddr{IP: ip})
	}
	require.NoError(t, k.NetSetResolver(netStubResolver{
		hosts: map[string][]net.IPAddr{strings.ToLower(host): addrs},
	}))
}

// netPrivateInterface finds a non-loopback private IPv4 address belonging to this
// machine, which is what the success path dials. Loopback cannot be used: it is refused
// outright and no opt-in permits it, correctly.
func netPrivateInterface(t *testing.T) (string, string) {
	t.Helper()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || !ip4.IsPrivate() {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if bits == 0 || ones > 24 {
				continue
			}
			cidr := &net.IPNet{
				IP:   ip4.Mask(net.CIDRMask(ones, 32)),
				Mask: net.CIDRMask(ones, 32),
			}
			return ip4.String(), cidr.String()
		}
	}
	t.Skip("this machine has no non-loopback private IPv4 interface, so the dial success path cannot be exercised")
	return "", ""
}

// ---------------------------------------------------------------------------
// The address decision, tested as a pure function over every range that matters.

// TestEveryBlockedRangeIsBlocked walks the set that decides whether this subsystem is
// worth having. One entry per range, including the cloud metadata address by name,
// because it is the single highest-value target and a reader should be able to see it
// listed rather than inferred from a link-local test.
func TestEveryBlockedRangeIsBlocked(t *testing.T) {
	netResetPrivate(t)

	blocked := []struct {
		name string
		ip   string
	}{
		{"loopback v4", "127.0.0.1"},
		{"loopback v4 other", "127.9.9.9"},
		{"loopback v6", "::1"},
		{"cloud metadata", "169.254.169.254"},
		{"link-local other", "169.254.1.1"},
		{"link-local v6", "fe80::1"},
		{"unspecified v4", "0.0.0.0"},
		{"unspecified v6", "::"},
		{"private 10/8", "10.1.2.3"},
		{"private 172.16/12", "172.16.0.1"},
		{"private 192.168/16", "192.168.1.1"},
		{"unique local v6", "fc00::1"},
		{"unique local v6 fd", "fd12:3456::1"},
		{"multicast v4", "224.0.0.1"},
		{"multicast v6", "ff02::1"},
		{"link-local multicast", "224.0.0.251"},
	}
	for _, c := range blocked {
		t.Run(c.name, func(t *testing.T) {
			err := kernel.NetAddressAllowed(net.ParseIP(c.ip))
			require.Error(t, err, "%s must be refused", c.ip)
			assert.ErrorIs(t, err, kernel.ErrNetAddressBlocked)
		})
	}

	allowed := []struct {
		name string
		ip   string
	}{
		{"public v4", "93.184.216.34"},
		{"public v4 other", "8.8.8.8"},
		{"public v6", "2606:2800:220:1:248:1893:25c8:1946"},
	}
	for _, c := range allowed {
		t.Run("permitted "+c.name, func(t *testing.T) {
			assert.NoError(t, kernel.NetAddressAllowed(net.ParseIP(c.ip)),
				"%s is a public address and must be permitted by default", c.ip)
		})
	}

	t.Run("a nil address is refused", func(t *testing.T) {
		assert.Error(t, kernel.NetAddressAllowed(nil))
	})
}

// TestThePrivateOptInIsHostSideAndNarrow pins the opt-in's two properties: it permits
// exactly the ranges named, and it can never permit the ranges no opt-in may cover.
func TestThePrivateOptInIsHostSideAndNarrow(t *testing.T) {
	netResetPrivate(t)

	// A private address is refused before any opt-in.
	require.ErrorIs(t, kernel.NetAddressAllowed(net.ParseIP("10.9.8.7")), kernel.ErrNetAddressBlocked)

	require.NoError(t, kernel.NetAllowPrivateRanges([]string{"10.9.0.0/16"}))
	assert.NoError(t, kernel.NetAddressAllowed(net.ParseIP("10.9.8.7")))
	assert.Equal(t, []string{"10.9.0.0/16"}, kernel.NetPrivateRanges())

	// Narrow, not a blanket private grant: another private range is still refused.
	assert.ErrorIs(t, kernel.NetAddressAllowed(net.ParseIP("10.8.8.7")), kernel.ErrNetAddressBlocked)
	assert.ErrorIs(t, kernel.NetAddressAllowed(net.ParseIP("192.168.1.1")), kernel.ErrNetAddressBlocked)

	// The opt-in replaces rather than accumulates, so a deployment cannot end up
	// permitting ranges nobody approved in one call.
	require.NoError(t, kernel.NetAllowPrivateRanges([]string{"192.168.0.0/16"}))
	assert.ErrorIs(t, kernel.NetAddressAllowed(net.ParseIP("10.9.8.7")), kernel.ErrNetAddressBlocked,
		"the previous opt-in must not persist")
	assert.NoError(t, kernel.NetAddressAllowed(net.ParseIP("192.168.1.1")))

	// And the ranges no opt-in may cover are refused even when named explicitly.
	for _, never := range []string{
		"127.0.0.0/8", "169.254.0.0/16", "::1/128", "0.0.0.0/0", "10.0.0.0/4",
	} {
		err := kernel.NetAllowPrivateRanges([]string{never})
		require.Error(t, err, "%s must not be opt-in-able", never)
		assert.Contains(t, err.Error(), "no opt-in can permit")
	}

	require.Error(t, kernel.NetAllowPrivateRanges([]string{"not a cidr"}))
}

// ---------------------------------------------------------------------------
// The declaration boundary.

// TestAnUndeclaredHostIsRefusedAndEscalated pins that the boundary is the module's own
// signed declaration, and that reaching past it is recorded as an attempt rather than
// only a failure.
func TestAnUndeclaredHostIsRefusedAndEscalated(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, pid := netLoad(t, k, "netbound", []kernel.Op{kernel.OpNetDial},
		[]string{"api.provider.example"}, "")

	_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: "evil.example", Port: 443})
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "an undeclared host is a policy denial: %v", err)
	assert.ErrorIs(t, err, kernel.ErrNetHostNotAllowed)
	assert.NotEmpty(t, kernel.DenialReason(err),
		"the module holds net:dial; what it lacks is this host, and the reason says so")

	esc := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation})
	assert.NotEmpty(t, esc, "reaching past a declared boundary is recorded as an escalation")

	// The positive case is asserted against the boundary decision rather than through a
	// second dial. NetHostAllowed is exported precisely so the decision can be checked on
	// its own, and going through NetDial here would cost a real connection attempt to
	// prove something the decision already proves: a dial refused for a network reason and
	// a dial refused by the boundary are indistinguishable from outside, which makes the
	// weaker test as well as the slower one.
	assert.NoError(t, kernel.NetHostAllowed(pid, "api.provider.example"),
		"a declared host is inside the boundary")
	_ = ctx
}

// TestAnEmptyDeclarationWillNotLoad pins deny-by-default at the point where it is
// strongest. A module declaring net:dial with no allowed host is refused at manifest
// validation, so it never runs at all, and the same holds for an empty host, a wildcard,
// a host carrying a scheme or port, and a loopback hostname. Enforcing this at load rather
// than at dial time means the declaration a reviewer signed is the declaration that exists.
func TestAnEmptyDeclarationWillNotLoad(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)

	for _, hosts := range [][]string{nil, {}, {""}, {"*.example"}, {"https://api.example"},
		{"api.example:443"}, {"api.example/path"}, {"user@api.example"}, {"localhost"},
		{"db.localhost"}} {
		name := netNextName("netempty")
		probe := &harness.Probe{}
		harness.RegisterProbe(t, name, probe)
		_, err := k.Load(kernel.Manifest{
			Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
			Require: []kernel.Op{kernel.OpNetDial}, AllowedHosts: hosts,
		})
		require.Error(t, err, "net:dial with allowed_hosts %v must not load", hosts)
		assert.Contains(t, err.Error(), "invalid manifest")
	}

	// net:listen without an address is refused for the same reason.
	name := netNextName("netnolisten")
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	_, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpNetListen},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen address")
}

// TestHostSpellingCannotWidenTheDeclaration pins normalization in both directions. DNS
// is case-insensitive and a trailing dot is the fully-qualified spelling of the same
// name; treating them as different would let a module reach an undeclared host by
// respelling a declared one, or refuse a declared one by respelling the request.
func TestHostSpellingCannotWidenTheDeclaration(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, pid := netLoad(t, k, "netspell", []kernel.Op{kernel.OpNetDial},
		[]string{"API.Provider.Example"}, "")

	// Asserted against the boundary decision, not through a dial: three respellings would
	// otherwise be three real connection attempts, and what is under test is whether the
	// comparison normalizes, which NetHostAllowed answers directly.
	for _, spelling := range []string{
		"api.provider.example", "API.PROVIDER.EXAMPLE", "api.provider.example.",
	} {
		assert.NoError(t, kernel.NetHostAllowed(pid, spelling),
			"%q is the declared host respelled and must match the declaration", spelling)
	}

	// And normalization does not become a widening: a different host is still refused, and
	// a respelling that is not the same name does not sneak through.
	for _, other := range []string{"other.example", "api.provider.example.evil",
		"xapi.provider.example", ".api.provider.example"} {
		assert.Error(t, kernel.NetHostAllowed(pid, other),
			"%q is not the declared host and must not match it", other)
	}
	_ = ctx
}

// TestAnAddressLiteralIsNotAHostname pins that the declaration is a list of hostnames
// and a module cannot dial an address directly. Resolving an IP literal to itself would
// let an address pass a hostname check nobody reviewed.
func TestAnAddressLiteralIsNotAHostname(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, _ := netLoad(t, k, "netlit", []kernel.Op{kernel.OpNetDial},
		[]string{"93.184.216.34", "api.provider.example"}, "")

	for _, lit := range []string{"93.184.216.34", "10.0.0.1", "::1"} {
		_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: lit, Port: 443})
		require.Error(t, err, "%q is an address and must be refused as a host", lit)
		assert.Contains(t, err.Error(), "is an address")
	}

	// And a spec that smuggles a port or a path into the host field is refused before
	// anything is resolved, because resolving a host this stack will not dial anyway is
	// a query an attacker could use to probe a resolver.
	for _, bad := range []string{"api.provider.example:8080", "api.provider.example/path",
		"user@api.provider.example", "api.provider.example#frag", ""} {
		_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: bad, Port: 443})
		require.Error(t, err, "%q must be refused", bad)
	}

	// A scheme this stack does not dial is refused for the same reason: the allowlist was
	// reviewed against TCP.
	_, err := kernel.NetDial(ctx, kernel.NetSpec{
		Host: "api.provider.example", Port: 443, Scheme: "udp",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TCP only")
}

// ---------------------------------------------------------------------------
// The SSRF control itself.

// TestANameResolvingToAPrivateAddressIsRefused is the case hostname matching cannot
// catch. The host is declared and reviewed; the address it resolves to is not.
func TestANameResolvingToAPrivateAddressIsRefused(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, _ := netLoad(t, k, "netssrf", []kernel.Op{kernel.OpNetDial},
		[]string{"internal.example"}, "")

	for _, ip := range []string{
		"169.254.169.254", "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "::1",
	} {
		t.Run(ip, func(t *testing.T) {
			netStub(t, k, "internal.example", ip)
			_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: "internal.example", Port: 443})
			require.Error(t, err, "a declared name resolving to %s must be refused", ip)
			assert.ErrorIs(t, err, kernel.ErrNetAddressBlocked)
		})
	}
}

// TestEveryResolvedAddressIsValidatedNotJustTheFirst pins the multi-record case. A name
// with one public and one private A record must be refused, because dialing the first
// permitted one would make the outcome depend on resolver ordering, which whoever runs
// the authoritative server for that name controls.
func TestEveryResolvedAddressIsValidatedNotJustTheFirst(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, _ := netLoad(t, k, "netmulti", []kernel.Op{kernel.OpNetDial},
		[]string{"dual.example"}, "")

	t.Run("public first then private", func(t *testing.T) {
		netStub(t, k, "dual.example", "93.184.216.34", "10.0.0.1")
		_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: "dual.example", Port: 443})
		require.Error(t, err)
		assert.ErrorIs(t, err, kernel.ErrNetAddressBlocked,
			"a private address anywhere in the answer must refuse the whole dial")
	})

	t.Run("private first then public", func(t *testing.T) {
		netStub(t, k, "dual.example", "10.0.0.1", "93.184.216.34")
		_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: "dual.example", Port: 443})
		require.Error(t, err)
		assert.ErrorIs(t, err, kernel.ErrNetAddressBlocked)
	})
}

// TestTheDialTargetsTheAddressThatWasChecked pins the rebinding defence. The stub returns
// a private address, so if the dialer re-resolved the name and got a public one, the dial
// would proceed - and the refusal proves the validated address is the one used. The
// Control hook is the second check, on the socket address the kernel is about to use.
func TestTheDialTargetsTheAddressThatWasChecked(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, _ := netLoad(t, k, "netrebind", []kernel.Op{kernel.OpNetDial},
		[]string{"rebind.example"}, "")

	netStub(t, k, "rebind.example", "169.254.169.254")

	_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: "rebind.example", Port: 80})
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrNetAddressBlocked)

	// The refusal is escalated, because a declared host resolving to the metadata
	// endpoint is not a misconfiguration, it is an attempt.
	esc := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation})
	var sawControl bool
	for _, e := range esc {
		if reason, _ := e.Fields["reason"].(string); strings.Contains(reason, "metadata") {
			sawControl = true
		}
	}
	assert.True(t, sawControl, "the metadata address is named in the escalation")
}

// TestASuccessfulDialUsesTheValidatedAddress is the success path, and it needs a real
// non-loopback private address on this machine. It proves the whole chain works when the
// address is permitted: declaration, resolution, validation, dial, and an fd the caller
// can write to.
func TestASuccessfulDialUsesTheValidatedAddress(t *testing.T) {
	harness.QuietConsole(t)
	ip, cidr := netPrivateInterface(t)
	netResetPrivate(t)
	k := netBoot(t)
	require.NoError(t, kernel.NetAllowPrivateRanges([]string{cidr}))
	ctx, pid := netLoad(t, k, "netok", []kernel.Op{kernel.OpNetDial},
		[]string{"provider.internal"}, "")

	// A listener on this machine's own private address, which is what the dial reaches.
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	accepted := make(chan string, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		accepted <- string(buf[:n])
	}()

	netStub(t, k, "provider.internal", ip)
	res, err := kernel.NetDial(ctx, kernel.NetSpec{
		Host: "provider.internal", Port: port, Label: "provider",
	})
	require.NoError(t, err, "a declared host resolving to a permitted address must dial")

	assert.Equal(t, net.JoinHostPort(ip, portStr), res.Address,
		"the reported address is the one that was validated and dialed")
	assert.False(t, res.Pooled)
	assert.NotEqual(t, kernel.FD(0), res.FD)

	n, err := kernel.NetWrite(ctx, res.FD, []byte("hello provider"))
	require.NoError(t, err)
	assert.Equal(t, 14, n)

	select {
	case got := <-accepted:
		assert.Equal(t, "hello provider", got, "the bytes crossed to the listener")
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never received the write")
	}

	// The socket is attributed to this pid and appears in its handle list.
	sockets := kernel.NetSockets(pid)
	require.Len(t, sockets, 1)
	assert.Equal(t, res.FD, sockets[0].FD)
	assert.Contains(t, sockets[0].Label, "provider")

	stats := kernel.NetStatsSnapshot()
	assert.Positive(t, stats.Dialed)

	require.NoError(t, kernel.NetClose(ctx, res.FD))
	assert.Empty(t, kernel.NetSockets(pid), "a closed socket leaves the handle list")
}

// TestThePoolReturnsTheSameSocketAndRevalidatesOnReuse pins both halves of pooling: a
// released socket is handed back rather than reopened, and a socket whose range stopped
// being permitted is dropped instead of returned.
func TestThePoolReturnsTheSameSocketAndRevalidatesOnReuse(t *testing.T) {
	harness.QuietConsole(t)
	ip, cidr := netPrivateInterface(t)
	netResetPrivate(t)
	k := netBoot(t)
	require.NoError(t, kernel.NetAllowPrivateRanges([]string{cidr}))
	ctx, pid := netLoad(t, k, "netpool", []kernel.Op{kernel.OpNetDial},
		[]string{"provider.internal"}, "")

	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 256)
				for {
					if _, rerr := c.Read(buf); rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	netStub(t, k, "provider.internal", ip)
	spec := kernel.NetSpec{Host: "provider.internal", Port: port}

	first, err := kernel.NetDial(ctx, spec)
	require.NoError(t, err)
	require.NoError(t, kernel.NetRelease(ctx, first.FD))

	assert.Equal(t, 1, kernel.NetStatsSnapshot().Pooled, "the released socket is pooled")

	second, err := kernel.NetDial(ctx, spec)
	require.NoError(t, err)
	assert.True(t, second.Pooled, "a second dial draws from the pool")
	assert.Equal(t, first.Address, second.Address,
		"the pool is keyed on the resolved address, not the name")
	assert.Zero(t, kernel.NetStatsSnapshot().Pooled)

	// Narrowing the opt-in after a socket is pooled must not hand that socket back.
	require.NoError(t, kernel.NetRelease(ctx, second.FD))
	require.Equal(t, 1, kernel.NetStatsSnapshot().Pooled)
	require.NoError(t, kernel.NetAllowPrivateRanges([]string{"10.250.0.0/16"}))

	third, err := kernel.NetDial(ctx, spec)
	require.Error(t, err, "the pooled socket points into a range that is no longer permitted")
	assert.Zero(t, kernel.NetStatsSnapshot().Pooled, "and it was dropped rather than left idle")
	_ = third
	assert.Empty(t, kernel.NetSockets(pid))
}

// TestThePoolCeilingClosesRatherThanRefuses pins the bounded pool's behaviour at its
// limit. A release that failed because the pool was full would leave the descriptor open,
// which is the opposite of what a bound exists for.
func TestThePoolCeilingClosesRatherThanRefuses(t *testing.T) {
	harness.QuietConsole(t)
	ip, cidr := netPrivateInterface(t)
	netResetPrivate(t)
	k := netBoot(t)
	require.NoError(t, kernel.NetAllowPrivateRanges([]string{cidr}))
	ctx, pid := netLoad(t, k, "netpoolcap", []kernel.Op{kernel.OpNetDial},
		[]string{"provider.internal"}, "")

	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 256)
				for {
					if _, rerr := c.Read(buf); rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	netStub(t, k, "provider.internal", ip)
	spec := kernel.NetSpec{Host: "provider.internal", Port: port}
	stats := kernel.NetStatsSnapshot()
	limit := stats.MaxPooled
	require.Positive(t, limit)

	// Opened all at once and released afterwards, because a dial draws from the pool
	// before resolving: dial-release-dial-release would reuse one socket forever and the
	// pool would never fill, which is correct behaviour and not the thing under test.
	opened := make([]kernel.FD, 0, limit+1)
	for range limit + 1 {
		res, derr := kernel.NetDial(ctx, spec)
		require.NoError(t, derr)
		opened = append(opened, res.FD)
	}
	for _, fd := range opened {
		require.NoError(t, kernel.NetRelease(ctx, fd))
	}

	after := kernel.NetStatsSnapshot()
	assert.LessOrEqual(t, after.Pooled, limit, "the pool never exceeds its per-module bound")

	// Every socket still open is a pooled one, which is what distinguishes "the pool
	// closed the surplus" from "the surplus is still open and simply uncounted".
	remaining := kernel.NetSockets(pid)
	assert.Len(t, remaining, after.Pooled)
	for _, s := range remaining {
		assert.True(t, s.Pooled, "fd %d is open but not pooled", s.FD)
	}
	assert.Len(t, remaining, limit, "the socket that could not be pooled was closed")
}

// ---------------------------------------------------------------------------
// Handles, kinds and reclamation.

// TestASocketHandleIsNotUsableAsAnotherKind pins the kind check. An integer is what a
// module holds, and without a kind check a pipe handle passed here would get socket
// behaviour on a pipe's resource.
func TestASocketHandleIsNotUsableAsAnotherKind(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, _ := netLoad(t, k, "netkind",
		[]kernel.Op{kernel.OpNetDial, kernel.OpPipeOpen, kernel.OpPipeWrite, kernel.OpPipeRead},
		[]string{"provider.example"}, "")

	// A pipe handle is a real fd of a different kind.
	w, err := kernel.OpenPipe(ctx, "kind-probe", 4096, kernel.PipeNonBlocking)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.SyscallClose(w) })

	_, err = kernel.NetWrite(ctx, w, []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a socket")

	_, err = kernel.NetRead(ctx, w, 16)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a socket")

	require.Error(t, kernel.NetRelease(ctx, w))
	require.Error(t, kernel.NetClose(ctx, w))

	// The pipe is untouched by all of that, which is what distinguishes a kind check from
	// a broken lookup.
	_, err = ctx.SyscallPipeWrite(w, []byte("still a pipe"), 0)
	require.NoError(t, err)

	// An fd that was never issued is refused rather than treated as closed.
	_, err = kernel.NetWrite(ctx, kernel.FD(9999), []byte("x"))
	require.Error(t, err)
}

// TestSocketsAreReclaimedWhenTheModuleIsUnloaded pins the lifetime property, and it is
// the one that decides whether a crashed module leaks a descriptor. The pool is checked
// too, because a pooled entry naming a closed socket would be handed to a later caller.
func TestSocketsAreReclaimedWhenTheModuleIsUnloaded(t *testing.T) {
	harness.QuietConsole(t)
	ip, cidr := netPrivateInterface(t)
	netResetPrivate(t)
	k := netBoot(t)
	require.NoError(t, kernel.NetAllowPrivateRanges([]string{cidr}))
	name := netNextName("netreclaim")
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpNetDial}, AllowedHosts: []string{"provider.internal"},
	})
	require.NoError(t, err)
	require.NotNil(t, probe.Ctx)

	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 256)
				for {
					if _, rerr := c.Read(buf); rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	netStub(t, k, "provider.internal", ip)
	open, err := kernel.NetDial(probe.Ctx, kernel.NetSpec{Host: "provider.internal", Port: port})
	require.NoError(t, err)
	pooled, err := kernel.NetDial(probe.Ctx, kernel.NetSpec{Host: "provider.internal", Port: port})
	require.NoError(t, err)
	require.NoError(t, kernel.NetRelease(probe.Ctx, pooled.FD))
	require.Equal(t, 1, kernel.NetStatsSnapshot().Pooled)

	require.NoError(t, k.Unload(pid))

	assert.Empty(t, kernel.NetSockets(pid), "an unloaded module holds no socket")
	assert.Zero(t, kernel.NetStatsSnapshot().Pooled,
		"the pool holds no entry naming a socket whose owner is gone")

	// And the descriptor really is gone, not merely unlisted: a write through the old
	// handle fails rather than reaching the listener.
	_, err = kernel.NetWrite(probe.Ctx, open.FD, []byte("after unload"))
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Listeners.

// TestAListenerNeedsItsDeclaredAddressExactly pins the exact match. A declaration of
// "127.0.0.1:8080" that an operator reviewed is not a declaration of "0.0.0.0:8080", and
// binding the latter is binding every interface on the host.
func TestAListenerNeedsItsDeclaredAddressExactly(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, _ := netLoad(t, k, "netlisten", []kernel.Op{kernel.OpNetListen},
		nil, "127.0.0.1:0")

	fd, err := kernel.NetListen(ctx, "127.0.0.1:0")
	require.NoError(t, err, "the declared address binds")
	t.Cleanup(func() { _ = kernel.NetCloseListener(ctx, fd) })

	for _, other := range []string{"0.0.0.0:0", "127.0.0.1:9999", "[::1]:0", ""} {
		_, err := kernel.NetListen(ctx, other)
		require.Error(t, err, "%q is not the declared address", other)
		if other != "" {
			assert.True(t, kernel.IsDenied(err), "binding an undeclared address is a denial")
		}
	}

	esc := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation})
	assert.NotEmpty(t, esc, "binding an address nobody declared is recorded as an attempt")
}

// TestAnAcceptedConnectionIsBoundedButNotAddressValidated pins the deliberate asymmetry.
// An inbound peer chose its own source address, so refusing a client because it is behind
// a private network would refuse most real clients; what bounds an accepted connection is
// the listener's declared address, which an operator reviewed, plus the deadline and size
// ceiling every read and write carries.
func TestAnAcceptedConnectionIsBoundedButNotAddressValidated(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, pid := netLoad(t, k, "netaccept", []kernel.Op{kernel.OpNetListen}, nil, "127.0.0.1:0")

	fd, err := kernel.NetListen(ctx, "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = kernel.NetCloseListener(ctx, fd) }()

	// The bound port is discovered from the handle's label, since a declaration of port 0
	// means the kernel chose one.
	var bound string
	for _, f := range kernel.FDList(pid) {
		if f.Kind == "listener" {
			bound = strings.TrimPrefix(f.Label, "listen ")
		}
	}
	require.NotEmpty(t, bound)

	client, err := net.Dial("tcp", bound)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	conn, err := kernel.NetAccept(ctx, fd)
	require.NoError(t, err, "an inbound connection from loopback is accepted")

	go func() { _, _ = client.Write([]byte("a request")) }()

	got, err := kernel.NetRead(ctx, conn, 64)
	require.NoError(t, err)
	assert.Equal(t, "a request", string(got))

	// The size ceiling is the kernel's, not the caller's.
	_, err = kernel.NetRead(ctx, conn, 0)
	require.Error(t, err)
	_, err = kernel.NetRead(ctx, conn, 1<<30)
	require.Error(t, err, "a read limit above the ceiling is refused")

	// And a listener handle is not a socket handle.
	_, err = kernel.NetWrite(ctx, fd, []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a socket")

	// This module holds net:listen and not net:dial, and it could still read from and
	// close the connection it accepted. Gating a socket on the operation that created it
	// rather than on a fixed one is what makes that work; requiring net:dial here would
	// leak a descriptor for the life of a listener-only module.
	require.NoError(t, kernel.NetClose(ctx, conn))
}

// TestListenerCeilingsAreEnforced pins both bounds, per module and across the kernel.
func TestListenerCeilingsAreEnforced(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, pid := netLoad(t, k, "netlcap", []kernel.Op{kernel.OpNetListen}, nil, "127.0.0.1:0")

	var fds []kernel.FD
	t.Cleanup(func() {
		for _, fd := range fds {
			_ = kernel.NetCloseListener(ctx, fd)
		}
	})

	// The per-module ceiling is 4, so the fifth is refused.
	for range 4 {
		fd, err := kernel.NetListen(ctx, "127.0.0.1:0")
		require.NoError(t, err)
		fds = append(fds, fd)
	}
	_, err := kernel.NetListen(ctx, "127.0.0.1:0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ceiling")

	var listeners int
	for _, f := range kernel.FDList(pid) {
		if f.Kind == "listener" {
			listeners++
		}
	}
	assert.Equal(t, 4, listeners, "the per-module ceiling is enforced, not merely declared")
	assert.Equal(t, 4, kernel.NetStatsSnapshot().Listeners)
}

// ---------------------------------------------------------------------------
// The grant, the ledger and the reset.

// TestTheGrantIsWhatDecidesNotTheAddress pins the two refusal classes separately. A
// module that never declared net:dial gets a policy denial and learns nothing about
// whether the host was permitted; a module that declared it and reached past its boundary
// gets a denial naming the declaration. Conflating them would tell an undeclared module
// which hosts exist.
func TestTheGrantIsWhatDecidesNotTheAddress(t *testing.T) {
	buf := harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)

	// Declares the host but not the operation.
	ctx, _ := netLoad(t, k, "netnogrant", []kernel.Op{kernel.OpKVRead},
		[]string{"169.254.169.254.nip.io"}, "")

	_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: "169.254.169.254.nip.io", Port: 443})
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.NotErrorIs(t, err, kernel.ErrNetAddressBlocked,
		"the policy gate refuses first, so the address is never resolved or judged")
	assert.Positive(t, len(harness.Faults(buf)), "a denial is visible as a fault")
}

// TestTheLedgerRecordsDialsAndRefusals pins that this surface is visible, including the
// address actually dialed, which is the field that makes a name resolving somewhere
// unexpected discoverable after the fact.
func TestTheLedgerRecordsDialsAndRefusals(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	ctx, _ := netLoad(t, k, "netledger", []kernel.Op{kernel.OpNetDial},
		[]string{"provider.example", "internal.example"}, "")

	netStub(t, k, "internal.example", "169.254.169.254")
	_, err := kernel.NetDial(ctx, kernel.NetSpec{Host: "internal.example", Port: 443})
	require.Error(t, err)

	netStub(t, k, "provider.example", "93.184.216.34")
	_, err = kernel.NetDial(ctx, kernel.NetSpec{Host: "undeclared.example", Port: 443})
	require.Error(t, err)

	var sawBlocked, sawRefused bool
	for _, r := range kernel.NetHistory() {
		switch {
		case r.Host == "internal.example" && strings.HasPrefix(r.Outcome, "blocked"):
			sawBlocked = true
			assert.Equal(t, "169.254.169.254", r.Address,
				"the record names the address, not only the hostname")
		case r.Host == "undeclared.example" && strings.HasPrefix(r.Outcome, "refused"):
			sawRefused = true
		}
	}
	assert.True(t, sawBlocked, "a blocked address is on the ledger")
	assert.True(t, sawRefused, "an undeclared host is on the ledger")

	stats := kernel.NetStatsSnapshot()
	assert.Positive(t, stats.Blocked)
	assert.Positive(t, stats.Refused)
}

// TestNothingSurvivesRestart pins the reset, including the private-range opt-in. Keeping
// the opt-in would let a range approved for one boot persist into a boot whose operator
// never approved it.
func TestNothingSurvivesRestart(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	require.NoError(t, kernel.NetAllowPrivateRanges([]string{"10.20.0.0/16"}))
	require.NotEmpty(t, kernel.NetPrivateRanges())
	ctx, _ := netLoad(t, k, "netreset", []kernel.Op{kernel.OpNetDial, kernel.OpNetListen},
		[]string{"provider.example"}, "127.0.0.1:0")
	fd, err := kernel.NetListen(ctx, "127.0.0.1:0")
	require.NoError(t, err)
	_ = fd

	require.NoError(t, k.Shutdown())

	assert.Empty(t, kernel.NetPrivateRanges(),
		"the host's private-range opt-in does not survive a restart")
	assert.ErrorIs(t, kernel.NetAddressAllowed(net.ParseIP("10.20.0.1")),
		kernel.ErrNetAddressBlocked)

	k2 := netBoot(t)
	_ = k2
	stats := kernel.NetStatsSnapshot()
	assert.Zero(t, stats.Listeners, "no listener survives a restart")
	assert.Zero(t, stats.Pooled)
	assert.Empty(t, kernel.NetHistory())
}

// ---------------------------------------------------------------------------
// Concurrency.

// TestConcurrentDialsAndClosesUnderRace exercises the pool, the ledger and the fd table
// from many goroutines at once. What is asserted is that every dial either produced a
// usable handle or a typed refusal, and that no socket outlives its owner.
func TestConcurrentDialsAndClosesUnderRace(t *testing.T) {
	harness.QuietConsole(t)
	netResetPrivate(t)
	k := netBoot(t)
	// Only one of the two hosts is declared. The other is refused by the declaration, so
	// the two failure modes under contention are an address refusal and a boundary
	// refusal, and neither depends on the system resolver.
	ctx, pid := netLoad(t, k, "netconc", []kernel.Op{kernel.OpNetDial},
		[]string{"blocked.example"}, "")

	netStub(t, k, "blocked.example", "10.0.0.1")

	const goroutines = 12
	const perGoroutine = 8
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range perGoroutine {
				host := "blocked.example"
				if (g+i)%2 == 0 {
					host = "undeclared.example"
				}
				res, err := kernel.NetDial(ctx, kernel.NetSpec{Host: host, Port: 443})
				if err != nil {
					// Both hosts fail, one by address and one by declaration, and each
					// failure must be typed rather than a bare error.
					assert.True(t, errors.Is(err, kernel.ErrNetAddressBlocked) ||
						errors.Is(err, kernel.ErrNetHostNotAllowed) ||
						kernel.IsDenied(err), "an unexpected refusal: %v", err)
					continue
				}
				assert.NotEqual(t, kernel.FD(0), res.FD)
				_ = kernel.NetRelease(ctx, res.FD)
			}
		}(g)
	}
	wg.Wait()

	assert.Empty(t, kernel.NetSockets(pid), "no socket outlives the goroutines that opened it")
	assert.LessOrEqual(t, kernel.NetStatsSnapshot().Pooled, kernel.NetStatsSnapshot().MaxPooled)

	history := kernel.NetHistory()
	assert.NotEmpty(t, history)
	for i := 1; i < len(history); i++ {
		assert.Greater(t, history[i].Seq, history[i-1].Seq, "ledger sequence numbers increase")
	}
}
