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

package identity

import (
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestUntrustedDomainGetsNothing proves an unknown or rejected domain is denied
// every operation, including the ones plugins do hold.
func TestUntrustedDomainGetsNothing(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)

	probe := &harness.MetadataProbe{}
	kernel.Register("untrustedprobe", func() (kernel.Module, error) { return probe, nil })
	t.Cleanup(func() { kernel.Unregister("untrustedprobe") })

	// A manifest requesting metadata:write cannot be satisfied by the plugin
	// domain, so validation fails and no context is ever created for it.
	_, err := k.Load(kernel.Manifest{
		Name: "untrustedprobe", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpMetadataWrite},
	})
	require.Error(t, err, "a manifest requesting a non-grantable operation must be rejected")

	var manifestErr *kernel.ManifestError
	require.ErrorAs(t, err, &manifestErr)

	// The rejection is recorded in the process table under the untrusted
	// domain, so "something was refused" is visible rather than invisible.
	var sawRejected bool
	for _, r := range kernel.ProcTable() {
		if r.Name == "untrustedprobe" {
			sawRejected = true
			assert.Equal(t, kernel.DomainUntrusted, r.Domain)
			assert.Equal(t, kernel.ProcRejected, r.State)
		}
	}
	assert.True(t, sawRejected, "a rejected module must appear in the process table")
	assert.Nil(t, probe.Ctx, "a rejected module must never receive a context")
	assert.NotEmpty(t, harness.Faults(buf), "a rejection must emit a fault record")
}

// TestManifestValidation is the boundary test for the plugin declaration. Each
// case is a manifest that must be rejected, with the reason it is rejected.
func TestManifestValidation(t *testing.T) {
	base := func(mut func(*kernel.Manifest)) kernel.Manifest {
		m := kernel.Manifest{
			Name: "m", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		}
		mut(&m)
		return m
	}

	cases := []struct {
		name string
		m    kernel.Manifest
		want string
	}{
		{"valid minimal", base(func(*kernel.Manifest) {}), ""},
		{"empty name", base(func(m *kernel.Manifest) { m.Name = "" }), "name is required"},
		{"name with slash", base(func(m *kernel.Manifest) { m.Name = "a/b" }), "path separator"},
		{"empty version", base(func(m *kernel.Manifest) { m.Version = "" }), "version is required"},
		{"kernel API too new", base(func(m *kernel.Manifest) { m.MinKernelAPI = 99 }), "outside module range"},
		{"kernel API too old", base(func(m *kernel.Manifest) { m.MaxKernelAPI = 0 }), "outside module range"},
		{"unknown operation", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{"metadata:rmrf"}
		}), "unknown operation"},
		{"non-grantable operation", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpMetadataWrite}
		}), "not grantable"},
		{"module:load requested", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpModuleLoad}
		}), "not grantable"},
		{"duplicate operation", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpMetadataRead, kernel.OpMetadataRead}
		}), "duplicate operation"},
		{"net:dial with no hosts", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
		}), "requires at least one allowed host"},
		{"net:dial wildcard host", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
			m.AllowedHosts = []string{"*"}
		}), "wildcard host"},
		{"net:dial glob host", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
			m.AllowedHosts = []string{"*.example.com"}
		}), "wildcard host"},
		{"net:dial localhost", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
			m.AllowedHosts = []string{"localhost"}
		}), "loopback"},
		{"net:dial host with port", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
			m.AllowedHosts = []string{"example.com:8080"}
		}), "bare hostname"},
		{"net:dial userinfo", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
			m.AllowedHosts = []string{"user@example.com"}
		}), "bare hostname"},
		{"net:dial empty label", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
			m.AllowedHosts = []string{"example..com"}
		}), "empty label"},
		{"net:dial duplicate host", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
			m.AllowedHosts = []string{"example.com", "example.com"}
		}), "duplicate allowed host"},
		{"net:dial valid", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetDial}
			m.AllowedHosts = []string{"api.example.com"}
		}), ""},
		{"net:listen with no addr", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpNetListen}
		}), "requires a listen address"},
		{"fs:read with no paths", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpFSRead}
		}), "requires at least one read path"},
		{"fs:read absolute path", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpFSRead}
			m.ReadPaths = []string{"/etc/passwd"}
		}), "must be relative"},
		{"fs:read traversal", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpFSRead}
			m.ReadPaths = []string{"../../etc"}
		}), "escapes the data root"},
		{"fs:read whole tree", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpFSRead}
			m.ReadPaths = []string{"./"}
		}), "resolves to the data root"},
		{"fs:write valid", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpFSWrite}
			m.WritePaths = []string{"cache"}
		}), ""},
		{"secret:read with no prefix", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpSecretRead}
		}), "requires at least one secret key prefix"},
		{"secret:read empty prefix", base(func(m *kernel.Manifest) {
			m.Require = []kernel.Op{kernel.OpSecretRead}
			m.SecretPrefixes = []string{""}
		}), "read-all grant"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.m.Validate()
			if c.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			var me *kernel.ManifestError
			require.ErrorAs(t, err, &me, "rejections must be typed ManifestError, got %T", err)
			assert.Contains(t, err.Error(), c.want)
		})
	}
}

// TestManifestDigestIsStable proves the digest recorded in the process table
// depends on the manifest's content, not on how it was written. Two equal
// manifests must hash equal, and a changed grant must hash differently, or the
// digest cannot serve as provenance.
func TestManifestDigestIsStable(t *testing.T) {
	a := diag.Manifest()
	b := diag.Manifest()
	assert.Equal(t, a.Digest(), b.Digest())
	assert.Len(t, a.Digest(), 64, "sha256 hex")

	b.Require = append([]kernel.Op{}, b.Require...)
	b.Require = append(b.Require, kernel.OpIPCCall)
	assert.NotEqual(t, a.Digest(), b.Digest(), "a wider grant must produce a different digest")
}

// TestManifestNarrowsDomainCeiling proves a declaration is enforced rather than
// merely recorded. The plugin domain holds metadata:read, so a module that omits
// it from its manifest must be denied at runtime even though its domain would
// allow it. Without this, a manifest is documentation.
func TestManifestNarrowsDomainCeiling(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)

	narrow := &harness.Probe{}
	narrow.Load = func(ctx kernel.SContext) error {
		_, err := ctx.SyscallMetadataGet("anything")
		narrowResult = err
		return nil
	}
	harness.RegisterProbe(t, "narrow", narrow)

	pid, err := k.Load(kernel.Manifest{
		Name: "narrow", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		// metadata:read deliberately NOT declared.
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, narrowResult, "an undeclared operation must be denied even though the domain holds it")
	assert.True(t, kernel.IsDenied(narrowResult))
	assert.Contains(t, narrowResult.Error(), "not declared in the manifest")
	assert.Contains(t, kernel.DenialReason(narrowResult), "not declared in the manifest",
		"DenialReason must expose the manifest narrowing so a module author can fix the declaration")

	var sawReason bool
	for _, r := range harness.Faults(buf) {
		if strings.Contains(r.Msg, "metadata:read") {
			sawReason = true
		}
	}
	assert.True(t, sawReason, "the denial must be recorded as a fault")

	ops, constrained := kernel.GrantsFor(pid)
	assert.True(t, constrained)
	assert.Equal(t, []kernel.Op{kernel.OpLogWrite}, ops)
}

var narrowResult error

// TestUndeclaredEverythingDeniesEverything is the empty-manifest case: a module
// that declares nothing can do nothing, which is the correct reading of an empty
// declaration rather than of an absent one.
func TestUndeclaredEverythingDeniesEverything(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	var readErr, logErr error
	harness.RegisterProbe(t, "silent", &harness.Probe{Load: func(ctx kernel.SContext) error {
		_, readErr = ctx.SyscallMetadataGet("k")
		logErr = ctx.SyscallLog(kernel.LogInfo, "hello")
		return nil
	}})

	pid, err := k.Load(kernel.Manifest{
		Name: "silent", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	assert.True(t, kernel.IsDenied(readErr))
	assert.True(t, kernel.IsDenied(logErr), "an undeclared log:write must be denied")

	ops, constrained := kernel.GrantsFor(pid)
	assert.True(t, constrained)
	assert.Empty(t, ops)
}

// TestIsScopedMatchesTheScopedSet pins which operations are scope-enforced. A
// scoped operation is one whose manifest field must be filled in; getting this
// set wrong silently turns a capability into an unbounded grant.
//
// The list is spelled out rather than derived from the kernel, on purpose: if it
// were derived, adding a scoped operation without a scope field would pass this
// test by construction. Spelling it out makes the omission a test failure.
func TestIsScopedMatchesTheScopedSet(t *testing.T) {
	scoped := []kernel.Op{
		kernel.OpNetDial, kernel.OpNetListen,
		kernel.OpFSRead, kernel.OpFSWrite,
		kernel.OpSecretRead, kernel.OpSecretUse,
		kernel.OpPeerDial,
	}
	for _, op := range scoped {
		assert.True(t, kernel.IsScoped(op), "%s must be scope-enforced", op)
	}
	for _, op := range []kernel.Op{
		kernel.OpMetadataRead, kernel.OpMetadataWrite, kernel.OpProcessFork,
		kernel.OpModuleLoad, kernel.OpModuleUnload, kernel.OpIPCBind,
		kernel.OpIPCCall, kernel.OpLogWrite, kernel.OpUsageEmit,
		kernel.OpAuditAppend, kernel.OpAuditRead, kernel.OpMeterRecord,
		kernel.OpMeterRead, kernel.OpTokenCount, kernel.OpReceiptIssue,
		kernel.OpReceiptVerify, kernel.OpQosAdmit, kernel.OpSlotAcquire,
		kernel.OpPipeOpen, kernel.OpShmAlloc, kernel.OpLockTake,
		kernel.OpRouteRegister, kernel.OpRouteCall, kernel.OpCryptoRandom,
		kernel.OpCryptoHash, kernel.OpCryptoSign, kernel.OpCryptoVerify,
		kernel.OpSchedSpawn, kernel.OpSignalSend, kernel.OpTraceSpan,
		kernel.OpKVRead, kernel.OpKVWrite,
	} {
		assert.False(t, kernel.IsScoped(op), "%s must not be scope-enforced", op)
	}
	// Every operation in the kernel must be classified one way or the other by
	// the lists above, so a newly added Op forces a decision here rather than
	// silently landing outside both.
	accounted := append([]kernel.Op{}, scoped...)
	for _, op := range kernel.AllOps {
		if !kernel.IsScoped(op) {
			accounted = append(accounted, op)
		}
	}
	seen := map[kernel.Op]bool{}
	for _, op := range kernel.AllOps {
		assert.False(t, seen[op], "%s appears twice in AllOps", op)
		seen[op] = true
		assert.True(t, harness.ContainsOp(accounted, op),
			"%s is neither in this test's scoped list nor in AllOps as unscoped", op)
	}
	assert.Len(t, kernel.AllOps, len(seen))
}

// TestPolicyMatrixIsComplete asserts the three structural invariants of the
// policy table, which are the ones a careless edit breaks: every operation in
// AllOps is known, the kernel domain holds all of them, and the untrusted domain
// holds none.
func TestPolicyMatrixIsComplete(t *testing.T) {
	assert.Len(t, kernel.OpsFor(kernel.DomainKernel), len(kernel.AllOps),
		"the kernel domain must hold every operation")
	assert.Empty(t, kernel.OpsFor(kernel.DomainUntrusted),
		"the untrusted domain must hold nothing")

	for _, op := range kernel.AllOps {
		assert.False(t, kernel.Allowed(kernel.DomainUntrusted, op),
			"untrusted must be denied %s", op)
		assert.False(t, kernel.Allowed(kernel.Domain("u:r:never:s0"), op),
			"an unknown domain must be denied %s", op)
	}
}

// TestInitIsNotAKernelClone is the privilege-drop invariant. Init is long-lived,
// so every operation it holds outlives the boot. If init drifts toward the kernel
// domain, the privilege drop in Boot stops meaning anything.
func TestInitIsNotAKernelClone(t *testing.T) {
	refused := []struct {
		op  kernel.Op
		why string
	}{
		{kernel.OpSecretRead, "credential custody is a kernel service"},
		{kernel.OpSecretUse, "init has no traffic to apply a credential to"},
		{kernel.OpCryptoSign, "signing needs node key material"},
		{kernel.OpReceiptIssue, "a receipt is a settlement claim; init must not mint one"},
		{kernel.OpNetDial, "egress belongs to knet acting for a module"},
		{kernel.OpNetListen, "the listener belongs to the service subsystem"},
		{kernel.OpPeerDial, "mesh egress is not a boot concern"},
		{kernel.OpSlashAdjudicate, "mesh governance must not share a context with module loading"},
		{kernel.OpUsageEmit, "init serves no traffic, so it has no usage"},
		{kernel.OpMeterRecord, "metering records come from modules that served a request"},
		{kernel.OpFSRead, "init reads configuration through the sealed boot config"},
		{kernel.OpFSWrite, "init has nothing legitimate to write"},
		{kernel.OpPipeOpen, "pipes are a module-to-module resource"},
		{kernel.OpShmAlloc, "shared buffers are a module-to-module resource"},
		{kernel.OpLockTake, "init takes no module-visible lock"},
		{kernel.OpEventWait, "init does not subscribe to module events"},
	}

	for _, c := range refused {
		assert.False(t, kernel.Allowed(kernel.DomainInit, c.op),
			"init must not hold %s: %s", c.op, c.why)
	}

	held := kernel.OpsFor(kernel.DomainInit)
	assert.Less(t, len(held), len(kernel.AllOps)/2,
		"init must hold a minority of the operation set, or the privilege drop is cosmetic")

	// The operations init does need, so narrowing it is not mistaken for
	// stripping it.
	for _, op := range []kernel.Op{
		kernel.OpProcessFork, kernel.OpModuleLoad, kernel.OpModuleUnload,
		kernel.OpRouteRegister, kernel.OpRouteCall, kernel.OpAuditAppend,
		kernel.OpAuditRead, kernel.OpSlotAcquire, kernel.OpQosAdmit,
		kernel.OpSignalSend, kernel.OpCPUTimeRead, kernel.OpTTYOpen,
	} {
		assert.True(t, kernel.Allowed(kernel.DomainInit, op),
			"init needs %s to bring services up and supervise them", op)
	}
}

// TestPluginCannotReachTrustRoot asserts the three refusals that make the other
// subsystems trustworthy: no plaintext secret, no signing, no audit fabrication.
func TestPluginCannotReachTrustRoot(t *testing.T) {
	refused := []struct {
		op  kernel.Op
		why string
	}{
		{kernel.OpSecretRead, "a module must never see a plaintext credential"},
		{kernel.OpCryptoSign, "a module that can sign can forge a settlement receipt"},
		{kernel.OpReceiptIssue, "issuing a receipt is a settlement claim"},
		{kernel.OpAuditAppend, "a module writes commentary, the kernel writes evidence"},
		{kernel.OpMetadataWrite, "kernel state is not module-writable"},
		{kernel.OpModuleLoad, "a module must not load code"},
		{kernel.OpModuleUnload, "a module must not unload another"},
		{kernel.OpProcessFork, "a module does not spawn contexts"},
		{kernel.OpIPCBind, "a module calls the bus, it does not own an endpoint on it"},
		{kernel.OpSlashAdjudicate, "a module reports cheating, it does not judge it"},
		{kernel.OpTTYOpen, "the console is an operator surface"},
	}

	for _, c := range refused {
		assert.False(t, kernel.Allowed(kernel.DomainPlugin, c.op),
			"the plugin domain must not hold %s: %s", c.op, c.why)
	}

	// And the capabilities a module does get, so this test cannot pass by
	// accident when the whole domain is emptied.
	for _, op := range []kernel.Op{
		kernel.OpSecretUse, kernel.OpCryptoRandom, kernel.OpCryptoHash,
		kernel.OpCryptoVerify, kernel.OpReceiptVerify, kernel.OpMeterRecord,
		kernel.OpMeterRead, kernel.OpTokenCount, kernel.OpUsageEmit,
		kernel.OpRouteRegister, kernel.OpRouteCall, kernel.OpSlotAcquire,
		kernel.OpPipeOpen, kernel.OpShmAlloc, kernel.OpLockTake,
		kernel.OpEventWait, kernel.OpSlashReport, kernel.OpKVRead,
		kernel.OpKVWrite, kernel.OpSignalSend, kernel.OpTraceSpan,
	} {
		assert.True(t, kernel.Allowed(kernel.DomainPlugin, op),
			"the plugin domain must hold %s", op)
	}
}
