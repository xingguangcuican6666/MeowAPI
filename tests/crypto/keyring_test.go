/*
Copyright (C) 2023-2026 xingguangcuican6666

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

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// These tests drive kkeyring through the module-reachable syscall surface. The
// property under test in every one of them is the same: the module gets a result, and
// never the credential. Where a test needs the plaintext to build an expectation it
// computes that expectation from a value the test itself supplied, not from anything
// the kernel returned.

// krBuf is a mutex-guarded console sink, so tests asserting on faults do not race the
// goroutine emitting them.
type krBuf struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *krBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *krBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// krQuiet redirects the kernel console and returns the buffer.
func krQuiet(t *testing.T) *krBuf {
	t.Helper()
	sink := &krBuf{}
	kernel.KernelConsole().SetOutput(sink)
	t.Cleanup(func() { kernel.KernelConsole().SetOutput(nil) })
	return sink
}

// krBoot starts a kernel with a minimal trust root. Credentials are installed by the
// host process afterwards, which is the shape the policy table forces: no live
// context holds secret:read, so custody is a host operation.
func krBoot(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "kr-node"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// krManifest declares a module that uses secrets under the given prefixes. The
// prefixes are the scope the keyring enforces at call time.
func krManifest(name string, prefixes []string, ops ...kernel.Op) kernel.Manifest {
	return kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: ops, SecretPrefixes: prefixes,
	}
}

// krModule is a probe module that runs one callback during OnLoad and keeps its
// context, so a test can drive several calls after the load completes.
type krModule struct {
	onLoad func(ctx kernel.SContext) error
	ctx    kernel.SContext
}

func (m *krModule) OnLoad(ctx kernel.SContext) error {
	m.ctx = ctx
	if m.onLoad != nil {
		return m.onLoad(ctx)
	}
	return nil
}
func (m *krModule) OnUnload() error { return nil }

// krLoad registers and loads a module.
func krLoad(t *testing.T, k *kernel.Kernel, m kernel.Module, mf kernel.Manifest) kernel.PID {
	t.Helper()
	kernel.Register(mf.Name, func() (kernel.Module, error) { return m, nil })
	t.Cleanup(func() { kernel.Unregister(mf.Name) })
	pid, err := k.Load(mf)
	require.NoError(t, err)
	return pid
}

// krSecretValue is the credential the tests install. It is a constant known to the
// test, so every expectation below is computed from this and from nothing the kernel
// handed back.
const krSecretValue = "sk-test-credential-do-not-leak"

// krInstall puts a credential under an alias through the host-only path.
func krInstall(t *testing.T, k *kernel.Kernel, alias, header, scheme, value string) {
	t.Helper()
	require.NoError(t, k.InstallSecret(kernel.SecretSpec{
		Alias: alias, Header: header, Scheme: scheme, Value: []byte(value),
	}))
}

// krHMAC computes the expected MAC the same way the kernel does, from the test's own
// copy of the credential.
func krHMAC(secret, data string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(data))
	return m.Sum(nil)
}

// TestSecretUseSignReturnsOnlyTheResult is the grant. The module asks for an HMAC and
// receives an HMAC, and the credential itself is nowhere in the result.
func TestSecretUseSignReturnsOnlyTheResult(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.api.key", "", "", krSecretValue)

	m := &krModule{}
	krLoad(t, k, m, krManifest("krsigner", []string{"provider."}, kernel.OpSecretUse))

	res, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("body"))
	require.NoError(t, err)
	assert.Equal(t, "provider.api.key", res.Alias)
	assert.Equal(t, kernel.SecretActionSign, res.Action)
	assert.Equal(t, krHMAC(krSecretValue, "body"), res.MAC,
		"the MAC must be the real HMAC over the caller's data")

	// The result must not contain the credential, in any field, in any encoding.
	assert.NotContains(t, string(res.MAC), krSecretValue)
	assert.Zero(t, res.FD)
	assert.Empty(t, res.Header)

	// The audit record names the alias and the action and nothing else.
	entries := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditSecret})
	require.NotEmpty(t, entries)
	used := entries[len(entries)-1]
	assert.Equal(t, "provider.api.key", used.Fields["alias"])
	assert.Equal(t, "sign", used.Fields["action"])
	for key, value := range used.Fields {
		assert.NotEqual(t, krSecretValue, value, "field %q carries the credential", key)
	}
}

// TestSecretUseMatchIsConstantTimeAndVerdictOnly covers the inbound-authentication
// action. A module can authenticate a token it was handed without ever holding the
// stored one, and the answer is a bool.
func TestSecretUseMatchIsConstantTimeAndVerdictOnly(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "auth.token", "", "", krSecretValue)

	m := &krModule{}
	krLoad(t, k, m, krManifest("krmatcher", []string{"auth."}, kernel.OpSecretUse))

	good, err := m.ctx.SyscallSecretUse("auth.token", kernel.SecretActionMatch, []byte(krSecretValue))
	require.NoError(t, err)
	assert.True(t, good.Match, "the real credential must match")
	assert.Empty(t, good.MAC)

	bad, err := m.ctx.SyscallSecretUse("auth.token", kernel.SecretActionMatch, []byte(krSecretValue+"x"))
	require.NoError(t, err)
	assert.False(t, bad.Match)

	// A prefix of the credential must not match: an early-returning comparison would
	// report success on a partial match, and that is the side channel this action
	// exists to avoid.
	prefix, err := m.ctx.SyscallSecretUse("auth.token", kernel.SecretActionMatch,
		[]byte(krSecretValue[:len(krSecretValue)-1]))
	require.NoError(t, err)
	assert.False(t, prefix.Match)

	_, err = m.ctx.SyscallSecretUse("auth.token", kernel.SecretActionMatch, nil)
	require.Error(t, err, "matching against nothing must be refused")
}

// TestSecretUseHeaderSealsTheValue covers the action a provider adaptor needs. The
// rendered header value stays inside the kernel: the module receives a handle and a
// header name, and the network layer is the only thing that can open the handle.
func TestSecretUseHeaderSealsTheValue(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.bearer", "Authorization", "Bearer ", krSecretValue)

	m := &krModule{}
	pid := krLoad(t, k, m, krManifest("krheader", []string{"provider."}, kernel.OpSecretUse))

	res, err := m.ctx.SyscallSecretUse("provider.bearer", kernel.SecretActionHeader, []byte("api.example.com"))
	require.NoError(t, err)
	assert.Equal(t, "Authorization", res.Header, "the header name is not a secret")
	assert.NotZero(t, res.FD)
	assert.Empty(t, res.MAC)
	assert.False(t, res.Match)
	assert.Equal(t, 1, kernel.FDCount(pid))
	assert.Equal(t, "secret", krKindOf(pid, res.FD))

	// The handle is per pid. Another module that guesses the same number finds
	// nothing in its own table, which is the isolation property: there is no object
	// reference to hand over, so there is nothing to steal.
	thief := &krModule{}
	thiefPid := krLoad(t, k, thief, krManifest("krthief", []string{"provider."}, kernel.OpSecretUse))
	assert.NotEqual(t, thiefPid, pid)
	assert.Zero(t, kernel.FDCount(thiefPid))
	assert.Error(t, thief.ctx.SyscallClose(res.FD),
		"another pid must not resolve this handle")
	assert.Equal(t, 1, kernel.FDCount(pid), "the guess must not disturb the owner's handle")

	// Closing wipes the value and releases the handle.
	require.NoError(t, m.ctx.SyscallClose(res.FD))
	assert.Zero(t, kernel.FDCount(pid))
	assert.Error(t, m.ctx.SyscallClose(res.FD), "a second close must report the resource as closed")
}

// krKindOf reports the kind of an open handle.
func krKindOf(pid kernel.PID, fd kernel.FD) string {
	for _, info := range kernel.FDList(pid) {
		if info.FD == fd {
			return info.Kind
		}
	}
	return ""
}

// TestSecretUseDeniedWithoutDeclaration is the denial: a module that declared nothing
// cannot use a credential, and the refusal reaches the audit chain.
func TestSecretUseDeniedWithoutDeclaration(t *testing.T) {
	buf := krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.api.key", "", "", krSecretValue)

	m := &krModule{}
	krLoad(t, k, m, krManifest("krnogrant", nil))

	_, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("body"))
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "a module without secret:use must be denied: %v", err)
	assert.Contains(t, err.Error(), "secret:use")
	assert.Zero(t, kernel.FDCount(m.ctx.PID()))

	denials := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial})
	found := false
	for _, e := range denials {
		if e.Fields["op"] == "secret:use" && e.PID == m.ctx.PID() {
			found = true
		}
	}
	assert.True(t, found, "the denial must name the operation and the pid")

	// Init holds neither secret operation, which is the second refusal the policy
	// table encodes: a long-lived holder of a plaintext key is a long-lived exposure.
	_, initErr := k.InitContext().SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("b"))
	require.Error(t, initErr)
	assert.True(t, kernel.IsDenied(initErr))
	_, readErr := k.InitContext().SyscallSecretRead("provider.api.key")
	require.Error(t, readErr)
	assert.True(t, kernel.IsDenied(readErr), "init must not read plaintext credentials either")

	assert.Contains(t, buf.String(), "avc: denied { secret:use }",
		"the denial must be visible on the console in the canonical form")
}

// TestSecretPrefixScopeIsEnforced is the scope control. A module declares the
// prefixes it needs and gets nothing outside them, and the enumeration path is
// narrowed the same way the use path is.
func TestSecretPrefixScopeIsEnforced(t *testing.T) {
	buf := krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.a", "", "", krSecretValue)
	krInstall(t, k, "provider.b", "", "", krSecretValue)
	krInstall(t, k, "database.password", "", "", krSecretValue)
	krInstall(t, k, "mesh.peer.key", "", "", krSecretValue)

	m := &krModule{}
	krLoad(t, k, m, krManifest("krscoped", []string{"provider.a", "mesh."}, kernel.OpSecretUse))

	aliases, err := m.ctx.SyscallSecretAliases()
	require.NoError(t, err)
	assert.Equal(t, []string{"mesh.peer.key", "provider.a"}, aliases,
		"the visible set is the declared set, sorted")

	_, err = m.ctx.SyscallSecretUse("provider.a", kernel.SecretActionSign, []byte("x"))
	require.NoError(t, err)

	for _, outside := range []string{"provider.b", "database.password"} {
		_, err := m.ctx.SyscallSecretUse(outside, kernel.SecretActionSign, []byte("x"))
		require.Error(t, err, "%s is outside the declaration", outside)
		var secretErr *kernel.SecretError
		require.True(t, errors.As(err, &secretErr), "got %T", err)
		assert.False(t, kernel.IsDenied(err),
			"a scope refusal is not a policy denial: the module holds secret:use")
	}

	// An out-of-scope alias and an unknown alias must be indistinguishable, or this
	// call becomes an oracle for which credentials the deployment holds.
	_, unknown := m.ctx.SyscallSecretUse("provider.does-not-exist", kernel.SecretActionSign, []byte("x"))
	_, scoped := m.ctx.SyscallSecretUse("database.password", kernel.SecretActionSign, []byte("x"))
	assert.Equal(t, unknown.Error(), scoped.Error(),
		"the error must not reveal whether an out-of-scope alias exists")

	// Both refusals are escalations, because asking outside the declaration is an
	// attempt to widen a grant.
	escalations := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation})
	require.NotEmpty(t, escalations)
	// A scope refusal is a fault on the console, not an avc denial: the module holds
	// secret:use, it asked for something outside what it declared.
	assert.Contains(t, buf.String(), "secret use refused")
	assert.Contains(t, buf.String(), "outside the declared secret prefixes")
}

// TestSecretScopeIsNotInheritedByASpawnedChild is the fail-closed property of the
// scope table. A module may spawn a child context in the plugin domain, and that child
// carries no manifest of its own, so the kernel does not know what it may see and
// gives it nothing. Inheriting the parent's scope would let a module widen its own
// declaration at runtime by handing a child the alias it was not granted.
func TestSecretScopeIsNotInheritedByASpawnedChild(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.api.key", "", "", krSecretValue)

	parent := &krModule{}
	krLoad(t, k, parent, krManifest("krparent", []string{"provider."}, kernel.OpSecretUse))

	// The parent is in scope and can use the credential.
	_, err := parent.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("x"))
	require.NoError(t, err)

	// A plugin cannot spawn, so the reachable way to get a plugin-domain context
	// with no manifest behind it is init spawning one directly. That context carries
	// the plugin domain's ceiling - including secret:use - and no declaration at all.
	child, err := k.InitContext().SyscallSpawn(kernel.DomainPlugin, "krchild")
	require.NoError(t, err)
	require.NotNil(t, child)

	_, err = child.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("x"))
	require.Error(t, err, "a spawned child must not inherit its parent's secret scope")
	var secretErr *kernel.SecretError
	require.True(t, errors.As(err, &secretErr))
	assert.False(t, kernel.IsDenied(err),
		"the child holds secret:use; what it lacks is a declaration")

	aliases, err := child.SyscallSecretAliases()
	require.NoError(t, err)
	assert.Empty(t, aliases, "an unknown scope enumerates nothing")
}

// TestSecretScopeIsDenyByDefault pins the empty-declaration case, which is the one
// that would otherwise be read generously. A module that declared no prefixes sees no
// alias and uses none, and an empty prefix string is not a wildcard.
func TestSecretScopeIsDenyByDefault(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.api.key", "", "", krSecretValue)

	undeclared := &krModule{}
	krLoad(t, k, undeclared, krManifest("krundeclared", nil, kernel.OpSecretUse))

	aliases, err := undeclared.ctx.SyscallSecretAliases()
	require.NoError(t, err)
	assert.Empty(t, aliases, "a module with no declaration enumerates nothing")
	_, err = undeclared.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("x"))
	require.Error(t, err)

	// An empty prefix would match every alias, so it is skipped rather than honored.
	empty := &krModule{}
	krLoad(t, k, empty, krManifest("krempty", []string{""}, kernel.OpSecretUse))
	aliases, err = empty.ctx.SyscallSecretAliases()
	require.NoError(t, err)
	assert.Empty(t, aliases, "an empty prefix is not a read-all grant")
	_, err = empty.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("x"))
	require.Error(t, err)
}

// TestSecretCeilingIsTyped covers every ceiling the keyring enforces, and proves a
// refusal leaves the store usable rather than corrupted.
func TestSecretCeilingIsTyped(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)

	// A credential over the value ceiling is refused as a typed limit error.
	tooBig := make([]byte, kernel.MaxSecretValueBytes()+1)
	for i := range tooBig {
		tooBig[i] = 'k'
	}
	err := k.InstallSecret(kernel.SecretSpec{Alias: "big.key", Value: tooBig})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrSecretLimit), "got %v", err)
	// The caller's slice was wiped even though the install was refused, because
	// ownership transferred on the call.
	assert.Equal(t, byte(0), tooBig[0], "a refused install must still wipe the caller's value")

	// An empty value is a caller bug, not a limit.
	err = k.InstallSecret(kernel.SecretSpec{Alias: "empty.key", Value: nil})
	require.Error(t, err)
	assert.False(t, errors.Is(err, kernel.ErrSecretLimit))

	// A malformed alias is refused before anything is stored.
	for _, alias := range []string{"", "has space", "new\nline", strings.Repeat("a", 200)} {
		err := k.InstallSecret(kernel.SecretSpec{Alias: alias, Value: []byte(krSecretValue)})
		require.Error(t, err, "alias %q must be refused", alias)
	}
	// A header name carrying a control character would be a header-injection vector.
	err = k.InstallSecret(kernel.SecretSpec{
		Alias: "inject.key", Header: "X-Bad\r\nInjected: 1", Value: []byte(krSecretValue),
	})
	require.Error(t, err)

	// The data ceiling applies to the use path as well.
	krInstall(t, k, "provider.api.key", "", "", krSecretValue)
	m := &krModule{}
	krLoad(t, k, m, krManifest("krceil", []string{"provider."}, kernel.OpSecretUse))
	_, err = m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign,
		make([]byte, kernel.MaxCryptoInputBytes()+1))
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrSecretLimit), "got %v", err)

	// An unknown action is refused rather than defaulted, because a default branch
	// here would be a way to ask for "whatever returns the value".
	_, err = m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretAction("decrypt"), []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown secret action")
	_, err = m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, nil)
	require.Error(t, err, "sign requires data")

	// The store is intact after all of that.
	require.Equal(t, 1, kernel.SecretCount())
	res, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("body"))
	require.NoError(t, err)
	assert.Equal(t, krHMAC(krSecretValue, "body"), res.MAC)
}

// TestSecretHandlesAreReclaimedOnUnload is the reclaim property, and it is the reason
// a sealed header value cannot outlive the module that asked for it.
func TestSecretHandlesAreReclaimedOnUnload(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.a", "", "", krSecretValue)
	krInstall(t, k, "provider.b", "", "", krSecretValue)

	m := &krModule{}
	pid := krLoad(t, k, m, krManifest("krreclaim", []string{"provider."}, kernel.OpSecretUse))

	var opened []kernel.FD
	for _, alias := range []string{"provider.a", "provider.b"} {
		res, err := m.ctx.SyscallSecretUse(alias, kernel.SecretActionHeader, []byte("api.example.com"))
		require.NoError(t, err)
		opened = append(opened, res.FD)
	}
	require.Len(t, opened, 2)
	assert.Equal(t, 2, kernel.FDCount(pid))

	require.NoError(t, k.Unload(pid))
	assert.Zero(t, kernel.FDCount(pid), "unload must reclaim every sealed header handle")
	assert.Empty(t, kernel.FDList(pid))
}

// TestSecretHandlesAreReclaimedWhenModulePanics is the crash path: a module that
// dies holding sealed credentials leaks nothing and gets no chance to clean up after
// itself. The kernel recovers the panic and still walks the handle table, which is
// the property that makes a broken provider adaptor a restart rather than a leak.
func TestSecretHandlesAreReclaimedWhenModulePanics(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.a", "", "", krSecretValue)
	krInstall(t, k, "provider.b", "", "", krSecretValue)

	panicker := &krPanics{}
	pid := krLoad(t, k, panicker, krManifest("krpanics", []string{"provider."}, kernel.OpSecretUse))

	// Seal two credentials against this pid, then make the module die.
	var opened []kernel.FD
	for _, alias := range []string{"provider.a", "provider.b"} {
		res, err := panicker.ctx.SyscallSecretUse(alias, kernel.SecretActionHeader, []byte("api.example.com"))
		require.NoError(t, err)
		opened = append(opened, res.FD)
	}
	require.Len(t, opened, 2)
	assert.Equal(t, 2, kernel.FDCount(pid))

	panicker.panicOnUnload = true
	err := k.Unload(pid)
	require.Error(t, err)
	require.ErrorContains(t, err, "OnUnload panicked")

	assert.Zero(t, kernel.FDCount(pid), "a panicking module must leak no sealed credential")
	assert.Empty(t, kernel.FDList(pid))
	assert.Equal(t, kernel.ProcTerminated, krProcState(pid),
		"the record still closes as terminated: the panic is contained, not fatal")
}

// krPanics is a module that seals credentials and can be made to die during teardown.
type krPanics struct {
	ctx           kernel.SContext
	panicOnUnload bool
}

func (m *krPanics) OnLoad(ctx kernel.SContext) error { m.ctx = ctx; return nil }
func (m *krPanics) OnUnload() error {
	if m.panicOnUnload {
		panic("provider adaptor exploded")
	}
	return nil
}

// krProcState reads a pid's state from the process table.
func krProcState(pid kernel.PID) kernel.ProcState {
	for _, r := range kernel.ProcTable() {
		if r.PID == pid {
			return r.State
		}
	}
	return ""
}

// TestSecretHandleCeilingIsTyped proves the handle ceiling reaches the sealed header
// path too, and that a refused seal does not leave a rendered credential behind or
// consume a handle.
func TestSecretHandleCeilingIsTyped(t *testing.T) {
	krQuiet(t)
	tr := kernel.BootTrustRoot{
		NodeID: "kr-node",
		Limits: kernel.BootLimits{MaxOpenFDsPerModule: 1},
	}
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: tr})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	krInstall(t, k, "provider.a", "", "", krSecretValue)
	krInstall(t, k, "provider.b", "", "", krSecretValue)

	m := &krModule{}
	pid := krLoad(t, k, m, krManifest("krhandleceil", []string{"provider."}, kernel.OpSecretUse))

	first, err := m.ctx.SyscallSecretUse("provider.a", kernel.SecretActionHeader, []byte("h1"))
	require.NoError(t, err)
	assert.Equal(t, 1, kernel.FDCount(pid))

	_, err = m.ctx.SyscallSecretUse("provider.b", kernel.SecretActionHeader, []byte("h2"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrSecretLimit), "got %v", err)
	assert.Equal(t, 1, kernel.FDCount(pid), "a refused seal must not consume a handle")

	// The signing action still works under the same ceiling, because it allocates no
	// handle at all.
	res, err := m.ctx.SyscallSecretUse("provider.b", kernel.SecretActionSign, []byte("body"))
	require.NoError(t, err)
	assert.Equal(t, krHMAC(krSecretValue, "body"), res.MAC)

	require.NoError(t, m.ctx.SyscallClose(first.FD))
	second, err := m.ctx.SyscallSecretUse("provider.b", kernel.SecretActionHeader, []byte("h2"))
	require.NoError(t, err, "closing must free the slot")
	assert.NotZero(t, second.FD)
}

// TestSecretRevocationStopsUse covers rotation, which is the operational reason a
// credential is custodied centrally at all: the host rotates it once and every module
// picks up the new value without ever having held either one.
func TestSecretRevocationStopsUse(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.api.key", "", "", krSecretValue)

	m := &krModule{}
	krLoad(t, k, m, krManifest("krrotate", []string{"provider."}, kernel.OpSecretUse))

	before, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("body"))
	require.NoError(t, err)
	assert.Equal(t, krHMAC(krSecretValue, "body"), before.MAC)

	require.NoError(t, k.RevokeSecret("provider.api.key"))
	assert.Zero(t, kernel.SecretCount())

	_, err = m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("body"))
	require.Error(t, err, "a revoked alias must stop working immediately")

	// Revoking something that is not there is an error, because an operator rotating
	// credentials needs to know the alias they meant to remove was absent.
	require.Error(t, k.RevokeSecret("provider.api.key"))

	// A sealed handle issued before revocation still resolves: revoking the stored
	// credential must not silently invalidate an in-flight request. Each handle wipes
	// its own copy when it is closed or reclaimed.
	krInstall(t, k, "provider.api.key", "", "", krSecretValue)
	sealed, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionHeader, []byte("api.example.com"))
	require.NoError(t, err)
	require.NoError(t, k.RevokeSecret("provider.api.key"))
	assert.Equal(t, 1, kernel.FDCount(m.ctx.PID()))
	require.NoError(t, m.ctx.SyscallClose(sealed.FD))
	assert.Zero(t, kernel.FDCount(m.ctx.PID()))

	// Re-registering under the same alias replaces the value rather than adding a
	// second one, and the new value is what the module now sees.
	const rotated = "sk-rotated-credential"
	krInstall(t, k, "provider.api.key", "", "", rotated)
	after, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("body"))
	require.NoError(t, err)
	assert.Equal(t, krHMAC(rotated, "body"), after.MAC)
	assert.NotEqual(t, before.MAC, after.MAC)
	assert.Equal(t, 1, kernel.SecretCount())
}

// TestSecretValueNeverReachesAnOutput is the negative test the whole subsystem is
// for. Every channel a module or an operator can read - the result struct, the alias
// list, the inventory, the audit chain, the console - is swept for the credential.
func TestSecretValueNeverReachesAnOutput(t *testing.T) {
	buf := krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.api.key", "Authorization", "Bearer ", krSecretValue)

	m := &krModule{}
	krLoad(t, k, m, krManifest("krleak", []string{"provider."}, kernel.OpSecretUse))

	_, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("body"))
	require.NoError(t, err)
	_, err = m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionMatch, []byte(krSecretValue))
	require.NoError(t, err)
	sealed, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionHeader, []byte("h"))
	require.NoError(t, err)
	aliases, err := m.ctx.SyscallSecretAliases()
	require.NoError(t, err)

	// Everything a module received.
	for _, surface := range []string{
		fmt.Sprint(aliases),
		fmt.Sprint(sealed),
		buf.String(),
	} {
		assert.NotContains(t, surface, krSecretValue)
		assert.NotContains(t, surface, "Bearer "+krSecretValue)
	}

	// Everything an operator can read.
	for _, info := range kernel.SecretInventory() {
		assert.Equal(t, "provider.api.key", info.Alias)
		assert.Equal(t, "Authorization", info.Header)
		assert.Equal(t, "Bearer ", info.Scheme)
		assert.Positive(t, info.Uses)
	}
	assert.NotContains(t, fmt.Sprint(kernel.SecretInventory()), krSecretValue)

	// The audit chain, field by field, including the length of the value, which for
	// a low-entropy credential would narrow a brute-force search.
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditSecret}) {
		for key, value := range e.Fields {
			s := fmt.Sprint(value)
			assert.NotContains(t, s, krSecretValue, "audit field %q carries the credential", key)
			assert.NotEqual(t, "30", s, "audit field %q carries the credential length", key)
		}
	}

	// The kernel dump is the last place a value could hide, and it is the one an
	// operator is most likely to paste into a bug report.
	var dump strings.Builder
	require.NoError(t, kernel.Dump(&dump))
	assert.NotContains(t, dump.String(), krSecretValue)
}

// TestSecretUseConcurrency hammers the keyring from several goroutines under -race.
// The store, the prefix cache and the sealed-handle path all share state.
func TestSecretUseConcurrency(t *testing.T) {
	krQuiet(t)
	k := krBoot(t)
	krInstall(t, k, "provider.a", "", "", krSecretValue)
	krInstall(t, k, "provider.b", "", "", "other-credential")

	m := &krModule{}
	krLoad(t, k, m, krManifest("krconc", []string{"provider."}, kernel.OpSecretUse))
	ctx := m.ctx

	const workers, each = 8, 25
	var wg sync.WaitGroup
	macs := make([][]string, workers)
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			out := make([]string, 0, each)
			for i := range each {
				alias := "provider.a"
				want := krHMAC(krSecretValue, fmt.Sprintf("%d-%d", w, i))
				if i%2 == 1 {
					alias = "provider.b"
					want = krHMAC("other-credential", fmt.Sprintf("%d-%d", w, i))
				}
				res, err := ctx.SyscallSecretUse(alias, kernel.SecretActionSign,
					[]byte(fmt.Sprintf("%d-%d", w, i)))
				if err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
				assert.Equal(t, want, res.MAC, "worker %d got a MAC under the wrong key", w)
				out = append(out, hex.EncodeToString(res.MAC))

				// Sealing and immediately closing exercises the handle path under
				// contention, which is where a shared buffer would show up.
				sealed, err := ctx.SyscallSecretUse(alias, kernel.SecretActionHeader, []byte("h"))
				if err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
				if err := ctx.SyscallClose(sealed.FD); err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
			}
			macs[w] = out
		}(w)
	}
	wg.Wait()

	// Every MAC is distinct because every message was distinct, which also proves no
	// two workers were handed the same buffer.
	seen := map[string]bool{}
	for _, group := range macs {
		for _, mac := range group {
			assert.False(t, seen[mac], "two workers produced the same MAC: %s", mac)
			seen[mac] = true
		}
	}
	assert.Len(t, seen, workers*each)
	assert.Zero(t, kernel.FDCount(m.ctx.PID()), "every sealed handle must have been closed")
}

// TestSecretResetBetweenBoots is the reset path. A credential must not survive the
// operator's decision to restart: a restarted kernel begins holding nothing, and the
// host must install this boot's own.
func TestSecretResetBetweenBoots(t *testing.T) {
	krQuiet(t)
	k1 := krBoot(t)
	krInstall(t, k1, "provider.api.key", "", "", krSecretValue)
	require.Equal(t, 1, kernel.SecretCount())
	uses, _ := kernel.SecretUseStats()
	assert.Zero(t, uses)

	require.NoError(t, k1.Shutdown())

	assert.Zero(t, kernel.SecretCount(), "credentials must not survive a shutdown")
	assert.Empty(t, kernel.SecretInventory())
	uses, refused := kernel.SecretUseStats()
	assert.Zero(t, uses)
	assert.Zero(t, refused)

	k2 := krBoot(t)
	m := &krModule{}
	krLoad(t, k2, m, krManifest("krafterreset", []string{"provider."}, kernel.OpSecretUse))
	aliases, err := m.ctx.SyscallSecretAliases()
	require.NoError(t, err)
	assert.Empty(t, aliases, "the previous boot's keyring must not carry over")
	_, err = m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("x"))
	require.Error(t, err)

	// And this boot's own install works, so the reset is not a permanent refusal.
	krInstall(t, k2, "provider.api.key", "", "", krSecretValue)
	res, err := m.ctx.SyscallSecretUse("provider.api.key", kernel.SecretActionSign, []byte("x"))
	require.NoError(t, err)
	assert.Equal(t, krHMAC(krSecretValue, "x"), res.MAC)
}

// TestSecretHostPathsRefuseAfterShutdown covers the host-side surface, which is the
// only path that can install a credential. A handle from a stopped kernel does
// nothing, so a shutdown cannot be followed by a late credential install.
func TestSecretHostPathsRefuseAfterShutdown(t *testing.T) {
	krQuiet(t)
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "kr-node"},
	})
	require.NoError(t, err)
	require.NoError(t, k.Shutdown())

	err = k.InstallSecret(kernel.SecretSpec{Alias: "late.key", Value: []byte(krSecretValue)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shut down")
	require.Error(t, k.RevokeSecret("late.key"))
	assert.Zero(t, kernel.SecretCount())
}

// TestSecretRegisterAndReadAreContextGated covers the two secret:read entry points.
// Both are refused to init, which is the policy table's refusal and not this
// subsystem's, and both are exercised here so a future widening of the init domain
// fails a test rather than silently granting plaintext access.
func TestSecretRegisterAndReadAreContextGated(t *testing.T) {
	buf := krQuiet(t)
	k := krBoot(t)
	init := k.InitContext()

	value := []byte(krSecretValue)
	err := init.SyscallSecretRegister(kernel.SecretSpec{Alias: "init.key", Value: value})
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.Contains(t, err.Error(), "secret:read")
	assert.Equal(t, byte(0), value[0], "a refused register must still wipe the caller's value")

	krInstall(t, k, "provider.api.key", "", "", krSecretValue)
	_, err = init.SyscallSecretRead("provider.api.key")
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	err = init.SyscallSecretRevoke("provider.api.key")
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.Equal(t, 1, kernel.SecretCount(), "a denied revoke must not remove anything")

	// A module asking for secret:read cannot even load: the operation is scoped, so
	// validation passes it to per-call enforcement, and the call is then denied.
	m := &krModule{}
	krLoad(t, k, m, krManifest("krreader", []string{"provider."}, kernel.OpSecretUse, kernel.OpSecretRead))
	_, err = m.ctx.SyscallSecretRead("provider.api.key")
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "a module must never read a plaintext credential: %v", err)

	assert.Contains(t, buf.String(), "avc: denied { secret:read }")
}
