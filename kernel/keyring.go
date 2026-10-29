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

package kernel

// kkeyring: secret custody (subsystem: kkeyring, the analogue of the Linux kernel
// keyring plus the credential helper a service manager provides).
//
// SYSCALL WIRING FOR THE INTEGRATOR.
//
// The exported functions below are the implementation; paste this block into
// kernel/context.go to expose them as syscalls.
//
// 1. Add the group to the SContext interface's group list, next to SyscallCrypto:
//
//	SyscallKeyring
//
// 2. Add the group interface and the methods:
//
//	// SyscallKeyring is the secret-custody half of the syscall surface. No method
//	// here hands a plaintext credential to a module.
//	type SyscallKeyring interface {
//	    // SyscallSecretAliases lists the aliases visible to this context.
//	    // Requires secret:use, and the result is narrowed to the secret prefixes
//	    // the manifest declared.
//	    SyscallSecretAliases() ([]string, error)
//	    // SyscallSecretUse applies a custodied secret on this context's behalf and
//	    // returns only the result. Requires secret:use, scoped by prefix.
//	    SyscallSecretUse(alias string, action SecretAction, data []byte) (SecretResult, error)
//	    // SyscallSecretRead returns a plaintext credential. Requires secret:read.
//	    SyscallSecretRead(alias string) ([]byte, error)
//	    // SyscallSecretRegister takes custody of a credential. Requires
//	    // secret:read.
//	    SyscallSecretRegister(spec SecretSpec) error
//	    // SyscallSecretRevoke destroys a custodied credential. Requires
//	    // secret:read.
//	    SyscallSecretRevoke(alias string) error
//	}
//
//	func (c *sContext) SyscallSecretAliases() ([]string, error) { return SecretAliases(c) }
//	func (c *sContext) SyscallSecretUse(alias string, action SecretAction, data []byte) (SecretResult, error) {
//	    return SecretUse(c, alias, action, data)
//	}
//	func (c *sContext) SyscallSecretRead(alias string) ([]byte, error) { return SecretRead(c, alias) }
//	func (c *sContext) SyscallSecretRegister(spec SecretSpec) error { return SecretRegister(c, spec) }
//	func (c *sContext) SyscallSecretRevoke(alias string) error { return SecretRevoke(c, alias) }
//
// 3. Add resetKeyring() to resetKernel() in kernel/kernel.go, immediately before
//    kboot.reset(): the stored credentials are wiped on reset, and wiping them
//    after the trust root has been cleared would still be correct but leaves a
//    window in which a restarted kernel and a stale keyring coexist.
//
// 4. kernel/module.go must record a module's declared secret scope at spawn time,
//    immediately after the setGrants call in LoadModule, so that a module needing a
//    credential during OnLoad is authorized under the declaration it was loaded
//    with. A module's own record is only published after OnLoad returns, so without
//    this hook a credential request made during initialization fails closed:
//
//	setSecretScope(child.pid, m.SecretPrefixes)
//
//    and in the abandon closure, next to clearGrants, nothing is needed: the scope
//    is per pid and pids are never reused, and resetKeyring clears the whole cache.
//
// 5. knet, when it exists, resolves a sealed header with the package-private
//    resolveSecretHeader(pid, fd) rather than with any exported function. That
//    helper performs no policy check of its own, because the fd table already
//    scopes the handle to the pid that opened it and the module was authorized when
//    the handle was issued.
//
// POLICY NOTE the integrator and the owner must read before wiring secret:read.
//
// kernel/policy.go grants secret:read to the kernel domain alone. The plugin domain
// holds secret:use, and the init domain holds NEITHER - the comment above the
// DomainInit row says why: init is long-lived, and a long-lived holder of a
// plaintext key is a long-lived exposure of it.
//
// The kernel domain belongs to the pid 0 root context, which boot.go retires the
// instant init exists. So in a running kernel no live context holds secret:read, and
// SecretRegister, SecretRead, SecretAliasesAll and SecretRevoke cannot be reached
// through a context at all. That is a property of the policy table, not a defect
// here, and it is not something this file may change.
//
// Custody is therefore also reachable from the *Kernel handle, which only the host
// process holds and which a module cannot obtain: Kernel.InstallSecret and
// Kernel.RevokeSecret. This mirrors Kernel.Publish, which is likewise host-only. It
// adds no capability the host did not already have - the host supplied the
// credentials in the first place - and it performs no check that a context would
// have performed, so it does not widen the policy.
//
// If the owner wants init to manage credentials at runtime, that is a change to the
// DomainInit row of kernel/policy.go and it needs owner approval. It is reported
// here rather than made.

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// The whole subsystem exists for one sentence: a module never sees a plaintext
// credential. It names an alias and an action, the kernel applies the secret and
// returns the result. That is a stronger statement than "we do not log the secret",
// and it changes what a compromised module can do. A module holding a credential can
// exfiltrate it, replay it against a host the operator never approved, or keep using
// it after rotation. A module holding only the ability to ask the kernel for an HMAC
// over data it supplied can do none of those: it can produce a valid MAC for one
// message, which is what the request it is serving needed.
//
// The three actions are chosen so that each returns a value that cannot be turned
// back into the credential:
//
//   - sign: an HMAC over caller-supplied data. Proves possession to a verifier that
//     shares the secret, without disclosing it.
//   - match: a bool from a constant-time comparison. Lets a module authenticate an
//     inbound token it was handed without ever holding the stored one.
//   - header: an opaque sealed handle. The rendered header value stays inside the
//     kernel and is attached to the request by the kernel's own network layer. This
//     is the action a provider adaptor needs, and it is the reason the network
//     syscall must belong to the kernel rather than to the module: a module that owns
//     its HTTP client owns the header, and the guarantee is gone.
//
// What this cannot enforce, stated plainly: it is mandatory access control over what
// a module may ask the kernel to do. A module that reads the same credential from its
// own environment or its own config file is outside this subsystem entirely. That is
// a review and signing concern, not something a policy table can stop.

// SecretAction names what the kernel should do with a custodied secret. The set is
// closed; an unknown action is refused rather than defaulted, because a default
// branch here would be a way to ask for "whatever returns the value".
type SecretAction string

const (
	// SecretActionSign returns an HMAC-SHA256 over the supplied data, keyed with
	// the secret. data must be non-empty.
	SecretActionSign SecretAction = "sign"
	// SecretActionMatch compares the supplied data against the secret in constant
	// time and returns only the verdict. data must be non-empty.
	SecretActionMatch SecretAction = "match"
	// SecretActionHeader seals the rendered header value into a handle owned by the
	// calling pid. data, when non-empty, is the destination host the value is bound
	// to; the binding is recorded so the network layer can refuse to send a
	// credential to a host it was not requested for.
	SecretActionHeader SecretAction = "header"
)

// SecretActions lists the actions the kernel will perform.
func SecretActions() []SecretAction {
	return []SecretAction{SecretActionSign, SecretActionMatch, SecretActionHeader}
}

// Keyring ceilings. They are package constants rather than BootLimits fields because
// adding a field to the sealed trust root is a change owned by kboot, and a subsystem
// must not widen the struct it reads.
const (
	maxSecretAliasLen = 128
	maxSecretValueLen = 64 << 10
	// maxSecretsTotal bounds the whole keyring, so a bug or an attacker in a
	// privileged context cannot grow kernel memory without limit.
	maxSecretsTotal = 1024
)

// MaxSecrets reports the ceiling on the number of custodied credentials.
func MaxSecrets() int { return maxSecretsTotal }

// MaxSecretValueBytes reports the ceiling on one credential's length.
func MaxSecretValueBytes() int { return maxSecretValueLen }

// SecretError reports a refused keyring operation. It is a distinct type so a caller
// can tell "the kernel will not do this" from "the kernel could not", and so a scope
// refusal is not mistaken for a policy denial or for a missing secret.
type SecretError struct {
	Msg string
	// Err carries the underlying cause, which lets errors.Is find a ceiling
	// sentinel wrapped by a subsystem the caller did not invoke directly.
	Err error
}

func (e *SecretError) Error() string {
	if e.Err == nil {
		return "kernel: secret refused: " + e.Msg
	}
	return "kernel: secret refused: " + e.Msg + ": " + e.Err.Error()
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *SecretError) Unwrap() error { return e.Err }

// ErrSecretLimit is the sentinel for every keyring ceiling. It is wrapped in a
// SecretError, so a caller can ask both questions: was this refused because a limit
// was hit, and which limit.
var ErrSecretLimit = errors.New("kernel: secret limit reached")

func secretErr(format string, a ...any) error {
	return &SecretError{Msg: fmt.Sprintf(format, a...)}
}

func secretLimit(err error, format string, a ...any) error {
	return &SecretError{Msg: fmt.Sprintf(format, a...), Err: err}
}

// defaultSecretHeader is used when a spec names no header.
const defaultSecretHeader = "Authorization"

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

// SecretInfo describes a custodied credential without disclosing it. This is the
// shape an operator's inventory view and the console dump use.
type SecretInfo struct {
	Alias     string `json:"alias"`
	Header    string `json:"header"`
	Scheme    string `json:"scheme,omitempty"`
	Owner     PID    `json:"owner"`
	CreatedAt int64  `json:"created_at"`
	Uses      int64  `json:"uses"`
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

// secretEntry is one custodied credential.
type secretEntry struct {
	alias     string
	header    string
	scheme    string
	value     []byte
	owner     PID
	createdAt int64
	uses      int64
}

// keyringStore owns the credential table, the per-pid prefix cache and the counters.
type keyringStore struct {
	mu      sync.Mutex
	byAlias map[string]*secretEntry
	// prefixes caches each pid's declared secret prefixes. The cache is sound
	// because a manifest is fixed at load, so a live pid's prefixes cannot change,
	// and pids are never reused within a boot; resetKeyring drops it with the rest.
	prefixes map[PID][]string
	// uses and refused are counters, so a module sweeping aliases it cannot see is
	// visible in aggregate even though each individual refusal is cheap and quiet.
	uses    int64
	refused int64
}

var kkeyring = &keyringStore{
	byAlias:  map[string]*secretEntry{},
	prefixes: map[PID][]string{},
}

// wipe zeroes a byte slice. Every working copy of a credential goes through it, so a
// value that has been applied does not sit in the heap waiting for a core dump or a
// memory-disclosure bug to find it.
//
// The honest limit: Go's garbage collector may already have moved or copied the
// backing array, and the compiler may keep a byte in a register. Wiping makes the
// common case - a long-lived heap buffer outliving the request - safe, and that is
// worth doing. It is not a guarantee that no copy ever existed, and no in-process
// design can give one.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// validAlias rejects the forms that would make prefix scoping or the audit record
// ambiguous. Control and non-ASCII characters are refused because an alias is written
// into audit lines and console output verbatim, and an alias carrying a newline can
// forge a log line.
func validAlias(alias string) error {
	if alias == "" {
		return secretErr("empty secret alias")
	}
	if len(alias) > maxSecretAliasLen {
		return secretErr("alias longer than %d bytes", maxSecretAliasLen)
	}
	for _, r := range alias {
		if r <= 0x20 || r >= 0x7f {
			return secretErr("alias %q contains a control or non-ASCII character", alias)
		}
	}
	return nil
}

// installSecret is the shared custody path. It validates, copies the value, wipes the
// caller's slice, and records the entry. The caller has already established the
// authority to install.
func installSecret(ctx *sContext, spec SecretSpec, owner PID) error {
	if err := validAlias(spec.Alias); err != nil {
		wipe(spec.Value)
		return err
	}
	if len(spec.Value) == 0 {
		return secretErr("alias %q has an empty value", spec.Alias)
	}
	if len(spec.Value) > maxSecretValueLen {
		// Wipe before refusing. A rejected value is still a credential in memory,
		// and the caller has already given up ownership by making the call.
		wipe(spec.Value)
		return secretLimit(ErrSecretLimit, "alias %q value of %d bytes exceeds the ceiling %d",
			spec.Alias, len(spec.Value), maxSecretValueLen)
	}
	if err := validHeaderName(spec.Header); err != nil {
		wipe(spec.Value)
		return err
	}

	stored := make([]byte, len(spec.Value))
	copy(stored, spec.Value)
	// Ownership transferred: the caller's copy is wiped so the credential exists in
	// exactly one place, the keyring's own buffer.
	wipe(spec.Value)

	header := spec.Header
	if header == "" {
		header = defaultSecretHeader
	}

	kkeyring.mu.Lock()
	if _, exists := kkeyring.byAlias[spec.Alias]; !exists && len(kkeyring.byAlias) >= maxSecretsTotal {
		kkeyring.mu.Unlock()
		wipe(stored)
		return secretLimit(ErrSecretLimit, "the keyring holds the maximum of %d credentials", maxSecretsTotal)
	}
	// Replacing an alias wipes the old value rather than leaving it to the
	// collector. Rotation is the common case, and an unrotated copy sitting in the
	// heap is exactly what rotation was supposed to remove.
	if old, exists := kkeyring.byAlias[spec.Alias]; exists {
		wipe(old.value)
	}
	kkeyring.byAlias[spec.Alias] = &secretEntry{
		alias:     spec.Alias,
		header:    header,
		scheme:    spec.Scheme,
		value:     stored,
		owner:     owner,
		createdAt: mono(),
	}
	kkeyring.mu.Unlock()

	kaudit.record(AuditSecret, ctx, "secret registered", map[string]any{
		// The alias, the header name and the owner are recorded. The value never is,
		// and neither is its length: for a low-entropy credential the length narrows
		// a brute-force search, and the audit trail is readable by anything holding
		// audit:read.
		"alias":  spec.Alias,
		"header": header,
		"owner":  owner,
	})
	return nil
}

// validHeaderName rejects a header name that could not be put on the wire, so the
// error surfaces at registration rather than at the moment a request is being
// written.
func validHeaderName(header string) error {
	if len(header) > maxSecretAliasLen {
		return secretErr("header name longer than %d bytes", maxSecretAliasLen)
	}
	for _, r := range header {
		if r <= 0x20 || r >= 0x7f {
			return secretErr("header name %q contains a control or non-ASCII character", header)
		}
	}
	return nil
}

// InstallSecret takes custody of a credential from the host process. It is a method
// on Kernel rather than a free function so that only a holder of the boot handle can
// call it: a module never receives one, and Boot refuses a second call, so module
// code cannot obtain one of its own.
//
// Ownership of spec.Value transfers. On return the caller's slice is zeroed, whether
// the call succeeded or was refused. Copy it first if the host still needs it.
//
// There is no policy check here because there is no context to check. See the policy
// note at the top of this file.
func (k *Kernel) InstallSecret(spec SecretSpec) error {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return errors.New("kernel: already shut down")
	}
	return installSecret(k.initCtx, spec, k.initCtx.pid)
}

// RevokeSecret destroys a custodied credential from the host process, wiping the
// stored value. Revoking an unknown alias is an error rather than a no-op: an
// operator rotating credentials needs to know the alias they meant to remove was not
// there.
func (k *Kernel) RevokeSecret(alias string) error {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return errors.New("kernel: already shut down")
	}
	return revokeSecret(k.initCtx, alias)
}

// SecretRegister takes custody of a credential on a context's behalf. Requires
// secret:read, which no live context holds in the current policy table.
func SecretRegister(ctx SContext, spec SecretSpec) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpSecretRead); err != nil {
		// Wipe even on refusal: the caller handed over ownership, and a refused call
		// must not leave the credential in the caller's buffer with nobody
		// responsible for it.
		wipe(spec.Value)
		return err
	}
	return installSecret(c, spec, c.pid)
}

// SecretRead returns a plaintext credential. Requires secret:read.
//
// This exists because the kernel needs credentials in the clear in exactly one place
// - the network layer attaching a header to an outbound request - and because a
// custody subsystem with no read path cannot be tested or debugged. It is the reason
// secret:read is absent from the plugin domain: with it, "a module never sees a
// plaintext credential" would be false.
//
// The returned slice is a copy owned by the caller, who must wipe it. The stored
// value is untouched.
func SecretRead(ctx SContext, alias string) ([]byte, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if err := c.syscall(OpSecretRead); err != nil {
		return nil, err
	}

	kkeyring.mu.Lock()
	e := kkeyring.byAlias[alias]
	var out []byte
	if e != nil {
		out = make([]byte, len(e.value))
		copy(out, e.value)
		e.uses++
	}
	kkeyring.mu.Unlock()

	if e == nil {
		refuseSecret(c, alias, "read", "unknown alias")
		return nil, secretErr("alias %q is not custodied", alias)
	}
	kaudit.record(AuditSecret, c, "secret read", map[string]any{"alias": alias, "action": "read"})
	return out, nil
}

// SecretRevoke destroys a custodied credential. Requires secret:read.
func SecretRevoke(ctx SContext, alias string) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpSecretRead); err != nil {
		return err
	}
	return revokeSecret(c, alias)
}

// revokeSecret wipes and removes one alias.
//
// Sealed header handles already issued for it are deliberately left alone: revoking
// the stored credential must not silently invalidate an in-flight request, and each
// handle zeroes its own copy when it is closed or reclaimed. A host needing an
// immediate cutoff revokes the alias and then unloads the module holding the handles,
// which reclaims them.
func revokeSecret(ctx *sContext, alias string) error {
	kkeyring.mu.Lock()
	e := kkeyring.byAlias[alias]
	if e != nil {
		wipe(e.value)
		e.value = nil
		delete(kkeyring.byAlias, alias)
	}
	kkeyring.mu.Unlock()

	if e == nil {
		return secretErr("alias %q is not custodied", alias)
	}
	kaudit.record(AuditSecret, ctx, "secret revoked", map[string]any{"alias": alias})
	return nil
}

// SecretAliases lists the aliases visible to a context. Requires secret:use.
//
// The list is narrowed to the manifest's declared prefixes, so a module cannot
// enumerate credentials it was never going to be allowed to use. Alias names are not
// secrets, but the set of them reveals what a deployment talks to, and a module that
// can enumerate can also target.
func SecretAliases(ctx SContext) ([]string, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if err := c.syscall(OpSecretUse); err != nil {
		return nil, err
	}
	// A module whose scope is not yet known sees nothing rather than everything:
	// the enumeration path fails closed for the same reason the use path does.
	scope := secretPrefixesFor(c)
	if scope.state == scopeUnknown {
		return nil, nil
	}
	return visibleAliases(scope), nil
}

// errSecretNotVisible is the one message a module gets for an alias outside its
// scope and for an alias that does not exist. Sharing the error is the control.
var errSecretNotVisible = &SecretError{Msg: "alias is not visible to this module"}

// visibleAliases returns the sorted aliases inside one scope. An empty prefix list
// matches nothing, which is deny-by-default rather than an empty answer that happens
// to look like one.
func visibleAliases(scope secretScope) []string {
	kkeyring.mu.Lock()
	defer kkeyring.mu.Unlock()
	out := make([]string, 0, len(kkeyring.byAlias))
	for alias := range kkeyring.byAlias {
		if scope.allows(alias) {
			out = append(out, alias)
		}
	}
	sort.Strings(out)
	return out
}

// aliasInScope reports whether an alias matches a declared prefix. An empty prefix
// list matches nothing, which is the whole of deny-by-default: a module that declared
// no secret prefixes sees no alias and uses none.
//
// An empty prefix string would match everything, so it is skipped rather than
// honored. manifest.go already rejects an empty prefix for secret:read; this defends
// the same hole on the secret:use path, where validation does not currently require
// prefixes at all.
func aliasInScope(alias string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(alias, p) {
			return true
		}
	}
	return false
}

// secretScope is what a context may see in the keyring.
//
//	unscoped  the domain is not manifest-constrained, so every alias is visible
//	scoped    the alias must match one of prefixes
//	unknown   the context is a plugin whose declaration the kernel has not been
//	          told about yet, which is treated as an empty scope
type secretScope struct {
	prefixes []string
	state    int
}

const (
	scopeUnknown = iota
	scopeScoped
	scopeUnscoped
)

// secretPrefixesFor resolves a context's keyring scope.
//
// A non-plugin domain is not manifest-constrained, so it is unscoped; every domain
// that could actually reach the keyring syscalls is denied by the policy ceiling
// anyway, so that branch is about correctness rather than reachability.
//
// A plugin's scope comes from a table the module loader fills at spawn time, with a
// fallback to the live module record. The fallback covers the window between spawn
// and load: a module's own record is only published after OnLoad returns, so without
// either source a module that needs a credential during initialization would be
// refused. Neither source is available only when the loader hook from the wiring note
// has not been added, and then the answer is unknown, which every caller treats as an
// empty scope. That is fail-closed on purpose: a plugin whose declaration the kernel
// cannot see gets nothing, rather than everything.
//
// An unknown scope is never cached. Caching it would freeze a module out of its own
// credentials for the rest of the boot, which is the failure mode the fallback exists
// to avoid.
func secretPrefixesFor(c *sContext) secretScope {
	if c.dom != DomainPlugin {
		return secretScope{state: scopeUnscoped}
	}

	kkeyring.mu.Lock()
	declared, ok := kkeyring.prefixes[c.pid]
	kkeyring.mu.Unlock()
	if ok {
		return secretScope{prefixes: declared, state: scopeScoped}
	}

	for _, m := range LoadedModules() {
		if m.PID == c.pid {
			// A live module's declaration is immutable and pids are never reused
			// within a boot, so this is safe to cache.
			prefixes := append([]string(nil), m.Manifest.SecretPrefixes...)
			kkeyring.mu.Lock()
			if existing, cached := kkeyring.prefixes[c.pid]; cached {
				prefixes = existing
			} else {
				kkeyring.prefixes[c.pid] = prefixes
			}
			kkeyring.mu.Unlock()
			return secretScope{prefixes: prefixes, state: scopeScoped}
		}
	}
	return secretScope{state: scopeUnknown}
}

// allows reports whether one alias is inside this scope.
func (s secretScope) allows(alias string) bool {
	switch s.state {
	case scopeUnscoped:
		return true
	case scopeScoped:
		return aliasInScope(alias, s.prefixes)
	}
	return false
}

// setSecretScope records the secret prefixes a pid declared. The module loader calls
// it next to setGrants, before any module code runs, so that a module needing a
// credential during OnLoad is authorized under the declaration it was loaded with.
// See the wiring note at the top of this file.
func setSecretScope(pid PID, prefixes []string) {
	kkeyring.mu.Lock()
	defer kkeyring.mu.Unlock()
	kkeyring.prefixes[pid] = append([]string(nil), prefixes...)
}

// refuseSecret records a lookup or scope failure. It is a fault and an audit entry,
// both carrying the alias and the action and nothing else, because a credential use
// that was refused is exactly the event an investigation looks for.
func refuseSecret(ctx *sContext, alias, action, reason string) {
	kkeyring.mu.Lock()
	kkeyring.refused++
	kkeyring.mu.Unlock()
	fault(ctx, "secret use refused", map[string]any{
		"alias": alias, "action": action, "reason": reason,
	})
	kaudit.record(AuditSecret, ctx, "secret use refused", map[string]any{
		"alias": alias, "action": action, "reason": reason,
	})
}

// refuseSecretScope is the scope-violation path. It records an escalation as well as
// a refusal, because a module asking for a credential outside its declaration is
// attempting to widen what it was granted, which is a different fact from mistyping
// an alias.
func refuseSecretScope(ctx *sContext, alias, action string) {
	refuseSecret(ctx, alias, action, "alias is outside the declared secret prefixes")
	kaudit.record(AuditEscalation, ctx, "secret alias outside declared scope", map[string]any{
		"alias": alias, "action": action,
	})
}

// SecretUse applies a custodied secret on a module's behalf and returns only the
// result. Requires secret:use, and the alias must fall inside the prefixes the
// module's manifest declared.
//
// An alias that exists but is out of scope and an alias that does not exist return
// the same error. Distinguishing them would turn this call into an oracle for which
// credentials a deployment holds, and that inventory is worth more to an attacker
// than any single low-value secret.
func SecretUse(ctx SContext, alias string, action SecretAction, data []byte) (SecretResult, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return SecretResult{}, errForeignContext
	}
	if err := c.syscall(OpSecretUse); err != nil {
		return SecretResult{}, err
	}

	switch action {
	case SecretActionSign, SecretActionMatch, SecretActionHeader:
	default:
		return SecretResult{}, secretErr("unknown secret action %q", action)
	}
	if action != SecretActionHeader && len(data) == 0 {
		return SecretResult{}, secretErr("action %q requires data", action)
	}
	if len(data) > maxCryptoInputBytes {
		return SecretResult{}, secretLimit(ErrSecretLimit, "data of %d bytes exceeds the ceiling %d",
			len(data), maxCryptoInputBytes)
	}

	// Both the scope refusal and the unknown-alias refusal carry the same message.
	// Distinguishing them would make this call an oracle for which credentials the
	// deployment holds, and that inventory is worth more to an attacker than any
	// single low-value secret.
	if !secretPrefixesFor(c).allows(alias) {
		refuseSecretScope(c, alias, string(action))
		return SecretResult{}, errSecretNotVisible
	}
	// The instance filter runs after the scope check, and a refusal here is folded into
	// the SAME message rather than returned as ErrSeccompRefused.
	//
	// That folding is not cosmetic. Everywhere else in this kernel a filter refusal can
	// be distinguished from a scope refusal without leaking anything new, because the
	// manifest is the module author's own document: comparing what they declared against
	// what they observe tells them the filter's effect, and no runtime narrowing can hide
	// its own effect. Secret aliases are different. The alias inventory belongs to the
	// deployment, not to the manifest, so a distinct refusal here would answer a question
	// the module could not otherwise answer - "does this alias exist and is it filtered?"
	// - which is exactly the oracle the shared message above exists to close.
	if err := SeccompAllow(c, OpSecretUse, alias); err != nil {
		refuseSecretScope(c, alias, string(action))
		return SecretResult{}, errSecretNotVisible
	}

	kkeyring.mu.Lock()
	e := kkeyring.byAlias[alias]
	if e != nil {
		e.uses++
		kkeyring.uses++
	}
	kkeyring.mu.Unlock()

	if e == nil {
		refuseSecretScope(c, alias, string(action))
		return SecretResult{}, errSecretNotVisible
	}

	res, err := applySecret(c, e, action, data)
	if err != nil {
		return SecretResult{}, err
	}
	kaudit.record(AuditSecret, c, "secret used", map[string]any{
		"alias": alias, "action": string(action), "outcome": "ok",
	})
	return res, nil
}

// applySecret performs one action against one entry. It reads the stored value under
// the keyring lock into a working copy and wipes that copy before returning, so the
// credential is not left in a local buffer after the request completes.
func applySecret(ctx *sContext, e *secretEntry, action SecretAction, data []byte) (SecretResult, error) {
	kkeyring.mu.Lock()
	if e.value == nil {
		kkeyring.mu.Unlock()
		return SecretResult{}, secretErr("alias %q was revoked", e.alias)
	}
	working := make([]byte, len(e.value))
	copy(working, e.value)
	header, scheme := e.header, e.scheme
	kkeyring.mu.Unlock()

	switch action {
	case SecretActionSign:
		mac := hmacSHA256(working, data)
		wipe(working)
		return SecretResult{Alias: e.alias, Action: action, MAC: mac}, nil

	case SecretActionMatch:
		// Constant-time, so the verdict does not leak how much of a supplied
		// candidate matched. An early-returning comparison is a brute-force
		// accelerator for anyone who can call this in a loop.
		match := constantTimeEqualBytes(working, data)
		wipe(working)
		return SecretResult{Alias: e.alias, Action: action, Match: match}, nil

	case SecretActionHeader:
		value := make([]byte, 0, len(scheme)+len(working))
		value = append(value, scheme...)
		value = append(value, working...)
		wipe(working)

		sealed := &sealedSecret{alias: e.alias, header: header, value: value, host: string(data)}
		fd, err := install(ctx.pid, sealed, "secret:"+e.alias)
		if err != nil {
			// The rendered value already exists, so it is wiped before the error is
			// returned. Hitting a ceiling must not leave a credential in the heap.
			wipe(value)
			sealed.value = nil
			return SecretResult{}, secretLimit(ErrSecretLimit,
				"cannot seal a header for alias %q: %v", e.alias, err)
		}
		return SecretResult{Alias: e.alias, Action: action, FD: fd, Header: header}, nil
	}
	wipe(working)
	return SecretResult{}, secretErr("unknown secret action %q", action)
}

// hmacSHA256 is the keyed digest the keyring applies on a module's behalf. It lives
// here, next to the only key it is ever called with, rather than in crypto.go, so
// that there is exactly one place in the kernel where a MAC over a custodied secret is
// constructed.
func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// sealedSecret is a rendered header value the kernel holds on a module's behalf. It
// is a resource in the fd table, which is what makes it reclaimable: a module that is
// unloaded, that panics, or that simply forgets the handle leaks nothing, because the
// kernel walks the table and wipes every value in it.
type sealedSecret struct {
	closedFlag
	alias  string
	header string
	host   string
	value  []byte
}

// Kind names the resource for the fd table and the console dump.
func (s *sealedSecret) Kind() string { return "secret" }

// Close wipes the rendered value. Once-only, via the embedded closedFlag, so a module
// closing a handle twice gets errClosed rather than a second wipe of a buffer the
// allocator may already have handed to someone else.
func (s *sealedSecret) Close() error {
	if !s.mark() {
		return errClosed
	}
	if s.value != nil {
		wipe(s.value)
		s.value = nil
	}
	return nil
}

// resolveSecretHeader opens a sealed header handle inside one pid. It is
// package-private and takes a pid rather than a context, because its only caller is
// the kernel's own network layer acting for that pid: authorization already happened
// when the handle was issued, and the fd table enforces the isolation.
//
// The returned slice is the kernel's own buffer. The caller must copy it into the
// request and must not retain it, because the handle's Close wipes it in place.
func resolveSecretHeader(pid PID, fd FD) (header string, value []byte, host string, err error) {
	entry, err := lookup(pid, fd)
	if err != nil {
		return "", nil, "", err
	}
	sealed, ok := entry.res.(*sealedSecret)
	if !ok {
		return "", nil, "", fmt.Errorf("kernel: fd %d is a %s, not a sealed secret", fd, entry.kind)
	}
	if sealed.done() {
		return "", nil, "", errClosed
	}
	return sealed.header, sealed.value, sealed.host, nil
}

// SecretInventory returns the custodial table without values, for the console dump and
// for an operator answering "which credentials are loaded, and how often has each
// been used".
func SecretInventory() []SecretInfo {
	kkeyring.mu.Lock()
	defer kkeyring.mu.Unlock()
	out := make([]SecretInfo, 0, len(kkeyring.byAlias))
	for _, e := range kkeyring.byAlias {
		out = append(out, SecretInfo{
			Alias: e.alias, Header: e.header, Scheme: e.scheme,
			Owner: e.owner, CreatedAt: e.createdAt, Uses: e.uses,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// SecretCount reports how many credentials are custodied.
func SecretCount() int {
	kkeyring.mu.Lock()
	defer kkeyring.mu.Unlock()
	return len(kkeyring.byAlias)
}

// SecretUseStats reports the number of successful uses and refusals. A module
// sweeping aliases it cannot see shows up here as refusals climbing while uses stay
// flat, which is the signal an operator needs and which no single refusal carries on
// its own.
func SecretUseStats() (uses int64, refused int64) {
	kkeyring.mu.Lock()
	defer kkeyring.mu.Unlock()
	return kkeyring.uses, kkeyring.refused
}

// resetKeyring wipes every stored credential and clears the table. Called only from
// resetKernel, so a restarted kernel begins holding no credentials and the host
// process must install this boot's own. Inheriting the previous boot's keyring would
// mean a credential surviving the operator's decision to restart, which is the
// opposite of what a restart is usually for.
func resetKeyring() {
	kkeyring.mu.Lock()
	defer kkeyring.mu.Unlock()
	for _, e := range kkeyring.byAlias {
		wipe(e.value)
		e.value = nil
	}
	kkeyring.byAlias = map[string]*secretEntry{}
	kkeyring.prefixes = map[PID][]string{}
	kkeyring.uses = 0
	kkeyring.refused = 0
}
