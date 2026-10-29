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

// kverifier: manifest signature appraisal and declaration audit (subsystem:
// kverifier, the analogue of IMA appraisal plus the signature check a
// classloader performs before it hands code to a VM).
//
// WIRING FOR THE INTEGRATOR.
//
// 1. resetVerifier() goes in resetKernel() in kernel/kernel.go, in the
//    secrets block immediately before kboot.reset(), beside resetKeyring()
//    and resetReceipts(). The appraisal posture and its ledger are read
//    against the sealed trust root, so they are dropped while that root is
//    still the current one, and a restarted kernel re-derives both from its
//    own configuration instead of inheriting the previous boot's posture:
//
//	resetVerifier()
//	resetKeyring()
//	resetReceipts()
//	kboot.reset()
//
//    Until that line is added the subsystem resets itself: see
//    verifierSyncBoot, which detects a boot boundary from the audit chain's
//    own boot record. Wiring the reset makes that check a no-op rather than
//    changing any behavior, so the two paths do not have to land together.
//
// 2. There is no Syscall group for this subsystem, so there is no line for
//    kernel/context.go and no addition to the SContext composition.
//    Verification is a load-path and host concern. policy.go has no operation
//    for it and none may be added without owner approval, so nothing here is
//    reachable from a context: no method on *sContext, no group interface.
//
// 3. The load-path hook goes in kernel/module.go's LoadModule, immediately
//    after the m.Validate() branch closes and before the registry lookup, so
//    a module whose declared scope fails appraisal never reaches a factory,
//    a context in the plugin domain, or OnLoad:
//
//	if err := VerifyManifestLoad(c, m, sig); err != nil {
//	    var rejectedPID PID
//	    if rejected, spawnErr := kscm.spawn(c, DomainUntrusted, m.Name); spawnErr == nil {
//	        kscm.setArtifact(rejected.pid, m.Name, m.Digest(), ProcRejected)
//	        rejectedPID = rejected.pid
//	    }
//	    kaudit.record(AuditReject, c, "module manifest failed verification", map[string]any{
//	        "module": m.Name, "version": m.Version, "digest": m.Digest(),
//	        "reason": err.Error(), "rejected_pid": rejectedPID,
//	    })
//	    return 0, err
//	}
//
//    sig is the VerifierSignature the deployment carries beside the manifest.
//    LoadModule has no parameter for one today, so the integrator either
//    widens LoadModule to take it, or adds a parallel
//    LoadModuleSigned(ctx, m, sig) and has LoadModule delegate with nil. The
//    fault is already emitted inside VerifyManifestLoad with the loader's
//    context attached, so the hook adds only the untrusted process-table
//    record and the reject entry, mirroring the manifest-rejection branch
//    directly above it.
//
//    INTEGRATION HAZARD, stated because it will otherwise read as a mystery
//    failure: the posture is derived from the trust root when the host has
//    not set one explicitly, and a trust root carrying cluster root keys
//    derives enforce. tests/harness.BootTrust() carries two placeholder keys
//    ("root-key-a", "root-key-b"), so wiring this hook makes every existing
//    suite that loads an unsigned module over that root fail at load. The
//    integrator must either set VerifierPolicy(VerifierOff) in those suites
//    or sign their manifests; the placeholder keys are not verifiable keys,
//    so appraisal against them can only ever refuse.
//
// THE TRANSLATION, AND WHAT IT DOES NOT CLAIM.
//
// The owner's JVM spec has two halves: verify the plugin artifact's
// public/private-key signature at module-load time, and scan bytecode at
// class-load time to intercept high-risk calls statically (System.exit,
// Runtime.exec, System.loadLibrary, JNI escape). Neither half carries over
// literally, and pretending otherwise would produce theater.
//
// Bytecode scanning has no Go analogue here. Modules are Go packages
// compiled into the same binary as the kernel and registered from a
// package-level init; there is no artifact loaded at runtime, no classloader
// and no bytecode, and `go plugin` (.so) is explicitly not used - see
// AGENT.md, "Plugin execution model". A source-level grep for os.Exit is not
// the substitute and is deliberately absent from this file: it cannot see
// reflection, indirection through a dependency, an assembly stub or
// go:linkname, so it would be trivially bypassed while presenting itself as a
// control. A check that is bypassable but believed is worse than no check,
// because it moves the reviewer's attention away from the declaration that
// does bind. Static analysis of module source belongs to CI and to the review
// step that signs the manifest, and the declaration audit below is what feeds
// that review.
//
// The signature half carries over, and it is the real Go equivalent of the
// owner's intent. What exists at load time here is the Manifest: the module's
// declaration of what it needs, whose digest is already recorded in the
// process table. The control this subsystem implements is appraisal - a
// module's declared scope must have been signed by a key the operator trusts,
// and the signature must be bound to that exact identity and digest. Without
// it, a manifest that was reviewed can be silently widened between review and
// deployment: Require, AllowedHosts, SecretPrefixes or ServeRoutes changed
// and nobody re-approved. The kernel would then enforce the widened
// declaration faithfully, because manifest narrowing is only as strong as the
// declaration being the one that was reviewed. That is precisely what IMA/EVM
// appraisal exists to prevent.
//
// A signature is not a capability. Verification decides whether a module may
// load, never what it may do. Grant narrowing, the domain ceiling and
// per-call scope enforcement are untouched by this file: nothing here writes
// to grants, to the policy table, to the process table or to the trust root,
// and a verified module holds exactly the operations its manifest and its
// domain already allowed it to hold unverified.
//
// No secret material crosses this file's boundary. Signing goes through
// crypto.go's signWithNodeKey and verification through
// verifyAgainstClusterRoots; the node private key is never read here, never
// returned, never logged, never wrapped into an error and never written into
// the ledger. Only the public key's short digest appears anywhere.
//
// All ordering and timestamps come from mono(). Nothing here reads a wall
// clock, and the one time-like field inside a signature is evidence in the
// payload rather than an input to any decision.
//
// Signing is deliberately NOT offered here.
//
// There is no VerifierSignManifest, no Kernel method that mints a manifest
// signature, and no syscall that does. The reason is the kcrypto guarantee:
// signing is reachable by no live context after boot. A package-level signing
// function would be a manifest-signing oracle reachable from any in-process
// module, because modules are linked into the same binary and can name any
// exported symbol - and a module that could sign its own manifest could widen
// its own declaration and appraise it, which is the exact attack this subsystem
// exists to stop. receipt.go can offer Kernel.IssueReceipt because that is a
// method on a handle no module ever receives; this file may not edit boot.go, so
// it has no such handle, and the correct answer is to offer nothing rather than
// to offer a package function with a comment claiming modules will not call it.
//
// What the host and the operator's signing pipeline get instead is
// VerifierBindingPayload: the exact bytes a signature must cover. Signing them
// is one ed25519 call with the key the deployment already holds, performed
// offline, in CI, or in whatever tool custody owns the key. That is also where
// the declaration audit belongs - VerifierAuditDeclaration reads the manifest
// the signer is about to vouch for.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// VerifierBindingVersion is the binding-payload version this kernel signs
// and accepts. A signature minted under another version is refused rather
// than reinterpreted: the field layout is part of what the signature covers,
// and a verifier that guessed at an unknown layout would be appraising an
// encoding it did not read.
const VerifierBindingVersion = 1

// VerifierPolicy is the load-time appraisal posture for module manifests.
//
// The set is closed. There is deliberately no auto mode as a selectable
// value: a posture that silently followed the key list at call time would let
// a change to that list move enforcement without anyone deciding to. The
// derivation from the trust root happens only when the host has chosen
// nothing, and VerifierPolicyExplicit reports which case is in force.
type VerifierPolicy string

const (
	// VerifierOff performs no appraisal. Every manifest is admitted, the
	// ledger is not written and nothing is audited, because off means the
	// operator asked for silence and a record of not checking is noise on the
	// chain.
	VerifierOff VerifierPolicy = "off"
	// VerifierAudit admits every manifest and records the outcome of every
	// appraisal on the audit chain and in the ledger, with a fault for each
	// signature that is absent or invalid. It is how an operator gathers the
	// evidence that enforce will not refuse a legitimate module before turning
	// enforce on.
	VerifierAudit VerifierPolicy = "audit"
	// VerifierEnforce refuses a module whose manifest has no valid signature
	// from a trusted cluster root key, before any module code runs.
	VerifierEnforce VerifierPolicy = "enforce"
)

// verifierPolicies is the closed set, in increasing strictness. The order is
// the seal ordering: once a boot has begun appraising, the posture may only
// move right.
var verifierPolicies = []VerifierPolicy{VerifierOff, VerifierAudit, VerifierEnforce}

// verifierStrictness ranks a posture for the tightening-only seal. An unknown
// value ranks below off, which VerifierSetPolicy refuses anyway; the fail-closed
// ranking is there so a future caller cannot treat an unrecognized posture as
// maximally strict and thereby allow any change.
func verifierStrictness(p VerifierPolicy) int {
	for i, known := range verifierPolicies {
		if known == p {
			return i
		}
	}
	return -1
}

// VerifierPolicies lists the postures this kernel implements, in increasing
// strictness, for diagnostics and for an operator console offering a choice.
func VerifierPolicies() []VerifierPolicy {
	return slices.Clone(verifierPolicies)
}

// Refusal sentinels. Each is distinct so an operator's tooling can tell
// "unsigned" from "malformed" from "bad signature" from "key not trusted" from
// "identity mismatch" with errors.Is and errors.As, without string matching.
// The message text is for humans; the sentinel is the contract.
var (
	// ErrVerifierSealed is returned by VerifierSetPolicy when the requested
	// posture is laxer than the one in force and this boot has already begun
	// appraising. See the seal note on VerifierSetPolicy.
	ErrVerifierSealed = errors.New("kernel: verifier policy may only be tightened once appraisal has begun")
	// ErrVerifierUnsigned: the module presented no signature while the posture
	// requires an appraisal.
	ErrVerifierUnsigned = errors.New("kernel: module manifest is unsigned")
	// ErrVerifierMalformed: the signature is not a well-formed
	// ed25519 signature - wrong length, empty, or naming no key. This is a
	// structural refusal, distinct from a well-formed signature that does not
	// verify, because the two have different causes and different fixes: one
	// is a broken pipeline, the other is a broken declaration.
	ErrVerifierMalformed = errors.New("kernel: module manifest signature is malformed")
	// ErrVerifierBadSignature: the signature is well-formed, names a trusted
	// key and matches this manifest's identity, but no sealed cluster root
	// verifies it over the binding payload. For well-formed input that covers a
	// tampered manifest and a signature minted over different bytes, which are
	// the same fact from the kernel's point of view: nothing the operator
	// trusts signed this declaration.
	ErrVerifierBadSignature = errors.New("kernel: module manifest signature does not verify")
	// ErrVerifierKeyUntrusted: the signature names a key id that no sealed
	// cluster root key has. The check is by key id computed from key bytes, so
	// two spellings of one public key are one key and a re-encoded root cannot
	// dodge the inventory.
	ErrVerifierKeyUntrusted = errors.New("kernel: manifest signing key is not a trusted cluster root")
	// ErrVerifierIdentityMismatch: the signature's embedded module identity
	// does not match the manifest being loaded. A signature is bound to one
	// module's name, version and digest; presenting it for anything else is a
	// replay, reported distinctly because a replay and a forgery call for
	// different responses.
	ErrVerifierIdentityMismatch = errors.New("kernel: manifest signature was minted for a different module identity")
	// ErrVerifierDigestMismatch: the signature names this module and version but
	// covers a different digest, which is a declaration that was signed and then
	// edited. It is reported apart from a bad signature because it is the specific
	// case this subsystem exists for: a manifest widened between review and
	// deployment.
	ErrVerifierDigestMismatch = errors.New("kernel: manifest digest is not the one that was signed")
	// ErrVerifierBindingVersion: the signature's binding-payload version is not
	// one this kernel accepts.
	ErrVerifierBindingVersion = errors.New("kernel: manifest signature has an unsupported binding version")
)

// VerifierError is the typed refusal a failed appraisal returns. It follows the
// SecretError and ReceiptError precedent: a distinct type so a caller can tell
// "this module's declaration was not appraised" from "the kernel broke", and a
// wrapped sentinel so errors.Is distinguishes the reasons without string
// matching. errors.As recovers the module name, the digest and the key id, which
// is what an operator's tooling needs to file the refusal against the right
// artifact.
//
// A verification refusal is not a policy denial and IsDenied reports false for
// it, deliberately: a denial means "this domain may not ask for that", which a
// module author fixes by changing what it asks for. This means "nobody the
// operator trusts vouched for this declaration", which only a signature fixes.
type VerifierError struct {
	// Module, Version and Digest name the declaration that was refused.
	Module  string
	Version string
	Digest  string
	// KeyID is the signer's key id as the signature named it, empty when the
	// refusal happened before a key was consulted.
	KeyID string
	// Msg is the human-readable detail.
	Msg string
	// Err carries the sentinel, so errors.Is finds it.
	Err error
}

func (e *VerifierError) Error() string {
	if e.Err == nil {
		return "kernel: manifest verification refused: " + e.Msg
	}
	return "kernel: manifest verification refused: " + e.Msg + ": " + e.Err.Error()
}

// Unwrap exposes the sentinel to errors.Is and errors.As.
func (e *VerifierError) Unwrap() error { return e.Err }

// verifierRefuse builds one typed refusal. It is the only constructor, so every
// refusal this subsystem produces carries the same fields and the same shape.
func verifierRefuse(m Manifest, sig *VerifierSignature, sentinel error, format string, a ...any) error {
	return &VerifierError{
		Module:  m.Name,
		Version: m.Version,
		Digest:  m.Digest(),
		KeyID:   verifierSigKeyID(sig),
		Msg:     fmt.Sprintf(format, a...),
		Err:     sentinel,
	}
}

// VerifierSignature is a detached operator signature over one manifest's
// binding payload. It travels beside the deployment rather than inside the
// manifest: the manifest is module-authored data, the signature is the
// operator's appraisal of it, and storing the appraisal inside the thing
// appraised would let the appraised party carry and re-present it.
type VerifierSignature struct {
	// Version is the binding-payload version and must equal
	// VerifierBindingVersion.
	Version int `json:"version"`
	// Module, ModuleVersion and Digest restate the signed identity, so a
	// mismatch is diagnosable from the refusal alone and a refused load names
	// what the signature was actually minted for. Digest is the sha256 hex of
	// the manifest the signer reviewed, matching Manifest.Digest().
	Module        string `json:"module"`
	ModuleVersion string `json:"module_version"`
	Digest        string `json:"digest"`
	// KeyID identifies the signing key as its short public-key digest, so the
	// trust check and the operator's key inventory use the same name and no key
	// material appears in a record.
	KeyID string `json:"key_id"`
	// SignedMono is the signer's mono() reading at mint time. It is evidence
	// inside the payload and not an authorization input: no freshness, expiry
	// or ordering decision reads it, because a decision that did would let a
	// signer weaken a later appraisal by backdating this one.
	SignedMono int64 `json:"signed_mono"`
	// Bytes is the raw ed25519 signature over the binding payload.
	Bytes []byte `json:"bytes"`
}

// verifierBindingPayload is the canonical encoding the signature covers, and
// the only thing it covers. It binds the module identity and the declaration
// digest together, so a signature minted for module A cannot be replayed onto
// module B and a signature over an older, narrower manifest cannot be reused
// for a widened one: changing either side changes the signed bytes.
//
// The encoding follows receipt.go's discipline. Every field is a
// netstring-style length-prefixed name=value pair, written in a fixed order
// that is part of the format and must not change without bumping
// VerifierBindingVersion. The lengths are what make it unambiguous: with
// bare separators, a module named "a" at version "b|c" would encode identically
// to one named "a|b" at version "c", and a forger could re-split fields across
// a boundary without breaking the signature. Length prefixing removes that
// class of forgery outright. There is also no field a forger can reorder or
// omit, because the order and the presence of all four are fixed here rather
// than derived from a map or from the input.
func verifierBindingPayload(module, moduleVersion, digest string) []byte {
	var b bytes.Buffer
	field := func(name, value string) {
		b.WriteString(strconv.Itoa(len(name)))
		b.WriteByte(':')
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
		b.WriteByte(';')
	}

	field("version", strconv.Itoa(VerifierBindingVersion))
	field("module", module)
	field("module_version", moduleVersion)
	field("manifest_digest", digest)
	return b.Bytes()
}

// VerifierBindingPayload returns the canonical bytes a signature over one
// manifest must cover. It is exported for the same reason receipt.go exports
// ReceiptPayload: a signer in another language, or an operator's signing script,
// can be checked against this kernel's own bytes, which is the only way to find
// an encoding disagreement before it costs a deployment that refuses to load.
//
// It contains no secret and grants nothing. Signing these bytes requires the
// node key, which lives in the sealed trust root.
func VerifierBindingPayload(m Manifest) []byte {
	return verifierBindingPayload(m.Name, m.Version, m.Digest())
}

// VerifierEntry is one appraisal outcome, in the form the ledger hands out.
//
// It is evidence, so it records the manifest digest and the key id that matched
// or was rejected, and it never records signature bytes. The ledger is readable
// by the host and by dump tooling, and a signature is a bearer artifact: a copy
// of one taken from a ledger dump could be presented elsewhere before the copy
// was noticed missing.
type VerifierEntry struct {
	// Seq is the ledger sequence, assigned under the write lock, so it is
	// gap-free for one boot and a missing number is a missing appraisal.
	Seq int64 `json:"seq"`
	// Mono is the appraisal time on the kernel clock.
	Mono int64 `json:"mono"`
	// PID is the loader's pid. Zero marks an appraisal made with no context,
	// which only the direct host-side call shape produces.
	PID PID `json:"pid"`
	// Domain is the loader's domain, so a refusal is attributable.
	Domain Domain `json:"domain,omitempty"`
	// Module, Version and Digest name the appraised declaration.
	Module  string `json:"module"`
	Version string `json:"version_declared"`
	Digest  string `json:"digest"`
	// KeyID is the signer's key id as the signature named it, trusted or not.
	// Recording a rejected key id is the point: it is how an operator finds a
	// rotated-out signing key still in a deployment.
	KeyID string `json:"key_id,omitempty"`
	// Policy is the posture in force for this appraisal.
	Policy VerifierPolicy `json:"policy"`
	// Admitted is whether the module was allowed to proceed.
	Admitted bool `json:"admitted"`
	// Reason is the refusal text, empty on a clean admit. An investigator reads
	// it; the sentinel behind it is the checkable fact.
	Reason string `json:"reason,omitempty"`
}

// maxVerifyLedgerEntries bounds the ledger. Appraisal runs once per load
// attempt, so an audit-policy deployment accumulates one entry per attempt, and
// a caller that can trigger loads in a loop - a reload bug, a supervision retry
// storm - must not be able to grow the kernel's heap without bound. The bound is
// a memory ceiling and not a retention promise; the evicted counter keeps that
// honest.
const maxVerifyLedgerEntries = 4096

// MaxVerifyLedgerEntries reports the ledger ceiling.
func MaxVerifyLedgerEntries() int { return maxVerifyLedgerEntries }

// verifierState is the subsystem singleton: the appraisal posture and the
// ledger behind one lock. The posture is read on the load path and written only
// by the host, so the load path never observes a half-applied change.
type verifierState struct {
	mu sync.RWMutex
	// explicit is the host-set posture, nil when the host has chosen nothing
	// and the posture is therefore derived from the sealed trust root.
	explicit *VerifierPolicy
	// armed latches at the first appraisal of a boot and engages the
	// tightening-only seal. See VerifierSetPolicy.
	armed bool
	// bootID is the boot this state belongs to. See verifierSyncBoot.
	bootID int64

	ledger []VerifierEntry
	// nextSeq and evicted are the ledger's own counters.
	nextSeq int64
	evicted int64
}

var kverifier = &verifierState{}

// verifierBootID identifies the current boot. The boot audit record's mono
// timestamp is written once by Boot before anything else, differs between boots
// because mono() never repeats a reading, and is cleared by kaudit's own reset,
// so it is a per-boot identity that this subsystem can read through the
// kernel's own accessor rather than by reaching into another subsystem's state.
//
// Zero means no boot record is visible, which is either a kernel that is down
// or a chain window small enough to have evicted it. Callers distinguish the
// two with the boot guard rather than assuming the worse one.
func verifierBootID() int64 {
	entries := AuditQuery(AuditFilter{Kind: AuditBoot, Limit: 1})
	if len(entries) == 0 {
		return 0
	}
	return entries[0].Time
}

// verifierSyncBoot drops state that belongs to a previous boot.
//
// resetVerifier() is the real reset and belongs in resetKernel(), but this file
// may not edit kernel.go, and a subsystem whose per-boot state outlives the boot
// is a subsystem whose evidence is wrong: a ledger carrying the previous boot's
// appraisals would let an investigator read a refusal that did not happen under
// the trust root they are looking at. So the boundary is detected here instead,
// and the detection is idempotent - once resetVerifier() is wired, this is a
// no-op on every call because the boot id already matches.
//
// The two rules encode the difference between configuration and evidence. State
// created while no boot record exists belongs to the forthcoming boot and is
// adopted by it, which is what lets a host set the posture before Boot in the
// ordinary way; state created under a different boot is evidence about that boot
// and is dropped. An evicted boot record is not treated as a boundary while the
// boot guard says the kernel is up, so a small audit window cannot wipe a live
// ledger.
func verifierSyncBoot() {
	current := verifierBootID()

	kverifier.mu.Lock()
	defer kverifier.mu.Unlock()

	if current == 0 {
		if kverifier.bootID != 0 && !booted.Load() {
			verifierResetLocked()
		}
		return
	}
	if kverifier.bootID == 0 {
		kverifier.bootID = current
		return
	}
	if kverifier.bootID != current {
		verifierResetLocked()
		kverifier.bootID = current
	}
}

// verifierEffective resolves the posture in force. hasClusterRoots is read by
// the caller before taking the lock, so this subsystem never holds its own lock
// across another subsystem's.
//
// An explicit host choice always wins. Without one the posture is derived from
// the sealed trust root: a deployment that configured cluster root keys almost
// certainly meant to verify against them, so the derived posture is enforce, and
// the gap between configuring those keys and enforcing against them is exactly
// where a reviewed manifest gets widened without anyone re-approving it. A
// deployment with no keys derives off, because there is nothing to verify
// against and refusing every module would be a self-inflicted outage rather than
// a control.
//
// The derivation reads the trust root rather than caching a decision made at
// seal time, so the posture can never disagree with the roots actually in force.
func verifierEffective(hasClusterRoots bool) VerifierPolicy {
	if kverifier.explicit != nil {
		return *kverifier.explicit
	}
	if hasClusterRoots {
		return VerifierEnforce
	}
	return VerifierOff
}

// VerifierPolicyCurrent reports the posture in force, explicit or derived.
func VerifierPolicyCurrent() VerifierPolicy {
	verifierSyncBoot()
	hasRoots := len(ClusterRootKeys()) > 0
	kverifier.mu.RLock()
	defer kverifier.mu.RUnlock()
	return verifierEffective(hasRoots)
}

// VerifierPolicyExplicit reports the host-set posture and whether the host set
// one at all. A false answer means the posture is being derived from the trust
// root, which is the fact an operator needs when enforcement surprises them.
func VerifierPolicyExplicit() (VerifierPolicy, bool) {
	verifierSyncBoot()
	kverifier.mu.RLock()
	defer kverifier.mu.RUnlock()
	if kverifier.explicit == nil {
		return "", false
	}
	return *kverifier.explicit, true
}

// VerifierSetPolicy installs the appraisal posture. It is host-side control,
// exposed as a package function rather than a method on Kernel because this
// subsystem may not edit boot.go where Kernel is defined.
//
// Three properties make it safe, and each is enforced rather than documented:
//
//   - There is no syscall, no policy operation and no context parameter, so no
//     loaded module has a call shape that reaches it. A module can name the
//     function, because modules are in-process Go - equally true of SetQosPolicy
//     and BootSet, and a fact about the execution model rather than about this
//     file. What stops a module changing the posture that governs it is the seal
//     below.
//   - The seal is monotonic tightening. The first appraisal of a boot latches
//     it, and after that only a stricter posture may be installed. Appraisal
//     runs in the load path before the factory is called and before OnLoad, so
//     any module code that exists at all exists after the latch: no module can
//     widen the posture governing its own load or any later one. It can only
//     ever make verification stricter, which costs it nothing it is entitled to.
//   - An unknown posture string is refused rather than defaulted, because a
//     typo silently landing on audit is how enforce gets lost.
//
// Before the latch the host may set anything, and that window is the
// configuration window. A host that wants to relax a posture after modules are
// running restarts, which is the only way to get a fresh window and a fresh
// audit chain to go with it.
func VerifierSetPolicy(p VerifierPolicy) error {
	if verifierStrictness(p) < 0 {
		return fmt.Errorf("kernel: unknown verifier policy %q (want one of off, audit, enforce)", p)
	}
	verifierSyncBoot()
	hasRoots := len(ClusterRootKeys()) > 0

	kverifier.mu.Lock()
	defer kverifier.mu.Unlock()
	if kverifier.armed && verifierStrictness(p) < verifierStrictness(verifierEffective(hasRoots)) {
		return fmt.Errorf("%w: %s is in force and this boot has appraised a manifest",
			ErrVerifierSealed, verifierEffective(hasRoots))
	}
	set := p
	kverifier.explicit = &set
	return nil
}

// verifierRecordLocked appends one entry. Caller holds the write lock.
func verifierRecordLocked(e VerifierEntry) {
	e.Seq = kverifier.nextSeq
	kverifier.nextSeq++
	kverifier.ledger = append(kverifier.ledger, e)
	verifierTrimLocked()
}

// verifierTrimLocked keeps the ledger at its bound. Caller holds the write lock.
//
// It trims back to seven eighths of the bound in one step rather than one entry
// per insert, which is the trade meter.go's trimLocked makes and for the same
// reason: trimming exactly to the bound makes every insert past the ceiling
// reallocate and copy the whole ledger under the write lock, which is O(n) per
// insert forever and lands as a throughput cliff precisely when a load loop is
// flooding the subsystem. Dropping an eighth at once makes the cost amortized
// constant - one copy per eighth of the ledger's worth of inserts. The price is
// that a query can see slightly fewer entries than the bound, and the evicted
// counter is what keeps that honest.
func verifierTrimLocked() {
	if len(kverifier.ledger) <= maxVerifyLedgerEntries {
		return
	}
	keep := maxVerifyLedgerEntries - maxVerifyLedgerEntries/8
	if len(kverifier.ledger) <= keep {
		return
	}
	over := len(kverifier.ledger) - keep
	kverifier.evicted += int64(over)
	kverifier.ledger = append([]VerifierEntry(nil), kverifier.ledger[over:]...)
}

// verifierResetLocked clears every per-boot field. Caller holds the write lock.
func verifierResetLocked() {
	kverifier.explicit = nil
	kverifier.armed = false
	kverifier.bootID = 0
	kverifier.ledger = nil
	kverifier.nextSeq = 0
	kverifier.evicted = 0
}

// VerifierRecord adds one externally produced appraisal to the ledger. It is
// host-side only, for the case where the operator's own tooling appraised a
// manifest outside this kernel and wants that fact on the same ledger the
// kernel's own appraisals use, so an investigator reads one record of what was
// checked instead of reconciling two.
//
// The kernel assigns the sequence number, the timestamp and the posture; the
// caller chooses none of them, because a caller that could order its own entries
// could interleave them inside the evidence of a refusal. There is no context
// parameter and no policy check, in the shape of SetQosPolicy: this is host
// configuration surface, and a module has no reference by which to reach it on
// anyone else's behalf.
func VerifierRecord(module, version, digest, keyID string, admitted bool, reason string) {
	verifierSyncBoot()
	hasRoots := len(ClusterRootKeys()) > 0

	kverifier.mu.Lock()
	defer kverifier.mu.Unlock()
	verifierRecordLocked(VerifierEntry{
		Mono:     mono(),
		Module:   module,
		Version:  version,
		Digest:   digest,
		KeyID:    keyID,
		Policy:   verifierEffective(hasRoots),
		Admitted: admitted,
		Reason:   reason,
	})
}

// VerifierLedger returns the retained appraisal entries, oldest first, as copies
// in a fresh slice. The order is by sequence and the slice is rebuilt on every
// call, so a caller cannot mutate the ledger through the result, cannot hold a
// live window into kernel state, and cannot observe a concurrent appraisal
// reorder what it is reading. This is what dump tooling and an investigator read.
func VerifierLedger() []VerifierEntry {
	verifierSyncBoot()
	kverifier.mu.RLock()
	defer kverifier.mu.RUnlock()
	out := make([]VerifierEntry, len(kverifier.ledger))
	copy(out, kverifier.ledger)
	return out
}

// VerifierLedgerLen reports how many entries are retained and how many have been
// evicted, in the shape of AuditLen so the same tooling reads both.
func VerifierLedgerLen() (retained int, evicted int64) {
	verifierSyncBoot()
	kverifier.mu.RLock()
	defer kverifier.mu.RUnlock()
	return len(kverifier.ledger), kverifier.evicted
}

// VerifierLedgerFor returns the retained entries for one module name, oldest
// first, as copies. It is the query an investigator actually asks - what did the
// kernel conclude about this module - and it exists so that answer does not
// require copying the whole ledger out of the kernel in order to filter it.
func VerifierLedgerFor(module string) []VerifierEntry {
	var out []VerifierEntry
	for _, e := range VerifierLedger() {
		if e.Module == module {
			out = append(out, e)
		}
	}
	return out
}

// VerifyManifest appraises one manifest signature with no caller context. It is
// the host-tooling form of VerifyManifestLoad, for a deployment pipeline that
// checks a manifest before offering it to the kernel. The appraisal, the ledger
// entry and the audit record are identical; the entry carries pid 0 because
// there is no loader to attribute it to.
func VerifyManifest(m Manifest, sig *VerifierSignature) error {
	return VerifyManifestLoad(nil, m, sig)
}

// VerifyManifestLoad appraises a manifest's signature under the posture in
// force. It is the load-path hook the integrator wires into LoadModule, and it
// accepts a nil context for direct host-side appraisal.
//
// The appraisal has three shapes. Under off nothing happens at all: no ledger
// write, no audit entry, no fault. Under audit, every appraisal lands on the
// audit chain and in the ledger and a missing or invalid signature additionally
// raises a fault: the module loads, but the fact that it loaded unverified is on
// a record it cannot erase, which is the whole value of the mode. Under enforce,
// a missing or invalid signature is a typed refusal - the fault carries the
// loader's pid and domain, the audit chain carries the refusal with the
// manifest's digest, and the error goes back to the loader before the registry
// lookup runs, so no module code executes.
//
// The seal latch is set on every call, before the appraisal and including under
// off. That ordering is what makes the seal hold against module code: this hook
// runs in LoadModule before the factory is called, so the first module of a boot
// is already past the latch by the time any module code exists.
//
// A refusal is checkable with errors.Is against the sentinels declared above.
func VerifyManifestLoad(ctx SContext, m Manifest, sig *VerifierSignature) error {
	c, _ := ctx.(*sContext)
	verifierSyncBoot()
	hasRoots := len(ClusterRootKeys()) > 0

	kverifier.mu.Lock()
	kverifier.armed = true
	policy := verifierEffective(hasRoots)
	kverifier.mu.Unlock()

	if policy == VerifierOff {
		return nil
	}

	verr := verifyManifestBinding(m, sig)
	admitted := verr == nil || policy == VerifierAudit
	reason := ""
	if verr != nil {
		reason = verr.Error()
	}

	fields := map[string]any{
		"module": m.Name, "version": m.Version, "digest": m.Digest(),
		"policy": string(policy), "admitted": admitted,
	}
	if sig != nil {
		fields["key_id"] = sig.KeyID
	}
	if verr != nil {
		fields["reason"] = reason
	}

	kverifier.mu.Lock()
	verifierRecordLocked(VerifierEntry{
		Mono:     mono(),
		PID:      verifierAttribPID(c),
		Domain:   verifierAttribDomain(c),
		Module:   m.Name,
		Version:  m.Version,
		Digest:   m.Digest(),
		KeyID:    verifierSigKeyID(sig),
		Policy:   policy,
		Admitted: admitted,
		Reason:   reason,
	})
	kverifier.mu.Unlock()

	// The audit entry is written before the error reaches the caller, which is
	// the ordering kaudit's guarantee states: a refusal is on the chain even if
	// the caller swallows the error.
	kaudit.record(AuditPolicy, c, "manifest signature appraisal", fields)

	if verr == nil {
		return nil
	}
	// The console record gets its own copy. kaudit does not copy Fields and
	// neither does the console, so handing both the same map would leave two
	// subsystems holding one mutable structure, and a later reader of the
	// console history could see a field the audit chain never hashed.
	if policy == VerifierAudit {
		fault(c, "module admitted without a valid manifest signature (audit policy)", copyFields(fields))
		return nil
	}
	fault(c, "module load refused: manifest signature verification failed", copyFields(fields))
	return verr
}

// verifierAttribPID, verifierAttribDomain and verifierSigKeyID read attribution
// fields without dereferencing nil, so the context-free and signature-free call
// shapes are plain values rather than panics.
func verifierAttribPID(c *sContext) PID {
	if c == nil {
		return 0
	}
	return c.pid
}

func verifierAttribDomain(c *sContext) Domain {
	if c == nil {
		return ""
	}
	return c.dom
}

func verifierSigKeyID(sig *VerifierSignature) string {
	if sig == nil {
		return ""
	}
	return sig.KeyID
}

// verifyManifestBinding is the appraisal itself: structure, then identity, then
// trust, then the cryptographic verdict. That is the order a reviewer asks the
// questions in, and each failure carries its own sentinel because an operator's
// response to a replayed signature is not the response to a forged one.
//
// The identity check runs before the trust check on purpose. A signature from an
// untrusted key that also names the wrong module is a mismatch, and reporting it
// as "key not trusted" would hide the more specific fact and send the operator
// to their key inventory instead of to the replay.
func verifyManifestBinding(m Manifest, sig *VerifierSignature) error {
	if sig == nil {
		return verifierRefuse(m, nil, ErrVerifierUnsigned,
			"module %q presented no signature", m.Name)
	}
	if sig.Version != VerifierBindingVersion {
		return verifierRefuse(m, sig, ErrVerifierBindingVersion,
			"module %q carries binding version %d, this kernel accepts %d",
			m.Name, sig.Version, VerifierBindingVersion)
	}
	// A wrong-length signature is malformed rather than unverifying. That is the
	// distinction receipt.go draws, and it is also what keeps ed25519.Verify from
	// ever being handed a length it would panic on.
	if len(sig.Bytes) != ed25519.SignatureSize {
		return verifierRefuse(m, sig, ErrVerifierMalformed,
			"module %q carries a signature of %d bytes, want %d",
			m.Name, len(sig.Bytes), ed25519.SignatureSize)
	}
	if sig.KeyID == "" {
		return verifierRefuse(m, sig, ErrVerifierMalformed,
			"module %q carries a signature naming no key id", m.Name)
	}

	digest := m.Digest()
	// The envelope is a claim, checked here for diagnosis, and the payload below
	// is rebuilt from the manifest rather than from the envelope. That ordering is
	// what makes the envelope safe to read as a label: an attacker who edits it to
	// match a tampered manifest still fails the cryptographic check, because the
	// bytes that check covers come from the manifest in hand.
	if sig.Module != m.Name || sig.ModuleVersion != m.Version {
		return verifierRefuse(m, sig, ErrVerifierIdentityMismatch,
			"signature covers %s@%s, load presented %s@%s",
			sig.Module, sig.ModuleVersion, m.Name, m.Version)
	}
	if sig.Digest != digest {
		// Reported apart from a bad signature because the two have different
		// causes. This one is the widening-between-review-and-deployment case the
		// subsystem exists for: a declaration that was signed and then edited, so
		// the digest moved and the signature no longer covers what is loading.
		return verifierRefuse(m, sig, ErrVerifierDigestMismatch,
			"signature covers digest %s, this manifest digests to %s", sig.Digest, digest)
	}

	// The trust check runs only when the root set is usable at all. With no
	// parsable root there is no inventory to be absent from, and reporting "this
	// key is not trusted" would state a verdict about the module when the real
	// fact is that the kernel cannot appraise anything. The cryptographic step
	// below reports the configuration failure itself.
	if verifierUsableRoots() > 0 && !verifierTrustedKeyID(sig.KeyID) {
		return verifierRefuse(m, sig, ErrVerifierKeyUntrusted,
			"key id %s is not among the sealed cluster roots", sig.KeyID)
	}

	ok, _, err := verifyAgainstClusterRoots(
		verifierBindingPayload(m.Name, m.Version, digest), sig.Bytes)
	if err != nil {
		// An unverifiable configuration - no roots at all, no parsable root - is
		// not a verdict on the module. It is reported as itself so it cannot be
		// read as "the module cheated", which is the same line receipt.go draws
		// between a false verdict and an error, and it carries no sentinel because
		// there is no fact about the module to check against. Under enforce it
		// still refuses the load, because fail-closed is the only safe answer when
		// the kernel cannot appraise.
		return fmt.Errorf("kernel: cannot appraise manifest for %q: %w", m.Name, err)
	}
	if !ok {
		return verifierRefuse(m, sig, ErrVerifierBadSignature,
			"no sealed cluster root verifies the signature over module %q digest %s",
			m.Name, digest)
	}
	return nil
}

// verifierUsableRoots counts how many sealed cluster roots parse as ed25519
// public keys. Zero means the trust root is configured but unusable, which is a
// deployment defect rather than a verdict on any module.
func verifierUsableRoots() int {
	usable := 0
	for _, root := range ClusterRootKeys() {
		if _, err := parseEd25519Public(root); err == nil {
			usable++
		}
	}
	return usable
}

// verifierTrustedKeyID reports whether keyID names a sealed cluster root. It
// recomputes the id from each root's key bytes rather than comparing the strings
// a signer and an operator happened to write down, so PEM, hex and base64
// spellings of one public key are one key.
func verifierTrustedKeyID(keyID string) bool {
	for _, root := range ClusterRootKeys() {
		pub, err := parseEd25519Public(root)
		if err != nil {
			continue
		}
		if ed25519KeyID(pub) == keyID {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Declaration audit.
//
// The second half of the subsystem, and the Go substitute for the bytecode scan:
// the statically reviewable facts about a manifest that an operator should see
// before signing it. Where the JVM spec intercepted dangerous calls at
// class-load time, this reviews the declaration that bounds them at signing
// time, which is the only point in this architecture where the question can be
// answered before code runs.
//
// It is advisory on purpose. Manifest.Validate already refuses what must not
// load, and duplicating a refusal here would give one rule two implementations
// that drift apart and would bury the real findings under things the kernel is
// about to reject anyway. Nothing Validate refuses is reported here. What is
// reported is what Validate deliberately accepts because it can be legitimate:
// a scoped operation no module domain holds, a scope declared for an operation
// never requested, a numeric host in private or link-local space, a path
// spelling that cleans to something else, a route that nests with another, a
// listen address that binds every interface. A reviewer signing a manifest is
// vouching for these too, and they deserve to see them listed rather than
// discover them in production.

// VerifierFindingCode names one class of advisory finding. The set is closed so a
// reviewer can enumerate it and so tooling matches on the class rather than on
// message text.
type VerifierFindingCode string

const (
	// VerifierFindingUnreachableOp: the manifest requests a scoped operation that
	// Validate passes through but no module domain holds, so every call would
	// be denied. Validate refuses this for unscoped operations and skips the
	// ceiling check for scoped ones, which is the gap this finding covers.
	VerifierFindingUnreachableOp VerifierFindingCode = "unreachable-op"
	// VerifierFindingDeadScope: a scope field is populated but the manifest does not
	// request the operation it bounds. The declaration never takes effect,
	// which means the manifest was edited without review or a request was
	// removed without removing its boundary.
	VerifierFindingDeadScope VerifierFindingCode = "dead-scope"
	// VerifierFindingMissingScope: a scoped operation is requested with no boundary
	// declared where Validate does not require one. The module loads and every
	// scoped call is then refused, which reads as a kernel bug rather than as
	// an incomplete declaration.
	VerifierFindingMissingScope VerifierFindingCode = "missing-scope"
	// VerifierFindingWeakScope: one declared scope subsumes another, so the broader entry
	// governs and the narrower one is decoration. None of these are invalid;
	// all of them are where a widened declaration hides.
	VerifierFindingWeakScope VerifierFindingCode = "weak-scope"
	// VerifierFindingPrivateHost: an allowed host is a numeric address in
	// loopback, private, link-local, multicast, unspecified or documentation
	// space. validateHost refuses loopback by name only, so a numeric 127.0.0.1
	// clears validation; this layer parses addresses, which validation does not.
	VerifierFindingPrivateHost VerifierFindingCode = "private-host"
	// VerifierFindingPathForm: a declared path does not survive cleaning unchanged, or
	// two spellings clean onto one grant. Both are legal; both are how a grant
	// reads narrower in review than it behaves.
	VerifierFindingPathForm VerifierFindingCode = "path-form"
	// VerifierFindingRouteForm: one declared serve route nests with another, so a
	// prefix-dispatching caller resolves one through the other. Routes are the
	// surface other modules call, and a shadow-prone declaration is a review
	// item even when it is valid.
	VerifierFindingRouteForm VerifierFindingCode = "route-form"
	// VerifierFindingListenForm: a listen address that does not parse as host:port, leaves
	// the port to the stack, or binds every interface. Validate requires only
	// that it be non-empty.
	VerifierFindingListenForm VerifierFindingCode = "listen-form"
	// VerifierFindingIdentityForm: an identity string carrying characters with special
	// meaning in the console, the audit log or the digest pipeline. Validate
	// bounds the name's separators and never reads the version, and a version
	// containing a newline writes a second log line when it is printed.
	VerifierFindingIdentityForm VerifierFindingCode = "identity-form"
)

// VerifierFindingCodes lists the finding classes, for a reviewer building a
// checklist and for tooling enumerating what this layer can report.
func VerifierFindingCodes() []VerifierFindingCode {
	return []VerifierFindingCode{
		VerifierFindingUnreachableOp, VerifierFindingDeadScope, VerifierFindingMissingScope, VerifierFindingWeakScope,
		VerifierFindingPrivateHost, VerifierFindingPathForm, VerifierFindingRouteForm, VerifierFindingListenForm,
		VerifierFindingIdentityForm,
	}
}

// VerifierFinding is one advisory observation about a manifest. It is what a
// reviewer questions, never what the kernel refuses.
type VerifierFinding struct {
	// Code is the closed finding class.
	Code VerifierFindingCode `json:"code"`
	// Field names the manifest field the finding is about.
	Field string `json:"field"`
	// Detail is the observation, for a human reading a signing checklist.
	Detail string `json:"detail"`
}

// VerifierAuditDeclaration statically reviews a manifest and reports what a signer
// should question. It never refuses and never re-runs Validate: the input is
// taken as a declaration that is about to be, or has just been, validated, and
// anything Validate would reject is left to Validate.
//
// It reads only the manifest. It reaches no disk, no network and no kernel
// state, so its findings cannot be influenced by anything the module under
// review controls, and reviewing an hostile manifest cannot itself be an attack
// on the reviewer's machine.
func VerifierAuditDeclaration(m Manifest) []VerifierFinding {
	var out []VerifierFinding

	if strings.ContainsAny(m.Version, "\n\r") {
		out = append(out, VerifierFinding{
			Code:  VerifierFindingIdentityForm,
			Field: "version",
			Detail: fmt.Sprintf("version %q contains a line break and is printed into console and audit records verbatim",
				m.Version),
		})
	}

	for _, op := range m.Require {
		// Validate refuses an unscoped operation the ceiling does not hold, so
		// only scoped operations reach here unreported. A scoped operation is
		// passed through the ceiling check by design, because its scope is meant
		// to be enforced per call; when the ceiling does not hold it either, the
		// per-call enforcement never runs and every call is denied before it is
		// scoped.
		if !IsScoped(op) || Allowed(DomainPlugin, op) {
			continue
		}
		detail := fmt.Sprintf("%s is requested and passes manifest validation as a scoped operation, but no module domain holds it, so every call is denied by the ceiling",
			op)
		if op == OpSecretRead {
			detail += fmt.Sprintf("; use %s, under which the kernel applies the credential and returns only the result",
				OpSecretUse)
		}
		out = append(out, VerifierFinding{Code: VerifierFindingUnreachableOp, Field: "require", Detail: detail})
	}

	// Dead scopes: a boundary declared for an operation the manifest never
	// requests. Validate refuses the opposite direction - a scoped operation
	// with no boundary - and accepts these, because each field is an optional
	// input. That acceptance is exactly the gap a reviewer needs listed.
	if len(m.AllowedHosts) > 0 && !m.requires(OpNetDial) {
		out = append(out, VerifierFinding{
			Code:  VerifierFindingDeadScope,
			Field: "allowed_hosts",
			Detail: fmt.Sprintf("%d allowed host(s) declared but %s is not requested, so the list never takes effect",
				len(m.AllowedHosts), OpNetDial),
		})
	}
	if len(m.ReadPaths) > 0 && !m.requires(OpFSRead) {
		out = append(out, VerifierFinding{
			Code:  VerifierFindingDeadScope,
			Field: "read_paths",
			Detail: fmt.Sprintf("%d read path(s) declared but %s is not requested, so the list never takes effect",
				len(m.ReadPaths), OpFSRead),
		})
	}
	if len(m.WritePaths) > 0 && !m.requires(OpFSWrite) {
		out = append(out, VerifierFinding{
			Code:  VerifierFindingDeadScope,
			Field: "write_paths",
			Detail: fmt.Sprintf("%d write path(s) declared but %s is not requested, so the list never takes effect",
				len(m.WritePaths), OpFSWrite),
		})
	}
	if m.ListenAddr != "" && !m.requires(OpNetListen) {
		out = append(out, VerifierFinding{
			Code:  VerifierFindingDeadScope,
			Field: "listen_addr",
			Detail: fmt.Sprintf("listen address %q declared but %s is not requested, so the module never binds it",
				m.ListenAddr, OpNetListen),
		})
	}

	// Missing scope where Validate does not require one. secret:use is the case
	// that matters: it is in the plugin ceiling, so Validate neither refuses it
	// nor requires a prefix for it, and a manifest that requests it with no
	// prefixes loads cleanly and is then refused every credential - which the
	// module author will read as a keyring bug.
	if (m.requires(OpSecretUse) || m.requires(OpSecretRead)) && len(m.SecretPrefixes) == 0 {
		out = append(out, VerifierFinding{
			Code:   VerifierFindingMissingScope,
			Field:  "secret_prefixes",
			Detail: "a secret operation is requested with no key prefix declared, so the keyring scope is empty and every alias is invisible to this module",
		})
	}
	if m.requires(OpPeerDial) && len(m.AllowedHosts) == 0 {
		out = append(out, VerifierFinding{
			Code:  VerifierFindingMissingScope,
			Field: "allowed_hosts",
			Detail: fmt.Sprintf("%s is requested with no allowed host declared, so there is no peer this module may dial",
				OpPeerDial),
		})
	}

	// Subsumed secret prefixes: a shorter prefix makes every longer one
	// redundant, and the shorter one is the grant that actually governs.
	for i := range m.SecretPrefixes {
		for j := range m.SecretPrefixes {
			if i == j {
				continue
			}
			short, long := m.SecretPrefixes[i], m.SecretPrefixes[j]
			if short != "" && len(short) < len(long) && strings.HasPrefix(long, short) {
				out = append(out, VerifierFinding{
					Code:  VerifierFindingWeakScope,
					Field: "secret_prefixes",
					Detail: fmt.Sprintf("prefix %q subsumes prefix %q, so the longer entry grants nothing the shorter one does not",
						short, long),
				})
			}
		}
	}

	// Numeric hosts in reserved space. validateHost refuses loopback by name and
	// refuses any entry carrying "/@:?#", but a bare numeric address contains
	// none of those characters, so 127.0.0.1 and 10.0.0.5 both pass validation
	// today. This layer parses addresses, which validation does not.
	for _, h := range m.AllowedHosts {
		ip := net.ParseIP(h)
		if ip == nil {
			continue
		}
		if cls := verifierIPClass(ip); cls != "" {
			out = append(out, VerifierFinding{
				Code:  VerifierFindingPrivateHost,
				Field: "allowed_hosts",
				Detail: fmt.Sprintf("host %q is a numeric address in %s space and passes validation, which refuses loopback by name only",
					h, cls),
			})
		}
	}

	out = append(out, verifierPathFindings("read_paths", m.ReadPaths)...)
	out = append(out, verifierPathFindings("write_paths", m.WritePaths)...)

	// Route nesting, reported once per pair in declaration order so a reviewer
	// sees the relationship rather than two copies of it.
	for i := range m.ServeRoutes {
		for j := i + 1; j < len(m.ServeRoutes); j++ {
			a, b := m.ServeRoutes[i], m.ServeRoutes[j]
			if !strings.HasPrefix(b, a+"/") && !strings.HasPrefix(a, b+"/") {
				continue
			}
			out = append(out, VerifierFinding{
				Code:  VerifierFindingRouteForm,
				Field: "serve_routes",
				Detail: fmt.Sprintf("route %q nests with route %q, so a prefix-dispatching caller resolves one through the other",
					a, b),
			})
		}
	}

	if m.ListenAddr != "" {
		host, port, err := net.SplitHostPort(m.ListenAddr)
		switch {
		case err != nil:
			out = append(out, VerifierFinding{
				Code:  VerifierFindingListenForm,
				Field: "listen_addr",
				Detail: fmt.Sprintf("listen address %q does not parse as host:port (%v), and validation requires only that it be non-empty",
					m.ListenAddr, err),
			})
		case port == "" || port == "0":
			out = append(out, VerifierFinding{
				Code:  VerifierFindingListenForm,
				Field: "listen_addr",
				Detail: fmt.Sprintf("listen address %q leaves the port to the stack, so a reviewer cannot tell which port the signature covers",
					m.ListenAddr),
			})
		case host == "" || host == "0.0.0.0" || host == "::":
			out = append(out, VerifierFinding{
				Code:  VerifierFindingListenForm,
				Field: "listen_addr",
				Detail: fmt.Sprintf("listen address %q binds every interface, so the signature vouches for an any-interface service",
					m.ListenAddr),
			})
		}
	}

	return out
}

// verifierIPClass names the reserved address class of a parsed IP, or "" for
// ordinary global unicast.
//
// Loopback is included even though validateHost refuses it, because it refuses
// the NAME forms only - "localhost" and "*.localhost". A numeric loopback
// address carries none of the characters validateHost rejects and passes
// validation, so this is the layer that catches it. Reporting it is not
// duplicating a refusal; it is covering the half of the range the refusal does
// not reach.
func verifierIPClass(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsPrivate():
		return "RFC1918 private"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsMulticast():
		return "multicast"
	}
	// The documentation ranges are not routable, so a host in one is a
	// placeholder that shipped, which is a review catch rather than a
	// configuration error.
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2:
			return "documentation (192.0.2.0/24)"
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100:
			return "documentation (198.51.100.0/24)"
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
			return "documentation (203.0.113.0/24)"
		}
	}
	return ""
}

// verifierPathFindings reports the path findings for one declared path list: a
// spelling that cleaning would rewrite, two spellings that clean onto one grant,
// and one path that a broader declared path already covers.
//
// Validate rejects absolute paths, traversal and the data root itself. It does
// not compare a spelling with its cleaned form or one path against another,
// because neither is invalid - both are how a grant reads narrower in review
// than it behaves, which is a signing question and not a load question.
//
// Subsumption is a second pass over every ordered pair rather than a comparison
// against the paths seen so far, so the finding does not depend on the order the
// author happened to write the list in. ["a/b","a"] and ["a","a/b"] are the same
// declaration and must produce the same review; a one-pass version reports the
// first and stays silent on the second.
func verifierPathFindings(field string, paths []string) []VerifierFinding {
	var out []VerifierFinding
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		clean := path.Clean(p)
		if clean != p {
			out = append(out, VerifierFinding{
				Code:  VerifierFindingPathForm,
				Field: field,
				Detail: fmt.Sprintf("path %q cleans to %q, and the cleaned form is the grant, not the spelling under review",
					p, clean),
			})
		}
		if slices.Contains(cleaned, clean) {
			out = append(out, VerifierFinding{
				Code:  VerifierFindingPathForm,
				Field: field,
				Detail: fmt.Sprintf("path %q cleans to %q, which another declared path already cleans to",
					p, clean),
			})
		}
		cleaned = append(cleaned, clean)
	}

	for i := range cleaned {
		for j := range cleaned {
			if i == j || !strings.HasPrefix(cleaned[j], cleaned[i]+"/") {
				continue
			}
			out = append(out, VerifierFinding{
				Code:   VerifierFindingWeakScope,
				Field:  field,
				Detail: fmt.Sprintf("path %q is already covered by the broader path %q", cleaned[j], cleaned[i]),
			})
		}
	}
	return out
}

// resetVerifier clears the posture, the seal latch and the ledger. Called only
// from resetKernel, immediately before the secrets and the trust root are
// dropped, so a restarted kernel re-derives its posture from its own
// configuration instead of inheriting the previous boot's choice: a boot under a
// root with no cluster keys must not silently keep enforcing against keys that
// are no longer configured, and a boot under a root that added keys must not
// silently keep skipping them. The latch clears with it, which is what reopens
// the configuration window for the next boot.
func resetVerifier() {
	kverifier.mu.Lock()
	defer kverifier.mu.Unlock()
	verifierResetLocked()
}
