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

// kreceipt: signed settlement receipts (subsystem: kreceipt, the analogue of a
// signed invoice a payment authority issues, and of the receipt a light node
// verifies against a state root).
//
// SYSCALL WIRING FOR THE INTEGRATOR.
//
// The exported functions below are the implementation; paste this block into
// kernel/context.go to expose them as syscalls.
//
// 1. Add the group to the SContext interface's group list, next to SyscallCrypto:
//
//	SyscallReceipt
//
// 2. Add the group interface and the methods:
//
//	// SyscallReceipt is the settlement half of the syscall surface. A module may
//	// verify any receipt and take custody of one; only a context holding
//	// receipt:issue may mint one, and no module domain does.
//	type SyscallReceipt interface {
//	    // SyscallReceiptIssue mints and signs one settlement receipt. Requires
//	    // receipt:issue.
//	    SyscallReceiptIssue(spec ReceiptSpec) (Receipt, error)
//	    // SyscallReceiptVerify recomputes a receipt's canonical encoding and
//	    // checks its signature against the sealed cluster roots. Requires
//	    // receipt:verify.
//	    SyscallReceiptVerify(r Receipt) (ReceiptVerdict, error)
//	    // SyscallReceiptOpen verifies a receipt and returns a per-pid handle to
//	    // the verdict. Requires receipt:verify.
//	    SyscallReceiptOpen(r Receipt) (FD, ReceiptVerdict, error)
//	}
//
//	func (c *sContext) SyscallReceiptIssue(spec ReceiptSpec) (Receipt, error) {
//	    return ReceiptIssue(c, spec)
//	}
//	func (c *sContext) SyscallReceiptVerify(r Receipt) (ReceiptVerdict, error) {
//	    return ReceiptVerify(c, r)
//	}
//	func (c *sContext) SyscallReceiptOpen(r Receipt) (FD, ReceiptVerdict, error) {
//	    return ReceiptOpen(c, r)
//	}
//
// 3. kmeter's MeterMarkSettled gates on receipt:issue, which no live context holds,
//    so the "this request was settled" flag cannot be set from Kernel.IssueReceipt.
//    Either give the host path a package-private markSettled(id) in meter.go, or
//    grant receipt:issue to a domain the owner approves. This is reported rather than
//    changed, because it is a policy decision.
//
// 4. Add resetReceipts() to resetKernel() in kernel/kernel.go, immediately before
//    kboot.reset(): the sequence ledger is per boot and per node, and a cursor that
//    survived a restart would either repeat a sequence number or open a gap, and
//    both break the settlement record.
//
// POLICY NOTE the integrator must read before wiring receipt:issue anywhere.
//
// kernel/policy.go grants receipt:issue to the kernel domain alone. The init domain
// deliberately does not hold it, and the comment above that row says why: init is
// long-lived, so anything that compromised init could mint settlement receipts for
// work that never happened. The plugin domain does not hold it either, and no
// manifest can grant it.
//
// The consequence is that the pid 0 root context is the only context that ever
// holds receipt:issue, and boot.go retires it the instant init exists. So after
// boot, no live context can issue a receipt through a policy check. Issuance is
// therefore also reachable from the *Kernel handle as Kernel.IssueReceipt, which is
// host-only for the same reason Kernel.Publish and Kernel.InstallSecret are: a
// module never receives the handle, and Boot refuses a second call, so module code
// cannot obtain one.
//
// This is not a widening of the policy and adds no capability the host did not
// already have: the host process supplied BootTrustRoot.SigningKeyPEM, so it holds
// the signing key outright and could sign a receipt itself. It is reported here,
// rather than fixed by editing policy.go, because granting receipt:issue to a live
// domain is a trust-root change that needs owner approval.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xingguangcuican6666/MeowAPI/abi"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReceiptVersion is the encoding version this kernel issues and accepts. A receipt
// from another version is refused rather than reinterpreted, because the meaning of
// a field is part of what the signature covers: a verifier that guessed at an
// unknown layout would be signing off on a record it did not read.
const ReceiptVersion = 1

// Receipt is abi.Receipt: a module passes it to or receives it from the
// kernel, so the shape lives in the package the module compiles against.
type Receipt = abi.Receipt

// ReceiptSpec is abi.ReceiptSpec: a module passes it to or receives it from the
// kernel, so the shape lives in the package the module compiles against.
type ReceiptSpec = abi.ReceiptSpec

// Receipt ceilings. They bound one receipt, and each one exists because an unbounded
// field in a signed record is a way to make the node store, hash and transmit
// arbitrary volume under a valid signature.
const (
	maxReceiptLabelLen    = 128
	maxReceiptPromptBytes = maxCryptoInputBytes
	// maxReceiptElapsedNanos bounds the service time one receipt may claim. A
	// receipt claiming a year of service is either forged or the product of a
	// StartedMono reading from another boot, and both must be refused rather than
	// settled.
	maxReceiptElapsedNanos = int64(24 * time.Hour)
)

// MaxReceiptLabelLen reports the ceiling on a receipt's trace and route labels.
func MaxReceiptLabelLen() int { return maxReceiptLabelLen }

// ErrReceiptLimit is the sentinel for every receipt ceiling. It is wrapped in a
// ReceiptError so a caller can ask both questions: was this refused because a limit
// was hit, and which limit.
var ErrReceiptLimit = errors.New("kernel: receipt limit reached")

// ReceiptError reports a refused receipt operation. It is a distinct type so a
// caller can tell "the kernel will not settle this" from "the kernel could not".
type ReceiptError struct {
	Msg string
	// Err carries the underlying cause, which lets errors.Is find ErrReceiptLimit
	// and a caller see the original failure.
	Err error
}

func (e *ReceiptError) Error() string {
	if e.Err == nil {
		return "kernel: receipt refused: " + e.Msg
	}
	return "kernel: receipt refused: " + e.Msg + ": " + e.Err.Error()
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *ReceiptError) Unwrap() error { return e.Err }

func receiptErr(format string, a ...any) error {
	return &ReceiptError{Msg: fmt.Sprintf(format, a...)}
}

func receiptLimit(err error, format string, a ...any) error {
	return &ReceiptError{Msg: fmt.Sprintf(format, a...), Err: err}
}

// receiptLedger owns the per-node sequence numbers. Gap-free is a property of the
// ledger and not of the caller, so the sequence number is assigned inside the same
// critical section that commits the receipt: an issue that fails validation or fails
// to sign consumes nothing, and a verifier that sees 1,2,4 knows a receipt was
// issued and then lost rather than never issued at all.
type receiptLedger struct {
	mu      sync.Mutex
	next    map[string]int64
	issued  int64
	refused int64
}

var kreceipts = &receiptLedger{next: map[string]int64{}}

// ReceiptLedgerStats reports issuance counters and the per-node sequence cursor.
// Nothing here is secret: the cursor appears in every receipt the node publishes.
type ReceiptLedgerStats struct {
	Issued  int64            `json:"issued"`
	Refused int64            `json:"refused"`
	Cursor  map[string]int64 `json:"cursor"`
}

// ReceiptStats returns a copy of the ledger counters, for the console dump and for
// an operator checking that settlement is progressing.
func ReceiptStats() ReceiptLedgerStats {
	kreceipts.mu.Lock()
	defer kreceipts.mu.Unlock()
	cursor := make(map[string]int64, len(kreceipts.next))
	for node, seq := range kreceipts.next {
		// The cursor holds the next number to issue, so the last issued one is
		// one less. Reporting it that way keeps "no receipts yet" at zero.
		cursor[node] = seq - 1
	}
	return ReceiptLedgerStats{Issued: kreceipts.issued, Refused: kreceipts.refused, Cursor: cursor}
}

// ReceiptCursor reports the highest sequence number issued for one node, or 0 when
// this boot has issued none.
func ReceiptCursor(nodeID string) int64 {
	kreceipts.mu.Lock()
	defer kreceipts.mu.Unlock()
	next := kreceipts.next[nodeID]
	if next <= 0 {
		return 0
	}
	return next - 1
}

// countRefusal records a refused issue. A node that refuses to settle is a node
// whose operators need to know why, and the counter is what makes a run of
// refusals visible when each one on its own is cheap and quiet.
func countRefusal() {
	kreceipts.mu.Lock()
	kreceipts.refused++
	kreceipts.mu.Unlock()
}

// ReceiptIssue mints and signs one settlement receipt. Requires receipt:issue,
// which no live context holds in the current policy table; see the note at the top
// of this file for the host-side path that does the work.
func ReceiptIssue(ctx SContext, spec ReceiptSpec) (Receipt, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return Receipt{}, errForeignContext
	}
	if err := c.syscall(OpReceiptIssue); err != nil {
		countRefusal()
		return Receipt{}, err
	}
	target := spec.PID
	if target == 0 {
		target = c.pid
	}
	return issueReceipt(c, target, spec)
}

// IssueReceipt mints and signs a receipt on the host process's behalf.
//
// It performs no policy check, because no live context could pass one: receipt:issue
// is held only by the kernel domain and that context is retired during boot. The
// host process is the authority here in the same sense that it is the authority for
// the trust root it handed to Boot - it supplied the signing key, so it could sign
// this receipt itself. A module cannot reach this method: it never receives a
// *Kernel, and Boot refuses a second call.
func (k *Kernel) IssueReceipt(spec ReceiptSpec) (Receipt, error) {
	if err := k.hostOnly(); err != nil {
		return Receipt{}, err
	}
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return Receipt{}, errors.New("kernel: already shut down")
	}
	target := spec.PID
	if target == 0 {
		target = k.initCtx.pid
	}
	return issueReceipt(k.initCtx, target, spec)
}

// issueReceipt validates, encodes, signs and commits one receipt. Attribution
// context is used for faults and audit entries only; the caller has already
// established the authority to issue.
func issueReceipt(ctx *sContext, target PID, spec ReceiptSpec) (Receipt, error) {
	nodeID, _ := BootGet("node.id")
	if nodeID == "" {
		countRefusal()
		return Receipt{}, errors.New("kernel: the sealed trust root declares no node id")
	}

	r, err := buildReceipt(nodeID, target, spec)
	if err != nil {
		countRefusal()
		fault(ctx, "receipt issue refused", map[string]any{
			"pid": target, "node_id": nodeID, "reason": err.Error(),
		})
		return Receipt{}, err
	}

	// The key id is part of the signed payload, so it must be known before the
	// first byte is encoded. Asking for it here also means an unusable signing key
	// is discovered before a sequence number is reserved.
	keyID, err := NodeKeyID()
	if err != nil {
		countRefusal()
		fault(ctx, "cannot issue receipt: no usable node signing key",
			map[string]any{"error": err.Error()})
		return Receipt{}, err
	}
	r.KeyID = keyID

	// The sequence number is taken and committed under one lock, with signing
	// inside it. Signing is the only step that can still fail after validation, and
	// letting it fail after consuming a number would open a gap that no verifier
	// could distinguish from a receipt that was issued and then suppressed - which
	// is exactly the fraud a gap-free ledger exists to expose.
	//
	// The unlock is deferred, and the refusal counter is incremented inline rather
	// than through countRefusal, because countRefusal takes this same mutex and
	// would deadlock. Deferring rather than unlocking at each return is what keeps a
	// panic in this window from wedging the kernel: signing calls into ed25519 with
	// key material the cache produced, and a zero-length key makes Sign panic with
	// "index out of range [0] with length 0". With an explicit unlock the panic left
	// the settlement mutex held forever, and the next thing to take it was
	// resetReceipts during Shutdown - so the failure mode was not a bad receipt but
	// a kernel that could no longer shut down. Measured: a test that tripped it
	// hung for the full ten-minute timeout instead of reporting a failure.
	//
	// The commit is a closure rather than inline, so the audit record below is
	// written after the lock is released. Holding the settlement mutex across an
	// audit write would put this subsystem's lock underneath kaudit's for no reason,
	// and the two are otherwise independent.
	commit := func() (Receipt, error) {
		kreceipts.mu.Lock()
		defer kreceipts.mu.Unlock()

		r.Seq = kreceipts.next[nodeID]
		if r.Seq <= 0 {
			r.Seq = 1
		}
		sig, serr := signWithNodeKey(ctx, receiptPayload(r))
		if serr != nil {
			kreceipts.refused++
			return Receipt{}, serr
		}
		r.Signature = sig.Bytes
		kreceipts.next[nodeID] = r.Seq + 1
		kreceipts.issued++
		return r, nil
	}
	r, err = commit()
	if err != nil {
		return Receipt{}, err
	}

	kaudit.record(AuditSettle, ctx, "receipt issued", map[string]any{
		"node_id": nodeID, "seq": r.Seq, "pid": target, "trace": r.Trace,
		"tokens_in": r.TokensIn, "tokens_out": r.TokensOut,
		"elapsed_nanos": r.ElapsedNanos, "digest": ReceiptDigest(r),
		// The prompt and completion are not recorded, and neither are their
		// hashes: the hashes are in the receipt, which the audit entry names by
		// digest, and a request body is user data that does not belong in the
		// kernel's own record.
	})
	return r, nil
}

// buildReceipt fills in every kernel-owned field and validates the issuer's claims.
// It does not touch the ledger, so a refusal here costs no sequence number.
func buildReceipt(nodeID string, target PID, spec ReceiptSpec) (Receipt, error) {
	if target < 0 {
		return Receipt{}, receiptErr("negative pid %d", target)
	}
	if len(spec.Trace) > maxReceiptLabelLen {
		return Receipt{}, receiptLimit(ErrReceiptLimit,
			"trace id of %d bytes exceeds the ceiling %d", len(spec.Trace), maxReceiptLabelLen)
	}
	if len(spec.Route) > maxReceiptLabelLen {
		return Receipt{}, receiptLimit(ErrReceiptLimit,
			"route label of %d bytes exceeds the ceiling %d", len(spec.Route), maxReceiptLabelLen)
	}
	if strings.ContainsAny(spec.Trace, "\n\r") || strings.ContainsAny(spec.Route, "\n\r") {
		return Receipt{}, receiptErr("trace and route must not contain a line break")
	}
	if len(spec.Prompt) > maxReceiptPromptBytes {
		return Receipt{}, receiptLimit(ErrReceiptLimit,
			"prompt of %d bytes exceeds the ceiling %d", len(spec.Prompt), maxReceiptPromptBytes)
	}
	if len(spec.Completion) > maxReceiptPromptBytes {
		return Receipt{}, receiptLimit(ErrReceiptLimit,
			"completion of %d bytes exceeds the ceiling %d", len(spec.Completion), maxReceiptPromptBytes)
	}

	promptHash, err := contentDigest(spec.PromptHash, spec.Prompt, "prompt")
	if err != nil {
		return Receipt{}, err
	}
	completionHash, err := contentDigest(spec.CompletionHash, spec.Completion, "completion")
	if err != nil {
		return Receipt{}, err
	}

	metered, err := settleAgainstMeter(spec.Request, target)
	if err != nil {
		return Receipt{}, err
	}

	in, out, err := validateTokens(target, spec.TokensIn, spec.TokensOut, metered)
	if err != nil {
		return Receipt{}, err
	}

	elapsed, err := validateElapsed(spec.StartedMono, metered)
	if err != nil {
		return Receipt{}, err
	}

	return Receipt{
		Version:        ReceiptVersion,
		NodeID:         nodeID,
		Trace:          spec.Trace,
		Route:          spec.Route,
		PID:            target,
		PromptHash:     promptHash,
		CompletionHash: completionHash,
		TokensIn:       in,
		TokensOut:      out,
		ElapsedNanos:   elapsed,
		IssuedMono:     mono(),
		IssuedWall:     nowUTC().UnixNano(),
	}, nil
}

// contentDigest resolves one content hash. A supplied digest must be exactly 64
// lowercase hex characters, which is the shape a sha256 digest has everywhere else
// in this kernel; anything else is refused rather than passed through, because a
// receipt carrying a malformed digest cannot be compared with a peer's copy and
// would silently agree with nothing.
func contentDigest(supplied string, content []byte, what string) (string, error) {
	if supplied == "" {
		sum := sha256Sum(content)
		return sum, nil
	}
	if len(supplied) != 64 {
		return "", receiptErr("%s hash must be 64 hex characters, got %d", what, len(supplied))
	}
	lower := strings.ToLower(supplied)
	if _, err := hex.DecodeString(lower); err != nil {
		return "", receiptErr("%s hash is not hex: %v", what, err)
	}
	if lower != supplied {
		// Normalizing case would make two nodes that differ only in case agree on
		// the receipt but disagree on the digest string they compare, so the
		// kernel fixes the case here and says so.
		return "", receiptErr("%s hash must be lowercase hex", what)
	}
	return lower, nil
}

// settleAgainstMeter reads the kmeter record for one request, when the issuer named
// one. A nil result means "not settling against a specific request", in which case the
// per-pid accounting totals from usage.go are the floor instead.
//
// This is the cross-subsystem read the receipt needs, and it is the reason a receipt
// means anything: the counts inside the signature are the kernel's own measurement of
// the work, not the module's opinion of it. It reads through meterLookup rather than
// through a syscall, because no policy check is owed here - the caller has already been
// authorized to issue, and the request id is data.
func settleAgainstMeter(id RequestID, target PID) (*MeterRecord, error) {
	if id == "" {
		return nil, nil
	}
	rec, err := meterLookup(id)
	if err != nil {
		return nil, receiptErr("request %q is not in the meter ledger: %v", id, err)
	}
	if rec.PID != target {
		// Settling another module's work under this pid is the fraud the receipt
		// exists to prevent, so it is refused rather than reconciled.
		return nil, receiptErr("request %q belongs to pid %d, not to pid %d", id, rec.PID, target)
	}
	return &rec, nil
}

// validateTokens bounds one receipt's token counts and cross-checks them against what
// the kernel measured.
//
// The cross-check is the anti-fraud control: a module cannot settle tokens it never
// reported. It may under-claim, which costs it revenue and is not a security problem.
// It may not over-claim, which is the fraud kslashing exists to arbitrate and which
// should never reach a peer in the first place.
//
// Two sources are consulted, in increasing order of strength. Without a request id the
// floor is the pid's usage totals from usage.go, which is what a module reports
// through usage:emit. With one, the floor is that request's own kmeter record, which
// the kernel measured per request and which a module cannot inflate after the fact.
func validateTokens(target PID, in, out int64, metered *MeterRecord) (int64, int64, error) {
	if in < 0 || out < 0 {
		return 0, 0, receiptErr("negative token counts (%d in, %d out)", in, out)
	}
	if in > maxTokenClaim || out > maxTokenClaim {
		return 0, 0, receiptLimit(ErrReceiptLimit,
			"token count exceeds the per-receipt ceiling %d", maxTokenClaim)
	}
	if metered != nil {
		if metered.TokensIn < in {
			return 0, 0, receiptErr("request %q metered %d prompt tokens, cannot settle %d",
				metered.ID, metered.TokensIn, in)
		}
		if metered.TokensOut < out {
			return 0, 0, receiptErr("request %q metered %d completion tokens, cannot settle %d",
				metered.ID, metered.TokensOut, out)
		}
		return in, out, nil
	}
	reported := UsageSnapshot()[target]
	if reported.Total[UsageTokensIn] < in {
		return 0, 0, receiptErr("pid %d claims %d prompt tokens but has only reported %d",
			target, in, reported.Total[UsageTokensIn])
	}
	if reported.Total[UsageTokensOut] < out {
		return 0, 0, receiptErr("pid %d claims %d completion tokens but has only reported %d",
			target, out, reported.Total[UsageTokensOut])
	}
	return in, out, nil
}

// maxTokenClaim is the per-receipt token ceiling. It matches usage.go's per-event
// ceiling so that a count too large to report is also too large to settle, and there
// is no window in which a claim is acceptable to one subsystem and not the other.
const maxTokenClaim = int64(1) << 40

// validateElapsed measures the service time on the monotonic clock and bounds it.
//
// Zero means "no start reading was taken", so the elapsed time is zero - unless the
// issuer named a kmeter request, in which case the duration is the one the kernel
// measured for that request and the caller's reading is ignored. Any other reading must
// lie inside this boot's clock: a negative one did not come from mono(), which starts at
// zero and never decreases, and accepting it would let an issuer choose the duration it
// is billed for.
func validateElapsed(startedMono int64, metered *MeterRecord) (int64, error) {
	if metered != nil {
		return boundElapsed(metered.ElapsedNanos())
	}
	if startedMono == 0 {
		return 0, nil
	}
	now := mono()
	if startedMono < 0 {
		return 0, receiptErr("start reading %d did not come from the monotonic clock", startedMono)
	}
	if startedMono > now {
		return 0, receiptErr("start reading %d is in the future of the monotonic clock %d",
			startedMono, now)
	}
	return boundElapsed(now - startedMono)
}

// boundElapsed applies the per-receipt duration ceiling.
func boundElapsed(elapsed int64) (int64, error) {
	if elapsed > maxReceiptElapsedNanos {
		return 0, receiptLimit(ErrReceiptLimit,
			"elapsed %d ns exceeds the ceiling %d ns", elapsed, maxReceiptElapsedNanos)
	}
	return elapsed, nil
}

// ReceiptPayload returns the canonical signed encoding of a receipt. It is exported
// so a peer implementation in another language can be checked against this kernel's
// own bytes, which is the only way to find an encoding disagreement before it costs
// a settlement dispute.
//
// The encoding itself is abi.ReceiptPayload, because it is part of the wire contract
// and a module holding a receipt has to be able to recompute what the signature
// covers. The netstring-style length prefixes are what make it unambiguous: with
// bare separators, a receipt with trace "a" and route "b|c" would encode identically
// to one with trace "a|b" and route "c", and a forger could re-split fields across a
// boundary without breaking the signature.
func ReceiptPayload(r Receipt) []byte { return receiptPayload(r) }

// DecodeReceipt parses a receipt from its wire encoding. It does not verify it; a
// caller must pass the result to ReceiptVerify. Parsing and verifying are separate
// steps because a peer sending garbage and a peer sending a forgery are different
// events, and kslashing needs to tell them apart.
func DecodeReceipt(b []byte) (Receipt, error) {
	var r Receipt
	if err := json.Unmarshal(b, &r); err != nil {
		return Receipt{}, fmt.Errorf("kernel: cannot decode receipt: %w", err)
	}
	return r, nil
}

// ReceiptVerdict is abi.ReceiptVerdict: a module passes it to or receives it from the
// kernel, so the shape lives in the package the module compiles against.
type ReceiptVerdict = abi.ReceiptVerdict

// ReceiptVerify recomputes a receipt's canonical encoding and checks its signature
// against the sealed cluster roots. Requires receipt:verify, which every domain but
// untrusted holds: verifying is how a module protects itself from a peer's claim,
// and refusing it would leave modules trusting unsigned data instead.
//
// The verdict is only the verdict. There is no error return for "the signature did
// not match", because a caller that has to distinguish an error from a false is a
// caller that will eventually treat one as the other. A configuration that makes
// verification impossible - no roots at all, no parsable root - is returned as an
// error, so it cannot be read as "the peer cheated".
func ReceiptVerify(ctx SContext, r Receipt) (ReceiptVerdict, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return ReceiptVerdict{}, errForeignContext
	}
	if err := c.syscall(OpReceiptVerify); err != nil {
		return ReceiptVerdict{}, err
	}
	return verifyReceipt(r)
}

// verifyReceipt is the shared verification path, used by ReceiptVerify and by
// ReceiptOpen.
func verifyReceipt(r Receipt) (ReceiptVerdict, error) {
	digest := ReceiptDigest(r)
	structural := func(reason string) ReceiptVerdict {
		return ReceiptVerdict{Digest: digest, Reason: reason, Structural: true}
	}

	if r.Version != ReceiptVersion {
		return structural(fmt.Sprintf("unsupported receipt version %d, this kernel issues %d",
			r.Version, ReceiptVersion)), nil
	}
	if r.NodeID == "" {
		return structural("receipt names no issuing node"), nil
	}
	if r.Seq <= 0 {
		return structural(fmt.Sprintf("receipt sequence %d is not a valid sequence number", r.Seq)), nil
	}
	if r.TokensIn < 0 || r.TokensOut < 0 {
		return structural("receipt carries a negative token count"), nil
	}
	if r.ElapsedNanos < 0 {
		return structural("receipt carries a negative elapsed time"), nil
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return structural(fmt.Sprintf("signature is %d bytes, want %d",
			len(r.Signature), ed25519.SignatureSize)), nil
	}

	ok, keyID, err := verifyAgainstClusterRoots(receiptPayload(r), r.Signature)
	if err != nil {
		// Unverifiable is not invalid: the node cannot reach a conclusion, and
		// reporting one would either excuse a forgery or accuse an honest peer.
		return ReceiptVerdict{Digest: digest}, err
	}
	if !ok {
		return ReceiptVerdict{Digest: digest, Reason: "no sealed cluster root verifies this signature"}, nil
	}
	return ReceiptVerdict{Valid: true, Digest: digest, KeyID: keyID}, nil
}

// ReceiptOpen verifies a receipt and returns a per-pid handle to the verdict, along
// with the verdict itself. Requires receipt:verify.
//
// The handle exists so that a module holding a receipt is holding a kernel resource
// rather than a copy it can keep forever: it is bounded by the same handle ceiling as
// every other resource, it is per-pid so a verdict cannot be lent to another module,
// and it is reclaimed when the module is unloaded, panics or is killed. An invalid
// receipt is not opened, because tracking a forgery is how a node ends up replaying
// one.
func ReceiptOpen(ctx SContext, r Receipt) (FD, ReceiptVerdict, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, ReceiptVerdict{}, errForeignContext
	}
	if err := c.syscall(OpReceiptVerify); err != nil {
		return noFD, ReceiptVerdict{}, err
	}
	verdict, err := verifyReceipt(r)
	if err != nil {
		return noFD, verdict, err
	}
	if !verdict.Valid {
		return noFD, verdict, receiptErr("receipt %s is not valid: %s", verdict.Digest, verdict.Reason)
	}
	ref := &receiptRef{receipt: r, verdict: verdict}
	fd, err := install(c.pid, ref, "receipt")
	if err != nil {
		// The handle ceiling is reported as a receipt ceiling rather than passed
		// through raw, because from the caller's point of view the thing that
		// failed is "settle this request", and a caller that branches on
		// ErrReceiptLimit must not have to know which subsystem ran out of room.
		return noFD, verdict, &ReceiptError{
			Msg: fmt.Sprintf("cannot open a receipt handle for pid %d: %v", c.pid, err),
			Err: ErrReceiptLimit,
		}
	}
	return fd, verdict, nil
}

// receiptRef is a module-held reference to a verified receipt.
type receiptRef struct {
	closedFlag
	receipt Receipt
	verdict ReceiptVerdict
}

// Kind names the resource for the fd table and the console dump.
func (r *receiptRef) Kind() string { return "receipt" }

// Close releases the reference. A receipt is public data, so there is nothing to
// wipe; the once-only guard is what keeps a double close from looking like a
// successful second release.
func (r *receiptRef) Close() error {
	if !r.mark() {
		return errClosed
	}
	r.receipt = Receipt{}
	r.verdict = ReceiptVerdict{}
	return nil
}

// ReceiptHandle returns the receipt behind a handle this context opened. Requires
// receipt:verify. The handle must belong to this pid, which is the fd table's
// isolation property and the reason a verdict cannot be handed to another module.
func ReceiptHandle(ctx SContext, fd FD) (Receipt, ReceiptVerdict, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return Receipt{}, ReceiptVerdict{}, errForeignContext
	}
	if err := c.syscall(OpReceiptVerify); err != nil {
		return Receipt{}, ReceiptVerdict{}, err
	}
	entry, err := lookup(c.pid, fd)
	if err != nil {
		return Receipt{}, ReceiptVerdict{}, err
	}
	ref, ok := entry.res.(*receiptRef)
	if !ok {
		return Receipt{}, ReceiptVerdict{}, fmt.Errorf("kernel: fd %d is a %s, not a receipt", fd, entry.kind)
	}
	if ref.done() {
		return Receipt{}, ReceiptVerdict{}, errClosed
	}
	return ref.receipt, ref.verdict, nil
}

// SequenceGaps reports the missing sequence numbers in one node's receipts, between
// the lowest and the highest present. A gap is evidence: this kernel never skips a
// number, so a missing one was either suppressed in transit or never issued by a
// node that claimed it did. kslashing is the subsystem that acts on the answer; this
// function only computes it, because computing it wrong is how an honest peer gets
// slashed.
func SequenceGaps(nodeID string, in []Receipt) []int64 {
	var seqs []int64
	for _, r := range in {
		if r.NodeID == nodeID {
			seqs = append(seqs, r.Seq)
		}
	}
	if len(seqs) < 2 {
		return nil
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	var gaps []int64
	for i := 1; i < len(seqs); i++ {
		for want := seqs[i-1] + 1; want < seqs[i]; want++ {
			gaps = append(gaps, want)
		}
	}
	return gaps
}

// resetReceipts clears the ledger. Called only from resetKernel. The sequence cursor
// restarts at 1 for the new boot, which is correct because the node id is part of
// every receipt and a boot under a different trust root is a different issuer; a
// cursor that survived would either repeat a number under the new root or open a gap
// under the old one.
func resetReceipts() {
	kreceipts.mu.Lock()
	defer kreceipts.mu.Unlock()
	kreceipts.next = map[string]int64{}
	kreceipts.issued = 0
	kreceipts.refused = 0
}

// receiptPayload is abi.ReceiptPayload: the canonical encoding is part of the wire
// contract, so it lives with the type rather than beside the signer.
func receiptPayload(r Receipt) []byte { return abi.ReceiptPayload(r) }

// ReceiptDigest is a method-shaped call on the receipt's canonical encoding. It is a
// function rather than a method because Receipt now lives in abi and Go forbids methods
// on a foreign type; the encoding itself moved there too, so this is a two-line wrapper.
func ReceiptDigest(r Receipt) string { return sha256Sum(abi.ReceiptPayload(r)) }
