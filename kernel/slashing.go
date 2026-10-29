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

// kslashing: fraud proofs against peer settlement receipts (subsystem: kslashing, the
// analogue of a slashing condition in a proof-of-stake mesh).
//
// SYSCALL WIRING FOR THE INTEGRATOR.
//
// The exported functions below are the implementation; paste this block into
// kernel/context.go to expose them as syscalls.
//
// 1. Add the group to the SContext interface's group list, next to SyscallReceipt:
//
//	SyscallSlashing
//
// 2. Add the group interface and the methods:
//
//	// SyscallSlashing is the mesh-governance half of the syscall surface. Filing a
//	// proof and adjudicating one are separate operations with separate grants, and
//	// no context holds both: a reporter cannot write its own verdict.
//	type SyscallSlashing interface {
//	    // SyscallSlashReport files a fraud proof. Requires slash:report, which the
//	    // plugin domain holds and init does not.
//	    SyscallSlashReport(p SlashProof) (SlashID, error)
//	    // SyscallSlashAdjudicate decides one filed proof. Requires slash:adjudicate,
//	    // which no live context holds.
//	    SyscallSlashAdjudicate(id SlashID) (SlashRecord, error)
//	    // SyscallSlashRecords lists decided and pending proofs. Requires
//	    // slash:report.
//	    SyscallSlashRecords(f SlashFilter) ([]SlashRecord, error)
//	}
//
//	func (c *sContext) SyscallSlashReport(p SlashProof) (SlashID, error) { return SlashReport(c, p) }
//	func (c *sContext) SyscallSlashAdjudicate(id SlashID) (SlashRecord, error) {
//	    return SlashAdjudicate(c, id)
//	}
//	func (c *sContext) SyscallSlashRecords(f SlashFilter) ([]SlashRecord, error) {
//	    return SlashRecords(c, f)
//	}
//
// 3. Add resetSlashing() to resetKernel() in kernel/kernel.go, in the "Identity and
//    evidence" block immediately after kaudit.reset(): the ledger is evidence about
//    receipts, and receipts are reset in the secrets block below, so a restarted
//    kernel must not carry forward accusations against a sequence numbering that has
//    restarted at 1.
//
// 4. Optional, and dump.go is the integrator's call: a "--- slashing ---" section
//    reading SlashStatsSnapshot() and a bounded prefix of SlashLedger(), modelled on
//    the receipts and secrets sections.
//
// POLICY NOTE the integrator must read before wiring slash:adjudicate to any context.
//
// kernel/policy.go grants slash:report to the plugin domain alone, and slash:adjudicate
// to the kernel domain alone. Two facts follow, and both are deliberate:
//
//   - DomainInit holds NEITHER. Its row in policy.go states the reason for refusing
//     adjudication: mesh governance must not be reachable from the same context that
//     decides what code runs, and init holds module:load. Init also cannot report,
//     because init does not serve traffic and therefore never sees a peer's receipts.
//     Both refusals are preserved here and are asserted by tests/mesh.
//   - After boot no live context holds slash:adjudicate, because the kernel domain
//     belongs to the pid 0 root context that boot.go retires the instant init exists.
//
// So the syscall exists and runs the full prologue - the op is the named gate and
// widening it must be a policy change rather than a code change - and the reachable
// path is the host handle (*Kernel).AdjudicateSlash, following Kernel.IssueReceipt and
// Kernel.InstallSecret.
//
// WHY THE HOST IS THE AUTHORITY, stated precisely because "the host is privileged" is
// not a reason that survives review: adjudication decides a proof by verifying ed25519
// signatures against BootTrustRoot.ClusterRootKeys. Those keys are the ones the host
// sealed into the trust root at boot, and kboot makes them unchangeable afterwards. The
// host can adjudicate not because it outranks init but because the verification keys
// the decision rests on are the keys it supplied. An attacker who compromised init
// could not substitute a friendlier root list - the seal refuses the write - so handing
// the decision to the host adds no trust the deployment did not already place there.
//
// If the owner wants a live context to adjudicate, the change is to add
// OpSlashAdjudicate to a domain row in kernel/policy.go, and the row it must NOT be
// added to is DomainInit. That is a trust-root change needing owner approval. It is
// reported here rather than made.

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
)

// The guarantee this file provides is that a claim of fraud against a peer is decided
// by recomputation rather than by trust in the accuser, and that the decision is on the
// audit chain before the caller sees it.
//
// Every check here re-derives its conclusion from the receipts themselves: signatures
// are verified against the sealed cluster roots, sequence numbers are compared, content
// digests are compared, and the contradiction a proof asserts is confirmed or refuted
// rather than believed. A reporter that files an equivocation claim over two identical
// receipts gets an unproven verdict, not a confirmed one, because the kernel checks
// whether the two actually differ.
//
// WHAT THIS FILE DELIBERATELY DOES NOT CHECK, and why.
//
// Fraud that the issuance path already makes impossible is not re-litigated here,
// because a check that can never fire is not a control and reading it as one is how a
// reviewer stops looking for the holes that are open:
//
//   - A module cannot forge a receipt at all. crypto:sign and receipt:issue are absent
//     from both the plugin and the init ceilings, and the policy comment above the
//     DomainInit row says exactly this: if init could sign, anything that compromised
//     init could mint settlement receipts.
//   - A receipt's node id, sequence number, key id and issue timestamps are
//     kernel-assigned, not issuer-supplied, and all of them are inside the signature.
//     A peer cannot re-sign another node's receipt without that node's key.
//   - This kernel never skips a sequence number: the cursor advances under one lock.
//   - Token claims are bounded by the issuing kernel's own metering through
//     validateTokens, so a node cannot settle more than it metered.
//
// WHAT A PEER HOLDING ITS OWN VALID KEY CAN STILL DO, which is what this file exists
// to catch. The peer's key is legitimate and every signature verifies, so none of the
// above stops it:
//
//   - Equivocation. It signs two different receipts under the same node id and sequence
//     number and gives one to each of two nodes. Both verify. The cluster now holds two
//     contradictory settlement facts about the same work, and nothing short of
//     comparing them reveals it. This is the strongest finding and the reason the
//     subsystem exists.
//   - Suppression. It issues sequence 3 and never releases it, so a node holding 2 and 4
//     can prove 3 exists but cannot see it. The honest limit is stated on the kind: a
//     gap proves the receipt was ISSUED, because issuance is gap-free; it does not prove
//     the peer is withholding it dishonestly rather than having lost it in transit. It
//     is recorded as a weaker finding than equivocation for exactly that reason.
//   - Settling work that did not happen. It signs a receipt claiming prompt tokens
//     against a prompt hash that is the digest of empty input. Its own metering cannot
//     catch this because the metering is also its own; the contradiction is internal to
//     the single signed receipt, which is what makes it checkable here.
//
// What this is not. It is not a punishment mechanism: a confirmed finding is evidence
// and a record, and what a cluster does with it - dropping a peer, refusing its traffic,
// alerting an operator - belongs to the host and to kpeer's session lifecycle, not to a
// kernel that has no opinion about consequences. It is also not a court of appeal: an
// unproven verdict means the proof did not establish the claim, not that the accused
// node is honest. And it is not an address-space control, for the same reason every
// other subsystem here is not one.

// SlashID identifies one filed proof. It is the digest of the proof's canonical
// encoding, so two reporters filing identical evidence converge on one case rather than
// opening two.
type SlashID string

// SlashKind names what a proof claims. The set is closed and an unknown kind is
// refused rather than defaulted, because a default branch is where an unspecified
// accusation becomes an accepted one.
type SlashKind string

const (
	// SlashEquivocation claims two receipts from one node under one sequence number
	// that disagree. This is the strongest finding: both signatures are valid, so
	// nothing but comparing them reveals the contradiction.
	SlashEquivocation SlashKind = "equivocation"
	// SlashSequenceGap claims a node's sequence has a hole. The honest limit is part
	// of the definition: a gap proves the missing receipt was ISSUED, because
	// issuance is gap-free under one lock. It does not prove dishonest withholding
	// rather than loss in transit, so this kind is recorded as weaker evidence than
	// equivocation and an operator should weight it accordingly.
	SlashSequenceGap SlashKind = "sequence-gap"
	// SlashEmptyContent claims a receipt settles prompt tokens against a prompt whose
	// hash is the digest of empty input. The contradiction is internal to one signed
	// receipt, which is what makes it checkable without any cross-node state.
	SlashEmptyContent SlashKind = "empty-content"
)

// SlashKinds lists the claim kinds the kernel will adjudicate, sorted.
func SlashKinds() []SlashKind {
	out := []SlashKind{SlashEquivocation, SlashSequenceGap, SlashEmptyContent}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func knownSlashKind(k SlashKind) bool {
	for _, want := range SlashKinds() {
		if k == want {
			return true
		}
	}
	return false
}

// SlashVerdict is the state of one filed proof.
type SlashVerdict string

const (
	// SlashPending is a proof that has been filed and not yet decided.
	SlashPending SlashVerdict = "pending"
	// SlashConfirmed means the kernel recomputed the claim from the receipts and it
	// holds. This is the verdict an operator acts on.
	SlashConfirmed SlashVerdict = "confirmed"
	// SlashUnproven means the claim did not hold. It is NOT a statement that the
	// accused node is honest: the receipts may have been insufficient, or the
	// reporter may have mischaracterized them.
	SlashUnproven SlashVerdict = "unproven"
)

// SlashProof is one accusation. The reporter supplies the receipts and the kind of
// claim; everything else - whether the receipts verify, whether they actually
// contradict, who is accused - is recomputed by the kernel.
//
// That division is the control. A reporter that could set the verdict would be writing
// its own evidence, and a reporter that could name the accused node without supplying a
// receipt signed by it could accuse anyone.
type SlashProof struct {
	// Kind is the claim. It must be one of the closed set.
	Kind SlashKind `json:"kind"`
	// NodeID is the node being accused. Every receipt in the proof must carry this
	// node id, and every receipt's signature must verify, so the accusation cannot
	// be pointed at a node that signed nothing here.
	NodeID string `json:"node_id"`
	// Receipts are the evidence. At least one is required, and for equivocation
	// exactly two are compared.
	Receipts []Receipt `json:"receipts"`
	// Note is an optional operator-readable statement from the reporter. It is
	// length-bounded and line-break-free because it is copied into audit fields.
	Note string `json:"note,omitempty"`
}

// SlashFinding is what the kernel concluded. It is separate from the proof because the
// proof is the accusation and the finding is the decision, and conflating them is how a
// reporter's characterization ends up being read as a verdict.
type SlashFinding struct {
	// Kind echoes the claim that was decided.
	Kind SlashKind `json:"kind"`
	// Established is true when the recomputation confirmed the claim.
	Established bool `json:"established"`
	// Reason explains the conclusion either way. An unproven finding carries the
	// reason it failed, which is what tells an operator whether the accusation was
	// wrong or merely unsupported.
	Reason string `json:"reason"`
	// Digests names the receipts the decision rests on, so a dispute can be
	// re-examined without the original proof object.
	Digests []string `json:"digests,omitempty"`
	// MissingSeqs lists the sequence numbers a gap finding proved were issued. Empty
	// for every other kind.
	MissingSeqs []int64 `json:"missing_seqs,omitempty"`
}

// SlashRecord is one case in the ledger.
type SlashRecord struct {
	ID      SlashID      `json:"id"`
	Kind    SlashKind    `json:"kind"`
	NodeID  string       `json:"node_id"`
	Verdict SlashVerdict `json:"verdict"`
	// Reporters are the pids that filed this proof, in the order they arrived. It is
	// a list rather than a single pid because two independent reporters filing the
	// same evidence is materially stronger than one, and collapsing them would throw
	// that away.
	Reporters []PID `json:"reporters"`
	// FiledMono and DecidedMono are monotonic readings.
	FiledMono   int64 `json:"filed_mono"`
	DecidedMono int64 `json:"decided_mono,omitempty"`
	// Finding is the kernel's conclusion, present once decided.
	Finding SlashFinding `json:"finding"`
	// Note echoes the first reporter's note, for an operator reading the ledger.
	Note string `json:"note,omitempty"`
}

// SlashFilter selects ledger records. Zero values mean no constraint on that field.
type SlashFilter struct {
	Kind    SlashKind
	NodeID  string
	Verdict SlashVerdict
	// Since returns only records filed at or after this Mono() reading.
	Since int64
	Limit int
}

// SlashStats are the ledger counters.
//
// Refused is a single counter for every kind of refusal, on the same reasoning
// keyring.go gives for making an out-of-scope alias and an unknown alias
// indistinguishable: a reporter that could tell which of its proofs were rejected for
// shape and which for duplication could probe the ledger's contents.
type SlashStats struct {
	Pending   int   `json:"pending"`
	Confirmed int64 `json:"confirmed"`
	Unproven  int64 `json:"unproven"`
	Filed     int64 `json:"filed"`
	// Corroborated counts proofs a second reporter added itself to.
	Corroborated  int64 `json:"corroborated"`
	Refused       int64 `json:"refused"`
	Records       int   `json:"records"`
	RecordEvicted int64 `json:"record_evicted"`
	MaxRecords    int   `json:"max_records"`
}

// SlashError reports a refused slashing operation. It is a distinct type so a caller
// can tell "the kernel will not adjudicate this" from "the kernel could not", and so a
// ceiling is not mistaken for a policy denial.
type SlashError struct {
	Msg string
	Err error
}

func (e *SlashError) Error() string {
	if e.Err == nil {
		return "kernel: slashing refused: " + e.Msg
	}
	return "kernel: slashing refused: " + e.Msg + ": " + e.Err.Error()
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *SlashError) Unwrap() error { return e.Err }

// Slashing sentinels.
var (
	// ErrSlashLimit is the sentinel for every ledger ceiling.
	ErrSlashLimit = errors.New("kernel: slashing limit reached")
	// ErrSlashUnknown names a proof id that is not in the ledger.
	ErrSlashUnknown = errors.New("kernel: unknown fraud proof")
	// ErrSlashDuplicate means this reporter already filed this exact proof.
	ErrSlashDuplicate = errors.New("kernel: fraud proof already filed by this reporter")
	// ErrSlashDecided means the proof was already adjudicated. A verdict is final
	// within a boot: re-deciding the same evidence would let a caller retry until it
	// liked the answer.
	ErrSlashDecided = errors.New("kernel: fraud proof already decided")
)

func slashErr(format string, a ...any) error {
	return &SlashError{Msg: fmt.Sprintf(format, a...)}
}

func slashLimit(err error, format string, a ...any) error {
	return &SlashError{Msg: fmt.Sprintf(format, a...), Err: err}
}

// Ledger ceilings. They are package constants rather than BootLimits fields because
// adding a field to the sealed trust root is a change owned by kboot, and a subsystem
// must not widen the struct it reads.
const (
	// maxSlashProofReceipts bounds one proof's evidence. A proof carrying ten
	// thousand receipts is a memory pin, and no finding in the closed set needs more
	// than a handful.
	maxSlashProofReceipts = 64
	// maxSlashRecords bounds the retained ledger, trimmed in batches of seven
	// eighths like kmeter and ktrace rather than one record per insert.
	maxSlashRecords = 4096
	// maxSlashReportersPerRecord bounds one case's corroboration list.
	maxSlashReportersPerRecord = 16
	// maxSlashPendingPerReporter bounds how many undecided proofs one pid may have
	// open. Without it a module could fill the pending queue and starve every other
	// reporter, and the flood would be invisible because each individual filing is
	// cheap.
	maxSlashPendingPerReporter = 32
	// maxSlashNoteLen bounds the reporter's note, which is copied into audit fields.
	maxSlashNoteLen = 512
	// maxSlashNodeIDLen bounds an accused node's identifier. It is a separate
	// constant from kpeer's rather than a shared one: the two subsystems are
	// independently reviewable, and sharing a bound would make one subsystem's
	// ceiling change silently alter the other's.
	maxSlashNodeIDLen = 128
)

// MaxSlashRecords reports the ledger ceiling.
func MaxSlashRecords() int { return maxSlashRecords }

// slashLedger owns the case table, the per-reporter pending counts and the counters.
type slashLedger struct {
	mu sync.Mutex

	byID  map[SlashID]*SlashRecord
	order []SlashID
	// pending counts undecided proofs per reporter. It exists so one module cannot
	// fill the queue and starve every other reporter: each filing is cheap, so the
	// flood is invisible without a bound.
	pending map[PID]int

	filed        int64
	corroborated int64
	confirmed    int64
	unproven     int64
	refused      int64
	evicted      int64
}

var kslashing = &slashLedger{
	byID:    map[SlashID]*SlashRecord{},
	pending: map[PID]int{},
}

// slashProofID is the identity of a claim.
//
// It is the digest of the kind, the accused node and the SORTED digests of the
// evidence - and deliberately not of the reporter's note or pid. Two reporters filing
// the same evidence with different notes therefore converge on one case and corroborate
// each other, rather than opening two records that an operator has to notice are the
// same. Sorting the digests is what makes the identity order-independent: presenting
// the same two receipts in the other order is the same accusation.
//
// The encoding is the netstring form receipt.go uses for its canonical payload, for the
// same reason: with bare separators, a node id of "a" plus a digest of "b|c" would
// encode identically to a node id of "a|b" plus a digest of "c", and two distinct
// claims would collide.
func slashProofID(kind SlashKind, nodeID string, receipts []Receipt) SlashID {
	digests := make([]string, 0, len(receipts))
	for _, r := range receipts {
		digests = append(digests, r.Digest())
	}
	sort.Strings(digests)

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
	field("kind", string(kind))
	field("node_id", nodeID)
	field("digests", strconv.Itoa(len(digests)))
	for _, d := range digests {
		field("digest", d)
	}
	return SlashID(sha256Sum(b.Bytes()))
}

// slashNodeID validates an accused node's identifier. The rune filter is the log-forgery
// control keyring.go and kpeer both apply: this value is copied into audit fields and
// console lines verbatim, so an identifier carrying a newline could forge a log line.
func slashNodeID(id string) error {
	if id == "" {
		return slashErr("a fraud proof must name the node it accuses")
	}
	if len(id) > maxSlashNodeIDLen {
		return slashErr("accused node id of %d bytes exceeds the ceiling %d", len(id), maxSlashNodeIDLen)
	}
	for _, r := range id {
		if r <= 0x20 || r >= 0x7f {
			return slashErr("accused node id %q contains a control or non-ASCII character", id)
		}
	}
	return nil
}

// slashNote validates a reporter's note, which is operator prose rather than an
// identifier. It is bounded and may not carry a line break, which is the same rule
// receipt.go applies to its own labels; it is not held to the identifier rune filter
// because a note that cannot contain a space is useless for its only purpose.
func slashNote(note string) error {
	if len(note) > maxSlashNoteLen {
		return slashErr("reporter note of %d bytes exceeds the ceiling %d", len(note), maxSlashNoteLen)
	}
	if bytes.ContainsAny([]byte(note), "\n\r") {
		return slashErr("reporter note must not contain a line break")
	}
	return nil
}

// validateProof checks a proof's shape before anything derived from it is stored or
// recorded. Every refusal here is a shape refusal, so none of them is an accusation
// against the named node and none of them writes an escalation.
func validateProof(p SlashProof) error {
	if !knownSlashKind(p.Kind) {
		return slashErr("unknown fraud proof kind %q", p.Kind)
	}
	if err := slashNodeID(p.NodeID); err != nil {
		return err
	}
	if err := slashNote(p.Note); err != nil {
		return err
	}
	if len(p.Receipts) == 0 {
		return slashErr("a fraud proof must carry at least one receipt")
	}
	if len(p.Receipts) > maxSlashProofReceipts {
		return slashLimit(ErrSlashLimit,
			"a fraud proof carries %d receipts, above the ceiling %d", len(p.Receipts), maxSlashProofReceipts)
	}
	for i := range p.Receipts {
		if p.Receipts[i].NodeID != p.NodeID {
			return slashErr("receipt %d names node %q, not the accused %q",
				i, p.Receipts[i].NodeID, p.NodeID)
		}
	}
	switch p.Kind {
	case SlashEquivocation:
		if len(p.Receipts) < 2 {
			return slashErr("an equivocation proof must carry the two contradictory receipts")
		}
	case SlashSequenceGap:
		if len(p.Receipts) < 2 {
			// A gap is a hole between two sequence numbers. One receipt has
			// nothing to be a hole between, so the claim cannot be established
			// even in principle.
			return slashErr("a sequence-gap proof must carry receipts on both sides of the gap")
		}
	}
	return nil
}

// SlashReport files a fraud proof and returns the case id. Requires slash:report, which
// the plugin domain holds and init does not.
//
// Filing decides nothing. A proof is stored as pending and the accusation is recorded as
// an accusation; the verdict comes from adjudication, which no reporter can reach. That
// separation is the whole governance rule: a module may accuse, and the party that
// decides is the one holding the cluster roots.
func SlashReport(ctx SContext, p SlashProof) (SlashID, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return "", errForeignContext
	}
	if err := c.syscall(OpSlashReport); err != nil {
		return "", err
	}
	return slashReport(c, p)
}

func slashReport(ctx *sContext, p SlashProof) (SlashID, error) {
	if err := validateProof(p); err != nil {
		kslashing.mu.Lock()
		kslashing.refused++
		kslashing.mu.Unlock()
		fault(ctx, "fraud proof refused", map[string]any{
			"kind": string(p.Kind), "node_id": p.NodeID, "reason": err.Error(),
		})
		return "", err
	}

	id := slashProofID(p.Kind, p.NodeID, p.Receipts)

	kslashing.mu.Lock()
	if kslashing.pending[ctx.pid] >= maxSlashPendingPerReporter {
		kslashing.refused++
		kslashing.mu.Unlock()
		fault(ctx, "pending fraud proof ceiling reached", map[string]any{
			"pid": ctx.pid, "max_pending_per_reporter": maxSlashPendingPerReporter,
		})
		return "", slashLimit(ErrSlashLimit,
			"pid %d has the maximum of %d undecided fraud proofs", ctx.pid, maxSlashPendingPerReporter)
	}

	rec, exists := kslashing.byID[id]
	switch {
	case exists && containsPID(rec.Reporters, ctx.pid):
		kslashing.refused++
		kslashing.mu.Unlock()
		return "", &SlashError{
			Msg: fmt.Sprintf("pid %d already filed fraud proof %q", ctx.pid, id),
			Err: ErrSlashDuplicate,
		}

	case exists && len(rec.Reporters) >= maxSlashReportersPerRecord:
		// The corroboration list is bounded so one case cannot grow without limit.
		// The filing still succeeds as a duplicate-of-record: the case exists and is
		// known, so the reporter's evidence is not lost, it is simply not appended.
		kslashing.mu.Unlock()
		return id, nil

	case exists:
		rec.Reporters = append(rec.Reporters, ctx.pid)
		kslashing.corroborated++
		if rec.Verdict == SlashPending {
			kslashing.pending[ctx.pid]++
		}
		kslashing.filed++
		kslashing.mu.Unlock()

		kaudit.record(AuditSlash, ctx, "fraud proof corroborated", map[string]any{
			"id": string(id), "kind": string(p.Kind), "node_id": p.NodeID,
			"verdict": string(rec.Verdict), "reporters": len(rec.Reporters),
		})
		return id, nil

	default:
		kslashing.byID[id] = &SlashRecord{
			ID: id, Kind: p.Kind, NodeID: p.NodeID, Verdict: SlashPending,
			Reporters: []PID{ctx.pid}, FiledMono: mono(), Note: p.Note,
			// The evidence is kept so adjudication recomputes from the receipts
			// themselves rather than from a summary the reporter wrote.
			Finding: SlashFinding{Kind: p.Kind, Digests: receiptDigests(p.Receipts)},
		}
		kslashing.order = append(kslashing.order, id)
		kslashing.pending[ctx.pid]++
		kslashing.filed++
		// Trim after the insert, the way kmeter's Record does. Trimming before it
		// cannot work: at exactly the bound the ledger is still within it, so the
		// trim is a no-op and the insert takes the ledger one past its ceiling on
		// every filing.
		dropped := kslashing.trimLocked()
		kslashing.mu.Unlock()

		// The evicted cases' evidence is dropped outside the ledger lock. Holding
		// pendingProofs.mu under kslashing.mu would fix a lock order across two
		// locks for no benefit, and every other path here takes them one at a time.
		for _, gone := range dropped {
			dropPendingProof(gone)
		}

		// The evidence is stored after the ledger is unlocked, because it lives
		// behind its own lock and taking that one while holding this one would fix a
		// lock order across two subsystems for no benefit.
		//
		// Only the first filing stores it. A corroborating report is the same proof by
		// construction - the case id is derived from the kind, the accused node and the
		// sorted receipt digests - so re-storing would replace identical evidence and
		// would let a second reporter swap the receipts a case is decided on.
		storePendingProof(id, p)
	}

	kaudit.record(AuditSlash, ctx, "fraud proof filed", map[string]any{
		"id": string(id), "kind": string(p.Kind), "node_id": p.NodeID,
		"receipts": len(p.Receipts), "verdict": string(SlashPending),
	})
	return id, nil
}

// receiptDigests names the evidence, for the record and for a dispute that has to be
// re-examined without the original proof object.
func receiptDigests(rs []Receipt) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Digest())
	}
	return out
}

func containsPID(list []PID, want PID) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}

// SlashAdjudicate decides one filed proof. Requires slash:adjudicate, which no live
// context holds after boot; see the policy note at the top of this file.
func SlashAdjudicate(ctx SContext, id SlashID) (SlashRecord, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return SlashRecord{}, errForeignContext
	}
	if err := c.syscall(OpSlashAdjudicate); err != nil {
		return SlashRecord{}, err
	}
	return slashAdjudicate(c, id)
}

// AdjudicateSlash decides one filed proof from the host process.
//
// It performs no policy check because no live context could pass one, and the host is the
// authority for the reason stated in the policy note rather than because it is
// privileged: the decision rests on verifying signatures against the cluster roots, and
// the host is the party that sealed those roots into the trust root at boot. It cannot
// substitute a friendlier root list afterwards, because kboot refuses the write.
func (k *Kernel) AdjudicateSlash(id SlashID) (SlashRecord, error) {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return SlashRecord{}, errors.New("kernel: already shut down")
	}
	return slashAdjudicate(k.initCtx, id)
}

func slashAdjudicate(ctx *sContext, id SlashID) (SlashRecord, error) {
	kslashing.mu.Lock()
	rec, ok := kslashing.byID[id]
	if !ok {
		kslashing.refused++
		kslashing.mu.Unlock()
		return SlashRecord{}, &SlashError{
			Msg: fmt.Sprintf("no fraud proof %q has been filed", id), Err: ErrSlashUnknown,
		}
	}
	if rec.Verdict != SlashPending {
		kslashing.mu.Unlock()
		return SlashRecord{}, &SlashError{
			Msg: fmt.Sprintf("fraud proof %q was already decided as %s", id, rec.Verdict),
			Err: ErrSlashDecided,
		}
	}
	kslashing.mu.Unlock()

	// The receipts were stored at filing time and the ledger does not hand out live
	// pointers to them, so the decision is recomputed from the evidence rather than
	// from anything the reporter asserted about it.
	proof := pendingProofFor(id)
	if proof == nil {
		return SlashRecord{}, slashErr("fraud proof %q lost its evidence", id)
	}

	finding, err := decideProof(*proof)
	if err != nil {
		// A configuration failure is an error and NOT an unproven verdict. Recording
		// a conclusion this node cannot reach would either excuse a forgery or accuse
		// an honest peer, and only the second one gets noticed. The case stays pending
		// so it can be decided once the trust root is usable.
		fault(ctx, "cannot adjudicate fraud proof", map[string]any{
			"id": string(id), "kind": string(proof.Kind), "node_id": proof.NodeID,
			"error": err.Error(),
		})
		return SlashRecord{}, err
	}

	kslashing.mu.Lock()
	rec.Verdict = SlashUnproven
	if finding.Established {
		rec.Verdict = SlashConfirmed
		kslashing.confirmed++
	} else {
		kslashing.unproven++
	}
	rec.DecidedMono = mono()
	rec.Finding = finding
	// The evidence is dropped with the decision. A verdict is final within a boot, so
	// nothing will read the receipts again, and keeping them would pin every filed
	// proof's content for the lifetime of the process.
	dropPendingProof(id)
	out := *rec
	out.Reporters = append([]PID(nil), rec.Reporters...)
	for _, pid := range rec.Reporters {
		if kslashing.pending[pid] > 0 {
			kslashing.pending[pid]--
		}
	}
	kslashing.mu.Unlock()

	// A confirmed finding is fraud this kernel proved, so it reaches the console as a
	// fault as well as the chain: the chain is what an investigation reads, the fault
	// is what an operator sees now. An unproven finding is recorded without a fault,
	// because an accusation that did not hold is not an incident.
	if finding.Established {
		fault(ctx, "fraud proof confirmed", map[string]any{
			"id": string(id), "kind": string(finding.Kind), "node_id": out.NodeID,
			"reason": finding.Reason, "reporters": len(out.Reporters),
		})
	}
	kaudit.record(AuditSlash, ctx, "fraud proof adjudicated", map[string]any{
		"id": string(id), "kind": string(finding.Kind), "node_id": out.NodeID,
		"verdict": string(out.Verdict), "reason": finding.Reason,
		"reporters": len(out.Reporters),
	})
	return out, nil
}

// pendingProofs holds the evidence for undecided cases.
//
// It is a separate map from the ledger records rather than a field on SlashRecord
// because the record is handed out to callers: storing the receipts inside it would
// either hand a caller the evidence slice to retain and mutate, or force a deep copy of
// every receipt on every read of the ledger. Keeping the evidence private and copying
// it out only at adjudication is both cheaper and safer.
var pendingProofs = struct {
	mu sync.Mutex
	m  map[SlashID]SlashProof
}{m: map[SlashID]SlashProof{}}

func storePendingProof(id SlashID, p SlashProof) {
	pendingProofs.mu.Lock()
	pendingProofs.m[id] = p
	pendingProofs.mu.Unlock()
}

func pendingProofFor(id SlashID) *SlashProof {
	pendingProofs.mu.Lock()
	defer pendingProofs.mu.Unlock()
	p, ok := pendingProofs.m[id]
	if !ok {
		return nil
	}
	out := p
	out.Receipts = append([]Receipt(nil), p.Receipts...)
	return &out
}

func dropPendingProof(id SlashID) {
	pendingProofs.mu.Lock()
	delete(pendingProofs.m, id)
	pendingProofs.mu.Unlock()
}

// decideProof recomputes one claim from its receipts.
//
// Every branch verifies signatures first. A receipt whose signature does not verify is
// not evidence against the node it names, because anyone can construct an unsigned or
// wrongly-signed receipt naming any node they like; treating it as evidence would let a
// reporter accuse an honest peer with a forgery of its own making. So a proof whose
// receipts do not verify is unproven, and the reason says which digest failed.
func decideProof(p SlashProof) (SlashFinding, error) {
	digests := receiptDigests(p.Receipts)

	verdicts := make([]ReceiptVerdict, len(p.Receipts))
	for i := range p.Receipts {
		v, err := verifyReceipt(p.Receipts[i])
		if err != nil {
			return SlashFinding{}, err
		}
		verdicts[i] = v
		if !v.Valid {
			return SlashFinding{
				Kind: p.Kind, Established: false, Digests: digests,
				Reason: fmt.Sprintf("receipt %s does not verify: %s", v.Digest, v.Reason),
			}, nil
		}
	}

	switch p.Kind {
	case SlashEquivocation:
		return decideEquivocation(p, digests), nil
	case SlashSequenceGap:
		return decideSequenceGap(p, digests), nil
	case SlashEmptyContent:
		return decideEmptyContent(p, digests), nil
	}
	// validateProof already refused an unknown kind, so this is unreachable through
	// the syscall. It is written as a refusal rather than a default that establishes
	// nothing, because a default branch here would be the place an unspecified
	// accusation becomes an accepted one.
	return SlashFinding{
		Kind: p.Kind, Digests: digests,
		Reason: fmt.Sprintf("fraud proof kind %q is not adjudicable", p.Kind),
	}, nil
}

// decideEquivocation confirms or refutes a contradiction claim.
//
// Equivocation requires three things to hold at once: the receipts share one sequence
// number, and at least two of them differ. Same sequence is what makes them claims about
// the same settlement slot; differing content is what makes them contradictory. Two
// receipts under different sequence numbers are two settlements and prove nothing, and
// two identical receipts under one number are one settlement filed twice.
func decideEquivocation(p SlashProof, digests []string) SlashFinding {
	seq := p.Receipts[0].Seq
	for _, r := range p.Receipts {
		if r.Seq != seq {
			return SlashFinding{
				Kind: SlashEquivocation, Digests: digests,
				Reason: fmt.Sprintf("the receipts carry different sequence numbers (%d and %d), so they are not claims about the same settlement",
					seq, r.Seq),
			}
		}
	}

	// The first receipt whose content differs from the first receipt's establishes the
	// contradiction. Digests are compared rather than fields, because the digest covers
	// the whole canonical payload: any difference in what was settled shows up there,
	// and comparing fields would mean this file has to agree with receipt.go about which
	// fields matter.
	base := p.Receipts[0]
	for _, r := range p.Receipts[1:] {
		if r.Digest() != base.Digest() {
			return SlashFinding{
				Kind: SlashEquivocation, Established: true, Digests: digests,
				Reason: fmt.Sprintf("node %q signed two different receipts under sequence %d", p.NodeID, seq),
			}
		}
	}
	return SlashFinding{
		Kind: SlashEquivocation, Digests: digests,
		Reason: fmt.Sprintf("every receipt is identical, so node %q signed one settlement, not two", p.NodeID),
	}
}

// decideSequenceGap confirms or refutes a suppression claim, using kreceipt's own
// gap computation rather than a second implementation of it.
//
// The finding records which numbers are missing and states the honest limit: issuance is
// gap-free under one lock, so a hole proves the receipt was issued by that node. It does
// not prove the node is withholding it dishonestly rather than having lost it in transit,
// which is why this kind is weaker evidence than equivocation.
func decideSequenceGap(p SlashProof, digests []string) SlashFinding {
	gaps := SequenceGaps(p.NodeID, p.Receipts)
	if len(gaps) == 0 {
		return SlashFinding{
			Kind: SlashSequenceGap, Digests: digests,
			Reason: "the supplied receipts are contiguous, so no sequence number is missing between them",
		}
	}
	return SlashFinding{
		Kind: SlashSequenceGap, Established: true, Digests: digests, MissingSeqs: gaps,
		Reason: fmt.Sprintf("node %q issued %d sequence number(s) that are absent from its own contiguous numbering",
			p.NodeID, len(gaps)),
	}
}

// decideEmptyContent confirms or refutes a claim that a node settled work it did not do.
//
// The contradiction is internal to one signed receipt, which is what makes it checkable
// without any cross-node state: a receipt claiming prompt tokens against a prompt hash
// that is the digest of empty input is asserting it metered a prompt that was not there.
// The digest of empty input is computed rather than written as a literal, so this file
// cannot drift from the hash function the receipts use.
func decideEmptyContent(p SlashProof, digests []string) SlashFinding {
	empty := sha256Sum(nil)
	for _, r := range p.Receipts {
		switch {
		case r.TokensIn > 0 && r.PromptHash == empty:
			return SlashFinding{
				Kind: SlashEmptyContent, Established: true, Digests: digests,
				Reason: fmt.Sprintf("receipt %s settles %d prompt tokens against an empty prompt",
					r.Digest(), r.TokensIn),
			}
		case r.TokensOut > 0 && r.CompletionHash == empty:
			return SlashFinding{
				Kind: SlashEmptyContent, Established: true, Digests: digests,
				Reason: fmt.Sprintf("receipt %s settles %d completion tokens against an empty completion",
					r.Digest(), r.TokensOut),
			}
		}
	}
	return SlashFinding{
		Kind: SlashEmptyContent, Digests: digests,
		Reason: "no supplied receipt settles tokens against empty content",
	}
}

// SlashRecords lists ledger entries matching a filter, oldest first. Requires
// slash:report, so a reporter can see the state of its own accusations.
//
// It requires report rather than adjudicate on purpose: a module that can accuse must be
// able to see whether the accusation was decided, and refusing that would leave it
// re-filing the same proof to learn the outcome.
func SlashRecords(ctx SContext, f SlashFilter) ([]SlashRecord, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if err := c.syscall(OpSlashReport); err != nil {
		return nil, err
	}
	return slashQuery(f), nil
}

// slashQuery returns copies, so a caller cannot rewrite a case through the result.
func slashQuery(f SlashFilter) []SlashRecord {
	kslashing.mu.Lock()
	defer kslashing.mu.Unlock()

	var out []SlashRecord
	for _, id := range kslashing.order {
		rec, ok := kslashing.byID[id]
		if !ok {
			continue
		}
		if f.Kind != "" && rec.Kind != f.Kind {
			continue
		}
		if f.NodeID != "" && rec.NodeID != f.NodeID {
			continue
		}
		if f.Verdict != "" && rec.Verdict != f.Verdict {
			continue
		}
		if f.Since > 0 && rec.FiledMono < f.Since {
			continue
		}
		cp := *rec
		cp.Reporters = append([]PID(nil), rec.Reporters...)
		cp.Finding.Digests = append([]string(nil), rec.Finding.Digests...)
		cp.Finding.MissingSeqs = append([]int64(nil), rec.Finding.MissingSeqs...)
		out = append(out, cp)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

// SlashLedger returns the whole ledger in filing order, for the console dump and for the
// host. It takes no context and performs no check, which puts it in the family of
// ProcTable, RouteTable and SecretInventory: read-only observability that grants no
// privilege and hands out copies.
func SlashLedger() []SlashRecord { return slashQuery(SlashFilter{}) }

// SlashStatsSnapshot returns the ledger counters. MaxRecords is reported so an operator
// reading the dump can tell whether a refusal means the ledger is full or the bound is
// too small.
func SlashStatsSnapshot() SlashStats {
	kslashing.mu.Lock()
	defer kslashing.mu.Unlock()

	pending := 0
	for _, id := range kslashing.order {
		if rec, ok := kslashing.byID[id]; ok && rec.Verdict == SlashPending {
			pending++
		}
	}
	return SlashStats{
		Pending: pending, Confirmed: kslashing.confirmed, Unproven: kslashing.unproven,
		Filed: kslashing.filed, Corroborated: kslashing.corroborated, Refused: kslashing.refused,
		Records: len(kslashing.order), RecordEvicted: kslashing.evicted, MaxRecords: maxSlashRecords,
	}
}

// trimLocked keeps the ledger at its bound. Caller holds kslashing.mu.
//
// It trims in batches rather than one record at a time, for the reason kmeter's
// trimLocked states: trimming exactly to the bound would reallocate and copy the whole
// ledger under the lock on every filing past the ceiling, which is O(n) per filing
// forever. Dropping back to seven eighths makes the cost amortized constant.
//
// The oldest records go, and a pending count belonging to an evicted undecided case is
// released with it. Leaving the count behind would slowly freeze a reporter out of the
// ledger for cases nobody can ever decide again.
//
// It returns the ids of the evicted cases whose evidence the caller must drop. Taking
// pendingProofs.mu here instead would nest one lock inside the other, and every other
// path in this file takes them one at a time.
func (l *slashLedger) trimLocked() []SlashID {
	if len(l.order) <= maxSlashRecords {
		return nil
	}
	keep := maxSlashRecords - maxSlashRecords/8
	if len(l.order) <= keep {
		return nil
	}
	over := len(l.order) - keep

	dropped := make([]SlashID, 0, over)
	for _, id := range l.order[:over] {
		if rec, ok := l.byID[id]; ok {
			if rec.Verdict == SlashPending {
				for _, pid := range rec.Reporters {
					if l.pending[pid] > 0 {
						l.pending[pid]--
					}
				}
				dropped = append(dropped, id)
			}
			delete(l.byID, id)
		}
	}
	l.evicted += int64(over)
	l.order = append([]SlashID(nil), l.order[over:]...)
	return dropped
}

// resetSlashing clears the ledger. Called only from resetKernel.
//
// The sequence cursor in kreceipt restarts at 1 for a new boot, so a ledger carried
// across a restart would hold accusations about a numbering that no longer means the
// same thing. Clearing is what makes a restarted kernel indistinguishable from a
// first-booted one.
func resetSlashing() {
	kslashing.mu.Lock()
	ids := append([]SlashID(nil), kslashing.order...)
	kslashing.byID = map[SlashID]*SlashRecord{}
	kslashing.order = nil
	kslashing.pending = map[PID]int{}
	kslashing.filed, kslashing.corroborated = 0, 0
	kslashing.confirmed, kslashing.unproven, kslashing.refused = 0, 0, 0
	kslashing.evicted = 0
	kslashing.mu.Unlock()

	pendingProofs.mu.Lock()
	for _, id := range ids {
		delete(pendingProofs.m, id)
	}
	// Nothing was ever decided in the new boot, so the whole evidence map goes.
	pendingProofs.m = map[SlashID]SlashProof{}
	pendingProofs.mu.Unlock()
}

// SyscallSlashing is the mesh-governance half of the syscall surface.
//
// Filing and deciding are separate operations with separate grants and no context holds
// both, which is the property that makes the ledger trustworthy: a reporter cannot write
// its own verdict, and the party that writes verdicts does not serve traffic and
// therefore never sees a peer's receipts.
type SyscallSlashing interface {
	// SyscallSlashReport files a fraud proof. Requires slash:report.
	SyscallSlashReport(p SlashProof) (SlashID, error)
	// SyscallSlashAdjudicate decides one filed proof. Requires slash:adjudicate,
	// which no live context holds.
	SyscallSlashAdjudicate(id SlashID) (SlashRecord, error)
	// SyscallSlashRecords lists decided and pending proofs. Requires slash:report.
	SyscallSlashRecords(f SlashFilter) ([]SlashRecord, error)
}

func (c *sContext) SyscallSlashReport(p SlashProof) (SlashID, error) { return SlashReport(c, p) }
func (c *sContext) SyscallSlashAdjudicate(id SlashID) (SlashRecord, error) {
	return SlashAdjudicate(c, id)
}
func (c *sContext) SyscallSlashRecords(f SlashFilter) ([]SlashRecord, error) {
	return SlashRecords(c, f)
}
