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

package mesh

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// These tests drive kslashing through the module-reachable surface for filing, because
// that is what the policy table grants: slash:report is held by the plugin domain, and a
// module may accuse. Adjudication is driven through the host handle, because no live
// context holds slash:adjudicate after boot.
//
// The receipts under test are constructed and signed here rather than issued by this
// kernel, and that is the point rather than a shortcut. Every fraud shape this subsystem
// exists to catch is committed by a REMOTE node holding its own legitimate key, so the
// evidence arrives already signed by a key that is in this cluster's root list. A
// receipt this kernel issued could not equivocate at all: its sequence cursor advances
// under one lock and never skips or repeats.

// slashCounter makes accused node ids unique per test, so a case filed by one test cannot
// be observed by another through the process-wide ledger.
var slashSeq = &slashSequence{}

type slashSequence struct {
	mu sync.Mutex
	n  int
}

func (c *slashSequence) next(prefix string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return prefix + "-" + harness.Itoa(c.n)
}

// slashPeer is a remote node whose key this cluster trusts: the hex public key that goes
// in ClusterRootKeys and the private key the test signs with.
type slashPeer struct {
	nodeID string
	pubHex string
	priv   ed25519.PrivateKey
}

// newSlashPeer generates one remote node identity.
func newSlashPeer(t *testing.T, nodeID string) slashPeer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return slashPeer{nodeID: nodeID, pubHex: hex.EncodeToString(pub), priv: priv}
}

// slashBoot starts a kernel whose cluster roots contain this node's own key and every
// remote peer the test named, so a receipt signed by any of them verifies here. That is
// the normal cluster configuration and the one a fraud proof is adjudicated under.
func slashBoot(t *testing.T, selfNode string, peers ...slashPeer) *kernel.Kernel {
	t.Helper()
	selfSeed, selfPub, _ := meshKeyPair(t)

	roots := make([]string, 0, len(peers)+1)
	roots = append(roots, selfPub)
	for _, p := range peers {
		roots = append(roots, p.pubHex)
	}

	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{
			NodeID:          selfNode,
			ClusterRootKeys: roots,
			SigningKeyPEM:   selfSeed,
		},
		Console: meshDiscard{},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// signReceipt builds one receipt signed by a remote peer's key.
//
// The signature covers kernel.ReceiptPayload, which is the exported canonical encoding,
// so a test cannot accidentally produce a receipt this kernel would verify for the wrong
// reason.
func signReceipt(p slashPeer, seq int64, prompt, completion string, tokensIn, tokensOut int64) kernel.Receipt {
	r := kernel.Receipt{
		Version: kernel.ReceiptVersion, NodeID: p.nodeID, Seq: seq,
		Route: "mesh-route", PromptHash: sha256Hex([]byte(prompt)),
		CompletionHash: sha256Hex([]byte(completion)),
		TokensIn:       tokensIn, TokensOut: tokensOut, KeyID: "peer-key",
	}
	r.Signature = ed25519.Sign(p.priv, kernel.ReceiptPayload(r))
	return r
}

// slashReporter loads a module that holds slash:report and keeps its context, so a test
// can file proofs as that module.
func slashReporter(t *testing.T, k *kernel.Kernel) *msProbe {
	t.Helper()
	_, mod := msLoad(t, k, nil, kernel.OpSlashReport)
	require.NotNil(t, mod.ctx)
	return mod
}

// ---------------------------------------------------------------------------
// The policy split: a module may accuse, nothing live may decide.

// TestSlashAdjudicateIsDeniedToEveryLiveContext is the governance invariant, asserted as
// runtime behaviour rather than as a table read.
//
// policy.go refuses slash:adjudicate to init for a stated reason: mesh governance must not
// be reachable from the same context that decides what code runs, and init holds
// module:load. It also refuses slash:report to init, because init does not serve traffic
// and so never sees a peer's receipts. Both refusals are pinned here.
func TestSlashAdjudicateIsDeniedToEveryLiveContext(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	id := kernel.SlashID("no-such-case")

	_, initErr := kernel.SlashAdjudicate(k.InitContext(), id)
	require.Error(t, initErr, "init must not hold slash:adjudicate")
	assert.True(t, kernel.IsDenied(initErr), "the refusal must be a policy denial: %v", initErr)

	mod := slashReporter(t, k)
	_, modErr := kernel.SlashAdjudicate(mod.ctx, id)
	require.Error(t, modErr, "a module must not hold slash:adjudicate")
	assert.True(t, kernel.IsDenied(modErr))

	// Init cannot report either. A test asserting the opposite would be asserting a
	// policy that does not exist.
	_, reportErr := kernel.SlashReport(k.InitContext(), kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: "anywhere",
		Receipts: []kernel.Receipt{{NodeID: "anywhere"}},
	})
	require.Error(t, reportErr, "init must not hold slash:report")
	assert.True(t, kernel.IsDenied(reportErr))

	assert.True(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpSlashReport),
		"a module may accuse")
	assert.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpSlashAdjudicate),
		"and may not decide")
	assert.False(t, kernel.Allowed(kernel.DomainInit, kernel.OpSlashAdjudicate),
		"mesh governance is not reachable from the context that loads modules")
}

// TestSlashReportIsDeniedWithoutTheGrant pins the denial counterpart from the other side:
// a module that did not declare slash:report cannot file, and the refusal is a policy
// denial rather than a shape complaint about the proof.
func TestSlashReportIsDeniedWithoutTheGrant(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	// No OpSlashReport in the manifest.
	_, mod := msLoad(t, k, nil)
	require.NotNil(t, mod.ctx)

	_, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: "somewhere",
		Receipts: []kernel.Receipt{{NodeID: "somewhere"}},
	})
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "want a policy denial, got %v", err)
}

// TestSlashRecordsRequiresReportNotAdjudicate pins that a reporter can see the outcome of
// its own accusation. Refusing that would leave a module re-filing the same proof to learn
// whether it was decided, which is worse than letting it read the ledger.
func TestSlashRecordsRequiresReportNotAdjudicate(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	mod := slashReporter(t, k)
	records, err := kernel.SlashRecords(mod.ctx, kernel.SlashFilter{})
	require.NoError(t, err, "a reporter must be able to read the ledger")
	assert.Empty(t, records, "an empty ledger reads as empty, not as an error")

	_, noGrant := msLoad(t, k, nil)
	_, err = kernel.SlashRecords(noGrant.ctx, kernel.SlashFilter{})
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
}

// ---------------------------------------------------------------------------
// The fraud shapes: what a peer with its own valid key can still forge.

// TestSlashEquivocationIsConfirmed is the load-bearing case, and the reason the subsystem
// exists. Two receipts from one node under one sequence number that disagree both verify,
// so nothing short of comparing them reveals the contradiction.
func TestSlashEquivocationIsConfirmed(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	// The same settlement slot, two different answers: one node was told 100 tokens
	// in and the other 900. Both signatures are valid.
	one := signReceipt(accused, 7, "shared prompt", "answer A", 100, 40)
	two := signReceipt(accused, 7, "shared prompt", "answer B", 900, 40)
	require.NotEqual(t, one.Digest(), two.Digest())

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEquivocation, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{one, two}, Note: "two answers for one request",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// Filed, not decided. Filing decides nothing, and a reporter cannot reach the
	// verdict itself.
	pending := filterRecords(kernel.SlashFilter{Verdict: kernel.SlashPending, NodeID: accused.nodeID})
	require.NotEmpty(t, pending, "the case must be pending after filing")

	rec, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashConfirmed, rec.Verdict)
	assert.True(t, rec.Finding.Established)
	assert.Equal(t, kernel.SlashEquivocation, rec.Finding.Kind)
	assert.Contains(t, rec.Finding.Reason, "two different receipts")
	assert.ElementsMatch(t, []string{one.Digest(), two.Digest()}, rec.Finding.Digests,
		"the finding must name the evidence it rests on")

	// A confirmed finding reaches the console as a fault, because the chain is what an
	// investigation reads later and the fault is what an operator sees now.
	assert.Equal(t, 1, countAudit(t, kernel.AuditSlash, "fraud proof adjudicated"),
		"the verdict must be on the chain, exactly once, before the caller sees it")

	stats := kernel.SlashStatsSnapshot()
	assert.GreaterOrEqual(t, stats.Confirmed, int64(1))
	assert.Zero(t, stats.Pending, "a decided case is no longer pending")
}

// TestSlashEquivocationOverIdenticalReceiptsIsUnproven pins that the kernel checks whether
// the two receipts actually differ. A reporter filing the same receipt twice gets an
// unproven verdict rather than a confirmed one, so filing is not self-proving.
func TestSlashEquivocationOverIdenticalReceiptsIsUnproven(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	one := signReceipt(accused, 3, "prompt", "completion", 10, 5)

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEquivocation, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{one, one},
	})
	require.NoError(t, err)

	rec, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashUnproven, rec.Verdict)
	assert.False(t, rec.Finding.Established)
	assert.Contains(t, rec.Finding.Reason, "identical")
}

// TestSlashEquivocationAcrossDifferentSeqsIsUnproven pins the other half of the
// definition. Two receipts under different sequence numbers are two settlements, and
// treating them as a contradiction would let any reporter slash an honest node by pairing
// two of its legitimate receipts.
func TestSlashEquivocationAcrossDifferentSeqsIsUnproven(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEquivocation, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{
			signReceipt(accused, 1, "a", "b", 10, 5),
			signReceipt(accused, 2, "c", "d", 20, 6),
		},
	})
	require.NoError(t, err)

	rec, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashUnproven, rec.Verdict)
	assert.Contains(t, rec.Finding.Reason, "different sequence numbers")
}

// TestSlashForgedEvidenceCannotAccuseAnHonestPeer is the control that stops the ledger
// being weaponized. A receipt whose signature does not verify is not evidence against the
// node it names, because anyone can construct one naming anyone.
func TestSlashForgedEvidenceCannotAccuseAnHonestPeer(t *testing.T) {
	harness.QuietConsole(t)
	honest := newSlashPeer(t, slashSeq.next("slash-honest"))
	k := slashBoot(t, slashSeq.next("slash-self"), honest)
	mod := slashReporter(t, k)

	one := signReceipt(honest, 5, "prompt", "answer A", 10, 5)
	two := signReceipt(honest, 5, "prompt", "answer B", 10, 5)

	// The attacker re-signs nothing: it just corrupts one receipt's signature, so the
	// pair still "contradicts" but one of them is not the honest node's.
	two.Signature[0] ^= 0xff

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEquivocation, NodeID: honest.nodeID,
		Receipts: []kernel.Receipt{one, two},
	})
	require.NoError(t, err, "filing is accepted; the adjudication is what rejects it")

	rec, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashUnproven, rec.Verdict,
		"a forgery must not confirm fraud against the node it names")
	assert.Contains(t, rec.Finding.Reason, "does not verify")

	assert.Zero(t, kernel.SlashStatsSnapshot().Confirmed,
		"no finding may be confirmed on unverifiable evidence")
}

// TestSlashConfigurationFailureIsAnErrorNotAVerdict pins receipt.go's rule, carried over
// verbatim: unverifiable is not invalid. A node with no cluster roots cannot reach a
// conclusion, and recording one would either excuse a forgery or accuse an honest peer.
func TestSlashConfigurationFailureIsAnErrorNotAVerdict(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))

	// Boot with no cluster roots at all, then file through a reporter.
	selfSeed, _, _ := meshKeyPair(t)
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{
			NodeID: slashSeq.next("slash-self"), SigningKeyPEM: selfSeed,
		},
		Console: meshDiscard{},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	mod := slashReporter(t, k)
	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 1, "", "x", 10, 5)},
	})
	require.NoError(t, err)

	_, err = k.AdjudicateSlash(id)
	require.Error(t, err, "no cluster roots is a configuration failure, not a verdict")
	assert.Contains(t, err.Error(), "no cluster verification keys")

	// The case stays pending rather than being recorded as unproven, so it can be
	// decided once the trust root is usable.
	pending := filterRecords(kernel.SlashFilter{Verdict: kernel.SlashPending, NodeID: accused.nodeID})
	assert.Len(t, pending, 1, "an undecidable case must stay pending")
	assert.Zero(t, kernel.SlashStatsSnapshot().Unproven)
	assert.Zero(t, countAudit(t, kernel.AuditSlash, "fraud proof adjudicated"),
		"a conclusion the node cannot reach must not go on the chain")
}

// TestSlashSequenceGapIsConfirmed pins the suppression shape, and the honest limit that
// comes with it: a gap proves the missing receipt was issued, because issuance is gap-free
// under one lock. It does not prove dishonest withholding rather than loss in transit.
func TestSlashSequenceGapIsConfirmed(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	// Receipts 4 and 7, so 5 and 6 are provably issued and absent.
	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashSequenceGap, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{
			signReceipt(accused, 4, "a", "b", 1, 1),
			signReceipt(accused, 7, "c", "d", 1, 1),
		},
	})
	require.NoError(t, err)

	rec, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashConfirmed, rec.Verdict)
	assert.Equal(t, []int64{5, 6}, rec.Finding.MissingSeqs,
		"the finding must name exactly which numbers are missing")
	assert.Contains(t, rec.Finding.Reason, "absent from its own contiguous numbering")

	// The gap computation is kreceipt's own, not a second implementation of it.
	assert.Equal(t, rec.Finding.MissingSeqs, kernel.SequenceGaps(accused.nodeID, []kernel.Receipt{
		signReceipt(accused, 4, "a", "b", 1, 1),
		signReceipt(accused, 7, "c", "d", 1, 1),
	}))
}

// TestSlashSequenceGapNeedsBothSides pins that a contiguous run is not a gap. Without this
// a reporter could slash an honest node by filing any two adjacent receipts.
func TestSlashSequenceGapNeedsBothSides(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashSequenceGap, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{
			signReceipt(accused, 1, "a", "b", 1, 1),
			signReceipt(accused, 2, "c", "d", 1, 1),
		},
	})
	require.NoError(t, err)

	rec, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashUnproven, rec.Verdict)
	assert.Contains(t, rec.Finding.Reason, "contiguous")

	// And a single receipt has nothing to be a hole between, so it is refused at
	// filing rather than adjudicated into a verdict.
	_, err = kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashSequenceGap, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 9, "a", "b", 1, 1)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both sides of the gap")
}

// TestSlashEmptyContentIsConfirmed pins the shape whose contradiction is internal to one
// signed receipt: settling prompt tokens against a prompt that was not there.
func TestSlashEmptyContentIsConfirmed(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 2, "", "an answer", 500, 20)},
	})
	require.NoError(t, err)

	rec, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashConfirmed, rec.Verdict)
	assert.Contains(t, rec.Finding.Reason, "empty prompt")
	assert.Contains(t, rec.Finding.Reason, "500")
}

// TestSlashEmptyContentIsUnprovenWhenContentIsPresent pins the negative: real content is
// not fraud, and the digest of empty input is computed in the kernel rather than compared
// against a literal that could drift.
func TestSlashEmptyContentIsUnprovenWhenContentIsPresent(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 2, "a real prompt", "a real answer", 500, 20)},
	})
	require.NoError(t, err)

	rec, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashUnproven, rec.Verdict)
	assert.Contains(t, rec.Finding.Reason, "no supplied receipt settles tokens against empty content")

	// The empty digest the kernel compares against is sha256 of nothing, which is what
	// makes the check drift-proof.
	empty := sha256.Sum256(nil)
	assert.Equal(t, hex.EncodeToString(empty[:]), signReceipt(accused, 2, "", "x", 1, 1).PromptHash)
}

// ---------------------------------------------------------------------------
// Ledger invariants: identity, corroboration, finality, ceilings.

// TestSlashProofIdentityIgnoresTheReporterAndTheOrder pins that two reporters filing the
// same evidence converge on one case. The id is derived from the kind, the accused node
// and the SORTED receipt digests, and deliberately not from the note or the pid, so
// presenting the same pair in the other order is the same accusation.
func TestSlashProofIdentityIgnoresTheReporterAndTheOrder(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)

	one := signReceipt(accused, 11, "p", "a", 1, 1)
	two := signReceipt(accused, 11, "p", "b", 2, 2)

	first := slashReporter(t, k)
	idA, err := kernel.SlashReport(first.ctx, kernel.SlashProof{
		Kind: kernel.SlashEquivocation, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{one, two}, Note: "first reporter",
	})
	require.NoError(t, err)

	// Same evidence, opposite order, a different note, and no reporter overlap.
	second := slashReporter(t, k)
	idB, err := kernel.SlashReport(second.ctx, kernel.SlashProof{
		Kind: kernel.SlashEquivocation, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{two, one}, Note: "second reporter",
	})
	require.NoError(t, err)

	assert.Equal(t, idA, idB, "the same evidence must be the same case")

	recs := filterRecords(kernel.SlashFilter{NodeID: accused.nodeID})
	require.Len(t, recs, 1, "one case, not two records an operator must reconcile")
	assert.ElementsMatch(t, []kernel.PID{first.ctx.PID(), second.ctx.PID()}, recs[0].Reporters,
		"both reporters must be recorded on the one case")
	assert.GreaterOrEqual(t, kernel.SlashStatsSnapshot().Corroborated, int64(1))
}

// TestSlashDuplicateFilingByOneReporterIsRefused pins that a module cannot inflate its own
// corroboration by filing the same proof repeatedly.
func TestSlashDuplicateFilingByOneReporterIsRefused(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	proof := kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 4, "", "x", 9, 1)},
	}
	id, err := kernel.SlashReport(mod.ctx, proof)
	require.NoError(t, err)

	_, err = kernel.SlashReport(mod.ctx, proof)
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrSlashDuplicate), "want ErrSlashDuplicate, got %v", err)

	recs := filterRecords(kernel.SlashFilter{NodeID: accused.nodeID})
	require.Len(t, recs, 1)
	assert.Len(t, recs[0].Reporters, 1, "a duplicate filing must not add the reporter twice")
	assert.Equal(t, id, recs[0].ID)
}

// TestSlashVerdictIsFinalWithinABoot pins that re-deciding the same evidence is refused.
// Without it a caller could retry until it liked the answer, and the ledger would stop
// being a record of what the kernel concluded.
func TestSlashVerdictIsFinalWithinABoot(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 6, "", "x", 3, 1)},
	})
	require.NoError(t, err)

	first, err := k.AdjudicateSlash(id)
	require.NoError(t, err)
	assert.Equal(t, kernel.SlashConfirmed, first.Verdict)

	_, err = k.AdjudicateSlash(id)
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrSlashDecided), "want ErrSlashDecided, got %v", err)

	_, err = k.AdjudicateSlash(kernel.SlashID("never-filed"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrSlashUnknown), "want ErrSlashUnknown, got %v", err)

	assert.Equal(t, int64(1), kernel.SlashStatsSnapshot().Confirmed,
		"a refused re-adjudication must not double-count the finding")
}

// TestSlashProofShapeIsRefusedBeforeAnythingIsStored pins that a malformed proof is
// refused at filing and records no case. Each of these is a shape complaint about the
// accusation, so none of them is an escalation against the named node.
func TestSlashProofShapeIsRefusedBeforeAnythingIsStored(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	good := signReceipt(accused, 1, "p", "c", 1, 1)
	other := newSlashPeer(t, slashSeq.next("slash-other"))

	cases := []struct {
		name   string
		proof  kernel.SlashProof
		reason string
	}{
		{"unknown kind", kernel.SlashProof{
			Kind: "smuggle", NodeID: accused.nodeID, Receipts: []kernel.Receipt{good},
		}, "unknown fraud proof kind"},
		{"no accused node", kernel.SlashProof{
			Kind: kernel.SlashEmptyContent, Receipts: []kernel.Receipt{good},
		}, "must name the node it accuses"},
		{"node id with a newline", kernel.SlashProof{
			Kind: kernel.SlashEmptyContent, NodeID: "evil\nnode",
			Receipts: []kernel.Receipt{good},
		}, "control or non-ASCII"},
		{"no receipts", kernel.SlashProof{
			Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		}, "at least one receipt"},
		{"receipt names another node", kernel.SlashProof{
			Kind: kernel.SlashEmptyContent, NodeID: other.nodeID,
			Receipts: []kernel.Receipt{good},
		}, "not the accused"},
		{"equivocation with one receipt", kernel.SlashProof{
			Kind: kernel.SlashEquivocation, NodeID: accused.nodeID,
			Receipts: []kernel.Receipt{good},
		}, "two contradictory receipts"},
		{"note with a line break", kernel.SlashProof{
			Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
			Receipts: []kernel.Receipt{good}, Note: "forged\nsecond line",
		}, "must not contain a line break"},
	}

	before := len(filterRecords(kernel.SlashFilter{}))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kernel.SlashReport(mod.ctx, tc.proof)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.reason)
			assert.False(t, kernel.IsDenied(err),
				"a shape refusal is not a policy denial and must not read as one")
		})
	}

	assert.Equal(t, before, len(filterRecords(kernel.SlashFilter{})),
		"a refused proof must not open a case")
	assert.GreaterOrEqual(t, kernel.SlashStatsSnapshot().Refused, int64(len(cases)))

	// A shape refusal accuses nobody, so it must not escalate against the named node.
	for _, e := range auditEntries(t, kernel.AuditEscalation) {
		assert.NotContains(t, e.Msg, "fraud proof")
	}
}

// TestSlashPendingCeilingBoundsOneReporter pins the flood control. Each filing is cheap,
// so without a per-reporter bound one module could fill the pending queue and starve every
// other reporter invisibly.
func TestSlashPendingCeilingBoundsOneReporter(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	const bound = 32 // maxSlashPendingPerReporter
	for i := range bound {
		_, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
			Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
			Receipts: []kernel.Receipt{signReceipt(accused, int64(i+1), "", "x", 1, 1)},
		})
		require.NoError(t, err, "filing %d must succeed", i)
	}

	_, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 999, "", "x", 1, 1)},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrSlashLimit), "want ErrSlashLimit, got %v", err)

	// A second reporter is not affected by the first one's queue, which is the point of
	// bounding it per reporter rather than globally.
	other := slashReporter(t, k)
	_, err = kernel.SlashReport(other.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 5000, "", "x", 1, 1)},
	})
	require.NoError(t, err, "one reporter's queue must not starve another")

	// Adjudicating one of the first reporter's cases frees its slot.
	recs := filterRecords(kernel.SlashFilter{Verdict: kernel.SlashPending, NodeID: accused.nodeID})
	require.NotEmpty(t, recs)
	_, err = k.AdjudicateSlash(recs[0].ID)
	require.NoError(t, err)

	_, err = kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 1000, "", "x", 1, 1)},
	})
	assert.NoError(t, err, "a decided case must release its reporter's pending slot")
}

// TestSlashLedgerTrimsInOneStep protects against the ledger bug returning. Trimming exactly
// to the bound would reallocate and copy every record under the lock on each filing past
// the ceiling, which is O(n) per filing forever; the batch drop to seven eighths is what
// makes it amortized constant.
func TestSlashLedgerTrimsInOneStep(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	const bound = 4096 // maxSlashRecords
	const batch = bound / 8

	baseEvicted := kernel.SlashStatsSnapshot().RecordEvicted
	base := len(kernel.SlashLedger())

	// Filling the ledger requires deciding each case as it is filed, and that is not a
	// test artifact but the two ceilings composing: maxSlashPendingPerReporter bounds how
	// many UNDECIDED proofs one reporter may hold, so a single reporter can never reach
	// the ledger bound on its own. Adjudicating frees the slot, which is what lets the
	// ledger grow to its own ceiling.
	for i := range bound - base + 1 {
		id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
			Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
			Receipts: []kernel.Receipt{signReceipt(accused, int64(i+100000), "", "x", 1, 1)},
		})
		require.NoError(t, err)
		_, err = k.AdjudicateSlash(id)
		require.NoError(t, err)
	}

	stats := kernel.SlashStatsSnapshot()
	assert.Greater(t, stats.RecordEvicted, baseEvicted, "the trim must be counted, not silent")
	assert.LessOrEqual(t, len(kernel.SlashLedger()), bound)
	// A one-record-per-insert trim would leave evicted at exactly the overflow. A batch
	// trim evicts at least a full batch at once, which is the observable difference
	// between the two implementations.
	assert.GreaterOrEqual(t, stats.RecordEvicted-baseEvicted, int64(batch),
		"eviction must happen in batches of seven eighths, not one record at a time")
}

// TestSlashingResetsAcrossRestart pins the reset ordering slot. kreceipt's sequence cursor
// restarts at 1 for a new boot, so a ledger carried across a restart would hold
// accusations about a numbering that no longer means the same thing.
func TestSlashingResetsAcrossRestart(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 1, "", "x", 1, 1)},
	})
	require.NoError(t, err)
	require.NotEmpty(t, id)
	require.NoError(t, k.Shutdown())

	k2 := slashBoot(t, slashSeq.next("slash-self2"), accused)
	assert.Empty(t, kernel.SlashLedger(), "a case must not survive a restart")

	stats := kernel.SlashStatsSnapshot()
	assert.Zero(t, stats.Pending)
	assert.Zero(t, stats.Filed)
	assert.Zero(t, stats.Confirmed)
	assert.Zero(t, stats.Refused)
	assert.Zero(t, stats.RecordEvicted)

	_, err = k2.AdjudicateSlash(id)
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrSlashUnknown),
		"the previous boot's case id must be unknown to the new one: %v", err)
}

// TestSlashAdjudicateIsRefusedAfterShutdown pins that the host handle stops working when the
// kernel stops, so a decision cannot be recorded against a ledger that has been cleared.
func TestSlashAdjudicateIsRefusedAfterShutdown(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	id, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 1, "", "x", 1, 1)},
	})
	require.NoError(t, err)
	require.NoError(t, k.Shutdown())

	_, err = k.AdjudicateSlash(id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shut down")
}

// TestSlashKindsAreAClosedSet pins that the claim set is enumerable and that an unknown
// kind is refused rather than defaulted. A default branch here is where an unspecified
// accusation becomes an accepted one.
func TestSlashKindsAreAClosedSet(t *testing.T) {
	kinds := kernel.SlashKinds()
	assert.ElementsMatch(t, []kernel.SlashKind{
		kernel.SlashEquivocation, kernel.SlashSequenceGap, kernel.SlashEmptyContent,
	}, kinds)
	assert.Len(t, kinds, 3, "the claim set is closed and enumerable")
	assert.Equal(t, kinds[0], kernel.SlashEmptyContent, "the list is sorted")
}

// TestSlashFilterNarrowsTheLedger pins the query surface a reporter and the dump use.
func TestSlashFilterNarrowsTheLedger(t *testing.T) {
	harness.QuietConsole(t)
	one := newSlashPeer(t, slashSeq.next("slash-peer"))
	two := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), one, two)
	mod := slashReporter(t, k)

	idOne, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: one.nodeID,
		Receipts: []kernel.Receipt{signReceipt(one, 1, "", "x", 1, 1)},
	})
	require.NoError(t, err)
	_, err = kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEquivocation, NodeID: two.nodeID,
		Receipts: []kernel.Receipt{
			signReceipt(two, 1, "p", "a", 1, 1), signReceipt(two, 1, "p", "b", 2, 2),
		},
	})
	require.NoError(t, err)

	_, err = k.AdjudicateSlash(idOne)
	require.NoError(t, err)

	byNode := filterRecords(kernel.SlashFilter{NodeID: one.nodeID})
	require.Len(t, byNode, 1)
	assert.Equal(t, kernel.SlashEmptyContent, byNode[0].Kind)

	byVerdict := filterRecords(kernel.SlashFilter{Verdict: kernel.SlashConfirmed})
	for _, r := range byVerdict {
		assert.Equal(t, kernel.SlashConfirmed, r.Verdict)
		assert.True(t, r.Finding.Established)
		assert.Greater(t, r.DecidedMono, int64(0))
	}

	byKind := filterRecords(kernel.SlashFilter{Kind: kernel.SlashEquivocation, NodeID: two.nodeID})
	require.Len(t, byKind, 1)
	assert.Equal(t, kernel.SlashPending, byKind[0].Verdict)

	limited := filterRecords(kernel.SlashFilter{Limit: 1})
	assert.Len(t, limited, 1)
}

// TestSlashRecordsHandOutCopies pins that a caller cannot rewrite a case through the
// result, which is the same property ProcTable and MeterQuery have.
func TestSlashRecordsHandOutCopies(t *testing.T) {
	harness.QuietConsole(t)
	accused := newSlashPeer(t, slashSeq.next("slash-peer"))
	k := slashBoot(t, slashSeq.next("slash-self"), accused)
	mod := slashReporter(t, k)

	_, err := kernel.SlashReport(mod.ctx, kernel.SlashProof{
		Kind: kernel.SlashEmptyContent, NodeID: accused.nodeID,
		Receipts: []kernel.Receipt{signReceipt(accused, 1, "", "x", 1, 1)},
	})
	require.NoError(t, err)

	recs := filterRecords(kernel.SlashFilter{NodeID: accused.nodeID})
	require.Len(t, recs, 1)
	recs[0].Verdict = kernel.SlashConfirmed
	recs[0].Reporters = append(recs[0].Reporters, 99999)

	again := filterRecords(kernel.SlashFilter{NodeID: accused.nodeID})
	require.Len(t, again, 1)
	assert.Equal(t, kernel.SlashPending, again[0].Verdict, "a caller must not be able to write a verdict")
	assert.NotContains(t, again[0].Reporters, kernel.PID(99999))
}

// ---------------------------------------------------------------------------
// Local helper.

// filterRecords reads the ledger through the exported read-only surface and narrows it the
// way SlashFilter describes. SlashLedger is the unfiltered read the console dump uses;
// the kernel's own filtered query is exercised through the syscall in
// TestSlashFilterNarrowsTheLedger.
func filterRecords(f kernel.SlashFilter) []kernel.SlashRecord {
	var out []kernel.SlashRecord
	for _, r := range kernel.SlashLedger() {
		if f.Kind != "" && r.Kind != f.Kind {
			continue
		}
		if f.NodeID != "" && r.NodeID != f.NodeID {
			continue
		}
		if f.Verdict != "" && r.Verdict != f.Verdict {
			continue
		}
		if f.Since > 0 && r.FiledMono < f.Since {
			continue
		}
		out = append(out, r)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}
