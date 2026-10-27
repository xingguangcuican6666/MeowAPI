package kernel_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// These tests drive kreceipt through the module-reachable surface for verification
// and through the host-side issue path for minting, because that is exactly how the
// policy table splits the two: receipt:verify is nearly universal, receipt:issue is
// held by no live context.

// rcptDiscard swallows console output for tests that do not assert on it.
type rcptDiscard struct{}

func (rcptDiscard) Write(p []byte) (int, error) { return len(p), nil }

// rcptKeyPair makes a fresh ed25519 key pair encoded the way an operator would
// supply one in the trust root: a hex seed for signing, a hex public key as the
// cluster root.
func rcptKeyPair(t *testing.T) (seedHex string, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub)
}

// rcptTrustRoot is a trust root whose cluster root list contains this node's own
// public key, so receipts issued here verify here. That is the normal single-node
// configuration and the one a peer list is built from.
func rcptTrustRoot(t *testing.T) kernel.BootTrustRoot {
	t.Helper()
	seed, pub := rcptKeyPair(t)
	return kernel.BootTrustRoot{
		NodeID:          "rcpt-node",
		ClusterRootKeys: []string{pub},
		SigningKeyPEM:   seed,
	}
}

// rcptBoot starts a kernel with the given trust root.
func rcptBoot(t *testing.T, tr kernel.BootTrustRoot) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: tr, Console: rcptDiscard{}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// rcptManifest declares exactly the operations a settlement-aware module needs.
func rcptManifest(name string, ops ...kernel.Op) kernel.Manifest {
	return kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1, Require: ops,
	}
}

// rcptReporter is a module that reports token usage, because a receipt cross-checks
// its counts against what the pid actually emitted. A module that reported nothing
// cannot be the subject of a receipt at all, which is the point of the check.
type rcptReporter struct {
	in, out int64
	ctx     kernel.SContext
}

func (m *rcptReporter) OnLoad(ctx kernel.SContext) error {
	m.ctx = ctx
	if m.in > 0 {
		if err := ctx.SyscallUsageEmit(kernel.UsageFact{
			Kind: kernel.UsageTokensIn, Quantity: m.in, Label: "rcpt",
		}); err != nil {
			return err
		}
	}
	if m.out > 0 {
		if err := ctx.SyscallUsageEmit(kernel.UsageFact{
			Kind: kernel.UsageTokensOut, Quantity: m.out, Label: "rcpt",
		}); err != nil {
			return err
		}
	}
	return nil
}
func (m *rcptReporter) OnUnload() error { return nil }

// rcptLoad registers and loads a module.
func rcptLoad(t *testing.T, k *kernel.Kernel, m kernel.Module, mf kernel.Manifest) kernel.PID {
	t.Helper()
	kernel.Register(mf.Name, func() (kernel.Module, error) { return m, nil })
	t.Cleanup(func() { kernel.Unregister(mf.Name) })
	pid, err := k.Load(mf)
	require.NoError(t, err)
	return pid
}

// rcptSpec is a minimal well-formed settlement request for a module that reported
// the given counts.
func rcptSpec(pid kernel.PID, in, out int64) kernel.ReceiptSpec {
	return kernel.ReceiptSpec{
		PID: pid, Route: "rcpt/route", Trace: "trace-1",
		Prompt: []byte("the prompt"), Completion: []byte("the completion"),
		TokensIn: in, TokensOut: out, StartedMono: 1,
	}
}

// rcptSha256Hex renders a digest the way the kernel does, so a test can supply a
// precomputed hash for the streamed-completion path.
func rcptSha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestReceiptIssueSignsAndVerifies is the end-to-end path across both halves of the
// subsystem: the host mints, a module verifies. Every field the kernel owns is
// asserted, because a field the kernel does not own is a field a module can lie
// about.
func TestReceiptIssueSignsAndVerifies(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 120, out: 40}
	pid := rcptLoad(t, k, reporter,
		rcptManifest("rcptworker", kernel.OpUsageEmit, kernel.OpReceiptVerify))

	r, err := k.IssueReceipt(rcptSpec(pid, 120, 40))
	require.NoError(t, err)

	assert.Equal(t, kernel.ReceiptVersion, r.Version)
	assert.Equal(t, "rcpt-node", r.NodeID)
	assert.Equal(t, int64(1), r.Seq, "the first receipt of a boot is sequence 1")
	assert.Equal(t, pid, r.PID)
	assert.Len(t, r.PromptHash, 64)
	assert.Len(t, r.CompletionHash, 64)
	assert.NotEqual(t, r.PromptHash, r.CompletionHash)
	assert.Equal(t, rcptSha256Hex([]byte("the prompt")), r.PromptHash)
	assert.Equal(t, int64(120), r.TokensIn)
	assert.Equal(t, int64(40), r.TokensOut)
	assert.Positive(t, r.ElapsedNanos, "elapsed time comes from mono(), not from the caller")
	assert.Positive(t, r.IssuedMono)
	assert.Positive(t, r.IssuedWall)
	assert.NotEmpty(t, r.KeyID)
	assert.Len(t, r.Signature, 64)

	// The module verifies what was settled about it, and gets a verdict rather than
	// a bool, so it can act on the reason.
	verdict, err := reporter.ctx.SyscallReceiptVerify(r)
	require.NoError(t, err)
	assert.True(t, verdict.Valid)
	assert.NotEmpty(t, verdict.KeyID)
	assert.Empty(t, verdict.Reason)
	assert.False(t, verdict.Structural)
	assert.Equal(t, r.Digest(), verdict.Digest)
}

// TestReceiptIssueDeniedToModules is the load-bearing denial: no module can mint a
// settlement receipt, and neither can init.
//
// The manifest cannot even request receipt:issue - validation refuses an operation
// the plugin domain can never hold - so the module here loads with no declaration and
// is stopped by the domain ceiling. Both refusals are the policy table working, at
// two different layers.
func TestReceiptIssueDeniedToModules(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	// First: a manifest asking for receipt:issue never loads at all.
	kernel.Register("rcptforger", func() (kernel.Module, error) { return &rcptReporter{}, nil })
	t.Cleanup(func() { kernel.Unregister("rcptforger") })
	_, err := k.Load(rcptManifest("rcptforger", kernel.OpReceiptIssue))
	require.Error(t, err, "a manifest requesting receipt:issue must be rejected before load")
	assert.Contains(t, err.Error(), "not grantable")

	// Second: a loaded module that calls the syscall anyway is denied by the
	// domain ceiling.
	reporter := &rcptReporter{in: 10, out: 10}
	pid := rcptLoad(t, k, reporter, rcptManifest("rcptcaller", kernel.OpUsageEmit))

	_, moduleErr := reporter.ctx.SyscallReceiptIssue(rcptSpec(pid, 10, 10))
	_, initErr := k.InitContext().SyscallReceiptIssue(rcptSpec(pid, 10, 10))

	require.Error(t, moduleErr)
	assert.True(t, kernel.IsDenied(moduleErr), "a module must not be able to issue: %v", moduleErr)
	assert.Contains(t, moduleErr.Error(), "receipt:issue")
	require.Error(t, initErr)
	assert.True(t, kernel.IsDenied(initErr), "init must not be able to issue either: %v", initErr)

	counted := 0
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial}) {
		if e.Fields["op"] == "receipt:issue" {
			counted++
		}
	}
	assert.GreaterOrEqual(t, counted, 2, "both refusals must reach the audit chain")
}

// TestReceiptVerifyDeniedWithoutDeclaration is the denial on the verify side. The
// grant is near-universal, so the refusal has to be tested explicitly or it will
// quietly become unconditional.
func TestReceiptVerifyDeniedWithoutDeclaration(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 5, out: 5}
	pid := rcptLoad(t, k, reporter, rcptManifest("rcptnoverify", kernel.OpUsageEmit))

	r, err := k.IssueReceipt(rcptSpec(pid, 5, 5))
	require.NoError(t, err)

	_, err = reporter.ctx.SyscallReceiptVerify(r)
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.Contains(t, err.Error(), "receipt:verify")

	found := false
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial}) {
		if e.Fields["op"] == "receipt:verify" {
			found = true
		}
	}
	assert.True(t, found)
}

// TestReceiptTamperingIsDetected proves the signature covers every signed field.
// Each mutation is one an attacker would try: inflate the tokens, swap a content
// hash, move the receipt to another node, replay it under a different sequence.
func TestReceiptTamperingIsDetected(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 100, out: 100}
	pid := rcptLoad(t, k, reporter,
		rcptManifest("rcpttamper", kernel.OpUsageEmit, kernel.OpReceiptVerify))
	r, err := k.IssueReceipt(rcptSpec(pid, 100, 100))
	require.NoError(t, err)

	base, err := reporter.ctx.SyscallReceiptVerify(r)
	require.NoError(t, err)
	require.True(t, base.Valid)

	cases := []struct {
		name string
		mut  func(*kernel.Receipt)
	}{
		{"inflate tokens out", func(x *kernel.Receipt) { x.TokensOut = 100000 }},
		{"inflate tokens in", func(x *kernel.Receipt) { x.TokensIn = 100000 }},
		{"swap completion hash", func(x *kernel.Receipt) { x.CompletionHash = x.PromptHash }},
		{"claim another node", func(x *kernel.Receipt) { x.NodeID = "other-node" }},
		{"move the sequence", func(x *kernel.Receipt) { x.Seq = 4242 }},
		{"shorten the elapsed time", func(x *kernel.Receipt) { x.ElapsedNanos = 0 }},
		{"claim another pid", func(x *kernel.Receipt) { x.PID = x.PID + 1 }},
		{"drop the signature", func(x *kernel.Receipt) { x.Signature = nil }},
		{"truncate the signature", func(x *kernel.Receipt) { x.Signature = x.Signature[:32] }},
		{"flip a signature byte", func(x *kernel.Receipt) { x.Signature[0] ^= 0xff }},
		{"change the route", func(x *kernel.Receipt) { x.Route = "rcpt/expensive" }},
		{"change the key id", func(x *kernel.Receipt) { x.KeyID = "deadbeefdeadbeef" }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			forged := r
			forged.Signature = append([]byte(nil), r.Signature...)
			c.mut(&forged)

			verdict, err := reporter.ctx.SyscallReceiptVerify(forged)
			require.NoError(t, err, "a forged receipt yields a verdict, not an error")
			assert.False(t, verdict.Valid)
			assert.NotEmpty(t, verdict.Reason)
			// The digest names the receipt as presented, so a dispute can cite
			// exactly what the peer sent rather than what it meant to send.
			assert.Equal(t, forged.Digest(), verdict.Digest)
		})
	}
}

// TestReceiptVersionAndShapeAreCheckedSeparatelyFromTheSignature pins the structural
// half of the verdict. A receipt from another encoding version is a protocol
// mismatch, not a fraud claim, and kslashing must be able to tell them apart before
// it accuses a peer.
func TestReceiptVersionAndShapeAreCheckedSeparatelyFromTheSignature(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 1, out: 1}
	pid := rcptLoad(t, k, reporter,
		rcptManifest("rcptshape", kernel.OpUsageEmit, kernel.OpReceiptVerify))
	r, err := k.IssueReceipt(rcptSpec(pid, 1, 1))
	require.NoError(t, err)

	cases := []struct {
		name string
		mut  func(*kernel.Receipt)
		want string
	}{
		{"unknown version", func(x *kernel.Receipt) { x.Version = 99 }, "version"},
		{"empty node id", func(x *kernel.Receipt) { x.NodeID = "" }, "node"},
		{"zero sequence", func(x *kernel.Receipt) { x.Seq = 0 }, "sequence"},
		{"negative tokens", func(x *kernel.Receipt) { x.TokensIn = -1 }, "negative"},
		{"negative elapsed", func(x *kernel.Receipt) { x.ElapsedNanos = -5 }, "negative"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			broken := r
			broken.Signature = append([]byte(nil), r.Signature...)
			c.mut(&broken)

			verdict, err := reporter.ctx.SyscallReceiptVerify(broken)
			require.NoError(t, err)
			assert.False(t, verdict.Valid)
			assert.True(t, verdict.Structural,
				"a malformed receipt is a protocol failure, not a signature failure")
			assert.Contains(t, verdict.Reason, c.want)
		})
	}

	// A well-formed receipt whose signature matches nothing in the root set is the
	// fraud case: structural is false, valid is false.
	foreign := r
	foreign.Signature = make([]byte, 64)
	verdict, err := reporter.ctx.SyscallReceiptVerify(foreign)
	require.NoError(t, err)
	assert.False(t, verdict.Valid)
	assert.False(t, verdict.Structural)
	assert.Contains(t, verdict.Reason, "cluster root")
}

// TestReceiptTokensAreCrossCheckedAgainstAccounting is the anti-fraud control that
// makes a receipt mean something: a module cannot settle tokens it never reported
// through usage:emit. Under-claiming is allowed and costs the module revenue;
// over-claiming is refused here rather than left for a peer dispute.
func TestReceiptTokensAreCrossCheckedAgainstAccounting(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 100, out: 50}
	pid := rcptLoad(t, k, reporter, rcptManifest("rcpttokens", kernel.OpUsageEmit))

	_, err := k.IssueReceipt(rcptSpec(pid, 100, 50))
	require.NoError(t, err)
	_, err = k.IssueReceipt(rcptSpec(pid, 10, 1))
	require.NoError(t, err, "under-claiming is the module's own loss, not a fraud")

	_, err = k.IssueReceipt(rcptSpec(pid, 101, 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only reported")
	_, err = k.IssueReceipt(rcptSpec(pid, 100, 51))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only reported")

	_, err = k.IssueReceipt(rcptSpec(pid, -1, 1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "negative")

	// A pid that reported nothing cannot settle anything, which is the case that
	// would otherwise let an idle module bill for work it never did.
	_, err = k.IssueReceipt(rcptSpec(pid+1000, 1, 1))
	require.Error(t, err)
}

// TestReceiptSettlesAgainstTheMeterRecord covers the strongest form of the
// cross-check. When the issuer names a kmeter request, the counts and the duration
// inside the signature come from the kernel's own per-request measurement, so there is
// nothing left for the issuer to claim and an over-claim is refused against a number the
// module cannot influence.
func TestReceiptSettlesAgainstTheMeterRecord(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 500, out: 250}
	pid := rcptLoad(t, k, reporter,
		rcptManifest("rcptmeter", kernel.OpUsageEmit, kernel.OpMeterRecord, kernel.OpReceiptVerify))

	ctx := reporter.ctx
	id, err := ctx.SyscallMeterOpen("trace-meter-1", "rcpt/meter")
	require.NoError(t, err)
	require.NoError(t, ctx.SyscallMeterAdd(id,
		kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: 300}))
	require.NoError(t, ctx.SyscallMeterAdd(id,
		kernel.UsageFact{Kind: kernel.UsageTokensOut, Quantity: 120}))
	closed, err := ctx.SyscallMeterClose(id, 200)
	require.NoError(t, err)

	spec := rcptSpec(pid, 300, 120)
	spec.Request = id
	r, err := k.IssueReceipt(spec)
	require.NoError(t, err)
	assert.Equal(t, int64(300), r.TokensIn)
	assert.Equal(t, int64(120), r.TokensOut)
	assert.Equal(t, closed.ElapsedNanos(), r.ElapsedNanos,
		"the duration must be the kernel's measurement of the request, not the issuer's")

	verdict, err := ctx.SyscallReceiptVerify(r)
	require.NoError(t, err)
	assert.True(t, verdict.Valid)

	// Over-claiming against the meter is refused even though the pid's usage totals
	// would allow it: 500 reported overall, 300 metered on this request.
	spec = rcptSpec(pid, 301, 120)
	spec.Request = id
	_, err = k.IssueReceipt(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metered")

	// A request belonging to another module cannot be settled under this pid.
	other := &rcptReporter{in: 10, out: 10}
	otherPid := rcptLoad(t, k, other,
		rcptManifest("rcptmeterother", kernel.OpUsageEmit, kernel.OpMeterRecord))
	otherID, err := other.ctx.SyscallMeterOpen("trace-meter-2", "rcpt/other")
	require.NoError(t, err)
	require.NoError(t, other.ctx.SyscallMeterAdd(otherID,
		kernel.UsageFact{Kind: kernel.UsageTokensIn, Quantity: 10}))
	spec = rcptSpec(pid, 10, 0)
	spec.Request = otherID
	_, err = k.IssueReceipt(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "belongs to pid")

	// An id that is not in the ledger is refused rather than treated as unmetered,
	// because silently falling back would let a module escape the stronger check by
	// naming a request that was evicted.
	spec = rcptSpec(pid, 1, 1)
	spec.Request = kernel.RequestID("not-a-request")
	_, err = k.IssueReceipt(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "meter ledger")
	assert.NotZero(t, otherPid)
}

// TestReceiptCeilingIsTypedAndLeavesStateIntact covers every per-receipt ceiling.
// Each is a typed limit error, and each leaves the ledger usable: the next
// well-formed issue succeeds and takes the next sequence number, with no gap. A
// refused issue that consumed a number would open a gap indistinguishable from
// suppression.
func TestReceiptCeilingIsTypedAndLeavesStateIntact(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 10, out: 10}
	pid := rcptLoad(t, k, reporter,
		rcptManifest("rcptceiling", kernel.OpUsageEmit, kernel.OpReceiptVerify))

	first, err := k.IssueReceipt(rcptSpec(pid, 10, 10))
	require.NoError(t, err)
	require.Equal(t, int64(1), first.Seq)

	cases := []struct {
		name string
		mut  func(*kernel.ReceiptSpec)
	}{
		{"trace too long", func(s *kernel.ReceiptSpec) {
			s.Trace = strings.Repeat("t", kernel.MaxReceiptLabelLen()+1)
		}},
		{"route too long", func(s *kernel.ReceiptSpec) {
			s.Route = strings.Repeat("r", kernel.MaxReceiptLabelLen()+1)
		}},
		{"prompt too large", func(s *kernel.ReceiptSpec) {
			s.Prompt = make([]byte, kernel.MaxCryptoInputBytes()+1)
		}},
		{"completion too large", func(s *kernel.ReceiptSpec) {
			s.Completion = make([]byte, kernel.MaxCryptoInputBytes()+1)
		}},
		{"token ceiling", func(s *kernel.ReceiptSpec) { s.TokensIn = 1 << 62 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := rcptSpec(pid, 10, 10)
			c.mut(&spec)
			_, err := k.IssueReceipt(spec)
			require.Error(t, err)
			assert.True(t, errors.Is(err, kernel.ErrReceiptLimit),
				"%s must be a typed limit error, got %v", c.name, err)
		})
	}

	// A reading outside this boot's clock is refused whichever side of it the issuer
	// lands on: the duration is the kernel's measurement, not the issuer's claim.
	t.Run("start reading in the future", func(t *testing.T) {
		spec := rcptSpec(pid, 10, 10)
		spec.StartedMono = kernel.KernelClock().Mono() + int64(time.Hour)
		_, err := k.IssueReceipt(spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "future")
	})

	t.Run("negative start reading", func(t *testing.T) {
		spec := rcptSpec(pid, 10, 10)
		spec.StartedMono = -1
		_, err := k.IssueReceipt(spec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "monotonic clock")
	})

	t.Run("line break in a label", func(t *testing.T) {
		spec := rcptSpec(pid, 10, 10)
		spec.Trace = "a\nb"
		_, err := k.IssueReceipt(spec)
		require.Error(t, err)
	})

	// The ledger is intact after every refusal.
	next, err := k.IssueReceipt(rcptSpec(pid, 10, 10))
	require.NoError(t, err)
	assert.Equal(t, first.Seq+1, next.Seq, "a refused issue must not consume a sequence number")

	verdict, err := reporter.ctx.SyscallReceiptVerify(next)
	require.NoError(t, err)
	assert.True(t, verdict.Valid)
	assert.Empty(t, kernel.SequenceGaps("rcpt-node", []kernel.Receipt{first, next}))
}

// TestReceiptHandleCeilingIsTyped covers the handle side of the ceiling: a module
// may hold only as many receipt references as the sealed root allows, and hitting
// that limit is a typed error rather than a panic or a silent truncation.
func TestReceiptHandleCeilingIsTyped(t *testing.T) {
	tr := rcptTrustRoot(t)
	tr.Limits = kernel.BootLimits{MaxOpenFDsPerModule: 1}
	k := rcptBoot(t, tr)

	reporter := &rcptReporter{in: 10, out: 10}
	pid := rcptLoad(t, k, reporter,
		rcptManifest("rcpthandles", kernel.OpUsageEmit, kernel.OpReceiptVerify))

	r1, err := k.IssueReceipt(rcptSpec(pid, 10, 10))
	require.NoError(t, err)
	r2, err := k.IssueReceipt(rcptSpec(pid, 10, 10))
	require.NoError(t, err)

	first, _, err := reporter.ctx.SyscallReceiptOpen(r1)
	require.NoError(t, err)
	assert.Equal(t, 1, kernel.FDCount(pid))

	_, _, secondErr := reporter.ctx.SyscallReceiptOpen(r2)
	require.Error(t, secondErr)
	assert.True(t, errors.Is(secondErr, kernel.ErrReceiptLimit),
		"the handle ceiling must be a typed limit error, got %v", secondErr)
	assert.Equal(t, 1, kernel.FDCount(pid), "a refused open must not consume a handle")

	// Closing frees the slot, so the ceiling is a live quota and not a latch.
	require.NoError(t, reporter.ctx.SyscallClose(first))
	assert.Zero(t, kernel.FDCount(pid))
	fd, _, err := reporter.ctx.SyscallReceiptOpen(r2)
	require.NoError(t, err)
	assert.Equal(t, 1, kernel.FDCount(pid))

	held, verdict, err := kernel.ReceiptHandle(reporter.ctx, fd)
	require.NoError(t, err)
	assert.Equal(t, r2.Digest(), held.Digest())
	assert.True(t, verdict.Valid)

	// An invalid receipt is not opened at all: tracking a forgery is how a node
	// ends up replaying one.
	forged := r2
	forged.TokensOut = 999999
	_, _, err = reporter.ctx.SyscallReceiptOpen(forged)
	require.Error(t, err)
	assert.Equal(t, 1, kernel.FDCount(pid))

	// Closing twice reports the resource as closed rather than silently succeeding.
	require.NoError(t, reporter.ctx.SyscallClose(fd))
	assert.Error(t, reporter.ctx.SyscallClose(fd))
	assert.Zero(t, kernel.FDCount(pid))
}

// TestReceiptHandlesAreReclaimedOnUnload is the reclaim property. A module holding
// receipt references leaks nothing, because the kernel owns the table and walks it.
func TestReceiptHandlesAreReclaimedOnUnload(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 30, out: 30}
	pid := rcptLoad(t, k, reporter,
		rcptManifest("rcptreclaim", kernel.OpUsageEmit, kernel.OpReceiptVerify))

	var opened []kernel.FD
	for range 3 {
		r, err := k.IssueReceipt(rcptSpec(pid, 30, 30))
		require.NoError(t, err)
		fd, _, err := reporter.ctx.SyscallReceiptOpen(r)
		require.NoError(t, err)
		opened = append(opened, fd)
	}
	require.Len(t, opened, 3)
	assert.Equal(t, 3, kernel.FDCount(pid))
	for _, fd := range opened {
		assert.Equal(t, "receipt", rcptKindOf(pid, fd))
	}

	require.NoError(t, k.Unload(pid))
	assert.Zero(t, kernel.FDCount(pid), "unload must reclaim every receipt handle")
	assert.Empty(t, kernel.FDList(pid))
}

// rcptKindOf reports the kind of an open handle, for asserting what a module holds.
func rcptKindOf(pid kernel.PID, fd kernel.FD) string {
	for _, info := range kernel.FDList(pid) {
		if info.FD == fd {
			return info.Kind
		}
	}
	return ""
}

// TestReceiptHandlesAreReclaimedWhenModulePanics is the crash path. A module that
// panics while holding settlement references is exactly the module whose references
// most need closing, and it gets no chance to clean up after itself.
func TestReceiptHandlesAreReclaimedWhenModulePanics(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 20, out: 20}
	worker := rcptLoad(t, k, reporter, rcptManifest("rcptpanicworker", kernel.OpUsageEmit))
	r, err := k.IssueReceipt(rcptSpec(worker, 20, 20))
	require.NoError(t, err)

	const name = "rcptpanic"
	kernel.Register(name, func() (kernel.Module, error) {
		return &rcptPanics{receipt: r}, nil
	})
	t.Cleanup(func() { kernel.Unregister(name) })

	_, err = k.Load(rcptManifest(name, kernel.OpReceiptVerify))
	require.Error(t, err)
	require.ErrorContains(t, err, "OnLoad panicked")

	var pid kernel.PID
	for _, rec := range kernel.ProcTable() {
		if rec.Name == name {
			pid = rec.PID
		}
	}
	require.NotZero(t, pid)
	assert.Equal(t, kernel.ProcRejected, rcptProcState(pid))
	assert.Zero(t, kernel.FDCount(pid), "a panicking module must leak no receipt handle")
	assert.Zero(t, kernel.FDCount(worker), "the worker's own state must be untouched")
}

// rcptPanics opens a receipt handle and then dies, which is the shape of a module
// that crashes mid-settlement.
type rcptPanics struct{ receipt kernel.Receipt }

func (m *rcptPanics) OnLoad(ctx kernel.SContext) error {
	if _, _, err := ctx.SyscallReceiptOpen(m.receipt); err != nil {
		return err
	}
	panic("settlement module exploded")
}
func (m *rcptPanics) OnUnload() error { return nil }

// rcptProcState reads a pid's state from the process table.
func rcptProcState(pid kernel.PID) kernel.ProcState {
	for _, r := range kernel.ProcTable() {
		if r.PID == pid {
			return r.State
		}
	}
	return ""
}

// TestReceiptSequenceIsMonotonicAndGapFree is the settlement property the owner
// named. A gap is indistinguishable from a receipt that was issued and then
// suppressed, so the ledger must never produce one - including under contention from
// several goroutines settling at once.
func TestReceiptSequenceIsMonotonicAndGapFree(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	const workers, each = 6, 12
	pids := make([]kernel.PID, workers)
	for w := range workers {
		pids[w] = rcptLoad(t, k, &rcptReporter{in: 5, out: 5},
			rcptManifest(fmt.Sprintf("rcptseq%d", w), kernel.OpUsageEmit))
	}

	var mu sync.Mutex
	seqs := make([]int64, 0, workers*each)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for range each {
				r, err := k.IssueReceipt(rcptSpec(pids[w], 5, 5))
				if err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
				mu.Lock()
				seqs = append(seqs, r.Seq)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()

	require.Len(t, seqs, workers*each)
	assert.Empty(t, kernel.SequenceGaps("rcpt-node", rcptFromSeqs(seqs)),
		"the ledger must not skip or duplicate a sequence number")
	assert.Equal(t, int64(workers*each), kernel.ReceiptCursor("rcpt-node"))

	stats := kernel.ReceiptStats()
	assert.Equal(t, int64(workers*each), stats.Issued)
	assert.Zero(t, stats.Refused)
	assert.Equal(t, int64(workers*each), stats.Cursor["rcpt-node"])
}

// rcptFromSeqs builds receipts carrying only the fields SequenceGaps reads, so the
// gap computation is exercised on the shape it will see collected from a peer.
func rcptFromSeqs(seqs []int64) []kernel.Receipt {
	out := make([]kernel.Receipt, 0, len(seqs))
	for _, s := range seqs {
		out = append(out, kernel.Receipt{NodeID: "rcpt-node", Seq: s})
	}
	return out
}

// TestReceiptSequenceGapsDetectsSuppression proves the gap computation itself, which
// is what kslashing will act on. Getting it wrong either misses a suppression or
// slashes an honest peer.
func TestReceiptSequenceGapsDetectsSuppression(t *testing.T) {
	cases := []struct {
		name string
		seqs []int64
		want []int64
	}{
		{"contiguous", []int64{1, 2, 3, 4}, nil},
		{"one missing", []int64{1, 2, 4, 5}, []int64{3}},
		{"run missing", []int64{1, 5}, []int64{2, 3, 4}},
		{"unordered input", []int64{4, 1, 3}, []int64{2}},
		{"single receipt", []int64{7}, nil},
		{"empty", nil, nil},
		{"duplicates are not gaps", []int64{1, 1, 2}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, kernel.SequenceGaps("rcpt-node", rcptFromSeqs(c.seqs)))
		})
	}

	// Another node's receipts are not this node's gaps.
	mixed := []kernel.Receipt{
		{NodeID: "a", Seq: 1}, {NodeID: "a", Seq: 3},
		{NodeID: "b", Seq: 1}, {NodeID: "b", Seq: 2},
	}
	assert.Equal(t, []int64{2}, kernel.SequenceGaps("a", mixed))
	assert.Empty(t, kernel.SequenceGaps("b", mixed))
}

// TestReceiptCanonicalEncodingIsFixed pins the property that makes cross-node
// comparison possible at all. The encoding is a fixed field order with length
// prefixes, so two receipts whose fields would collide under a separator-based
// encoding do not encode identically, and re-splitting a field across a boundary
// cannot preserve a signature.
func TestReceiptCanonicalEncodingIsFixed(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 1, out: 1}
	pid := rcptLoad(t, k, reporter, rcptManifest("rcptencoding", kernel.OpUsageEmit))

	spec := rcptSpec(pid, 1, 1)
	spec.Trace = "a"
	spec.Route = "b"
	first, err := k.IssueReceipt(spec)
	require.NoError(t, err)

	spec2 := rcptSpec(pid, 1, 1)
	spec2.Trace = "a;b"
	spec2.Route = ""
	second, err := k.IssueReceipt(spec2)
	require.NoError(t, err)

	assert.NotEqual(t, kernel.ReceiptPayload(first), kernel.ReceiptPayload(second))
	assert.NotEqual(t, first.Digest(), second.Digest())

	// The payload is stable across recomputation, which is what a peer relies on.
	assert.Equal(t, kernel.ReceiptPayload(first), kernel.ReceiptPayload(first))
	assert.Len(t, first.Digest(), 64)

	// The sequence number is inside the encoding, so two otherwise identical
	// receipts from one node never share a digest.
	third, err := k.IssueReceipt(rcptSpec(pid, 1, 1))
	require.NoError(t, err)
	assert.NotEqual(t, first.Digest(), third.Digest())

	// Every signed field appears in the payload, so a reviewer can see the encoding
	// covers what the receipt claims.
	payload := string(kernel.ReceiptPayload(third))
	for _, want := range []string{
		"version", "node_id", "seq", "trace", "route", "pid",
		"prompt_hash", "completion_hash", "tokens_in", "tokens_out",
		"elapsed_nanos", "issued_mono", "issued_wall", "key_id",
	} {
		assert.Contains(t, payload, want)
	}
	// And the signature is not part of what it signs.
	assert.NotContains(t, payload, "signature")
}

// TestReceiptWireEncodingRoundTrips covers the shape a peer actually receives. The
// JSON layout is deliberately not the canonical encoding, so the wire format can
// change without invalidating a single issued receipt.
func TestReceiptWireEncodingRoundTrips(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 7, out: 3}
	pid := rcptLoad(t, k, reporter, rcptManifest("rcptwire", kernel.OpUsageEmit, kernel.OpReceiptVerify))
	r, err := k.IssueReceipt(rcptSpec(pid, 7, 3))
	require.NoError(t, err)

	encoded, err := r.Encode()
	require.NoError(t, err)
	decoded, err := kernel.DecodeReceipt(encoded)
	require.NoError(t, err)

	assert.Equal(t, r, decoded)
	assert.Equal(t, r.Digest(), decoded.Digest(), "the digest must survive the wire")

	verdict, err := reporter.ctx.SyscallReceiptVerify(decoded)
	require.NoError(t, err)
	assert.True(t, verdict.Valid)

	// Garbage from a peer is a parse failure, not a verdict, so kslashing can tell a
	// broken peer from a dishonest one.
	_, err = kernel.DecodeReceipt([]byte("{not json"))
	require.Error(t, err)
}

// TestReceiptPrecomputedHashesAreValidated covers the streamed-completion path,
// where the issuer digested each chunk and no longer holds the body. A malformed
// digest is refused rather than passed through, because a receipt carrying one cannot
// be compared with a peer's copy and would silently agree with nothing.
func TestReceiptPrecomputedHashesAreValidated(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 1, out: 1}
	pid := rcptLoad(t, k, reporter, rcptManifest("rcpthashes", kernel.OpUsageEmit))

	sum := rcptSha256Hex([]byte("the prompt"))
	spec := rcptSpec(pid, 1, 1)
	spec.Prompt = nil
	spec.PromptHash = sum
	spec.CompletionHash = rcptSha256Hex([]byte("the completion"))
	r, err := k.IssueReceipt(spec)
	require.NoError(t, err)
	assert.Equal(t, sum, r.PromptHash)

	cases := []struct {
		name  string
		hash  string
		error string
	}{
		{"not hex", "not-hex", "64 hex"},
		{"too short", "abcd", "64 hex"},
		{"uppercase", strings.ToUpper(sum), "lowercase"},
		{"right length wrong alphabet", strings.Repeat("z", 64), "not hex"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad := rcptSpec(pid, 1, 1)
			bad.PromptHash = c.hash
			bad.CompletionHash = sum
			_, err := k.IssueReceipt(bad)
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.error)
		})
	}
}

// TestReceiptResetBetweenBoots is the reset path. The ledger is per boot and per
// node, and a cursor that survived a restart would either repeat a sequence number
// or open a gap in the record of a node that never issued one.
func TestReceiptResetBetweenBoots(t *testing.T) {
	k1 := rcptBoot(t, rcptTrustRoot(t))
	reporter := &rcptReporter{in: 1, out: 1}
	pid := rcptLoad(t, k1, reporter, rcptManifest("rcptreset", kernel.OpUsageEmit))
	for range 3 {
		_, err := k1.IssueReceipt(rcptSpec(pid, 1, 1))
		require.NoError(t, err)
	}
	assert.Equal(t, int64(3), kernel.ReceiptCursor("rcpt-node"))
	assert.Equal(t, int64(3), kernel.ReceiptStats().Issued)
	require.NoError(t, k1.Shutdown())

	assert.Zero(t, kernel.ReceiptCursor("rcpt-node"))
	stats := kernel.ReceiptStats()
	assert.Zero(t, stats.Issued)
	assert.Zero(t, stats.Refused)
	assert.Empty(t, stats.Cursor)

	k2 := rcptBoot(t, rcptTrustRoot(t))
	reporter2 := &rcptReporter{in: 1, out: 1}
	pid2 := rcptLoad(t, k2, reporter2, rcptManifest("rcptreset2", kernel.OpUsageEmit))
	r, err := k2.IssueReceipt(rcptSpec(pid2, 1, 1))
	require.NoError(t, err)
	assert.Equal(t, int64(1), r.Seq, "a new boot restarts the ledger at 1")
}

// TestReceiptConcurrentVerification hammers the verify path from several goroutines
// under -race, which is where a shared digest buffer or an unsynchronized cluster
// root read would show up.
func TestReceiptConcurrentVerification(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 50, out: 50}
	pid := rcptLoad(t, k, reporter,
		rcptManifest("rcptconc", kernel.OpUsageEmit, kernel.OpReceiptVerify))

	receipts := make([]kernel.Receipt, 0, 8)
	for range 8 {
		r, err := k.IssueReceipt(rcptSpec(pid, 50, 50))
		require.NoError(t, err)
		receipts = append(receipts, r)
	}

	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range 20 {
				r := receipts[(w+i)%len(receipts)]
				verdict, err := reporter.ctx.SyscallReceiptVerify(r)
				if err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
				if !verdict.Valid {
					t.Errorf("worker %d: genuine receipt %d failed: %s", w, r.Seq, verdict.Reason)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// TestReceiptAuditRecordsSettlementWithoutContent proves the settlement path leaves
// evidence behind, and that the evidence names the receipt without carrying the
// request body. A receipt is public, but a user's prompt is not the kernel's record
// to keep.
func TestReceiptAuditRecordsSettlementWithoutContent(t *testing.T) {
	k := rcptBoot(t, rcptTrustRoot(t))

	reporter := &rcptReporter{in: 11, out: 12}
	pid := rcptLoad(t, k, reporter, rcptManifest("rcptaudit", kernel.OpUsageEmit))

	spec := rcptSpec(pid, 11, 12)
	spec.Trace = "trace-audit-1"
	r, err := k.IssueReceipt(spec)
	require.NoError(t, err)

	entries := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditSettle})
	require.NotEmpty(t, entries)
	last := entries[len(entries)-1]
	assert.Equal(t, r.Digest(), last.Fields["digest"])
	assert.Equal(t, int64(1), last.Fields["seq"])
	assert.Equal(t, "trace-audit-1", last.Fields["trace"])
	assert.Equal(t, int64(11), last.Fields["tokens_in"])
	assert.Equal(t, int64(12), last.Fields["tokens_out"])
	assert.NotContains(t, last.Fields, "prompt")
	assert.NotContains(t, last.Fields, "completion")
	assert.NotContains(t, last.Fields, "prompt_hash")

	// The audit chain still verifies with the settlement entries in it.
	assert.Equal(t, -1, kernel.VerifyChain(kernel.AuditQuery(kernel.AuditFilter{}), kernel.AuditGenesis))
}
