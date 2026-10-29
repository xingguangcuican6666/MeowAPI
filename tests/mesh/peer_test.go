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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// These tests drive kpeer through the host handle for everything that needs
// peer:dial or peer:announce, and through the module-reachable surface for the
// denials, because that is exactly how the policy table splits the two: both mesh
// operations are held by the kernel domain alone, and the pid 0 context that holds
// them is retired the instant init exists.
//
// Every transport here is a deterministic in-test fake whose behaviour the test
// controls through a channel or a canned reply. No test sleeps to wait for work and
// no test compares wall-clock durations: the only timing assertions are the
// house-shaped ones tests/channels already makes for klock, which pin that a
// deadline arrived rather than how long the scheduler took.

// closeOnce returns an idempotent close for a channel used to release a blocked fake
// transport. A test that fails an assertion before its own explicit unblock must still
// release the goroutine, and a double close would panic and mask the real failure.
func closeOnce(ch chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// meshDiscard swallows console output for the boots that do not assert on it. Tests
// that do assert take a buffer from harness.QuietConsole instead.
type meshDiscard struct{}

func (meshDiscard) Write(p []byte) (int, error) { return len(p), nil }

// peerCounter makes node ids unique per test. kpeer's registry is package state and
// resetPeers is wired by the integrator, so a test that reused a node id could
// observe the previous test's session and pass for the wrong reason.
var peerCounter atomic.Int64

func peerNodeName(prefix string) string {
	return prefix + "-" + harness.Itoa(int(peerCounter.Add(1)))
}

// meshKeyPair makes a fresh ed25519 key pair encoded the way an operator supplies one
// in the trust root: a hex seed for signing, a hex public key as a cluster root.
func meshKeyPair(t *testing.T) (seedHex string, pubHex string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub), priv
}

// meshBoot starts a kernel whose cluster roots contain both this node's own key and
// the test peer's key, so a handshake from either verifies here and an envelope this
// node signs can be looped back through PeerDeliver. That single-node-plus-one-peer
// shape is the configuration a real cluster root list is built from.
//
// It returns the kernel, this node's id, and the peer's signing key.
func meshBoot(t *testing.T) (*kernel.Kernel, string, ed25519.PrivateKey) {
	t.Helper()
	selfSeed, selfPub, _ := meshKeyPair(t)
	_, peerPub, peerPriv := meshKeyPair(t)

	nodeID := peerNodeName("mesh-self")
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{
			NodeID:          nodeID,
			ClusterRootKeys: []string{selfPub, peerPub},
			SigningKeyPEM:   selfSeed,
		},
		Console: meshDiscard{},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k, nodeID, peerPriv
}

// signPeerHandshake builds one handshake reply the way an honest peer would: both
// nonces, the initiator, and the endpoint the peer was dialed at are inside the
// signature, which is what makes a captured reply unusable in a different exchange.
func signPeerHandshake(t *testing.T, priv ed25519.PrivateKey, nodeID, endpoint, initiator string, nonceA []byte) kernel.PeerHandshake {
	t.Helper()
	nonceB := make([]byte, 32)
	for i := range nonceB {
		nonceB[i] = byte(i + 1)
	}
	h := kernel.PeerHandshake{
		Version:   kernel.PeerVersion,
		NodeID:    nodeID,
		KeyID:     "peer-key",
		Initiator: initiator,
		NonceA:    nonceA,
		NonceB:    nonceB,
		Endpoint:  endpoint,
	}
	h.Signature = ed25519.Sign(priv, kernel.PeerHandshakePayload(h))
	return h
}

// fakeTransport is an in-test PeerTransport. Each field the test sets changes one
// behaviour; unset fields make the call fail loudly rather than silently succeed, so
// a test that forgot to configure a path cannot pass by accident.
type fakeTransport struct {
	mu sync.Mutex

	// calls records every frame the kernel handed over, so a test can assert the
	// transport was never reached on a refusal path.
	calls []kernel.PeerFrame

	// handshake answers a PeerFrameHandshake. When nil the exchange fails.
	handshake func(req kernel.PeerHandshake) (kernel.PeerHandshake, error)
	// probe answers a PeerFrameProbe.
	probe func(seq int64) (kernel.PeerFrame, error)
	// forward answers a PeerFrameForward, typically by looping the frame back
	// through Kernel.PeerDeliver so the same kernel plays the remote node.
	forward func(frame kernel.PeerFrame) (kernel.PeerFrame, error)
	// blockOn, when set, makes Exchange wait on it instead of answering. The test
	// controls whether it ever closes, which is how a timeout is produced without
	// sleeping.
	blockOn chan struct{}
	// ignoreDeadline makes a blocked Exchange disregard the deadline the kernel
	// passed. That is the honest way to test the kernel-side guarantee: a host that
	// never returns is exactly the case where only the kernel's own timer can end the
	// call. A fake that honoured the deadline would race the kernel's timer at the
	// same instant and could win, which would prove the fake works rather than that
	// the kernel times its own waits.
	ignoreDeadline bool
	// panicWith, when non-empty, makes Exchange panic with that value.
	panicWith string
	// sendErr is returned by Send.
	sendErr error
}

func (f *fakeTransport) record(frame kernel.PeerFrame) {
	f.mu.Lock()
	f.calls = append(f.calls, frame)
	f.mu.Unlock()
}

func (f *fakeTransport) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeTransport) Send(endpoint string, frame kernel.PeerFrame, deadline int64) error {
	f.record(frame)
	return f.sendErr
}

func (f *fakeTransport) Exchange(endpoint string, frame kernel.PeerFrame, deadline int64) (kernel.PeerFrame, error) {
	f.record(frame)

	if f.panicWith != "" {
		panic(f.panicWith)
	}
	if f.blockOn != nil {
		if f.ignoreDeadline {
			<-f.blockOn
			return kernel.PeerFrame{}, errors.New("fake transport: unblocked by the test")
		}
		select {
		case <-f.blockOn:
		case <-time.After(time.Until(deadlineMonoTime(deadline))):
		}
		return kernel.PeerFrame{}, fmt.Errorf("fake transport: deadline passed")
	}

	switch frame.Kind {
	case kernel.PeerFrameHandshake:
		if f.handshake == nil {
			return kernel.PeerFrame{}, errors.New("fake transport: no handshake answer configured")
		}
		var req kernel.PeerHandshake
		if err := json.Unmarshal(frame.Body, &req); err != nil {
			return kernel.PeerFrame{}, err
		}
		reply, err := f.handshake(req)
		if err != nil {
			return kernel.PeerFrame{}, err
		}
		body, err := json.Marshal(reply)
		if err != nil {
			return kernel.PeerFrame{}, err
		}
		return kernel.PeerFrame{Kind: kernel.PeerFrameHandshakeReply, Seq: frame.Seq, Body: body}, nil

	case kernel.PeerFrameProbe:
		if f.probe == nil {
			return kernel.PeerFrame{Kind: kernel.PeerFrameProbeReply, Seq: frame.Seq}, nil
		}
		return f.probe(frame.Seq)

	case kernel.PeerFrameForward:
		if f.forward == nil {
			return kernel.PeerFrame{}, errors.New("fake transport: no forward answer configured")
		}
		return f.forward(frame)
	}
	return kernel.PeerFrame{}, fmt.Errorf("fake transport: unexpected frame kind %q", frame.Kind)
}

// deadlineMonoTime converts a kernel mono() deadline into a wall-clock instant the
// fake transport can wait on. It is test-only glue: the kernel itself never does this
// conversion, which is the property under test.
func deadlineMonoTime(deadline int64) time.Time {
	remaining := time.Duration(deadline - kernel.KernelClock().Mono())
	if remaining < 0 {
		remaining = 0
	}
	return time.Now().Add(remaining)
}

// ---------------------------------------------------------------------------
// Denials: every mesh grant has a denial counterpart.

// TestPeerDialIsDeniedToModulesAndInit pins the policy refusal as runtime behaviour
// rather than as a table read: peer:dial belongs to the kernel domain alone, so
// neither init nor a loaded module can dial, and the denial is the canonical avc line.
func TestPeerDialIsDeniedToModulesAndInit(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)

	_, initErr := kernel.PeerDial(k.InitContext(), kernel.PeerDialSpec{Endpoint: "peer.example"})
	require.Error(t, initErr, "init must not hold peer:dial")
	assert.True(t, kernel.IsDenied(initErr), "the refusal must be a policy denial: %v", initErr)

	pid, mod := msLoad(t, k, nil)
	_, modErr := kernel.PeerDial(mod.ctx, kernel.PeerDialSpec{Endpoint: "peer.example"})
	require.Error(t, modErr, "a module must not hold peer:dial")
	assert.True(t, kernel.IsDenied(modErr), "the refusal must be a policy denial: %v", modErr)

	faults := harness.Faults(buf)
	require.NotEmpty(t, faults, "a denial must reach the console as a fault")
	var sawInit, sawModule bool
	for _, f := range faults {
		if !strings.Contains(f.Msg, "avc: denied { peer:dial }") {
			continue
		}
		if strings.Contains(f.Msg, string(kernel.DomainInit)) {
			sawInit = true
		}
		if strings.Contains(f.Msg, fmt.Sprintf("pid=%d", pid)) {
			sawModule = true
		}
	}
	assert.True(t, sawInit, "the canonical avc line must name the init domain")
	assert.True(t, sawModule, "the canonical avc line must name the refusing pid")
}

// TestPeerAnnounceIsDeniedToModulesAndInit is the denial half of announce.
func TestPeerAnnounceIsDeniedToModulesAndInit(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	a := kernel.PeerAnnouncement{Version: kernel.PeerVersion, NodeID: "somewhere", Seq: 1}
	require.Error(t, kernel.PeerAnnounce(k.InitContext(), a), "init must not hold peer:announce")

	_, mod := msLoad(t, k, nil)
	err := kernel.PeerAnnounce(mod.ctx, a)
	require.Error(t, err, "a module must not hold peer:announce")
	assert.True(t, kernel.IsDenied(err))
}

// TestModuleCannotDialOutsideItsDeclaredBoundary pins the invariant that actually
// matters, and it holds under either of two policy states.
//
// Today peer:dial is absent from policy.go's enforcedScopedOps, so a module cannot reach
// it at all and the ceiling refuses the call: the boundary is never consulted because
// nothing gets that far. kpeer nevertheless implements the per-call check
// (peerEndpointAllowed), so if the owner adds peer:dial to the whitelist the invariant
// is enforced by the declaration instead - and a module still cannot dial an endpoint it
// did not declare.
//
// The test branches on which mechanism is live rather than assuming one, because the
// property worth pinning is "a module cannot dial an undeclared endpoint", not "the
// refusal happens to come from the ceiling". Assuming the ceiling would make this test go
// red on a legitimate policy widening; assuming the scope check would make it green today
// without testing anything.
func TestModuleCannotDialOutsideItsDeclaredBoundary(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	const declared = "declared.example"
	const undeclared = "undeclared.example"

	name := peerNodeName("ms-scope")
	mod := &msProbe{}
	kernel.Register(name, func() (kernel.Module, error) { return mod, nil })
	defer kernel.Unregister(name)

	_, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require:      []kernel.Op{kernel.OpPeerDial},
		AllowedHosts: []string{declared},
	})
	require.NoError(t, err, "a scoped op validates at load even without a scope branch")
	require.NotNil(t, mod.ctx)

	// Both dials happen after the load returns, through the retained context. Driving
	// them from inside OnLoad would test a different fact: a module's record is
	// published only once OnLoad completes, so during OnLoad there is no live manifest
	// and the scope check fails closed with "no declared peer boundary". That is the
	// same reason RouteRegister refuses during OnLoad, and it is correct, but it is
	// not the boundary property under test here.
	_, declaredErr := kernel.PeerDial(mod.ctx, kernel.PeerDialSpec{Endpoint: declared})
	_, undeclaredErr := kernel.PeerDial(mod.ctx, kernel.PeerDialSpec{Endpoint: undeclared})

	// The load-bearing assertion, true under both policy states.
	require.Error(t, undeclaredErr, "a module must never dial an endpoint it did not declare")

	if kernel.IsDenied(undeclaredErr) && kernel.DenialReason(undeclaredErr) == "" {
		// The ceiling is what refused, which is today's state: peer:dial has no
		// per-call enforcement in the whitelist, so the declaration is never reached.
		assert.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpPeerDial),
			"and the ceiling itself must keep refusing peer:dial to the plugin domain")
		require.Error(t, declaredErr, "with the ceiling live, the declared endpoint is refused too")
		assert.True(t, kernel.IsDenied(declaredErr))
		return
	}

	// The scope check is what refused, which is the state after peer:dial enters
	// enforcedScopedOps. The refusal must carry a reason naming the boundary, must be
	// recorded as an escalation, and must not have reached the transport.
	assert.NotEmpty(t, kernel.DenialReason(undeclaredErr),
		"a scope refusal must say which boundary was crossed: %v", undeclaredErr)
	assert.Contains(t, kernel.DenialReason(undeclaredErr), "allowed_hosts")

	var sawEscalation bool
	for _, e := range auditEntries(t, kernel.AuditEscalation) {
		if e.Msg == "peer endpoint outside declared boundary" && e.Fields["endpoint"] == undeclared {
			sawEscalation = true
		}
	}
	assert.True(t, sawEscalation,
		"probing one's own boundary is evidence about the module and must be escalated")

	// And the declared endpoint is not refused by the scope check. It may still fail
	// for an unrelated reason - the fake transport has no handshake answer - but the
	// failure must not be the boundary.
	if declaredErr != nil {
		assert.NotContains(t, declaredErr.Error(), "allowed_hosts",
			"the declared endpoint must pass the boundary check")
	}
}

// TestPeerAnnounceIsNotGrantableToAManifest pins the other half: peer:announce is not
// a scoped op, so a manifest asking for it is rejected before any module code runs.
func TestPeerAnnounceIsNotGrantableToAManifest(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	name := peerNodeName("ms-announce")
	kernel.Register(name, func() (kernel.Module, error) { return &harness.NoopModule{}, nil })
	defer kernel.Unregister(name)

	_, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpPeerAnnounce},
	})
	require.Error(t, err, "peer:announce is not grantable to the plugin domain")
	assert.Contains(t, err.Error(), "not grantable")
}

// ---------------------------------------------------------------------------
// Handshake: the identity contract.

// TestPeerHostDialCompletesAMutualHandshake is the end-to-end identity contract: the
// kernel mints a nonce, the peer signs both nonces plus its own identity and the
// endpoint it was dialed at, and the kernel accepts only a reply bound to this
// exchange.
func TestPeerHostDialCompletesAMutualHandshake(t *testing.T) {
	harness.QuietConsole(t)
	k, selfID, peerPriv := meshBoot(t)

	peerID := peerNodeName("mesh-peer")
	endpoint := "peer-one.cluster.example"

	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		// The dial must have carried this node's own identity and a full-length
		// nonce, or the reply would be signing a claim about an exchange that
		// never happened.
		if req.NodeID != selfID || req.Initiator != selfID {
			return kernel.PeerHandshake{}, fmt.Errorf("dial named %q/%q, want %q", req.NodeID, req.Initiator, selfID)
		}
		if len(req.NonceA) != 32 {
			return kernel.PeerHandshake{}, fmt.Errorf("dial nonce is %d bytes", len(req.NonceA))
		}
		return signPeerHandshake(t, peerPriv, peerID, endpoint, req.Initiator, req.NonceA), nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	sess, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: endpoint, Label: "peer one"})
	require.NoError(t, err)

	assert.Equal(t, peerID, sess.NodeID)
	assert.NotEmpty(t, sess.KeyID, "the verdict must report which cluster root matched")
	assert.Equal(t, endpoint, sess.Endpoint)
	assert.Equal(t, "peer one", sess.Label)
	assert.NotEqual(t, kernel.FD(0), sess.FD, "a session must carry a handle")
	assert.Greater(t, sess.Seq, int64(0), "sequence numbers start at 1")

	// The handle resolves in the fd table of the context the host path acts under,
	// which is what makes it reclaimable rather than a leaked reference.
	found := false
	for _, info := range kernel.FDList(k.InitContext().PID()) {
		if info.FD == sess.FD && info.Kind == "peer" {
			found = true
		}
	}
	assert.True(t, found, "the session handle must be installed as kind peer")

	// The nonce the kernel minted must have reached the transport inside the signed
	// payload, otherwise the handshake is not bound to this exchange at all.
	require.Equal(t, 1, ft.callCount())
	assert.Equal(t, kernel.PeerFrameHandshake, ft.calls[0].Kind)
	var sent kernel.PeerHandshake
	require.NoError(t, json.Unmarshal(ft.calls[0].Body, &sent))
	assert.Len(t, sent.NonceA, 32)
	assert.Equal(t, selfID, sent.Initiator)

	var rows []kernel.PeerInfo
	for _, p := range kernel.PeerTableSnapshot() {
		if p.NodeID == peerID {
			rows = append(rows, p)
		}
	}
	require.Len(t, rows, 1, "the trusted peer must be in the mesh table exactly once")
	assert.False(t, rows[0].Closed)
}

// TestPeerHandshakeRejectsAnUntrustedKey is the load-bearing forgery test. A
// well-formed claim signed by a key outside the sealed roots is not trusted, is not
// structural, lands an escalation on the chain, and installs no session. The
// Structural:false half is what kslashing treats as evidence of dishonesty rather than
// as a protocol disagreement.
func TestPeerHandshakeRejectsAnUntrustedKey(t *testing.T) {
	harness.QuietConsole(t)
	k, selfID, _ := meshBoot(t)

	_, _, roguePriv := meshKeyPair(t)
	peerID := peerNodeName("mesh-rogue")
	endpoint := "rogue.cluster.example"

	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		h := signPeerHandshake(t, roguePriv, peerID, endpoint, req.Initiator, req.NonceA)
		h.KeyID = "rogue-key"
		return h, nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: endpoint})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerUntrusted), "want ErrPeerUntrusted, got %v", err)

	for _, p := range kernel.PeerTableSnapshot() {
		assert.NotEqual(t, peerID, p.NodeID, "an untrusted peer must not enter the mesh table")
	}
	assert.Empty(t, kernel.FDList(k.InitContext().PID()), "an untrusted dial must install no handle")

	// The verdict shape is the contract kslashing depends on.
	verdict, verr := kernel.VerifyPeerHandshake(signPeerHandshake(t, roguePriv, peerID, endpoint, selfID, make([]byte, 32)))
	require.NoError(t, verr, "a misconfigured node is an error; a wrong key is a verdict")
	assert.False(t, verdict.Trusted)
	assert.False(t, verdict.Structural, "a bad signature on a well-formed claim is not structural")
	assert.NotEmpty(t, verdict.Reason)

	esc := auditEntries(t, kernel.AuditEscalation)
	require.NotEmpty(t, esc, "an untrusted identity is an escalation, not a peer fact")
	var saw bool
	for _, e := range esc {
		if strings.Contains(e.Msg, "peer handshake failed verification") && e.Fields["node_id"] == peerID {
			saw = true
		}
	}
	assert.True(t, saw, "the escalation must name the peer that could not prove its identity")
}

// TestPeerHandshakeConfigurationFailureIsAnError pins "unverifiable is not invalid".
// A node with no cluster roots cannot reach a conclusion, and reporting one would
// either excuse a forgery or accuse an honest peer.
func TestPeerHandshakeConfigurationFailureIsAnError(t *testing.T) {
	harness.QuietConsole(t)
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: peerNodeName("mesh-noroots")},
		Console:   meshDiscard{},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	_, _, peerPriv := meshKeyPair(t)
	h := signPeerHandshake(t, peerPriv, "honest-peer", "honest.example", "mesh-noroots", make([]byte, 32))

	verdict, verr := kernel.VerifyPeerHandshake(h)
	require.Error(t, verr, "no cluster roots is a configuration failure, not a verdict")
	assert.False(t, verdict.Trusted)
	assert.Empty(t, verdict.Reason, "a verdict the node cannot reach must not carry an accusation")
	assert.False(t, verdict.Structural)

	assert.Empty(t, auditEntries(t, kernel.AuditEscalation),
		"a misconfigured node must not accuse an honest peer on the chain")
}

// TestPeerHandshakeStructuralFailureIsNotAForgery pins the three-way outcome split
// from collapsing. Each of these is a protocol disagreement, so each is Trusted:false
// with Structural:true and a nil error, and none of them is an accusation.
func TestPeerHandshakeStructuralFailureIsNotAForgery(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	require.NotNil(t, k)

	base := signPeerHandshake(t, peerPriv, "struct-peer", "struct.example", "mesh-self", make([]byte, 32))

	cases := []struct {
		name   string
		mut    func(h *kernel.PeerHandshake)
		reason string
	}{
		{"wrong version", func(h *kernel.PeerHandshake) { h.Version = kernel.PeerVersion + 1 }, "unsupported peer version"},
		{"empty node id", func(h *kernel.PeerHandshake) { h.NodeID = "" }, "empty peer node id"},
		{"node id with a newline", func(h *kernel.PeerHandshake) { h.NodeID = "evil\npeer" }, "control or non-ASCII"},
		{"short nonce", func(h *kernel.PeerHandshake) { h.NonceA = make([]byte, 8) }, "nonces must be 32 bytes"},
		{"no signature", func(h *kernel.PeerHandshake) { h.Signature = nil }, "carries no signature"},
		{"empty endpoint", func(h *kernel.PeerHandshake) { h.Endpoint = "" }, "empty peer endpoint"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := base
			h.NonceA = append([]byte(nil), base.NonceA...)
			h.NonceB = append([]byte(nil), base.NonceB...)
			h.Signature = append([]byte(nil), base.Signature...)
			tc.mut(&h)

			verdict, err := kernel.VerifyPeerHandshake(h)
			require.NoError(t, err, "a malformed frame is a verdict, not an error")
			assert.False(t, verdict.Trusted)
			assert.True(t, verdict.Structural, "shape failures must be marked structural")
			assert.Contains(t, verdict.Reason, tc.reason)
		})
	}
}

// TestPeerHandshakeRefusesACapturedReplyAtAnotherEndpoint pins the endpoint binding.
// Signing a field nobody compares binds nothing, so the dial must refuse a reply whose
// signed endpoint is not the one it dialed: that is the redirect attack the signature
// exists to stop.
func TestPeerHandshakeRefusesACapturedReplyAtAnotherEndpoint(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	peerID := peerNodeName("mesh-redirect")

	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		// An attacker who captured a handshake for a different address replays it
		// here: same signature, different endpoint than the one being dialed.
		return signPeerHandshake(t, peerPriv, peerID, "captured.example", req.Initiator, req.NonceA), nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "live.example"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signed endpoint")

	for _, p := range kernel.PeerTableSnapshot() {
		assert.NotEqual(t, peerID, p.NodeID, "a redirected handshake must install no session")
	}
}

// TestPeerDialRefusesASelfClaim pins that a peer claiming this node's own identity is
// refused. Without it a node could be talked into a session with itself, and every
// attribution built on the session's node id would be wrong.
func TestPeerDialRefusesASelfClaim(t *testing.T) {
	harness.QuietConsole(t)
	k, selfID, peerPriv := meshBoot(t)

	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		return signPeerHandshake(t, peerPriv, selfID, req.Endpoint, req.Initiator, req.NonceA), nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "self.example"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "own identity")
}

// TestPeerDialRefusesACrossedNonce pins the two-leg binding. A reply carrying a
// different NonceA is a replay or a crossed connection, and accepting it would let a
// captured handshake stand in for a live one.
func TestPeerDialRefusesACrossedNonce(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	peerID := peerNodeName("mesh-replay")

	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		stale := make([]byte, 32)
		copy(stale, req.NonceA)
		stale[0] ^= 0xff
		return signPeerHandshake(t, peerPriv, peerID, req.Endpoint, req.Initiator, stale), nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "replay.example"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce")
}

// TestPeerNonceIsNeverRecorded protects the replay-resistance value from leaking into
// a chain that anything holding audit:read can query. The signature bytes are checked
// for the same reason: both are the material a replayer needs.
func TestPeerNonceIsNeverRecorded(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)

	peerID := peerNodeName("mesh-leak")
	var capturedNonce []byte
	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		capturedNonce = append([]byte(nil), req.NonceA...)
		return signPeerHandshake(t, peerPriv, peerID, req.Endpoint, req.Initiator, req.NonceA), nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "leak.example"})
	require.NoError(t, err)
	require.Len(t, capturedNonce, 32)

	// One refused handshake as well, so the scan covers both the success and the
	// escalation paths.
	_, _, roguePriv := meshKeyPair(t)
	rogueID := peerNodeName("mesh-leak-rogue")
	ft.handshake = func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		return signPeerHandshake(t, roguePriv, rogueID, req.Endpoint, req.Initiator, req.NonceA), nil
	}
	_, err = k.PeerDial(kernel.PeerDialSpec{Endpoint: "leak2.example"})
	require.Error(t, err)

	nonceHex := hex.EncodeToString(capturedNonce)
	for _, e := range auditEntries(t, "") {
		enc, merr := json.Marshal(e.Fields)
		require.NoError(t, merr)
		assert.NotContains(t, string(enc), nonceHex, "seq %d leaks the nonce in hex", e.Seq)
		assert.NotContains(t, e.Msg, nonceHex)
		for key, v := range e.Fields {
			assert.NotEqual(t, "nonce", key, "no audit field may be named nonce")
			assert.NotEqual(t, "nonce_a", key)
			assert.NotEqual(t, "signature", key)
			if s, ok := v.(string); ok {
				assert.NotContains(t, s, nonceHex)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Probing: monotonic time, mandatory deadlines, bounded ledgers.

// TestPeerProbeRequiresADeadline pins the no-untimed-wait rule klock established. An
// untimed wait on an unreachable peer is a hung goroutine nobody can cancel.
func TestPeerProbeRequiresADeadline(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	ft := &fakeTransport{}
	require.NoError(t, k.PeerSetTransport(ft))

	for _, deadline := range []int64{0, -1} {
		_, err := k.PeerProbe(sess.FD, deadline)
		require.Error(t, err, "deadline %d must be refused", deadline)
		assert.Contains(t, err.Error(), "requires a deadline on the monotonic clock")
	}
	assert.Zero(t, ft.callCount(), "a refused probe must not reach the transport")
}

// TestPeerProbeTimesOutWithoutHanging pins that a peer which never answers produces
// ErrPeerTimeout at the deadline rather than a hung call, and that the timeout is
// recorded exactly once.
func TestPeerProbeTimesOutWithoutHanging(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	// The transport never answers and ignores the deadline it was given, so the only
	// thing that can end this call is the kernel's own timer. That is the guarantee
	// under test - "kpeer does not trust the host's deadline and times every wait
	// itself" - and a fake that honoured the deadline would not test it.
	block := make(chan struct{})
	unblock := closeOnce(block)
	t.Cleanup(unblock)
	ft := &fakeTransport{blockOn: block, ignoreDeadline: true}
	require.NoError(t, k.PeerSetTransport(ft))

	before := countAudit(t, kernel.AuditPeer, "peer probe timed out")
	beforeTimeouts := kernel.PeerStatsSnapshot().ProbeTimeouts
	start := time.Now()
	_, err := k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(30*time.Millisecond))
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerTimeout), "want ErrPeerTimeout, got %v", err)

	// The house shape for a deadline assertion, copied from the klock timeout tests:
	// bound it on both sides so a deadline that never arrives and one that arrives
	// instantly are both failures. The upper bound is generous because this runs
	// under -race with the rest of the package; what it pins is that the call
	// returned at the deadline rather than waiting for the host.
	assert.GreaterOrEqual(t, time.Since(start), 30*time.Millisecond)
	assert.Less(t, time.Since(start), 30*time.Second)

	assert.Equal(t, before+1, countAudit(t, kernel.AuditPeer, "peer probe timed out"),
		"one timed-out probe must write exactly one record")
	assert.Equal(t, beforeTimeouts+1, kernel.PeerStatsSnapshot().ProbeTimeouts,
		"and count exactly one timeout")

	lat, ok := kernel.PeerLatencyOf(sess.NodeID)
	require.True(t, ok)
	assert.Equal(t, int64(1), lat.Timeouts)

	// The host never answered, so the session is still usable and its inflight slot
	// came back: a wedged transport saturates the budget and then refuses, it does not
	// consume it permanently.
	unblock()
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))
	_, err = k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err, "the slot must be released when the kernel's timer fires")
}

// TestPeerProbeIsMeasuredOnTheMonotonicClock pins the guarantee that an NTP step
// cannot make a probe lie. The assertion is bounded rather than an equality, because
// an equality against a surrounding Mono() difference is a flake factory under -race;
// what the property actually requires is that the reading is positive, that it does
// not exceed the interval the call really occupied, and that no field of PeerLatency
// is derived from a wall clock.
func TestPeerProbeIsMeasuredOnTheMonotonicClock(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	before := kernel.KernelClock().Mono()
	lat, err := k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)
	after := kernel.KernelClock().Mono()

	assert.Greater(t, lat.RTTNanos, int64(0), "a measured round trip must be positive")
	assert.LessOrEqual(t, lat.RTTNanos, after-before,
		"the RTT must fit inside the interval the call actually occupied")
	assert.Equal(t, int64(1), lat.Samples)
	assert.Greater(t, lat.EWMANanos, int64(0), "the first sample seeds the moving average")
	assert.GreaterOrEqual(t, lat.LastMono, before, "LastMono is a mono() reading, not a wall clock")
	assert.LessOrEqual(t, lat.LastMono, after)
	assert.Zero(t, lat.Timeouts)
}

// TestPeerLatencySamplesTrimInOneStep protects against the ledger bug returning.
// Trimming exactly to the bound would copy the whole sample ledger under the lock on
// every probe past the ceiling, which is O(n) per probe forever on the hottest path
// in the subsystem. The batch drop to seven eighths is what makes it amortized
// constant, and the assertion is on the retained count rather than on timing.
func TestPeerLatencySamplesTrimInOneStep(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	const bound = 64 // maxPeerLatencySamples
	for range bound {
		_, err := k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(time.Second))
		require.NoError(t, err)
	}
	lat, ok := kernel.PeerLatencyOf(sess.NodeID)
	require.True(t, ok)
	assert.Equal(t, int64(bound), lat.Samples, "at the bound nothing is trimmed yet")

	_, err := k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, err)

	lat, ok = kernel.PeerLatencyOf(sess.NodeID)
	require.True(t, ok)
	// One step back to seven eighths, not one record at a time. The ledger is
	// trimmed after the new sample is appended, so the retained count is exactly
	// the batch target: a per-insert trim would leave 64.
	assert.Equal(t, int64(bound-bound/8), lat.Samples,
		"one probe past the bound must drop the ledger to seven eighths in a single step")
}

// TestPeerEventLedgerTrimsInOneStep is the same contract on the mesh event ledger,
// read through the snapshot so the assertion is on observable state.
func TestPeerEventLedgerTrimsInOneStep(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	const bound = 4096 // maxRetainedPeerEvents
	const batch = bound / 8

	base := len(kernel.PeerEvents())
	baseEvicted := kernel.PeerStatsSnapshot().EventEvicted

	// Each probe records one event, so driving past the bound from wherever the
	// binary currently is exercises the trim without depending on a clean registry.
	needed := bound - base + 1
	for range needed {
		_, err := k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(time.Second))
		require.NoError(t, err)
	}

	stats := kernel.PeerStatsSnapshot()
	assert.Greater(t, stats.EventEvicted, baseEvicted, "the trim must be counted, not silent")
	assert.LessOrEqual(t, len(kernel.PeerEvents()), bound)
	// A one-record-per-insert trim would leave evicted at exactly the overflow. A
	// batch trim evicts at least a full batch at once, which is the observable
	// difference between the two implementations.
	assert.GreaterOrEqual(t, stats.EventEvicted-baseEvicted, int64(batch),
		"eviction must happen in batches of seven eighths, not one record at a time")
}

// TestPeerProbeWritesNoAuditRecordOnSuccess pins that telemetry does not evict
// evidence. At one probe per second across a full mesh a per-probe record would push
// the real evidence out of the in-memory window, so a successful probe writes to the
// event ledger only and a timeout writes to the chain.
func TestPeerProbeWritesNoAuditRecordOnSuccess(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	beforeAudit := countAudit(t, kernel.AuditPeer, "")
	beforeProbes := kernel.PeerStatsSnapshot().Probes
	for range 5 {
		_, err := k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(time.Second))
		require.NoError(t, err)
	}
	assert.Equal(t, beforeAudit, countAudit(t, kernel.AuditPeer, ""),
		"successful probes must not write to the audit chain")

	// Deltas rather than absolutes: the counters are kernel state, and a suite that
	// asserts an absolute count is really asserting that no earlier test ran.
	assert.Equal(t, int64(5), kernel.PeerStatsSnapshot().Probes-beforeProbes,
		"a probe that writes no record must still be counted")
	assert.NotEmpty(t, kernel.PeerEvents(), "and it must land in the event ledger")
}

// ---------------------------------------------------------------------------
// Forwarding: the service.go boundary, seen from the mesh side.

// TestPeerForwardDispatchesUnderTheForwarderContextNotTheCaller pins that a request
// arriving from another node does not lend the accepting node's authority to the
// handler. The handler runs under its own grants, and the caller it sees is the local
// forwarding context rather than anything the remote peer chose.
func TestPeerForwardDispatchesUnderTheForwarderContextNotTheCaller(t *testing.T) {
	harness.QuietConsole(t)
	k, selfID, peerPriv := meshBoot(t)

	const route = "/mesh/echo"
	var gotCaller kernel.PID
	var gotModule string
	var gotTrace kernel.TraceID
	var secretErr error
	handler := &msProbe{serve: func(ctx kernel.SContext, req kernel.RouteRequest) (kernel.RouteResponse, error) {
		gotCaller = req.CallerPID
		gotModule = req.CallerModule
		gotTrace = req.Trace
		// The handler runs as itself, so a credential it was never granted stays
		// refused even though the request arrived through a privileged local path.
		_, secretErr = ctx.SyscallSecretUse("mesh-token", kernel.SecretActionMatch, []byte("x"))
		return kernel.RouteResponse{Status: 200, Payload: append([]byte("echo:"), req.Payload...)}, nil
	}}
	msLoadNamed(t, k, handler, peerNodeName("mesh-handler"),
		kernel.Manifest{
			Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
			Require:     []kernel.Op{kernel.OpRouteRegister, kernel.OpRouteCall},
			ServeRoutes: []string{route},
		})
	handler.serveRoute(t)

	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	trace, err := kernel.NewTraceID()
	require.NoError(t, err)
	frame := signPeerForward(t, peerPriv, selfID, route, "POST", string(trace), []byte("hello mesh"))

	reply, err := k.PeerDeliver("remote-node", frame)
	require.NoError(t, err)
	require.Equal(t, kernel.PeerFrameForwardReply, reply.Kind)

	var resp kernel.RouteResponse
	require.NoError(t, json.Unmarshal(reply.Body, &resp))
	assert.Equal(t, 200, resp.Status)
	assert.Equal(t, "echo:hello mesh", string(resp.Payload))

	assert.Equal(t, k.InitContext().PID(), gotCaller,
		"the caller a forwarded request names is the local forwarding context, not a remote pid")
	// RouteCall assigns CallerModule from the calling context, so it is init's name
	// and not a mesh label. That is not a gap to work around but the property: a
	// handler cannot distinguish mesh traffic from local traffic by reading the
	// request, and provenance is on the audit chain instead, asserted below.
	assert.Equal(t, "init", gotModule,
		"the caller module is kernel-assigned from the forwarding context")
	assert.Equal(t, trace, gotTrace, "the remote trace id is carried through as a correlation id")
	require.Error(t, secretErr, "the handler must run under its own grants")
	assert.True(t, kernel.IsDenied(secretErr))

	msgs := auditMsgs(t, kernel.AuditPeer)
	assert.Contains(t, msgs, "peer forward accepted",
		"the mesh fact must be on the chain before the dispatch result reaches the caller")
}

// TestPeerForwardRefusesAnUntrustedEnvelope pins that one altered byte in the
// signature stops the request before any handler runs. This is the control that makes
// a cross-node request attributable to the node that sent it.
func TestPeerForwardRefusesAnUntrustedEnvelope(t *testing.T) {
	harness.QuietConsole(t)
	k, selfID, peerPriv := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	var handlerRan atomic.Bool
	const route = "/mesh/tampered"
	handler := &msProbe{serve: func(ctx kernel.SContext, req kernel.RouteRequest) (kernel.RouteResponse, error) {
		handlerRan.Store(true)
		return kernel.RouteResponse{Status: 200}, nil
	}}
	msLoadNamed(t, k, handler, peerNodeName("mesh-tamper"),
		kernel.Manifest{
			Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
			Require:     []kernel.Op{kernel.OpRouteRegister, kernel.OpRouteCall},
			ServeRoutes: []string{route},
		})
	handler.serveRoute(t)

	frame := signPeerForward(t, peerPriv, selfID, route, "", "", []byte("x"))
	tampered := mutateEnvelope(t, frame, func(env *kernel.PeerEnvelope) {
		// Flip one byte of the signature: the envelope is now a claim no root verifies.
		env.Signature[0] ^= 0xff
	})

	_, err := k.PeerDeliver("remote-node", tampered)
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerUntrusted), "want ErrPeerUntrusted, got %v", err)
	assert.False(t, handlerRan.Load(), "a tampered envelope must never reach a handler")

	var saw bool
	for _, e := range auditEntries(t, kernel.AuditEscalation) {
		if strings.Contains(e.Msg, "inbound forward failed verification") {
			saw = true
		}
	}
	assert.True(t, saw, "an unverifiable forward is an escalation and must be on the chain")
}

// TestPeerForwardBindsThePayloadDigest pins that signing the digest is not
// decorative. The signature stays valid over the envelope while the payload is
// swapped for different bytes of the same length, which is exactly the substitution a
// relay would attempt.
func TestPeerForwardBindsThePayloadDigest(t *testing.T) {
	harness.QuietConsole(t)
	k, selfID, peerPriv := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	var gotPayload string
	const route = "/mesh/swap"
	handler := &msProbe{serve: func(ctx kernel.SContext, req kernel.RouteRequest) (kernel.RouteResponse, error) {
		gotPayload = string(req.Payload)
		return kernel.RouteResponse{Status: 200}, nil
	}}
	msLoadNamed(t, k, handler, peerNodeName("mesh-swap"),
		kernel.Manifest{
			Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
			Require:     []kernel.Op{kernel.OpRouteRegister, kernel.OpRouteCall},
			ServeRoutes: []string{route},
		})
	handler.serveRoute(t)

	frame := signPeerForward(t, peerPriv, selfID, route, "", "", []byte("good"))
	swapped := mutateEnvelope(t, frame, func(env *kernel.PeerEnvelope) {
		// Same length, different bytes, signature and PayloadHash untouched. This is
		// the substitution a relay would attempt, and it is caught by the hash.
		env.Payload = []byte("EVIL")
	})

	_, err := k.PeerDeliver("remote-node", swapped)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match its signed digest")
	assert.Empty(t, gotPayload, "the substituted payload must never reach the handler")
}

// TestPeerForwardRefusesAnotherNodesTarget pins that this node is not an open relay.
// Forwarding traffic addressed elsewhere would attribute it to a node with no policy
// relationship to either end, which is how a mesh becomes an amplification target.
func TestPeerForwardRefusesAnotherNodesTarget(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	var handlerRan atomic.Bool
	ft := &fakeTransport{forward: func(frame kernel.PeerFrame) (kernel.PeerFrame, error) {
		var env peerEnvelope
		require.NoError(t, json.Unmarshal(frame.Body, &env))
		env.ToNode = "some-third-node"
		body, err := json.Marshal(env)
		require.NoError(t, err)
		relayed := frame
		relayed.Body = body
		_, derr := k.PeerDeliver("attacker", relayed)
		require.Error(t, derr)
		assert.True(t, errors.Is(derr, kernel.ErrPeerLoop), "want ErrPeerLoop, got %v", derr)
		handlerRan.Store(true)
		return kernel.PeerFrame{}, derr
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerForward(kernel.PeerForwardRequest{
		NodeID: sess.NodeID, Route: "/mesh/relay", Payload: []byte("x"), TimeoutMillis: 5000,
	})
	require.Error(t, err)
	assert.True(t, handlerRan.Load(), "the inbound refusal must have been exercised")
}

// TestPeerForwardRefusesALogForgingRoute pins the ingest-time string validation. A
// correctly signed envelope from a trusted peer can still carry a route containing a
// newline, and audit fields are written verbatim, so the filter has to run before the
// first audit write rather than after it.
func TestPeerForwardRefusesALogForgingRoute(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	ft := &fakeTransport{forward: func(frame kernel.PeerFrame) (kernel.PeerFrame, error) {
		var env peerEnvelope
		require.NoError(t, json.Unmarshal(frame.Body, &env))
		env.Route = "/mesh/ok\nINJECTED fault line"
		env.PayloadHash = sha256Hex(env.Payload)
		body, err := json.Marshal(env)
		require.NoError(t, err)
		forged := frame
		forged.Body = body
		_, derr := k.PeerDeliver("attacker", forged)
		require.Error(t, derr)
		assert.Contains(t, derr.Error(), "control or non-ASCII")
		return kernel.PeerFrame{}, derr
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerForward(kernel.PeerForwardRequest{
		NodeID: sess.NodeID, Route: "/mesh/forge", Payload: []byte("x"), TimeoutMillis: 5000,
	})
	require.Error(t, err)

	for _, e := range auditEntries(t, "") {
		assert.NotContains(t, e.Msg, "INJECTED", "seq %d carries a forged line", e.Seq)
		enc, merr := json.Marshal(e.Fields)
		require.NoError(t, merr)
		assert.NotContains(t, string(enc), "INJECTED\n", "audit fields must not carry the injected newline")
	}
}

// TestPeerForwardRefusesAnOversizedPayload pins the borrowed kservice ceiling on the
// outbound side, and that the transport is never reached for a request the kernel
// will not send.
func TestPeerForwardRefusesAnOversizedPayload(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	ft := &fakeTransport{}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerForward(kernel.PeerForwardRequest{
		NodeID: sess.NodeID, Route: "/mesh/big",
		Payload: make([]byte, 8*1024*1024+1), TimeoutMillis: 5000,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerLimit), "want ErrPeerLimit, got %v", err)
	assert.Zero(t, ft.callCount(), "a refused forward must not reach the transport")
}

// TestPeerForwardRefusesTheHopCeiling pins the loop bound.
func TestPeerForwardRefusesTheHopCeiling(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	ft := &fakeTransport{}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerForward(kernel.PeerForwardRequest{
		NodeID: sess.NodeID, Route: "/mesh/hops", Hops: 9, TimeoutMillis: 5000,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hop count")
	assert.Zero(t, ft.callCount())
}

// TestPeerForwardToAnUnknownNodeIsTyped pins that "no session with this node" is
// distinguishable from a timeout or a refusal, because the correct responses differ:
// an unknown node means dial first, a timeout means shed load.
func TestPeerForwardToAnUnknownNodeIsTyped(t *testing.T) {
	harness.QuietConsole(t)
	k, _, _ := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	_, err := k.PeerForward(kernel.PeerForwardRequest{
		NodeID: peerNodeName("never-dialed"), Route: "/mesh/x", TimeoutMillis: 1000,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerUnknown), "want ErrPeerUnknown, got %v", err)
}

// ---------------------------------------------------------------------------
// Handles, ceilings, and the inbound boundary.

// TestPeerSessionHandleIsKindChecked pins the two halves of the handle contract that
// are actually reachable, and states why the third is not.
//
// A module passing its own pipe handle to a peer entry point is refused by the policy
// check before the kind check runs, because no module holds peer:dial. And the host
// path resolves handles in init's table, where init can open no fd of any kind - it
// holds none of the resource operations - so the only handles there are peer handles.
// The kind check is therefore defence in depth behind a policy gate, not a reachable
// refusal today, and asserting a "not a peer" message from either path would be
// asserting a branch no caller can enter.
//
// What is asserted instead is the pair of facts the check is built from: the handle
// reports the constant kind the check compares against, and a foreign handle is
// refused rather than reinterpreted.
func TestPeerSessionHandleIsKindChecked(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	// The handle carries the constant kind install() caches, which is what a kind
	// check compares against. If this drifted, every peer handle would fail its own
	// subsystem's check.
	var found bool
	for _, info := range kernel.FDList(k.InitContext().PID()) {
		if info.FD == sess.FD {
			found = true
			assert.Equal(t, "peer", info.Kind, "a peer handle must report kind peer")
			assert.Contains(t, info.Label, sess.NodeID, "the label must name the session")
		}
	}
	require.True(t, found, "the session handle must be in the fd table")

	// A handle from another subsystem, passed by a module that owns it, is refused
	// before any reinterpretation. The refusal is the policy gate, and that it is a
	// gate rather than a crash is the property: a pipe fd is never treated as a peer.
	_, mod := msLoad(t, k, nil, kernel.OpPipeOpen)
	pipeFD, err := mod.ctx.SyscallOpenPipe("kind-check", 0, kernel.PipeNonBlocking)
	require.NoError(t, err)

	_, err = kernel.PeerProbe(mod.ctx, pipeFD, kernel.KernelClock().Deadline(time.Second))
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err),
		"a foreign handle must be refused at the gate, not reinterpreted: %v", err)

	// And a handle that was never issued is not a session either.
	_, err = k.PeerProbe(kernel.FD(999999), kernel.KernelClock().Deadline(time.Second))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not open in pid")
}

// TestPeerSessionCloseIsIdempotentBothWays pins the two double-close paths reclamation
// depends on: through the fd table a second close reports "not open", and on the
// resource object it reports errClosed. Code that handles only one of them reports a
// spurious failure during unload.
func TestPeerSessionCloseIsIdempotentBothWays(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	require.NoError(t, k.InitContext().SyscallClose(sess.FD))

	err := k.InitContext().SyscallClose(sess.FD)
	require.Error(t, err, "a second close through the fd table must fail")
	assert.Contains(t, err.Error(), "is not open in pid")

	// The session is gone from the mesh table, which is what makes the close
	// observable rather than only a handle-table bookkeeping event.
	for _, p := range kernel.PeerTableSnapshot() {
		assert.NotEqual(t, sess.NodeID, p.NodeID, "a closed session must leave the mesh table")
	}

	// And a probe against the closed handle fails rather than hanging.
	_, err = k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(time.Second))
	require.Error(t, err)
}

// TestPeerSessionCloseWakesABlockedProbe pins the broadcast-outside-the-state-mutex
// requirement. Without it, closing a session strands whatever was waiting on it, and
// the unload path leaks a goroutine per in-flight exchange.
func TestPeerSessionCloseWakesABlockedProbe(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	block := make(chan struct{})
	t.Cleanup(closeOnce(block))
	require.NoError(t, k.PeerSetTransport(&fakeTransport{blockOn: block}))

	// A deadline long enough that the close, not the timer, is what ends the call.
	done := make(chan error, 1)
	go func() {
		_, err := k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(10*time.Second))
		done <- err
	}()

	// Give the probe time to enter the exchange. This is not a timing assertion: the
	// test fails by hanging, not by observing the wrong duration, and the deadline
	// above bounds the hang.
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, k.InitContext().SyscallClose(sess.FD))

	select {
	case err := <-done:
		require.Error(t, err, "a closed session must end the blocked probe with an error")
		assert.True(t, errors.Is(err, kernel.ErrPeerGone),
			"the wake must come from the close, not from the 10s deadline: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("closing the session did not wake the blocked probe")
	}

	// The in-flight slot must be released when the caller returns rather than when the
	// host's Exchange eventually does, or a wedged transport would hold its budget
	// hostage past the close. The session is gone, so the observable proof is that a
	// fresh session against an answering transport probes successfully immediately
	// afterwards: the per-peer and total budgets were not left consumed.
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))
	fresh := dialWith(t, k, peerPriv, peerNodeName("mesh-after-close"), "after-close.example")
	_, probeErr := k.PeerProbe(fresh.FD, kernel.KernelClock().Deadline(time.Second))
	require.NoError(t, probeErr, "the budget must be released when the caller returns")

	// A session closed underneath a probe is local teardown, not a peer that failed to
	// answer, so it must not be counted as a timeout.
	assert.Zero(t, kernel.PeerStatsSnapshot().ProbeTimeouts,
		"a close must not be recorded as a peer timeout")
}

// TestPeerTableRefusesRatherThanEvicts pins that a full mesh refuses a new peer
// instead of dropping an existing one. Silently evicting a peer to make room for an
// announcer is how an attacker empties the honest mesh, and a refusal is visible while
// an eviction is not.
func TestPeerTableRefusesRatherThanEvicts(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	existing := make(map[string]bool)
	for _, p := range kernel.PeerTableSnapshot() {
		existing[p.NodeID] = true
	}

	// Fill from wherever the binary currently is, so the assertion does not depend on
	// the registry having been reset by an earlier test.
	for len(kernel.PeerTableSnapshot()) < kernel.MaxPeers() {
		dialWith(t, k, peerPriv, peerNodeName("mesh-fill"), "fill.example")
	}
	require.Len(t, kernel.PeerTableSnapshot(), kernel.MaxPeers())

	// One more peer, signed by a key that IS in the roots, so the refusal is the
	// ceiling and not a verification failure. dialWith asserts success, so the
	// overflow dial is made directly here.
	overflow := peerNodeName("mesh-overflow")
	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		return signPeerHandshake(t, peerPriv, overflow, "overflow.example", req.Initiator, req.NonceA), nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))
	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "overflow.example", TimeoutMillis: 5000})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerLimit), "want ErrPeerLimit, got %v", err)

	for _, p := range kernel.PeerTableSnapshot() {
		existing[p.NodeID] = false
	}
	for id, gone := range existing {
		assert.False(t, gone, "peer %q was evicted to make room", id)
	}
	assert.Len(t, kernel.PeerTableSnapshot(), kernel.MaxPeers(), "the table must not grow past its ceiling")
}

// TestPeerAnnouncementRequiresASignature pins that an unsigned announcement is
// refused. The peer table decides where forwarded work goes, so an unsigned entry is
// not a discovery convenience but a hijack.
func TestPeerAnnouncementRequiresASignature(t *testing.T) {
	harness.QuietConsole(t)
	k, _, _ := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	err := k.PeerAnnounce(kernel.PeerAnnouncement{
		Version: kernel.PeerVersion, NodeID: peerNodeName("mesh-unsigned"),
		Endpoint: "unsigned.example", Seq: 1, TTLNanos: int64(time.Minute),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no signature")
}

// TestPeerAnnouncementRefusesASequenceRewind pins the replay control on discovery. An
// announcement numbered at or below one already accepted is either a replay or a peer
// that restarted, and silently accepting it would let a captured announcement reinsert
// a stale endpoint.
func TestPeerAnnouncementRefusesASequenceRewind(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	peerID := peerNodeName("mesh-announce")
	signed := func(seq int64) kernel.PeerAnnouncement {
		a := kernel.PeerAnnouncement{
			Version: kernel.PeerVersion, NodeID: peerID, Endpoint: "announce.example",
			KeyID: "peer-key", Seq: seq, TTLNanos: int64(time.Minute),
		}
		a.Signature = ed25519.Sign(peerPriv, kernel.PeerAnnouncePayload(a))
		return a
	}

	require.NoError(t, k.PeerAnnounce(signed(7)))
	require.Error(t, k.PeerAnnounce(signed(7)), "a repeated sequence is a replay")
	require.Error(t, k.PeerAnnounce(signed(3)), "a rewound sequence must be refused")
	require.NoError(t, k.PeerAnnounce(signed(8)), "a strictly later sequence is accepted")

	var saw bool
	for _, e := range auditEntries(t, kernel.AuditEscalation) {
		if strings.Contains(e.Msg, "announcement sequence rewound") {
			saw = true
		}
	}
	assert.True(t, saw, "a rewind is an escalation, not a peer fact")
}

// TestPeerFieldValidationRefusesForgedLines pins the log-forgery filters on the three
// fields that reach audit lines and console output verbatim.
//
// These are the controls that stop a peer from writing a second log line inside one
// record, and they had no test: mutation-testing this suite showed that deleting
// peerLabel's line-break check and peerMethodField's rune filter entirely left every
// existing test green. A filter nobody asserts on is a filter that can be removed by
// accident, so each one is driven through the public entry point that validates it.
//
// The three are deliberately not the same rule, and the test pins the difference rather
// than flattening it. A node id and an endpoint are identifiers: they index the mesh
// table, appear in avc-shaped fault lines, and are compared for equality by peers, so
// they get the strict filter. A label is prose an operator typed - "peer one", "us-east
// fallback" - and refusing a space in it would make the field useless for its only
// purpose, so it is bounded and line-break-free only. An inbound method is chosen by a
// remote peer, not by an operator, so it gets the identifier filter even though it is
// only a label in the record.
func TestPeerFieldValidationRefusesForgedLines(t *testing.T) {
	harness.QuietConsole(t)
	k, selfID, peerPriv := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	// --- the label: an operator's prose field. A space is fine, a newline is not. ---
	// The accepted case needs a transport that answers the handshake, because the dial
	// has to complete for the label to be observable on the session. The refused cases
	// below need none: validation runs before the transport is consulted, which is
	// itself worth knowing - a malformed label never reaches the host.
	const labelEndpoint = "label.example"
	require.NoError(t, k.PeerSetTransport(&fakeTransport{
		handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
			return signPeerHandshake(t, peerPriv, peerNodeName("mesh-label"),
				labelEndpoint, req.Initiator, req.NonceA), nil
		},
	}))
	okSess, err := k.PeerDial(kernel.PeerDialSpec{
		Endpoint: labelEndpoint, Label: "us-east fallback, primary",
	})
	require.NoError(t, err, "a label with spaces and punctuation must be accepted")
	assert.Equal(t, "us-east fallback, primary", okSess.Label)

	for _, tc := range []struct{ name, label string }{
		{"newline", "peer\nINJECTED fault line"},
		{"carriage return", "peer\rINJECTED"},
		{"over the ceiling", strings.Repeat("x", 129)},
	} {
		t.Run("label "+tc.name, func(t *testing.T) {
			_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "label.example", Label: tc.label})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "peer label")
			assert.False(t, kernel.IsDenied(err),
				"a shape refusal is not a policy denial: %v", err)
		})
	}

	// From here on nothing may reach the host: every case below is a shape refusal, and
	// a non-answering transport is what proves it. A validation that ran after the
	// transport lookup would still refuse, but it would refuse too late.
	ft := &fakeTransport{}
	require.NoError(t, k.PeerSetTransport(ft))

	// --- the endpoint and the node id: identifiers, strict filter. ---
	for _, tc := range []struct{ name, endpoint string }{
		{"empty", ""},
		{"newline", "peer.example\nINJECTED"},
		{"tab", "peer\texample"},
		{"non-ascii", "peer-\u00e9xample.example"},
		{"over the ceiling", strings.Repeat("e", 257)},
	} {
		t.Run("endpoint "+tc.name, func(t *testing.T) {
			_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: tc.endpoint})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "peer endpoint")
		})
	}

	// --- the inbound method: remote-controlled, so the identifier filter applies. ---
	// Driven through the real inbound path: the test plays the remote node and signs an
	// envelope carrying the method, so the filter is exercised where it actually runs.
	for _, tc := range []struct{ name, method string }{
		{"newline", "POST\nINJECTED audit line"},
		{"carriage return", "POST\rINJECTED"},
		{"tab", "PO\tST"},
		{"non-ascii", "P\u00d6ST"},
		{"over the ceiling", strings.Repeat("M", 129)},
	} {
		t.Run("method "+tc.name, func(t *testing.T) {
			before := countAudit(t, kernel.AuditPeer, "peer forward refused")
			frame := signPeerForward(t, peerPriv, selfID, "/mesh/x", tc.method, "", []byte("body"))
			_, err := k.PeerDeliver("remote-node", frame)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "forward method",
				"the refusal must name the field that failed, not a generic shape error")
			assert.Greater(t, countAudit(t, kernel.AuditPeer, "peer forward refused"), before,
				"a refused inbound frame must be recorded")
		})
	}

	assert.Zero(t, ft.callCount(),
		"a shape refusal must never reach the host transport")

	// An empty method is accepted: it means the peer named no verb, and the record says
	// so rather than inventing one. What is refused is a method that could forge a line.
	frame := signPeerForward(t, peerPriv, selfID, "/mesh/x", "", "", []byte("body"))
	_, err = k.PeerDeliver("remote-node", frame)
	assert.NotContains(t, fmt.Sprint(err), "forward method",
		"an empty method is not a shape violation: %v", err)
}

// TestPeerAnnounceEpochDistinguishesARestartFromAReplay pins the reason the epoch field
// exists. A bare sequence check cannot tell an honest peer that restarted and began
// numbering from 1 again from a captured announcement being replayed, and it would refuse
// the honest one forever. The epoch resolves the ambiguity in one direction only: a newer
// epoch resets the baseline, and within an epoch the sequence must still strictly
// increase.
func TestPeerAnnounceEpochDistinguishesARestartFromAReplay(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	peerID := peerNodeName("mesh-epoch")
	signed := func(epoch, seq int64) kernel.PeerAnnouncement {
		a := kernel.PeerAnnouncement{
			Version: kernel.PeerVersion, NodeID: peerID, Endpoint: "epoch.example",
			KeyID: "peer-key", Seq: seq, Epoch: epoch, TTLNanos: int64(time.Minute),
		}
		a.Signature = ed25519.Sign(peerPriv, kernel.PeerAnnouncePayload(a))
		return a
	}

	// One boot, counting up.
	require.NoError(t, k.PeerAnnounce(signed(100, 1)))
	require.NoError(t, k.PeerAnnounce(signed(100, 2)))

	// A replay of either, under the same epoch, is refused.
	require.Error(t, k.PeerAnnounce(signed(100, 2)), "a repeated sequence is a replay")
	require.Error(t, k.PeerAnnounce(signed(100, 1)), "a rewound sequence is a replay")

	// The peer restarts. Its epoch moves forward and its numbering begins again, which
	// must be ACCEPTED: this is the honest case a bare sequence check would refuse
	// forever.
	require.NoError(t, k.PeerAnnounce(signed(200, 1)),
		"a newer epoch must reset the sequence baseline")
	require.NoError(t, k.PeerAnnounce(signed(200, 2)))

	// Within the new epoch the old rules still apply.
	require.Error(t, k.PeerAnnounce(signed(200, 1)), "the reset baseline is not a licence to replay")

	// And an announcement from the OLD epoch is refused even though its sequence is
	// higher, because accepting it would let a captured pre-restart announcement
	// reinsert a stale endpoint after the peer has moved on.
	err := k.PeerAnnounce(signed(100, 9))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "older than")

	var sawRewind bool
	for _, e := range auditEntries(t, kernel.AuditEscalation) {
		if e.Msg == "peer announcement sequence rewound" {
			sawRewind = true
		}
	}
	assert.True(t, sawRewind, "a replay attempt is an escalation, not a peer fact")
}

// TestPeerHandshakeCarriesThisNodesEpoch pins that the epoch is inside the signed
// handshake. An epoch a peer could rewrite would let it reset the sequence baseline at
// will, which is the whole control the field exists to support.
func TestPeerHandshakeCarriesThisNodesEpoch(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)

	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		assert.NotZero(t, req.Epoch, "the dial must carry this node's boot identity")
		// The epoch is part of what the reply signs, so a peer echoing a different
		// one produces a signature this node will not accept for the handshake it
		// actually sent.
		h := signPeerHandshake(t, peerPriv, peerNodeName("mesh-epoch-peer"),
			req.Endpoint, req.Initiator, req.NonceA)
		h.Epoch = req.Epoch
		h.Signature = ed25519.Sign(peerPriv, kernel.PeerHandshakePayload(h))
		return h, nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "epoch.example"})
	require.NoError(t, err)
	require.Equal(t, 1, ft.callCount())

	var sent kernel.PeerHandshake
	require.NoError(t, json.Unmarshal(ft.calls[0].Body, &sent))
	assert.NotZero(t, sent.Epoch)

	// The encoding the signature covers includes the epoch, which is what makes it
	// unrewritable. Two handshakes differing only in epoch must encode differently.
	other := sent
	other.Epoch = sent.Epoch + 1
	assert.NotEqual(t, kernel.PeerHandshakePayload(sent), kernel.PeerHandshakePayload(other),
		"the epoch must be inside the signed payload")
}

// TestPeerAnnouncementRejectsABadTTL pins that the lifetime bound is enforced at
// ingest. An unbounded TTL would let a peer install a table entry that outlives every
// restart of itself.
func TestPeerAnnouncementRejectsABadTTL(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	for _, ttl := range []int64{0, -1, int64(48 * time.Hour)} {
		peerID := peerNodeName("mesh-ttl")
		a := kernel.PeerAnnouncement{
			Version: kernel.PeerVersion, NodeID: peerID, Endpoint: "ttl.example",
			KeyID: "peer-key", Seq: 1, TTLNanos: ttl,
		}
		a.Signature = ed25519.Sign(peerPriv, kernel.PeerAnnouncePayload(a))

		err := k.PeerAnnounce(a)
		require.Error(t, err, "ttl %d must be refused", ttl)
		assert.Contains(t, err.Error(), "ttl")
	}
}

// TestPeerDeliverIsOnlyReachableFromTheHost pins the inbound boundary behaviourally.
// A module has no frame-delivery method on its context and never holds a *Kernel, so
// there is no call shape in which a module injects a frame and the kernel treats it as
// a peer's claim. The assertion is on what a module can actually do, not on a method
// set enumeration an external package cannot perform.
func TestPeerDeliverIsOnlyReachableFromTheHost(t *testing.T) {
	harness.QuietConsole(t)
	k, selfID, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)

	var moduleErrs []error
	_, mod := msLoad(t, k, func(ctx kernel.SContext) error {
		// Every mesh entry point a module can reach is a denial. There is no
		// delivery entry point to call, which is the property: the compile would
		// fail if one existed on SContext.
		_, e1 := kernel.PeerDial(ctx, kernel.PeerDialSpec{Endpoint: "x.example"})
		e2 := kernel.PeerAnnounce(ctx, kernel.PeerAnnouncement{Version: kernel.PeerVersion, NodeID: "x", Seq: 1})
		_, e3 := kernel.PeerProbe(ctx, sess.FD, kernel.KernelClock().Deadline(time.Second))
		_, e4 := kernel.PeerForward(ctx, kernel.PeerForwardRequest{NodeID: sess.NodeID, Route: "/x"})
		_, e5 := kernel.PeerPeers(ctx)
		moduleErrs = append(moduleErrs, e1, e2, e3, e4, e5)
		return nil
	})
	require.NotNil(t, mod.ctx)
	require.Len(t, moduleErrs, 5)
	for i, err := range moduleErrs {
		require.Error(t, err, "mesh entry point %d must be refused to a module", i)
		assert.True(t, kernel.IsDenied(err), "entry point %d: want a policy denial, got %v", i, err)
	}

	// The host path is the one that works, which is what makes the asymmetry real
	// rather than merely an absence.
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))
	_, err := k.PeerProbe(sess.FD, kernel.KernelClock().Deadline(time.Second))
	assert.NoError(t, err)
	assert.NotEqual(t, "", selfID)
}

// TestPeerDeliverRefusesAnUnsolicitedReply pins that a frame kind belonging to an
// outbound exchange cannot arrive unsolicited. Accepting one would let a peer answer a
// question nobody asked.
func TestPeerDeliverRefusesAnUnsolicitedReply(t *testing.T) {
	harness.QuietConsole(t)
	k, _, _ := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	for _, kind := range []kernel.PeerFrameKind{
		kernel.PeerFrameHandshake, kernel.PeerFrameHandshakeReply,
		kernel.PeerFrameProbeReply, kernel.PeerFrameForwardReply,
	} {
		_, err := k.PeerDeliver("anywhere", kernel.PeerFrame{Kind: kind, Seq: 1})
		require.Error(t, err, "frame kind %q must not be accepted unsolicited", kind)
		assert.Contains(t, err.Error(), "not accepted unsolicited")
	}
}

// TestPeerDeliverRefusesAnUnknownFrameKind pins the closed set. A default branch here
// is where an unspecified frame becomes an accepted one, which is the hole usage.go
// exists to warn about.
func TestPeerDeliverRefusesAnUnknownFrameKind(t *testing.T) {
	harness.QuietConsole(t)
	k, _, _ := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	_, err := k.PeerDeliver("anywhere", kernel.PeerFrame{Kind: "smuggle", Seq: 1, Body: []byte("{}")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown peer frame kind")

	// Every kind the kernel does know is listed, so the closed set is asserted
	// rather than assumed.
	assert.ElementsMatch(t, []kernel.PeerFrameKind{
		kernel.PeerFrameHandshake, kernel.PeerFrameHandshakeReply,
		kernel.PeerFrameProbe, kernel.PeerFrameProbeReply,
		kernel.PeerFrameAnnounce, kernel.PeerFrameForward,
		kernel.PeerFrameForwardReply, kernel.PeerFrameGoodbye,
	}, kernel.PeerFrameKinds())
}

// TestPeerDeliverRefusesAnOversizedFrameBody pins the ingress ceiling. Without it this
// call would decode host-fed bytes of any size, and unlike the syscall side there is no
// sealed quota in front of it.
func TestPeerDeliverRefusesAnOversizedFrameBody(t *testing.T) {
	harness.QuietConsole(t)
	k, _, _ := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	_, err := k.PeerDeliver("anywhere", kernel.PeerFrame{
		Kind: kernel.PeerFrameForward, Seq: 1, Body: make([]byte, 1<<20+1),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerLimit), "want ErrPeerLimit, got %v", err)
}

// TestPeerGoodbyeClosesTheLocalSession pins the teardown path, and that a goodbye from
// a node with no session is a no-op rather than a fault: both teardown orders are
// legitimate and a shutdown race must not read as an incident.
func TestPeerGoodbyeClosesTheLocalSession(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))

	_, err := k.PeerDeliver(sess.NodeID, kernel.PeerFrame{Kind: kernel.PeerFrameGoodbye, Seq: 1})
	require.NoError(t, err)

	for _, p := range kernel.PeerTableSnapshot() {
		assert.NotEqual(t, sess.NodeID, p.NodeID, "a goodbye must end the session")
	}

	// An unknown peer's goodbye is quiet.
	_, err = k.PeerDeliver(peerNodeName("never-seen"), kernel.PeerFrame{Kind: kernel.PeerFrameGoodbye, Seq: 1})
	require.NoError(t, err, "a goodbye from an unknown peer is a no-op, not an error")
}

// TestNilTransportIsAnErrorNotAPanic pins that a mesh with no transport refuses every
// operation with a typed error and leaves the kernel usable.
func TestNilTransportIsAnErrorNotAPanic(t *testing.T) {
	harness.QuietConsole(t)
	k, _, _ := meshBoot(t)

	require.Error(t, k.PeerSetTransport(nil), "a nil transport must not be installable")

	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "x.example"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerNoTransport), "want ErrPeerNoTransport, got %v", err)

	_, err = k.PeerForward(kernel.PeerForwardRequest{NodeID: "x", Route: "/x"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerUnknown) || errors.Is(err, kernel.ErrPeerNoTransport),
		"want a typed mesh error, got %v", err)

	// The kernel is still usable, which is the part that matters: a missing
	// transport is a configuration state, not a corruption.
	assert.NotEmpty(t, kernel.ProcTable())
	assert.NoError(t, k.InitContext().SyscallLog(kernel.LogInfo, "kernel still usable"))
}

// TestPeerTransportPanicIsContained pins that host code the kernel does not own cannot
// take it down. The panic is recovered, recorded as a kernel-observed fact, and the
// caller gets an error.
func TestPeerTransportPanicIsContained(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)

	ft := &fakeTransport{panicWith: "transport exploded"}
	require.NoError(t, k.PeerSetTransport(ft))

	_, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: "panic.example", TimeoutMillis: 2000})
	require.Error(t, err, "a panicking transport must produce an error, not a crash")

	_ = peerPriv
	var saw bool
	for _, e := range auditEntries(t, kernel.AuditPanic) {
		if strings.Contains(e.Msg, "peer transport panicked") {
			saw = true
		}
	}
	assert.True(t, saw, "the panic must be on the chain as a kernel-observed fact")

	// And the kernel keeps serving, which is the actual guarantee.
	k2, err := kernel.Boot(kernel.BootConfig{Console: meshDiscard{}})
	if err == nil {
		_ = k2.Shutdown()
	}
	assert.NotEmpty(t, kernel.ProcTable())
}

// TestPeerDeliverIsRefusedAfterShutdown pins that the host handle stops working when
// the kernel stops, so a frame arriving during teardown cannot act on a reset mesh.
func TestPeerDeliverIsRefusedAfterShutdown(t *testing.T) {
	harness.QuietConsole(t)
	k, _, _ := meshBoot(t)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))
	require.NoError(t, k.Shutdown())

	_, err := k.PeerDeliver("anywhere", kernel.PeerFrame{Kind: kernel.PeerFrameProbe, Seq: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shut down")

	_, err = k.PeerDial(kernel.PeerDialSpec{Endpoint: "x.example"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shut down")
}

// TestPeersResetAcrossRestart pins the reset ordering slot. A restarted kernel must not
// inherit the previous boot's mesh: the transport is host configuration that does not
// survive a boot, and a session table that did would let a kernel send frames under a
// node identity it has not re-read.
func TestPeersResetAcrossRestart(t *testing.T) {
	harness.QuietConsole(t)
	k, _, peerPriv := meshBoot(t)
	sess := dialOne(t, k, peerPriv)
	require.NotNil(t, sess.NodeID)
	require.NoError(t, k.PeerSetTransport(&fakeTransport{}))
	require.NoError(t, k.Shutdown())

	// A second kernel, booted with a different identity, must start with no mesh.
	seed2, pub2, priv2 := meshKeyPair(t)
	k2, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{
			NodeID:          peerNodeName("mesh-restart"),
			ClusterRootKeys: []string{pub2},
			SigningKeyPEM:   seed2,
		},
		Console: meshDiscard{},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k2.Shutdown() })

	for _, p := range kernel.PeerTableSnapshot() {
		assert.NotEqual(t, sess.NodeID, p.NodeID, "a session must not survive a restart")
	}
	stats := kernel.PeerStatsSnapshot()
	assert.Zero(t, stats.Peers)
	assert.Zero(t, stats.Accepted)
	assert.Zero(t, stats.Probes)
	assert.Empty(t, kernel.PeerEvents())

	_, err = k2.PeerDial(kernel.PeerDialSpec{Endpoint: "after-restart.example"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrPeerNoTransport),
		"the transport must not survive a restart either: %v", err)

	assert.NotNil(t, priv2)
}

// ---------------------------------------------------------------------------
// Local helpers, following the chLoad/crxLoad pattern the other suites use.

// signPeerForward builds one inbound forward envelope the way the remote peer would:
// addressed to this node, signed with the peer's key over the canonical digest. It
// returns the frame PeerDeliver accepts.
//
// The envelope is constructed here rather than captured from an outbound PeerForward
// and looped back, and the reason is the ToNode field. An outbound envelope is
// addressed to the remote node, so looping it into this kernel's own inbound path is
// correctly refused as ErrPeerLoop - that is the no-open-relay control working. To
// exercise the inbound path honestly the test has to play the remote node, which means
// signing an envelope addressed here.
func signPeerForward(t *testing.T, peerPriv ed25519.PrivateKey, toNode, route, method, trace string, payload []byte) kernel.PeerFrame {
	t.Helper()
	env := kernel.PeerEnvelope{
		Version: kernel.PeerVersion, FromNode: peerNodeName("mesh-remote"), ToNode: toNode,
		Route: route, Method: method, Trace: trace, Hops: 1, Seq: 1, KeyID: "peer-key",
		PayloadHash: sha256Hex(payload), Payload: payload,
	}
	env.Signature = ed25519.Sign(peerPriv, kernel.PeerForwardDigest(env))
	body, err := json.Marshal(env)
	require.NoError(t, err)
	return kernel.PeerFrame{Kind: kernel.PeerFrameForward, Seq: 1, Body: body}
}

// mutateEnvelope re-signs nothing: it decodes a frame, applies one change, and
// re-encodes it. Whatever the change is, the signature no longer covers the envelope,
// which is the point of every test that uses it.
func mutateEnvelope(t *testing.T, frame kernel.PeerFrame, mut func(env *kernel.PeerEnvelope)) kernel.PeerFrame {
	t.Helper()
	var env kernel.PeerEnvelope
	require.NoError(t, json.Unmarshal(frame.Body, &env))
	mut(&env)
	body, err := json.Marshal(env)
	require.NoError(t, err)
	out := frame
	out.Body = body
	return out
}

// msProbe is a module that runs one callback under its own context, keeps the context
// so a test can drive further syscalls as that module, and optionally serves one route.
type msProbe struct {
	run   func(kernel.SContext) error
	serve func(kernel.SContext, kernel.RouteRequest) (kernel.RouteResponse, error)
	ctx   kernel.SContext
	// route is set by msLoadNamed before the load, because a handler must register
	// the exact path its manifest declared.
	route string
}

func (m *msProbe) OnLoad(ctx kernel.SContext) error {
	m.ctx = ctx
	// The route is NOT registered here. A module's own record is published only
	// after OnLoad returns, so manifestOf does not yet report it as live and
	// RouteRegister refuses with "pid N is not a loaded module". Registration is
	// therefore done by the test after the load, through the retained context,
	// which is also how a real handler module would do it from its own supervisor.
	if m.run != nil {
		return m.run(ctx)
	}
	return nil
}

// serveRoute registers the handler this probe was built with, after its load.
func (m *msProbe) serveRoute(t *testing.T) {
	t.Helper()
	if m.serve == nil {
		return
	}
	require.NotNil(t, m.ctx)
	require.NoError(t, m.ctx.SyscallRouteRegister(m.route, m.serve))
}

func (m *msProbe) OnUnload() error { return nil }

// msLoad registers and loads a module with the given grants, returning its pid and
// instance.
func msLoad(t *testing.T, k *kernel.Kernel, run func(kernel.SContext) error, ops ...kernel.Op) (kernel.PID, *msProbe) {
	t.Helper()
	name := peerNodeName("ms")
	mod := &msProbe{run: run}
	msLoadNamed(t, k, mod, name, kernel.Manifest{
		Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: ops,
	})
	return mod.ctx.PID(), mod
}

// msLoadNamed loads a module under an explicit name and manifest, filling in the name
// and, when the module serves a route, the path it must register.
func msLoadNamed(t *testing.T, k *kernel.Kernel, mod *msProbe, name string, m kernel.Manifest) kernel.PID {
	t.Helper()
	m.Name = name
	if len(m.ServeRoutes) == 1 && mod.serve != nil {
		mod.route = m.ServeRoutes[0]
	}
	kernel.Register(name, func() (kernel.Module, error) { return mod, nil })
	t.Cleanup(func() { kernel.Unregister(name) })

	pid, err := k.Load(m)
	require.NoError(t, err)
	return pid
}

// peerEnvelope mirrors the wire shape of kernel.PeerEnvelope for the tests that tamper
// with one. It is a local type because the kernel's is exported only for encoding, and
// a test that mutated a live envelope in place would be testing its own copy.
type peerEnvelope struct {
	Version     int    `json:"version"`
	FromNode    string `json:"from_node"`
	ToNode      string `json:"to_node"`
	Route       string `json:"route"`
	Method      string `json:"method,omitempty"`
	Trace       string `json:"trace,omitempty"`
	Hops        int64  `json:"hops"`
	Seq         int64  `json:"seq"`
	KeyID       string `json:"key_id"`
	PayloadHash string `json:"payload_hash"`
	Payload     []byte `json:"payload,omitempty"`
	Signature   []byte `json:"signature"`
}

// dialOne establishes one trusted session and returns it, re-installing a plain fake
// transport so the caller controls what happens next.
func dialOne(t *testing.T, k *kernel.Kernel, peerPriv ed25519.PrivateKey) kernel.PeerSession {
	t.Helper()
	return dialWith(t, k, peerPriv, peerNodeName("mesh-peer"), "peer.cluster.example")
}

// dialWith establishes a session with an explicit peer id and endpoint, which the
// ceiling test needs in order to dial many distinct peers.
func dialWith(t *testing.T, k *kernel.Kernel, peerPriv ed25519.PrivateKey, peerID, endpoint string) kernel.PeerSession {
	t.Helper()
	ft := &fakeTransport{handshake: func(req kernel.PeerHandshake) (kernel.PeerHandshake, error) {
		return signPeerHandshake(t, peerPriv, peerID, endpoint, req.Initiator, req.NonceA), nil
	}}
	require.NoError(t, k.PeerSetTransport(ft))

	sess, err := k.PeerDial(kernel.PeerDialSpec{Endpoint: endpoint, TimeoutMillis: 5000})
	require.NoError(t, err)
	require.Equal(t, peerID, sess.NodeID)
	return sess
}

// sha256Hex digests a payload the way the kernel does, for tests that rebind a
// tampered envelope's payload hash so the digest check passes and a later check is the
// one under test.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// auditEntries returns the chain entries of one kind, or every entry when kind is
// empty. It reads through the audit syscall on the init context, which holds
// audit:read, so the tests observe the chain the way an investigator would.
func auditEntries(t *testing.T, kind kernel.AuditKind) []kernel.AuditEntry {
	t.Helper()
	return queryAudit(t, kind, "")
}

// auditMsgs returns the messages of one kind's entries.
func auditMsgs(t *testing.T, kind kernel.AuditKind) []string {
	t.Helper()
	var out []string
	for _, e := range queryAudit(t, kind, "") {
		out = append(out, e.Msg)
	}
	return out
}

// countAudit counts entries of one kind whose message contains substr, or all entries
// of the kind when substr is empty.
func countAudit(t *testing.T, kind kernel.AuditKind, substr string) int {
	t.Helper()
	return len(queryAudit(t, kind, substr))
}

// queryAudit is the one place these tests reach the chain. It boots nothing and holds
// no kernel of its own: it uses the audit query API, which reads the process-wide
// chain the current kernel owns.
func queryAudit(t *testing.T, kind kernel.AuditKind, substr string) []kernel.AuditEntry {
	t.Helper()
	entries := kernel.AuditQuery(kernel.AuditFilter{Kind: kind, Limit: 8192})
	if substr == "" {
		return entries
	}
	var out []kernel.AuditEntry
	for _, e := range entries {
		if strings.Contains(e.Msg, substr) {
			out = append(out, e)
		}
	}
	return out
}
