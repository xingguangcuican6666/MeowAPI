package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// These tests drive kcrypto through the module-reachable syscall surface wherever
// a module is allowed to act, and through the host-only paths where it is not. The
// distinction is the point of the subsystem: random, hash and verify are module
// capabilities; sign is not, and no test may make it one.

// crxBuffer is a mutex-guarded console sink, so tests can assert on kernel output
// without racing the goroutine that emits it.
type crxBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *crxBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *crxBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// crxQuiet redirects the kernel console for one test.
func crxQuiet(t *testing.T) *crxBuffer {
	t.Helper()
	sink := &crxBuffer{}
	kernel.KernelConsole().SetOutput(sink)
	t.Cleanup(func() { kernel.KernelConsole().SetOutput(nil) })
	return sink
}

// crxKeyPair makes a node signing key and its matching cluster root list. Tests
// need a real key pair because a signature that verifies against nothing proves
// nothing about the verification path.
func crxKeyPair(t *testing.T) (seedHex string, rootHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub)
}

// crxTrustRoot is a trust root with a working signing key and the matching cluster
// root, so signatures issued by this node verify here.
func crxTrustRoot(t *testing.T) kernel.BootTrustRoot {
	t.Helper()
	seed, pub := crxKeyPair(t)
	return kernel.BootTrustRoot{
		NodeID:          "crx-node",
		ClusterRootKeys: []string{pub},
		SigningKeyPEM:   seed,
	}
}

// crxKeylessTrustRoot is a trust root with no signing key at all, which is the
// configuration a signature must fail loudly under rather than silently degrade.
// crxBoot starts a kernel with the given trust root.
func crxBoot(t *testing.T, tr kernel.BootTrustRoot) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: tr})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// crxManifest declares exactly the crypto operations a conforming module needs.
func crxManifest(name string, ops ...kernel.Op) kernel.Manifest {
	return kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1, Require: ops,
	}
}

// crxModule captures the context it was loaded under and runs one callback.
type crxModule struct {
	name   string
	onLoad func(ctx kernel.SContext) error
	ctx    kernel.SContext
}

func (m *crxModule) OnLoad(ctx kernel.SContext) error {
	m.ctx = ctx
	if m.onLoad != nil {
		return m.onLoad(ctx)
	}
	return nil
}
func (m *crxModule) OnUnload() error { return nil }

// crxReporter is a module that reports token usage during OnLoad. It exists because a
// receipt cross-checks its counts against what the settled pid actually emitted, so a
// test that needs a signed payload needs a pid with accounting behind it.
type crxReporter struct {
	in, out int64
	ctx     kernel.SContext
}

func (m *crxReporter) OnLoad(ctx kernel.SContext) error {
	m.ctx = ctx
	if err := ctx.SyscallUsageEmit(kernel.UsageFact{
		Kind: kernel.UsageTokensIn, Quantity: m.in, Label: "crx",
	}); err != nil {
		return err
	}
	return ctx.SyscallUsageEmit(kernel.UsageFact{
		Kind: kernel.UsageTokensOut, Quantity: m.out, Label: "crx",
	})
}
func (m *crxReporter) OnUnload() error { return nil }

// crxSettled boots a kernel with a working key, loads a module that has reported the
// given counts, and issues one receipt against it. The receipt's canonical payload is
// a real signed message, which is what makes the verification assertions below mean
// something rather than checking a synthetic byte string.
func crxSettled(t *testing.T) (*kernel.Kernel, *crxReporter, kernel.Receipt) {
	t.Helper()
	k := crxBoot(t, crxTrustRoot(t))
	reporter := &crxReporter{in: 64, out: 32}
	pid := crxLoad(t, k, reporter,
		crxManifest("crxsettled", kernel.OpUsageEmit, kernel.OpCryptoVerify))
	r, err := k.IssueReceipt(kernel.ReceiptSpec{
		PID: pid, Route: "crx/route", Prompt: []byte("prompt"), Completion: []byte("completion"),
		TokensIn: 64, TokensOut: 32, StartedMono: 1,
	})
	require.NoError(t, err)
	return k, reporter, r
}

// crxLoad registers and loads a module, returning its pid.
func crxLoad(t *testing.T, k *kernel.Kernel, m kernel.Module, mf kernel.Manifest) kernel.PID {
	t.Helper()
	kernel.Register(mf.Name, func() (kernel.Module, error) { return m, nil })
	t.Cleanup(func() { kernel.Unregister(mf.Name) })
	pid, err := k.Load(mf)
	require.NoError(t, err)
	return pid
}

// TestCryptoRandomIsGrantedAndUsable is the grant: a module holding crypto:random
// receives entropy of the length it asked for, and two calls do not agree, because
// agreeing would mean the source is not a source.
func TestCryptoRandomIsGrantedAndUsable(t *testing.T) {
	crxQuiet(t)
	k := crxBoot(t, crxTrustRoot(t))

	var first, second string
	m := &crxModule{onLoad: func(ctx kernel.SContext) error {
		var err error
		first, err = ctx.SyscallCryptoRandomHex(32)
		if err != nil {
			return err
		}
		raw, err := ctx.SyscallCryptoRandom(16)
		if err != nil {
			return err
		}
		second = hex.EncodeToString(raw)
		return nil
	}}
	crxLoad(t, k, m, crxManifest("crxrand",
		kernel.OpCryptoRandom, kernel.OpCryptoHash))

	assert.Len(t, first, 64, "32 bytes must render as 64 hex characters")
	assert.Len(t, second, 32)
	assert.NotEqual(t, first, second)
	for _, r := range first {
		assert.Contains(t, "0123456789abcdef", string(r), "hex must be lowercase")
	}
}

// TestCryptoRandomDeniedWithoutDeclaration is the denial: a module that declared
// nothing gets nothing, the refusal is a policy denial, and it lands on the audit
// chain where an investigator can see that a module tried.
func TestCryptoRandomDeniedWithoutDeclaration(t *testing.T) {
	crxQuiet(t)
	k := crxBoot(t, crxTrustRoot(t))

	var err error
	m := &crxModule{onLoad: func(ctx kernel.SContext) error {
		_, err = ctx.SyscallCryptoRandom(16)
		return nil
	}}
	crxLoad(t, k, m, crxManifest("crxnogrant"))

	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "a module without crypto:random must be denied: %v", err)
	assert.Contains(t, err.Error(), "crypto:random")

	denials := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial})
	require.NotEmpty(t, denials, "the denial must be recorded on the audit chain")
	found := false
	for _, e := range denials {
		if e.Fields["op"] == "crypto:random" && e.PID == m.ctx.PID() {
			found = true
		}
	}
	assert.True(t, found, "the denial entry must name the operation and the pid")
}

// TestCryptoRandomCeiling covers both malformed requests and the ceiling, and
// proves the state is not corrupted: the next well-formed request still succeeds.
func TestCryptoRandomCeiling(t *testing.T) {
	crxQuiet(t)
	k := crxBoot(t, crxTrustRoot(t))

	var zero, over, after error
	var okLen int
	m := &crxModule{onLoad: func(ctx kernel.SContext) error {
		_, zero = ctx.SyscallCryptoRandom(0)
		_, over = ctx.SyscallCryptoRandom(kernel.MaxCryptoRandomBytes() + 1)
		raw, err := ctx.SyscallCryptoRandom(8)
		after = err
		if err == nil {
			okLen = len(raw)
		}
		return nil
	}}
	crxLoad(t, k, m, crxManifest("crxceil", kernel.OpCryptoRandom))

	require.Error(t, zero, "zero bytes is a caller bug, not an empty token")
	assert.False(t, kernel.IsDenied(zero))
	require.Error(t, over)
	assert.True(t, errors.Is(over, kernel.ErrCryptoLimit),
		"the ceiling must be a typed limit error, got %v", over)
	assert.NoError(t, after)
	assert.Equal(t, 8, okLen, "the kernel must stay usable after a refused request")
}

// TestCryptoHashMatchesKnownVectors pins the digest: sha256 of the classic test
// vector, so a change in the algorithm behind the name is caught here and not in a
// settlement dispute.
func TestCryptoHashMatchesKnownVectors(t *testing.T) {
	crxQuiet(t)
	k := crxBoot(t, crxTrustRoot(t))

	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	var got string
	var unknownErr, overErr error
	m := &crxModule{onLoad: func(ctx kernel.SContext) error {
		got, _ = ctx.SyscallCryptoHash(kernel.HashSHA256, []byte("abc"))
		_, unknownErr = ctx.SyscallCryptoHash(kernel.HashAlgo("md5"), []byte("abc"))
		_, overErr = ctx.SyscallCryptoHash(kernel.HashSHA256,
			[]byte(strings.Repeat("x", kernel.MaxCryptoInputBytes()+1)))
		return nil
	}}
	crxLoad(t, k, m, crxManifest("crxhash", kernel.OpCryptoHash))

	assert.Equal(t, want, got)
	require.Error(t, unknownErr, "an unknown algorithm must be refused, not defaulted")
	assert.False(t, kernel.IsDenied(unknownErr))
	assert.True(t, errors.Is(overErr, kernel.ErrCryptoLimit))
}

// TestCryptoSignIsDeniedToEveryLiveContext is the load-bearing refusal of the
// whole subsystem: neither a module nor init can mint a signature. The root context
// that could is retired before any module exists, so there is nothing left to ask.
func TestCryptoSignIsDeniedToEveryLiveContext(t *testing.T) {
	crxQuiet(t)
	k := crxBoot(t, crxTrustRoot(t))

	// A manifest asking for crypto:sign never loads at all: validation refuses an
	// operation the plugin domain can never hold, so the refusal is visible before
	// any module code runs.
	kernel.Register("crxsigner", func() (kernel.Module, error) { return &crxModule{}, nil })
	t.Cleanup(func() { kernel.Unregister("crxsigner") })
	_, loadErr := k.Load(crxManifest("crxsigner", kernel.OpCryptoSign))
	require.Error(t, loadErr)
	assert.Contains(t, loadErr.Error(), "not grantable")

	// A loaded module that calls the syscall anyway is stopped by the domain
	// ceiling rather than by the manifest.
	var moduleErr, initErr error
	m := &crxModule{onLoad: func(ctx kernel.SContext) error {
		_, moduleErr = ctx.SyscallCryptoSign([]byte("forge me"))
		return nil
	}}
	crxLoad(t, k, m, crxManifest("crxsignercaller", kernel.OpCryptoHash))
	_, initErr = k.InitContext().SyscallCryptoSign([]byte("forge me"))

	require.Error(t, moduleErr)
	assert.True(t, kernel.IsDenied(moduleErr))
	require.Error(t, initErr)
	assert.True(t, kernel.IsDenied(initErr), "init must not sign either")

	denials := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial})
	counted := 0
	for _, e := range denials {
		if e.Fields["op"] == "crypto:sign" {
			counted++
		}
	}
	assert.GreaterOrEqual(t, counted, 2, "both attempts must be on the audit chain")
}

// TestCryptoSignWithoutKeyFailsLoudly proves there is no fallback. A kernel whose
// trust root holds no signing key must refuse to sign rather than produce something
// that looks signed, because an unsigned artifact that looks signed is the failure
// mode every verifier downstream forgets to check.
func TestCryptoSignWithoutKeyFailsLoudly(t *testing.T) {
	crxQuiet(t)
	_, pub := crxKeyPair(t)
	k := crxBoot(t, kernel.BootTrustRoot{
		NodeID: "crx-node", ClusterRootKeys: []string{pub}, SigningKeyPEM: "",
	})

	_, err := k.IssueReceipt(kernel.ReceiptSpec{Prompt: []byte("p"), Completion: []byte("c")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing key")
	assert.Zero(t, kernel.ReceiptStats().Issued, "a refused issue must not consume a number")

	// Verification still works against the declared roots, so refusing to sign does
	// not blind the node to everyone else's signatures.
	m := &crxModule{}
	crxLoad(t, k, m, crxManifest("crxkeyless", kernel.OpCryptoVerify))
	ok, keyID, err := m.ctx.SyscallCryptoVerifyCluster([]byte("m"), make([]byte, 64))
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, keyID)
}

// TestCryptoVerifyAgainstClusterKeys drives the verification grant from a module.
// The signature is a real one over the node's canonical payload, produced by the
// host-side issue path, so the verification is end to end rather than synthetic.
func TestCryptoVerifyAgainstClusterKeys(t *testing.T) {
	crxQuiet(t)
	_, reporter, r := crxSettled(t)
	payload := kernel.ReceiptPayload(r)

	ok, keyID, err := reporter.ctx.SyscallCryptoVerifyCluster(payload, r.Signature)
	require.NoError(t, err)
	assert.True(t, ok, "a genuine signature must verify")
	assert.NotEmpty(t, keyID)
	assert.Equal(t, r.KeyID, keyID, "the matched root must be the one that signed")

	bad, _, err := reporter.ctx.SyscallCryptoVerifyCluster([]byte("other message"), r.Signature)
	require.NoError(t, err)
	assert.False(t, bad, "the same signature over different bytes must not verify")

	// A named-key check against the node's own public key must agree.
	pub, err := kernel.NodeVerificationKey()
	require.NoError(t, err)
	named, err := reporter.ctx.SyscallCryptoVerify(pub, payload, r.Signature)
	require.NoError(t, err)
	assert.True(t, named)

	// And a signature from a foreign key must not.
	_, foreignPub := foreignKeyPair(t)
	other, err := reporter.ctx.SyscallCryptoVerify(foreignPub, payload, r.Signature)
	require.NoError(t, err)
	assert.False(t, other)
}

// foreignKeyPair is a key pair this node does not trust, for proving that a valid
// signature from someone else is not accepted.
func foreignKeyPair(t *testing.T) (string, string) {
	t.Helper()
	return crxKeyPair(t)
}

// TestCryptoVerifyRejectsMalformedSignature pins the boundary between an error and
// a verdict: a wrong-length signature is a false verdict, because that is what
// verification is for, and an unparsable key is an error, because a caller must not
// read a configuration mistake as "did not match".
func TestCryptoVerifyRejectsMalformedSignature(t *testing.T) {
	crxQuiet(t)
	k := crxBoot(t, crxTrustRoot(t))

	pub, err := kernel.NodeVerificationKey()
	require.NoError(t, err)

	var short bool
	var keyErr error
	m := &crxModule{onLoad: func(ctx kernel.SContext) error {
		short, _ = ctx.SyscallCryptoVerify(pub, []byte("m"), []byte("too short"))
		_, keyErr = ctx.SyscallCryptoVerify("not-a-key", []byte("m"), make([]byte, 64))
		return nil
	}}
	crxLoad(t, k, m, crxManifest("crxmalformed", kernel.OpCryptoVerify))

	assert.False(t, short, "a malformed signature is a false verdict, not a panic")
	require.Error(t, keyErr, "an unparsable key is an error, not a verdict")
}

// TestCryptoClusterVerifyWithNoRootsIsAnError, not a false: a node with no usable
// roots cannot reach a conclusion, and reporting one would either excuse a forgery
// or accuse an honest peer.
func TestCryptoClusterVerifyWithNoRootsIsAnError(t *testing.T) {
	crxQuiet(t)
	k := crxBoot(t, kernel.BootTrustRoot{NodeID: "crx-node"})

	m := &crxModule{}
	crxLoad(t, k, m, crxManifest("crxnoroots", kernel.OpCryptoVerify))
	_, _, err := m.ctx.SyscallCryptoVerifyCluster([]byte("m"), make([]byte, 64))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cluster")
}

// TestCryptoSourceIsCryptoRand reads the kernel's own imports and asserts that the
// randomness source is crypto/rand and that math/rand appears nowhere. A token
// minted from math/rand is guessable, and the source is a property of the file
// rather than of any one call, so it is checked at the file level.
// kernelDir is the kernel package's directory relative to this suite's. go test sets
// the working directory to the package directory, so this path is stable. The suite
// reads kernel sources because the property under test is about which package the
// kernel imports, and that is not observable through any call.
const kernelDir = "../../kernel"

func TestCryptoSourceIsCryptoRand(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(kernelDir)
	require.NoError(t, err)

	sawCryptoRand := false
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(kernelDir, name), nil, parser.ImportsOnly)
		require.NoError(t, err, "cannot parse %s", name)
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			assert.NotEqual(t, "math/rand", path, "%s must not use math/rand", name)
			assert.NotEqual(t, "math/rand/v2", path, "%s must not use math/rand/v2", name)
			if name == "crypto.go" && path == "crypto/rand" {
				sawCryptoRand = true
			}
		}
	}
	assert.True(t, sawCryptoRand, "kernel/crypto.go must draw its randomness from crypto/rand")
}

// TestCryptoConcurrency hammers the module-reachable calls from many goroutines at
// once. The suite runs -race, and a cached key guarded badly or a shared buffer
// handed to two callers shows up here or nowhere.
func TestCryptoConcurrency(t *testing.T) {
	crxQuiet(t)
	k := crxBoot(t, crxTrustRoot(t))

	const workers, each = 8, 16
	results := make([][]string, workers)
	var wg sync.WaitGroup
	m := &crxModule{}
	crxLoad(t, k, m, crxManifest("crxconc",
		kernel.OpCryptoRandom, kernel.OpCryptoHash, kernel.OpCryptoVerify))

	ctx := m.ctx
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			out := make([]string, 0, each)
			for i := range each {
				h, err := ctx.SyscallCryptoRandomHex(16)
				if err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
				out = append(out, h)
				d, err := ctx.SyscallCryptoHash(kernel.HashSHA256, []byte(fmt.Sprintf("%d-%d", w, i)))
				if err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
				out = append(out, d)
			}
			results[w] = out
		}(w)
	}
	wg.Wait()

	seen := map[string]bool{}
	for _, group := range results {
		for _, v := range group {
			assert.False(t, seen[v], "two goroutines received the same value: %s", v)
			seen[v] = true
		}
	}
	assert.Len(t, seen, workers*each*2, "each iteration produces a token and a digest")
}

// TestCryptoResetBetweenBoots is the reset path: a key parsed by one boot does not
// serve the next. The next boot's key id comes from the next boot's trust root, and
// a keyless boot reports no key at all.
func TestCryptoResetBetweenBoots(t *testing.T) {
	crxQuiet(t)

	k1 := crxBoot(t, crxTrustRoot(t))
	id1, err := kernel.NodeKeyID()
	require.NoError(t, err)
	require.NoError(t, k1.Shutdown())

	// The root context is gone with the boot, so the cached key must be too.
	_, err = kernel.NodeKeyID()
	require.Error(t, err)

	k2 := crxBoot(t, crxTrustRoot(t))
	defer func() { _ = k2.Shutdown() }()
	id2, err := kernel.NodeKeyID()
	require.NoError(t, err)
	assert.NotEqual(t, id1, id2, "a fresh key pair must yield a fresh key id")
}
