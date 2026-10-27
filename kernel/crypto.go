package kernel

// kcrypto: cryptographic primitives whose key material never leaves the kernel
// (subsystem: kcrypto, the analogue of an in-kernel crypto accelerator fronting
// the machine's key store).
//
// SYSCALL WIRING FOR THE INTEGRATOR.
//
// This file cannot declare methods on *sContext or a Syscall group interface,
// because that means editing kernel/context.go while several agents share the
// tree. The exported functions below are the implementation; paste the block at
// the end of this comment into kernel/context.go to expose them as syscalls.
//
// 1. Add the group to the SContext interface's group list, next to SyscallBoot:
//
//	SyscallCrypto
//
// 2. Add the group interface and the methods:
//
//	// SyscallCrypto is the primitives half of the syscall surface. Key material
//	// does not cross this boundary in either direction.
//	type SyscallCrypto interface {
//	    // SyscallCryptoRandom returns n cryptographically secure random bytes.
//	    // Requires crypto:random.
//	    SyscallCryptoRandom(n int) ([]byte, error)
//	    // SyscallCryptoRandomHex returns n random bytes as 2n lowercase hex
//	    // characters, for tokens and nonces. Requires crypto:random.
//	    SyscallCryptoRandomHex(n int) (string, error)
//	    // SyscallCryptoHash digests data with a kernel-approved algorithm and
//	    // returns the hex digest. Requires crypto:hash.
//	    SyscallCryptoHash(algo HashAlgo, data []byte) (string, error)
//	    // SyscallCryptoSign signs msg with this node's key and returns only the
//	    // signature. Requires crypto:sign, which no module domain holds.
//	    SyscallCryptoSign(msg []byte) (Signature, error)
//	    // SyscallCryptoVerify checks a signature against one named verification
//	    // key and reports only the verdict. Requires crypto:verify.
//	    SyscallCryptoVerify(key string, msg, sig []byte) (bool, error)
//	    // SyscallCryptoVerifyCluster checks a signature against the sealed
//	    // cluster roots and reports the verdict with the matching key id.
//	    // Requires crypto:verify.
//	    SyscallCryptoVerifyCluster(msg, sig []byte) (bool, string, error)
//	}
//
//	func (c *sContext) SyscallCryptoRandom(n int) ([]byte, error) {
//	    return CryptoRandom(c, n)
//	}
//	func (c *sContext) SyscallCryptoRandomHex(n int) (string, error) {
//	    return CryptoRandomHex(c, n)
//	}
//	func (c *sContext) SyscallCryptoHash(algo HashAlgo, data []byte) (string, error) {
//	    return CryptoHash(c, algo, data)
//	}
//	func (c *sContext) SyscallCryptoSign(msg []byte) (Signature, error) {
//	    return CryptoSign(c, msg)
//	}
//	func (c *sContext) SyscallCryptoVerify(key string, msg, sig []byte) (bool, error) {
//	    return CryptoVerify(c, key, msg, sig)
//	}
//	func (c *sContext) SyscallCryptoVerifyCluster(msg, sig []byte) (bool, string, error) {
//	    return CryptoVerifyCluster(c, msg, sig)
//	}
//
// 3. Add resetCrypto() to resetKernel() in kernel/kernel.go, immediately before
//    kboot.reset(): the cache it drops holds key material parsed from the trust
//    root, so it must be cleared while that root is still the one it came from and
//    must not survive into the next boot.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
)

// The guarantee this file provides is one-directional: results cross the boundary,
// key material does not. A module asks for randomness, a digest or a signature and
// receives exactly that. It never receives the node's private key, never receives a
// handle to one, and cannot ask for one, because no entry point here returns key
// material and the signing operation is absent from the plugin domain.
//
// What this is not: it is not an address-space boundary. A module that imports
// crypto/ed25519 itself and generates its own key is not stopped by this file.
// What it cannot do is produce a signature the cluster accepts, because it holds no
// key that verifies against the sealed roots - and that is the property settlement
// actually depends on. Containing what a module can compute is a sandbox question;
// containing what a module can make the cluster believe is a key-custody question,
// and this subsystem answers the second one.
//
// Randomness comes from crypto/rand and nowhere else. A token minted from
// math/rand is guessable from a handful of observations, and every authorization
// decision built on it is guessable too; that is a breach rather than a style
// problem, so the source is fixed here and pinned by a test that reads the
// kernel's own import list.

// Ceilings for one call. They are package constants rather than BootLimits fields
// because adding a field to the sealed trust root is a change owned by kboot, and a
// subsystem must not widen the struct it reads. Each bound applies to a single
// request; a caller needing more loops, which keeps the cost of one call
// reviewable.
const (
	// maxCryptoRandomBytes bounds one randomness request.
	maxCryptoRandomBytes = 4096
	// maxCryptoInputBytes bounds one hashing, signing or verification input.
	maxCryptoInputBytes = 1 << 20
)

// MaxCryptoRandomBytes reports the ceiling on one randomness request.
func MaxCryptoRandomBytes() int { return maxCryptoRandomBytes }

// MaxCryptoInputBytes reports the ceiling on one hashing or signing input.
func MaxCryptoInputBytes() int { return maxCryptoInputBytes }

// CryptoError reports a refused cryptographic operation. It is a distinct type so a
// caller can tell "the kernel will not do this" from "the kernel could not", and so
// hitting a ceiling is not mistaken for a policy denial.
type CryptoError struct {
	Msg string
	// Err carries the underlying cause, which lets errors.Is find a ceiling
	// sentinel without string matching.
	Err error
}

func (e *CryptoError) Error() string {
	if e.Err == nil {
		return "kernel: crypto refused: " + e.Msg
	}
	return "kernel: crypto refused: " + e.Msg + ": " + e.Err.Error()
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *CryptoError) Unwrap() error { return e.Err }

// ErrCryptoLimit is the sentinel for every primitive ceiling.
var ErrCryptoLimit = errors.New("kernel: crypto limit reached")

func cryptoErr(format string, a ...any) error {
	return &CryptoError{Msg: fmt.Sprintf(format, a...)}
}

func cryptoLimit(format string, a ...any) error {
	return &CryptoError{Msg: fmt.Sprintf(format, a...), Err: ErrCryptoLimit}
}

// HashAlgo names a digest algorithm the kernel will apply. The set is closed and an
// unknown algorithm is refused rather than defaulted, because a default branch is
// where a downgrade to a weaker digest would hide.
type HashAlgo string

const (
	// HashSHA256 is the digest for hashes that cross a node boundary.
	HashSHA256 HashAlgo = "sha256"
	// HashSHA384 exists for callers whose protocol fixes it.
	HashSHA384 HashAlgo = "sha384"
	// HashSHA512 exists for callers whose protocol fixes it.
	HashSHA512 HashAlgo = "sha512"
)

// HashAlgos lists the digest algorithms the kernel accepts.
func HashAlgos() []HashAlgo { return []HashAlgo{HashSHA256, HashSHA384, HashSHA512} }

// digestFor returns a fresh digest state for one algorithm.
func digestFor(algo HashAlgo) (hash.Hash, error) {
	switch algo {
	case HashSHA256:
		return sha256.New(), nil
	case HashSHA384:
		return sha512.New384(), nil
	case HashSHA512:
		return sha512.New(), nil
	}
	return nil, cryptoErr("unknown hash algorithm %q", algo)
}

// Signature is a detached signature plus the metadata needed to select a
// verification key. The key id is a digest of the public key rather than the key,
// so a signature can be routed to the right root without carrying key material.
type Signature struct {
	// Algo is the signing algorithm. Only ed25519 is implemented.
	Algo string `json:"algo"`
	// KeyID identifies the verification key as a short digest of it.
	KeyID string `json:"key_id"`
	// Bytes is the raw signature.
	Bytes []byte `json:"bytes"`
}

// algoEd25519 is the only signing algorithm this kernel implements. One algorithm
// means one review, one set of test vectors, and no negotiation to downgrade.
const algoEd25519 = "ed25519"

// nodeKeyCache holds the parsed node signing key. Parsing PEM and DER on every
// signature would be wasted work on the settlement path, so the result is cached
// against the material it came from. resetCrypto drops it, and material that
// differs from the cache invalidates it by comparison, so the cache cannot outlive
// the trust root it was parsed from.
type nodeKeyCache struct {
	mu       sync.Mutex
	material string
	priv     ed25519.PrivateKey
	keyID    string
}

var kcryptoKeys = &nodeKeyCache{}

// nodePrivateKey returns the parsed node signing key and its key id. An empty or
// unparseable trust root is an error and never a fallback: a subsystem that signed
// with a generated ephemeral key, or that returned an unsigned record, would
// produce settlement artifacts that look complete and verify nowhere. Failing
// loudly is the only behavior that makes a missing key an outage instead of a
// silent forgery factory.
func nodePrivateKey() (ed25519.PrivateKey, string, error) {
	material := nodeSigningKey()

	kcryptoKeys.mu.Lock()
	defer kcryptoKeys.mu.Unlock()

	if material != "" && kcryptoKeys.material == material {
		return kcryptoKeys.priv, kcryptoKeys.keyID, nil
	}
	kcryptoKeys.material = material

	priv, err := parseEd25519Private(material)
	if err != nil {
		kcryptoKeys.priv = nil
		kcryptoKeys.keyID = ""
		return nil, "", err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		kcryptoKeys.priv = nil
		kcryptoKeys.keyID = ""
		return nil, "", errors.New("kernel: node signing key does not yield an ed25519 public key")
	}
	kcryptoKeys.priv = priv
	kcryptoKeys.keyID = ed25519KeyID(pub)
	return kcryptoKeys.priv, kcryptoKeys.keyID, nil
}

// ed25519KeyID derives the short identifier for a public key. It is a truncated
// digest rather than the key itself, so it is safe in a receipt, an audit field and
// a console line.
func ed25519KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// sha256Sum is the one digest construction the kernel uses for content that is not
// key material: receipt payloads, module manifests, prompt and completion bodies.
// Having a single function means a single place to review when the choice of digest
// is ever revisited.
func sha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// parseEd25519Private accepts the encodings an operator plausibly holds: a PEM
// PKCS8 block, a 32-byte seed, or a full 64-byte ed25519 private key, each carried
// as PEM, hex or base64. Anything else is refused.
func parseEd25519Private(material string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(material) == "" {
		return nil, errors.New("kernel: the sealed trust root holds no node signing key")
	}
	raw, err := decodePEMHexOrBase64(material)
	if err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("kernel: node signing key is %T, want ed25519", key)
		}
		return ed, nil
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, errors.New("kernel: node signing key material is not an ed25519 key")
}

// parseEd25519Public accepts the same carrier encodings for a verification key.
func parseEd25519Public(material string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(material) == "" {
		return nil, errors.New("kernel: empty verification key")
	}
	raw, err := decodePEMHexOrBase64(material)
	if err != nil {
		return nil, err
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	if key, err := x509.ParsePKIXPublicKey(raw); err == nil {
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("kernel: verification key is %T, want ed25519", key)
		}
		return ed, nil
	}
	return nil, errors.New("kernel: verification key material is not an ed25519 public key")
}

// decodePEMHexOrBase64 normalizes the three carrier encodings into raw bytes. Hex
// is tried before base64 because a hex string is also valid base64 far more often
// than the reverse, and guessing wrong yields a confusing length error later.
func decodePEMHexOrBase64(material string) ([]byte, error) {
	trimmed := strings.TrimSpace(material)
	if strings.Contains(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, errors.New("kernel: key material looks like PEM but does not decode")
		}
		return block.Bytes, nil
	}
	if raw, err := hex.DecodeString(trimmed); err == nil && len(raw) > 0 {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(raw) > 0 {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(raw) > 0 {
		return raw, nil
	}
	return nil, errors.New("kernel: key material is not PEM, hex or base64")
}

// NodeVerificationKey returns this node's public verification key as hex, derived
// from the sealed signing key. The host process uses it to build the cluster root
// list its peers are configured with. A module may read it: a public key is not a
// secret, and a module that cannot learn which key will verify its own receipts
// cannot debug a settlement failure.
func NodeVerificationKey() (string, error) {
	priv, err := parseEd25519Private(nodeSigningKey())
	if err != nil {
		return "", err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("kernel: node signing key does not yield an ed25519 public key")
	}
	return hex.EncodeToString(pub), nil
}

// NodeKeyID returns the short identifier of this node's verification key, or an
// error when the trust root holds no usable key. Receipts and audit records carry
// this rather than the key.
func NodeKeyID() (string, error) {
	_, id, err := nodePrivateKey()
	if err != nil {
		return "", err
	}
	return id, nil
}

// constantTimeEqualBytes compares two byte slices without leaking, through timing,
// how much of a secret prefix matched. Every equality check on a value derived from
// a secret goes through here; an early-returning comparison is a side channel, and
// crypto/subtle exists precisely so that nobody writes one.
func constantTimeEqualBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// CryptoRandom returns n cryptographically secure random bytes. Requires
// crypto:random.
//
// n must be positive and at most MaxCryptoRandomBytes. A request for zero bytes is
// refused rather than answered with an empty slice, because an empty token is the
// failure mode that silently produces a constant value at a call site expecting
// entropy.
func CryptoRandom(ctx SContext, n int) ([]byte, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if err := c.syscall(OpCryptoRandom); err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, cryptoErr("random length must be positive, got %d", n)
	}
	if n > maxCryptoRandomBytes {
		return nil, cryptoLimit("random length %d exceeds the ceiling %d", n, maxCryptoRandomBytes)
	}
	out, err := randomBytes(n)
	if err != nil {
		fault(c, "crypto/rand failed", map[string]any{"error": err.Error()})
		return nil, err
	}
	return out, nil
}

// randomBytes fills a fresh buffer from crypto/rand. It is package-private and does
// no policy check, so kernel subsystems that need an unguessable identifier - ktrace
// for a trace id, kreceipt for a nonce - can call it without routing through the
// syscall surface. Nothing outside the kernel can reach it.
//
// A failed entropy read is fatal to the caller and is never papered over with a
// weaker source or a partially filled buffer: a token built from a half-filled buffer
// is a token with a predictable suffix, and the call site cannot tell.
func randomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("kernel: random length must be positive, got %d", n)
	}
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("kernel: crypto/rand failed: %w", err)
	}
	return out, nil
}

// CryptoRandomHex returns n random bytes as 2n lowercase hex characters. Requires
// crypto:random. This is the call a module uses for a token, a nonce or any
// identifier that authorizes something.
func CryptoRandomHex(ctx SContext, n int) (string, error) {
	raw, err := CryptoRandom(ctx, n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// CryptoHash digests data and returns the lowercase hex digest. Requires
// crypto:hash. An unknown algorithm is refused; there is no default.
func CryptoHash(ctx SContext, algo HashAlgo, data []byte) (string, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return "", errForeignContext
	}
	if err := c.syscall(OpCryptoHash); err != nil {
		return "", err
	}
	if len(data) > maxCryptoInputBytes {
		return "", cryptoLimit("input of %d bytes exceeds the ceiling %d", len(data), maxCryptoInputBytes)
	}
	h, err := digestFor(algo)
	if err != nil {
		return "", err
	}
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CryptoSign signs msg with this node's private key and returns the signature and
// nothing else. Requires crypto:sign, which the plugin domain does not hold and no
// manifest can grant, so a module can never mint a signature the cluster accepts.
//
// A missing or unparseable signing key is an error. There is deliberately no
// fallback, because an unsigned or self-signed artifact that looks like a node
// signature is worse than a failed request: it is indistinguishable from the real
// thing at every call site that forgot to check.
func CryptoSign(ctx SContext, msg []byte) (Signature, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return Signature{}, errForeignContext
	}
	if err := c.syscall(OpCryptoSign); err != nil {
		return Signature{}, err
	}
	return signWithNodeKey(c, msg)
}

// signWithNodeKey is the signing path shared by CryptoSign and kreceipt. The policy
// decision was already made by the caller, so this function is not reachable from a
// module except through a caller that checked; the context is used for fault
// attribution only.
func signWithNodeKey(ctx *sContext, msg []byte) (Signature, error) {
	if len(msg) > maxCryptoInputBytes {
		return Signature{}, cryptoLimit("input of %d bytes exceeds the ceiling %d", len(msg), maxCryptoInputBytes)
	}
	priv, keyID, err := nodePrivateKey()
	if err != nil {
		fault(ctx, "cannot sign: no usable node signing key", map[string]any{"error": err.Error()})
		return Signature{}, err
	}
	return Signature{Algo: algoEd25519, KeyID: keyID, Bytes: ed25519.Sign(priv, msg)}, nil
}

// CryptoVerify checks sig over msg against one named verification key and reports
// only the verdict. Requires crypto:verify. An unparsable key is an error rather
// than a false verdict, so a caller cannot read a configuration mistake as "the
// signature did not match".
func CryptoVerify(ctx SContext, key string, msg, sig []byte) (bool, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return false, errForeignContext
	}
	if err := c.syscall(OpCryptoVerify); err != nil {
		return false, err
	}
	pub, err := parseEd25519Public(key)
	if err != nil {
		return false, err
	}
	if len(msg) > maxCryptoInputBytes {
		return false, cryptoLimit("input of %d bytes exceeds the ceiling %d", len(msg), maxCryptoInputBytes)
	}
	// A wrong-length signature is a false verdict rather than an error: it is a
	// malformed input from a peer, which is what verification exists to reject,
	// and ed25519.Verify would panic on it.
	if len(sig) != ed25519.SignatureSize {
		return false, nil
	}
	return ed25519.Verify(pub, msg, sig), nil
}

// CryptoVerifyCluster checks sig over msg against every key in the sealed cluster
// root set and reports the verdict with the key id that matched, or an empty id when
// none did. Requires crypto:verify.
//
// Roots that do not parse are skipped rather than fatal: a cluster list may contain
// a key for an algorithm this node does not implement, and refusing to verify
// anything because one entry is opaque would be a self-inflicted outage. A root set
// in which nothing parses is an error, because then the verdict carries no
// information and a caller would read "false" as "the peer cheated".
func CryptoVerifyCluster(ctx SContext, msg, sig []byte) (bool, string, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return false, "", errForeignContext
	}
	if err := c.syscall(OpCryptoVerify); err != nil {
		return false, "", err
	}
	return verifyAgainstClusterRoots(msg, sig)
}

// verifyAgainstClusterRoots is the shared verification path used by
// CryptoVerifyCluster and by kreceipt.
func verifyAgainstClusterRoots(msg, sig []byte) (bool, string, error) {
	roots := ClusterRootKeys()
	if len(roots) == 0 {
		return false, "", errors.New("kernel: the sealed trust root declares no cluster verification keys")
	}
	if len(msg) > maxCryptoInputBytes {
		return false, "", cryptoLimit("input of %d bytes exceeds the ceiling %d", len(msg), maxCryptoInputBytes)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, "", nil
	}
	parsed := 0
	for _, root := range roots {
		pub, err := parseEd25519Public(root)
		if err != nil {
			continue
		}
		parsed++
		if ed25519.Verify(pub, msg, sig) {
			return true, ed25519KeyID(pub), nil
		}
	}
	if parsed == 0 {
		return false, "", errors.New("kernel: no cluster verification key is a usable ed25519 key")
	}
	return false, "", nil
}

// resetCrypto drops the cached node key. Called only from resetKernel, so a
// restarted kernel re-reads its own trust root instead of signing with a key parsed
// before the restart.
func resetCrypto() {
	kcryptoKeys.mu.Lock()
	defer kcryptoKeys.mu.Unlock()
	kcryptoKeys.material = ""
	kcryptoKeys.priv = nil
	kcryptoKeys.keyID = ""
}
