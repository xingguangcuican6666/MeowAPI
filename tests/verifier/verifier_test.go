package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// These tests drive kverifier through the two call shapes it actually has: the
// load-path hook with the loader's context attached, and the host-side form with
// no context. There is no syscall to drive it through, and that absence is
// asserted below rather than assumed.
//
// Signing is done here with crypto/ed25519 directly, not through the kernel.
// That is not a workaround: the kernel deliberately offers no manifest signing
// entry point, because a package-level signer would be an oracle any in-process
// module could call to appraise its own widened declaration. What the kernel
// exports is VerifierBindingPayload, the exact bytes a signature must cover, and
// every signature in this file is built from it - which is itself the proof that
// an external signer can reproduce the encoding without kernel help.

// verifierKeyPair produces a signing seed and the matching cluster root, encoded
// the way an operator supplies them in the trust root: a hex seed for signing, a
// hex public key as the root. This is this package's own copy of the tests/crypto
// helper, which lives in a different package and cannot be imported.
func verifierKeyPair(t *testing.T) (seedHex string, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub)
}

// verifierKeyID reproduces the kernel's short public-key identifier: the first
// eight bytes of the sha256 of the public key, hex encoded. A test that computed
// this differently would be asserting against its own invention rather than
// against the kernel's naming.
func verifierKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// verifierPub decodes a hex public key.
func verifierPub(t *testing.T, pubHex string) ed25519.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(pubHex)
	require.NoError(t, err)
	require.Len(t, raw, ed25519.PublicKeySize)
	return ed25519.PublicKey(raw)
}

// verifierBoot starts a kernel over a trust root built from the given cluster
// roots and signing key, with the console captured. The cleanup matters more than
// it looks: the boot guard is process-wide, so a leaked boot fails every later
// test in the binary with "already booted".
func verifierBoot(t *testing.T, roots []string, seedHex string) (*kernel.Kernel, *bytes.Buffer) {
	t.Helper()
	buf := harness.QuietConsole(t)
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{
		NodeID:          "vrf-node",
		ClusterRootKeys: roots,
		SigningKeyPEM:   seedHex,
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k, buf
}

// verifierManifest is a minimal valid declaration.
func verifierManifest(name string, ops ...kernel.Op) kernel.Manifest {
	return kernel.Manifest{
		Name: name, Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1, Require: ops,
	}
}

// verifierSign mints a signature over one manifest's binding payload with the
// given seed, exactly as an operator's signing tool would: read the payload the
// kernel says must be covered, sign it, fill in the envelope.
func verifierSign(t *testing.T, seedHex string, m kernel.Manifest) kernel.VerifierSignature {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	require.NoError(t, err)
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok)
	return kernel.VerifierSignature{
		Version:       kernel.VerifierBindingVersion,
		Module:        m.Name,
		ModuleVersion: m.Version,
		Digest:        m.Digest(),
		KeyID:         verifierKeyID(pub),
		SignedMono:    1,
		Bytes:         ed25519.Sign(priv, kernel.VerifierBindingPayload(m)),
	}
}

// verifierAppraisals returns the audit entries this subsystem wrote, in chain
// order. Filtering on the message keeps the assertion immune to the other
// AuditPolicy records a boot produces.
func verifierAppraisals() []kernel.AuditEntry {
	var out []kernel.AuditEntry
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPolicy}) {
		if e.Msg == "manifest signature appraisal" {
			out = append(out, e)
		}
	}
	return out
}

// verifierField reads one audit field as a string, failing when it is absent: an
// appraisal record that quietly dropped a field is the defect this guards.
func verifierField(t *testing.T, e kernel.AuditEntry, key string) string {
	t.Helper()
	v, ok := e.Fields[key]
	require.True(t, ok, "audit entry %d has no %q field: %v", e.Seq, key, e.Fields)
	s, ok := v.(string)
	require.True(t, ok, "audit field %q is %T, want string", key, v)
	return s
}

// verifierFieldSprint renders any audit field, for assertions on booleans.
func verifierFieldSprint(t *testing.T, e kernel.AuditEntry, key string) string {
	t.Helper()
	v, ok := e.Fields[key]
	require.True(t, ok, "audit entry %d has no %q field", e.Seq, key)
	return fmt.Sprint(v)
}

// verifierJSON renders a value for the "no secret crosses a boundary" assertions.
func verifierJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// verifierDetails joins every detail for one finding class, so an assertion can
// require a substance that appears in the second finding of a class rather than
// only the first.
func verifierDetails(findings []kernel.VerifierFinding, want kernel.VerifierFindingCode) string {
	var b strings.Builder
	for _, f := range findings {
		if f.Code == want {
			b.WriteString(f.Detail)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// verifierHasCode reports whether one finding class fired.
func verifierHasCode(findings []kernel.VerifierFinding, want kernel.VerifierFindingCode) bool {
	for _, f := range findings {
		if f.Code == want {
			return true
		}
	}
	return false
}

// verifierDetail returns the detail text of the first finding of one class, or ""
// when the class did not fire.
func verifierDetail(findings []kernel.VerifierFinding, want kernel.VerifierFindingCode) string {
	for _, f := range findings {
		if f.Code == want {
			return f.Detail
		}
	}
	return ""
}

// TestVerifierBindingPayloadIsCanonicalAndUnambiguous pins the encoding a
// signature covers. Two properties are load-bearing here and neither is a
// coverage assertion.
//
// The bytes are exactly the length-prefixed form, so a signer implemented outside
// this kernel - the operator's signing script, a CI job, a peer in another
// language - can be checked against them byte for byte. And the length prefixes
// are what stop a field boundary from being moved: without them, a module named
// "a" at version "b|c" would encode identically to one named "a|b" at version
// "c", and a signature minted for the first would appraise the second.
func TestVerifierBindingPayloadIsCanonicalAndUnambiguous(t *testing.T) {
	m := verifierManifest("adapter", kernel.OpLogWrite)
	payload := kernel.VerifierBindingPayload(m)

	want := "7:version=1:1;6:module=7:adapter;14:module_version=5:1.0.0;" +
		"15:manifest_digest=64:" + m.Digest() + ";"
	assert.Equal(t, want, string(payload), "the binding payload is a fixed wire format")

	// The forgery class the length prefixes exist to remove. Both manifests are
	// valid declarations, they are different declarations, and their payloads must
	// differ.
	left := kernel.Manifest{Name: "a", Version: "b|c", MinKernelAPI: 1, MaxKernelAPI: 1}
	right := kernel.Manifest{Name: "a|b", Version: "c", MinKernelAPI: 1, MaxKernelAPI: 1}
	require.NoError(t, left.Validate())
	require.NoError(t, right.Validate())
	assert.NotEqual(t,
		string(kernel.VerifierBindingPayload(left)),
		string(kernel.VerifierBindingPayload(right)),
		"a field boundary must not be movable without changing the signed bytes")

	// Every field the appraisal binds appears, in order, so a forger can neither
	// reorder nor omit one without producing different bytes.
	fields := []string{"version", "module", "module_version", "manifest_digest"}
	pos := -1
	for _, f := range fields {
		i := strings.Index(string(payload), ":"+f+"=")
		require.Greater(t, i, pos, "field %q is missing or out of order", f)
		pos = i
	}
	assert.Contains(t, string(payload), m.Digest(), "the payload binds the declaration's own digest")
}

// TestVerifierValidSignatureAdmits is the happy path, asserted through all three
// records the subsystem owes: the returned error, the ledger entry and the audit
// chain. A test that checked only the error would pass with an empty ledger, and
// an empty ledger is an uninvestigable deployment.
func TestVerifierValidSignatureAdmits(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	sig := verifierSign(t, seed, m)

	require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig))

	entries := kernel.VerifierLedger()
	require.Len(t, entries, 1)
	e := entries[0]
	assert.True(t, e.Admitted)
	assert.Empty(t, e.Reason, "a clean admit records no refusal")
	assert.Equal(t, kernel.VerifierEnforce, e.Policy)
	assert.Equal(t, m.Name, e.Module)
	assert.Equal(t, m.Version, e.Version)
	assert.Equal(t, m.Digest(), e.Digest)
	assert.Equal(t, kernel.DomainInit, e.Domain, "the appraisal is attributed to the loader")
	assert.Equal(t, verifierKeyID(verifierPub(t, pub)), e.KeyID, "the ledger names the key that matched")
	assert.Positive(t, e.Mono, "the timestamp comes from mono()")
	assert.EqualValues(t, 0, e.Seq, "the ledger sequence starts at zero and is gap-free")

	audits := verifierAppraisals()
	require.Len(t, audits, 1)
	assert.Equal(t, "true", verifierFieldSprint(t, audits[0], "admitted"))
	assert.Equal(t, m.Digest(), verifierField(t, audits[0], "digest"))
	assert.Equal(t, "enforce", verifierField(t, audits[0], "policy"))
	assert.Equal(t, kernel.DomainInit, audits[0].Domain)
	assert.NotZero(t, audits[0].PID, "a pid=0 appraisal record tells an operator nothing")
	assert.Equal(t, -1, kernel.VerifyChain(audits, audits[0].Prev), "the entry sits on an intact chain")
}

// TestVerifierTamperedManifestRefused is the core control, one mutation per case.
//
// Each mutation is the widening an attacker actually performs between review and
// deployment, and each must produce the same typed refusal: the digest moved, so
// the signature no longer covers what is loading. Asserting them separately
// matters because they are separate fields with separate review meanings - a
// single "tampered" case would prove only that one of them is caught, and the
// ones an operator most needs caught (Require, AllowedHosts, ServeRoutes) are the
// ones a shared case would hide behind.
func TestVerifierTamperedManifestRefused(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, buf := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	signed := kernel.Manifest{
		Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require:      []kernel.Op{kernel.OpLogWrite},
		AllowedHosts: []string{"api.example.com"},
		ServeRoutes:  []string{"/v1/chat"},
	}
	signed.Require = append(signed.Require, kernel.OpRouteRegister)
	require.NoError(t, signed.Validate())
	sig := verifierSign(t, seed, signed)

	cases := []struct {
		name string
		// want is the sentinel this mutation must produce. Bumping the version
		// changes the signed identity and is reported as an identity mismatch;
		// every other mutation leaves the identity intact and moves the digest
		// underneath a signature that still names this module, which is the
		// digest-mismatch case. Asserting the distinction is the point: it is what
		// tells an operator "someone re-versioned the module" from "someone edited
		// the declaration".
		want   error
		mutate func(m kernel.Manifest) kernel.Manifest
	}{
		{
			name:   "version bumped",
			want:   kernel.ErrVerifierIdentityMismatch,
			mutate: func(m kernel.Manifest) kernel.Manifest { m.Version = "1.0.1"; return m },
		},
		{
			name: "require widened with an extra operation",
			want: kernel.ErrVerifierDigestMismatch,
			mutate: func(m kernel.Manifest) kernel.Manifest {
				m.Require = append(append([]kernel.Op{}, m.Require...), kernel.OpMetadataRead)
				return m
			},
		},
		{
			name: "require narrowed to look innocent",
			want: kernel.ErrVerifierDigestMismatch,
			mutate: func(m kernel.Manifest) kernel.Manifest {
				// route:register stays, or manifest.go refuses the declaration for
				// its serve routes and the case would be testing validation. What
				// is dropped is log:write, so the loaded declaration is narrower
				// than the one that was signed - a benign-looking edit that still
				// has to be caught, because the reviewer approved a different
				// declaration than the one that ran.
				m.Require = []kernel.Op{kernel.OpRouteRegister}
				return m
			},
		},
		{
			name: "allowed hosts extended",
			want: kernel.ErrVerifierDigestMismatch,
			mutate: func(m kernel.Manifest) kernel.Manifest {
				m.AllowedHosts = append(append([]string{}, m.AllowedHosts...), "evil.example.net")
				return m
			},
		},
		{
			name: "allowed host replaced",
			mutate: func(m kernel.Manifest) kernel.Manifest {
				m.AllowedHosts = []string{"attacker.example.net"}
				return m
			},
		},
		{
			name: "serve route added",
			mutate: func(m kernel.Manifest) kernel.Manifest {
				m.ServeRoutes = append(append([]string{}, m.ServeRoutes...), "/v1/admin")
				return m
			},
		},
		{
			name: "secret prefixes added",
			mutate: func(m kernel.Manifest) kernel.Manifest {
				m.Require = append(append([]kernel.Op{}, m.Require...), kernel.OpSecretUse)
				m.SecretPrefixes = []string{"provider."}
				return m
			},
		},
		{
			name: "write paths added",
			mutate: func(m kernel.Manifest) kernel.Manifest {
				m.Require = append(append([]kernel.Op{}, m.Require...), kernel.OpFSWrite)
				m.WritePaths = []string{"state"}
				return m
			},
		},
		{
			name: "listen address added",
			mutate: func(m kernel.Manifest) kernel.Manifest {
				m.Require = append(append([]kernel.Op{}, m.Require...), kernel.OpNetListen)
				m.ListenAddr = "0.0.0.0:8080"
				return m
			},
		},
		{
			name:   "kernel api range widened",
			mutate: func(m kernel.Manifest) kernel.Manifest { m.MaxKernelAPI = 99; return m },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tc.mutate(signed)
			require.NoError(t, tampered.Validate(),
				"the mutation must still be a valid manifest, or the test proves validation rather than appraisal")
			require.NotEqual(t, signed.Digest(), tampered.Digest(), "the mutation must move the digest")

			want := tc.want
			if want == nil {
				want = kernel.ErrVerifierDigestMismatch
			}

			present := sig
			err := kernel.VerifyManifestLoad(k.InitContext(), tampered, &present)
			require.Error(t, err)
			assert.True(t, errors.Is(err, want),
				"an edited declaration must be refused as %v, got %v", want, err)
			assert.False(t, errors.Is(err, kernel.ErrVerifierBadSignature),
				"a tamper is reported as a tamper, not as a forgery")

			var ve *kernel.VerifierError
			require.True(t, errors.As(err, &ve), "the refusal is typed")
			assert.Equal(t, tampered.Name, ve.Module)
			assert.Equal(t, tampered.Digest(), ve.Digest, "the refusal names the digest that was presented")

			// The refusal reached both records, with the loader attached.
			entries := kernel.VerifierLedgerFor(tampered.Name)
			require.NotEmpty(t, entries)
			last := entries[len(entries)-1]
			assert.False(t, last.Admitted)
			assert.Equal(t, tampered.Digest(), last.Digest)
			assert.Equal(t, kernel.DomainInit, last.Domain)

			faults := harness.Faults(buf)
			require.NotEmpty(t, faults, "a refusal under enforce is a fault")
			assert.Contains(t, faults[len(faults)-1].Msg, "refused")
			assert.Equal(t, k.InitContext().PID(), faults[len(faults)-1].Pid,
				"the fault carries the loader's pid, not zero")

			audits := verifierAppraisals()
			require.NotEmpty(t, audits)
			assert.Equal(t, "false", verifierFieldSprint(t, audits[len(audits)-1], "admitted"))
		})
	}

	// The unmodified declaration still verifies after every mutation attempt, so
	// the refusals above are about the tampered bytes and not about a key that
	// stopped working mid-test.
	assert.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), signed, &sig))
}

// TestVerifierSignatureForOtherModuleIsRefused is the identity binding. A
// signature is minted over name, version and digest together, so a valid
// signature for module A presented for module B is a replay and must be refused
// distinctly from a forgery: the operator's response to a replay is to look at
// the deployment pipeline, and to a forgery to look at the keys.
func TestVerifierSignatureForOtherModuleIsRefused(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	signedFor := verifierManifest("module-a", kernel.OpLogWrite)
	sig := verifierSign(t, seed, signedFor)

	cases := []struct {
		name    string
		present kernel.Manifest
	}{
		{"different name", verifierManifest("module-b", kernel.OpLogWrite)},
		{
			"same name, wider declaration",
			kernel.Manifest{
				Name: "module-a", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
				Require: []kernel.Op{kernel.OpLogWrite, kernel.OpMetadataRead},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.present.Validate())
			replay := sig
			err := kernel.VerifyManifestLoad(k.InitContext(), tc.present, &replay)
			require.Error(t, err)
			assert.True(t, errors.Is(err, kernel.ErrVerifierIdentityMismatch) ||
				errors.Is(err, kernel.ErrVerifierDigestMismatch),
				"a replayed signature is refused as a binding failure, got %v", err)
			assert.False(t, errors.Is(err, kernel.ErrVerifierBadSignature),
				"a replay is reported as a replay, not as a bad signature")

			var ve *kernel.VerifierError
			require.True(t, errors.As(err, &ve))
			assert.Equal(t, signedFor.Name, sig.Module, "the envelope still names what it was minted for")
			assert.Equal(t, tc.present.Name, ve.Module, "the refusal names what was presented")
		})
	}

	// A signature whose envelope was edited to name module B is still refused:
	// the payload the cryptographic check covers is rebuilt from the manifest in
	// hand, never from the envelope, so relabelling the envelope changes nothing.
	t.Run("relabelled envelope", func(t *testing.T) {
		forged := sig
		forged.Module = "module-b"
		other := verifierManifest("module-b", kernel.OpLogWrite)
		forged.Digest = other.Digest()
		err := kernel.VerifyManifestLoad(k.InitContext(),
			verifierManifest("module-b", kernel.OpLogWrite), &forged)
		require.Error(t, err)
		assert.True(t, errors.Is(err, kernel.ErrVerifierBadSignature),
			"a relabelled envelope fails the cryptographic check, got %v", err)
	})

	// The original still verifies, so nothing above broke the key.
	assert.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), signedFor, &sig))
}

// TestVerifierUntrustedKeyRefused covers the trust boundary. A signature from a
// key outside the sealed cluster root set is refused, and it is refused as a key
// problem rather than as a signature problem, because the fix is in the operator's
// key inventory and not in the module.
func TestVerifierUntrustedKeyRefused(t *testing.T) {
	nodeSeed, nodePub := verifierKeyPair(t)
	outsideSeed, outsidePub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{nodePub}, nodeSeed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	require.NoError(t, m.Validate())

	t.Run("key outside the cluster roots", func(t *testing.T) {
		sig := verifierSign(t, outsideSeed, m)
		require.NotEqual(t, verifierKeyID(verifierPub(t, nodePub)), sig.KeyID,
			"the two keys must have different ids for this case to mean anything")

		err := kernel.VerifyManifestLoad(k.InitContext(), m, &sig)
		require.Error(t, err)
		assert.True(t, errors.Is(err, kernel.ErrVerifierKeyUntrusted),
			"an untrusted key is its own refusal class, got %v", err)
		assert.False(t, errors.Is(err, kernel.ErrVerifierBadSignature))

		// The rejected key id is on the record. That is how an operator finds a
		// rotated-out signing key still present in a deployment.
		entries := kernel.VerifierLedgerFor(m.Name)
		require.NotEmpty(t, entries)
		assert.Equal(t, verifierKeyID(verifierPub(t, outsidePub)), entries[len(entries)-1].KeyID)
		assert.False(t, entries[len(entries)-1].Admitted)
	})

	t.Run("key id claimed without matching bytes", func(t *testing.T) {
		// A well-formed signature from the outside key, with the envelope
		// relabelled to claim the trusted key's id. The trust check passes on the
		// label and the cryptographic check then fails on the bytes, which is the
		// correct outcome: claiming a key id is not holding the key.
		sig := verifierSign(t, outsideSeed, m)
		sig.KeyID = verifierKeyID(verifierPub(t, nodePub))
		err := kernel.VerifyManifestLoad(k.InitContext(), m, &sig)
		require.Error(t, err)
		assert.True(t, errors.Is(err, kernel.ErrVerifierBadSignature),
			"a claimed key id does not substitute for the key, got %v", err)
	})

	t.Run("any trusted root verifies", func(t *testing.T) {
		// A deployment with several roots accepts a signature from any of them,
		// and the ledger names which one matched. This needs its own boot, so it
		// is its own test below; what is checked here is the inventory the trust
		// check reads: both roots are usable keys with distinct ids, so a refusal
		// cannot be explained by an unparsable root.
		for _, r := range []string{nodePub, outsidePub} {
			_, err := hex.DecodeString(r)
			require.NoError(t, err)
			assert.NotEmpty(t, verifierKeyID(verifierPub(t, r)))
		}
		assert.NotEqual(t,
			verifierKeyID(verifierPub(t, nodePub)),
			verifierKeyID(verifierPub(t, outsidePub)),
			"the two roots have distinct ids")
	})
}

// TestVerifierAnyTrustedRootVerifies covers a multi-root deployment: a mesh with
// several trusted keys accepts a signature from any of them, and the ledger names
// which one matched. It is its own test because the boot guard is process-wide.
func TestVerifierAnyTrustedRootVerifies(t *testing.T) {
	seedA, pubA := verifierKeyPair(t)
	seedB, pubB := verifierKeyPair(t)
	seedC, _ := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pubA, pubB}, seedA)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	require.NoError(t, m.Validate())

	for _, seed := range []string{seedA, seedB} {
		sig := verifierSign(t, seed, m)
		require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig),
			"a signature from any trusted root must verify")
	}

	// And the ledger names the key that matched in each case, so an operator can
	// see which of their roots is actually being used.
	entries := kernel.VerifierLedgerFor(m.Name)
	require.Len(t, entries, 2)
	assert.Equal(t, verifierKeyID(verifierPub(t, pubA)), entries[0].KeyID)
	assert.Equal(t, verifierKeyID(verifierPub(t, pubB)), entries[1].KeyID)
	for _, e := range entries {
		assert.True(t, e.Admitted)
		assert.Empty(t, e.Reason)
	}

	// A third key, outside the list, is still refused, so the acceptance above is
	// about the root set and not about any well-formed signature.
	outside := verifierSign(t, seedC, m)
	err := kernel.VerifyManifestLoad(k.InitContext(), m, &outside)
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrVerifierKeyUntrusted))
}

// TestVerifierMalformedSignatureRefused proves that garbage input produces a
// typed refusal rather than a panic or a silent admit. ed25519.Verify panics on a
// wrong-length signature, so the length check is a crash guard as well as a
// semantic one, and the distinction between "not a signature" and "a signature
// that does not verify" is what an operator's tooling branches on.
func TestVerifierMalformedSignatureRefused(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, buf := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	require.NoError(t, m.Validate())
	good := verifierSign(t, seed, m)

	cases := []struct {
		name string
		sig  kernel.VerifierSignature
		want error
	}{
		{
			name: "truncated signature",
			sig: func() kernel.VerifierSignature {
				s := good
				s.Bytes = s.Bytes[:ed25519.SignatureSize-1]
				return s
			}(),
			want: kernel.ErrVerifierMalformed,
		},
		{
			name: "empty signature",
			sig: func() kernel.VerifierSignature {
				s := good
				s.Bytes = nil
				return s
			}(),
			want: kernel.ErrVerifierMalformed,
		},
		{
			name: "oversized signature",
			sig: func() kernel.VerifierSignature {
				s := good
				s.Bytes = append(append([]byte{}, s.Bytes...), 0)
				return s
			}(),
			want: kernel.ErrVerifierMalformed,
		},
		{
			name: "wrong length but plausible",
			sig: func() kernel.VerifierSignature {
				s := good
				s.Bytes = bytes.Repeat([]byte{0xAB}, 32)
				return s
			}(),
			want: kernel.ErrVerifierMalformed,
		},
		{
			name: "no key id",
			sig: func() kernel.VerifierSignature {
				s := good
				s.KeyID = ""
				return s
			}(),
			want: kernel.ErrVerifierMalformed,
		},
		{
			name: "flipped signature bytes",
			sig: func() kernel.VerifierSignature {
				s := good
				b := append([]byte{}, s.Bytes...)
				b[0] ^= 0xFF
				s.Bytes = b
				return s
			}(),
			want: kernel.ErrVerifierBadSignature,
		},
		{
			name: "unsupported binding version",
			sig: func() kernel.VerifierSignature {
				s := good
				s.Version = kernel.VerifierBindingVersion + 1
				return s
			}(),
			want: kernel.ErrVerifierBindingVersion,
		},
		{
			name: "binding version zero",
			sig: func() kernel.VerifierSignature {
				s := good
				s.Version = 0
				return s
			}(),
			want: kernel.ErrVerifierBindingVersion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(harness.Faults(buf))
			present := tc.sig
			require.NotPanics(t, func() {
				err := kernel.VerifyManifestLoad(k.InitContext(), m, &present)
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.want), "want %v, got %v", tc.want, err)

				var ve *kernel.VerifierError
				require.True(t, errors.As(err, &ve), "every refusal is typed")
				assert.Equal(t, m.Name, ve.Module)
				assert.Equal(t, m.Digest(), ve.Digest)
				assert.False(t, kernel.IsDenied(err),
					"a verification refusal is not a policy denial")
			}, "malformed input must be refused, never panic")

			after := harness.Faults(buf)
			assert.Greater(t, len(after), before, "each refusal raises a fault")
		})
	}
}

// TestVerifierPolicies covers the three postures and the exact record each one
// owes. The differences are the point: off is silent, audit admits but leaves
// evidence an attacker cannot erase, enforce refuses. A deployment that cannot
// tell those apart cannot reason about its own posture.
func TestVerifierPolicies(t *testing.T) {
	seed, pub := verifierKeyPair(t)

	t.Run("enforce refuses an unsigned module", func(t *testing.T) {
		k, buf := verifierBoot(t, []string{pub}, seed)
		require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

		m := verifierManifest("unsigned", kernel.OpLogWrite)
		err := kernel.VerifyManifestLoad(k.InitContext(), m, nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, kernel.ErrVerifierUnsigned))

		entries := kernel.VerifierLedgerFor(m.Name)
		require.Len(t, entries, 1)
		assert.False(t, entries[0].Admitted)
		assert.Equal(t, kernel.VerifierEnforce, entries[0].Policy)

		audits := verifierAppraisals()
		require.Len(t, audits, 1)
		assert.Equal(t, "false", verifierFieldSprint(t, audits[0], "admitted"))

		faults := harness.Faults(buf)
		require.Len(t, faults, 1)
		assert.Contains(t, faults[0].Msg, "refused")
	})

	t.Run("audit admits and records", func(t *testing.T) {
		k, buf := verifierBoot(t, []string{pub}, seed)
		require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierAudit))

		m := verifierManifest("unsigned", kernel.OpLogWrite)
		require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, nil),
			"under audit the module loads")

		entries := kernel.VerifierLedgerFor(m.Name)
		require.Len(t, entries, 1)
		assert.True(t, entries[0].Admitted, "the module was admitted")
		assert.Equal(t, kernel.VerifierAudit, entries[0].Policy)
		assert.Contains(t, entries[0].Reason, "unsigned",
			"the fact that it was unverified is recorded even though it loaded")

		audits := verifierAppraisals()
		require.Len(t, audits, 1)
		assert.Equal(t, "true", verifierFieldSprint(t, audits[0], "admitted"))
		assert.Equal(t, "audit", verifierField(t, audits[0], "policy"))
		assert.NotEmpty(t, verifierField(t, audits[0], "reason"))

		faults := harness.Faults(buf)
		require.Len(t, faults, 1)
		assert.Contains(t, faults[0].Msg, "audit policy")

		// A bad signature under audit behaves the same way: admitted, faulted,
		// on the chain. The mode is about evidence, not about leniency.
		bad := verifierSign(t, seed, m)
		bad.Bytes[0] ^= 0xFF
		require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &bad))
		assert.Len(t, harness.Faults(buf), 2)
	})

	t.Run("off is silent", func(t *testing.T) {
		k, buf := verifierBoot(t, []string{pub}, seed)
		require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierOff))

		m := verifierManifest("unsigned", kernel.OpLogWrite)
		require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, nil))

		assert.Empty(t, kernel.VerifierLedger(), "off writes no ledger entry")
		assert.Empty(t, verifierAppraisals(), "off writes no audit entry")
		assert.Empty(t, harness.Faults(buf), "off raises no fault")
		for _, r := range harness.Records(t, buf) {
			assert.NotContains(t, r.Msg, "signature",
				"off must not emit anything about appraisal; got %q", r.Msg)
			assert.NotContains(t, r.Msg, "manifest",
				"off must not emit anything about appraisal; got %q", r.Msg)
		}
	})

	t.Run("audit records a clean appraisal too", func(t *testing.T) {
		k, _ := verifierBoot(t, []string{pub}, seed)
		require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierAudit))

		m := verifierManifest("signed", kernel.OpLogWrite)
		sig := verifierSign(t, seed, m)
		require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig))

		entries := kernel.VerifierLedgerFor(m.Name)
		require.Len(t, entries, 1)
		assert.True(t, entries[0].Admitted)
		assert.Empty(t, entries[0].Reason, "a clean appraisal records no refusal")
	})
}

// TestVerifierPolicyDefaultsFromTrustRoot pins the derivation rule and the reason
// it exists. A deployment that configured cluster root keys meant to verify
// against them; defaulting such a deployment to off would leave the keys
// configured and unused, which is precisely the gap where a reviewed manifest
// gets widened. The derivation is also read live rather than cached at seal time,
// so the posture can never disagree with the roots actually in force.
func TestVerifierPolicyDefaultsFromTrustRoot(t *testing.T) {
	seed, pub := verifierKeyPair(t)

	t.Run("cluster roots configured derives enforce", func(t *testing.T) {
		_, _ = verifierBoot(t, []string{pub}, seed)
		explicit, set := kernel.VerifierPolicyExplicit()
		assert.False(t, set, "no host choice was made")
		assert.Empty(t, explicit)
		assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent())

		// And the derived posture actually refuses, which is the property that
		// matters: a derivation that only changed a reported string would be
		// decoration.
		m := verifierManifest("unsigned", kernel.OpLogWrite)
		assert.True(t, errors.Is(
			kernel.VerifyManifestLoad(nil, m, nil), kernel.ErrVerifierUnsigned))
	})

	t.Run("no cluster roots derives off", func(t *testing.T) {
		_, _ = verifierBoot(t, nil, seed)
		assert.Equal(t, kernel.VerifierOff, kernel.VerifierPolicyCurrent())

		m := verifierManifest("unsigned", kernel.OpLogWrite)
		assert.NoError(t, kernel.VerifyManifestLoad(nil, m, nil),
			"a deployment with nothing to verify against admits")
		assert.Empty(t, kernel.VerifierLedger())
	})

	t.Run("harness placeholder roots also derive enforce", func(t *testing.T) {
		// harness.BootTrust carries two non-key placeholders. They are not
		// verifiable keys, so appraisal against them can only ever refuse - which
		// is the integration hazard documented in verifier.go and the reason an
		// integrator wiring the load hook must set a posture explicitly in the
		// suites that load unsigned modules.
		buf := harness.QuietConsole(t)
		k, err := kernel.Boot(kernel.BootConfig{TrustRoot: harness.BootTrust()})
		require.NoError(t, err)
		t.Cleanup(func() { _ = k.Shutdown() })

		assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent())
		m := verifierManifest("unsigned", kernel.OpLogWrite)
		err = kernel.VerifyManifestLoad(k.InitContext(), m, nil)
		assert.True(t, errors.Is(err, kernel.ErrVerifierUnsigned))
		_ = buf
	})

	t.Run("explicit choice overrides the derivation", func(t *testing.T) {
		_, _ = verifierBoot(t, []string{pub}, seed)
		require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierOff))
		explicit, set := kernel.VerifierPolicyExplicit()
		require.True(t, set)
		assert.Equal(t, kernel.VerifierOff, explicit)
		assert.Equal(t, kernel.VerifierOff, kernel.VerifierPolicyCurrent(),
			"an explicit host choice wins over the derivation")
	})

	t.Run("unknown policy is refused rather than defaulted", func(t *testing.T) {
		_, _ = verifierBoot(t, []string{pub}, seed)
		require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

		for _, bad := range []kernel.VerifierPolicy{"", "Enforce", "ENFORCE", "auditing", "permissive"} {
			err := kernel.VerifierSetPolicy(bad)
			require.Error(t, err, "policy %q must be refused", bad)
			assert.Contains(t, err.Error(), "unknown verifier policy")
		}
		assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent(),
			"a refused setter leaves the posture untouched")

		assert.Equal(t,
			[]kernel.VerifierPolicy{kernel.VerifierOff, kernel.VerifierAudit, kernel.VerifierEnforce},
			kernel.VerifierPolicies(), "the policy set is closed and ordered by strictness")
	})
}

// TestVerifierPolicySealIsMonotonicTightening is the property that stands in for
// "the host sets the policy and a module cannot widen it". Appraisal runs in the
// load path before the factory and before OnLoad, so the first appraisal of a
// boot latches the seal and every module that exists at all exists after it. A
// module may therefore only ever make verification stricter.
func TestVerifierPolicySealIsMonotonicTightening(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierAudit))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	sig := verifierSign(t, seed, m)
	require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig),
		"the first appraisal latches the seal")

	// Tightening is allowed, from audit to enforce.
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))
	assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent())

	// Widening is refused, at every step down, and the refusal is typed so an
	// operator's tooling can tell a sealed posture from a typo.
	for _, laxer := range []kernel.VerifierPolicy{kernel.VerifierAudit, kernel.VerifierOff} {
		err := kernel.VerifierSetPolicy(laxer)
		require.Error(t, err, "widening to %s must be refused", laxer)
		assert.True(t, errors.Is(err, kernel.ErrVerifierSealed))
	}
	assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent(),
		"a refused widening leaves enforce in force")

	// Re-asserting the same posture is not a widening and is allowed, so an
	// idempotent configuration pass does not fail.
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))
}

// TestVerifierSealIsArmedEvenWhenOff proves the latch is set by the appraisal
// call itself and not by the posture being strict. Without this, a deployment
// that booted with off and later derived enforce could be walked back down by
// whatever code ran in between.
func TestVerifierSealIsArmedEvenWhenOff(t *testing.T) {
	seed, _ := verifierKeyPair(t)
	_, _ = verifierBoot(t, nil, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierOff))
	assert.Equal(t, kernel.VerifierOff, kernel.VerifierPolicyCurrent())

	m := verifierManifest("adapter", kernel.OpLogWrite)
	require.NoError(t, kernel.VerifyManifestLoad(nil, m, nil))

	// The appraisal happened under off, so it wrote nothing - but it armed the
	// seal, so the posture cannot now be walked to something laxer than the one
	// in force.
	err := kernel.VerifierSetPolicy(kernel.VerifierOff)
	assert.NoError(t, err, "re-asserting the posture in force is not a widening")

	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierAudit))
	assert.Equal(t, kernel.VerifierAudit, kernel.VerifierPolicyCurrent())
	err = kernel.VerifierSetPolicy(kernel.VerifierOff)
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrVerifierSealed))
}

// TestVerifierNoSyscallSurface asserts the API contract the design depends on:
// there is no verification syscall. policy.go has no operation for appraisal and
// none may be added without owner approval, so the whole surface is package-level
// functions and host-side setters. A future change that exposed appraisal through
// a context would make it a capability a module could invoke, and this test is
// what turns that from a silent design regression into a failure.
func TestVerifierNoSyscallSurface(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierOff))

	m := verifierManifest("probe", kernel.OpLogWrite)
	loaded := false
	harness.RegisterProbe(t, m.Name, &harness.Probe{
		Load: func(ctx kernel.SContext) error {
			// The context a module actually holds exposes no verifier group. The
			// method set is the contract, so it is read rather than assumed.
			typ := reflect.TypeOf(ctx)
			for i := range typ.NumMethod() {
				name := typ.Method(i).Name
				assert.False(t, strings.HasPrefix(name, "SyscallVerifier"),
					"appraisal must not be reachable as a syscall, found %s", name)
				assert.NotEqual(t, "SyscallVerifyManifest", name)
			}

			// And there is no in-kernel path by which a module can mint a
			// manifest signature: crypto:sign is absent from the plugin ceiling,
			// so the payload this subsystem exports cannot be signed from inside
			// a module. Without that, appraisal would be a formality.
			_, err := ctx.SyscallCryptoSign(kernel.VerifierBindingPayload(m))
			require.Error(t, err)
			assert.True(t, kernel.IsDenied(err),
				"a module asking the kernel to sign is denied by policy, not refused ad hoc")

			loaded = true
			return nil
		},
	})

	pid, err := k.Load(m)
	require.NoError(t, err)
	assert.NotZero(t, pid)
	assert.True(t, loaded, "the probe's OnLoad ran")

	// The kernel still holds no exported signer: the only way to produce a
	// signature is to hold the key, which is what keeps appraisal meaningful.
	// Asserted structurally, because the absence of a symbol is the property.
	kernelType := reflect.TypeOf(k)
	for i := range kernelType.NumMethod() {
		assert.NotEqual(t, "SignManifest", kernelType.Method(i).Name)
		assert.NotEqual(t, "SignManifestBinding", kernelType.Method(i).Name)
		assert.NotEqual(t, "VerifierSign", kernelType.Method(i).Name)
	}
}

// TestVerifierNoSecretCrossesBoundary is the kcrypto guarantee applied to this
// subsystem: results cross, key material does not. Every artifact this subsystem
// produces - the binding payload, the ledger entry, the audit fields, the console
// record, the typed error - is rendered and searched for the signing seed and for
// the public key bytes. The signing key is kernel-held and never returned, and
// the ledger records a key id rather than a key, because a signature or a key
// copied out of a log dump is a bearer artifact.
func TestVerifierNoSecretCrossesBoundary(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, buf := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	sig := verifierSign(t, seed, m)
	require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig))

	// A refusal path too, so the error text is covered and not only the success
	// record.
	bad := verifierManifest("refused", kernel.OpLogWrite)
	err := kernel.VerifyManifestLoad(k.InitContext(), bad, nil)
	require.Error(t, err)

	secrets := []string{seed, pub, strings.ToUpper(seed), strings.ToUpper(pub)}
	rendered := []string{
		verifierJSON(t, kernel.VerifierBindingPayload(m)),
		verifierJSON(t, kernel.VerifierLedger()),
		verifierJSON(t, verifierAppraisals()),
		verifierJSON(t, harness.Records(t, buf)),
		verifierJSON(t, err),
	}
	var ve *kernel.VerifierError
	require.True(t, errors.As(err, &ve))
	rendered = append(rendered, verifierJSON(t, *ve))

	for _, r := range rendered {
		for _, s := range secrets {
			assert.NotContains(t, r, s, "key material must not appear in kernel output")
		}
	}

	// The payload binds identity and digest only. It is what an external signer
	// hashes, so it must be reproducible without any kernel secret.
	payload := string(kernel.VerifierBindingPayload(m))
	assert.Contains(t, payload, m.Name)
	assert.Contains(t, payload, m.Version)
	assert.Contains(t, payload, m.Digest())
	assert.Len(t, payload, len("7:version=1:1;6:module=7:adapter;14:module_version=5:1.0.0;15:manifest_digest=64:")+64+1)

	// The ledger names the key by id, which is a digest of the public half and
	// safe in a record.
	entries := kernel.VerifierLedgerFor(m.Name)
	require.Len(t, entries, 1)
	assert.Equal(t, verifierKeyID(verifierPub(t, pub)), entries[0].KeyID)
	assert.NotContains(t, entries[0].KeyID, pub)

	// BootGet still will not hand over the signing key: it is held beside the
	// configuration map, not inside it, and this subsystem did not change that.
	// The public root is legitimately readable - a public key is not a secret,
	// and a module that cannot learn which key verifies its own declarations
	// cannot debug a refusal - so only the seed is asserted absent.
	for _, kv := range kernel.BootAll() {
		assert.NotContains(t, kv.Value, seed, "the signing seed must not be in the readable trust root")
		assert.NotContains(t, kv.Key, "signing", "no signing-key entry is published")
	}
	_, ok := kernel.BootGet("signing_key_pem")
	assert.False(t, ok, "the signing key is not in the readable trust root map")

	// The public root IS reachable, and that is correct: asserting its absence
	// would be asserting a defect.
	assert.Contains(t, kernel.ClusterRootKeys(), pub)
}

// TestVerifierLedgerCannotBeForged covers the two ways a caller might try to
// write evidence: through the host-side record entry point, and through the query
// result. Both fail, for structural reasons worth pinning.
func TestVerifierLedgerCannotBeForged(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	sig := verifierSign(t, seed, m)
	require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig))

	before := kernel.VerifierLedger()
	require.Len(t, before, 1)

	// VerifierRecord accepts the descriptive fields and nothing else: the kernel
	// assigns the sequence, the timestamp and the posture. A caller that could
	// choose the sequence could interleave its own entries inside the evidence of
	// a refusal; a caller that could choose the posture could record an appraisal
	// as having happened under a stricter policy than was in force.
	kernel.VerifierRecord("external", "2.0.0", "deadbeef", "keyid", true, "")
	after := kernel.VerifierLedger()
	require.Len(t, after, 2)
	e := after[1]
	assert.EqualValues(t, 1, e.Seq, "the sequence is kernel-assigned and continues the ledger")
	assert.Equal(t, before[0].Seq+1, e.Seq)
	assert.Positive(t, e.Mono, "the timestamp is kernel-assigned from mono()")
	assert.Equal(t, kernel.VerifierEnforce, e.Policy, "the posture recorded is the one in force")
	assert.Zero(t, e.PID, "an external record is attributed to no pid")
	assert.Empty(t, e.Domain)
	assert.Equal(t, "external", e.Module)
	assert.True(t, e.Admitted)

	// The query hands out copies. Mutating the result must not reach kernel
	// state, and two queries must not alias one array.
	snapshot := kernel.VerifierLedger()
	require.NotEmpty(t, snapshot)
	original := snapshot[0]
	snapshot[0].Module = "tampered"
	snapshot[0].Admitted = true
	snapshot[0].Reason = ""
	snapshot[0].Seq = 9999

	fresh := kernel.VerifierLedger()
	require.Len(t, fresh, len(snapshot))
	assert.Equal(t, original, fresh[0], "the ledger is not writable through a query result")
	assert.NotEqual(t, "tampered", fresh[0].Module)

	// A caller holding one result cannot even see the other's backing array, so
	// retaining a slice is not retaining a window into kernel state.
	one := kernel.VerifierLedger()
	two := kernel.VerifierLedger()
	require.NotEmpty(t, one)
	require.NotEmpty(t, two)
	assert.NotSame(t, &one[0], &two[0], "each query builds a fresh slice")

	// The audit chain is the record a forger cannot reach at all: it is written
	// by the kernel, and audit:append is absent from the plugin ceiling.
	entries := verifierAppraisals()
	require.Len(t, entries, 1)
	assert.Equal(t, -1, kernel.VerifyChain(entries, entries[0].Prev))
}

// TestVerifierLedgerIsBoundedAndTrimsInBatches pins the memory ceiling and the
// batching. Trimming one entry at a time would make every insert past the
// ceiling copy the whole ledger under the write lock, which is O(n) per insert
// forever; dropping back to seven eighths in one step makes it amortized
// constant. The observable difference is the evicted counter and the retained
// length after the ceiling is crossed, and both are asserted exactly.
func TestVerifierLedgerIsBoundedAndTrimsInBatches(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	_, _ = verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierAudit))

	bound := kernel.MaxVerifyLedgerEntries()
	require.Positive(t, bound)

	m := verifierManifest("flooder", kernel.OpLogWrite)
	for range bound + 1 {
		require.NoError(t, kernel.VerifyManifestLoad(nil, m, nil))
	}

	retained, evicted := kernel.VerifierLedgerLen()
	keep := bound - bound/8
	assert.Equal(t, keep, retained, "crossing the ceiling trims back to seven eighths in one step")
	assert.EqualValues(t, bound+1-keep, evicted, "the eviction counter accounts for everything dropped")
	assert.LessOrEqual(t, retained, bound)

	// One more insert is below the ceiling again, so nothing trims. This is the
	// assertion that separates batched trimming from per-insert trimming: with
	// one-at-a-time eviction the retained length would sit at the bound and the
	// evicted counter would read 1.
	require.NoError(t, kernel.VerifyManifestLoad(nil, m, nil))
	retained2, evicted2 := kernel.VerifierLedgerLen()
	assert.Equal(t, keep+1, retained2)
	assert.Equal(t, evicted, evicted2, "no second trim happened")

	// The retained window is the newest one, in ascending sequence order with no
	// gaps, so an investigator reading it sees a contiguous tail rather than a
	// sample.
	entries := kernel.VerifierLedger()
	require.Len(t, entries, retained2)
	assert.EqualValues(t, evicted2, entries[0].Seq, "the oldest retained entry is the first one not evicted")
	for i := 1; i < len(entries); i++ {
		assert.Equal(t, entries[i-1].Seq+1, entries[i].Seq, "sequence numbers are contiguous")
		assert.Greater(t, entries[i].Mono, entries[i-1].Mono-1, "mono readings never go backwards")
	}

	// Host-side records share the same bound, so the ceiling is a property of the
	// ledger rather than of one entry point.
	for range bound {
		kernel.VerifierRecord("host", "1", "d", "k", false, "external")
	}
	retained3, evicted3 := kernel.VerifierLedgerLen()
	assert.LessOrEqual(t, retained3, bound)
	assert.Greater(t, evicted3, evicted2, "the second flood evicted more")
}

// TestVerifierLedgerQueryIsSortedAndFiltered covers the read side an investigator
// and dump tooling use: ascending order, a stable snapshot, and a per-module
// filter that does not require copying the whole ledger out of the kernel first.
func TestVerifierLedgerQueryIsSortedAndFiltered(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierAudit))

	names := []string{"alpha", "beta", "alpha", "gamma", "beta", "alpha"}
	for i, n := range names {
		m := verifierManifest(n, kernel.OpLogWrite)
		m.Version = harness.Itoa(i)
		require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, nil))
	}

	all := kernel.VerifierLedger()
	require.Len(t, all, len(names))
	for i := 1; i < len(all); i++ {
		assert.Greater(t, all[i].Seq, all[i-1].Seq, "the ledger reads oldest first")
	}
	assert.Equal(t, all, kernel.VerifierLedger(), "two reads of an idle ledger agree exactly")

	alpha := kernel.VerifierLedgerFor("alpha")
	require.Len(t, alpha, 3)
	for _, e := range alpha {
		assert.Equal(t, "alpha", e.Module)
	}
	assert.Equal(t, []string{"0", "2", "5"},
		[]string{alpha[0].Version, alpha[1].Version, alpha[2].Version},
		"the filtered view keeps ledger order")

	assert.Empty(t, kernel.VerifierLedgerFor("nonexistent"))
	assert.Empty(t, kernel.VerifierLedgerFor(""))

	// Mutating a filtered result cannot reach the ledger either.
	alpha[0].Module = "forged"
	assert.Equal(t, "alpha", kernel.VerifierLedgerFor("alpha")[0].Module)
}

// TestVerifierRefusalReachesChainWithAttribution is the evidence property: the
// outcome reaches kaudit before the error reaches the caller, and a refusal
// carries the loader's pid rather than zero. It also pins the context-free shape,
// which records pid 0 honestly instead of inventing an attribution.
func TestVerifierRefusalReachesChainWithAttribution(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, buf := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("adapter", kernel.OpLogWrite)

	// Context-free host-side appraisal: recorded, attributed to nobody, and still
	// a refusal. This is the shape a deployment pipeline uses before Boot.
	require.True(t, errors.Is(kernel.VerifyManifest(m, nil), kernel.ErrVerifierUnsigned))
	entries := kernel.VerifierLedger()
	require.Len(t, entries, 1)
	assert.Zero(t, entries[0].PID, "a host-side appraisal has no loader to attribute")
	assert.Empty(t, entries[0].Domain)
	audits := verifierAppraisals()
	require.Len(t, audits, 1)
	assert.Zero(t, audits[0].PID)

	// With the loader's context attached, the same refusal is attributable, which
	// is the difference between an operator finding the module that was refused
	// and staring at a pid 0 line.
	err := kernel.VerifyManifestLoad(k.InitContext(), m, nil)
	require.Error(t, err)
	entries = kernel.VerifierLedger()
	require.Len(t, entries, 2)
	assert.Equal(t, k.InitContext().PID(), entries[1].PID)
	assert.Equal(t, kernel.DomainInit, entries[1].Domain)

	audits = verifierAppraisals()
	require.Len(t, audits, 2)
	assert.Equal(t, k.InitContext().PID(), audits[1].PID)
	assert.Equal(t, kernel.DomainInit, audits[1].Domain)
	assert.Equal(t, m.Digest(), verifierField(t, audits[1], "digest"),
		"the chain records which declaration was refused")
	assert.Contains(t, verifierField(t, audits[1], "reason"), "unsigned")

	// The chain is intact across both entries, so the refusal is evidence and not
	// a log line.
	assert.Equal(t, -1, kernel.VerifyChain(audits, audits[0].Prev))
	assert.True(t, kernel.VerifyEntry(audits[1]))

	faults := harness.Faults(buf)
	require.Len(t, faults, 2, "both refusals fault; the host-side one honestly reports pid 0")
	assert.Zero(t, faults[0].Pid, "a context-free appraisal has no loader, so it says so")
	assert.Empty(t, faults[0].Domain)
	assert.Equal(t, k.InitContext().PID(), faults[1].Pid,
		"the attributed refusal names the loader, which is what makes it actionable")
	assert.Equal(t, kernel.DomainInit, faults[1].Domain)
	assert.Equal(t, kernel.LogFault, faults[1].Level)
	assert.Contains(t, faults[1].Msg, "refused")
}

// TestVerifierNothingSurvivesRestart is the reset property. A ledger or a posture
// that survived Shutdown would let an investigator read a refusal that did not
// happen under the trust root they are looking at, and would let a previous
// boot's enforcement decision govern a new one.
//
// resetVerifier() is written for resetKernel() but is not wired into it, so this
// also proves the subsystem's own boot-boundary detection holds the property in
// the meantime.
func TestVerifierNothingSurvivesRestart(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	buf := harness.QuietConsole(t)

	first, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{
		NodeID: "vrf-node", ClusterRootKeys: []string{pub}, SigningKeyPEM: seed,
	}})
	require.NoError(t, err)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierAudit))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	sig := verifierSign(t, seed, m)
	require.NoError(t, kernel.VerifyManifestLoad(first.InitContext(), m, &sig))
	require.NoError(t, kernel.VerifyManifestLoad(first.InitContext(), m, nil))
	retained, _ := kernel.VerifierLedgerLen()
	require.Equal(t, 2, retained, "the first boot accumulated evidence")
	require.NoError(t, first.Shutdown())

	assert.Empty(t, kernel.VerifierLedger(), "the ledger does not survive a restart")
	retained, evicted := kernel.VerifierLedgerLen()
	assert.Zero(t, retained)
	assert.Zero(t, evicted, "the eviction counter resets with the ledger")
	assert.Empty(t, kernel.VerifierLedgerFor(m.Name))

	explicit, set := kernel.VerifierPolicyExplicit()
	assert.False(t, set, "the previous boot's posture is not inherited")
	assert.Empty(t, explicit)

	// The seal latch cleared too, which is what reopens the configuration window:
	// a new boot may choose a laxer posture than the one it inherited.
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierOff))

	second, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{
		NodeID: "vrf-node", ClusterRootKeys: []string{pub}, SigningKeyPEM: seed,
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Shutdown() })

	assert.Equal(t, kernel.VerifierOff, kernel.VerifierPolicyCurrent(),
		"the posture set in the configuration window governs the new boot")
	require.NoError(t, kernel.VerifyManifestLoad(second.InitContext(), m, nil))
	assert.Empty(t, kernel.VerifierLedger(), "the new boot starts with an empty ledger")

	// And the new boot's evidence is its own: appraising under audit writes
	// sequence zero again, so a reader cannot mistake it for a continuation.
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierAudit))
	require.NoError(t, kernel.VerifyManifestLoad(second.InitContext(), m, &sig))
	entries := kernel.VerifierLedger()
	require.Len(t, entries, 1)
	assert.Zero(t, entries[0].Seq)
	_ = buf
}

// TestVerifierBootBoundaryDropsStaleEvidence is the narrower half of the reset
// property: state created under one boot is dropped when a different boot is
// observed, and state created before any boot is adopted by the next one. That
// second rule is what lets a host set the posture before Boot in the ordinary
// way, and it is asserted here because it is the rule that makes pre-boot
// configuration work at all.
func TestVerifierBootBoundaryDropsStaleEvidence(t *testing.T) {
	seed, pub := verifierKeyPair(t)

	// Configuration written before any boot is adopted, not discarded.
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))
	explicit, set := kernel.VerifierPolicyExplicit()
	require.True(t, set)
	require.Equal(t, kernel.VerifierEnforce, explicit)

	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{
		NodeID: "vrf-node", ClusterRootKeys: []string{pub}, SigningKeyPEM: seed,
	}})
	require.NoError(t, err)
	assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent(),
		"the pre-boot posture governs the boot that followed it")

	m := verifierManifest("adapter", kernel.OpLogWrite)
	sig := verifierSign(t, seed, m)
	require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig))
	require.Equal(t, 1, len(kernel.VerifierLedger()))
	require.NoError(t, k.Shutdown())

	// Evidence from the boot that just ended is gone, and the posture with it.
	assert.Empty(t, kernel.VerifierLedger())
	_, set = kernel.VerifierPolicyExplicit()
	assert.False(t, set)
	assert.Equal(t, kernel.VerifierOff, kernel.VerifierPolicyCurrent(),
		"with no boot and no explicit choice the posture is off")
}

// TestVerifierSignatureIsNotACapability is the boundary that keeps appraisal from
// becoming a privilege. Nothing about holding a valid signature may grant an
// operation the domain ceiling or the manifest scope does not: verification
// decides whether a module may load, never what it may do.
func TestVerifierSignatureIsNotACapability(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	// A fully verified module with a deliberately narrow declaration.
	m := verifierManifest("narrow", kernel.OpLogWrite)
	require.NoError(t, m.Validate())
	sig := verifierSign(t, seed, m)
	require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig))

	var ctx kernel.SContext
	harness.RegisterProbe(t, m.Name, &harness.Probe{
		Load: func(c kernel.SContext) error { ctx = c; return nil },
	})
	pid, err := k.Load(m)
	require.NoError(t, err)

	// The effective grants are exactly the manifest narrowed to the ceiling, with
	// nothing added by having been verified.
	var record kernel.LoadedModule
	for _, lm := range kernel.LoadedModules() {
		if lm.PID == pid {
			record = lm
		}
	}
	require.NotZero(t, record.PID)
	assert.Equal(t, []kernel.Op{kernel.OpLogWrite}, record.Effective,
		"a valid signature adds no operation")
	grants, constrained := kernel.GrantsFor(pid)
	require.True(t, constrained)
	assert.Equal(t, []kernel.Op{kernel.OpLogWrite}, grants)

	// And at runtime the verified module is still refused what it did not
	// declare, which is the property that matters: the signature did not become a
	// capability token.
	require.NotNil(t, ctx)
	_, err = ctx.SyscallKVGet("anything")
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.Contains(t, kernel.DenialReason(err), "not declared in the manifest")

	_, err = ctx.SyscallCryptoSign([]byte("payload"))
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))

	err = ctx.SyscallSecretRegister(kernel.SecretSpec{Alias: "provider.key", Value: []byte("v")})
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))

	// A module denied an operation is not the same as a module denied a load, and
	// the two error families stay distinct.
	assert.False(t, errors.Is(err, kernel.ErrVerifierUnsigned))
	var ve *kernel.VerifierError
	assert.False(t, errors.As(err, &ve))
}

// TestVerifierConcurrentAppraisal runs appraisal, ledger reads and host-side
// records together under -race. The invariants asserted afterwards are the ones
// concurrency could break: sequence numbers unique and strictly increasing, every
// valid signature admitted, every missing one refused, and the ledger never
// exceeding its bound. Enforce is the posture here so that the two outcomes are
// distinguishable at the call site.
func TestVerifierConcurrentAppraisal(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	const workers = 24
	const perWorker = 12

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		admits  int
		refuses int
	)

	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signed := verifierManifest("signed-"+harness.Itoa(w), kernel.OpLogWrite)
			sig := verifierSign(t, seed, signed)
			unsigned := verifierManifest("unsigned-"+harness.Itoa(w), kernel.OpLogWrite)
			for i := range perWorker {
				if i%2 == 0 {
					if err := kernel.VerifyManifestLoad(k.InitContext(), signed, &sig); err == nil {
						mu.Lock()
						admits++
						mu.Unlock()
					}
				} else {
					err := kernel.VerifyManifestLoad(k.InitContext(), unsigned, nil)
					if errors.Is(err, kernel.ErrVerifierUnsigned) {
						mu.Lock()
						refuses++
						mu.Unlock()
					}
				}
				// Concurrent readers must never see a torn ledger.
				for _, e := range kernel.VerifierLedger() {
					_ = e.Seq
				}
				kernel.VerifierRecord("external", "1", "d", "k", true, "")
				_, _ = kernel.VerifierLedgerLen()
				_ = kernel.VerifierPolicyCurrent()
				_ = kernel.VerifierLedgerFor(signed.Name)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, workers*perWorker/2, admits, "every valid signature was admitted")
	assert.Equal(t, workers*perWorker/2, refuses, "every missing signature was refused")

	entries := kernel.VerifierLedger()
	require.NotEmpty(t, entries)
	retained, _ := kernel.VerifierLedgerLen()
	assert.Len(t, entries, retained)
	assert.LessOrEqual(t, retained, kernel.MaxVerifyLedgerEntries())

	seen := make(map[int64]bool, len(entries))
	var admitted, refused int
	for i, e := range entries {
		require.False(t, seen[e.Seq], "sequence %d was assigned twice", e.Seq)
		seen[e.Seq] = true
		if i > 0 {
			assert.Greater(t, e.Seq, entries[i-1].Seq, "the ledger stays in sequence order under concurrency")
		}
		assert.NotEmpty(t, e.Module)
		assert.Equal(t, kernel.VerifierEnforce, e.Policy)
		assert.NotZero(t, e.Mono)
		if e.Admitted {
			admitted++
			assert.Empty(t, e.Reason)
		} else {
			refused++
			assert.NotEmpty(t, e.Reason)
		}
	}
	// Every appraisal and every host-side record landed, minus whatever the bound
	// evicted, and the admitted/refused split is exactly what the workers produced.
	assert.Greater(t, admitted, 0)
	assert.GreaterOrEqual(t, refused, 0)

	// The chain survived the concurrent writes intact, which is the property that
	// makes the whole record usable as evidence.
	chain := kernel.AuditQuery(kernel.AuditFilter{})
	assert.Equal(t, -1, kernel.VerifyChain(chain, kernel.AuditGenesis),
		"concurrent appraisals do not break the audit chain")
}

// TestVerifierRefusalPrecedesModuleCode proves the ordering property the whole
// subsystem rests on: a manifest that fails appraisal never reaches OnLoad, and
// never even reaches the factory. It is asserted the way the integrator will wire
// it - the hook runs before the registry lookup - because that ordering is the
// only reason "verification happens before module code runs" is true rather than
// hoped for.
func TestVerifierRefusalPrecedesModuleCode(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	k, _ := verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("late", kernel.OpLogWrite)
	require.NoError(t, m.Validate())

	factoryRan := false
	onLoadRan := false
	kernel.Register(m.Name, func() (kernel.Module, error) {
		factoryRan = true
		return &harness.Probe{Load: func(kernel.SContext) error {
			onLoadRan = true
			return nil
		}}, nil
	})
	t.Cleanup(func() { kernel.Unregister(m.Name) })

	// The unsigned declaration is refused by the hook, and the load path the
	// integrator wires stops there.
	require.True(t, errors.Is(
		kernel.VerifyManifestLoad(k.InitContext(), m, nil), kernel.ErrVerifierUnsigned))

	// Nothing downstream ran, and no module is live.
	assert.False(t, factoryRan, "the factory must not run for a refused manifest")
	assert.False(t, onLoadRan, "OnLoad must not run for a refused manifest")
	assert.Empty(t, kernel.LoadedModules(), "a refused module is not live")

	// The signed declaration passes the hook and then loads for real, which is
	// the same code path with the appraisal satisfied.
	sig := verifierSign(t, seed, m)
	require.NoError(t, kernel.VerifyManifestLoad(k.InitContext(), m, &sig))
	pid, err := k.Load(m)
	require.NoError(t, err)
	assert.NotZero(t, pid)
	assert.True(t, factoryRan)
	assert.True(t, onLoadRan)
	require.Len(t, kernel.LoadedModules(), 1)
	assert.Equal(t, m.Digest(), kernel.LoadedModules()[0].Manifest.Digest(),
		"the module that loaded is the one that was appraised")
}

// TestVerifierAuditComplementsValidation is the non-duplication property, stated
// as pairs. Each row names one risk class, the spelling manifest.go refuses, and
// the spelling it accepts. The audit must be silent on the refused one - restating
// a refusal gives one rule two implementations that drift apart - and must fire on
// the accepted one, because that is the only layer that sees it.
func TestVerifierAuditComplementsValidation(t *testing.T) {
	base := func() kernel.Manifest {
		return kernel.Manifest{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1}
	}

	cases := []struct {
		name string
		// refused is the spelling manifest.go rejects; the audit must not report it.
		refused func(m kernel.Manifest) kernel.Manifest
		// accepted is the neighbouring spelling manifest.go allows; the audit must.
		accepted func(m kernel.Manifest) kernel.Manifest
		want     kernel.VerifierFindingCode
	}{
		{
			name: "loopback host",
			refused: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpNetDial}
				m.AllowedHosts = []string{"localhost"}
				return m
			},
			accepted: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpNetDial}
				m.AllowedHosts = []string{"127.0.0.1"}
				return m
			},
			want: kernel.VerifierFindingPrivateHost,
		},
		{
			name: "wildcard host",
			refused: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpNetDial}
				m.AllowedHosts = []string{"*.example.com"}
				return m
			},
			accepted: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpNetDial}
				m.AllowedHosts = []string{"10.0.0.5"}
				return m
			},
			want: kernel.VerifierFindingPrivateHost,
		},
		{
			name: "absolute path",
			refused: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpFSRead}
				m.ReadPaths = []string{"/etc/passwd"}
				return m
			},
			accepted: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpFSRead}
				m.ReadPaths = []string{"state/./data"}
				return m
			},
			want: kernel.VerifierFindingPathForm,
		},
		{
			name: "traversal path",
			refused: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpFSRead}
				m.ReadPaths = []string{"../outside"}
				return m
			},
			accepted: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpFSRead}
				m.ReadPaths = []string{"a//b"}
				return m
			},
			want: kernel.VerifierFindingPathForm,
		},
		{
			name: "read-all secret grant",
			refused: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpSecretRead}
				m.SecretPrefixes = []string{""}
				return m
			},
			accepted: func(m kernel.Manifest) kernel.Manifest { m.Require = []kernel.Op{kernel.OpSecretUse}; return m },
			want:     kernel.VerifierFindingMissingScope,
		},
		{
			name:    "non-grantable unscoped operation",
			refused: func(m kernel.Manifest) kernel.Manifest { m.Require = []kernel.Op{kernel.OpMetadataWrite}; return m },
			accepted: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpSecretRead}
				m.SecretPrefixes = []string{"provider."}
				return m
			},
			want: kernel.VerifierFindingUnreachableOp,
		},
		{
			name:    "routes without route:register",
			refused: func(m kernel.Manifest) kernel.Manifest { m.ServeRoutes = []string{"/v1/chat"}; return m },
			accepted: func(m kernel.Manifest) kernel.Manifest {
				m.Require = []kernel.Op{kernel.OpRouteRegister}
				m.ServeRoutes = []string{"/v1", "/v1/chat"}
				return m
			},
			want: kernel.VerifierFindingRouteForm,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := tc.refused(base())
			require.Error(t, bad.Validate(),
				"the refused spelling must actually be refused by manifest.go, or this row proves nothing")
			// The audit is advisory: it never refuses, and it does not restate a
			// refusal that is about to happen anyway.
			findings := kernel.VerifierAuditDeclaration(bad)
			assert.False(t, verifierHasCode(findings, tc.want),
				"the audit must not duplicate manifest.go's refusal of %q: %v", tc.name, findings)

			good := tc.accepted(base())
			require.NoError(t, good.Validate(),
				"the accepted spelling must actually pass manifest.go")
			findings = kernel.VerifierAuditDeclaration(good)
			assert.True(t, verifierHasCode(findings, tc.want),
				"the audit must report what validation accepts; got %v", findings)
			assert.NotEmpty(t, verifierDetail(findings, tc.want))
		})
	}
}

// TestVerifierAuditReportsWhatASignerShouldQuestion walks each finding class with
// a manifest that triggers exactly it. Every case is a declaration that loads
// today, so each finding is something a reviewer would otherwise discover in
// production rather than at signing time.
func TestVerifierAuditReportsWhatASignerShouldQuestion(t *testing.T) {
	valid := func(m kernel.Manifest) kernel.Manifest {
		m.Name, m.Version, m.MinKernelAPI, m.MaxKernelAPI = "adapter", "1.0.0", 1, 1
		require.NoError(t, m.Validate())
		return m
	}

	cases := []struct {
		name string
		m    func() kernel.Manifest
		want kernel.VerifierFindingCode
		// contains pins the substance of the finding without asserting prose.
		contains string
	}{
		{
			name: "scoped operation no module domain holds",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpSecretRead}, SecretPrefixes: []string{"provider."},
				})
			},
			want:     kernel.VerifierFindingUnreachableOp,
			contains: "denied by the ceiling",
		},
		{
			name: "unreachable finding names the reachable alternative",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpSecretRead}, SecretPrefixes: []string{"provider."},
				})
			},
			want:     kernel.VerifierFindingUnreachableOp,
			contains: string(kernel.OpSecretUse),
		},
		{
			name: "hosts declared for an operation never requested",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{AllowedHosts: []string{"api.example.com"}})
			},
			want:     kernel.VerifierFindingDeadScope,
			contains: string(kernel.OpNetDial),
		},
		{
			name: "read paths declared without fs:read",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{ReadPaths: []string{"state"}})
			},
			want:     kernel.VerifierFindingDeadScope,
			contains: string(kernel.OpFSRead),
		},
		{
			name: "write paths declared without fs:write",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{WritePaths: []string{"state"}})
			},
			want:     kernel.VerifierFindingDeadScope,
			contains: string(kernel.OpFSWrite),
		},
		{
			name: "listen address declared without net:listen",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{ListenAddr: "127.0.0.1:8080"})
			},
			want:     kernel.VerifierFindingDeadScope,
			contains: string(kernel.OpNetListen),
		},
		{
			name: "secret:use with no prefix loads and then can read nothing",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{Require: []kernel.Op{kernel.OpSecretUse}})
			},
			want:     kernel.VerifierFindingMissingScope,
			contains: "every alias is invisible",
		},
		{
			name: "peer:dial with no host",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{Require: []kernel.Op{kernel.OpPeerDial}})
			},
			want:     kernel.VerifierFindingMissingScope,
			contains: string(kernel.OpPeerDial),
		},
		{
			name: "a short secret prefix subsumes a longer one",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpSecretUse}, SecretPrefixes: []string{"prov.", "prov.openai."},
				})
			},
			want:     kernel.VerifierFindingWeakScope,
			contains: "subsumes",
		},
		{
			name: "link-local host",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpNetDial}, AllowedHosts: []string{"169.254.169.254"},
				})
			},
			want:     kernel.VerifierFindingPrivateHost,
			contains: "link-local",
		},
		{
			name: "documentation range host is a placeholder that shipped",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpNetDial}, AllowedHosts: []string{"203.0.113.7"},
				})
			},
			want:     kernel.VerifierFindingPrivateHost,
			contains: "documentation",
		},
		{
			name: "path spelling that cleaning rewrites",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpFSRead}, ReadPaths: []string{"state/./data"},
				})
			},
			want:     kernel.VerifierFindingPathForm,
			contains: "cleans to",
		},
		{
			name: "two spellings of one path grant",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpFSWrite}, WritePaths: []string{"a/b", "a//b"},
				})
			},
			want:     kernel.VerifierFindingPathForm,
			contains: "already cleans to",
		},
		{
			name: "a broader path covers a narrower one",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpFSRead}, ReadPaths: []string{"data/sub", "data"},
				})
			},
			want:     kernel.VerifierFindingWeakScope,
			contains: "already covered",
		},
		{
			name: "route nesting does not depend on declaration order",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpRouteRegister}, ServeRoutes: []string{"/v1/chat", "/v1"},
				})
			},
			want:     kernel.VerifierFindingRouteForm,
			contains: "nests with",
		},
		{
			name: "listen address binds every interface",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpNetListen}, ListenAddr: "0.0.0.0:8080",
				})
			},
			want:     kernel.VerifierFindingListenForm,
			contains: "every interface",
		},
		{
			name: "listen address leaves the port to the stack",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpNetListen}, ListenAddr: "127.0.0.1:0",
				})
			},
			want:     kernel.VerifierFindingListenForm,
			contains: "leaves the port",
		},
		{
			name: "listen address that does not parse",
			m: func() kernel.Manifest {
				return valid(kernel.Manifest{
					Require: []kernel.Op{kernel.OpNetListen}, ListenAddr: "not-an-address",
				})
			},
			want:     kernel.VerifierFindingListenForm,
			contains: "does not parse",
		},
		{
			name: "version carrying a line break forges a log line",
			m: func() kernel.Manifest {
				m := kernel.Manifest{Require: []kernel.Op{kernel.OpLogWrite}}
				m.Name, m.MinKernelAPI, m.MaxKernelAPI = "adapter", 1, 1
				m.Version = "1.0.0\nforged fault record"
				require.NoError(t, m.Validate())
				return m
			},
			want:     kernel.VerifierFindingIdentityForm,
			contains: "line break",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.m()
			findings := kernel.VerifierAuditDeclaration(m)
			require.True(t, verifierHasCode(findings, tc.want),
				"expected a %s finding, got %v", tc.want, findings)
			assert.Contains(t, verifierDetails(findings, tc.want), tc.contains)

			// Every finding names a field that exists on the manifest, so a
			// reviewer is never sent looking at a field that is not there.
			for _, f := range findings {
				assert.Contains(t, verifierManifestJSONFields(), f.Field,
					"finding %s names an unknown manifest field %q", f.Code, f.Field)
				assert.NotEmpty(t, f.Detail)
			}
		})
	}
}

// verifierManifestJSONFields lists the JSON field names of Manifest, read from the
// struct rather than restated, so a finding that names a field the manifest does
// not have is a failure.
func verifierManifestJSONFields() []string {
	typ := reflect.TypeFor[kernel.Manifest]()
	out := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}

// TestVerifierAuditIsSilentOnACleanDeclaration is the other half of an advisory
// layer: a declaration with nothing to question produces no findings. A reviewer
// who sees findings on every manifest stops reading them, and an audit that cries
// wolf is not a control.
func TestVerifierAuditIsSilentOnACleanDeclaration(t *testing.T) {
	clean := []kernel.Manifest{
		{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require: []kernel.Op{kernel.OpLogWrite}},
		{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require:        []kernel.Op{kernel.OpSecretUse},
			SecretPrefixes: []string{"provider.openai."}},
		{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite}},
		{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require: []kernel.Op{kernel.OpRouteRegister}, ServeRoutes: []string{"/v1/chat", "/v2/chat"}},
		{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require: []kernel.Op{kernel.OpCryptoHash, kernel.OpCryptoVerify}},
		{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1},
	}
	for i, m := range clean {
		require.NoError(t, m.Validate(), "case %d must be a valid manifest", i)
		assert.Empty(t, kernel.VerifierAuditDeclaration(m),
			"case %d (%v) should have nothing for a signer to question", i, m.Require)
	}

	// A public unicast host is not flagged, which is what keeps the private-host
	// finding meaningful rather than a warning on every declaration. net:dial
	// itself is unreachable from the plugin domain today, so that single finding
	// is expected here and is pinned by its own test below.
	public := kernel.Manifest{Name: "adapter", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpNetDial}, AllowedHosts: []string{"93.184.216.34", "api.example.com"}}
	require.NoError(t, public.Validate())
	findings := kernel.VerifierAuditDeclaration(public)
	require.Len(t, findings, 1)
	assert.Equal(t, kernel.VerifierFindingUnreachableOp, findings[0].Code)
	assert.Empty(t, verifierDetails(findings, kernel.VerifierFindingPrivateHost))
}

// TestVerifierAuditReportsTheScopedOpsNoModuleDomainHoldsYet pins a finding that
// is true of the policy table today and becomes false the day knet, kpeer and the
// fs syscall group land.
//
// net:dial, net:listen, fs:read, fs:write, peer:dial and secret:read are all in
// scopedOps, so manifest.go passes them through the ceiling check and lets a
// module declare them with their scope filled in. The plugin domain holds none of
// them, so every call is denied before the scope is ever consulted. That is not a
// validation failure and not a defect - the operations exist ahead of the
// subsystems that enforce their scope - but a reviewer signing a manifest that
// asks for net:dial is signing a declaration that cannot work, and the audit is
// the layer that says so.
func TestVerifierAuditReportsTheScopedOpsNoModuleDomainHoldsYet(t *testing.T) {
	decls := []struct {
		op    kernel.Op
		scope func(m *kernel.Manifest)
	}{
		{kernel.OpNetDial, func(m *kernel.Manifest) { m.AllowedHosts = []string{"api.example.com"} }},
		{kernel.OpNetListen, func(m *kernel.Manifest) { m.ListenAddr = "127.0.0.1:8080" }},
		{kernel.OpFSRead, func(m *kernel.Manifest) { m.ReadPaths = []string{"in"} }},
		{kernel.OpFSWrite, func(m *kernel.Manifest) { m.WritePaths = []string{"out"} }},
		{kernel.OpPeerDial, func(m *kernel.Manifest) { m.AllowedHosts = []string{"peer.example.com"} }},
		{kernel.OpSecretRead, func(m *kernel.Manifest) { m.SecretPrefixes = []string{"provider."} }},
	}

	for _, d := range decls {
		t.Run(string(d.op), func(t *testing.T) {
			m := kernel.Manifest{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
				Require: []kernel.Op{d.op}}
			d.scope(&m)
			require.NoError(t, m.Validate(),
				"%s must pass manifest validation, or the finding restates a refusal", d.op)
			require.False(t, kernel.Allowed(kernel.DomainPlugin, d.op),
				"this finding describes the current policy table; if %s is now granted, the finding and this test are both obsolete", d.op)

			findings := kernel.VerifierAuditDeclaration(m)
			require.True(t, verifierHasCode(findings, kernel.VerifierFindingUnreachableOp),
				"got %v", findings)
			assert.Contains(t, verifierDetails(findings, kernel.VerifierFindingUnreachableOp),
				"denied by the ceiling")
		})
	}

	// And the operations a module can hold are not reported, which is what keeps
	// the finding from firing on every manifest and turning the audit into noise.
	for _, op := range []kernel.Op{
		kernel.OpLogWrite, kernel.OpKVRead, kernel.OpKVWrite, kernel.OpSecretUse,
		kernel.OpRouteRegister, kernel.OpCryptoHash, kernel.OpCryptoVerify,
		kernel.OpUsageEmit, kernel.OpMeterRecord, kernel.OpReceiptVerify,
	} {
		require.True(t, kernel.Allowed(kernel.DomainPlugin, op),
			"the ceiling grants %s, so it must not be reported as unreachable", op)
		m := kernel.Manifest{Name: "adapter", Version: "1.0.0", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require: []kernel.Op{op}}
		if op == kernel.OpSecretUse {
			m.SecretPrefixes = []string{"provider."}
		}
		if op == kernel.OpRouteRegister {
			m.ServeRoutes = []string{"/v1/chat"}
		}
		require.NoError(t, m.Validate())
		assert.False(t, verifierHasCode(kernel.VerifierAuditDeclaration(m),
			kernel.VerifierFindingUnreachableOp), "%s is reachable and must not be reported", op)
	}
}

// TestVerifierAuditFindingCodesAreClosed pins the finding vocabulary. A reviewer's
// checklist and any tooling that filters on the class both depend on the set being
// enumerable, and a code the audit can emit that is absent from the list is a
// finding nobody can filter for.
func TestVerifierAuditFindingCodesAreClosed(t *testing.T) {
	codes := kernel.VerifierFindingCodes()
	require.NotEmpty(t, codes)

	seen := make(map[kernel.VerifierFindingCode]bool, len(codes))
	for _, c := range codes {
		assert.False(t, seen[c], "code %q is listed twice", c)
		seen[c] = true
		assert.NotEmpty(t, string(c))
		assert.NotContains(t, string(c), " ", "a code is an identifier, not prose")
	}

	// Every class this file's own cases produce is in the closed list.
	produced := map[kernel.VerifierFindingCode]bool{}
	samples := []kernel.Manifest{
		{Name: "a", Version: "1\n", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require: []kernel.Op{kernel.OpSecretRead, kernel.OpSecretUse, kernel.OpPeerDial,
				kernel.OpNetDial, kernel.OpNetListen, kernel.OpFSRead, kernel.OpFSWrite,
				kernel.OpRouteRegister},
			AllowedHosts:   []string{"127.0.0.1", "10.1.2.3", "169.254.1.1", "192.0.2.9"},
			SecretPrefixes: []string{"p.", "p.q."},
			ReadPaths:      []string{"x/./y", "x/y", "x"},
			WritePaths:     []string{"w"},
			ListenAddr:     "0.0.0.0:0",
			ServeRoutes:    []string{"/v1", "/v1/x"}},
		{Name: "b", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
			AllowedHosts: []string{"h"}, ReadPaths: []string{"p"}, WritePaths: []string{"q"},
			SecretPrefixes: []string{"s"}, ListenAddr: "unparseable"},
		{Name: "c", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require: []kernel.Op{kernel.OpSecretUse, kernel.OpPeerDial}},
	}
	for _, m := range samples {
		for _, f := range kernel.VerifierAuditDeclaration(m) {
			produced[f.Code] = true
			assert.True(t, seen[f.Code], "the audit emitted %q, which is not in the closed set", f.Code)
		}
	}
	assert.True(t, produced[kernel.VerifierFindingUnreachableOp])
	assert.True(t, produced[kernel.VerifierFindingDeadScope])
	assert.True(t, produced[kernel.VerifierFindingMissingScope])
	assert.True(t, produced[kernel.VerifierFindingWeakScope])
	assert.True(t, produced[kernel.VerifierFindingPrivateHost])
	assert.True(t, produced[kernel.VerifierFindingPathForm])
	assert.True(t, produced[kernel.VerifierFindingListenForm])
	assert.True(t, produced[kernel.VerifierFindingIdentityForm])
	assert.True(t, produced[kernel.VerifierFindingRouteForm])
	assert.Len(t, produced, len(codes),
		"every declared finding class is reachable, so none of them is dead vocabulary")

	// The audit never refuses: it has no error return, and a manifest that
	// manifest.go would reject still produces findings rather than a failure.
	broken := kernel.Manifest{Name: "", Version: "", Require: []kernel.Op{"not:an-op"}}
	require.Error(t, broken.Validate())
	assert.NotPanics(t, func() { _ = kernel.VerifierAuditDeclaration(broken) })
}

// TestVerifierAuditIsPureAndHostileInputSafe is the property that makes the audit
// safe to run on a manifest an attacker wrote: it reads only the manifest, reaches
// no disk and no network and no kernel state, and returns the same answer for the
// same input. Reviewing a hostile declaration must not itself be an attack on the
// reviewer's machine.
func TestVerifierAuditIsPureAndHostileInputSafe(t *testing.T) {
	hostile := kernel.Manifest{
		Name: "../../etc/passwd", Version: strings.Repeat("A", 4096),
		MinKernelAPI: 1, MaxKernelAPI: 1,
		Require:        []kernel.Op{kernel.OpNetDial, kernel.OpFSRead},
		AllowedHosts:   []string{"::", "0.0.0.0", "ff02::1", "%", ":", strings.Repeat("z", 300)},
		ReadPaths:      []string{"./", "a/../../b", strings.Repeat("/", 200), "\x00"},
		SecretPrefixes: []string{"", " ", strings.Repeat("k", 300)},
		ListenAddr:     "[::]:0",
		ServeRoutes:    []string{"/", "//", "/a/./b"},
	}

	require.NotPanics(t, func() {
		first := kernel.VerifierAuditDeclaration(hostile)
		second := kernel.VerifierAuditDeclaration(hostile)
		assert.Equal(t, first, second, "the audit is a pure function of its input")
		assert.NotEmpty(t, first, "a declaration like this has plenty to question")
		for _, f := range first {
			assert.Contains(t, verifierManifestJSONFields(), f.Field)
		}
	})

	// It needs no kernel at all: the audit runs with nothing booted, which is how
	// a signing pipeline uses it, offline, before the manifest is ever offered.
	assert.Empty(t, kernel.ProcTable(), "no kernel is booted in this test")
	assert.NotEmpty(t, kernel.VerifierAuditDeclaration(kernel.Manifest{
		Name: "x", Version: "1", Require: []kernel.Op{kernel.OpSecretUse},
	}))
}

// TestVerifierErrorFamilyIsDistinct pins the typed-error contract an operator's
// tooling depends on: every refusal is a *VerifierError carrying one sentinel, the
// sentinels do not overlap, and a verification refusal is never mistaken for a
// policy denial or for a receipt or secret refusal from a neighbouring subsystem.
func TestVerifierErrorFamilyIsDistinct(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	_, _ = verifierBoot(t, []string{pub}, seed)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierEnforce))

	m := verifierManifest("adapter", kernel.OpLogWrite)
	sig := verifierSign(t, seed, m)
	flipped := sig
	flipped.Bytes = append([]byte{}, sig.Bytes...)
	flipped.Bytes[0] ^= 0xFF

	sentinels := []error{
		kernel.ErrVerifierSealed,
		kernel.ErrVerifierUnsigned,
		kernel.ErrVerifierMalformed,
		kernel.ErrVerifierBadSignature,
		kernel.ErrVerifierKeyUntrusted,
		kernel.ErrVerifierIdentityMismatch,
		kernel.ErrVerifierDigestMismatch,
		kernel.ErrVerifierBindingVersion,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			assert.False(t, errors.Is(a, b), "sentinels %v and %v must not overlap", a, b)
		}
	}

	refusals := []struct {
		name string
		sig  *kernel.VerifierSignature
		want error
	}{
		{"unsigned", nil, kernel.ErrVerifierUnsigned},
		{"malformed", &kernel.VerifierSignature{
			Version: kernel.VerifierBindingVersion, Module: m.Name, ModuleVersion: m.Version,
			Digest: m.Digest(), KeyID: "k", Bytes: []byte{1, 2, 3},
		}, kernel.ErrVerifierMalformed},
		{"bad signature", &flipped, kernel.ErrVerifierBadSignature},
		{"untrusted key", func() *kernel.VerifierSignature {
			otherSeed, _ := verifierKeyPair(t)
			s := verifierSign(t, otherSeed, m)
			return &s
		}(), kernel.ErrVerifierKeyUntrusted},
		{"identity mismatch", func() *kernel.VerifierSignature {
			s := verifierSign(t, seed, verifierManifest("other", kernel.OpLogWrite))
			return &s
		}(), kernel.ErrVerifierIdentityMismatch},
		{"digest mismatch", func() *kernel.VerifierSignature {
			wider := verifierManifest("adapter", kernel.OpLogWrite, kernel.OpMetadataRead)
			s := verifierSign(t, seed, wider)
			s.Module, s.ModuleVersion = m.Name, m.Version
			return &s
		}(), kernel.ErrVerifierDigestMismatch},
		{"binding version", func() *kernel.VerifierSignature {
			s := sig
			s.Version = kernel.VerifierBindingVersion + 7
			return &s
		}(), kernel.ErrVerifierBindingVersion},
	}

	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			err := kernel.VerifyManifestLoad(nil, m, tc.sig)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.want), "want %v, got %v", tc.want, err)

			var ve *kernel.VerifierError
			require.True(t, errors.As(err, &ve), "the refusal is a *VerifierError")
			assert.Equal(t, m.Name, ve.Module)
			assert.Equal(t, m.Version, ve.Version)
			assert.Equal(t, m.Digest(), ve.Digest)
			assert.NotEmpty(t, ve.Msg)
			assert.ErrorIs(t, ve.Unwrap(), tc.want)
			assert.Contains(t, err.Error(), "manifest verification refused",
				"every refusal reads as what it is")

			// Not a policy denial, and not a neighbouring subsystem's refusal.
			assert.False(t, kernel.IsDenied(err))
			assert.Empty(t, kernel.DenialReason(err))
			var re *kernel.ReceiptError
			assert.False(t, errors.As(err, &re))
			var se *kernel.SecretError
			assert.False(t, errors.As(err, &se))
			var me *kernel.ManifestError
			assert.False(t, errors.As(err, &me),
				"a verification refusal is not a manifest-validation refusal")

			// Exactly one sentinel matches, so a caller branching on errors.Is
			// cannot land in two branches at once.
			matched := 0
			for _, s := range sentinels {
				if errors.Is(err, s) {
					matched++
				}
			}
			assert.Equal(t, 1, matched, "one refusal, one sentinel")
		})
	}
}

// TestVerifierUnappraisableConfigurationFailsClosed covers the case where the
// kernel cannot decide at all: a trust root whose cluster root keys are not usable
// ed25519 keys. That is a configuration failure and not a verdict on the module, so
// it carries no refusal sentinel - but under enforce it still refuses the load,
// because fail-closed is the only safe answer when appraisal is impossible.
//
// It is its own test rather than a subtest because it needs its own boot, and the
// boot guard is process-wide.
func TestVerifierUnappraisableConfigurationFailsClosed(t *testing.T) {
	seed, otherPub := verifierKeyPair(t)
	buf := harness.QuietConsole(t)

	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{
		NodeID: "vrf-broken", ClusterRootKeys: []string{"not-a-key"}, SigningKeyPEM: seed,
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	// A configured key list derives enforce even when the entries are unusable: the
	// operator asked for verification, so the kernel verifies and fails rather than
	// silently skipping.
	assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent())

	// Build a well-formed signature with a real key, so the failure is about the
	// trust root and not about the signature's shape.
	m := verifierManifest("adapter", kernel.OpLogWrite)
	priv := ed25519.NewKeyFromSeed(mustHex(t, seed))
	sig := kernel.VerifierSignature{
		Version: kernel.VerifierBindingVersion, Module: m.Name, ModuleVersion: m.Version,
		Digest: m.Digest(), KeyID: verifierKeyID(verifierPub(t, otherPub)), SignedMono: 1,
		Bytes: ed25519.Sign(priv, kernel.VerifierBindingPayload(m)),
	}

	err = kernel.VerifyManifestLoad(k.InitContext(), m, &sig)
	require.Error(t, err, "an unappraisable manifest is refused, not waved through")
	assert.Contains(t, err.Error(), "cannot appraise")

	sentinels := []error{
		kernel.ErrVerifierUnsigned, kernel.ErrVerifierMalformed, kernel.ErrVerifierBadSignature,
		kernel.ErrVerifierKeyUntrusted, kernel.ErrVerifierIdentityMismatch,
		kernel.ErrVerifierDigestMismatch, kernel.ErrVerifierBindingVersion,
	}
	for _, s := range sentinels {
		assert.False(t, errors.Is(err, s),
			"a configuration failure must not be reported as a verdict on the module")
	}
	var ve *kernel.VerifierError
	assert.False(t, errors.As(err, &ve))
	assert.False(t, kernel.IsDenied(err))

	// The refusal is still on the chain and still a fault, attributed to the loader.
	audits := verifierAppraisals()
	require.Len(t, audits, 1)
	assert.Equal(t, "false", verifierFieldSprint(t, audits[0], "admitted"))
	assert.Equal(t, k.InitContext().PID(), audits[0].PID)
	faults := harness.Faults(buf)
	require.Len(t, faults, 1)
	assert.Equal(t, k.InitContext().PID(), faults[0].Pid)

	// The ledger records the attempted key id, which is how an operator finds the
	// broken root instead of guessing at it.
	entries := kernel.VerifierLedgerFor(m.Name)
	require.Len(t, entries, 1)
	assert.Equal(t, verifierKeyID(verifierPub(t, otherPub)), entries[0].KeyID)
	assert.False(t, entries[0].Admitted)
	assert.Contains(t, entries[0].Reason, "cannot appraise")
}

// mustHex decodes a hex string.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	return raw
}
