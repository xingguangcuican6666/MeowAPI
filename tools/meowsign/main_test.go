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

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/abi"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// signingSeed generates one ed25519 seed and returns it hex encoded, which is the
// form the kernel's trust root accepts and the form an operator holds. Random rather
// than a constant so a test that passed by hard-coding a digest cannot pass here.
func signingSeed(t *testing.T) (seedHex string, pub ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	priv := ed25519.NewKeyFromSeed(seed)
	p, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok)
	return hex.EncodeToString(seed), p
}

// writeManifest marshals one declaration to a file the tool reads.
func writeManifest(t *testing.T, dir string, m abi.Manifest) string {
	t.Helper()
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	path := filepath.Join(dir, "manifest.json")
	require.NoError(t, os.WriteFile(path, raw, 0o644))
	return path
}

// cleanManifest is a declaration the audit reports nothing about, so a finding the
// test did not intend cannot be what refuses the signature. Both operations are in
// the plugin ceiling and neither is scoped, which is what makes it clean: a scoped
// operation no module domain holds is an unreachable-op finding, and a scope field
// declared without its operation is a dead-scope one.
func cleanManifest() abi.Manifest {
	return abi.Manifest{
		Name:         "example",
		Version:      "1.0.0",
		MinKernelAPI: abi.KernelAPI,
		MaxKernelAPI: abi.KernelAPI,
		Require:      []abi.Op{abi.OpLogWrite, abi.OpMetadataRead},
	}
}

func runTool(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestSignedManifestPassesKernelAppraisal is the end-to-end contract: a signature this
// tool mints is one the kernel admits. It is checked through kernel.VerifyManifest over
// a real boot whose sealed trust root carries the public key the tool prints, which is
// the whole chain an operator walks - seed in, .sig file out, module loads - rather than
// a reimplementation of the verification inside the test.
func TestSignedManifestPassesKernelAppraisal(t *testing.T) {
	dir := t.TempDir()
	seedHex, pub := signingSeed(t)
	m := cleanManifest()
	manifestPath := writeManifest(t, dir, m)
	sigPath := filepath.Join(dir, "example.so.sig")

	code, stdout, stderr := runTool(t,
		"-manifest", manifestPath, "-key-hex", seedHex, "-out", sigPath)
	require.Equal(t, 0, code, "stderr:\n%s", stderr)
	assert.Empty(t, stdout, "-out writes the signature to a file and leaves stdout clean")

	raw, err := os.ReadFile(sigPath)
	require.NoError(t, err)
	var sig kernel.VerifierSignature
	require.NoError(t, json.Unmarshal(raw, &sig), "the .sig file must parse as kernel.VerifierSignature")

	assert.Equal(t, abi.VerifierBindingVersion, sig.Version)
	assert.Equal(t, m.Name, sig.Module)
	assert.Equal(t, m.Version, sig.ModuleVersion)
	assert.Equal(t, m.Digest(), sig.Digest)
	assert.Len(t, sig.Bytes, ed25519.SignatureSize)
	assert.Contains(t, stderr, hex.EncodeToString(pub), "the operator is told which root key to trust")
	assert.NotContains(t, stderr+stdout, seedHex, "key material never reaches an output")

	// The appraisal needs a sealed trust root, so it needs a boot. One per binary: the
	// boot guard is process-wide and a leaked boot fails every later test with "already
	// booted", which is why the shutdown is a cleanup rather than a trailing line.
	var console bytes.Buffer
	k, err := kernel.Boot(kernel.BootConfig{
		Console:   &console,
		TrustRoot: kernel.BootTrustRoot{NodeID: "meowsign-test", ClusterRootKeys: []string{hex.EncodeToString(pub)}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	assert.NoError(t, kernel.VerifyManifest(m, &sig), "console:\n%s", console.String())

	// The negative half of the same contract, because a verification that passes
	// everything is not a verification. Widening the declaration moves its digest, and
	// the appraisal must then refuse - that is the review-to-deployment gap kverifier
	// exists to close.
	widened := m
	widened.AllowedHosts = append(append([]string{}, m.AllowedHosts...), "evil.example.com")
	err = kernel.VerifyManifest(widened, &sig)
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrVerifierDigestMismatch)
}

// TestFindingsRefuseSignatureWithoutForce covers the checklist's teeth: an advisory
// finding is printed and the signature is withheld until the reviewer says otherwise,
// and -force signs with the fact recorded on stderr.
func TestFindingsRefuseSignatureWithoutForce(t *testing.T) {
	dir := t.TempDir()
	seedHex, _ := signingSeed(t)

	// secret:use with no prefix declared is a finding the kernel does not refuse, so it
	// reaches the audit and is exactly the case a reviewer should read before vouching.
	m := cleanManifest()
	m.Require = append(m.Require, abi.OpSecretUse)
	manifestPath := writeManifest(t, dir, m)
	sigPath := filepath.Join(dir, "example.so.sig")

	code, stdout, stderr := runTool(t, "-manifest", manifestPath, "-key-hex", seedHex, "-out", sigPath)
	assert.Equal(t, 1, code)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, string(kernel.VerifierFindingMissingScope))
	assert.Contains(t, stderr, "-force")
	_, err := os.Stat(sigPath)
	assert.True(t, os.IsNotExist(err), "a refused signing writes no signature file")

	code, _, stderr = runTool(t, "-manifest", manifestPath, "-key-hex", seedHex, "-out", sigPath, "-force")
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr, "WARNING")
	assert.Contains(t, stderr, "unresolved finding")
	_, err = os.Stat(sigPath)
	assert.NoError(t, err, "-force signs with the findings unresolved")
}

// TestVerifyMode is the round trip through the tool's own second mode: a signature it
// minted verifies against the roots the deployment names, and one over a digest that
// moved does not. Both verdicts are exit codes, which is what a pipeline consumes.
func TestVerifyMode(t *testing.T) {
	dir := t.TempDir()
	seedHex, pub := signingSeed(t)
	m := cleanManifest()
	manifestPath := writeManifest(t, dir, m)
	sigPath := filepath.Join(dir, "example.so.sig")
	roots := hex.EncodeToString(pub)

	code, _, stderr := runTool(t, "-manifest", manifestPath, "-key-hex", seedHex, "-out", sigPath)
	require.Equal(t, 0, code, "stderr:\n%s", stderr)

	code, stdout, _ := runTool(t, "-verify", "-manifest", manifestPath, "-sig", sigPath, "-roots", roots)
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "OK")

	// A declaration edited after signing, which is the case the whole subsystem exists
	// for. The digest moves, so the appraisal refuses with the specific reason rather
	// than a generic bad signature.
	edited := m
	edited.ReadPaths = []string{"cache", "credentials"}
	editedPath := filepath.Join(dir, "edited.json")
	raw, err := json.Marshal(edited)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(editedPath, raw, 0o644))

	code, stdout, _ = runTool(t, "-verify", "-manifest", editedPath, "-sig", sigPath, "-roots", roots)
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "REFUSED")
	assert.Contains(t, stdout, "signed and then edited")

	// An untrusted key is a key-inventory fact, reported as itself: the operator's fix
	// is to add or rotate a root, not to re-read the manifest.
	_, otherPub := signingSeed(t)
	code, stdout, _ = runTool(t, "-verify", "-manifest", manifestPath, "-sig", sigPath,
		"-roots", hex.EncodeToString(otherPub))
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "not among the")
}

// TestUsageErrors keeps the invoked-wrongly cases on exit code 2 and, more importantly,
// keeps them distinguishable from a refusal to sign.
func TestUsageErrors(t *testing.T) {
	dir := t.TempDir()
	seedHex, _ := signingSeed(t)
	manifestPath := writeManifest(t, dir, cleanManifest())

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no manifest", []string{"-key-hex", seedHex}, "no manifest"},
		{"missing manifest file", []string{"-manifest", filepath.Join(dir, "absent.json"), "-key-hex", seedHex}, "reading the manifest"},
		{"both key forms", []string{"-manifest", manifestPath, "-key", seedHex, "-key-hex", seedHex}, "pass one of them"},
		{"no key", []string{"-manifest", manifestPath}, "no signing key"},
		{"bad key material", []string{"-manifest", manifestPath, "-key-hex", "not-a-key"}, "not PEM, hex or base64"},
		{"short key material", []string{"-manifest", manifestPath, "-key-hex", "0011"}, "want a 32-byte seed"},
		{"verify without sig", []string{"-verify", "-manifest", manifestPath, "-roots", "aa"}, "needs -sig"},
		{"verify without roots", []string{"-verify", "-manifest", manifestPath, "-sig", manifestPath}, "needs -roots"},
		{"verify with a key", []string{"-verify", "-manifest", manifestPath, "-sig", manifestPath, "-roots", "aa", "-key-hex", seedHex}, "takes no signing key"},
		{"positional argument", []string{manifestPath}, "no positional arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runTool(t, tc.args...)
			assert.Equal(t, 2, code)
			assert.Contains(t, stderr, tc.want)
			assert.NotContains(t, stderr, seedHex, "a usage error does not quote the key it was given")
		})
	}

	t.Run("help is not an error", func(t *testing.T) {
		// Asking for help is a request and not a mistake, so it shares the exit code
		// with success rather than with the invocations above.
		code, _, stderr := runTool(t, "-h")
		assert.Equal(t, 0, code)
		assert.Contains(t, stderr, "-manifest")
		assert.Contains(t, stderr, "Exit codes")
	})
}

// TestManifestIsRefusedNotReinterpreted covers the two ways a manifest file can say
// something other than what the operator read: a field the declaration does not have,
// which changes what gets signed without changing what appears in the file, and a
// declaration the kernel would refuse at load, which wastes the key and produces a
// signature whose later refusal reads as a cryptography failure.
func TestManifestIsRefusedNotReinterpreted(t *testing.T) {
	dir := t.TempDir()
	seedHex, _ := signingSeed(t)

	t.Run("unknown field", func(t *testing.T) {
		path := filepath.Join(dir, "typo.json")
		require.NoError(t, os.WriteFile(path, []byte(
			`{"name":"example","version":"1.0.0","min_kernel_api":1,"max_kernel_api":1,"allowed_host":["a.example.com"],"require":["net:dial"]}`), 0o644))
		code, _, stderr := runTool(t, "-manifest", path, "-key-hex", seedHex)
		assert.Equal(t, 2, code)
		assert.Contains(t, stderr, "not a valid manifest")
		assert.Contains(t, stderr, "allowed_host")
	})

	t.Run("trailing data", func(t *testing.T) {
		path := filepath.Join(dir, "trailing.json")
		require.NoError(t, os.WriteFile(path, []byte(
			`{"name":"example","version":"1.0.0","min_kernel_api":1,"max_kernel_api":1} {"name":"other"}`), 0o644))
		code, _, stderr := runTool(t, "-manifest", path, "-key-hex", seedHex)
		assert.Equal(t, 2, code)
		assert.Contains(t, stderr, "trailing data")
	})

	t.Run("kernel would refuse it", func(t *testing.T) {
		// net:dial with no allowed host is refused by ValidateManifest, and the audit
		// deliberately does not duplicate that refusal, so the tool is the caller that has
		// to run validation before signing.
		m := cleanManifest()
		m.Require = append(m.Require, abi.OpNetDial)
		path := writeManifest(t, dir, m)
		code, _, stderr := runTool(t, "-manifest", path, "-key-hex", seedHex)
		assert.Equal(t, 2, code)
		assert.Contains(t, stderr, "invalid manifest")
		assert.Contains(t, stderr, string(abi.OpNetDial))
	})
}

// TestKeyEncodingsTheKernelAccepts pins the carrier encodings against the trust root's
// own contract. A signing tool that accepted fewer spellings than the kernel does would
// refuse a key the operator already deploys; one that accepted more would mint
// signatures no root can name, which look complete and verify nowhere.
func TestKeyEncodingsTheKernelAccepts(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeManifest(t, dir, cleanManifest())
	seedHex, pub := signingSeed(t)

	seedRaw, err := hex.DecodeString(seedHex)
	require.NoError(t, err)
	full := ed25519.NewKeyFromSeed(seedRaw)

	encodings := map[string]string{
		"hex seed":       seedHex,
		"base64 seed":    base64.StdEncoding.EncodeToString(seedRaw),
		"hex full key":   hex.EncodeToString(full),
		"base64 fullkey": base64.StdEncoding.EncodeToString(full),
	}
	for name, material := range encodings {
		t.Run(name, func(t *testing.T) {
			sigPath := filepath.Join(dir, "sig-"+strings.ReplaceAll(name, " ", "-")+".json")
			code, _, stderr := runTool(t, "-manifest", manifestPath, "-key-hex", material, "-out", sigPath)
			require.Equal(t, 0, code, "stderr:\n%s", stderr)

			raw, err := os.ReadFile(sigPath)
			require.NoError(t, err)
			var sig abi.VerifierSignature
			require.NoError(t, json.Unmarshal(raw, &sig))
			// Every spelling of one key names one key id, and it is the id the kernel
			// recomputes from the root's own bytes when it checks trust.
			assert.Equal(t, keyID(pub), sig.KeyID)
			assert.NotContains(t, stderr, material, "key material is never echoed, in any encoding")
		})
	}
}

// TestKeyFileForm covers -key, the form a deployment uses because a seed on a command
// line lands in the shell history and in the process table of every account on the host.
func TestKeyFileForm(t *testing.T) {
	dir := t.TempDir()
	seedHex, _ := signingSeed(t)
	keyPath := filepath.Join(dir, "signing.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(seedHex+"\n"), 0o600))
	manifestPath := writeManifest(t, dir, cleanManifest())

	code, stdout, stderr := runTool(t, "-manifest", manifestPath, "-key", keyPath)
	require.Equal(t, 0, code, "stderr:\n%s", stderr)
	assert.NotContains(t, stdout+stderr, seedHex)

	var sig abi.VerifierSignature
	require.NoError(t, json.Unmarshal([]byte(stdout), &sig))
	m := cleanManifest()
	assert.Equal(t, m.Digest(), sig.Digest)

	code, _, stderr = runTool(t, "-manifest", manifestPath, "-key", filepath.Join(dir, "absent.key"))
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "reading the signing key")
}
