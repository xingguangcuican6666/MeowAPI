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

// Command meowsign mints the detached manifest signature the kernel requires
// before it will load a module.
//
// It exists because the kernel deliberately refuses to sign anything. kverifier
// gives the reason: a package-level signing function inside the kernel would be a
// manifest-signing oracle reachable from any module linked into the same binary,
// and a module that could appraise its own widened declaration is the exact attack
// the appraisal exists to stop. What the kernel exports instead is the payload a
// signature must cover, and this command is the host-side half of that split. It
// runs where the key is - offline, in CI, in whatever custody holds the seed - and
// writes the JSON file the console reads from <component>.so.sig.
//
// Usage:
//
//	meowsign -manifest example.json (-key seed.hex | -key-hex 9f2c...) [-out example.so.sig] [-force]
//	meowsign -verify -manifest example.json -sig example.so.sig -roots <pubhex>[,<pubhex>...]
//
// Exit codes:
//
//	0  a signature was minted, or -verify confirmed one
//	1  the declaration audit reported findings and -force was not given, or -verify
//	   found a signature that does not hold
//	2  usage error: an unreadable file, a manifest that does not parse or does not
//	   validate, key material that is not an ed25519 key, a flag combination that
//	   asks for nothing or for two things at once
//
// -h and -help print the usage text and exit 0, because asking for help is a request
// and not a mistake, and a runbook that prints the usage would otherwise record a
// failure.
//
// A refusal to sign is a finding about the declaration and gets 1, while a mistake
// in how the command was invoked gets 2, so a pipeline can tell "fix the manifest"
// from "fix the command line" without parsing text.
//
// Key material is never printed: not on success, not inside an error, not inside a
// finding. The seed is read, used for one ed25519 call and dropped, and the only
// key-derived value that reaches any output is the public key's short digest and,
// on signing, the public key itself, which is what the operator has to add to the
// deployment's trust root.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xingguangcuican6666/MeowAPI/abi"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is the whole program behind an injectable argv and output, in the shape of
// tools/auditverify, so it is testable without a subprocess and without
// intercepting os.Exit. It returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("meowsign", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		manifestPath = fs.String("manifest", "", "the module manifest, as JSON")
		keyPath      = fs.String("key", "", "a file holding the signing key material (hex, base64 or PEM)")
		keyInline    = fs.String("key-hex", "", "the signing key material itself; never echoed back")
		outPath      = fs.String("out", "", "write the signature to this path instead of to stdout")
		force        = fs.Bool("force", false, "sign even though the declaration audit reported findings")
		verify       = fs.Bool("verify", false, "check an existing signature instead of minting one")
		sigPath      = fs.String("sig", "", "with -verify: the signature file to check")
		roots        = fs.String("roots", "", "with -verify: comma-separated cluster root public keys")
	)
	fs.Usage = func() { usage(stderr, fs) }

	if err := fs.Parse(args); err != nil {
		// Help is a request and not a mistake, so it exits 0: a pipeline that runs
		// `-h` to print usage into a runbook would otherwise record a failure. Every
		// other parse error is an invocation the command cannot carry out, which is the
		// exit code 2 documented above.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fail(stderr, "meowsign takes no positional arguments, got %q", strings.Join(fs.Args(), " "))
		fs.Usage()
		return 2
	}

	m, err := readManifest(*manifestPath)
	if err != nil {
		fail(stderr, "%v", err)
		return 2
	}

	if *verify {
		code, err := verifySignature(stdout, m, *sigPath, *roots, *keyPath, *keyInline, *outPath, *force)
		if err != nil {
			fail(stderr, "%v", err)
			return code
		}
		return code
	}

	code, err := sign(stdout, stderr, m, *keyPath, *keyInline, *outPath, *force)
	if err != nil {
		fail(stderr, "%v", err)
	}
	return code
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `meowsign mints the detached manifest signature the kernel appraises at module load.

  meowsign -manifest example.json (-key seed.hex | -key-hex VALUE) [-out example.so.sig] [-force]
  meowsign -verify -manifest example.json -sig example.so.sig -roots PUBKEY[,PUBKEY...]

The signature covers kernel.VerifierBindingPayload: the module's name, its version
and the manifest's digest, length-prefixed and in a fixed order. Signing anything
else produces a file the kernel refuses as a bad signature.

`)
	fs.PrintDefaults()
	fmt.Fprint(w, `
Exit codes: 0 signed or verified, 1 refused on the declaration or on the signature,
2 invoked wrongly. Key material is never printed.
`)
}

func fail(w io.Writer, format string, a ...any) {
	fmt.Fprintf(w, "meowsign: "+format+"\n", a...)
}

// sign is the minting path: audit the declaration, then sign the payload the kernel
// says a signature must cover. It returns the exit code and, separately, an error
// only for the cases that are a usage mistake rather than a verdict.
func sign(stdout, stderr io.Writer, m abi.Manifest, keyPath, keyInline, outPath string, force bool) (int, error) {
	if keyPath != "" && keyInline != "" {
		return 2, errors.New("-key and -key-hex are two ways to give one key; pass one of them")
	}
	material := keyInline
	if keyPath != "" {
		raw, err := os.ReadFile(keyPath)
		if err != nil {
			return 2, fmt.Errorf("reading the signing key: %w", err)
		}
		material = string(raw)
	}
	if strings.TrimSpace(material) == "" {
		return 2, errors.New("no signing key: pass -key with a file or -key-hex with the value")
	}
	priv, err := parseSigningKey(material)
	if err != nil {
		return 2, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return 2, errors.New("the signing key does not yield an ed25519 public key")
	}

	// The audit runs before the signature and its findings go to stderr, so a
	// pipeline that captures stdout for the signature still shows the reviewer what
	// they are about to vouch for. Findings are advisory in the kernel and the
	// kernel is right to keep them that way - it loads modules and must not turn a
	// review observation into a refusal - but a signing tool that printed them and
	// signed regardless would make the checklist decoration. Refusing by default and
	// requiring -force to proceed is what makes the reviewer's decision a recorded
	// act rather than a message scrolled past.
	findings := kernel.VerifierAuditDeclaration(m)
	printFindings(stderr, m, findings)
	if len(findings) > 0 {
		if !force {
			fmt.Fprintf(stderr, "meowsign: refusing to sign %s %s: resolve the findings above, "+
				"or pass -force to sign with them unresolved\n", m.Name, m.Version)
			return 1, nil
		}
		fmt.Fprintf(stderr, "meowsign: WARNING: signing %s %s with %d unresolved finding(s) under -force\n",
			m.Name, m.Version, len(findings))
	}

	sig := abi.VerifierSignature{
		Version:       abi.VerifierBindingVersion,
		Module:        m.Name,
		ModuleVersion: m.Version,
		Digest:        m.Digest(),
		KeyID:         keyID(pub),
		// The kernel clock's monotonic reading, which is the same construction the
		// kernel itself would stamp. Its origin is this process's start, so the number
		// is comparable between two signatures minted in one run and means nothing
		// across runs. That is acceptable because SignedMono is evidence inside the
		// payload and not an input to any decision: abi/verifier.go states that no
		// freshness, expiry or ordering rule reads it, precisely so that a signer
		// cannot weaken a later appraisal by backdating this one.
		SignedMono: kernel.KernelClock().Mono(),
		Bytes:      ed25519.Sign(priv, kernel.VerifierBindingPayload(m)),
	}

	raw, err := marshalSignature(sig)
	if err != nil {
		return 2, err
	}
	if outPath != "" {
		// 0644 rather than 0600: a signature is public data, and a component directory
		// the daemon reads under a service account has to stay readable by it. The seed
		// is what needs a mode, and it is never written here.
		if err := os.WriteFile(outPath, raw, 0o644); err != nil {
			return 2, fmt.Errorf("writing %s: %w", outPath, err)
		}
		fmt.Fprintf(stderr, "meowsign: wrote %s\n", outPath)
	} else if _, err := stdout.Write(raw); err != nil {
		return 2, fmt.Errorf("writing the signature: %w", err)
	}

	fmt.Fprintf(stderr, "meowsign: signed %s %s digest %s key %s\n", m.Name, m.Version, sig.Digest, sig.KeyID)
	// The public key is printed because the operator needs it and it is not a secret:
	// it is the value that goes into the deployment's -verify-key list, without which
	// the signature just minted verifies against nothing. Printing it here saves the
	// operator from re-deriving it from the seed with a second tool, which is the step
	// where a key inventory goes stale.
	fmt.Fprintf(stderr, "meowsign: the matching cluster root key is %s\n", hex.EncodeToString(pub))
	return 0, nil
}

// verifySignature is -verify: the same appraisal the kernel performs, run against a
// root list given on the command line rather than one sealed into a booted kernel.
//
// It does not call kernel.VerifyManifest, and the difference is the point of the
// mode. That function appraises against the sealed trust root of a running kernel,
// so using it here would mean booting one, which would mean holding the very key
// custody this command exists to serve offline. What it reproduces instead is
// verifyManifestBinding's order and its distinctions - structure, identity, digest,
// trust, then the cryptographic verdict - so an operator learns here which of the
// kernel's refusals a deployment is about to produce, and in the same words.
func verifySignature(stdout io.Writer, m abi.Manifest, sigPath, rootList, keyPath, keyInline, outPath string, force bool) (int, error) {
	if sigPath == "" {
		return 2, errors.New("-verify needs -sig with the signature file to check")
	}
	if keyPath != "" || keyInline != "" {
		return 2, errors.New("-verify checks a signature against public roots and takes no signing key")
	}
	if outPath != "" || force {
		return 2, errors.New("-out and -force belong to the signing path, not to -verify")
	}

	// Every flag-level mistake is settled before any file is opened, so an invocation
	// that asked for nothing usable reports that rather than whichever read happened to
	// fail first. Two usage errors on one command line otherwise produce whichever
	// message the ordering picked, and the operator fixes one and re-runs into the other.
	rootKeys, err := parseRoots(rootList)
	if err != nil {
		return 2, err
	}

	raw, err := os.ReadFile(sigPath)
	if err != nil {
		return 2, fmt.Errorf("reading the signature: %w", err)
	}
	var sig abi.VerifierSignature
	if err := json.Unmarshal(raw, &sig); err != nil {
		return 2, fmt.Errorf("%s is not a valid signature file: %w", sigPath, err)
	}

	if err := appraise(m, &sig, rootKeys); err != nil {
		fmt.Fprintf(stdout, "%s: REFUSED: %v\n", sigPath, err)
		return 1, nil
	}
	// The verdict names no count of roots, because a root that does not parse is
	// skipped rather than fatal and a number printed here would then describe the list
	// the operator typed rather than the keys that were consulted. The refusal paths
	// name the count they actually checked.
	fmt.Fprintf(stdout, "%s: OK: %s %s digest %s key %s verifies against the cluster roots given\n",
		sigPath, m.Name, m.Version, sig.Digest, sig.KeyID)
	return 0, nil
}

// appraise is the verification ladder, in the order kernel/verifier.go's
// verifyManifestBinding runs it. Each refusal is reported with the distinction the
// kernel draws, because the operator's response to a replayed signature is not
// their response to a forged one and not their response to a key they rotated out.
func appraise(m abi.Manifest, sig *abi.VerifierSignature, rootKeys []string) error {
	if sig.Version != abi.VerifierBindingVersion {
		return fmt.Errorf("binding version %d, this kernel accepts %d", sig.Version, abi.VerifierBindingVersion)
	}
	// A wrong-length signature is malformed rather than unverifying, and the check
	// also keeps ed25519.Verify from ever being handed a length it would panic on.
	if len(sig.Bytes) != ed25519.SignatureSize {
		return fmt.Errorf("the signature is %d bytes, want %d", len(sig.Bytes), ed25519.SignatureSize)
	}
	if sig.KeyID == "" {
		return errors.New("the signature names no key id")
	}

	// The envelope is a claim and the payload below is rebuilt from the manifest in
	// hand, never from the envelope. Checking the claim first is for diagnosis only:
	// an attacker who edits it to match a tampered manifest still fails the
	// cryptographic step, because those bytes come from the manifest.
	if sig.Module != m.Name || sig.ModuleVersion != m.Version {
		return fmt.Errorf("the signature covers %s@%s, the manifest is %s@%s",
			sig.Module, sig.ModuleVersion, m.Name, m.Version)
	}
	digest := m.Digest()
	if sig.Digest != digest {
		return fmt.Errorf("the signature covers digest %s, this manifest digests to %s: "+
			"the declaration was signed and then edited", sig.Digest, digest)
	}

	// The trust check runs before the cryptographic one and only when at least one root
	// parses, both mirroring verifyManifestBinding. A signature from a key the operator
	// never trusted is a key-inventory problem even when it happens to verify, and
	// reporting it as a clean OK would send them looking at the declaration instead. With
	// no parsable root at all there is no inventory to be absent from, so the answer is a
	// configuration error rather than a verdict on this signature.
	usable, trusted := 0, false
	for _, root := range rootKeys {
		pub, err := parseVerificationKey(root)
		if err != nil {
			// Skipped rather than fatal, mirroring verifyAgainstClusterRoots: a cluster
			// list may hold a key this tool cannot parse, and refusing to check anything
			// because one entry is opaque would be a self-inflicted outage.
			continue
		}
		usable++
		if keyID(pub) == sig.KeyID {
			trusted = true
		}
	}
	if usable == 0 {
		return errors.New("no cluster root key is a usable ed25519 key, so there is nothing to appraise against")
	}
	if !trusted {
		return fmt.Errorf("key id %s is not among the %d cluster root(s) given", sig.KeyID, usable)
	}

	payload := kernel.VerifierBindingPayload(m)
	for _, root := range rootKeys {
		pub, err := parseVerificationKey(root)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, payload, sig.Bytes) {
			return nil
		}
	}
	return errors.New("the signature is well formed and names a trusted key, but no cluster root verifies it " +
		"over this manifest's binding payload")
}

// parseRoots splits the comma-separated root list. An empty entry is refused rather
// than skipped: the kernel's own validateTrustRoot refuses an empty cluster root
// key, and silently dropping one here would let a trailing comma report a verdict
// about a smaller trust root than the deployment actually seals.
func parseRoots(rootList string) ([]string, error) {
	if strings.TrimSpace(rootList) == "" {
		return nil, errors.New("-verify needs -roots with the cluster root public keys the deployment trusts")
	}
	var out []string
	for entry := range strings.SplitSeq(rootList, ",") {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			return nil, errors.New("-roots has an empty entry; the kernel refuses an empty cluster root key too")
		}
		out = append(out, trimmed)
	}
	return out, nil
}

// readManifest reads one manifest declaration.
//
// Unknown fields are refused and trailing data is refused, both because of what the
// digest covers. Manifest.Digest hashes the marshalled struct, so a JSON file
// carrying "allowed_host" instead of "allowed_hosts" parses happily into a manifest
// with no host list at all: the operator signs a narrower declaration than the
// component actually exports, and the failure surfaces much later as a digest
// mismatch at load, pointing at the wrong file. Refusing the spelling turns that
// into an error at the moment it is made.
func readManifest(path string) (abi.Manifest, error) {
	var m abi.Manifest
	if strings.TrimSpace(path) == "" {
		return m, errors.New("no manifest: pass -manifest with the declaration to sign")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return m, fmt.Errorf("reading the manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("%s is not a valid manifest: %w", path, err)
	}
	if dec.More() {
		return m, fmt.Errorf("%s has trailing data after the manifest object", path)
	}

	// Validation runs here rather than being left to the load, because
	// VerifierAuditDeclaration deliberately does not re-run it: that function takes its
	// input as a declaration that is about to be validated, and this tool is the caller
	// that has to. Signing a declaration the kernel will refuse at load wastes the
	// operator's key and produces a signature whose refusal reads as a cryptography
	// problem rather than as the manifest defect it is.
	if err := kernel.ValidateManifest(&m); err != nil {
		return m, err
	}
	if m.Digest() == "" {
		return m, errors.New("the manifest does not marshal, so it has no digest to sign")
	}
	return m, nil
}

// printFindings renders the declaration audit as the reviewer's checklist, numbered in
// the order the kernel reported them. A clean declaration gets one line rather than
// silence, so an operator running this in a pipeline can tell "the audit ran and found
// nothing" from "the audit never ran", which is the distinction a suppressed checklist
// destroys.
func printFindings(w io.Writer, m abi.Manifest, findings []kernel.VerifierFinding) {
	if len(findings) == 0 {
		fmt.Fprintf(w, "meowsign: the declaration audit is clean for %s %s\n", m.Name, m.Version)
		return
	}
	fmt.Fprintf(w, "meowsign: the declaration audit reported %d finding(s) for %s %s:\n",
		len(findings), m.Name, m.Version)
	for i, f := range findings {
		fmt.Fprintf(w, "  %d. [%s] %s: %s\n", i+1, f.Code, f.Field, f.Detail)
	}
}

// marshalSignature renders the signature exactly as the console loader reads it.
// internal/console's readComponentSignature json.Unmarshals a kernel.VerifierSignature
// out of <component>.so.sig, and kernel.VerifierSignature is an alias of the abi type
// encoded here, so the one encoder serves both the file and stdout and there is no
// second spelling of the format to drift.
func marshalSignature(sig abi.VerifierSignature) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sig); err != nil {
		return nil, fmt.Errorf("encoding the signature: %w", err)
	}
	return buf.Bytes(), nil
}

// keyID derives the short identifier for a public key: the first eight bytes of its
// sha256, hex encoded.
//
// It must stay identical to kernel/crypto.go's unexported ed25519KeyID. The trust
// check in verifyManifestBinding recomputes the id from each sealed cluster root's key
// bytes and compares, so a construction that drifts here - a different digest, a
// different prefix length, an uppercase encoding - mints a signature the kernel
// refuses as coming from an untrusted key, with no indication that the two spellings
// of one rule are what disagreed.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// parseSigningKey accepts every encoding the kernel's trust root accepts for
// BootTrustRoot.SigningKeyPEM: a PEM PKCS8 block, a 32-byte seed or a full 64-byte
// ed25519 private key, each carried as PEM, hex or base64. It mirrors
// parseEd25519Private in kernel/crypto.go, which is unexported.
//
// Accepting less than the kernel does would refuse a key the operator already
// deploys. Accepting more is the worse failure: a signature minted under material no
// trust root can name is a signature that verifies nowhere, and it looks complete
// everywhere it is read.
//
// No error carries any part of the material. A key that fails to parse is the one
// value this tool must not quote back, because the failure text is what lands in a
// terminal scrollback, a CI log and a shell history.
func parseSigningKey(material string) (ed25519.PrivateKey, error) {
	raw, err := decodeKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("the signing key is a %T, want ed25519", key)
		}
		return ed, nil
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("the signing key material decodes to %d bytes, want a %d-byte seed, "+
		"a %d-byte ed25519 private key or a PKCS8 block",
		len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
}

// parseVerificationKey accepts the same carrier encodings for a public key, mirroring
// kernel/crypto.go's parseEd25519Public: a bare 32-byte key or a PKIX block, as PEM,
// hex or base64.
func parseVerificationKey(material string) (ed25519.PublicKey, error) {
	raw, err := decodeKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	if key, err := x509.ParsePKIXPublicKey(raw); err == nil {
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("the verification key is a %T, want ed25519", key)
		}
		return ed, nil
	}
	return nil, errors.New("the key material is not an ed25519 public key")
}

// decodeKeyMaterial normalizes the three carrier encodings into raw bytes, in the
// order decodePEMHexOrBase64 in kernel/crypto.go tries them. Hex goes before base64
// because a hex string is also valid base64 far more often than the reverse, and
// guessing wrong yields a confusing length error later rather than a clear one here.
func decodeKeyMaterial(material string) ([]byte, error) {
	trimmed := strings.TrimSpace(material)
	if trimmed == "" {
		return nil, errors.New("the key material is empty")
	}
	if strings.Contains(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, errors.New("the key material looks like PEM but does not decode")
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
	return nil, errors.New("the key material is not PEM, hex or base64")
}
