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

package abi

// The operator's signature over a module's declaration.
//
// It lives here rather than in the kernel because it is part of a syscall's
// parameter list: SyscallTTYLoadModule takes one, and a module has to be able to
// name a type in a signature it calls. The kernel re-exports it as an alias, so
// there is one type and not two.
//
// It is DATA only. Nothing in this file verifies anything - the appraisal, the
// trust check and the ledger stay in kverifier, which is where the sealed cluster
// roots live and which a module cannot reach. A component can construct one of
// these values, and an unsigned or forged one is exactly what the kernel's
// appraisal exists to refuse.

// VerifierBindingVersion is the binding-payload version this kernel signs and
// accepts. A signature minted under another version is refused rather than
// reinterpreted: the field layout is part of what the signature covers, and a
// verifier that guessed at an unknown layout would be appraising an encoding it
// did not read.
const VerifierBindingVersion = 1

// VerifierSignature is a detached operator signature over one manifest's binding
// payload. It travels beside the deployment rather than inside the manifest: the
// manifest is module-authored data, the signature is the operator's appraisal of
// it, and storing the appraisal inside the thing appraised would let the appraised
// party carry and re-present it.
type VerifierSignature struct {
	// Version is the binding-payload version and must equal
	// VerifierBindingVersion.
	Version int `json:"version"`
	// Module, ModuleVersion and Digest restate the signed identity, so a mismatch
	// is diagnosable from the refusal alone and a refused load names what the
	// signature was actually minted for. Digest is the sha256 hex of the manifest
	// the signer reviewed, matching Manifest.Digest().
	Module        string `json:"module"`
	ModuleVersion string `json:"module_version"`
	Digest        string `json:"digest"`
	// KeyID identifies the signing key as its short public-key digest, so the
	// trust check and the operator's key inventory use the same name and no key
	// material appears in a record.
	KeyID string `json:"key_id"`
	// SignedMono is the signer's mono() reading at mint time. It is evidence inside
	// the payload and not an authorization input: no freshness, expiry or ordering
	// decision reads it, because a decision that did would let a signer weaken a
	// later appraisal by backdating this one.
	SignedMono int64 `json:"signed_mono"`
	// Bytes is the raw ed25519 signature over the binding payload.
	Bytes []byte `json:"bytes"`
}
