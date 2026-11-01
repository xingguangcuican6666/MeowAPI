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

// The settlement receipt, its canonical signed encoding and its verdict.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// Receipt is one signed settlement record. Every field except Signature is covered
// by the signature through the canonical encoding, and every field is set by the
// kernel: the node id and the sequence number come from the sealed trust root and
// the ledger, the elapsed time from mono(), and the two content hashes are computed
// by the kernel unless the issuer supplies a precomputed digest.
//
// A receipt is public data. It is meant to leave the node, to be handed to a client
// and to be compared against a peer's copy by kslashing, so nothing here is secret
// and there is no path by which verifying one discloses key material.
type Receipt struct {
	// Version is the canonical encoding version.
	Version int `json:"version"`
	// NodeID is the issuing node, from the sealed trust root. It is inside the
	// signature, so a receipt cannot be replayed as another node's.
	NodeID string `json:"node_id"`
	// Seq is the per-node sequence number: monotonic, gap-free, starting at 1.
	Seq int64 `json:"seq"`
	// Trace is the request trace id, if the issuer supplied one. It links the
	// receipt to the audit entries for the same request.
	Trace string `json:"trace,omitempty"`
	// Route is a label for the model or route that served the request.
	Route string `json:"route,omitempty"`
	// PID is the module whose work this settles.
	PID PID `json:"pid"`
	// PromptHash and CompletionHash are sha256 hex digests of the request and the
	// response. They are what two nodes compare to agree that they served the same
	// content, so a peer that truncated a completion is caught by the digest and
	// not by a length check.
	PromptHash     string `json:"prompt_hash"`
	CompletionHash string `json:"completion_hash"`
	// TokensIn and TokensOut are the settled token counts.
	TokensIn  int64 `json:"tokens_in"`
	TokensOut int64 `json:"tokens_out"`
	// ElapsedNanos is the service time measured on the kernel's monotonic clock.
	// A wall clock is not used: it can step backwards, and a settlement record
	// with a negative duration is a record nobody can reason about.
	ElapsedNanos int64 `json:"elapsed_nanos"`
	// IssuedMono is the monotonic reading at issue time, so a receipt can be
	// ordered against the audit chain, which is stamped the same way.
	IssuedMono int64 `json:"issued_mono"`
	// IssuedWall is the wall-clock issue time in Unix nanoseconds, for humans and
	// for cross-node comparisons where monotonic readings are meaningless.
	IssuedWall int64 `json:"issued_wall"`
	// KeyID identifies the signing key as a short digest of its public half, so a
	// verifier can select a cluster root without being told which one.
	KeyID string `json:"key_id"`
	// Signature is the ed25519 signature over the canonical payload.
	Signature []byte `json:"signature"`
}

// ReceiptSpec is what an issuer supplies. The fields the kernel owns - node id,
// sequence number, key id, issue timestamps - are absent on purpose: an issuer that
// could choose them could choose someone else's node id or a sequence number that
// hides a gap.
type ReceiptSpec struct {
	// PID is the module whose work this settles. Zero means the calling context's
	// own pid.
	PID PID
	// Trace and Route are labels. Both are length-bounded because they are stored
	// in every receipt the node keeps a copy of.
	Trace string
	Route string
	// Prompt and Completion are the content the hashes are computed from. They may
	// be empty, for example when the issuer already holds digests.
	Prompt     []byte
	Completion []byte
	// PromptHash and CompletionHash, when set, are used verbatim instead of being
	// computed from the byte slices above. They must be 64 lowercase hex
	// characters. This exists for a streamed completion, where the issuer digested
	// each chunk as it arrived and no longer holds the whole body; supplying them
	// is the issuer's claim, and it is inside the signature either way.
	PromptHash     string
	CompletionHash string
	// TokensIn and TokensOut are the counts to settle. They are cross-checked
	// against the kernel's own accounting: see validateTokens.
	TokensIn  int64
	TokensOut int64
	// StartedMono is a mono() reading taken when the work began. Zero means the
	// work is being settled at issue time, so the elapsed time is zero. When Request
	// names a kmeter record, that record's own measurement wins.
	StartedMono int64
	// Request optionally names the kmeter request being settled. When it is set, the
	// token counts and the elapsed time come from the kernel's own meter record for
	// that request rather than from the issuer's claim, and the record must belong to
	// the pid being settled. This is the strongest form of the cross-check: there is
	// nothing for the issuer to claim.
	Request RequestID
}

// ReceiptVerdict is the outcome of a verification. It is a struct rather than a bool
// because a false verdict has reasons, and a fraud proof needs the reason and not
// only the conclusion.
type ReceiptVerdict struct {
	// Valid is true only when the structure is acceptable and the signature
	// verifies against a sealed cluster root.
	Valid bool `json:"valid"`
	// Digest is the receipt's canonical digest, present whether or not it
	// verified, so a refused receipt can still be named in a dispute.
	Digest string `json:"digest"`
	// KeyID is the cluster root that matched, or empty when none did.
	KeyID string `json:"key_id,omitempty"`
	// Reason explains a refusal. It is empty on a valid receipt.
	Reason string `json:"reason,omitempty"`
	// Structural is true when the receipt was rejected for its shape rather than
	// for its signature. A structural failure is a protocol or version mismatch;
	// a signature failure with a well-formed receipt is what a fraud proof claims.
	Structural bool `json:"structural,omitempty"`
}

// Encode renders a receipt for the wire as JSON. The JSON key order is not the
// canonical encoding and does not need to be: the signature covers the payload built
// by receiptPayload, so a peer that re-encodes with different key order still
// verifies. That separation is deliberate, because it means the wire format can
// change without invalidating a single issued receipt.
func (r Receipt) Encode() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("kernel: cannot encode receipt: %w", err)
	}
	return b, nil
}

// sha256Sum is the kernel's digest construction, repeated here rather than exported
// from it. abi cannot import the kernel, and the alternative - exporting a hashing
// primitive through the package every module compiles against - would add a name to
// the module-facing surface to save five lines. The two copies cannot drift in any
// way that matters: both are hex of a SHA-256 over the same bytes, and the canonical
// ENCODING, which is the part that must not change, lives next door in receiptPayload
// and is not duplicated.
func sha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ReceiptPayload is the canonical encoding a receipt's signature covers. It is
// exported because verification needs it: a peer that re-encodes differently would
// fail to verify a receipt that is perfectly valid, and a module holding a receipt
// should be able to check the payload the signature was taken over.
func ReceiptPayload(r Receipt) []byte {
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
	num := func(name string, v int64) { field(name, strconv.FormatInt(v, 10)) }

	// The order is part of the encoding and must not change without bumping
	// ReceiptVersion: a reordering makes every receipt issued by an older node
	// fail verification here, which is the correct outcome but is a protocol
	// break and not a refactor.
	field("version", strconv.Itoa(r.Version))
	field("node_id", r.NodeID)
	num("seq", r.Seq)
	field("trace", r.Trace)
	field("route", r.Route)
	num("pid", int64(r.PID))
	field("prompt_hash", r.PromptHash)
	field("completion_hash", r.CompletionHash)
	num("tokens_in", r.TokensIn)
	num("tokens_out", r.TokensOut)
	num("elapsed_nanos", r.ElapsedNanos)
	num("issued_mono", r.IssuedMono)
	num("issued_wall", r.IssuedWall)
	field("key_id", r.KeyID)
	return b.Bytes()
}
