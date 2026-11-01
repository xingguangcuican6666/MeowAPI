package abi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// Methods on the types a module holds. A method cannot stay in the kernel
// once its type lives here, so these moved with it.

// String renders a verdict for the console and the audit chain.
func (v TokenVerdict) String() string {
	switch v {
	case TokenConsistent:
		return "consistent"
	case TokenSuspicious:
		return "suspicious"
	case TokenImpossible:
		return "impossible"
	default:
		return fmt.Sprintf("verdict(%d)", int(v))
	}
}

func (r MeterRecord) ElapsedNanos() int64 {
	if r.Closed <= r.Opened {
		return 0
	}
	return r.Closed - r.Opened
}

func (s Span) ElapsedNanos() int64 {
	if s.End <= s.Start {
		return 0
	}
	return s.End - s.Start
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
