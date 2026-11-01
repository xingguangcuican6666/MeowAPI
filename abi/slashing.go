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

// Fraud proofs over signed receipts, their records and the ledger counters.

// SlashFilter selects ledger records. Zero values mean no constraint on that field.
type SlashFilter struct {
	Kind    SlashKind
	NodeID  string
	Verdict SlashVerdict
	// Since returns only records filed at or after this Mono() reading.
	Since int64
	Limit int
}

// SlashProof is one accusation. The reporter supplies the receipts and the kind of
// claim; everything else - whether the receipts verify, whether they actually
// contradict, who is accused - is recomputed by the kernel.
//
// That division is the control. A reporter that could set the verdict would be writing
// its own evidence, and a reporter that could name the accused node without supplying a
// receipt signed by it could accuse anyone.
type SlashProof struct {
	// Kind is the claim. It must be one of the closed set.
	Kind SlashKind `json:"kind"`
	// NodeID is the node being accused. Every receipt in the proof must carry this
	// node id, and every receipt's signature must verify, so the accusation cannot
	// be pointed at a node that signed nothing here.
	NodeID string `json:"node_id"`
	// Receipts are the evidence. At least one is required, and for equivocation
	// exactly two are compared.
	Receipts []Receipt `json:"receipts"`
	// Note is an optional operator-readable statement from the reporter. It is
	// length-bounded and line-break-free because it is copied into audit fields.
	Note string `json:"note,omitempty"`
}

// SlashRecord is one case in the ledger.
type SlashRecord struct {
	ID      SlashID      `json:"id"`
	Kind    SlashKind    `json:"kind"`
	NodeID  string       `json:"node_id"`
	Verdict SlashVerdict `json:"verdict"`
	// Reporters are the pids that filed this proof, in the order they arrived. It is
	// a list rather than a single pid because two independent reporters filing the
	// same evidence is materially stronger than one, and collapsing them would throw
	// that away.
	Reporters []PID `json:"reporters"`
	// FiledMono and DecidedMono are monotonic readings.
	FiledMono   int64 `json:"filed_mono"`
	DecidedMono int64 `json:"decided_mono,omitempty"`
	// Finding is the kernel's conclusion, present once decided.
	Finding SlashFinding `json:"finding"`
	// Note echoes the first reporter's note, for an operator reading the ledger.
	Note string `json:"note,omitempty"`
}

// SlashFinding is what the kernel concluded. It is separate from the proof because the
// proof is the accusation and the finding is the decision, and conflating them is how a
// reporter's characterization ends up being read as a verdict.
type SlashFinding struct {
	// Kind echoes the claim that was decided.
	Kind SlashKind `json:"kind"`
	// Established is true when the recomputation confirmed the claim.
	Established bool `json:"established"`
	// Reason explains the conclusion either way. An unproven finding carries the
	// reason it failed, which is what tells an operator whether the accusation was
	// wrong or merely unsupported.
	Reason string `json:"reason"`
	// Digests names the receipts the decision rests on, so a dispute can be
	// re-examined without the original proof object.
	Digests []string `json:"digests,omitempty"`
	// MissingSeqs lists the sequence numbers a gap finding proved were issued. Empty
	// for every other kind.
	MissingSeqs []int64 `json:"missing_seqs,omitempty"`
}

// SlashVerdict is the state of one filed proof.
type SlashVerdict string

const (
	// SlashPending is a proof that has been filed and not yet decided.
	SlashPending SlashVerdict = "pending"
	// SlashConfirmed means the kernel recomputed the claim from the receipts and it
	// holds. This is the verdict an operator acts on.
	SlashConfirmed SlashVerdict = "confirmed"
	// SlashUnproven means the claim did not hold. It is NOT a statement that the
	// accused node is honest: the receipts may have been insufficient, or the
	// reporter may have mischaracterized them.
	SlashUnproven SlashVerdict = "unproven"
)

// SlashStats are the ledger counters.
//
// Refused is a single counter for every kind of refusal, on the same reasoning
// keyring.go gives for making an out-of-scope alias and an unknown alias
// indistinguishable: a reporter that could tell which of its proofs were rejected for
// shape and which for duplication could probe the ledger's contents.
type SlashStats struct {
	Pending   int   `json:"pending"`
	Confirmed int64 `json:"confirmed"`
	Unproven  int64 `json:"unproven"`
	Filed     int64 `json:"filed"`
	// Corroborated counts proofs a second reporter added itself to.
	Corroborated  int64 `json:"corroborated"`
	Refused       int64 `json:"refused"`
	Records       int   `json:"records"`
	RecordEvicted int64 `json:"record_evicted"`
	MaxRecords    int   `json:"max_records"`
}
