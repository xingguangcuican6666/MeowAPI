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

// The kernel measurement a reported count is compared against.

import (
	"fmt"
)

// TokenMeasurement is what the kernel computed about one byte slice. It holds no
// reference to the input, so a caller that reuses or mutates its buffer afterwards
// cannot change anything the kernel recorded.
type TokenMeasurement struct {
	// Bytes is the length of the measured input.
	Bytes int `json:"bytes"`
	// CodePoints is the number of UTF-8 code points, counting each invalid byte as
	// one. It is not a token estimate; it is the denominator the ratios work on.
	CodePoints int `json:"code_points"`
	// Estimate is the kernel's deterministic approximation. See tokenEstimateModel
	// for exactly how it is derived; it is integer arithmetic only, so it cannot
	// differ between platforms or runs.
	Estimate int64 `json:"estimate"`
	// Floor is the structural lower bound. A report below it is provably wrong for a
	// tokenizer whose pre-tokenizer does not merge across whitespace or across a
	// letter/digit/punctuation class change - which is what the GPT-2 family regex
	// does, and every major provider's tokenizer is in that family. SentencePiece
	// unigram models can merge across those boundaries in principle, so the floor is
	// conditional on the tokenizer family rather than universal, and TokenStrictFloor
	// exists to let a deployment say which assumption it is making.
	Floor int64 `json:"floor"`
	// Runs is the count of pre-tokenizer runs the floor is derived from, exposed so a
	// reader can check the arithmetic rather than take the number on faith.
	Runs int `json:"runs"`
	// Invalid is the number of bytes that were not valid UTF-8. A tokenizer still has
	// to emit something for them, and an input that is mostly invalid is a different
	// shape of input from prose, so the count is reported rather than folded in.
	Invalid int `json:"invalid"`
	// Whitespace is counted separately because it is not ratio'd: in this tokenizer
	// family it attaches to a neighbouring token rather than becoming one. Reporting it
	// is what lets a reader see why an input's estimate is lower than its byte count
	// suggests.
	Whitespace int `json:"whitespace"`
}

// TokenCheck is the result of comparing one report against one measurement. It is a
// value rather than an error because the comparison succeeding is the normal case and
// a disagreement is a finding, not a failure.
type TokenCheck struct {
	Measurement TokenMeasurement `json:"measurement"`
	Reported    int64            `json:"reported"`
	Verdict     TokenVerdict     `json:"verdict"`
	// Reason says which rule produced the verdict. It is populated for every verdict
	// including TokenConsistent, because "consistent" without a reason is a number a
	// reader has to re-derive to trust.
	Reason string `json:"reason"`
}

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
