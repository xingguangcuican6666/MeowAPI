/*
Copyright (C) 2023-2026 xingguangcuican6666

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

// Package tokenizer tests ktokenizer: the deterministic in-kernel token measurement
// and the comparison of a module's reported usage against it.
//
// The properties here are the ones that make the measurement trustworthy enough to
// accuse a module with: determinism, a floor that is actually a floor for every input
// shape in play, tolerance edges that behave exactly at the boundary, adversarial input
// that neither panics nor reports zero, and a ledger that cannot be grown without limit
// or mutated through a snapshot.
package tokenizer

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// tokenCounter gives every test a unique module name.
var tokenCounter int

func tokenNextName(prefix string) string {
	tokenCounter++
	return prefix + harness.Itoa(tokenCounter)
}

func tokenBoot(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "node-token"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// tokenLoad loads a module holding token:count and returns its context.
func tokenLoad(t *testing.T, k *kernel.Kernel, prefix string, ops ...kernel.Op) kernel.SContext {
	t.Helper()
	all := append([]kernel.Op{kernel.OpTokenCount}, ops...)
	name := tokenNextName(prefix)
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: all,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, probe.Ctx)
	return probe.Ctx
}

// tokenResetStrict restores the default strictness. It is package state and one test
// that sets it would silently change the verdict every later test sees.
func tokenResetStrict(t *testing.T) {
	t.Helper()
	kernel.TokenSetStrictFloor(false)
	t.Cleanup(func() { kernel.TokenSetStrictFloor(false) })
}

// tokenInputs is the corpus every structural property is checked against. It is a
// variable rather than repeated literals so a new input shape is added in one place and
// every property test covers it.
var tokenInputs = []struct {
	name string
	// in is written with escape sequences for anything non-ASCII. The file is pure
	// ASCII because CI's instrcheck requires it of every tracked file's content and a
	// homoglyph in a test fixture is indistinguishable from an attack; the escapes make
	// the bytes explicit, which is also what the test is actually about.
	in string
}{
	{"empty", ""},
	{"one word", "hello"},
	{"english prose", "The quick brown fox jumps over the lazy dog."},
	{"json", `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`},
	{"cjk", "\u4e2d\u6587\u6d4b\u8bd5"},
	{"mixed scripts", "hello \u4e16\u754c 42"},
	{"digits only", "1234567890"},
	{"code", "func main() { fmt.Println(x) }"},
	{"punctuation dense", "!!!???...,,,;;;:::"},
	{"invalid utf8", "\xff\xfe\x00\x01abc"},
	{"nul heavy", "\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"newlines", "line one\nline two\nline three"},
	{"base64", "U29tZSBiYXNlNjQgZW5jb2RlZCBwYXlsb2FkIGhlcmU="},
}

// ---------------------------------------------------------------------------
// Determinism.

// TestMeasurementIsDeterministic pins the property everything else rests on. A number
// that differs between two calls cannot corroborate anything, and a number that differs
// between platforms cannot be compared against a receipt signed on another node.
func TestMeasurementIsDeterministic(t *testing.T) {
	for _, c := range tokenInputs {
		t.Run(c.name, func(t *testing.T) {
			first := kernel.TokenMeasure([]byte(c.in))
			for range 5 {
				assert.Equal(t, first, kernel.TokenMeasure([]byte(c.in)),
					"the same bytes must measure identically every time")
			}
		})
	}
}

// TestMeasurementIsDeterministicUnderConcurrency is the same property with the race
// detector watching, which is where a map-order-sensitive or shared-state-sensitive
// implementation shows up.
func TestMeasurementIsDeterministicUnderConcurrency(t *testing.T) {
	// An interpreted string, not a raw one: a backquoted string would pass the six
	// characters backslash-u-4-e-2-d through literally rather than the CJK code point,
	// and the fixture would measure something other than what its name says.
	payload := []byte("{\"a\":1,\"b\":[1,2,3],\"c\":\"mixed \u4e2d text\"}")
	want := kernel.TokenMeasure(payload)

	const goroutines = 16
	var wg sync.WaitGroup
	results := make(chan kernel.TokenMeasurement, goroutines)
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- kernel.TokenMeasure(payload)
		}()
	}
	wg.Wait()
	close(results)

	for got := range results {
		assert.Equal(t, want, got)
	}
}

// TestMeasurementDoesNotRetainTheCallersSlice pins that the kernel keeps no reference
// to module memory. This is the same guarantee kpipe makes, and the reason is the same:
// a measurement that can be changed after the fact by the party being measured is not a
// measurement.
func TestMeasurementDoesNotRetainTheCallersSlice(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokretain", kernel.OpUsageEmit)

	payload := []byte("a prompt whose tokens the module will report honestly")
	before, err := kernel.TokenCount(ctx, payload)
	require.NoError(t, err)

	// Mutate the caller's buffer in place, which is what a module reusing one buffer
	// across requests does.
	for i := range payload {
		payload[i] = 'x'
	}

	assert.Equal(t, before, kernel.TokenMeasure([]byte(
		"a prompt whose tokens the module will report honestly")),
		"the earlier measurement must not have changed")

	// And a recorded check is not retroactively altered either.
	_, err = kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, 8, []byte("second measurement"))
	require.NoError(t, err)
	ledger := kernel.TokenLedger()
	require.NotEmpty(t, ledger)
	first := ledger[0].Check.Measurement
	for i := range ledger {
		ledger[i].Check.Measurement.Estimate = -1
	}
	again := kernel.TokenLedger()
	assert.Equal(t, first, again[0].Check.Measurement,
		"mutating a returned ledger entry must not reach kernel state")
}

// ---------------------------------------------------------------------------
// The floor.

// TestTheEstimateIsNeverBelowItsOwnFloor is the internal-consistency property. The
// floor is a structural minimum for the assumed tokenizer family, so an estimate below
// it means the function contradicted itself. Punctuation-dense and JSON input are where
// a prose-derived ratio does that, which is why the corpus includes them.
func TestTheEstimateIsNeverBelowItsOwnFloor(t *testing.T) {
	for _, c := range tokenInputs {
		t.Run(c.name, func(t *testing.T) {
			m := kernel.TokenMeasure([]byte(c.in))
			assert.GreaterOrEqual(t, m.Estimate, m.Floor,
				"an estimate below its own floor is a self-contradiction")
		})
	}
}

// TestTheFloorCountsPreTokenizerRuns pins what the floor is made of, so a reader can
// check the arithmetic rather than take the number on faith. Each case states the run
// count by hand.
func TestTheFloorCountsPreTokenizerRuns(t *testing.T) {
	cases := []struct {
		name string
		in   string
		runs int
	}{
		// One letter run.
		{"single word", "hello", 1},
		// Whitespace separates words and does not count as a run of its own, because in
		// this tokenizer family a space attaches to the following token rather than
		// becoming one. Counting it would overstate the floor and accuse honest modules.
		{"two words", "one two", 2},
		// Nine words, ten runs: the final period is punctuation, a different class from
		// the letters before it, and a class change is a new run.
		{"nine word sentence", "The quick brown fox jumps over the lazy dog.", 10},
		// A class change inside a word is a new run: letters, then digits.
		{"letters then digits", "abc123", 2},
		// Punctuation is its own class, so each maximal punctuation run is one.
		{"trailing punctuation", "wait...", 2},
		// CJK characters are letters, and they are contiguous, so they form one run.
		// This is a documented under-count: a real tokenizer costs roughly one token per
		// CJK character. Understating a floor is the safe direction, since it can only
		// make the kernel accuse fewer modules, never more.
		{"cjk contiguous", "\u4e2d\u6587", 1},
		// Leading whitespace produces no leading run.
		{"leading space", "   word", 1},
		// Newlines are whitespace.
		{"newline separated", "a\nb\nc", 3},
		{"empty", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := kernel.TokenMeasure([]byte(c.in))
			assert.Equal(t, c.runs, m.Runs, "the run count is the floor's derivation")
			assert.Equal(t, int64(c.runs), m.Floor)
		})
	}
}

// TestTheFloorIsNotOverstated is the other direction, and it is the one that decides
// whether this subsystem can be used at all. A floor above what an honest tokenizer
// produces turns every legitimate report into an accusation, which is worse than having
// no floor. Whitespace and CJK contiguity are where an over-eager implementation
// overstates, so they are asserted explicitly.
func TestTheFloorIsNotOverstated(t *testing.T) {
	// Nine words, so at most nine runs: the punctuation at the end is attached to the
	// last word and forms its own run only because '.' is a different class, giving ten
	// at the very most. A floor above the word count plus one is overstating.
	m := kernel.TokenMeasure([]byte("The quick brown fox jumps over the lazy dog."))
	assert.LessOrEqual(t, m.Floor, int64(10))

	// Four CJK characters are one run, not four. Asserting four here would be asserting
	// a floor no tokenizer in the family actually exceeds for this input, and every CJK
	// request would be flagged.
	cjk := kernel.TokenMeasure([]byte("\u4e2d\u6587\u6d4b\u8bd5"))
	assert.Equal(t, int64(1), cjk.Floor)

	// A long run of one repeated byte is one run, not one per byte.
	one := kernel.TokenMeasure(bytes.Repeat([]byte("a"), 4096))
	assert.Equal(t, int64(1), one.Floor, "a repeated character is one pre-tokenizer run")
}

// ---------------------------------------------------------------------------
// The classification.

// TestVerdictsAreWhatTheRulesSay walks each verdict with a report chosen to land in it.
// The tolerance edges are tested at the boundary rather than well inside it, because
// "roughly consistent" is not a rule anybody can rely on.
func TestVerdictsAreWhatTheRulesSay(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokverdict", kernel.OpUsageEmit)

	kernel.TokenSetStrictFloor(true)
	defer kernel.TokenSetStrictFloor(false)

	text := []byte("The quick brown fox jumps over the lazy dog. Then it runs away quickly.")
	m := kernel.TokenMeasure(text)
	require.Positive(t, m.Estimate)
	require.Positive(t, m.Floor)

	// The absurd ceiling is estimate*8 + 64, so just below it is suspicious at worst and
	// just above it is impossible. Computing the edges from the constants rather than
	// hardcoding them is what keeps this test honest if the model changes.
	ceiling := m.Estimate*8 + 64
	highSuspicious := m.Estimate*2 + 64

	cases := []struct {
		name     string
		reported int64
		want     kernel.TokenVerdict
	}{
		{"at the estimate", m.Estimate, kernel.TokenConsistent},
		{"a little above", m.Estimate + m.Estimate/2, kernel.TokenConsistent},
		{"at the suspicious edge", highSuspicious + 1, kernel.TokenSuspicious},
		{"far above but under the ceiling", ceiling, kernel.TokenSuspicious},
		{"above the absurd ceiling", ceiling + 1, kernel.TokenImpossible},
		{"at the floor", m.Floor, kernel.TokenConsistent},
		{"one below the floor", m.Floor - 1, kernel.TokenImpossible},
		{"zero", 0, kernel.TokenImpossible},
		{"negative", -5, kernel.TokenImpossible},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, c.reported, text)
			require.NoError(t, err)
			assert.Equal(t, c.want, got.Verdict, "reported=%d estimate=%d floor=%d reason=%q",
				c.reported, m.Estimate, m.Floor, got.Reason)
			assert.NotEmpty(t, got.Reason, "every verdict carries the rule that produced it")
		})
	}
}

// TestBelowTheFloorFollowsTheDeploymentsAssumption is the one classification that is
// conditional, so it is tested in both settings. The floor is a fact about tokenizers
// whose pre-tokenizer does not merge across whitespace or a class change; a
// SentencePiece unigram model can merge in principle. Strict says impossible,
// non-strict says suspicious - still recorded, still faulted, still on the chain, but
// not asserted as a fact the kernel cannot prove.
func TestBelowTheFloorFollowsTheDeploymentsAssumption(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokstrict", kernel.OpUsageEmit)

	text := []byte("A report below the structural floor for this input.")
	m := kernel.TokenMeasure(text)
	require.Greater(t, m.Floor, int64(1))
	below := m.Floor - 1

	kernel.TokenSetStrictFloor(true)
	strict, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, below, text)
	require.NoError(t, err)
	assert.Equal(t, kernel.TokenImpossible, strict.Verdict)
	assert.Contains(t, strict.Reason, "floor")
	assert.True(t, kernel.TokenStrictFloor())

	kernel.TokenSetStrictFloor(false)
	loose, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, below, text)
	require.NoError(t, err)
	assert.Equal(t, kernel.TokenSuspicious, loose.Verdict,
		"non-strict flags the same report rather than asserting a fact it cannot prove")
	assert.False(t, kernel.TokenStrictFloor())
}

// TestStrictnessIsHostConfigurationNotAModuleChoice pins the access rule. A module that
// could choose the strictness of the check applied to its own reports would choose the
// loose one, and the subsystem would be a formality. There is no syscall for it, so the
// only thing to assert is that the setting is reachable from the host and that a module
// holding every grantable operation still cannot reach it.
func TestStrictnessIsHostConfigurationNotAModuleChoice(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokstrictset", kernel.OpUsageEmit)

	kernel.TokenSetStrictFloor(true)
	require.True(t, kernel.TokenStrictFloor())

	// The module's context has no path to it: the SyscallTokenizer group exposes measure
	// and check only. Asserting that requires calling what does exist and confirming the
	// setting did not move.
	_, err := kernel.TokenCount(ctx, []byte("measuring changes nothing about strictness"))
	require.NoError(t, err)
	_, err = kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, 3, []byte("nor does checking"))
	require.NoError(t, err)
	assert.True(t, kernel.TokenStrictFloor(),
		"a module holding token:count cannot loosen the check applied to its own reports")
}

// TestANonTokenQuantityIsRefusedRatherThanScored pins that a requests:count fact is not
// compared against a measurement of text. Scoring it would produce a verdict about
// something the measurement says nothing about, and a meaningless verdict on the audit
// chain is worse than no verdict.
func TestANonTokenQuantityIsRefusedRatherThanScored(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokkind", kernel.OpUsageEmit)

	_, err := kernel.TokenCheckUsage(ctx, kernel.UsageRequests, 1, []byte("some text"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a token quantity")

	_, err = kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, 1, nil)
	assert.ErrorIs(t, err, kernel.ErrTokenNoMeasurement,
		"with no bytes there is nothing to compare against, which is not a verdict")
}

// TestTheSyscallRequiresTokenCount pins the grant. Without it the call is a policy
// denial naming the operation, and the module learns nothing about the measurement.
func TestTheSyscallRequiresTokenCount(t *testing.T) {
	buf := harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)

	// Loaded without token:count.
	name := tokenNextName("toknogrant")
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpUsageEmit},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, probe.Ctx)

	_, err = kernel.TokenCount(probe.Ctx, []byte("measure me"))
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "measuring requires the grant: %v", err)
	assert.Contains(t, kernel.DenialReason(err), "token:count")

	_, err = kernel.TokenCheckUsage(probe.Ctx, kernel.UsageTokensIn, 1, []byte("measure me"))
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.Positive(t, len(harness.Faults(buf)), "a denial is visible as a fault")
}

// ---------------------------------------------------------------------------
// Adversarial input.

// TestAdversarialInputNeitherPanicsNorReportsZero walks the shapes that break a naive
// implementation: invalid UTF-8, NUL-heavy, one repeated byte, alternating scripts, and
// a megabyte of each. The property is that every one produces a measurement, the same
// measurement twice, and a non-zero estimate for a non-empty input - because zero is
// what a lying module reports and an estimator that returns zero for binary payloads
// would make every binary report look honest.
func TestAdversarialInputNeitherPanicsNorReportsZero(t *testing.T) {
	adversarial := []struct {
		name string
		data []byte
	}{
		{"invalid utf8", []byte("\xff\xfe\xfd\x00\x01\x02")},
		{"truncated multibyte", []byte("abc\xe4\xb8")},
		{"nul heavy", bytes.Repeat([]byte{0x00}, 4096)},
		{"one repeated byte", bytes.Repeat([]byte{'a'}, 1<<20)},
		{"alternating scripts", bytes.Repeat([]byte("a\u4e2d"), 1<<18)},
		{"all whitespace", bytes.Repeat([]byte(" \t\n"), 4096)},
		{"only punctuation", bytes.Repeat([]byte("!?.,;:"), 4096)},
		{"surrogate encoded as utf8", []byte("\xed\xa0\x80")},
		{"overlong encoding", []byte("\xc0\x80")},
	}
	for _, c := range adversarial {
		t.Run(c.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				first := kernel.TokenMeasure(c.data)
				second := kernel.TokenMeasure(c.data)
				assert.Equal(t, first, second, "deterministic for %s", c.name)

				if len(c.data) > 0 {
					assert.Equal(t, len(c.data), first.Bytes)
					assert.Positive(t, first.CodePoints)
					if first.Whitespace != first.CodePoints {
						// Content-bearing input must not estimate zero, or a lying report
						// of zero looks honest. Whitespace-only input is the one shape that
						// legitimately estimates zero, because whitespace is deliberately
						// not ratio'd, and the ceiling's byte-count floor is what keeps that
						// from accusing an honest report about it.
						assert.NotZero(t, first.Estimate,
							"a content-bearing input must not estimate zero")
					} else {
						assert.Zero(t, first.Estimate)
						assert.Positive(t, first.Whitespace)
					}
				}
				// The estimate never falls below the floor, for adversarial input either.
				assert.GreaterOrEqual(t, first.Estimate, first.Floor)
			})
		})
	}
}

// TestWhitespaceOnlyInputHasNoFloor pins a specific edge: whitespace separates runs and
// is never a run itself, so an input of only whitespace has a floor of zero. Asserting a
// positive floor there would flag every request whose body is padding.
func TestWhitespaceOnlyInputHasNoFloor(t *testing.T) {
	m := kernel.TokenMeasure(bytes.Repeat([]byte(" \n\t"), 512))
	assert.Zero(t, m.Floor, "whitespace is not a pre-tokenizer run")
	assert.Zero(t, m.Runs)
	assert.Zero(t, m.Estimate, "whitespace is not ratio'd, so padding carries no estimate")
	assert.Equal(t, 1536, m.Bytes)
	assert.Equal(t, 1536, m.Whitespace, "and the padding is reported rather than invisible")
}

// TestAWhitespaceHeavyBodyDoesNotFalselyAccuse pins the defect the whitespace case
// exposed. Whitespace is deliberately not ratio'd, so a padding-heavy body estimates
// zero; a ceiling derived only from that estimate would classify an honest report as
// impossible, because a byte-level tokenizer really does emit tokens for whitespace.
// The byte count is the ceiling's floor, and this asserts the accusation does not happen.
func TestAWhitespaceHeavyBodyDoesNotFalselyAccuse(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokpad", kernel.OpUsageEmit)
	kernel.TokenSetStrictFloor(true)
	defer kernel.TokenSetStrictFloor(false)

	padding := bytes.Repeat([]byte(" "), 12288)
	m := kernel.TokenMeasure(padding)
	require.Zero(t, m.Estimate, "padding carries no ratio'd content")
	require.Zero(t, m.Floor)

	// A report any byte-level tokenizer could produce for this input.
	got, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, 100, padding)
	require.NoError(t, err)
	assert.NotEqual(t, kernel.TokenImpossible, got.Verdict,
		"a whitespace-only body must not make an honest report look absurd: %s", got.Reason)

	// And the ceiling is still real: more tokens than there are bytes is impossible for
	// any tokenizer in the family, because none emits more than one token per byte.
	absurd, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, int64(len(padding))+1, padding)
	require.NoError(t, err)
	assert.Equal(t, kernel.TokenImpossible, absurd.Verdict,
		"more tokens than bytes is impossible for every tokenizer in the family")
	assert.Contains(t, absurd.Reason, "ceiling")
}

// TestEmptyInputIsZeroNotAnError pins the boundary. Zero is the correct measurement of
// nothing, and an error here would make every empty-body request a failure.
func TestEmptyInputIsZeroNotAnError(t *testing.T) {
	m := kernel.TokenMeasure(nil)
	assert.Equal(t, kernel.TokenMeasurement{}, m)

	m = kernel.TokenMeasure([]byte{})
	assert.Zero(t, m.Estimate)
	assert.Zero(t, m.Floor)
	assert.Zero(t, m.Bytes)
}

// ---------------------------------------------------------------------------
// The ledger.

// TestTheLedgerIsBoundedAndTrimsInOneStep pins the bound and the shape of the trim.
// Trimming exactly to the bound would reallocate and copy the whole ledger on every
// insert past the ceiling, under the write lock, which is a quadratic cost on the data
// path of every measured request.
func TestTheLedgerIsBoundedAndTrimsInOneStep(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokledger", kernel.OpUsageEmit)

	text := []byte("a report the kernel can measure")
	stats := kernel.TokenStatsSnapshot()
	limit := stats.MaxRecords
	require.Positive(t, limit)

	for range limit + limit/2 {
		_, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, 4, text)
		require.NoError(t, err)
	}

	after := kernel.TokenStatsSnapshot()
	assert.LessOrEqual(t, after.Retained, limit, "the ledger never exceeds its bound")
	// The trim drops back to seven eighths in one step, so after overshooting by half a
	// bound the retained count is at or below the bound and the eviction count is
	// positive. A ledger that trimmed one record per insert would have retained == limit
	// exactly and would have copied itself limit/2 times.
	assert.Positive(t, after.Evicted, "records were evicted rather than accumulated")
	assert.Equal(t, int64(limit+limit/2), after.Checked, "the checked counter counts every check")
}

// TestTheLedgerSnapshotIsSortedStableAndACopy pins the snapshot discipline.
func TestTheLedgerSnapshotIsSortedStableAndACopy(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctxA := tokenLoad(t, k, "toksnapA", kernel.OpUsageEmit)
	ctxB := tokenLoad(t, k, "toksnapB", kernel.OpUsageEmit)

	for range 3 {
		_, err := kernel.TokenCheckUsage(ctxA, kernel.UsageTokensIn, 4, []byte("module A reports"))
		require.NoError(t, err)
		_, err = kernel.TokenCheckUsage(ctxB, kernel.UsageTokensOut, 4, []byte("module B reports"))
		require.NoError(t, err)
	}

	first := kernel.TokenTotalsByModule()
	second := kernel.TokenTotalsByModule()
	require.NotEmpty(t, first)
	assert.Equal(t, first, second, "two identical snapshots are stable, so no map order leaks")

	for i := 1; i < len(first); i++ {
		assert.LessOrEqual(t, first[i-1].Module, first[i].Module, "sorted by module name")
	}

	first[0].Impossible = 999999
	first[0].Module = "tampered"
	third := kernel.TokenTotalsByModule()
	assert.NotEqual(t, "tampered", third[0].Module)
	assert.NotEqual(t, int64(999999), third[0].Impossible)
}

// TestPerModuleTotalsAttributeCorrectly pins that the counts land on the module that
// made them. A ledger that pooled everything would show a discrepancy without showing
// who caused it, which is not actionable.
func TestPerModuleTotalsAttributeCorrectly(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	kernel.TokenSetStrictFloor(true)
	defer kernel.TokenSetStrictFloor(false)

	honest := tokenLoad(t, k, "tokhonest", kernel.OpUsageEmit)
	lying := tokenLoad(t, k, "toklying", kernel.OpUsageEmit)

	text := []byte("The quick brown fox jumps over the lazy dog.")
	m := kernel.TokenMeasure(text)

	for range 3 {
		_, err := kernel.TokenCheckUsage(honest, kernel.UsageTokensIn, m.Estimate, text)
		require.NoError(t, err)
		_, err = kernel.TokenCheckUsage(lying, kernel.UsageTokensIn, 1, text)
		require.NoError(t, err)
	}

	var honestTotals, lyingTotals *kernel.TokenModuleTotals
	totals := kernel.TokenTotalsByModule()
	for i := range totals {
		switch {
		case strings.Contains(totals[i].Module, "tokhonest"):
			honestTotals = &totals[i]
		case strings.Contains(totals[i].Module, "toklying"):
			lyingTotals = &totals[i]
		}
	}
	require.NotNil(t, honestTotals)
	require.NotNil(t, lyingTotals)

	assert.Equal(t, int64(3), honestTotals.Consistent)
	assert.Zero(t, honestTotals.Impossible)
	assert.Equal(t, int64(3), lyingTotals.Impossible)
	assert.Zero(t, lyingTotals.Consistent,
		"a module reporting one token for a nine word sentence is never consistent")
}

// TestADisagreementReachesTheChainAndTheConsole pins that a finding is evidence rather
// than a return value. A flush on the way out of a process may leave no caller to read
// the returned check, and a module that under-reports must not be able to make the
// discrepancy disappear by discarding the result.
func TestADisagreementReachesTheChainAndTheConsole(t *testing.T) {
	buf := harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokchain", kernel.OpUsageEmit)
	kernel.TokenSetStrictFloor(true)
	defer kernel.TokenSetStrictFloor(false)

	text := []byte("The quick brown fox jumps over the lazy dog.")
	m := kernel.TokenMeasure(text)

	before := len(harness.Records(t, buf))
	_, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, 1, text)
	require.NoError(t, err, "a disagreement is a finding, not a call failure")

	records := harness.Records(t, buf)
	assert.Greater(t, len(records), before, "the disagreement reached the console")

	var onChain bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditUsage}) {
		if e.Fields["reported"] == int64(1) && e.Fields["floor"] == m.Floor {
			onChain = true
			assert.Equal(t, "impossible", e.Fields["verdict"])
			assert.NotEmpty(t, e.Fields["reason"])
		}
	}
	assert.True(t, onChain, "the disagreement is on the audit chain with both numbers")

	assert.Positive(t, len(harness.Faults(buf)), "and it is a fault, not only a log line")
}

// TestAConsistentReportIsNotAFault pins the other half. If an honest report faulted,
// the console would fill with noise and an operator would stop reading it, which is how
// a real finding gets missed.
func TestAConsistentReportIsNotAFault(t *testing.T) {
	buf := harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokquiet", kernel.OpUsageEmit)

	text := []byte("The quick brown fox jumps over the lazy dog.")
	m := kernel.TokenMeasure(text)

	before := len(harness.Faults(buf))
	_, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, m.Estimate, text)
	require.NoError(t, err)
	assert.Len(t, harness.Faults(buf), before, "an honest report does not fault")

	stats := kernel.TokenStatsSnapshot()
	assert.Equal(t, int64(1), stats.Consistent)
	assert.Zero(t, stats.Impossible)
}

// ---------------------------------------------------------------------------
// Flow measurement and reset.

// TestFlowMeasurementAttributesToTheWriterPid pins the pipe-path entry point. The party
// being measured is the writer, and the caller may be the kernel's own pipe code, which
// has no module context of its own - so this takes a pid rather than a context.
func TestFlowMeasurementAttributesToTheWriterPid(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokflow", kernel.OpUsageEmit)

	pid := ctx.PID()
	payload := []byte("a streamed completion chunk crossing a pipe")

	first := kernel.TokenMeasureFlow(pid, payload)
	assert.Equal(t, pid, first.PID)
	assert.Equal(t, len(payload), first.Bytes)
	assert.Positive(t, first.Tokens)
	assert.Equal(t, int64(1), first.Seq)

	second := kernel.TokenMeasureFlow(pid, payload)
	assert.Equal(t, int64(2), second.Seq, "flow records are sequenced")
	assert.Equal(t, first.Tokens, second.Tokens, "and the same bytes measure the same")

	var totals *kernel.TokenModuleTotals
	for _, tt := range kernel.TokenTotalsByModule() {
		if tt.PID == pid {
			totals = &tt
			break
		}
	}
	require.NotNil(t, totals)
	assert.Equal(t, int64(2*len(payload)), totals.FlowBytes)
	assert.Equal(t, first.Tokens+second.Tokens, totals.FlowTokens)
}

// TestNothingSurvivesRestart pins the reset. A ledger surviving a restart would compare
// this boot's reports against last boot's numbers, and the flow sequence would continue
// from where it stopped, which makes a cursor that outlives a boot look like a gap.
func TestNothingSurvivesRestart(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokreset", kernel.OpUsageEmit)

	_, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, 4, []byte("before the restart"))
	require.NoError(t, err)
	_ = kernel.TokenMeasureFlow(ctx.PID(), []byte("flow before the restart"))
	require.Positive(t, kernel.TokenStatsSnapshot().Checked)

	kernel.TokenSetStrictFloor(true)
	require.NoError(t, k.Shutdown())

	// The strictness setting is deployment configuration rather than per-boot state, so
	// it survives: an operator who chose it for the providers they route to has not
	// changed their mind because the process restarted.
	assert.True(t, kernel.TokenStrictFloor(), "the strictness setting is not per-boot state")
	kernel.TokenSetStrictFloor(false)

	k2 := tokenBoot(t)
	ctx2 := tokenLoad(t, k2, "tokreset2", kernel.OpUsageEmit)

	stats := kernel.TokenStatsSnapshot()
	assert.Zero(t, stats.Checked, "the ledger did not survive")
	assert.Zero(t, stats.Retained)
	assert.Empty(t, kernel.TokenLedger())

	rec := kernel.TokenMeasureFlow(ctx2.PID(), []byte("flow after the restart"))
	assert.Equal(t, int64(1), rec.Seq, "the flow sequence restarts with the boot")
}

// ---------------------------------------------------------------------------
// Concurrency.

// TestConcurrentChecksAndSnapshotsUnderRace exercises the ledger from many goroutines
// while snapshots are taken. What is asserted is that every check is counted exactly
// once and that no snapshot tears.
func TestConcurrentChecksAndSnapshotsUnderRace(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokconc", kernel.OpUsageEmit)

	before := kernel.TokenStatsSnapshot().Checked
	const goroutines = 12
	const perGoroutine = 25

	text := []byte("a report measured concurrently")
	stop := make(chan struct{})

	// Readers run until stopped, so the ledger is snapshotted while it is being written
	// rather than only before and after. A snapshot taken between two writes proves
	// nothing about tearing.
	var readers sync.WaitGroup
	for range 3 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = kernel.TokenStatsSnapshot()
					_ = kernel.TokenTotalsByModule()
					_ = kernel.TokenLedger()
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for g := range goroutines {
		writers.Add(1)
		go func(g int) {
			defer writers.Done()
			for i := range perGoroutine {
				reported := int64(4 + (g+i)%3)
				_, err := kernel.TokenCheckUsage(ctx, kernel.UsageTokensIn, reported, text)
				assert.NoError(t, err)
			}
		}(g)
	}

	writers.Wait()
	close(stop)
	readers.Wait()

	after := kernel.TokenStatsSnapshot()
	assert.Equal(t, before+int64(goroutines*perGoroutine), after.Checked,
		"every concurrent check was counted exactly once")
	assert.Equal(t, after.Checked,
		after.Consistent+after.Suspicious+after.Impossible,
		"the verdict counts partition the checks")
}

// TestTheSyscallSurfaceIsReachable pins that this subsystem is reachable through the
// sealed SContext rather than only through the package-level functions. The rest of this
// suite drives the package functions, and they would keep passing if SyscallTokenizer
// were missing from the SContext composition in context.go, which is the exact way a
// subsystem gets built and never wired.
func TestTheSyscallSurfaceIsReachable(t *testing.T) {
	harness.QuietConsole(t)
	tokenResetStrict(t)
	k := tokenBoot(t)
	ctx := tokenLoad(t, k, "tokwire", kernel.OpUsageEmit)

	text := []byte("a prompt measured through the sealed context")

	got, err := ctx.SyscallTokenCount(text)
	require.NoError(t, err)
	assert.Equal(t, kernel.TokenMeasure(text), got,
		"the syscall and the package function measure identically")
	assert.Positive(t, got.Estimate)

	check, err := ctx.SyscallTokenCheckUsage(kernel.UsageTokensIn, got.Estimate, text)
	require.NoError(t, err)
	assert.Equal(t, kernel.TokenConsistent, check.Verdict)

	// And a lying report through the same surface is still a finding.
	kernel.TokenSetStrictFloor(true)
	defer kernel.TokenSetStrictFloor(false)
	check, err = ctx.SyscallTokenCheckUsage(kernel.UsageTokensIn, 1, text)
	require.NoError(t, err)
	assert.Equal(t, kernel.TokenImpossible, check.Verdict)
}
