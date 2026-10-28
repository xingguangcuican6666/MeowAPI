package kernel

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"unicode"
	"unicode/utf8"
)

// ktokenizer: deterministic in-kernel token accounting (subsystem: ktokenizer).
//
// What it is for. A module calls SyscallUsageEmit with a quantity it chose. usage.go
// caps that quantity per event, which stops an absurd number but not a dishonest
// plausible one. A channel module fronting a provider sees the real traffic and
// reports what it likes: under-reporting costs the operator revenue, over-reporting
// against a metered customer is theft the other way, and a malicious mesh node can
// inflate a signed receipt's token count, which kreceipt will then sign because the
// receipt layer trusts the number it was handed. The kernel is the only party that
// sees the bytes without a motive to misdescribe them, so the kernel measures them.
//
// What it does NOT do, stated first because the alternative is a lie in the API. The
// kernel cannot know a provider's real tokenizer. Every provider uses its own BPE
// vocabulary and shipping one is a multi-megabyte data file this project does not
// have. So there is no CountBPE here and nothing in this file claims an exact count.
// What it produces is:
//
//   - Estimate: a deterministic, documented, reproducible approximation, computed
//     with integer arithmetic over character classes. Same bytes in, same number out,
//     on every platform and every run.
//   - Floor: a structural lower bound that no honest tokenizer of the family every
//     major provider uses can come in under. See TokenMeasurement.Floor for the exact
//     assumption this rests on, because it is conditional and the condition matters.
//
// An estimate the operator knows is an estimate is still a strong fraud signal: a
// module reporting ten times the kernel's estimate is lying regardless of which
// tokenizer is right. The floor is the sharper instrument, since a report below it is
// provably wrong rather than merely different - which is why it is stated with its
// assumption attached instead of being asserted unconditionally.
//
// Nothing here silently replaces a module's reported number. The report and the
// measurement are two facts, both are recorded, and the discrepancy between them is
// the signal; erasing either half destroys it. The estimate never becomes the billable
// number by default, and there is no code path in this file that makes it one.

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

// tokenEstimateModel is the estimation model, as integer ratios. Every ratio is a
// (dividend, divisor) pair so the arithmetic stays in integers; a float ratio would
// make the result depend on rounding that a reader cannot predict from the source.
//
// The classes and their ratios, with the reasoning for each:
//
//	ASCII letters, digits and punctuation   4 chars per token.
//	  This is the ratio the GPT-2 family converges to on English prose and on code,
//	  and it is the one class where a single ratio is genuinely representative.
//	Non-ASCII letters, including CJK        1 char per token.
//	  Deliberately conservative in both directions: Latin-1 accented letters often
//	  merge into one token, so this over-estimates them slightly, while Cyrillic and
//	  Greek cost two to three tokens per character in the GPT-2 family, so this
//	  under-estimates them. CJK is close to one token per character. A single ratio
//	  for "not ASCII" is coarse and is documented as coarse rather than pretending to
//	  per-script precision the model does not have.
//	Invalid UTF-8 bytes                     3 bytes per token.
//	  A byte-level BPE emits at least one token per byte and merges some, so this sits
//	  below the worst case. Base64 and binary payloads land here or in the ASCII class
//	  depending on whether they decode, and both are covered.
//	Whitespace                              not ratio'd at all.
//	  A space attaches to the token that follows it in this family rather than becoming
//	  one, so charging for it would inflate every prose estimate and make a body of
//	  nothing but padding look like content. Whitespace still shapes the result, through
//	  the run count the floor is derived from.
//
// The ratio part of the estimate is the sum of ceil(count/divisor) over the classes.
// Rounding up per class rather than once at the end means a short input never estimates
// zero, which matters because zero is what a lying module would report.
//
// The reported Estimate is then max(ratio, Floor). The floor is computed from the same
// bytes and is a structural minimum for the assumed tokenizer family, so an estimate
// below it would be the function contradicting itself; punctuation-dense input is where
// that happens, because four characters per token is a prose ratio and JSON is not
// prose.
const (
	tokenASCIICharsPerToken = 4
	tokenNonASCIIPerToken   = 1 // one token per character
	tokenInvalidBytesPer    = 3
)

// tokenAbsurdMultiple and tokenAbsurdSlack define the multiple-of-estimate part of the
// ceiling above which a report is classified impossible rather than merely suspicious.
// The slack exists so that a tiny input - where the estimate is 1 and any multiple of it
// is noise - does not produce a ceiling of 8 and accuse an honest module reporting 12.
// The ceiling also has a byte-count floor, applied in tokenClassify, because an estimate
// of zero would otherwise make any positive report absurd.
const (
	tokenAbsurdMultiple = 8
	tokenAbsurdSlack    = 64
)

// tokenSuspiciousMultiple is the ratio above which, or below which, a report is
// suspicious rather than consistent. Two is deliberately wide: the estimate is coarse
// by construction, so a tighter band would generate noise on honest traffic and train
// an operator to ignore the classification.
const tokenSuspiciousMultiple = 2

// TokenVerdict is the kernel's opinion about one reported quantity.
type TokenVerdict int

const (
	// TokenConsistent means the report is within tolerance of the measurement.
	TokenConsistent TokenVerdict = iota
	// TokenSuspicious means the report differs from the measurement by more than the
	// tolerance allows but is still arithmetically possible. It is a signal to look
	// at, not proof of anything.
	TokenSuspicious
	// TokenImpossible means the report cannot be produced by an honest tokenizer:
	// below the structural floor, above the absurd ceiling, or not positive.
	TokenImpossible
)

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

// ErrTokenNoMeasurement is what a check returns when there was no input to measure.
// It is not a verdict: without bytes there is nothing to compare against, and calling
// that impossible would accuse a module of lying about a request that carried no body.
var ErrTokenNoMeasurement = errors.New("kernel: tokenizer: nothing was measured")

// tokenState holds the bounded ledger of checks. It records what the kernel measured
// and what was reported, so an investigation can join the two after the fact rather
// than depending on a module's own logs.
type tokenState struct {
	mu      sync.Mutex
	records []TokenCheckRecord
	byPid   map[PID]*tokenPidTotals
	checked int64
	flowSeq int64

	consistent int64
	suspicious int64
	impossible int64
	evicted    int64

	// strictFloor records the deployment's choice about the tokenizer-family
	// assumption the floor rests on. It is host-set and never module-set.
	strictFloor bool
}

// tokenPidTotals is one module's running counts.
type tokenPidTotals struct {
	Checked    int64 `json:"checked"`
	Consistent int64 `json:"consistent"`
	Suspicious int64 `json:"suspicious"`
	Impossible int64 `json:"impossible"`
	// Measured counts bare measurements, which record no finding about anybody.
	Measured int64 `json:"measured"`
	// FlowBytes and FlowTokens are what crossed this module's pipes. They are the
	// independent half of the comparison: a usage report is a claim, and these are
	// what the kernel itself saw.
	FlowBytes  int64 `json:"flow_bytes"`
	FlowTokens int64 `json:"flow_tokens"`
}

// maxTokenChecks bounds the retained ledger. It is a kernel constant rather than a
// caller-supplied one, because a bound the measured party can raise is not a bound.
const maxTokenChecks = 2048

var ktokenizer = tokenState{byPid: map[PID]*tokenPidTotals{}}

// TokenMeasure computes a measurement over one byte slice. It is a pure function: it
// touches no kernel state, retains no reference to the input, and returns the same
// numbers for the same bytes every time.
//
// It needs no grant, because measuring bytes the caller already holds grants nothing.
// The syscalls below are the ones that need token:count, because they write to the
// ledger and can produce a finding about a module.
func TokenMeasure(data []byte) TokenMeasurement {
	var m TokenMeasurement
	m.Bytes = len(data)
	if len(data) == 0 {
		return m
	}

	var ascii, nonASCII, invalid, space int
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			// One byte that does not decode. Counted as one code point so the
			// arithmetic stays exact, and as invalid so the shape of the input is
			// visible rather than folded into a letter count.
			invalid++
			m.CodePoints++
			i++
		case unicode.IsSpace(r):
			// Whitespace is counted but not ratio'd. In this tokenizer family a space
			// attaches to the token that follows it rather than becoming one, so
			// charging four characters per token for it inflates the estimate on
			// padding-heavy input and makes a body of nothing but whitespace look like
			// it carries content. The floor already handles the structure whitespace
			// creates, by separating runs.
			space++
			m.CodePoints++
			i += size
		case r < utf8.RuneSelf:
			ascii++
			m.CodePoints++
			i += size
		default:
			nonASCII++
			m.CodePoints++
			i += size
		}
	}
	m.Invalid = invalid
	m.Whitespace = space

	m.Runs = tokenRuns(data)
	m.Floor = int64(m.Runs)

	// The ratio estimate, per class, rounded up per class. Integer division with the
	// remainder handled explicitly: no float, so no rounding that differs between
	// platforms or between runs.
	ratio := tokenCeilDiv(ascii, tokenASCIICharsPerToken) +
		int64(nonASCII)*int64(tokenNonASCIIPerToken) +
		tokenCeilDiv(invalid, tokenInvalidBytesPer)

	// The estimate is the larger of the ratio and the structural floor, and the reason
	// is that the ratio is a prose heuristic while the floor is a fact about this
	// input's structure. Four characters per token describes English prose and code
	// identifiers; it does not describe punctuation-dense input, where every class
	// change is a separate pre-token and a real tokenizer produces more tokens per byte
	// than prose does. Measured against JSON, the ratio alone came out below the floor
	// the same function had just computed, which is an internally inconsistent answer:
	// no estimate can be smaller than a proven minimum for the family it assumes.
	//
	// Taking the maximum keeps the estimate usable as an estimate rather than making it
	// a second floor. Where the ratio is the larger number - prose, CJK, binary - the
	// behaviour is unchanged.
	if ratio > m.Floor {
		m.Estimate = ratio
	} else {
		m.Estimate = m.Floor
	}
	return m
}

// tokenCeilDiv divides and rounds up without a float.
func tokenCeilDiv(n, d int) int64 {
	if n <= 0 {
		return 0
	}
	return int64((n + d - 1) / d)
}

// tokenRuns counts the pre-tokenizer runs the floor is derived from.
//
// The rule is the one the GPT-2 family regex implements, expressed as a scan: split on
// whitespace, then within each non-whitespace segment count maximal runs of one
// character class, where the classes are letter, digit and other. A token in that
// family cannot span a whitespace boundary and cannot span a class change, so each run
// costs at least one token and the run count is a lower bound on the token count.
//
// Walking the boundaries rather than the whole input twice is what keeps this linear
// and allocation-free, which matters because this runs on the data path of every
// measured request.
func tokenRuns(data []byte) int {
	runs := 0
	prev := tokenClassNone
	inWord := false

	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		i += size

		var class tokenClass
		switch {
		case r == utf8.RuneError && size <= 1:
			class = tokenClassOther
		case unicode.IsSpace(r):
			class = tokenClassSpace
		case unicode.IsLetter(r):
			class = tokenClassLetter
		case unicode.IsDigit(r):
			class = tokenClassDigit
		default:
			class = tokenClassOther
		}

		if class == tokenClassSpace {
			// Whitespace ends a run. It is not counted as a run of its own, because in
			// this tokenizer family a space is attached to the token that follows it
			// rather than becoming one, and counting it would overstate the floor -
			// which would turn an honest module into an accused one.
			inWord = false
			prev = tokenClassNone
			continue
		}
		if !inWord || class != prev {
			runs++
			inWord = true
		}
		prev = class
	}
	return runs
}

type tokenClass int

const (
	tokenClassNone tokenClass = iota
	tokenClassSpace
	tokenClassLetter
	tokenClassDigit
	tokenClassOther
)

// TokenSetStrictFloor records the deployment's choice about the floor's assumption.
//
// The floor is a lower bound for tokenizers whose pre-tokenizer does not merge across
// whitespace or across a class change. Every major provider's tokenizer is in that
// family. A deployment that routes to something else - a SentencePiece unigram model
// is the realistic case - can merge across those boundaries in principle, so treating
// a report below the floor as impossible would accuse an honest module.
//
// Strict is the setting that classifies below-floor as impossible. Non-strict, the
// default, classifies it as suspicious instead: still recorded, still faulted, still
// on the chain, but not asserted to be a fact the kernel cannot prove. The default is
// the conservative one because a false accusation of fraud is worse than a flagged
// anomaly, and it is the operator who knows which providers are in play.
//
// It is host-set. There is no syscall for it, and a module that could choose the
// strictness of the check applied to its own reports could simply choose the loose
// one.
func TokenSetStrictFloor(strict bool) {
	ktokenizer.mu.Lock()
	defer ktokenizer.mu.Unlock()
	ktokenizer.strictFloor = strict
}

// TokenStrictFloor reports the current setting.
func TokenStrictFloor() bool {
	ktokenizer.mu.Lock()
	defer ktokenizer.mu.Unlock()
	return ktokenizer.strictFloor
}

// TokenCheckUsage compares one reported quantity against a measurement of the bytes
// that produced it. Requires token:count.
//
// The kind matters: only token quantities are comparable against a measurement of
// text. A requests:count fact has no bytes to measure, and classifying it against a
// token floor would be meaningless, so it is refused rather than scored.
func TokenCheckUsage(ctx SContext, kind UsageKind, reported int64, data []byte) (TokenCheck, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return TokenCheck{}, errForeignContext
	}
	if err := c.syscall(OpTokenCount); err != nil {
		return TokenCheck{}, err
	}
	if len(data) == 0 {
		return TokenCheck{}, ErrTokenNoMeasurement
	}
	if kind != UsageTokensIn && kind != UsageTokensOut {
		return TokenCheck{}, fmt.Errorf(
			"kernel: tokenizer: %q is not a token quantity and cannot be compared against measured text", kind)
	}

	m := TokenMeasure(data)
	check := tokenClassify(m, reported, TokenStrictFloor())
	tokenRecord(c, kind, check)
	return check, nil
}

// tokenClassify is the decision, separated from the syscall so it can be tested
// directly against a measurement without booting a kernel.
func tokenClassify(m TokenMeasurement, reported int64, strict bool) TokenCheck {
	out := TokenCheck{Measurement: m, Reported: reported}

	switch {
	case reported <= 0:
		out.Verdict = TokenImpossible
		out.Reason = fmt.Sprintf("a served request consumed something; %d cannot be a token count", reported)

	case reported < m.Floor:
		// The one classification that rests on the tokenizer-family assumption, so it
		// is the one that follows the deployment's choice.
		if strict {
			out.Verdict = TokenImpossible
			out.Reason = fmt.Sprintf(
				"%d is below the structural floor %d: no tokenizer in the assumed family can produce it from %d bytes",
				reported, m.Floor, m.Bytes)
		} else {
			out.Verdict = TokenSuspicious
			out.Reason = fmt.Sprintf(
				"%d is below the structural floor %d, which is impossible for the assumed tokenizer family but not proven for every one",
				reported, m.Floor)
		}

	default:
		// The ceiling is the larger of a multiple of the estimate and the byte count,
		// and the second term is what makes it safe to accuse anybody. No tokenizer in
		// the assumed family emits more tokens than there are bytes: a byte-level BPE's
		// worst case is one token per byte, and every other class merges. Deriving the
		// ceiling from the estimate alone would falsely accuse a whitespace-heavy body,
		// because whitespace is deliberately not ratio'd and so a padding-only input
		// estimates zero - and a ceiling of zero times anything plus slack is a number
		// an honest report can exceed.
		ceiling := m.Estimate*tokenAbsurdMultiple + tokenAbsurdSlack
		if bytes := int64(m.Bytes); bytes > ceiling {
			ceiling = bytes
		}
		switch {
		case reported > ceiling:
			out.Verdict = TokenImpossible
			out.Reason = fmt.Sprintf("%d exceeds the absurd ceiling %d for a %d-byte input estimated at %d",
				reported, ceiling, m.Bytes, m.Estimate)
		case reported > m.Estimate*tokenSuspiciousMultiple+tokenAbsurdSlack:
			out.Verdict = TokenSuspicious
			out.Reason = fmt.Sprintf("%d is more than %dx the estimate %d",
				reported, tokenSuspiciousMultiple, m.Estimate)
		case m.Estimate > tokenSuspiciousMultiple*tokenAbsurdSlack &&
			reported*tokenSuspiciousMultiple < m.Estimate:
			out.Verdict = TokenSuspicious
			out.Reason = fmt.Sprintf("%d is less than a %dx fraction of the estimate %d",
				reported, tokenSuspiciousMultiple, m.Estimate)
		default:
			out.Verdict = TokenConsistent
			out.Reason = fmt.Sprintf("%d is within tolerance of the estimate %d and at or above the floor %d",
				reported, m.Estimate, m.Floor)
		}
	}
	return out
}

// TokenCheckRecord is one entry in the ledger. It holds the reported number and the
// measurement side by side, which is the point: a ledger that kept only the verdict
// would let nobody re-derive it, and a ledger that kept only the report would be the
// module's own claim with the kernel as a notary.
type TokenCheckRecord struct {
	Seq    int64      `json:"seq"`
	PID    PID        `json:"pid"`
	Module string     `json:"module,omitempty"`
	Kind   UsageKind  `json:"kind"`
	At     int64      `json:"at"`
	Check  TokenCheck `json:"check"`
}

// tokenRecord writes one check to the ledger, faults on anything that is not
// consistent, and puts a disagreement on the audit chain.
func tokenRecord(c *sContext, kind UsageKind, check TokenCheck) {
	ktokenizer.mu.Lock()
	ktokenizer.checked++
	seq := ktokenizer.checked
	tot := ktokenizer.byPid[c.pid]
	if tot == nil {
		tot = &tokenPidTotals{}
		ktokenizer.byPid[c.pid] = tot
	}
	tot.Checked++
	switch check.Verdict {
	case TokenConsistent:
		ktokenizer.consistent++
		tot.Consistent++
	case TokenSuspicious:
		ktokenizer.suspicious++
		tot.Suspicious++
	case TokenImpossible:
		ktokenizer.impossible++
		tot.Impossible++
	}
	ktokenizer.records = append(ktokenizer.records, TokenCheckRecord{
		Seq: seq, PID: c.pid, Module: c.name, Kind: kind, At: mono(), Check: check,
	})
	// Trim after the insert, the way kmeter's ledger does. Trimming before it cannot
	// work: at exactly the bound the ledger is still within it, so the trim is a no-op
	// and the insert takes it one past the ceiling on every check afterwards.
	ktokenizer.trimLocked()
	ktokenizer.mu.Unlock()

	if check.Verdict == TokenConsistent {
		return
	}
	// A disagreement is escalated rather than merely logged, because it is a claim
	// about a module's honesty and an operator needs it on the chain where the module
	// cannot edit it.
	fault(c, "token report disagrees with the kernel's measurement", map[string]any{
		"module": c.name, "kind": string(kind), "reported": check.Reported,
		"estimate": check.Measurement.Estimate, "floor": check.Measurement.Floor,
		"verdict": check.Verdict.String(), "reason": check.Reason,
	})
	kaudit.record(AuditUsage, c, "token report "+check.Verdict.String(), map[string]any{
		"module": c.name, "kind": string(kind), "verdict": check.Verdict.String(),
		"reported": check.Reported,
		"estimate": check.Measurement.Estimate, "floor": check.Measurement.Floor,
		"bytes": check.Measurement.Bytes, "reason": check.Reason,
	})
}

// trimLocked keeps the ledger at its bound, dropping back to seven eighths of it in
// ONE step. Caller holds ktokenizer.mu.
//
// Trimming exactly to the bound would reallocate and copy the whole ledger on every
// insert past the ceiling, under the write lock, which is a quadratic cost on the hot
// path of every measured request. Dropping an eighth at a time amortises it, and it is
// what kmeter does for the same reason.
func (s *tokenState) trimLocked() {
	if len(s.records) <= maxTokenChecks {
		return
	}
	keep := maxTokenChecks - maxTokenChecks/8
	if len(s.records) <= keep {
		return
	}
	over := len(s.records) - keep
	s.evicted += int64(over)
	s.records = append([]TokenCheckRecord(nil), s.records[over:]...)
}

// TokenStats is the ledger's totals.
type TokenStats struct {
	Checked     int64 `json:"checked"`
	Consistent  int64 `json:"consistent"`
	Suspicious  int64 `json:"suspicious"`
	Impossible  int64 `json:"impossible"`
	Retained    int   `json:"retained"`
	Evicted     int64 `json:"evicted"`
	MaxRecords  int   `json:"max_records"`
	StrictFloor bool  `json:"strict_floor"`
}

// TokenStatsSnapshot returns the totals. Counters only, so it is cheap enough to call
// on a status path.
func TokenStatsSnapshot() TokenStats {
	ktokenizer.mu.Lock()
	defer ktokenizer.mu.Unlock()
	return TokenStats{
		Checked: ktokenizer.checked, Consistent: ktokenizer.consistent,
		Suspicious: ktokenizer.suspicious, Impossible: ktokenizer.impossible,
		Retained: len(ktokenizer.records), Evicted: ktokenizer.evicted,
		MaxRecords: maxTokenChecks, StrictFloor: ktokenizer.strictFloor,
	}
}

// TokenTotalsByModule reports per-module counts, sorted by module name. It is a copy:
// mutating the result cannot reach kernel state, which is the same discipline every
// other snapshot in this kernel follows.
func TokenTotalsByModule() []TokenModuleTotals { return tokenTotals() }

// tokenTotals is the unlocked body of TokenTotalsByModule. Reading the process table
// while holding the ledger lock would fix a lock order across two subsystems for no
// benefit, so the name lookup happens first and the ledger second.
func tokenTotals() []TokenModuleTotals {
	// The process table is read before the ledger lock is taken. Its records are
	// append-only and only the kernel writes state into them, so a pid that has
	// terminated still has a name here, which is what makes a finding about a module
	// that is already gone still readable.
	names := map[PID]string{}
	for _, r := range ProcTable() {
		names[r.PID] = r.Name
	}

	ktokenizer.mu.Lock()
	defer ktokenizer.mu.Unlock()
	out := make([]TokenModuleTotals, 0, len(ktokenizer.byPid))
	for pid, tot := range ktokenizer.byPid {
		out = append(out, TokenModuleTotals{
			PID: pid, Module: names[pid], Checked: tot.Checked, Consistent: tot.Consistent,
			Suspicious: tot.Suspicious, Impossible: tot.Impossible,
			Measured: tot.Measured, FlowBytes: tot.FlowBytes, FlowTokens: tot.FlowTokens,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].PID < out[j].PID
	})
	return out
}

// TokenModuleTotals is one module's running counts, for a snapshot.
type TokenModuleTotals struct {
	PID        PID    `json:"pid"`
	Module     string `json:"module,omitempty"`
	Checked    int64  `json:"checked"`
	Consistent int64  `json:"consistent"`
	Suspicious int64  `json:"suspicious"`
	Impossible int64  `json:"impossible"`
	Measured   int64  `json:"measured"`
	FlowBytes  int64  `json:"flow_bytes"`
	FlowTokens int64  `json:"flow_tokens"`
}

// TokenLedger returns retained checks, most recent last, as copies.
func TokenLedger() []TokenCheckRecord {
	ktokenizer.mu.Lock()
	defer ktokenizer.mu.Unlock()
	return append([]TokenCheckRecord(nil), ktokenizer.records...)
}

// resetTokenizer clears the ledger for a fresh boot. It does not clear the strictness
// setting, because that is deployment configuration rather than per-boot state: an
// operator who chose non-strict for the providers they route to has not changed their
// mind because the process restarted.
func resetTokenizer() {
	ktokenizer.mu.Lock()
	defer ktokenizer.mu.Unlock()
	ktokenizer.records = nil
	ktokenizer.byPid = map[PID]*tokenPidTotals{}
	ktokenizer.checked = 0
	ktokenizer.consistent = 0
	ktokenizer.suspicious = 0
	ktokenizer.impossible = 0
	ktokenizer.evicted = 0
	ktokenizer.flowSeq = 0
}

// ---------------------------------------------------------------------------
// Flow measurement.
//
// The owner's specification puts accounting where the data flows, which in this kernel
// is kpipe. This file cannot edit pipe.go, so TokenMeasureFlow is the entry point and
// the wiring is reported at the bottom of this file.
//
// It is deliberately separate from TokenCheckUsage: measuring a flow records no
// finding about anybody, because a pipe write is not a usage claim. It exists so the
// kernel has a measurement of what actually crossed, which is the number a later
// usage report can be compared against rather than the number a module asserts about
// bytes the kernel never saw.

// TokenFlowRecord is one measured flow crossing.
type TokenFlowRecord struct {
	PID    PID   `json:"pid"`
	Seq    int64 `json:"seq"`
	At     int64 `json:"at"`
	Bytes  int   `json:"bytes"`
	Tokens int64 `json:"tokens"`
	Floor  int64 `json:"floor"`
}

// TokenMeasureFlow measures bytes crossing a pipe and attributes the measurement to a
// pid. It takes a pid rather than a context because the party being measured is the
// writer and the caller may be the kernel's own pipe code, which has no module context
// of its own.
func TokenMeasureFlow(pid PID, data []byte) TokenFlowRecord {
	m := TokenMeasure(data)
	rec := TokenFlowRecord{
		PID: pid, At: mono(), Bytes: m.Bytes, Tokens: m.Estimate, Floor: m.Floor,
	}
	ktokenizer.mu.Lock()
	ktokenizer.flowSeq++
	rec.Seq = ktokenizer.flowSeq
	tot := ktokenizer.byPid[pid]
	if tot == nil {
		tot = &tokenPidTotals{}
		ktokenizer.byPid[pid] = tot
	}
	tot.FlowBytes += int64(m.Bytes)
	tot.FlowTokens += m.Estimate
	ktokenizer.mu.Unlock()
	return rec
}

// ---------------------------------------------------------------------------
// Syscall surface.

// SyscallTokenizer is the module-facing half of this surface. It is read-and-report
// only: there is no way for a module to set the strictness of the check applied to its
// own reports, and no way for it to overwrite a measurement.
type SyscallTokenizer interface {
	// SyscallTokenCount measures bytes the caller already holds. Requires token:count.
	SyscallTokenCount(data []byte) (TokenMeasurement, error)
	// SyscallTokenCheckUsage compares a reported token quantity against a measurement
	// of the bytes that produced it. Requires token:count.
	SyscallTokenCheckUsage(kind UsageKind, reported int64, data []byte) (TokenCheck, error)
}

func (c *sContext) SyscallTokenCount(data []byte) (TokenMeasurement, error) {
	return TokenCount(c, data)
}

func (c *sContext) SyscallTokenCheckUsage(kind UsageKind, reported int64, data []byte) (TokenCheck, error) {
	return TokenCheckUsage(c, kind, reported, data)
}

// TokenCount measures bytes and records the measurement against the caller's ledger.
// Requires token:count, because it writes kernel state and a module that could measure
// without limit could grow the ledger.
func TokenCount(ctx SContext, data []byte) (TokenMeasurement, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return TokenMeasurement{}, errForeignContext
	}
	if err := c.syscall(OpTokenCount); err != nil {
		return TokenMeasurement{}, err
	}
	m := TokenMeasure(data)
	ktokenizer.mu.Lock()
	ktokenizer.checked++
	tot := ktokenizer.byPid[c.pid]
	if tot == nil {
		tot = &tokenPidTotals{}
		ktokenizer.byPid[c.pid] = tot
	}
	tot.Measured++
	ktokenizer.trimLocked()
	ktokenizer.mu.Unlock()
	return m, nil
}

// ---------------------------------------------------------------------------
// INTEGRATION. Nothing below is wired except resetTokenizer, which resetKernel calls.
//
// 1. context.go: SyscallTokenizer joins the SContext composition.
//
// 2. pipe.go, in the write path. SyscallPipeWrite currently reads:
//
//	func (c *sContext) SyscallPipeWrite(fd FD, data []byte, deadline int64) (int, error) {
//		if err := c.syscall(OpPipeWrite); err != nil {
//			return 0, err
//		}
//
//    The measurement belongs after the bytes have actually been accepted by the pipe
//    rather than before, so a refused write is not measured as though it crossed:
//
//	n, err := pipeWrite(c, fd, data, deadline)
//	if err == nil && n > 0 {
//	    TokenMeasureFlow(c.pid, data[:n])
//	}
//	    return n, err
//
//    Measuring only what crossed is the difference between a record of the traffic and
//    a record of the attempts.
//
// 3. The direct-report path, which is how most modules actually report. Nothing calls
//    TokenCheckUsage today, and that is the gap: emitUsage in usage.go validates the
//    quantity against its ceiling and records it, and never sees the bytes. The hook
//    cannot live inside emitUsage either, because usage.go has no bytes - a module
//    emits a number and the text it came from is already gone.
//
//    So the honest wiring is that a module which wants its report corroborated calls
//    SyscallTokenCheckUsage with the bytes, and a deployment that wants corroboration
//    to be mandatory makes it a review and signing condition on the channel module
//    rather than a runtime interception. Stating that plainly is better than building a
//    hook that looks mandatory and is not: usage.go cannot measure what it is never
//    shown.
//
// 4. dump.go should render TokenStatsSnapshot and TokenTotalsByModule under a
//    "--- token accounting ---" heading, beside the metering section, since the two
//    are the same question asked at different points.
