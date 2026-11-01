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

// Package ci holds the suite gate's regression test.
//
// suite-report.awk decides whether CI considers the suite to have run. It is 190 lines
// of text processing whose output is eval'd by a shell, and until this file existed it
// had no test at all: the shapes it handles were exercised by hand, in one session, and
// nothing recorded them. A gate with no test is a gate whose next edit is unaudited.
//
// The cases here are the ones that were measured rather than reasoned about. Each is a
// JSON event stream in the shape `go test -json` really emits, including the Output
// events that carry a skip's reason, because the allowlist matches on that text.
package ci

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const modPath = "github.com/xingguangcuican6666/MeowAPI/"

// awkScript resolves the classifier's path relative to this file, so the test works
// from any directory and fails loudly if the script moves.
func awkScript(t *testing.T) string {
	t.Helper()
	// A test's working directory is its own package directory, and the script sits
	// beside it. filepath.Abs keeps the error message readable when it is missing.
	p, err := filepath.Abs("suite-report.awk")
	require.NoError(t, err)
	_, err = os.Stat(p)
	require.NoError(t, err, "suite-report.awk must sit beside this test; the CI step invokes it at tools/ci/suite-report.awk")
	return p
}

// requireTool fails rather than skips when a tool the gate depends on is missing. CI
// runs this awk inside a bash step, so an environment without them cannot run the gate
// either, and a skip would report "not tested here" as though that were acceptable.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	require.NoError(t, err, "%s is required: the CI suite gate is a %s invocation, so without it neither the gate nor this test can run", name, name)
	return p
}

// runClassify feeds events to the awk script and returns its output as a map.
//
// Parsing is not a naive line split, because a list value is a single-quoted shell
// string that spans lines. Splitting on newline would see the closing quote as a line of
// its own and fail the output contract it is checking. This walks the text: a KEY= line
// starts a value, an opening quote after the = means the value continues until the
// matching close, and anything else must be a bare integer assignment.
func runClassify(t *testing.T, events ...map[string]any) map[string]string {
	t.Helper()
	awk := requireTool(t, "awk")

	var stream strings.Builder
	for _, e := range events {
		line, err := json.Marshal(e)
		require.NoError(t, err)
		stream.Write(line)
		stream.WriteByte('\n')
	}

	in := filepath.Join(t.TempDir(), "events.json")
	require.NoError(t, os.WriteFile(in, []byte(stream.String()), 0o600))

	out, err := exec.Command(awk, "-f", awkScript(t), in).CombinedOutput()
	require.NoError(t, err, "awk failed: %s", out)

	return parseReport(t, string(out))
}

// parseReport reads the classifier's shell-assignment output. It asserts the contract as
// it parses: every line either starts a KEY=VALUE assignment or is inside a quoted
// value, and a bare value must be an integer. That is the property the CI step's `eval`
// depends on, so a violation here is a defect in the gate rather than a test problem.
func parseReport(t *testing.T, text string) map[string]string {
	t.Helper()
	got := map[string]string{}
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		require.True(t, ok, "every output line must start a KEY=VALUE assignment the caller can eval, got %q", line)
		require.Regexp(t, `^[A-Z][A-Z0-9_]*$`, k, "the key must be a shell-safe upper-case name, got %q", k)

		if strings.HasPrefix(v, "'") {
			// A quoted list value: consume lines until the one that closes it.
			var body strings.Builder
			body.WriteString(strings.TrimPrefix(v, "'"))
			closed := strings.HasSuffix(body.String(), "'")
			for !closed {
				i++
				require.Less(t, i, len(lines), "unterminated quoted value for %s", k)
				body.WriteByte('\n')
				body.WriteString(lines[i])
				closed = strings.HasSuffix(body.String(), "'")
			}
			got[k] = strings.TrimSuffix(body.String(), "'")
			continue
		}

		require.NotContains(t, v, "'", "%s is unquoted, so it must not contain a quote", k)
		_, err := strconv.Atoi(v)
		require.NoError(t, err, "%s must be a bare integer, got %q", k, v)
		got[k] = v
	}
	return got
}

// num reads one integer counter, failing rather than defaulting when it is absent: a
// counter the classifier stopped printing is a regression, not a zero.
func num(t *testing.T, got map[string]string, key string) int {
	t.Helper()
	v, ok := got[key]
	require.True(t, ok, "the classifier must always print %s", key)
	n, err := strconv.Atoi(v)
	require.NoError(t, err, "%s must be an integer, got %q", key, v)
	return n
}

// pass is one passing test event.
func pass(pkg, test string) map[string]any {
	return map[string]any{"Action": "pass", "Package": modPath + pkg, "Test": test}
}

// skip is one skipping test event.
func skip(pkg, test string) map[string]any {
	return map[string]any{"Action": "skip", "Package": modPath + pkg, "Test": test}
}

// fail is one failing test event.
func fail(pkg, test string) map[string]any {
	return map[string]any{"Action": "fail", "Package": modPath + pkg, "Test": test}
}

// pkgVerdict is a package-level verdict, which has no Test field. This is the shape the
// classifier used to drop, and dropping a fail meant a red suite reported green.
func pkgVerdict(action, pkg string) map[string]any {
	return map[string]any{"Action": action, "Package": modPath + pkg, "Elapsed": 0.1}
}

// skipReason is the Output event carrying the text a test passed to t.Skip. In the real
// stream the newline is escaped inside the JSON string, and the classifier scans the raw
// line for exactly that reason.
func skipReason(pkg, test, fileLine, reason string) map[string]any {
	return map[string]any{
		"Action":  "output",
		"Package": modPath + pkg,
		"Test":    test,
		"Output":  "    " + fileLine + ": " + reason + `\n`,
	}
}

const egressReason = "this machine has no non-loopback private IPv4 interface, so the dial success path cannot be exercised"
const symlinkReason = "symlinks are not available here: operation not permitted"

// TestCountersArePrintedEvenWhenEverythingIsZero pins the output contract: an empty
// stream must still print every counter, because the CI step reads them unconditionally
// and a missing variable would make its arithmetic expand to nothing.
func TestCountersArePrintedEvenWhenEverythingIsZero(t *testing.T) {
	got := runClassify(t)
	for _, key := range []string{
		"PASSED", "FAILED", "PKG_FAIL", "BUILD_FAIL", "SKIP_TOP", "SKIP_SUB",
		"UNEXPECTED", "EXCESS", "PKG_STARTED", "PKG_FINISHED",
	} {
		assert.Equal(t, 0, num(t, got, key), "%s must be printed as zero rather than omitted", key)
	}
}

// TestPackageLevelPassIsNotCountedAsATest guards the floor's meaning. go test emits a
// pass event per package as well as per test; counting those would inflate the total by
// the package count and let a suite lose tests without the floor noticing.
func TestPackageLevelPassIsNotCountedAsATest(t *testing.T) {
	got := runClassify(t,
		pass("tests/state", "TestOne"),
		pass("tests/state", "TestTwo"),
		pkgVerdict("pass", "tests/state"),
	)
	assert.Equal(t, 2, num(t, got, "PASSED"), "two tests, not two tests plus their package")
	assert.Equal(t, 0, num(t, got, "FAILED"))
}

// TestSubtestPassIsNotCountedAsATest is the case the fixture set was missing, and the
// omission had a cost: the filter at the only place PASSED is incremented could be
// deleted, and every test here still passed. Measured on the real stream, that mutant
// moves PASSED from 641 to 1037 - 396 subtest passes joining the count - so 396 vanished
// top-level tests would still satisfy a floor derived from the filtered number. The whole
// point of counting top-level passes is that the floor means "this many tests ran"; a
// case whose expected PASSED differs between filtered and unfiltered is what pins it.
func TestSubtestPassIsNotCountedAsATest(t *testing.T) {
	got := runClassify(t,
		pass("tests/state", "TestParent"),
		pass("tests/state", "TestParent/sub_one"),
		pass("tests/state", "TestParent/sub_two"),
		pkgVerdict("pass", "tests/state"),
	)
	assert.Equal(t, 1, num(t, got, "PASSED"),
		"only the top-level test counts; a subtest pass does not remove a top-level pass "+
			"and must not add to the floor either")
}

// TestATruncatedStreamIsDetectable covers the counter that makes truncation visible.
// Every other number here can be satisfied by a stream cut short: the missing lines are
// trailing passes, not a missing verdict, so measured by cutting the real stream at
// exactly the floor's worth of top-level passes - 4596 of 4599 lines - PASSED holds at
// 641 and every other counter reads zero. What changes is that a package started and
// never reported.
func TestATruncatedStreamIsDetectable(t *testing.T) {
	complete := runClassify(t,
		map[string]any{"Action": "start", "Package": modPath + "tests/state"},
		pass("tests/state", "TestOne"),
		pkgVerdict("pass", "tests/state"),
		map[string]any{"Action": "start", "Package": modPath + "tests/fs"},
		pass("tests/fs", "TestTwo"),
		pkgVerdict("pass", "tests/fs"),
	)
	assert.Equal(t, 2, num(t, complete, "PKG_STARTED"))
	assert.Equal(t, 2, num(t, complete, "PKG_FINISHED"))

	truncated := runClassify(t,
		map[string]any{"Action": "start", "Package": modPath + "tests/state"},
		pass("tests/state", "TestOne"),
		pkgVerdict("pass", "tests/state"),
		map[string]any{"Action": "start", "Package": modPath + "tests/fs"},
		pass("tests/fs", "TestTwo"),
	)
	assert.Equal(t, 2, num(t, truncated, "PKG_STARTED"))
	assert.Equal(t, 1, num(t, truncated, "PKG_FINISHED"),
		"the second package started and never reported, which is what a cut stream looks like")
}

// TestAPackageWhoseTestsAllSkippedIsStillFinished pins the verdict value that is easy to
// miss: a package whose every test skipped reports its own Action=skip rather than pass.
// Counting only pass and fail left the real stream at 22 starts against 21 finishes, so a
// completeness check built on that pair would have failed every good run - the kind of
// false alarm that gets a check deleted rather than fixed.
func TestAPackageWhoseTestsAllSkippedIsStillFinished(t *testing.T) {
	got := runClassify(t,
		map[string]any{"Action": "start", "Package": modPath + "tests/egress"},
		pkgVerdict("skip", "tests/egress"),
	)
	assert.Equal(t, 1, num(t, got, "PKG_STARTED"))
	assert.Equal(t, 1, num(t, got, "PKG_FINISHED"))
	assert.Equal(t, 0, num(t, got, "PASSED"))
}

// TestPackageLevelFailIsAFailure covers the hole the first version of this classifier
// had. A TestMain that panics, an os.Exit, or a t.Cleanup that panics produces a
// package-level fail with no Test field - a red suite with no failing test to name. The
// classifier dropped it at its "no Test field, skip this event" line, so two passing
// tests plus a failed package reported success and exited 0.
func TestPackageLevelFailIsAFailure(t *testing.T) {
	got := runClassify(t,
		pass("tests/state", "TestOne"),
		pass("tests/state", "TestTwo"),
		pkgVerdict("fail", "tests/state"),
	)
	assert.Equal(t, 2, num(t, got, "PASSED"), "the tests that did pass still passed")
	assert.Equal(t, 0, num(t, got, "FAILED"), "and none of them failed, which is the point")
	assert.Equal(t, 1, num(t, got, "PKG_FAIL"), "the package failed, and that is a failure")
	assert.Contains(t, got["PKG_FAILURES"], "tests/state")
}

// TestBuildFailureIsNamedSeparately covers the diagnosis ordering. A package that does
// not compile emits build-fail plus a package-level fail; without naming the build
// failure the step's only complaint would be "expected at least N tests to run, got 0",
// which is true and is the wrong thing to read first.
func TestBuildFailureIsNamedSeparately(t *testing.T) {
	got := runClassify(t,
		map[string]any{"Action": "build-fail", "ImportPath": modPath + "kernel [kernel.test]"},
		pkgVerdict("fail", "kernel"),
	)
	assert.Equal(t, 1, num(t, got, "BUILD_FAIL"))
	assert.Contains(t, got["BUILD_FAILURES"], "kernel")
	assert.Equal(t, 1, num(t, got, "PKG_FAIL"), "the package verdict is counted too; the step reports the build failure first")
}

// TestTestFailureIsNamedWithItsPackage covers the ordinary case and pins that a failing
// test is reported as package/name rather than as a bare name, since two packages may
// hold tests with the same name.
func TestTestFailureIsNamedWithItsPackage(t *testing.T) {
	got := runClassify(t,
		pass("tests/state", "TestFine"),
		fail("tests/fs", "TestBroken"),
		pkgVerdict("fail", "tests/fs"),
	)
	assert.Equal(t, 1, num(t, got, "PASSED"))
	assert.Equal(t, 1, num(t, got, "FAILED"))
	assert.Contains(t, got["FAILURES"], "tests/fs/TestBroken")
}

// TestAnAllowlistedSkipWithItsOwnReasonIsClean is the legitimate case: a runner with no
// private IPv4 interface skips the dial test and says so. This must not fail the build.
func TestAnAllowlistedSkipWithItsOwnReasonIsClean(t *testing.T) {
	got := runClassify(t,
		pass("tests/state", "TestSomethingElse"),
		skipReason("tests/egress", "TestThePoolCeilingClosesRatherThanRefuses", "egress_test.go:162", egressReason),
		skip("tests/egress", "TestThePoolCeilingClosesRatherThanRefuses"),
	)
	assert.Equal(t, 1, num(t, got, "PASSED"))
	assert.Equal(t, 1, num(t, got, "SKIP_TOP"))
	assert.Equal(t, 0, num(t, got, "UNEXPECTED"))
	assert.Equal(t, 0, num(t, got, "EXCESS"))
}

// TestAnAllowlistedNameInTheWrongPackageIsUnexpected pins the package half of the key.
// A name-only allowlist lets any package skip under a permitted name.
func TestAnAllowlistedNameInTheWrongPackageIsUnexpected(t *testing.T) {
	got := runClassify(t,
		skipReason("tests/state", "TestThePoolCeilingClosesRatherThanRefuses", "kv_test.go:9", egressReason),
		skip("tests/state", "TestThePoolCeilingClosesRatherThanRefuses"),
	)
	assert.Equal(t, 1, num(t, got, "UNEXPECTED"))
	assert.Contains(t, got["UNEXPECTED_LIST"], "tests/state/TestThePoolCeilingClosesRatherThanRefuses")
}

// TestAnAllowlistedNameSkippingForANewReasonIsUnexpected is the reason the allowlist
// carries text and not just names. A test that starts skipping because of a fresh
// defect guard, while wearing a name the operator permitted for an environment
// condition, is a regression that a name-only list waves through - and the total can
// land exactly on the floor while it does.
func TestAnAllowlistedNameSkippingForANewReasonIsUnexpected(t *testing.T) {
	got := runClassify(t,
		skipReason("tests/state", "TestFSResolveRefusesEveryEscape", "kv_test.go:742",
			"a new guard found the resolver returning a relative path"),
		skip("tests/state", "TestFSResolveRefusesEveryEscape"),
	)
	assert.Equal(t, 1, num(t, got, "UNEXPECTED"))
	assert.Contains(t, got["UNEXPECTED_LIST"], "allowlisted, but skipped for an unrecognised reason",
		"the message must say the name was permitted and the reason was not")
}

// TestASkipWithNoReasonIsUnexpected covers a t.Skip("") and a stream where the Output
// events were lost. Matching nothing is the safe direction: an unexplained skip fails.
func TestASkipWithNoReasonIsUnexpected(t *testing.T) {
	got := runClassify(t, skip("tests/state", "TestSilent"))
	assert.Equal(t, 1, num(t, got, "UNEXPECTED"))
	assert.Contains(t, got["UNEXPECTED_LIST"], "gave no reason")
}

// TestAnAllowlistedNameSkippingTwiceIsExcess pins the per-entry cap. Without it, one
// permitted name could skip hundreds of times and satisfy a floor of N with nothing
// passing at all - the shape that made a count-based allowlist unsafe.
func TestAnAllowlistedNameSkippingTwiceIsExcess(t *testing.T) {
	name := "TestThePoolCeilingClosesRatherThanRefuses"
	got := runClassify(t,
		skipReason("tests/egress", name, "egress_test.go:162", egressReason),
		skip("tests/egress", name),
		skipReason("tests/egress", name, "egress_test.go:162", egressReason),
		skip("tests/egress", name),
	)
	assert.Equal(t, 2, num(t, got, "SKIP_TOP"))
	assert.Equal(t, 0, num(t, got, "UNEXPECTED"), "the first skip is permitted")
	assert.Equal(t, 1, num(t, got, "EXCESS"), "and the second is not")
	assert.Contains(t, got["EXCESS_LIST"], "skip #2")
}

// TestASubtestSkipIsAFailure is the shape that motivated moving off `go test -v`. The
// text form indents a subtest's verdict under its parent, which reports PASS at column
// zero, so a gate built on grepping ^--- SKIP could not see a test that stopped
// asserting. Counting it is not enough either: a subtest skip does not remove a pass,
// so the floor never moves and only a hard failure catches it.
func TestASubtestSkipIsAFailure(t *testing.T) {
	got := runClassify(t,
		pass("tests/state", "TestFSResolveRefusesEveryEscape"),
		skipReason("tests/state", "TestFSResolveRefusesEveryEscape/relative_root", "kv_test.go:834",
			"the temp root is not reachable by a relative path from here"),
		skip("tests/state", "TestFSResolveRefusesEveryEscape/relative_root"),
	)
	assert.Equal(t, 1, num(t, got, "PASSED"), "the parent still passes, which is exactly why the floor cannot catch this")
	assert.Equal(t, 0, num(t, got, "SKIP_TOP"), "a subtest skip is not a top-level skip")
	assert.Equal(t, 1, num(t, got, "SKIP_SUB"))
	assert.Equal(t, 1, num(t, got, "UNEXPECTED"))
	assert.Contains(t, got["UNEXPECTED_LIST"], "SUBTEST")
}

// TestOnlyTheLastReasonLineBeforeTheSkipIsUsed pins the reason-matching mechanism. A
// test prints many lines; the classifier keeps the most recent "file_test.go:NN:" line
// per test, which is the one t.Skip emits immediately before the skip event.
func TestOnlyTheLastReasonLineBeforeTheSkipIsUsed(t *testing.T) {
	name := "TestThePoolCeilingClosesRatherThanRefuses"
	got := runClassify(t,
		skipReason("tests/egress", name, "egress_test.go:100", "some unrelated diagnostic"),
		skipReason("tests/egress", name, "egress_test.go:162", egressReason),
		skip("tests/egress", name),
	)
	assert.Equal(t, 0, num(t, got, "UNEXPECTED"), "the last reason line is the skip's own")
}

// TestAReasonWithAQuoteStillMatches pins the accidental-truncation case the jsonend fix
// addresses. A skip reason can contain a quote - a subtest name does today, and a reason
// built from an error's text is not ours to choose - and a quote BEFORE the allowlisted
// substring truncates it away under a scan that stops at the first quote.
//
// No site the gate runs today can produce that order: the four egress reasons are
// constants with no format variable, and the state entry's only variable trails the fixed
// text. So this is a case for the shape rather than for a live defect, and the comment
// here says so because the earlier version of it claimed all five entries were shaped
// alike when only one has a variable at all.
func TestAReasonWithAQuoteStillMatches(t *testing.T) {
	got := runClassify(t,
		skipReason("tests/state", "TestFSResolveRefusesEveryEscape", "kv_test.go:742",
			`cannot create "escape" link: symlinks are not available here`),
		skip("tests/state", "TestFSResolveRefusesEveryEscape"),
	)
	assert.Equal(t, 1, num(t, got, "SKIP_TOP"))
	assert.Equal(t, 0, num(t, got, "UNEXPECTED"),
		"a quote before the allowlisted substring must not truncate the reason away")
}

// TestAnUnexpectedSkipReportsItsReasonUnescaped pins jsonunescape, which is easy to get
// wrong in the other direction: the assertion has to be about the TEXT the classifier
// reports, not about whether a match succeeded. My first version of this case appended a
// backslash-heavy suffix to an allowlisted reason and asserted the skip stayed permitted
// - which passed with jsonunescape deleted, because the allowlisted substring sat before
// the suffix and matching never looked at it. Mutation-tested: reverting the extractor to
// "cut at the first quote" fails TestAReasonWithAQuoteStillMatches, and reverting
// jsonunescape fails this one and nothing else.
//
// So the case is an UNEXPECTED skip, where the reason text is echoed into the failure
// list, and the assertion is that a doubled backslash in the stream arrives as the single
// one the test actually printed. That is what makes the diagnosis in a CI log readable
// rather than showing JSON's encoding of the message.
func TestAnUnexpectedSkipReportsItsReasonUnescaped(t *testing.T) {
	got := runClassify(t,
		skipReason("tests/state", "TestSomethingNew", "kv_test.go:12",
			`cannot resolve \\wsl$\eth0 for "iface"`),
		skip("tests/state", "TestSomethingNew"),
	)
	assert.Equal(t, 1, num(t, got, "UNEXPECTED"))
	list := got["UNEXPECTED_LIST"]
	assert.Contains(t, list, `\\wsl$\eth0`,
		"the reported reason must be the text the test printed, not JSON's encoding of it")
	assert.NotContains(t, list, `\\\\wsl`, "and not the doubled form from the raw stream")
	assert.Contains(t, list, `"iface"`, "quotes in the reason survive too")
}

// TestHostileTestNamesCannotInjectShell is the safety property of eval'ing the output.
// Go replaces spaces in a subtest name with underscores but leaves quotes alone, so a
// name like TestIt's compiles and reaches this stream. Every value the classifier prints
// is embedded in a single-quoted shell assignment, so a quote would terminate it and
// inject whatever followed.
//
// The names here are the ones a peer session used to break an earlier draft of this
// gate, plus the shapes that follow from them. The assertion is end to end: the report
// is eval'd by a real bash, a canary file must not appear, and every counter must still
// be an integer.
func TestHostileTestNamesCannotInjectShell(t *testing.T) {
	bash := requireTool(t, "bash")
	dir := t.TempDir()
	canary := filepath.Join(dir, "PWNED")

	hostile := []string{
		`Test'; touch ` + canary + `; '`,
		`Test$(touch ` + canary + `)`,
		"Test`touch " + canary + "`",
		`Test${IFS}x`,
		`Test'PASSED=99999'`,
		`Test"; rm -rf /; "`,
		`Test$(awk 'BEGIN{print 1}')`,
		"Test\nnewline",
		`Test\backslash`,
		`Test*glob*`,
		`Test?quest`,
		`Test[bracket]`,
		`Test|pipe`,
		`Test&amp`,
	}

	var events []map[string]any
	for _, name := range hostile {
		events = append(events,
			skipReason("tests/state", name, "x_test.go:1", "a reason with 'quotes' and $(commands)"),
			skip("tests/state", name),
		)
	}
	events = append(events, pass("tests/state", "TestHonest"))

	// Run the classifier, then eval its output in a real shell and read the counters
	// back out. If any value escaped its quotes, the shell would have executed it.
	in := filepath.Join(dir, "events.json")
	var stream strings.Builder
	for _, e := range events {
		line, err := json.Marshal(e)
		require.NoError(t, err)
		stream.Write(line)
		stream.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(in, []byte(stream.String()), 0o600))

	awk := requireTool(t, "awk")
	report, err := exec.Command(awk, "-f", awkScript(t), in).Output()
	require.NoError(t, err, "awk failed on hostile input")

	script := `set -uo pipefail
report="$1"
eval "$report"
printf 'PASSED=%s\nFAILED=%s\nPKG_FAIL=%s\nBUILD_FAIL=%s\nSKIP_TOP=%s\nSKIP_SUB=%s\nUNEXPECTED=%s\nEXCESS=%s\nPKG_STARTED=%s\nPKG_FINISHED=%s\n' \
  "$PASSED" "$FAILED" "$PKG_FAIL" "$BUILD_FAIL" "$SKIP_TOP" "$SKIP_SUB" "$UNEXPECTED" "$EXCESS" "$PKG_STARTED" "$PKG_FINISHED"
case "$PASSED$FAILED$SKIP_TOP$SKIP_SUB$UNEXPECTED$EXCESS" in
  *[!0-9]*) echo "NONINTEGER" ;;
esac`
	scriptPath := filepath.Join(dir, "eval.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o700))

	out, err := exec.Command(bash, scriptPath, string(report)).CombinedOutput()
	require.NoError(t, err, "the eval'd report must be valid shell: %s", out)

	text := string(out)
	assert.NotContains(t, text, "NONINTEGER", "every counter must survive the eval as an integer:\n%s", text)
	assert.Equal(t, "PASSED=1", firstLineMatching(text, "PASSED="), "one honest test passed")

	// All fourteen hostile names are counted, and every one is a failure. They are read
	// as a SUM of the two skip counters rather than as SKIP_TOP alone, because three of
	// these names contain a slash - the canary path - and a name with a slash is what a
	// subtest looks like in this stream. That is not a defect: the classifier cannot
	// distinguish a hostile name from a real subtest, both counters fail the build, and
	// asserting on one of them would be asserting on the shape of my own fixture path.
	top := atoiFromReport(t, text, "SKIP_TOP=")
	sub := atoiFromReport(t, text, "SKIP_SUB=")
	assert.Equal(t, len(hostile), top+sub, "every hostile name is counted as a skip, none of them executed")
	assert.Equal(t, len(hostile), atoiFromReport(t, text, "UNEXPECTED="),
		"and every one is unexpected, since none is allowlisted")

	_, statErr := os.Stat(canary)
	assert.True(t, os.IsNotExist(statErr), "no hostile name may create a file; %v", statErr)

	// The report itself must not contain an unescaped quote outside its own quoting.
	assert.NotContains(t, string(report), "'PASSED=99999'",
		"a quoted value inside the report must have had its quotes stripped")
}

func atoiFromReport(t *testing.T, text, prefix string) int {
	t.Helper()
	line := firstLineMatching(text, prefix)
	require.NotEmpty(t, line, "the report must contain a %s line:\n%s", prefix, text)
	n, err := strconv.Atoi(strings.TrimPrefix(line, prefix))
	require.NoError(t, err, "%s must hold an integer, got %q", prefix, line)
	return n
}

func firstLineMatching(text, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

// TestTheRealAllowlistMatchesTheRealSkipSites is the check that keeps the allowlist from
// drifting away from the tests it names. It reads the five skip sites out of the tree and
// asserts each one's package, name and reason text still match an entry - a renamed test
// or reworded t.Skip would otherwise turn a legitimate environment skip into a red build,
// or worse, leave a stale entry permitting a name that no longer exists.
func TestTheRealAllowlistMatchesTheRealSkipSites(t *testing.T) {
	sites := []struct {
		file   string
		reason string
	}{
		{"../../tests/egress/egress_test.go", "no non-loopback private IPv4 interface"},
		{"../../tests/state/kv_test.go", "symlinks are not available here"},
	}
	for _, site := range sites {
		body, err := os.ReadFile(site.file)
		require.NoError(t, err, "the gate's allowlist must be checked against the tree it gates")
		assert.Contains(t, string(body), site.reason,
			"%s must still skip with the reason text the allowlist matches on", site.file)
	}
}
