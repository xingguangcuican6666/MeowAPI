# suite-report.awk - classify `go test -json` events for CI's suite gate.
#
# Invoked as: awk -f tools/ci/suite-report.awk /tmp/suite.json
# Its output is shell assignments the workflow step evals, so every value that can
# hold text is single-quoted and has single quotes stripped (see safe()).
#
# Why -json and not -v. The text form prints "--- SKIP:" at column zero only for a
# top-level test; a skip inside a subtest is indented under its parent, which reports
# PASS. A gate that greps ^--- SKIP therefore cannot see the one shape that matters
# most - a test that silently stopped asserting - and cannot tell which package a skip
# came from. The JSON stream carries Action, Package and the full subtest path for
# every event, so this file can attribute each skip to a package AND a test, and can
# read the reason the test gave for skipping, which is in its Output events.
#
# What counts toward the floor. PASSED counts top-level pass events only, and SKIP_TOP
# counts top-level skips only, because a subtest that skips does NOT remove a pass: its
# parent still emits one. Adding subtest skips to the floor would double-count them.
#
# What fails the build. A package-level fail with no Test field (TestMain panicking, an
# os.Exit, a t.Cleanup that panics); a build failure; any skip that is not on the
# allowlist for THIS package and name with a reason matching THIS entry's text; an
# allowlisted name skipping more than once. The last two are what stop the allowlist
# from becoming a hole: a name-only list lets a different package skip for a different
# reason under the same name, and an uncapped list lets one permitted name skip enough
# times to satisfy the floor with nothing passing at all.
#
# This file is the thing that decides whether the suite ran, and it has a committed
# regression test: tools/ci/suite_report_test.go. Change one and change the other.

BEGIN {
    # A real newline, used as the separator inside the single-quoted values the caller
    # evals. awk's printf format cannot hold a literal newline without making the rest
    # of this file hard to read, so it is a variable built from the character code.
    NL = sprintf("%c", 10)

    # Environment-dependent skips, as package|test|reason-substring. The reason is part
    # of the key on purpose: an allowlisted test that starts skipping for a NEW reason
    # is a regression wearing a permitted name, and matching on the name alone would
    # wave it through. The substring must appear in the text the test passed to t.Skip
    # or t.Skipf, which arrives in its Output events as a "file_test.go:NN: reason"
    # line. A skip with no reason line at all matches nothing and fails, which is the
    # safe direction.
    #
    # tests/egress: the four dial tests need a non-loopback private IPv4 interface on
    # the runner, and all four reach it through one helper that skips with this text.
    allow["tests/egress|TestASuccessfulDialUsesTheValidatedAddress|no non-loopback private IPv4 interface"] = 1
    allow["tests/egress|TestThePoolReturnsTheSameSocketAndRevalidatesOnReuse|no non-loopback private IPv4 interface"] = 1
    allow["tests/egress|TestThePoolCeilingClosesRatherThanRefuses|no non-loopback private IPv4 interface"] = 1
    allow["tests/egress|TestSocketsAreReclaimedWhenTheModuleIsUnloaded|no non-loopback private IPv4 interface"] = 1
    # tests/state: the symlink-escape cases need os.Symlink to work.
    allow["tests/state|TestFSResolveRefusesEveryEscape|symlinks are not available here"] = 1
}

function jsonstr(line, key,    needle, start, rest, stop) {
    needle = "\"" key "\":\""
    start = index(line, needle)
    if (start == 0) { return "" }
    rest = substr(line, start + length(needle))
    stop = jsonend(rest)
    if (stop == 0) { return "" }
    return jsonunescape(substr(rest, 1, stop - 1))
}

# jsonend returns the offset of the closing quote of a JSON string body, skipping the
# ones that are escaped. Scanning to the first quote instead truncates any value that
# contains one, and these do: a test name may hold a quote, and a skip reason is built
# from an error whose text is not ours to choose.
#
# What the truncation breaks depends on WHERE the quote falls, and the distinction
# matters because it decides how much this fix buys. The allowlist matches a substring,
# so a quote after the substring leaves the match intact - which is the shape all five
# current entries have, since each reason reads "symlinks are not available here: %v"
# with the variable after the fixed text. A quote BEFORE the substring truncates it away
# and the skip is refused as unexpected. Measured both orders: with "cannot create
# \"escape\" link: symlinks are not available here" the old scan loses the match, and
# with the error trailing the text it does not.
function jsonend(s,    i, c) {
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "\\") { i++; continue }
        if (c == "\"") { return i }
    }
    return 0
}

# jsonunescape reverses the escapes the Go encoder writes. Only the ones that can appear
# in a test name or a skip reason are handled; anything else is left as written, because
# guessing at an unknown escape would be worse than passing it through.
function jsonunescape(s) {
    gsub(/\\n/, "\n", s)
    gsub(/\\t/, "\t", s)
    gsub(/\\r/, "\r", s)
    gsub(/\\"/, "\"", s)
    gsub(/\\\//, "/", s)
    gsub(/\\\\/, "\\", s)
    return s
}

# reasonFromOutput pulls the reason a test gave for skipping out of a raw JSON line.
#
# It reads the raw line rather than the extracted Output value, because the reason is
# what the test printed and it can contain anything - including the quote that would
# otherwise end the scan, which jsonend now skips over. The reason line looks like
# "    egress_test.go:162: this machine has no ...\n" inside the Output field, with the
# newline still escaped as two characters, so the scan stops at either that or the end
# of the JSON string.
function reasonFromOutput(line,    p, rest, q) {
    p = index(line, "_test.go:")
    if (p == 0) { return "" }
    rest = substr(line, p)
    if (match(rest, /^_test\.go:[0-9]+: /) == 0) { return "" }
    rest = substr(rest, RLENGTH + 1)
    q = index(rest, "\\n")
    if (q > 0) { rest = substr(rest, 1, q - 1) }
    q = jsonend(rest)
    if (q > 0) { rest = substr(rest, 1, q - 1) }
    return jsonunescape(rest)
}

# shortpkg drops the module path prefix so the lists read as paths in this repository.
function shortpkg(pkg) {
    sub(/^github\.com\/xingguangcuican6666\/MeowAPI\//, "", pkg)
    return pkg
}

# safe strips single quotes from a value that will be embedded in a single-quoted shell
# assignment the caller evals. Go replaces spaces in a subtest name with underscores
# before it reaches this stream, so a name can contain a single quote - "TestIt's"
# compiles - and one inside the value would terminate the quote and inject whatever
# followed. Checked against every test name in the suite today: none contains one, and
# the hostile-name cases in suite_report_test.go assert the defence rather than the
# current test list.
function safe(s) {
    gsub(/'/, "", s)
    return s
}

function addlist(arr, count, item) {
    count++
    arr[count] = item
    return count
}

function emitlist(name, arr, count,    i) {
    if (count <= 0) { return }
    printf "%s='", name
    for (i = 1; i <= count; i++) { printf "  %s%s", arr[i], NL }
    printf "'%s", NL
}

# permitted reports whether a package|test pair is allowlisted for this reason.
function permitted(pkg, test, reason,    k, parts, n) {
    for (k in allow) {
        n = split(k, parts, "|")
        if (n != 3) { continue }
        if (parts[1] != pkg || parts[2] != test) { continue }
        if (index(reason, parts[3]) > 0) { return 1 }
    }
    return 0
}

# namedByAnyEntry reports whether the package|test pair appears in the allowlist at all,
# under any reason. Used to word the failure precisely: a permitted name skipping for an
# unrecognised reason is a different problem from a name nobody allowlisted.
function namedByAnyEntry(pkg, test,    k, parts) {
    for (k in allow) {
        split(k, parts, "|")
        if (parts[1] == pkg && parts[2] == test) { return 1 }
    }
    return 0
}

{
    action = jsonstr($0, "Action")

    # A package that cannot build emits "build-fail" with an ImportPath and no Test,
    # then a package-level "fail". Without this branch the whole run reports zero tests
    # and the caller's floor message says "expected at least N tests to run, got 0",
    # which is a true statement about a misleading diagnosis: the suite did not run
    # because nothing compiled. Naming the build failure is what makes the two
    # distinguishable in a log a reviewer reads top to bottom.
    if (action == "build-fail") {
        buildfail++
        nbuild = addlist(buildlist, nbuild, safe(jsonstr($0, "ImportPath")))
        next
    }

    # Output events carry the reason a test gave for skipping. Only the last one before
    # the skip event matters, so it is stored per package|test and overwritten; that
    # also bounds memory instead of accumulating every line the suite printed.
    if (action == "output") {
        otest = jsonstr($0, "Test")
        if (otest != "") {
            r = reasonFromOutput($0)
            if (r != "") { reason[shortpkg(jsonstr($0, "Package")) "|" otest] = r }
        }
        next
    }

    if (action != "pass" && action != "fail" && action != "skip") { next }

    pkg = shortpkg(jsonstr($0, "Package"))
    test = jsonstr($0, "Test")

    # A package-level verdict, which has no Test field. A pass here is not a test and
    # must not be counted; a FAIL here is a failed package and must not be dropped. It
    # is the shape a TestMain panic, an os.Exit, or a panicking t.Cleanup produces, and
    # every one of those is a red suite with no failing test to name.
    if (test == "") {
        if (action == "fail") {
            pkgfail++
            npkgfail = addlist(pkgfaillist, npkgfail, safe(pkg))
        }
        next
    }

    if (action == "pass") {
        if (index(test, "/") == 0) { passed++ }
        next
    }

    if (action == "fail") {
        failed++
        nfail = addlist(faillist, nfail, safe(pkg "/" test))
        next
    }

    # action == "skip"
    key = pkg "|" test
    skipseen[key]++
    isSub = index(test, "/") != 0
    if (isSub) { skipSub++ } else { skipTop++ }

    why = reason[key]
    if (!permitted(pkg, test, why)) {
        if (namedByAnyEntry(pkg, test)) {
            detail = pkg "/" test " (allowlisted, but skipped for an unrecognised reason: " why ")"
        } else if (isSub) {
            detail = pkg "/" test " (a SUBTEST skipped, so its parent still passes and the floor never moves)"
        } else if (why == "") {
            detail = pkg "/" test " (gave no reason)"
        } else {
            detail = pkg "/" test " (" why ")"
        }
        nunexpected = addlist(unexpected, nunexpected, safe(detail))
    } else if (skipseen[key] > 1) {
        nexcess = addlist(excess, nexcess, safe(pkg "/" test " (skip #" skipseen[key] ")"))
    }
}

END {
    printf "PASSED=%d\n", passed + 0
    printf "FAILED=%d\n", failed + 0
    printf "PKG_FAIL=%d\n", pkgfail + 0
    printf "BUILD_FAIL=%d\n", buildfail + 0
    printf "SKIP_TOP=%d\n", skipTop + 0
    printf "SKIP_SUB=%d\n", skipSub + 0

    emitlist("BUILD_FAILURES", buildlist, nbuild)
    emitlist("PKG_FAILURES", pkgfaillist, npkgfail)
    emitlist("FAILURES", faillist, nfail)

    printf "UNEXPECTED=%d\n", nunexpected + 0
    emitlist("UNEXPECTED_LIST", unexpected, nunexpected)

    # An allowlisted name that skips more than once is a failure in its own right: the
    # floor is a count of distinct tests that ran, and a repeat skip inflates it.
    printf "EXCESS=%d\n", nexcess + 0
    emitlist("EXCESS_LIST", excess, nexcess)
}
