# suite-report.awk - classify `go test -json` events for CI's suite gate.
#
# Invoked as: awk -f tools/ci/suite-report.awk /tmp/suite.json
#
# Why -json and not -v. The text form prints "--- SKIP:" at column zero only for a
# top-level test; a skip inside a subtest is indented under its parent, which reports
# PASS. A gate that greps ^--- SKIP therefore cannot see the one shape that matters
# most - a test that silently stopped asserting - and cannot tell which package a
# skip came from. The JSON stream carries Action, Package and the full subtest path
# for every event, so this file can attribute each skip to a package AND a test.
#
# Two counts are emitted. PASSED short-circuits a package when it says "pass", so this
# counts test-level pass events only, never package-level ones. SKIP_TOP counts
# top-level skips, which is what the floor is measured against; SKIP_SUB is reported
# so a subtest that declines to assert is visible even though it does not move the
# floor.
#
# Output is shell assignments on stdout, one KEY=VALUE per line, evaluated by the
# workflow step. Values that can contain spaces or multiple lines are single-quoted
# and escaped for that use; nothing here is user-controlled beyond test names, which
# come from the repository itself.
#
# The allowlist is by package AND name, and each entry permits exactly one skip. That
# is not pedantry: a name-only allowlist lets a different package skip for a different
# reason under the same name, and an uncapped allowlist lets one permitted name skip
# any number of times and satisfy the floor with no test passing at all.

BEGIN {
    # A real newline, used as the separator inside the single-quoted values the caller
    # evals. awk's printf format cannot hold a literal newline without making the rest
    # of this file hard to read, so it is a variable built from the character code.
    NL = sprintf("%c", 10)

    # Five environment-dependent tests, each with the condition it needs. A skip here
    # is not a defect; a skip anywhere else is.
    # Adjacent awk string constants concatenate with NO separator, so each key here
    # spells the separator itself. Get one wrong and that test reports as unexpected.
    allow["tests/egress|TestASuccessfulDialUsesTheValidatedAddress"] = 1
    allow["tests/egress|TestThePoolReturnsTheSameSocketAndRevalidatesOnReuse"] = 1
    allow["tests/egress|TestThePoolCeilingClosesRatherThanRefuses"] = 1
    allow["tests/egress|TestSocketsAreReclaimedWhenTheModuleIsUnloaded"] = 1
    allow["tests/state|TestFSResolveRefusesEveryEscape"] = 1
}

function jsonstr(line, key,    needle, start, rest, stop) {
    needle = "\"" key "\":\""
    start = index(line, needle)
    if (start == 0) { return "" }
    rest = substr(line, start + length(needle))
    stop = index(rest, "\"")
    if (stop == 0) { return "" }
    return substr(rest, 1, stop - 1)
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
# followed. Checked against every test name in the suite today: none contains one. This
# makes that a property of the output rather than of the current test list.
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

{
    action = jsonstr($0, "Action")

    # A package that cannot build emits "build-fail" with an ImportPath and no Test,
    # then a package-level "fail". Without this branch the whole run reports zero tests
    # and the caller's floor message says "expected at least 619 tests to run, got 0",
    # which is a true statement about a misleading diagnosis: the suite did not run
    # because nothing compiled. Naming the build failure is what makes the two
    # distinguishable in a log a reviewer reads top to bottom.
    if (action == "build-fail") {
        buildfail++
        nbuild = addlist(buildlist, nbuild, safe(jsonstr($0, "ImportPath")))
        next
    }

    if (action != "pass" && action != "fail" && action != "skip") { next }

    test = jsonstr($0, "Test")
    if (test == "") { next }          # package-level verdict: PASSED counts tests only

    pkg = shortpkg(jsonstr($0, "Package"))

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
    if (index(test, "/") != 0) {
        # A subtest that declined to assert. It does not move the floor, because its
        # parent still reports PASS, but it is exactly the shape a text-based gate
        # cannot see, so it is reported.
        nsub = addlist(sublist, nsub, safe(pkg "/" test))
        next
    }

    skipTop++
    key = pkg "|" test
    skipseen[key]++
    if (!(key in allow)) {
        nunexpected = addlist(unexpected, nunexpected, safe(pkg "/" test))
    } else if (skipseen[key] > 1) {
        nexcess = addlist(excess, nexcess, safe(pkg "/" test " (skip #" skipseen[key] ")"))
    }
}

END {
    printf "PASSED=%d\n", passed + 0
    printf "FAILED=%d\n", failed + 0
    printf "BUILD_FAIL=%d\n", buildfail + 0
    printf "SKIP_TOP=%d\n", skipTop + 0
    printf "SKIP_SUB=%d\n", nsub + 0

    emitlist("BUILD_FAILURES", buildlist, nbuild)
    emitlist("FAILURES", faillist, nfail)

    # An allowlisted name that skips more than once is a failure in its own right: the
    # floor is a count of distinct tests that ran, and a repeat skip inflates it.
    printf "UNEXPECTED=%d\n", nunexpected + 0
    emitlist("UNEXPECTED_LIST", unexpected, nunexpected)

    printf "EXCESS=%d\n", nexcess + 0
    emitlist("EXCESS_LIST", excess, nexcess)

    emitlist("SUBTEST_SKIPS", sublist, nsub)
}
