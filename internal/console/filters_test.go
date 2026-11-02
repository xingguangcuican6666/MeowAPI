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

package console

import (
	"strings"
	"testing"
)

// The filters are asserted against the behaviour an operator already knows, because a
// filter that silently differs from the GNU tool is worse than one that is absent: the
// operator trusts it. Each case below is one somebody would notice.

const sample = "alpha\nbeta\ngamma\nbeta\ndelta\n"

func TestHeadAndTail(t *testing.T) {
	for _, c := range []struct {
		name string
		got  func() (string, error)
		want string
	}{
		{"head default", func() (string, error) { return headFilter(nil, sample) }, "alpha\nbeta\ngamma\nbeta\ndelta\n"},
		{"head -n 2", func() (string, error) { return headFilter([]string{"-n", "2"}, sample) }, "alpha\nbeta\n"},
		{"head -n2", func() (string, error) { return headFilter([]string{"-n2"}, sample) }, "alpha\nbeta\n"},
		{"head -n 0", func() (string, error) { return headFilter([]string{"-n", "0"}, sample) }, ""},
		{"tail -n 2", func() (string, error) { return tailFilter([]string{"-n", "2"}, sample) }, "beta\ndelta\n"},
		{"tail more than there is", func() (string, error) { return tailFilter([]string{"-n", "99"}, sample) }, sample},
	} {
		got, err := c.got()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestLineCountingDoesNotInventATrailingLine pins the property that a final newline
// does not make an extra empty record - the off-by-one every line tool has had.
func TestLineCountingDoesNotInventATrailingLine(t *testing.T) {
	if got, _ := wcFilter([]string{"-l"}, "a\nb\n"); got != "2\n" {
		t.Fatalf("wc -l of two lines gave %q", got)
	}
	if got, _ := wcFilter([]string{"-l"}, "a\nb"); got != "2\n" {
		t.Fatalf("wc -l of two unterminated lines gave %q", got)
	}
	if got, _ := wcFilter([]string{"-l"}, ""); got == "1\n" {
		t.Fatalf("empty input counted as one line")
	}
}

func TestWCFullOutput(t *testing.T) {
	// "hello world\n" is 2 words, 1 line, 12 bytes.
	got, err := wcFilter(nil, "hello world\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "1 2 12\n" {
		t.Fatalf("wc gave %q, want %q", got, "1 2 12\n")
	}
}

func TestGrep(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"plain", []string{"beta"}, "beta\nbeta\n"},
		{"case sensitive misses", []string{"BETA"}, ""},
		{"-i", []string{"-i", "BETA"}, "beta\nbeta\n"},
		{"-v", []string{"-v", "beta"}, "alpha\ngamma\ndelta\n"},
		{"-c", []string{"-c", "beta"}, "2\n"},
		{"-n", []string{"-n", "gamma"}, "3:gamma\n"},
		{"regex", []string{"^[ad]"}, "alpha\ndelta\n"},
	}
	for _, c := range cases {
		got, err := grepFilter(c.args, sample)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestGrepRefusesABadPattern pins that a bad regex is an error rather than a silent
// match-nothing, which is the failure that looks like "no results" and sends the
// operator looking in the wrong place.
func TestGrepRefusesABadPattern(t *testing.T) {
	if _, err := grepFilter([]string{"["}, sample); err == nil {
		t.Fatal("an unbalanced class was accepted")
	}
	if _, err := grepFilter([]string{"-i"}, sample); err == nil {
		t.Fatal("a missing pattern was accepted")
	}
	if _, err := grepFilter([]string{"a", "b"}, sample); err == nil {
		t.Fatal("two patterns were accepted")
	}
}

func TestCut(t *testing.T) {
	in := "a:b:c\nd:e:f\nnodelim\n"
	got, err := cutFilter([]string{"-d", ":", "-f", "2"}, in)
	if err != nil {
		t.Fatal(err)
	}
	want := "b\ne\n\n"
	if got != want {
		t.Fatalf("cut gave %q, want %q", got, want)
	}

	// Field 1 of a line with no delimiter is the whole line.
	got, err = cutFilter([]string{"-d", ":", "-f", "1"}, in)
	if err != nil {
		t.Fatal(err)
	}
	if want := "a\nd\nnodelim\n"; got != want {
		t.Fatalf("cut -f 1 gave %q, want %q", got, want)
	}
}

func TestCutRefusesAnUnusableField(t *testing.T) {
	// -d defaults to TAB, which is GNU cut's default, so a bare -f is legal and the
	// test above it covers that case. What must be refused is a field that cannot
	// exist or a delimiter that cannot split.
	for _, args := range [][]string{
		{"-d", ":", "-f", "0"},
		{"-d", ":", "-f", "-1"},
		{"-d", "", "-f", "1"},
	} {
		if _, err := cutFilter(args, sample); err == nil {
			t.Errorf("%q was accepted", args)
		}
	}
}

func TestSortAndUniq(t *testing.T) {
	got, err := sortFilter(nil, sample)
	if err != nil {
		t.Fatal(err)
	}
	if want := "alpha\nbeta\nbeta\ndelta\ngamma\n"; got != want {
		t.Fatalf("sort gave %q, want %q", got, want)
	}

	got, err = sortFilter([]string{"-r"}, sample)
	if err != nil {
		t.Fatal(err)
	}
	if want := "gamma\ndelta\nbeta\nbeta\nalpha\n"; got != want {
		t.Fatalf("sort -r gave %q, want %q", got, want)
	}

	got, err = sortFilter([]string{"-u"}, sample)
	if err != nil {
		t.Fatal(err)
	}
	if want := "alpha\nbeta\ndelta\ngamma\n"; got != want {
		t.Fatalf("sort -u gave %q, want %q", got, want)
	}
}

// TestUniqCollapsesOnlyAdjacentRepeats pins the one thing about uniq people get wrong.
func TestUniqCollapsesOnlyAdjacentRepeats(t *testing.T) {
	got, err := uniqFilter(nil, "a\nb\na\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := "a\nb\na\n"; got != want {
		t.Fatalf("uniq gave %q, want %q", got, want)
	}

	got, err = uniqFilter([]string{"-c"}, "a\na\nb\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := "      2 a\n      1 b\n"; got != want {
		t.Fatalf("uniq -c gave %q, want %q", got, want)
	}
}

// TestFiltersRefuseEmptyInput pins that a filter with no input is a usage error rather
// than an empty success: `head` with no pipe is a mistake, and reporting nothing would
// look like an empty result.
func TestFiltersRefuseEmptyInput(t *testing.T) {
	for name, f := range map[string]func([]string, string) (string, error){
		"head": headFilter, "tail": tailFilter, "wc": wcFilter,
		"sort": sortFilter, "uniq": uniqFilter,
	} {
		if _, err := f(nil, ""); err == nil {
			t.Errorf("%s accepted empty input", name)
		}
	}
	if _, err := grepFilter([]string{"x"}, ""); err == nil {
		t.Error("grep accepted empty input")
	}
}

// TestFilterInputCeiling pins the bound: each stage holds its input in memory, so an
// unbounded one is an allocation driven by the previous stage.
func TestFilterInputCeiling(t *testing.T) {
	big := strings.Repeat("x", maxFilterInput+1)
	if _, err := headFilter(nil, big); err == nil {
		t.Fatal("an oversized input was accepted")
	}
}
