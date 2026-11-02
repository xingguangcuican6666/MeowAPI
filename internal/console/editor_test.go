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
	"errors"
	"io"
	"strings"
	"testing"
)

// keyReader turns a string into a readKeyFunc, so a test can drive the decoder the
// way the terminal does: one byte at a time, with an escape sequence arriving as
// several reads.
func keyReader(s string) readKeyFunc {
	i := 0
	return func() (byte, error) {
		if i >= len(s) {
			return 0, io.EOF
		}
		b := s[i]
		i++
		return b, nil
	}
}

// TestDecodeKeySequences pins every binding the editor has. The failure mode this
// guards against is not "a key does nothing" but "a key does the wrong thing", which
// is how an up arrow once inserted "[A" into the line.
func TestDecodeKeySequences(t *testing.T) {
	cases := []struct {
		in   string
		kind keyKind
		r    rune
	}{
		{"a", keyRune, 'a'},
		{"\r", keyEnter, 0},
		{"\n", keyEnter, 0},
		{"\x7f", keyBackspace, 0},
		{"\t", keyTab, 0},
		{"\x1b[A", keyUp, 0},
		{"\x1b[B", keyDown, 0},
		{"\x1b[C", keyRight, 0},
		{"\x1b[D", keyLeft, 0},
		{"\x1b[H", keyHome, 0},
		{"\x1b[F", keyEnd, 0},
		{"\x1b[1~", keyHome, 0},
		{"\x1b[4~", keyEnd, 0},
		{"\x1b[3~", keyDelete, 0},
		{"\x1bOA", keyUp, 0},
		{"\x01", keyCtrlA, 0},
		{"\x03", keyInterrupt, 0},
		{"\x04", keyCtrlD, 0},
		{"\x05", keyCtrlE, 0},
		{"\x0b", keyCtrlK, 0},
		{"\x0c", keyCtrlL, 0},
		{"\x15", keyCtrlU, 0},
		{"\x17", keyCtrlW, 0},
		// A multi-byte character is one keystroke, not three.
		{"\xe4\xb8\xad", keyRune, '中'},
		// An escape sequence this build does not know is swallowed, not typed.
		{"\x1b[99~", keyUnknown, 0},
		{"\x1bOP", keyUnknown, 0},
	}
	for _, c := range cases {
		kind, r, err := decodeKey(keyReader(c.in))
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("%q: %v", c.in, err)
		}
		if kind != c.kind {
			t.Errorf("%q decoded as kind %d, want %d", c.in, kind, c.kind)
		}
		if c.kind == keyRune && r != c.r {
			t.Errorf("%q decoded as rune %q, want %q", c.in, r, c.r)
		}
	}
}

// TestEditorEditing pins the edit operations themselves.
func TestEditorEditing(t *testing.T) {
	e := newEditor()
	e.insert([]rune("hello world"))
	e.cursor = 5

	e.insert([]rune(" there"))
	if got := e.String(); got != "hello there world" {
		t.Fatalf("insert in the middle gave %q", got)
	}

	if !e.backspace() {
		t.Fatal("backspace refused at a non-zero cursor")
	}
	if got := e.String(); got != "hello ther world" {
		t.Fatalf("backspace gave %q", got)
	}

	e.cursor = 0
	if e.backspace() {
		t.Fatal("backspace at the start deleted something")
	}

	e.killToEnd()
	if got := e.String(); got != "" {
		t.Fatalf("killToEnd at the start left %q", got)
	}
}

// TestKillWord pins Ctrl-W, which is the binding an operator's fingers rely on and
// the one whose off-by-one is invisible until it eats the wrong word.
func TestKillWord(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"ls -la /tmp", "ls -la "},
		{"ls -la ", "ls "},
		{"one", ""},
		{"", ""},
	} {
		e := newEditor()
		e.insert([]rune(c.in))
		e.killWord()
		if got := e.String(); got != c.want {
			t.Errorf("killWord(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestHistoryWalk pins that walking back and forward returns the fresh line, which is
// the property that makes Up safe to press while composing something long.
func TestHistoryWalk(t *testing.T) {
	e := newEditor()
	e.record("first")
	e.record("second")
	e.record("second") // a repeat is not recorded twice
	e.record("   ")    // blank is not recorded

	if len(e.history) != 2 {
		t.Fatalf("history holds %d entries, want 2: %q", len(e.history), e.history)
	}

	e.insert([]rune("half typed"))
	if !e.up() {
		t.Fatal("up did nothing with history present")
	}
	if got := e.String(); got != "second" {
		t.Fatalf("first up gave %q", got)
	}
	e.up()
	if got := e.String(); got != "first" {
		t.Fatalf("second up gave %q", got)
	}
	if e.up() {
		t.Fatal("up walked past the oldest entry")
	}
	e.down()
	e.down()
	if got := e.String(); got != "half typed" {
		t.Fatalf("walking forward did not restore the fresh line, got %q", got)
	}
	if e.down() {
		t.Fatal("down walked past the fresh line")
	}
}

// TestHistoryIsBounded pins the ceiling: an unbounded history is a slow leak in a
// long-lived session.
func TestHistoryIsBounded(t *testing.T) {
	e := newEditor()
	for i := 0; i < historySize+50; i++ {
		e.record(strings.Repeat("x", 3) + string(rune('a'+i%26)) + string(rune('0'+i%10)))
	}
	if len(e.history) > historySize {
		t.Fatalf("history grew to %d entries, ceiling is %d", len(e.history), historySize)
	}
}

// TestWordAndCandidate pins the completion application: the word before the cursor is
// replaced and everything after it is kept.
func TestWordAndCandidate(t *testing.T) {
	e := newEditor()
	e.insert([]rune("help stat"))
	e.cursor = len(e.line) - 1 // inside "stat", after "sta"

	if got := e.word(); got != "sta" {
		t.Fatalf("word is %q, want %q", got, "sta")
	}
	next := e.withCandidate("status")
	if got := next.String(); got != "help status" {
		t.Fatalf("candidate gave %q, want %q", got, "help status")
	}
	if next.cursor != len([]rune("help status")) {
		t.Fatalf("cursor landed at %d, want %d", next.cursor, len([]rune("help status")))
	}
}

// TestCommonPrefix pins the shell rule: one match completes, several extend to their
// common prefix, none rings the bell (which the caller does).
func TestCommonPrefix(t *testing.T) {
	cases := []struct {
		word    string
		matches []string
		want    string
		wantN   int
	}{
		{"", nil, "", 0},
		{"st", []string{"status"}, "status", 0},
		{"st", []string{"status", "start"}, "sta", 2},
		{"x", []string{"xy", "xz"}, "x", 2},
		{"a", []string{"ab", "ac", "ad"}, "a", 3},
	}
	for _, c := range cases {
		got := buildCompletion(c.word, c.matches)
		if got.prefix != c.want || len(got.candidates) != c.wantN {
			t.Errorf("buildCompletion(%q, %q) = {%q, %d}, want {%q, %d}",
				c.word, c.matches, got.prefix, len(got.candidates), c.want, c.wantN)
		}
	}
}

// TestCompletionRoundTrip pins the wire format: a completion encoded by the daemon is
// decoded by the client to the same thing, including the case where no candidate
// contains the separator.
func TestCompletionRoundTrip(t *testing.T) {
	for _, c := range []completion{
		{},
		{prefix: "status"},
		{prefix: "sta", candidates: []string{"status", "start"}},
	} {
		got := decodeCompletion(c.encode())
		if got.prefix != c.prefix || len(got.candidates) != len(c.candidates) {
			t.Errorf("round trip of %+v gave %+v", c, got)
		}
	}
	for i, cand := range decodeCompletion(completion{prefix: "a", candidates: []string{"a", "b"}}.encode()).candidates {
		if cand != []string{"a", "b"}[i] {
			t.Fatalf("candidate %d round tripped as %q", i, cand)
		}
	}
}

// TestCandidateWithTheSeparatorIsDropped pins the one input that would break the wire
// format. The separator is 0x02 and every command name is validated to lowercase
// letters, digits, '-' and ':', so the only way it can arrive is a component returning
// arbitrary bytes from Complete. Dropping such a candidate is the honest response:
// encoding it would split into two candidates, and a completion that invents one is
// worse than a completion that offers fewer.
func TestCandidateWithTheSeparatorIsDropped(t *testing.T) {
	got := buildCompletion("a", []string{"a\x02b", "abc", "abd"})
	for _, c := range got.candidates {
		if strings.ContainsRune(c, rune(candidateSeparator)) {
			t.Fatalf("a candidate containing the separator survived: %q", c)
		}
	}
	if len(got.candidates) != 2 {
		t.Fatalf("candidates are %q, want the two clean matches", got.candidates)
	}
}

// TestRenderIsCorrectForEveryEdit pins the two render paths against each other: the
// fast append path must produce the same SCREEN as the full repaint. A terminal is a
// state machine, so the assertion is on the byte stream a terminal would receive.
func TestRenderIsCorrectForEveryEdit(t *testing.T) {
	e := newEditor()
	var out strings.Builder
	apply := func(s string) { out.WriteString(s) }

	// Type "abc" one character at a time: the fast path.
	for _, r := range "abc" {
		e.insert([]rune{r})
		render(apply, e)
	}
	if got := out.String(); got != "abc" {
		t.Fatalf("typing three characters emitted %q, want %q", got, "abc")
	}

	// Move the cursor left and insert: the full path, and it must repaint from the
	// start because the character goes in the middle.
	out.Reset()
	e.cursor = 1
	e.insert([]rune{'X'})
	render(apply, e)
	got := out.String()
	if !strings.HasPrefix(got, "\r") || !strings.Contains(got, "\x1b[K") {
		t.Fatalf("an edit in the middle did not repaint: %q", got)
	}
	if !strings.HasSuffix(got, "\x1b[2D") {
		t.Fatalf("the cursor was not moved back two columns: %q", got)
	}
}
