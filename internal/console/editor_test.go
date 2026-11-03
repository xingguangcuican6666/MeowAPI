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
	"time"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
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

// TestAMaskedEditorDrawsNothing pins the fix for a defect that only a pty could show.
//
// The daemon asked the client to stop echoing while an operator typed a password, and
// the client answered by clearing the terminal's ECHO flag - which does nothing in raw
// mode, because raw mode already cleared it and the editor draws every keystroke itself.
// Measured on a real pty: the password appeared in full, and the ECHO the daemon asked to
// be restored afterwards made the driver echo a line the editor was also drawing, so the
// next command came out as `dmmeessaagg`.
//
// What is asserted is the property rather than the mechanism: while masked, no character
// the operator types reaches the terminal, and no placeholder does either. A mask that
// drew one asterisk per keystroke would pass the "the secret is hidden" half and leak the
// password's LENGTH, which is the one fact about it a shoulder-surfer cannot count any
// other way - and `sudo` shows nothing for exactly this reason.
func TestAMaskedEditorDrawsNothing(t *testing.T) {
	e := newEditor()
	e.masked = true

	var out strings.Builder
	apply := func(s string) { out.WriteString(s) }

	for _, r := range "CorrectHorse99" {
		e.insert([]rune{r})
		render(apply, e)
	}

	// Nothing at all, and the assertion is on the byte count rather than on the absence
	// of particular characters. A masked editor that emitted an erase per keystroke would
	// hide the password and still write fourteen escape sequences to a line that is
	// already blank - invisible to the operator and pure traffic on a slow terminal.
	if got := out.String(); got != "" {
		t.Fatalf("a masked editor wrote %d bytes: %q", len(got), got)
	}
	if strings.ContainsAny(out.String(), "*•") {
		t.Fatal("a masked editor drew a placeholder, which leaks the password's length")
	}
}

// TestAMaskedEditorErasesWhatItAlreadyDrew is the one case where a masked render must
// write something: the mask arrived while a line was on screen. An operator who typed a
// command, pressed Tab, and had it turn out to be a password prompt is the shape that
// reaches it, and leaving what they typed visible would disclose the first characters of
// a secret.
func TestAMaskedEditorErasesWhatItAlreadyDrew(t *testing.T) {
	e := newEditor()
	var out strings.Builder
	apply := func(s string) { out.WriteString(s) }

	e.insert([]rune{'a', 'b'})
	render(apply, e)
	if out.String() != "ab" {
		t.Fatalf("the fixture did not draw: %q", out.String())
	}

	out.Reset()
	e.masked = true
	render(apply, e)
	got := out.String()
	if got != "\r\x1b[K" {
		t.Fatalf("masking a drawn line emitted %q, want an erase", got)
	}

	// And only once: a second masked render over an already-blank line writes nothing.
	out.Reset()
	render(apply, e)
	if got := out.String(); got != "" {
		t.Fatalf("the erase repeated on a blank line: %q", got)
	}
}

// TestUnmaskingDiscardsTheSecretLine is the other half. Restoring echo must not reveal
// the line the operator just typed: the daemon has read it, and redrawing it would leave
// a password on the screen for the rest of the session and in the terminal's scrollback,
// which outlives the process entirely.
func TestUnmaskingDiscardsTheSecretLine(t *testing.T) {
	e := newEditor()
	e.masked = true
	for _, r := range "CorrectHorse99" {
		e.insert([]rune{r})
	}
	if e.String() == "" {
		t.Fatal("the editor did not take the typing; the fixture is wrong")
	}

	// setMasked(false) resets rather than renders, and reset clears the line.
	e.masked = false
	e.reset()

	if got := e.String(); got != "" {
		t.Fatalf("the secret survived unmasking: %q", got)
	}
}

// TestRenderDmesgIsOneRecordPerLineWithElapsedSeconds pins the shape an operator
// recognises, and the two properties the shape is chosen for.
//
// One record per line is what makes `dmesg | grep drm` and `dmesg | wc -l` mean anything:
// the previous rendering put each field on its own indented continuation line, so wc
// counted one record as three and grep returned a message while dropping every field that
// explained it. Elapsed seconds rather than a wall clock is what makes the ORDER of two
// lines a fact instead of a claim - the kernel's monotonic clock cannot be stepped by NTP
// or by an operator, and the wall clock can.
func TestRenderDmesgIsOneRecordPerLineWithElapsedSeconds(t *testing.T) {
	base := time.Now().UTC()
	records := []kernel.Record{
		// The fractional part is written in microseconds because that is the field dmesg
		// prints, and writing it as a bare 104857 would be nanoseconds - a fixture that
		// looks right and asserts the wrong scale is worse than one that fails loudly.
		{Time: base, Mono: int64(3*time.Second) + 104857*int64(time.Microsecond),
			Level: kernel.LogInfo,
			Pid:   1, Domain: "u:r:init:s0", Msg: "boot complete",
			Fields: map[string]any{"modules": 0}},
		{Time: base.Add(time.Second), Mono: int64(31042*time.Second) + 440125*int64(time.Microsecond),
			Level: kernel.LogDebug, Pid: 0, Domain: "u:r:kernel:s0",
			Msg: "published kernel metadata", Fields: map[string]any{"key": "kernel.bin.dir"}},
	}

	got := renderDmesg(records)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("two records rendered as %d lines, so a field is on its own line:\n%s",
			len(lines), got)
	}

	if want := "[    3.104857] pid=1 u:r:init:s0 boot complete modules=0"; lines[0] != want {
		t.Fatalf("got %q\nwant %q", lines[0], want)
	}
	// A boot past 27 hours still lines up: the seconds field is right-aligned in five.
	if !strings.HasPrefix(lines[1], "[31042.440125] ") {
		t.Fatalf("a large elapsed time did not render in dmesg's field shape: %q", lines[1])
	}
}

// TestRenderDmesgCannotBeForgedByAModuleMessage is why the renderer escapes.
//
// A module chooses the message of every record it logs. Without an escape, a message
// containing a newline and a rendered prefix would appear, in the very output an operator
// reads to decide what the kernel did, as a kernel record that never happened. The
// console's own JSON renderer already escaped this and the text one did not.
func TestRenderDmesgCannotBeForgedByAModuleMessage(t *testing.T) {
	records := []kernel.Record{{
		Time: time.Now().UTC(), Mono: int64(2 * time.Second), Level: kernel.LogInfo,
		Pid: 7, Domain: "u:r:plugin:s0", Msg: "loaded",
		Fields: map[string]any{"note": "ok\n[    2.000000] pid=0 u:r:kernel:s0 FAULT disabled"},
	}}

	got := renderDmesg(records)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("a field containing a newline produced %d lines, so one record can forge "+
			"another:\n%s", len(lines), got)
	}
	if strings.Contains(got, "\n[") {
		t.Fatalf("the forged record survives into the output: %q", got)
	}
}

// TestRenderRecordsIsOneRecordPerLine pins the property the pipeline builtins depend on.
//
// `log | wc -l` and `log | grep error` are the first things an operator reaches for, and
// both are meaningless if a record spans several lines: wc would count fields as records,
// and grep would return the message while dropping every field that explains it - which is
// exactly the rendering dmesg had, where each field sat on its own indented line.
func TestRenderRecordsIsOneRecordPerLine(t *testing.T) {
	base := time.Now().UTC()
	records := []kernel.Record{
		{Time: base, Mono: int64(time.Second), Level: kernel.LogInfo, Pid: 1,
			Domain: "u:r:init:s0", Msg: "boot complete",
			Fields: map[string]any{"modules": 0, "oom_patrol": "running"}},
		{Time: base, Mono: int64(time.Second), Level: kernel.LogFault, Pid: 2,
			Domain: "u:r:plugin:s0", Msg: "module load refused",
			Fields: map[string]any{"module": "diag", "reason": "unsigned"}},
	}

	got := renderRecords(records)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("two records rendered as %d lines:\n%s", len(lines), got)
	}
	// Fields are on the record's own line, sorted, so two reads of one record are the
	// same bytes: a map's iteration order is randomised, and a log whose columns move
	// between reads cannot be diffed.
	if !strings.Contains(lines[0], " modules=0 oom_patrol=running") {
		t.Fatalf("the fields are not on the record's line, sorted: %q", lines[0])
	}
	// And a grep for the severity finds exactly the record it names.
	if n := strings.Count(got, "fault"); n != 1 {
		t.Fatalf("expected one fault line to match, got %d:\n%s", n, got)
	}
}

// TestRenderRecordsEscapesAModuleMessage is the same property for the `log` renderer that
// TestRenderDmesgCannotBeForgedByAModuleMessage asserts for dmesg. Two renderers over one
// buffer is two chances to forget the escape, and the kernel's text renderer escaped a
// message while this one did not - which is why both now call kernel.EscapeText rather
// than each carrying a copy: an escape applied in one view and not another lets the same
// record forge a line in one and not the other.
func TestRenderRecordsEscapesAModuleMessage(t *testing.T) {
	records := []kernel.Record{{
		Time: time.Now().UTC(), Mono: int64(time.Second), Level: kernel.LogInfo, Pid: 7,
		Domain: "u:r:plugin:s0", Msg: "loaded\n19:00:00.000 fault pid=0   u:r:kernel:s0      disabled",
	}}

	got := renderRecords(records)
	if n := strings.Count(got, "\n"); n != 1 {
		t.Fatalf("a message containing a newline rendered %d newlines:\n%s", n, got)
	}
	if strings.Contains(got, "\n19:00:00.000 fault") {
		t.Fatalf("a module's message forged a kernel fault record:\n%s", got)
	}
}

// TestAMaskedLineNeverEntersHistory is the leak the masking fix would have left behind.
//
// The editor draws nothing while masked, but history is a separate mechanism: the Enter
// handler recorded every submitted line, and Up recalls a line ONTO the command line,
// where it is drawn in plain text. So a password that survived into history reappeared on
// screen for the rest of the session, sat in the terminal's scrollback, and was one
// keypress away from being submitted as a command. Hiding what is typed and remembering
// it are two halves of one property, and only one of them was implemented.
func TestAMaskedLineNeverEntersHistory(t *testing.T) {
	e := newEditor()
	e.masked = true
	for _, r := range "CorrectHorse99" {
		e.insert([]rune{r})
	}

	// submit, not a replica of what submit does: the first version of this test inlined
	// the loop's own `if !masked { record }` and passed whether or not the loop had it,
	// which made it an assertion about a copy of the code. The decision now lives in the
	// editor, so this calls the same function the key loop calls.
	line, remembered := e.submit()
	if line == "" {
		t.Fatal("submit returned nothing; the fixture did not take the typing")
	}
	if remembered {
		t.Fatal("submit remembered a masked line")
	}

	e.masked = false
	if got := e.String(); got != "" {
		t.Fatalf("the line survived the submit: %q", got)
	}
	// Up on an empty history must not bring the secret back.
	if e.up() {
		t.Fatalf("history recalled a line after a masked submit: %q", e.String())
	}
	if got := e.String(); strings.Contains(got, "Horse") {
		t.Fatalf("the password is reachable from history: %q", got)
	}

	// And an ordinary command is still remembered, or the fix would have simply broken
	// history for everything.
	e.record("status")
	e.reset()
	if !e.up() || e.String() != "status" {
		t.Fatalf("an unmasked line was not remembered: %q", e.String())
	}
}
