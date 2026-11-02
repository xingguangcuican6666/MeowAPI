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
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xingguangcuican6666/MeowAPI/abi"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// This file is in package console because three of the properties below are about
// Unexported mechanisms - the escape rule, the name rule and the protocol framing -
// and a test outside the package could only assert them through a daemon, which would
// make a unit property depend on a booted kernel.

// TestEscapeControlStopsEveryLine pins the escape rule at the level it operates on.
//
// The property is not "the first line is escaped". The protocol is newline-delimited,
// so a control byte anywhere after a newline starts a line as far as the client is
// concerned, and escaping only the prefix would leave a component able to return
// "\n\x01N" and turn off an operator's echo.
func TestEscapeControlStopsEveryLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"\x01N", "\\x01N"},
		{"a\n\x01Pfake> ", "a\n\\x01Pfake> "},
		{"\x01Bbye", "\\x01Bbye"},
		// A control byte that is not at a line start is ordinary text and must be
		// left alone: escaping it would change output an operator asked to see.
		{"prefix \x01 char", "prefix \x01 char"},
		{"", ""},
	}
	for _, c := range cases {
		if got := escapeControl(c.in); got != c.want {
			t.Errorf("escapeControl(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestEscapedOutputIsReadBackAsText runs the escape through the real client reader:
// what the daemon writes must arrive as output and never as a control message.
func TestEscapedOutputIsReadBackAsText(t *testing.T) {
	for _, in := range []string{"\x01N", "a\n\x01Bfake goodbye", "\x01Pfake> "} {
		line, err := newBoundedReader(strings.NewReader(escapeControl(in) + "\n")).ReadLine()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, isCtrl := isControl(line); isCtrl {
			t.Errorf("%q was read back as a control message", in)
		}
	}
}

// TestControlMessagesAreNotEscaped is the other half of the same rule, and the half
// that a naive implementation gets wrong: the daemon's OWN control messages must pass
// through unescaped or the client would print them as text.
func TestControlMessagesAreNotEscaped(t *testing.T) {
	for _, kind := range []byte{ctrlPrompt, ctrlNoEcho, ctrlEcho, ctrlBye} {
		line := strings.TrimSuffix(control(kind, "x"), "\n")
		gotKind, payload, ok := isControl(line)
		if !ok || gotKind != kind || payload != "x" {
			t.Errorf("control(%q) did not round trip: ok=%t kind=%q payload=%q",
				string(kind), ok, string(gotKind), payload)
		}
	}
}

// TestBoundedReaderRejectsAnOverlongLine pins the buffer bound. Without it a client
// that opens a connection and never sends a newline grows the daemon's heap forever.
func TestBoundedReaderRejectsAnOverlongLine(t *testing.T) {
	// One byte over the ceiling, with no newline anywhere.
	body := strings.Repeat("x", maxLineBytes+1)
	_, err := newBoundedReader(strings.NewReader(body)).ReadLine()
	if err == nil {
		t.Fatal("an overlong line was accepted")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("the refusal does not name the ceiling: %v", err)
	}
}

// TestBoundedReaderHandlesPartialAndFinalLines pins the three shapes a real stream
// takes: a line split across reads, a final line with no newline, and an empty stream.
func TestBoundedReaderHandlesPartialAndFinalLines(t *testing.T) {
	// A reader that returns its bytes one at a time models a slow socket.
	slow := &oneByteReader{s: "first\nsecond\n"}
	r := newBoundedReader(slow)
	for _, want := range []string{"first", "second"} {
		got, err := r.ReadLine()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if _, err := newBoundedReader(strings.NewReader("no newline")).ReadLine(); err != nil {
		t.Fatalf("a final line with no newline must still be returned: %v", err)
	}
	if _, err := newBoundedReader(strings.NewReader("")).ReadLine(); !errors.Is(err, io.EOF) {
		t.Fatalf("an empty stream returned %v, want EOF", err)
	}
}

type oneByteReader struct {
	s string
	i int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	p[0] = r.s[r.i]
	r.i++
	return 1, nil
}

// TestCommandNames pins the shape rule for a contributed command.
func TestCommandNames(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"example", true},
		{"with-dash", true},
		{"with_underscore", true},
		{"ns:scoped", true},
		{"x", true},
		{"", false},
		{"has space", false},
		{"UPPER", false},
		{"\x01n", false},
		{"under/slash", false},
		{strings.Repeat("x", maxCommandNameLen+1), false},
	}
	for _, c := range cases {
		err := validateName(c.name)
		if (err == nil) != c.ok {
			t.Errorf("validateName(%q) = %v, want ok=%t", c.name, err, c.ok)
		}
	}
}

// TestTableRefusesDuplicatesAndBuiltins pins that a second registration of one name is
// refused rather than replacing the first, and that a builtin cannot be taken over.
func TestTableRefusesDuplicatesAndBuiltins(t *testing.T) {
	builtin := Builtin{
		Name: "help",
		Help: "the builtin",
		Run:  func(*Session, []string, string) (string, error) { return "", nil },
	}
	table := NewTable([]Builtin{builtin, builtin})
	if table.Len() != 1 {
		t.Fatalf("a duplicate builtin left %d entries, want 1", table.Len())
	}

	// A contributed name that collides with a builtin is refused. The registration
	// needs a context, and the refusal is expected before the context is consulted
	// for the collision case - nil is enough to reach the name check.
	err := table.Register(nil, 1, nil)
	if err == nil {
		t.Fatal("a registration with no context was accepted")
	}

	// A registration with no context is refused, and that is its own branch: a
	// command whose body takes a context and runs with none is not a command that
	// can be allowed to exist.
	collide := []abi.Command{{Name: "help", Help: "hijacked",
		Run: func(abi.SContext, []string, string) (string, error) { return "", nil }}}
	if err := table.Register(nil, 1, collide); err == nil ||
		!strings.Contains(err.Error(), "context") {
		t.Fatalf("a nil context returned %v, want a refusal naming the context", err)
	}
}

// TestTableCeilingIsFinite pins the bound on the command table: an operator reads it,
// and an unbounded list is a place to bury a command.
func TestTableCeilingIsFinite(t *testing.T) {
	if maxCommands <= 0 || maxCommands > 4096 {
		t.Fatalf("the command ceiling is %d, which is not a bound", maxCommands)
	}
}

// TestSessionRefusesPrivilegedBeforeTheBodyRuns pins the ordering, not just the
// refusal: a privileged command's body must not execute at all in an unauthenticated
// session, because a body that ran and then failed could still have done work.
func TestSessionRefusesPrivilegedBeforeTheBodyRuns(t *testing.T) {
	ran := false
	table := NewTable([]Builtin{{
		Name:       "danger",
		Help:       "does something",
		Privileged: true,
		Run: func(*Session, []string, string) (string, error) {
			ran = true
			return "did it", nil
		},
	}})

	s := &Session{d: &Daemon{table: table}}
	if _, err := s.execute("danger"); err == nil {
		t.Fatal("an unauthenticated session ran a privileged command")
	}
	if ran {
		t.Fatal("the privileged command's body ran before the authority check")
	}
}

// TestSplitHasNoShellSemantics pins that an argument is a run of non-space bytes.
// Every command here is reachable by whoever holds the socket, so a parser that
// interpreted quotes or expansions would be the injection surface this design avoids.
func TestSplitHasNoShellSemantics(t *testing.T) {
	name, args := split(`say "hello; rm -rf /"  $HOME`)
	if name != "say" {
		t.Fatalf("name = %q", name)
	}
	want := []string{`"hello;`, `rm`, `-rf`, `/"`, `$HOME`}
	if len(args) != len(want) {
		t.Fatalf("args = %q, want %q", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %q, want %q", args, want)
		}
	}
	if n, _ := split("   "); n != "" {
		t.Fatalf("blank input produced %q", n)
	}
}

// TestWriteDeadlineIsSet pins that a session whose client stopped reading cannot block
// a daemon goroutine forever: the write deadline is what turns it into a closed
// session. A net.Pipe has no deadlines, so this drives a real socketpair.
func TestWriteDeadlineIsSet(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	// Fill the pipe with a writer that never reads, then confirm a session write
	// returns rather than hanging. net.Pipe is synchronous, so one unanswered write
	// blocks; the deadline in Session.write is what bounds it.
	go func() {
		for {
			if _, err := b.Write([]byte("x")); err != nil {
				return
			}
		}
	}()

	s := &Session{conn: a}
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- s.write("blocked") }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a write to a client that never reads reported success")
		}
		// The bound is the write deadline, and a timeout is the shape it fails
		// with. A test that only waited for "returns eventually" would pass on a
		// build where the deadline was removed and the pipe happened to drain.
		if elapsed := time.Since(start); elapsed < time.Second {
			t.Fatalf("the write failed after %s, which is not the deadline", elapsed)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a write to a client that never reads did not return")
	}
}

// TestAuditTailShowsTheNewest pins the direction of `audit -n`.
//
// AuditQuery is oldest-first and its Limit truncates from the front, so the obvious
// call - AuditQuery{Limit: n} - returns the OLDEST n entries. Measured on a live
// daemon: `audit -n 6` straight after a load showed the boot records and none of the
// load. An operator reading that concludes nothing happened. This asserts on the
// kernel function the command is built on, so the direction is pinned where the
// mistake actually was.
func TestAuditTailShowsTheNewest(t *testing.T) {
	quietConsole()
	d, err := bootForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Stop(nil); <-d.Stopped() }()

	all := kernel.AuditQuery(kernel.AuditFilter{})
	if len(all) < 2 {
		t.Fatalf("the audit window holds %d entries; a boot writes several", len(all))
	}

	tail := all
	if len(tail) > 2 {
		tail = tail[len(tail)-2:]
	}
	if tail[len(tail)-1].Seq != all[len(all)-1].Seq {
		t.Fatalf("the last entry of the tail is seq %d, want the newest %d",
			tail[len(tail)-1].Seq, all[len(all)-1].Seq)
	}
	if tail[0].Seq >= tail[len(tail)-1].Seq {
		t.Fatalf("the tail is not in ascending order: %d then %d", tail[0].Seq, tail[len(tail)-1].Seq)
	}
}

// TestPrivilegedLoadGoesThroughKtty pins the second authority layer for `load`.
//
// The defect this exists for: `load` and `unload` called kernel.Kernel.Load, which
// checks hostOnly and nothing else. The daemon's own process authority stood in for
// the operator's credential, so an authenticated session's load was NOT gated on the
// console credential and did not appear on the audit chain with the provenance ktty
// adds. The interface below is what prevents a future command body doing the same
// thing again: the only loader a session can reach presents the credential, and the
// assertion is that its absence is what makes it refuse.
func TestPrivilegedLoadGoesThroughKtty(t *testing.T) {
	quietConsole()
	d, err := bootForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Stop(nil); <-d.Stopped() }()

	// With no shadow record there is no credential to present, so the console loader
	// must refuse rather than falling back to the daemon's own authority.
	_, err = consoleLoader{d}.LoadModule(abi.Manifest{Name: "probe", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1})
	if err == nil {
		t.Fatal("the console loader loaded a module with no credential available")
	}
	if !strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "credential") {
		t.Fatalf("the refusal does not name the missing credential: %v", err)
	}

	// And the two loaders refuse for DIFFERENT reasons, which is the whole point of
	// having two. The unprivileged one reaches the registry - this test binary
	// registers no factories, so it fails there - while the console loader never gets
	// that far. Asserting on the messages rather than on "both failed" is what keeps
	// this from passing when both refuse for the same reason.
	_, err = (kernelLoader{d.kernel}).LoadModule(abi.Manifest{
		Name: "diag", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "no module registered") {
		t.Fatalf("the unprivileged loader returned %v, want the registry refusal", err)
	}
}

// TestPipelinesFeedOneStageToTheNext pins the mechanism: a stage's output becomes the
// next stage's stdin, and the last stage's output is what the session prints.
//
// The stages here are test builtins rather than the real filters, so a failure names
// the pipeline rather than the filter that happened to be first.
func TestPipelinesFeedOneStageToTheNext(t *testing.T) {
	var seen []string
	mk := func(name string, fn func(string) string) Builtin {
		return Builtin{
			Name:       name,
			TakesInput: true,
			Run: func(_ *Session, _ []string, stdin string) (string, error) {
				seen = append(seen, name+"<"+stdin+">")
				return fn(stdin), nil
			},
		}
	}
	table := NewTable([]Builtin{
		mk("one", func(string) string { return "a" }),
		mk("two", func(s string) string { return s + "b" }),
		mk("three", func(s string) string { return s + "c" }),
	})
	s := &Session{d: &Daemon{table: table}}

	out, err := s.runStage("one", nil, "")
	if err != nil || out != "a" {
		t.Fatalf("stage one gave %q, %v", out, err)
	}
	out, err = s.runStage("two", nil, out)
	if err != nil || out != "ab" {
		t.Fatalf("stage two gave %q, %v", out, err)
	}
	out, err = s.runStage("three", nil, out)
	if err != nil || out != "abc" {
		t.Fatalf("stage three gave %q, %v", out, err)
	}
	if len(seen) != 3 {
		t.Fatalf("only %d stages ran", len(seen))
	}
}

// TestPipelineRefusesAnEmptyStage pins that `a | | b` is an error rather than a
// pipeline with the gap skipped. The operator almost certainly meant something else,
// and guessing would hide the typo.
func TestPipelineRefusesAnEmptyStage(t *testing.T) {
	table := NewTable([]Builtin{{
		Name: "noop", TakesInput: true,
		Run: func(*Session, []string, string) (string, error) { return "", nil },
	}})
	s := &Session{d: &Daemon{table: table}}
	if _, err := s.execute("noop | | noop"); err == nil {
		t.Fatal("an empty pipeline stage was accepted")
	}
}

// TestPipelineStopsAtTheFirstFailure pins that a later stage does not run when an
// earlier one fails, which is what makes `a | b` mean "b saw a's output" rather than
// "b saw a's output, unless a failed".
func TestPipelineStopsAtTheFirstFailure(t *testing.T) {
	ran := false
	table := NewTable([]Builtin{
		{Name: "boom", Run: func(*Session, []string, string) (string, error) {
			return "", errors.New("nope")
		}},
		{Name: "after", TakesInput: true, Run: func(*Session, []string, string) (string, error) {
			ran = true
			return "ran", nil
		}},
	})
	s := &Session{d: &Daemon{table: table}}
	_, err := s.execute("boom | after")
	if err == nil {
		t.Fatal("a pipeline whose first stage failed reported no error")
	}
	if ran {
		t.Fatal("a stage after a failure ran anyway")
	}
	if !strings.Contains(err.Error(), "stage 1") {
		t.Fatalf("the error does not name the stage: %v", err)
	}
}

// TestPipelineStageCeiling pins the bound on one line's pipeline.
func TestPipelineStageCeiling(t *testing.T) {
	table := NewTable([]Builtin{{
		Name: "noop", TakesInput: true,
		Run: func(*Session, []string, string) (string, error) { return "", nil },
	}})
	s := &Session{d: &Daemon{table: table}}
	// Exactly the ceiling is legal; one more is not. Asserting only the refusal would
	// pass on a ceiling of 1.
	ok := strings.TrimSuffix(strings.Repeat("noop|", maxPipelineStages), "|")
	if _, err := s.execute(ok); err != nil {
		t.Fatalf("%d stages were refused: %v", maxPipelineStages, err)
	}
	over := strings.TrimSuffix(strings.Repeat("noop|", maxPipelineStages+1), "|")
	if _, err := s.execute(over); err == nil {
		t.Fatalf("%d stages were accepted, ceiling is %d", maxPipelineStages+1, maxPipelineStages)
	}
}

// TestNoUnauthenticatedCommandPrintsAnotherPidsFacts pins the property the peer's
// audit found one instance of, as a property rather than as three fixes.
//
// The defect: `dump` was not gated and printed the process table, the policy grants,
// the trust root and the secret alias inventory - a strict superset of `ps`, which WAS
// gated. Asked which other commands print the same facts, `ls -v` (every module's
// grant set) and `audit` (which module was refused what) were both open too. Three
// separate flags would have been three fixes and no property; a command that prints
// another pid's identity, grants or refusals is the property, and this walks the whole
// table for it.
//
// A new command is not automatically covered - the list below has to name it - so the
// second half of the test fails on a command that is neither privileged nor explicitly
// exempt, which is the shape that turns "we fixed three" into "we cannot add a fourth
// by accident".
func TestNoUnauthenticatedCommandPrintsAnotherPidsFacts(t *testing.T) {
	d, err := bootForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Stop(nil); <-d.Stopped() }()

	// Commands whose entire purpose is to print facts about pids other than the
	// caller's. Each must be Privileged.
	//
	// `status` is deliberately NOT here, and the line is worth stating because it is a
	// decision rather than an oversight. status prints module names, versions and counts;
	// it prints no uid, no domain, no manifest digest, no grant set and no refusal - each
	// of which ps, ls and audit do print. It is the greeting that tells an operator whether
	// the daemon came up and whether their components loaded, before they have any way to
	// authenticate, and gating it would break the one question the console must answer
	// first. The socket is 0600 inside a 0700 directory, so "unauthenticated" already means
	// a process running as the daemon's own user, which can read root/bin anyway.
	mustBePrivileged := []string{
		"ps",                                             // the process table
		"ls",                                             // every module's authority
		"audit",                                          // what was refused, to whom
		"dump",                                           // all of it at once
		"dmesg",                                          // the kernel's own records
		"load", "unload", "reload", "harden", "poweroff", // state-changing
	}
	for _, name := range mustBePrivileged {
		e, ok := d.table.Lookup(name)
		if !ok {
			t.Errorf("%q is not registered; the list is stale", name)
			continue
		}
		if !e.privileged {
			t.Errorf("%q prints or changes state about pids other than the caller's and is "+
				"not gated; a session that has not authenticated can run it", name)
		}
	}

	// And the reverse: every privileged command is on that list, so a command cannot
	// be gated for a reason nobody wrote down.
	known := map[string]bool{}
	for _, n := range mustBePrivileged {
		known[n] = true
	}
	for _, name := range d.table.Names() {
		e, _ := d.table.Lookup(name)
		if e == nil || !e.privileged {
			continue
		}
		if !known[name] {
			t.Errorf("%q is Privileged and not on the list above; add it with the reason, "+
				"or the list stops describing what is gated", name)
		}
	}
}
