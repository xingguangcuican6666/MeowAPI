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
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A session is one attached terminal. It owns a connection, an authentication
// state, and the loop that reads commands and writes results.
//
// Sessions are independent and concurrent. One that hangs in a slow command does
// not stop another from being served, and one that is killed does not take the
// kernel with it - which is the property the owner asked for and the reason the
// daemon is a separate process from the terminal in the first place.

// maxPasswordAttempts bounds guessing. A local user who can reach the socket can
// open sessions without limit, and without a cap a password becomes a brute-force
// target at local speed. The cap is per session and the session is dropped when it
// is reached, so the cost of a guess is a reconnect rather than nothing.
const maxPasswordAttempts = 5

// passwordBackoff is the delay after a wrong password. It is short enough that an
// operator who mistypes does not notice and long enough that five attempts cost
// more than a second, which is the difference between a guess and a campaign.
const passwordBackoff = 400 * time.Millisecond

// readTimeout bounds how long a session may sit idle. A connection that is open
// and silent forever is a file descriptor the daemon holds for nobody, and a
// client that died without closing is indistinguishable from one that is thinking.
// The timeout is reset by every line, so an operator reading output is not
// disconnected; only an abandoned connection is.
const readTimeout = 30 * time.Minute

// Session is one connection's state. The exported fields are what the daemon and
// the command bodies need; everything else is private because a command body must
// not be able to reach into another session or flip this one's authentication.
type Session struct {
	id   int64
	conn net.Conn
	d    *Daemon

	// reader is created once per connection and used by every read, including the
	// ones inside `auth` and `passwd`, so a line split across two TCP-ish writes is
	// never half-consumed by one read and half by the next.
	reader *boundedReader

	// out serializes writes to the connection. Two goroutines write to one
	// session - the read loop and the log follower - and an interleaved write
	// would garble both.
	out sync.Mutex

	// authenticated is written by the read loop and read by command dispatch and
	// by the follower, so it is atomic rather than a plain bool.
	authenticated atomic.Bool

	// following is set while `log -f` is streaming, so the read loop stops
	// printing prompts into the middle of it and the follower knows when to stop.
	following atomic.Bool

	attempts int

	// Set by command bodies; read by the loop after the command returns.
	closeRequested    bool
	poweroffRequested bool

	// closed is set when the connection is finished with, so a follower or any
	// other long-running body can notice without doing a read, which would steal
	// the next command line.
	closed atomic.Bool
}

// isClosed reports whether this session's connection is finished. It is a method
// rather than a field read because a command body must not be able to write it.
func (s *Session) isClosed() bool { return s.closed.Load() }

// Authenticated reports whether this session has passed the password gate.
func (s *Session) Authenticated() bool { return s.authenticated.Load() }

// ID is the session number, for a status line and for the daemon's own log.
func (s *Session) ID() int64 { return s.id }

// write sends bytes to the client verbatim. Only control messages use it, because
// verbatim means an unquoted control byte at the start of a line would be read by
// the client as a protocol message rather than as text.
func (s *Session) write(raw string) error {
	s.out.Lock()
	defer s.out.Unlock()
	if raw == "" {
		return nil
	}
	// A write deadline keeps a client that stopped reading from blocking the
	// daemon's goroutine forever. A peer that is suspended mid-read is a real case,
	// and a deadline turns it into a closed session rather than a stuck goroutine.
	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := io.WriteString(s.conn, raw)
	return err
}

// print sends output text, quoting a leading control byte first.
//
// Every caller that is not sending a control message goes through this, and the
// reason is that output text is attacker-influenced: a module chooses its own log
// messages, a component chooses what its command returns. A line beginning with the
// control byte would otherwise turn off a client's echo or fake a prompt.
func (s *Session) print(text string) error {
	if text == "" {
		return nil
	}
	return s.write(escapeControl(text))
}

// printf writes formatted output.
func (s *Session) printf(format string, args ...any) error {
	return s.print(fmt.Sprintf(format, args...))
}

// prompt writes a prompt as a control message, so the client prints it with no
// trailing newline and the cursor waits after it.
func (s *Session) prompt(text string) error {
	return s.write(control(ctrlPrompt, text))
}

// serve runs the session to completion. It returns when the client disconnects,
// when `quit` runs, when the read timeout expires, or when `poweroff` asks the
// daemon to stop.
func (s *Session) serve() {
	defer func() {
		// A panic in a command body must not take the daemon down. The kernel
		// recovers module panics for the same reason; this is the host's copy of
		// that rule for host code.
		if r := recover(); r != nil {
			_ = s.printf("internal error: %v\n", r)
		}
		// Set before the connection is closed, so a follower still in its select
		// sees the reason rather than racing the close.
		s.closed.Store(true)
		_ = s.write(control(ctrlBye, ""))
		_ = s.conn.Close()
		s.d.forget(s)
	}()

	_ = s.print(banner(s.d))
	if s.d.credentials == nil {
		_ = s.print("no operator password is set; run `passwd` to set one\n")
	} else if !s.d.credentialSet() {
		_ = s.print("no operator password is set; run `passwd` to set one\n")
	}
	_ = s.prompt(prompt)

	for {
		line, err := s.readLine()
		if err != nil {
			// A client that half-closed its write side has asked for a clean end,
			// which is what a pipe running out of commands looks like. The goodbye
			// is still sent - the deferred teardown does that - so a scripted client
			// gets the output of everything it asked for before the socket closes.
			if errors.Is(err, io.EOF) {
				return
			}
			_ = s.printf("%v\n", err)
			return
		}
		// A control message is not a command. Completion is answered here, in the
		// same goroutine that would otherwise be running a command, because a
		// session is one conversation: an operator cannot complete a word while a
		// command is still producing output, and pretending otherwise would need a
		// second reader on the same connection.
		if kind, payload, ok := isControl(line); ok {
			if kind == ctrlComplete {
				lineText, word, _ := strings.Cut(payload, string(rune(completeFieldSeparator)))
				_ = s.write(control(ctrlComplete, s.d.complete(s, lineText, word).encode()))
			}
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			_ = s.prompt(prompt)
			continue
		}

		done, err := s.execute(line)
		if err != nil {
			_ = s.printf("%v\n", err)
		}
		if done {
			return
		}
		_ = s.prompt(prompt)
	}
}

// readLine reads one protocol line with the idle deadline applied.
func (s *Session) readLine() (string, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(readTimeout))
	line, err := s.reader.ReadLine()
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", errors.New("session idle for too long; disconnecting")
		}
		return "", err
	}
	return line, nil
}

// execute parses and runs one line. It reports whether the session should end.
//
// A line may hold a pipeline: `log -n 50 | grep error | head`. Each stage's output is
// the next stage's stdin. There is still no shell - no quoting, no globbing, no
// variables, no redirection - so a `|` inside an argument is impossible to express,
// which is the same trade split() makes for spaces and is the reason a command cannot
// be tricked into reading a file by a metacharacter.
func (s *Session) execute(line string) (bool, error) {
	stages := strings.Split(line, "|")
	if len(stages) > maxPipelineStages {
		return false, fmt.Errorf("a pipeline may have at most %d stages", maxPipelineStages)
	}

	s.closeRequested = false
	s.poweroffRequested = false

	var stdin string
	for i, stage := range stages {
		name, args := split(stage)
		if name == "" {
			// An empty stage is a syntax error rather than skipped, because `a | | b`
			// almost certainly means the operator meant something else, and guessing
			// what would hide the mistake.
			return false, fmt.Errorf("stage %d of the pipeline is empty", i+1)
		}
		out, err := s.runStage(name, args, stdin)
		if err != nil {
			// The error is RETURNED rather than printed here, so the caller has one
			// place that reports a failed command - the serve loop - and a pipeline
			// stage's failure is not printed twice. The stages after a failed one do
			// not run, which is what a shell does and what makes `a | b` mean "b saw
			// a's output" rather than "b saw a's output, unless a failed".
			if len(stages) > 1 {
				return s.closeRequested || s.poweroffRequested,
					fmt.Errorf("stage %d (%s): %w", i+1, name, err)
			}
			return s.closeRequested || s.poweroffRequested, err
		}
		stdin = out
	}

	if stdin != "" {
		_ = s.print(stdin)
	}

	// Asked for asynchronously rather than stopped from here, so this session can
	// finish printing its own output and run its teardown while the kernel unwinds.
	// Stopping synchronously would close the connection under the command body that
	// requested the stop.
	if s.poweroffRequested {
		s.d.RequestPoweroff(s.id)
	}
	return s.closeRequested || s.poweroffRequested, nil
}

// maxPipelineStages bounds one pipeline. Each stage holds its output in memory before
// the next stage sees it, so an unbounded chain is an unbounded buffer.
const maxPipelineStages = 16

// runStage resolves and runs one stage with the previous stage's output as its stdin.
func (s *Session) runStage(name string, args []string, stdin string) (string, error) {
	e, ok := s.d.table.Lookup(name)
	if !ok {
		return "", fmt.Errorf("%q: no such command; try `help`", name)
	}
	if e.privileged && !s.authenticated.Load() {
		return "", fmt.Errorf("%q needs an authenticated session; run `auth` first", name)
	}

	switch {
	case e.builtin != nil:
		return e.builtin.Run(s, args, stdin)
	case e.module != nil:
		return s.runModuleCommand(e.module, args, stdin)
	default:
		return "", fmt.Errorf("%q has no body", name)
	}
}

// runModuleCommand invokes a contributed command under its component's own
// context, with a deadline and with panics recovered.
//
// The deadline matters because the command body is code this process loaded from
// disk but did not write: a component that blocks forever would otherwise hold a
// session goroutine forever. The kernel's own supervised work has a deadline for
// the same reason.
func (s *Session) runModuleCommand(mc *moduleCommand, args []string, stdin string) (string, error) {
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)

	go func() {
		// The buffer of 1 means this send never blocks even if the caller has
		// already given up, so the goroutine cannot leak on a timeout.
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("the command panicked: %v", r)}
			}
		}()
		out, err := mc.cmd.Run(mc.ctx, args, stdin)
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		return r.out, r.err
	case <-time.After(commandTimeout):
		// Reported rather than cancelled: there is no way to stop a goroutine
		// that is not cooperating, and pretending otherwise would be the same
		// mistake kwatchdog documents. What is true is that the session moves on
		// and the component's work is left to finish or hang on its own.
		return "", fmt.Errorf("the command did not return within %s", commandTimeout)
	}
}

// commandTimeout bounds one contributed command.
const commandTimeout = 30 * time.Second

// authenticate runs the password exchange: echo off, prompt, read, echo on,
// check. The plaintext is never written to the connection, never logged, and
// never stored - only the derived hash is compared.
func (s *Session) authenticate() error {
	if s.attempts >= maxPasswordAttempts {
		return errors.New("too many failed attempts; this session is closed")
	}

	// The order is load-then-prompt rather than prompt-then-load, because a load
	// failure (an unreadable shadow file) should be reported before the operator
	// has typed anything into a gate that cannot check it.
	check, err := s.d.passwordChecker()
	if err != nil {
		if errors.Is(err, ErrNoCredential) {
			return errors.New("no password is set; run `passwd` first")
		}
		return err
	}

	if !echoSupported {
		// Said before the password is typed rather than after: an operator on a
		// platform this build cannot control echo on deserves to know their typing
		// is about to be displayed.
		_ = s.print("warning: this build cannot hide what you type\n")
	}
	_ = s.write(control(ctrlNoEcho, ""))
	_ = s.prompt(passwordPrompt)
	pw, err := s.readLine()
	_ = s.write(control(ctrlEcho, ""))
	// A newline of our own, because the client did not echo the one the operator
	// typed and the cursor is still on the prompt line.
	_ = s.print("\n")
	if err != nil {
		return err
	}

	if !check(pw) {
		s.attempts++
		time.Sleep(passwordBackoff)
		// One message for wrong, absent and unreadable, so the session is not an
		// oracle for which of them happened. The distinction is preserved in the
		// daemon's own log, where it belongs.
		s.d.logf("session %d: failed password attempt %d of %d", s.id, s.attempts, maxPasswordAttempts)
		if s.attempts >= maxPasswordAttempts {
			s.closeRequested = true
			return errors.New("too many failed attempts; this session is closed")
		}
		return errors.New("authentication failed")
	}

	s.authenticated.Store(true)
	s.attempts = 0
	s.d.logf("session %d: authenticated", s.id)
	return nil
}

// changePassword sets or rotates the operator password.
//
// The rules are the ones the owner set: a hash on disk, never the plaintext, and
// a rotation that requires the current password so that an open session on an
// unattended terminal is not a way to lock the operator out - or, worse, a way for
// whoever is at that terminal to become the operator.
//
// First boot is the exception and it is a deliberate one. With no record on disk
// there is no current password to prove, and the thing that makes this safe is the
// socket's own permission: it is 0600 in a 0700 directory, so the only sessions
// that can reach this point belong to the user who owns the state directory. That
// is the same trust boundary the shadow file itself sits behind.
func (s *Session) changePassword() error {
	store := s.d.credentials
	if store == nil {
		return errors.New("no credential store is configured")
	}

	existing, err := store.Load()
	haveRecord := err == nil
	if err != nil && !errors.Is(err, ErrNoCredential) {
		return err
	}

	if haveRecord {
		if !s.authenticated.Load() {
			// An authenticated session is proof enough when there is one; asking
			// for the old password again would be asking for the same secret twice
			// in one exchange, and the first ask was already checked.
			return errors.New("`passwd` needs an authenticated session; run `auth` first")
		}
		_ = s.write(control(ctrlNoEcho, ""))
		_ = s.prompt("Current password: ")
		cur, rerr := s.readLine()
		_ = s.write(control(ctrlEcho, ""))
		_ = s.print("\n")
		if rerr != nil {
			return rerr
		}
		if !existing.Check(cur) {
			return errors.New("the current password is wrong")
		}
	}

	_ = s.write(control(ctrlNoEcho, ""))
	_ = s.prompt("New password: ")
	first, err := s.readLine()
	_ = s.print("\n")
	if err != nil {
		_ = s.write(control(ctrlEcho, ""))
		return err
	}
	_ = s.prompt("Repeat new password: ")
	second, err := s.readLine()
	_ = s.write(control(ctrlEcho, ""))
	_ = s.print("\n")
	if err != nil {
		return err
	}
	if first != second {
		return errors.New("the two entries do not match; nothing was changed")
	}
	if first == "" {
		return errors.New("an empty password was refused; nothing was changed")
	}

	cred, err := HashPassword(first, CurrentIterations)
	if err != nil {
		return err
	}
	if err := store.Save(cred); err != nil {
		return err
	}

	// This session is now authenticated against the new record. It already was,
	// or it just proved the old password and set a new one; either way there is no
	// reason to make the operator re-type. Other sessions keep their own state,
	// which is correct: rotating a password does not retroactively authorise a
	// session that was authenticated against the previous one, and it does not
	// revoke one that is already open. Revoking those is `poweroff`.
	s.authenticated.Store(true)

	s.d.logf("session %d: the operator password was %s", s.id, map[bool]string{true: "rotated", false: "set"}[haveRecord])
	return nil
}

// split separates a command name from its arguments.
//
// There is deliberately no quoting and no shell interpretation. An argument is a
// run of non-space bytes, and a component that needs structured input takes a
// flag rather than a quoted string. A shell parser here would be a shell
// injection surface, and every command in this table is reachable by whoever holds
// the socket.
func split(line string) (name string, args []string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil
	}
	return strings.ToLower(fields[0]), fields[1:]
}
