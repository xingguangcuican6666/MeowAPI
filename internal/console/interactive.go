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
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// The client's interactive loop.
//
// This is the half that makes the console feel like a shell rather than a socket: it
// puts the terminal in raw mode, decodes keystrokes, keeps the line on screen as the
// operator edits it, and asks the daemon to complete a word when Tab is pressed.
//
// Everything here is client-side and per-terminal. None of it touches the kernel, and
// none of it exists when stdin is a pipe - a scripted session reads whole lines and
// sends them, which is what makes `printf 'help\n' | MeowAPI` keep working.

// readKeyFunc is how the editor gets bytes. It is an interface rather than a concrete
// reader because the raw-mode path reads one byte at a time from the terminal while
// the piped path reads lines, and the editor should not care which.
type readKeyFunc func() (byte, error)

// interactive runs the session in raw mode until the daemon closes it or the operator
// leaves. It is the tty path; the piped path is readKeyboard, unchanged.
func (c *client) interactive() error {
	saved, err := rawMode(c.term)
	if err != nil {
		// Falling back to the piped loop is right and is not a silent degradation:
		// the operator gets a working console, just without arrows and Tab. The
		// alternative - refusing the session - would make an unsupported terminal a
		// reason not to talk to the kernel at all.
		c.printf("note: this terminal cannot be put into raw mode (%v); history and\n"+
			"      completion are unavailable\n", err)
		return nil
	}
	// Restored on every exit path, INCLUDING the one where a signal kills the
	// process. A client that leaves the terminal in raw mode makes the shell it
	// returns to unable to show what is typed, and the operator has no way to find
	// out why - worse, they cannot type the command that would fix it.
	//
	// ISIG stays on in rawMode, so Ctrl-C is the kernel's SIGINT and terminates this
	// process outright. Measured on a real pty: without this handler the session
	// ended with the terminal still raw, and the next shell had no echo.
	restoreOnce := &sync.Once{}
	put := func() { restoreOnce.Do(func() { _ = restore(c.term, saved) }) }
	defer put()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	go func() {
		sig, ok := <-sigs
		if !ok {
			return
		}
		put()
		// Re-raised rather than swallowed, so a script's `kill` still reports the
		// death it expects and the exit status is the signal's.
		if s, isSig := sig.(syscall.Signal); isSig && s == syscall.SIGINT {
			// Ctrl-C at an interactive prompt is a normal thing to do, so it does
			// not look like a crash: the terminal is restored, a newline is emitted
			// so the shell's prompt starts on its own line, and the exit is clean.
			c.writeOut("^C\r\n")
			os.Exit(0)
		}
		c.writeOut("\r\n")
		os.Exit(1)
	}()

	br := bufio.NewReader(c.term)
	read := func() (byte, error) { return br.ReadByte() }

	e := newEditor()
	// The prompt the daemon sent is already on screen; the editor's first render
	// starts from an empty line after it.
	for {
		kind, r, err := decodeKey(read)
		if err != nil {
			return nil
		}

		switch kind {
		case keyEnter:
			line := e.String()
			c.printf("\r\n")
			e.record(line)
			e.reset()
			if _, werr := io.WriteString(c.conn, line+"\n"); werr != nil {
				return nil
			}
			// The daemon answers with output and then a fresh prompt; the loop below
			// waits for that prompt before reading again, so this returns and the
			// caller's prompt gate takes over. Returning here would end the session,
			// so instead the editor keeps running and simply does not read until the
			// next prompt arrives. See c.awaitPrompt.
			if err := c.awaitPrompt(); err != nil {
				return nil
			}

		case keyRune:
			e.insert([]rune{r})
			render(c.expr, e)

		case keyBackspace:
			if e.backspace() {
				render(c.expr, e)
			}

		case keyDelete:
			if e.deleteForward() {
				render(c.expr, e)
			}

		case keyLeft:
			if e.cursor > 0 {
				e.cursor--
				render(c.expr, e)
			}

		case keyRight:
			if e.cursor < len(e.line) {
				e.cursor++
				render(c.expr, e)
			}

		case keyHome, keyCtrlA:
			e.cursor = 0
			render(c.expr, e)

		case keyEnd, keyCtrlE:
			e.cursor = len(e.line)
			render(c.expr, e)

		case keyCtrlB:
			if e.cursor > 0 {
				e.cursor--
				render(c.expr, e)
			}

		case keyCtrlF:
			if e.cursor < len(e.line) {
				e.cursor++
				render(c.expr, e)
			}

		case keyUp, keyCtrlP:
			if e.up() {
				render(c.expr, e)
			}

		case keyDown, keyCtrlN:
			if e.down() {
				render(c.expr, e)
			}

		case keyCtrlK:
			e.killToEnd()
			render(c.expr, e)

		case keyCtrlU:
			e.killToStart()
			render(c.expr, e)

		case keyCtrlW:
			e.killWord()
			render(c.expr, e)

		case keyCtrlL:
			// Clear the screen and redraw the line, which is what Ctrl-L means
			// everywhere: the line survives, the transcript does not.
			c.printf("\x1b[H\x1b[2J")
			render(c.expr, e)

		case keyTab:
			next, err := c.complete(e)
			if err != nil {
				return nil
			}
			*e = *next
			render(c.expr, e)

		case keyCtrlD:
			if len(e.line) == 0 {
				// Ctrl-D on an empty line ends the session, the way a shell's does.
				// It sends the half-close rather than closing the connection, so the
				// daemon still gets to flush its goodbye.
				c.printf("\r\n")
				c.halfClose()
				return nil
			}
			// On a non-empty line it deletes under the cursor, which is GNU
			// readline's binding and the one an operator's fingers expect.
			if e.deleteForward() {
				render(c.expr, e)
			}

		case keyInterrupt:
			// Ctrl-C reaches this branch only if the terminal was put in a mode
			// where ISIG is off; the standard raw setup keeps ISIG on, so SIGINT
			// normally kills the process first. Handled anyway, and handled the way
			// a shell does: abandon the line, keep the session.
			c.printf("^C\r\n")
			e.reset()
			c.sendInterrupt()
			if err := c.awaitPrompt(); err != nil {
				return nil
			}

		case keyUnknown:
			// Swallowed rather than printed. A function key this build does not know
			// would otherwise insert its escape tail into the operator's line.
		}
	}
}

// expr writes to the client's output for the editor's render calls.
func (c *client) expr(s string) { c.writeOut(s) }

// writeOut sends bytes to the terminal, ignoring the error: a failed write means the
// terminal is gone, and the next read will report that properly.
func (c *client) writeOut(s string) {
	_, _ = io.WriteString(c.stdout, s)
}

// printf writes formatted output to the terminal.
func (c *client) printf(format string, args ...any) {
	c.writeOut(fmt.Sprintf(format, args...))
}

// complete asks the daemon for a completion and applies it.
//
// The exchange is synchronous and assumes the daemon has nothing else to say, which
// it does not: the session's serve loop answers completion in the same loop that runs
// commands, so the reply is the next message on the wire, not an interrupt in the
// middle of something. A daemon with pending output would break that assumption, so
// the caller only reaches here between prompts.
func (c *client) complete(e *editor) (*editor, error) {
	if err := c.sendControl(ctrlComplete, e.String()+"\x00"+e.word()); err != nil {
		return e, err
	}
	kind, payload, err := c.readControl(ctrlComplete)
	if err != nil {
		return e, err
	}
	if kind != ctrlComplete {
		return e, nil
	}
	got := decodeCompletion(payload)
	if got.prefix == "" {
		// No match: a bell, which is what a shell does and what stops the operator
		// wondering whether the key worked.
		c.writeOut("\a")
		return e, nil
	}
	if len(got.candidates) > 1 && got.prefix == e.word() {
		// Several matches and no common prefix to add: show them, then redraw the
		// line underneath. This is the second-Tab behaviour, without needing to
		// remember that Tab was pressed before.
		c.printf("\r\n%s\r\n", strings.Join(got.candidates, "  "))
		render(c.expr, e)
		return e, nil
	}
	return e.withCandidate(got.prefix), nil
}

// sendInterrupt tells the daemon the operator pressed Ctrl-C.
func (c *client) sendInterrupt() { _ = c.sendControl(ctrlInterrupt, "") }

// sendControl writes one client-to-daemon control message.
func (c *client) sendControl(kind byte, payload string) error {
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()
	c.awaiting = true
	defer func() { c.awaiting = false }()
	_, err := io.WriteString(c.conn, control(kind, payload))
	return err
}

// readControl reads the next protocol line and returns it if it is the expected
// control kind. Output that arrives in the meantime is printed, because a daemon that
// is still flushing a command's output should not have that output dropped while the
// client waits for a completion.
func (c *client) readControl(want byte) (byte, string, error) {
	for {
		line, err := c.wire.ReadLine()
		if err != nil {
			return 0, "", err
		}
		if kind, payload, ok := isControl(line); ok {
			if kind == want {
				return kind, payload, nil
			}
			// Anything else is handled the way readDaemon handles it, so a prompt
			// arriving here is not lost.
			c.handleControl(kind, payload)
			continue
		}
		c.printf("%s\r\n", line)
	}
}

// awaitPrompt blocks until the daemon sends the next prompt, printing whatever comes
// before it.
//
// This is the piece that makes a raw-mode client work at all: after Enter, the daemon
// runs a command and eventually prompts, and the editor must not read a keystroke
// during that time or the operator's typing would vanish into the command's output.
// Blocking here - rather than racing the two directions - is what keeps a session one
// conversation.
func (c *client) awaitPrompt() error {
	for {
		line, err := c.wire.ReadLine()
		if err != nil {
			return err
		}
		if kind, payload, ok := isControl(line); ok {
			if kind == ctrlPrompt {
				c.writeOut(payload)
				return nil
			}
			c.handleControl(kind, payload)
			continue
		}
		c.printf("%s\r\n", line)
	}
}

// handleControl is the client's shared interpretation of a control message, used by
// the daemon-reading goroutine and by the two blocking helpers above so the three
// cannot disagree.
func (c *client) handleControl(kind byte, payload string) {
	switch kind {
	case ctrlPrompt:
		c.writeOut(payload)
	case ctrlNoEcho:
		if c.term != nil {
			_ = setEcho(c.term, false)
		}
	case ctrlEcho:
		if c.term != nil {
			_ = setEcho(c.term, true)
		}
	case ctrlBye:
		if payload != "" {
			c.printf("%s\r\n", payload)
		}
	case ctrlComplete:
		// Stray completion outside an active request: dropped rather than printed,
		// because its payload contains a separator byte a terminal would render as
		// garbage.
	default:
		c.printf("[control %s: %s]\r\n", quoteByte(kind), payload)
	}
}

// errNoTerminal is returned when the interactive loop is asked for without a terminal.
var errNoTerminal = errors.New("console: no terminal")

// hasTerminal reports whether the client has a terminal to run the editor on.
func (c *client) hasTerminal() bool { return c.term != nil && rawModeSupported }

var _ = net.ErrClosed
var _ = os.ErrClosed
