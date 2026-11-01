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
	"os"
	"time"
)

// Attach connects to a running daemon and runs the terminal half of the protocol
// until the connection ends.
//
// This is the code that dies when a terminal is closed, and the daemon is the code
// that does not. The distinction is the whole feature: a client that exits on
// SIGHUP or on a broken pipe takes nothing with it, because everything worth
// keeping - the booted kernel, the loaded modules, the audit chain - lives in the
// other process.
//
// Attach does not boot a kernel and does not create one. If nothing is listening
// it says so, and starting a daemon is the caller's decision - which is what lets
// "run me" and "connect me" be the same binary.

// attachTimeout bounds the connect and the read of the daemon's banner.
const attachTimeout = 5 * time.Second

// Attach connects to path and serves the terminal.
func Attach(path string) error {
	conn, err := net.DialTimeout("unix", path, attachTimeout)
	if err != nil {
		return fmt.Errorf("no daemon is listening on %s: %w", path, err)
	}
	return ServeTerminal(conn, os.Stdin, os.Stdout)
}

// ServeTerminal runs the client side of the protocol. It is separate from Attach so
// a test can drive it over an in-memory pipe with no socket, no terminal and no
// daemon.
//
// stdin and stdout are parameters rather than globals because the echo control
// applies only when stdin is a terminal, and a test passing bytes in must not have
// its own process put into a changed terminal state.
func ServeTerminal(conn net.Conn, stdin io.Reader, stdout io.Writer) error {
	c := &client{
		conn:   conn,
		stdout: stdout,
		in:     newBoundedReader(stdin),
		wire:   newBoundedReader(conn),
	}
	if f, ok := stdin.(*os.File); ok && isTerminal(f) {
		c.term = f
	}

	// The daemon owns the session's lifetime, not the keyboard.
	//
	// Both directions run concurrently, but only readDaemon's result decides when
	// this function returns. That is what makes a piped session work: stdin reaches
	// EOF the moment the pipe is drained, which is BEFORE the daemon has answered
	// anything, so a client that treated keyboard-EOF as the end of the session
	// closed the connection and printed nothing - measured, that is exactly what the
	// first version did.
	//
	// The cost is a goroutine that may still be blocked in a terminal read when
	// ServeTerminal returns. It is not cancelled, and cannot be: there is no portable
	// way to interrupt a blocking read on a tty. It dies with the process, which for
	// a client whose only job is this session is the whole process lifetime anyway.
	go c.readKeyboard()
	err := c.readDaemon()
	_ = conn.Close()

	// A closed connection is the normal end of a session. The daemon sends a
	// goodbye control message before closing, so a client reaching EOF here has
	// already printed the reason if there was one.
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

type client struct {
	conn   net.Conn
	stdout io.Writer
	term   *os.File
	in     *boundedReader
	wire   *boundedReader
}

// readDaemon prints what the daemon sends and interprets its control messages.
func (c *client) readDaemon() error {
	for {
		line, err := c.wire.ReadLine()
		if err != nil {
			return err
		}
		if kind, payload, ok := isControl(line); ok {
			switch kind {
			case ctrlPrompt:
				if _, err := io.WriteString(c.stdout, payload); err != nil {
					return err
				}
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
					_, _ = fmt.Fprintf(c.stdout, "%s\n", payload)
				}
				return nil
			default:
				// An unknown control kind is printed rather than dropped: a
				// protocol mismatch between an older client and a newer daemon is
				// easier to diagnose from the bytes than from silence.
				_, _ = fmt.Fprintf(c.stdout, "[control %s: %s]\n", quoteByte(kind), payload)
			}
			continue
		}
		if _, err := fmt.Fprintln(c.stdout, line); err != nil {
			return err
		}
	}
}

// readKeyboard forwards typed lines to the daemon until stdin ends or the write
// fails. Its result is deliberately unread: see ServeTerminal for why the keyboard
// is not what ends a session.
func (c *client) readKeyboard() {
	// Restored on the way out whatever happens, because a client that exits with
	// echo off leaves the operator's terminal unable to show what they type - and
	// the session that ends is the one that cannot tell them so.
	if c.term != nil {
		defer func() { _ = setEcho(c.term, true) }()
	}
	for {
		line, err := c.in.ReadLine()
		if err != nil {
			// Stdin ended - Ctrl-D at a terminal, or a pipe that was drained. The
			// write side is closed rather than the connection, so the daemon sees
			// EOF on its read, ends the session cleanly and still has a channel to
			// send its goodbye and any pending output down. Closing the whole
			// connection here would race the daemon's last writes.
			c.halfClose()
			return
		}
		if _, err := io.WriteString(c.conn, line+"\n"); err != nil {
			return
		}
	}
}

// halfClose shuts the write side of the connection, if it is one that supports it.
func (c *client) halfClose() {
	if uc, ok := c.conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
		return
	}
	if tc, ok := c.conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// quoteByte renders a control kind for a diagnostic.
func quoteByte(b byte) string {
	if b >= ' ' && b < 0x7f {
		return string(b)
	}
	return fmt.Sprintf("0x%02x", b)
}
