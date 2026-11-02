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

// The wire protocol between a daemon and an attached terminal.
//
// It is a line protocol with three control messages, and the reason it is not
// just bytes in both directions is the password. A daemon that asks for one has
// to be able to tell the terminal to stop echoing, and a terminal has to know
// when to stop treating what it receives as text to print. Anything the daemon
// sends that is not a control message is output.
//
// A control message is one line beginning with ctrlByte, which cannot appear at
// the start of any output line because every line the daemon writes for a human
// is passed through escapeControl first.

import "strings"

const (
	// ctrlByte marks a control line rather than output.
	ctrlByte = 0x01
	// ctrlPrompt carries the rest of the line as a prompt to print with no
	// trailing newline, so the cursor sits after it while the operator types.
	ctrlPrompt = byte('P')
	// ctrlNoEcho asks the terminal to stop echoing the next line it reads.
	ctrlNoEcho = byte('N')
	// ctrlEcho asks it to resume.
	ctrlEcho = byte('E')
	// ctrlBye is sent before the daemon closes a session, so a client can tell
	// "the kernel stopped" from "my socket broke".
	ctrlBye = byte('B')
	// ctrlComplete travels in BOTH directions. A client sends it with the line and
	// the word to complete, separated by NUL; the daemon answers with the same kind,
	// carrying the longest common prefix and then every candidate. It is one message
	// rather than a request and a reply the client has to correlate, because a
	// session is a single synchronous conversation and there is exactly one
	// completion outstanding at a time.
	//
	// The word is sent separately rather than being re-derived by the daemon, because
	// the client's editor knows exactly where its cursor is and the two would
	// otherwise have to agree on what "the current word" means down to the byte.
	ctrlComplete = byte('C')
	// ctrlInterrupt travels client to daemon: the operator pressed Ctrl-C. The daemon
	// uses it to stop a streaming command, and for nothing else - a command that has
	// not finished in a second is not a command Ctrl-C should be able to kill, because
	// a component's body may be holding a lock the kernel owns.
	ctrlInterrupt = byte('I')
)

// candidateSeparator divides the fields of a completion reply. It is not a newline
// because a control message is one line, and it is not a space because an argument
// may contain one - the operator's command line has no quoting, so a candidate that
// needs a space is a candidate the completion cannot offer anyway, but a separator
// that cannot appear in a candidate is still the safer choice.
const candidateSeparator = 0x02

// completeFieldSeparator divides the two fields of a completion REQUEST. It is NUL
// because neither a line nor a word can contain one - the editor never inserts it and
// the line cannot carry it over the wire anyway.
const completeFieldSeparator = 0x00

// completion is one answer to a completion request.
type completion struct {
	// prefix is what the client should replace the word with when there is exactly
	// one candidate, or the longest common prefix of several.
	prefix string
	// candidates is every match, for the client to display when there is more than
	// one and no common prefix to add.
	candidates []string
}

// encode renders a completion as a control message payload.
func (c completion) encode() string {
	parts := append([]string{c.prefix}, c.candidates...)
	return strings.Join(parts, string(rune(candidateSeparator)))
}

// decodeCompletion parses a completion payload. A malformed one yields an empty
// completion rather than an error: a client and a daemon disagreeing about this is a
// version mismatch, and the right response is to offer nothing rather than to break
// the session the operator is typing into.
func decodeCompletion(payload string) completion {
	if payload == "" {
		return completion{}
	}
	parts := strings.Split(payload, string(rune(candidateSeparator)))
	c := completion{prefix: parts[0]}
	if len(parts) > 1 {
		c.candidates = parts[1:]
	}
	return c
}

// maxLineBytes bounds one protocol line in either direction. A session that
// sends more than this is disconnected rather than buffered: the daemon holds one
// buffer per session, and an unbounded read is how one client exhausts the
// process that every other client depends on.
const maxLineBytes = 64 * 1024

// prompt is what an authenticated session sees. It is deliberately short,
// because it is printed after every command and a long one pushes output off the
// screen.
const prompt = "meow> "

// passwordPrompt is what an unauthenticated one sees. It does not say whether a
// password is set, which is the same reason the kernel makes wrong and absent
// credentials indistinguishable.
const passwordPrompt = "Password: "

// control builds one control line.
func control(kind byte, text string) string {
	return string([]byte{ctrlByte, kind}) + text + "\n"
}

// isControl reports whether a line read from the wire is a control message, and
// returns its kind and payload.
func isControl(line string) (kind byte, payload string, ok bool) {
	if len(line) < 2 || line[0] != ctrlByte {
		return 0, "", false
	}
	return line[1], line[2:], true
}

// escapeControl makes output safe to write: every line that would be read back as
// a control message has its leading byte quoted.
//
// It walks every line and not just the first, because the protocol is
// newline-delimited: a control byte in the middle of a multi-line output is at the
// start of ITS line as far as the client is concerned. Escaping only the first line
// would leave a component that returns "\n\x01N" able to turn off the operator's
// echo. Without any escaping at all, a module that logs a message beginning with
// 0x01 could fake a prompt or disable echo - and a log message is text a module
// chooses.
func escapeControl(s string) string {
	if !strings.ContainsRune(s, ctrlByte) {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" && l[0] == ctrlByte {
			lines[i] = "\\x01" + l[1:]
		}
	}
	return strings.Join(lines, "\n")
}
