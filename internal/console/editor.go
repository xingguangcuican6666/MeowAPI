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
	"fmt"
	"strings"
	"unicode/utf8"
)

// The line editor.
//
// It runs in the CLIENT, not the daemon, and that is the whole reason it works: the
// daemon holds a session over a socket and cannot see a keystroke, while the client
// owns the terminal and is the only thing that can. A daemon-side editor would have to
// have the client forward every byte in raw mode, which is the same amount of code
// with an extra round trip per character and the added problem that a dropped
// connection loses the operator's half-typed line instead of one command.
//
// The keys are the ones a shell's line discipline gives you and a canonical-mode read
// does not: arrows for history and cursor, Ctrl-A/E/K/U/W, Backspace and Delete, Home
// and End, Ctrl-L to clear, and Tab for completion - which needs the daemon, so it is
// a control message rather than local state.
//
// What is deliberately absent: word-wise movement (M-b/M-f), vi mode, and anything
// that requires knowing where a line wraps on the screen. The editor tracks a column
// only for the escape sequences it emits, never for editing decisions, so a line
// longer than the terminal is a line whose cursor arithmetic depends on the terminal
// rather than on this code - which is a limit worth stating rather than a bug to hunt.

// historySize bounds the in-memory history. A hundred entries is what an operator can
// scroll through without a search key, and keeping less than the daemon's audit window
// means the history is not a copy of it.
const historySize = 100

// key is one decoded keystroke.
type keyKind int

const (
	keyRune keyKind = iota
	keyEnter
	keyBackspace
	keyDelete
	keyTab
	keyUp
	keyDown
	keyLeft
	keyRight
	keyHome
	keyEnd
	keyCtrlA
	keyCtrlB
	keyCtrlD
	keyCtrlE
	keyCtrlF
	keyCtrlK
	keyCtrlL
	keyCtrlP
	keyCtrlN
	keyCtrlU
	keyCtrlW
	keyInterrupt
	keyUnknown
)

// editor is one client's line-editing state. It persists across commands so history
// survives, and its terminal is set only when stdin is a tty.
type editor struct {
	// line is what the operator has typed so far, as runes so a multi-byte character
	// is one cursor position.
	line []rune
	// cursor is an index into line, 0..len(line).
	cursor int

	// history is oldest first; histAt is len(history) when the operator is composing
	// a fresh line, and an index into history when they have walked back.
	history []string
	histAt  int
	// pending is the fresh line stashed while walking history, restored when the
	// operator walks forward past the newest entry.
	pending string

	// lastRender is how many columns the visible line occupied last time it was
	// drawn, so a redraw can erase exactly that much.
	lastRender int
	// fullRedraw asks for the next render to repaint from column zero with an erase,
	// rather than appending what was typed. Appending is what makes a keystroke cost
	// one or two bytes instead of a whole line, and it is the difference between an
	// editor that keeps up on a slow terminal and one that does not.
	fullRedraw bool
}

// newEditor returns an editor with room for history.
func newEditor() *editor {
	return &editor{history: make([]string, 0, historySize)}
}

// record adds a submitted line to history, skipping blanks and immediate repeats.
func (e *editor) record(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	if n := len(e.history); n > 0 && e.history[n-1] == line {
		return
	}
	e.history = append(e.history, line)
	if len(e.history) > historySize {
		e.history = e.history[len(e.history)-historySize:]
	}
	e.histAt = len(e.history)
	e.pending = ""
}

// reset puts the cursor back to an empty line, which is what a submitted or
// interrupted command does.
func (e *editor) reset() {
	e.line = e.line[:0]
	e.cursor = 0
	e.histAt = len(e.history)
	e.pending = ""
	e.lastRender = 0
	// fullRedraw is set by an edit that changed more than the tail: history recall,
	// a completion, a clear. See render for why it matters.
	e.fullRedraw = true
}

// String is the line as typed.
func (e *editor) String() string { return string(e.line) }

// insert writes runes at the cursor.
func (e *editor) insert(rs []rune) {
	tail := append([]rune(nil), e.line[e.cursor:]...)
	e.line = append(e.line[:e.cursor], rs...)
	e.line = append(e.line, tail...)
	e.cursor += len(rs)
}

// backspace deletes the rune before the cursor.
func (e *editor) backspace() bool {
	if e.cursor == 0 {
		return false
	}
	e.line = append(e.line[:e.cursor-1], e.line[e.cursor:]...)
	e.cursor--
	return true
}

// deleteForward deletes the rune under the cursor.
func (e *editor) deleteForward() bool {
	if e.cursor >= len(e.line) {
		return false
	}
	e.line = append(e.line[:e.cursor], e.line[e.cursor+1:]...)
	return true
}

// killToEnd removes everything from the cursor to the end of the line.
func (e *editor) killToEnd() {
	e.line = e.line[:e.cursor]
}

// killToStart removes everything from the start of the line to the cursor.
func (e *editor) killToStart() {
	e.line = append(e.line[:0], e.line[e.cursor:]...)
	e.cursor = 0
}

// killWord removes the word before the cursor, including the spaces before it, which
// is what Ctrl-W does in every shell an operator has used.
func (e *editor) killWord() {
	i := e.cursor
	for i > 0 && e.line[i-1] == ' ' {
		i--
	}
	for i > 0 && e.line[i-1] != ' ' {
		i--
	}
	e.line = append(e.line[:i], e.line[e.cursor:]...)
	e.cursor = i
}

// up walks back through history.
func (e *editor) up() bool {
	if len(e.history) == 0 || e.histAt == 0 {
		return false
	}
	if e.histAt == len(e.history) {
		// Leaving the fresh line: stash it so walking forward restores it.
		e.pending = string(e.line)
	}
	e.histAt--
	e.setLine(e.history[e.histAt])
	return true
}

// down walks forward through history and then back to the fresh line.
func (e *editor) down() bool {
	if e.histAt >= len(e.history) {
		return false
	}
	e.histAt++
	if e.histAt == len(e.history) {
		e.setLine(e.pending)
		return true
	}
	e.setLine(e.history[e.histAt])
	return true
}

// setLine replaces the line and puts the cursor at its end.
func (e *editor) setLine(s string) {
	e.line = append(e.line[:0], []rune(s)...)
	e.cursor = len(e.line)
}

// withCandidate returns the line with the word at the cursor replaced by candidate.
//
// It is only correct for the FIRST word in practice, because that is the only place a
// candidate can be appended without quoting rules - and there are no quoting rules, by
// design. For an argument word, the candidate is appended to the text before the
// cursor, which is what a completion of a fixed vocabulary needs.
func (e *editor) withCandidate(candidate string) *editor {
	// The candidate is the whole word, and the operator's typed prefix is a PREFIX
	// of it. Appending the candidate would therefore double the prefix - measured on
	// a real pty: Tab on "st" produced "statusatus".
	//
	// The word's start is derived here from the cursor, before any edit, so the
	// replacement is [wordStart, wordEnd) -> candidate and nothing else moves.
	out := &editor{
		line:       append([]rune(nil), e.line...),
		cursor:     e.cursor,
		history:    e.history,
		histAt:     e.histAt,
		pending:    e.pending,
		lastRender: e.lastRender,
		fullRedraw: true,
	}
	start := out.wordStart()
	// The candidate is the ENTIRE completed word, and everything from the start of
	// the word to the CURSOR is the part of it the operator had typed. So what is
	// kept after the word is the rest of the word beyond the cursor, then whatever
	// followed it.
	wordEnd := out.cursor
	for wordEnd < len(out.line) && out.line[wordEnd] != ' ' && out.line[wordEnd] != '\t' && out.line[wordEnd] != '|' {
		wordEnd++
	}
	before := append([]rune(nil), out.line[:start]...)
	after := append([]rune(nil), out.line[wordEnd:]...)
	newLine := append(before, []rune(candidate)...)
	newLine = append(newLine, after...)
	out.line = newLine
	out.cursor = len(before) + len([]rune(candidate))
	return out
}

// wordStart is the index where the word before the cursor begins.
func (e *editor) wordStart() int {
	i := e.cursor
	for i > 0 && e.line[i-1] != ' ' && e.line[i-1] != '\t' && e.line[i-1] != '|' {
		i--
	}
	return i
}

// word is the part of the current word that is before the cursor.
func (e *editor) word() string { return string(e.line[e.wordStart():e.cursor]) }

// decodeKey reads one keystroke from a byte stream.
//
// The reader returns bytes, not runes, because an escape sequence and a UTF-8
// character are both byte sequences and deciding which one is arriving is the same
// decision in both cases: how many bytes does the terminal mean.
func decodeKey(read func() (byte, error)) (keyKind, rune, error) {
	b, err := read()
	if err != nil {
		return keyUnknown, 0, err
	}

	switch {
	case b == '\r' || b == '\n':
		return keyEnter, 0, nil
	case b == 0x7f || b == 0x08:
		return keyBackspace, 0, nil
	case b == '\t':
		return keyTab, 0, nil
	case b == 0x01:
		return keyCtrlA, 0, nil
	case b == 0x02:
		return keyCtrlB, 0, nil
	case b == 0x03:
		return keyInterrupt, 0, nil
	case b == 0x04:
		return keyCtrlD, 0, nil
	case b == 0x05:
		return keyCtrlE, 0, nil
	case b == 0x06:
		return keyCtrlF, 0, nil
	case b == 0x0b:
		return keyCtrlK, 0, nil
	case b == 0x0c:
		return keyCtrlL, 0, nil
	case b == 0x0e:
		return keyCtrlN, 0, nil
	case b == 0x10:
		return keyCtrlP, 0, nil
	case b == 0x15:
		return keyCtrlU, 0, nil
	case b == 0x17:
		return keyCtrlW, 0, nil
	case b == 0x1b:
		// An ESC begins either a sequence or a bare Escape press. The sequences this
		// editor understands are CSI (ESC [ ...) and SS3 (ESC O ...); anything else
		// is reported as unknown so the caller can ignore it without consuming
		// further bytes it did not understand.
		next, err := read()
		if err != nil {
			return keyUnknown, 0, nil
		}
		if next != '[' && next != 'O' {
			return keyUnknown, 0, nil
		}
		final, err := read()
		if err != nil {
			return keyUnknown, 0, nil
		}
		switch final {
		case 'A':
			return keyUp, 0, nil
		case 'B':
			return keyDown, 0, nil
		case 'C':
			return keyRight, 0, nil
		case 'D':
			return keyLeft, 0, nil
		case 'H':
			return keyHome, 0, nil
		case 'F':
			return keyEnd, 0, nil
		case '1', '2', '3', '4', '5', '6', '7', '8':
			// A numbered sequence: ESC [ 3 ~ is Delete, ESC [ 1 ~ and ESC [ 7 ~ are
			// Home, ESC [ 4 ~ and ESC [ 8 ~ are End. The parameters arrive as bytes
			// and the sequence ends with '~' or a letter; read until it does.
			param := []byte{final}
			for {
				c, err := read()
				if err != nil {
					return keyUnknown, 0, nil
				}
				if c == '~' {
					break
				}
				if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
					return keyUnknown, 0, nil
				}
				param = append(param, c)
				if len(param) > 8 {
					return keyUnknown, 0, nil
				}
			}
			switch string(param) {
			case "3":
				return keyDelete, 0, nil
			case "1", "7":
				return keyHome, 0, nil
			case "4", "8":
				return keyEnd, 0, nil
			}
			return keyUnknown, 0, nil
		}
		return keyUnknown, 0, nil
	case b < 0x20:
		return keyUnknown, 0, nil
	case b < utf8.RuneSelf:
		return keyRune, rune(b), nil
	default:
		// A multi-byte character. The lead byte says how many bytes follow, and
		// anything that does not decode is dropped rather than inserted as garbage.
		buf := []byte{b}
		for len(buf) < utf8.UTFMax && !utf8.FullRune(buf) {
			c, err := read()
			if err != nil {
				return keyUnknown, 0, nil
			}
			buf = append(buf, c)
		}
		r, size := utf8.DecodeRune(buf)
		if r == utf8.RuneError && size <= 1 {
			return keyUnknown, 0, nil
		}
		return keyRune, r, nil
	}
}

// render redraws the line after an edit.
//
// The fast path is appending: when the cursor is at the end and the line only grew,
// the character just typed is already echoed by nothing - the terminal is in raw mode,
// so it is not - and writing it is all that is needed. That is one or two bytes per
// keystroke instead of a whole line, which is what keeps the editor responsive over a
// slow link and on a terminal that is slow to repaint.
//
// Anything else repaints: \r to column zero, the whole line, \x1b[K to erase whatever
// of the old line was longer, and a move back to the cursor. It is correct in every
// case and costs one write; the fast path is the one that has to be proved to be
// equivalent, and it is only taken when it trivially is.
func render(out func(string), e *editor) {
	if !e.fullRedraw && e.cursor == len(e.line) && len(e.line) > e.lastRender {
		out(string(e.line[e.lastRender:]))
		e.lastRender = len(e.line)
		return
	}

	s := string(e.line)
	var b strings.Builder
	b.WriteString("\r")
	b.WriteString(s)
	b.WriteString("\x1b[K")
	// Move back from the end of the line to the cursor. len(e.line) is a CHARACTER
	// count because the line is stored as runes, which is what the terminal moves in.
	if back := len(e.line) - e.cursor; back > 0 {
		fmt.Fprintf(&b, "\x1b[%dD", back)
	}
	out(b.String())
	e.lastRender = len(e.line)
	e.fullRedraw = false
}

// eraseLine clears what is on screen and the editor's idea of it.
func eraseLine(out func(string), e *editor) {
	out("\r\x1b[K")
	e.lastRender = 0
}
