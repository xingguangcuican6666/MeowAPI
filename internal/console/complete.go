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
	"sort"
	"strings"
	"time"
)

// completionTimeout bounds a component's completion callback. It is short - shorter
// than a command body's - because a completion happens while a human is typing.
const completionTimeout = 750 * time.Millisecond

// Completion, on the daemon side.
//
// The client cannot answer "what commands exist" or "what does this argument mean"
// for itself: the command table is the daemon's, it changes when a component loads,
// and the file arguments a command could complete are inside a component the client
// cannot see. So completion is a request, and this file answers it.
//
// What it answers is deliberately narrow. A command name in the first word, and a
// component's own candidates for the rest. It does NOT complete file paths outside a
// component, because the daemon would have to read the host's filesystem to do it and
// an unauthenticated session must not be able to ask what exists on disk.

// maxCandidates caps one completion. A completion with ten thousand matches is not
// useful to read and is a way to make a session spend the daemon's memory; past this
// the answer says how many there were rather than listing them.
const maxCandidates = 128

// maxWordLen bounds the word a client may ask about. It exists so the completion path
// has the same kind of ceiling every other input path has.
const maxWordLen = 512

// complete answers one completion request.
//
// line is what the operator has typed and word is the part of the current word before
// the cursor, both supplied by the client's editor. The word is supplied rather than
// derived so the two sides cannot disagree about what "the current word" means - the
// editor knows where the cursor is and this function does not.
func (d *Daemon) complete(s *Session, line, word string) completion {
	if len(line) > maxLineBytes || len(word) > maxWordLen {
		return completion{}
	}

	// A pipeline: the stage the cursor is in is the one after the LAST pipe.
	stage := line
	if i := strings.LastIndexByte(line, '|'); i >= 0 {
		stage = line[i+1:]
	}

	// The command word is the stage's first word. If the cursor is inside that word,
	// this is a command completion; otherwise it is an argument completion for it.
	trimmed := strings.TrimLeft(stage, " \t")
	nameEnd := strings.IndexAny(trimmed, " \t")
	if nameEnd < 0 {
		// No whitespace after the name: the cursor is still in the command word.
		return d.completeCommand(word)
	}
	name := trimmed[:nameEnd]
	_ = s
	return d.completeArgument(name, word)
}

// completeCommand offers the command names that start with word.
//
// It is filtered by the session's authentication state: offering `poweroff` to an
// unauthenticated session would be advertising a command that session cannot run, and
// the set of command names is itself a small piece of information about the daemon's
// configuration.
func (d *Daemon) completeCommand(word string) completion {
	names := d.table.Names()
	matches := make([]string, 0, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, word) {
			matches = append(matches, n)
		}
	}
	sort.Strings(matches)
	return buildCompletion(word, matches)
}

// completeArgument asks a command for its own candidates.
//
// Only a component's commands have candidates, and only because the component offers
// them: a builtin does not, and there is no generic answer to give. The component is
// called under its own context with a deadline, exactly as its body is, because an
// argument completion that blocks would block the operator's typing.
func (d *Daemon) completeArgument(name, word string) completion {
	e, ok := d.table.Lookup(name)
	if !ok || e.module == nil || e.module.cmd.Complete == nil {
		return completion{}
	}
	matches, err := d.runCompletion(e.module, word)
	if err != nil {
		return completion{}
	}
	if len(matches) > maxCandidates {
		matches = matches[:maxCandidates]
	}
	return buildCompletion(word, matches)
}

// buildCompletion turns a match set into the message to send.
//
// The rule matches a shell's: nothing for no matches, the completed word for one, and
// the longest common prefix for several - which is what makes pressing Tab twice do
// something useful rather than only ever printing a list.
func buildCompletion(word string, matches []string) completion {
	// Anything containing the wire separator is dropped, because the encoding cannot
	// represent it: a candidate with a 0x02 in it would arrive at the client as two
	// candidates, one of them invented. The command-name rule already makes that
	// impossible for names; this covers a component returning arbitrary bytes from
	// Complete, which is the only path that can.
	clean := matches[:0:0]
	for _, m := range matches {
		if !strings.ContainsRune(m, rune(candidateSeparator)) {
			clean = append(clean, m)
		}
	}
	switch len(clean) {
	case 0:
		return completion{}
	case 1:
		return completion{prefix: clean[0]}
	default:
		return completion{prefix: commonPrefix(clean), candidates: clean}
	}
}

// commonPrefix is the longest string every match starts with.
func commonPrefix(matches []string) string {
	if len(matches) == 0 {
		return ""
	}
	p := matches[0]
	for _, m := range matches[1:] {
		for !strings.HasPrefix(m, p) {
			if p == "" {
				return ""
			}
			p = p[:len(p)-1]
		}
	}
	return p
}

// runCompletion invokes a component's completion callback with the same shield and
// deadline its body gets.
func (d *Daemon) runCompletion(mc *moduleCommand, word string) ([]string, error) {
	type res struct {
		out []string
		err error
	}
	done := make(chan res, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- res{err: fmt.Errorf("completion panicked: %v", r)}
			}
		}()
		out, err := mc.cmd.Complete(mc.ctx, word)
		done <- res{out, err}
	}()

	select {
	case r := <-done:
		return r.out, r.err
	case <-time.After(completionTimeout):
		// A completion that has not answered in a fraction of a second is one the
		// operator has already typed past. Nothing is reported: a message appearing
		// under the cursor mid-word is worse than no completion.
		return nil, fmt.Errorf("completion timed out")
	}
}
