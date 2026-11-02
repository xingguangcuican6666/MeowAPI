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

package abi

// The command surface a loaded component contributes.
//
// A component contributes commands the way it contributes everything else: as
// data the host reads and then registers through the kernel. The kernel does not
// know what a command does. It knows what a command IS - a name, one line of
// help, and the operation the operator must hold to run it - and it is the kernel
// that decides whether the registration is permitted, on the audit chain, before
// the command can be run.
//
// Why a symbol lookup rather than an init-time Register call. A statically linked
// module calls kernel.Register from its own init(), which works because it imports
// the kernel. A .so component deliberately does not: that import is what makes
// every plugin invalid the moment a kernel file changes, and it is the whole reason
// this package exists. Go's plugin package offers exactly one mechanism in that
// case - plugin.Open, then Lookup of a named symbol - so the lookup is the
// transport. It is not the authority. What the host finds is inert data until it
// hands it to a registration path that checks it, and a command that was never
// registered cannot be run no matter what the .so exported.

// CommandSymbol is the name a component's .so exports its commands under. It is
// declared here rather than in the loader so a component and the host cannot
// disagree about it, and so the disagreement is a compile error in the component
// rather than a silent no-op at load.
const CommandSymbol = "MeowAPICommands"

// Command is one command a component contributes.
//
// The host stores a copy of everything but Run and never a reference to the
// component's slice, so a component cannot rewrite a command's name, help or
// required operation after the registration was approved.
type Command struct {
	// Name is what an operator types. It is lowercase, contains no whitespace,
	// and is unique across the whole table: a component may not shadow a builtin
	// or another component's command, because an operator typing a familiar word
	// must not reach different code depending on load order.
	Name string `json:"name"`
	// Help is one line, shown by `help`. It is operator-facing text chosen by the
	// component author, and the kernel bounds its length: an unbounded string in a
	// table an operator reads is a place to hide a payload.
	Help string `json:"help"`
	// Requires names the operation the operator's session must hold to run this
	// command. Empty means any console session may run it.
	//
	// It may not name an operation the registering component does not itself hold.
	// A component cannot contribute a command that acts with authority the
	// component lacks, which is the same rule a route handler is held to: the
	// dispatch runs under the handler's own grants, never the caller's.
	Requires Op `json:"requires,omitempty"`
	// Run is the command body. It receives the context the component was loaded
	// with, not the operator's, and the arguments already split - there is no shell
	// interpretation anywhere in this path, so a metacharacter in an argument is a
	// character in a string and nothing else.
	//
	// It returns the text to print. An error is printed as this command's failure
	// and does not close the session.
	Run func(ctx SContext, args []string) (string, error) `json:"-"`
	// Complete offers argument completions for the word being typed, or nil when
	// the command has none.
	//
	// It is the component's own knowledge that is being asked for, which is why it
	// lives here rather than in the daemon: only the component knows what its
	// arguments mean, and only the component can say without the daemon reading the
	// host's filesystem on an unauthenticated session's behalf.
	//
	// It has a much shorter deadline than Run - a completion happens while a human
	// types - and a timeout, a panic or an error all mean "offer nothing".
	Complete func(ctx SContext, word string) ([]string, error) `json:"-"`
}
