//go:build !linux

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
	"os"
)

// Terminal echo control on platforms this build was not written for.
//
// The ioctl names differ per platform - TCGETS/TCSETS on Linux, TIOCGETA/TIOCSETA
// on the BSDs and macOS, and something else again on Windows - and guessing at
// them is how a program ends up clearing flags it did not mean to touch. So this
// file refuses instead, and the refusal is visible: the session warns the operator
// that what they type will be echoed, rather than silently displaying a password.
//
// A wrong termios write is worse than an echoed password, because it can leave the
// terminal unusable after the process exits and the operator has no way to type the
// command that would fix it.

var errEchoUnsupported = errors.New("console: this build cannot control terminal echo")

// isTerminal reports false, so no echo change is attempted.
func isTerminal(f *os.File) bool { return false }

// setEcho reports that it cannot.
func setEcho(f *os.File, on bool) error { return errEchoUnsupported }

// echoSupported is false, and the session says so before asking for a password.
const echoSupported = false
