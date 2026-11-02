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
	"syscall"
)

// Terminal control on platforms this build was not written for.
//
// The ioctl names differ per platform - TCGETS/TCSETS on Linux, TIOCGETA/TIOCSETA on
// the BSDs and macOS, and something else again on Windows - and guessing at them is
// how a program ends up clearing flags it did not mean to touch. So this file refuses
// instead, and the refusals are visible: the password prompt warns that what is typed
// will be echoed, and the client reads whole lines rather than editing them.
//
// A wrong termios write is worse than either, because it can leave the terminal
// unusable after the process exits and the operator has no way to type the command
// that would fix it.

var errTermUnsupported = errors.New("console: this build cannot control the terminal")

// isTerminal reports false, so no terminal state is changed.
func isTerminal(f *os.File) bool { return false }

// getTermios has nothing to return.
func getTermios(f *os.File) (syscall.Termios, error) { return syscall.Termios{}, errTermUnsupported }

// setTermios refuses.
func setTermios(f *os.File, t *syscall.Termios) error { return errTermUnsupported }

// setEcho refuses.
func setEcho(f *os.File, on bool) error { return errTermUnsupported }

// rawMode refuses.
func rawMode(f *os.File) (*syscall.Termios, error) { return nil, errTermUnsupported }

// restore refuses.
func restore(f *os.File, saved *syscall.Termios) error { return errTermUnsupported }

// echoSupported is false, and the session says so before asking for a password.
const echoSupported = false

// rawModeSupported is false, so the client reads whole lines.
const rawModeSupported = false
