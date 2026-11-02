//go:build linux

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
	"os"
	"syscall"
	"unsafe"
)

// Terminal control on Linux, through the standard library's own termios
// definitions. No third-party package: the daemon is host code but it is still
// shipped code, and a dependency taken to clear one flag bit is a dependency every
// build of this binary now has to resolve.

// isTerminal reports whether f is a tty.
//
// The test is an ioctl rather than os.Stat's mode bits, because a mode check answers
// "is this a character device" and a pty slave is a character device while a serial
// line is also one, and what actually matters is whether TCGETS succeeds - which is
// the same question the terminal drivers answer.
func isTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	return errno == 0
}

// getTermios reads the current settings.
func getTermios(f *os.File) (syscall.Termios, error) {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	if errno != 0 {
		return t, errno
	}
	return t, nil
}

// setTermios writes settings back.
//
// TCSANOW rather than TCSADRAIN: nothing is pending on the output side that matters
// here, and draining would block on a terminal whose output the operator has stopped
// with Ctrl-S.
func setTermios(f *os.File, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(t)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// setEcho turns terminal echo on or off, leaving every other flag alone.
//
// It is kept for the password path, which needs exactly this and nothing more. The
// line editor uses rawMode below, where echo is off as a consequence of the editor
// doing its own rendering.
func setEcho(f *os.File, on bool) error {
	t, err := getTermios(f)
	if err != nil {
		return err
	}
	if on {
		t.Lflag |= syscall.ECHO
	} else {
		t.Lflag &^= syscall.ECHO
	}
	return setTermios(f, &t)
}

// rawMode puts the terminal into the mode a line editor needs, and returns the state
// to restore.
//
// ICANON goes, because the editor has to see each keystroke as it arrives - that is
// what makes the arrow keys and Tab do anything at all, and it is why the shell this
// project replaces by hand could not. ECHO goes with it, because the editor renders
// the line itself and a terminal echoing as well would double every character.
//
// ISIG is deliberately KEPT, and the choice is worth stating: with ISIG on, Ctrl-C is
// still the kernel's SIGINT and still ends the client process, which is what an
// operator expects when the session is wedged. An editor that caught Ctrl-C itself
// would have to be right about when to forward it and when to clear the line, and the
// terminal driver already is.
//
// IEXTEN goes too, because its Ctrl-V quoting is the terminal's line discipline
// inserting characters the editor would then have to strip again.
func rawMode(f *os.File) (*syscall.Termios, error) {
	saved, err := getTermios(f)
	if err != nil {
		return nil, err
	}
	raw := saved
	raw.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.IEXTEN
	raw.Iflag &^= syscall.ICRNL | syscall.IXON
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if err := setTermios(f, &raw); err != nil {
		return nil, err
	}
	return &saved, nil
}

// restore puts a saved state back.
func restore(f *os.File, saved *syscall.Termios) error {
	if saved == nil {
		return nil
	}
	return setTermios(f, saved)
}

// echoSupported reports whether this build can hide a typed password.
const echoSupported = true

// rawModeSupported reports whether this build can run the line editor. A build
// without it still serves the console; the client falls back to reading whole lines.
const rawModeSupported = true
