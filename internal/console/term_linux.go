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

// Terminal echo control on Linux, through the standard library's own termios
// definitions. No third-party package: the daemon is host code but it is still
// shipped code, and a dependency taken to clear one flag bit is a dependency every
// build of this binary now has to resolve.

// isTerminal reports whether f is a tty.
//
// The test is an ioctl rather than os.Stat's mode bits, because a mode check
// answers "is this a character device" and a pty slave is a character device while
// a serial line is also one, and what actually matters is whether TCGETS succeeds
// - which is the same question the terminal drivers answer.
func isTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	return errno == 0
}

// setEcho turns terminal echo on or off, leaving every other flag alone.
//
// Only ECHO is touched. The tempting shortcut is raw mode, and it is wrong here:
// raw clears ICANON, so the operator's line editing stops working while they type a
// password, and it clears ISIG, so Ctrl-C stops being a way out. A password prompt
// that traps the user is worse than one that needs care.
func setEcho(f *os.File, on bool) error {
	var t syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)), 0, 0, 0); errno != 0 {
		return errno
	}
	if on {
		t.Lflag |= syscall.ECHO
	} else {
		t.Lflag &^= syscall.ECHO
	}
	// TCSANOW rather than TCSADRAIN: nothing is pending on the output side that
	// matters here, and draining would block on a terminal whose output the
	// operator has stopped with Ctrl-S.
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&t)), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// echoSupported reports whether this build can hide a typed password.
const echoSupported = true
