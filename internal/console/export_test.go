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
	"io"
	"os"
	"time"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// The probes in this file exist for the same reason kernel/export_test.go does: a
// property that cannot be reached from outside the package still has to be tested,
// and the alternative - exporting a way to construct one - would hand every caller
// the thing the property protects.
//
// Everything here is compiled only into this package's test binary. Nothing in it is
// reachable from a session, a component or the daemon.

// quietConsole points the kernel console at io.Discard so a test's output is the
// assertions rather than a boot log.
func quietConsole() {
	kernel.KernelConsole().SetOutput(io.Discard)
	kernel.KernelConsole().SetLevel(kernel.LogFault)
}

// bootForTest starts a Daemon on a socket under a temporary directory and waits for it
// to accept, so the test drives the real Start path rather than a hand-built state.
//
// The directory is removed by t.Cleanup only after Stop, because the socket lives in
// it and Stop is what unlinks the socket.
func bootForTest() (*Daemon, error) {
	dir, err := os.MkdirTemp("", "meow-console-test-*")
	if err != nil {
		return nil, err
	}
	d := New(Options{
		Root:      dir,
		LogWriter: io.Discard,
	})
	go func() { _ = d.Start() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if Probe(d.SocketPath()) == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if Probe(d.SocketPath()) != nil {
		d.Stop(nil)
		_ = os.RemoveAll(dir)
		return nil, errNoDaemonForTest
	}
	return d, nil
}

var errNoDaemonForTest = &testError{"the daemon did not start"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }
