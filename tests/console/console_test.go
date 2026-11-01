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

// Package console_test exercises the operator console's public surface: the password
// record and the socket.
//
// It is external on purpose. Everything here is reachable from outside the package,
// which is the surface an attacker has, and a suite that reached inside could pass on
// a mechanism no caller ever goes through. The protocol and the command table are
// tested in package console, because the checks that matter there - escaping an
// attacker-chosen line, refusing a privileged command before its body runs - drive
// unexported state directly.
package console_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xingguangcuican6666/MeowAPI/internal/console"
)

// The cost is deliberately below the shipped one. 600,000 iterations is right for a
// real record and would make this file minutes long; what these tests assert is the
// mechanism - a wrong password refused, a right one accepted, a weak record rejected -
// not the work factor, which is a constant the code reads and
// TestNewRecordsUseTheShippedCost pins.
const testIterations = 100_000

// TestCredentialRoundTrip is the base property: a record written once verifies against
// the password it was written with and no other.
func TestCredentialRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")
	store := console.NewCredentialStore(path)

	if _, err := store.Load(); !errors.Is(err, console.ErrNoCredential) {
		t.Fatalf("an absent record must report ErrNoCredential, got %v", err)
	}

	cred, err := console.HashPassword("correct-horse-battery", testIterations)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(cred); err != nil {
		t.Fatal(err)
	}

	if err := store.CheckPassword("correct-horse-battery"); err != nil {
		t.Fatalf("the password it was written with must verify: %v", err)
	}
	if err := store.CheckPassword("correct-horse-batterY"); err == nil {
		t.Fatal("a near-miss password verified")
	}
	if err := store.CheckPassword(""); err == nil {
		t.Fatal("an empty password verified")
	}

	// The file holds a hash and no plaintext. This is the property a reader of the
	// code is most likely to take on trust, so it is checked against the bytes.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "correct-horse-battery") {
		t.Fatal("the plaintext password appears in the credential file")
	}
	if !strings.Contains(string(raw), "pbkdf2-sha256") {
		t.Fatalf("the record does not name its scheme:\n%s", raw)
	}
}

// TestRotationReplacesTheRecord pins that a second Save is a replacement, not an append:
// two records in one file would make which password is live depend on parse order.
func TestRotationReplacesTheRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")
	store := console.NewCredentialStore(path)

	first, err := console.HashPassword("first-password-here", testIterations)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}
	second, err := console.HashPassword("second-password-here", testIterations)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(second); err != nil {
		t.Fatal(err)
	}

	if err := store.CheckPassword("second-password-here"); err != nil {
		t.Fatalf("the rotated password does not verify: %v", err)
	}
	if err := store.CheckPassword("first-password-here"); err == nil {
		t.Fatal("the replaced password still verifies")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "operator:"); n != 1 {
		t.Fatalf("the file holds %d operator records, want 1:\n%s", n, raw)
	}
}

// TestCredentialFileMode pins what makes first-boot provisioning safe: the record and
// the socket share one trust boundary, and the boundary is a mode on a directory.
func TestCredentialFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "shadow")
	store := console.NewCredentialStore(path)
	cred, err := console.HashPassword("correct-horse-battery", testIterations)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(cred); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		path string
		want os.FileMode
	}{
		{filepath.Dir(path), 0o700},
		{path, 0o600},
	} {
		info, err := os.Stat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != c.want {
			t.Errorf("%s has mode %04o, want %04o", c.path, got, c.want)
		}
	}
}

// TestWeakRecordsAreRefused pins the floor on the stored cost. A record is a file an
// operator can edit, and a hand-lowered cost is a silently weakened gate, so the parser
// refuses rather than verifies.
func TestWeakRecordsAreRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")

	cases := map[string]string{
		"cost below the floor": "operator:$pbkdf2-sha256$1$c2FsdHNhbHRzYWx0c2FsdA$" +
			strings.Repeat("A", 43),
		"unknown scheme": "operator:$md5$600000$c2FsdA$c2FsdA",
		"no scheme":      "operator:600000$c2FsdA$c2FsdA",
		"empty hash":     "operator:$pbkdf2-sha256$600000$c2FsdHNhbHRzYWx0c2FsdA$",
	}
	for name, body := range cases {
		if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := console.NewCredentialStore(path)
		if _, err := s.Load(); err == nil {
			t.Errorf("%s: the record was accepted", name)
		}
	}
}

// TestShortPasswordIsRefused pins the length floor, which is the one constraint that
// costs an attacker work rather than costing the operator a memorable string.
func TestShortPasswordIsRefused(t *testing.T) {
	if _, err := console.HashPassword("eleven-byte", testIterations); err == nil {
		t.Fatal("an 11-byte password was accepted with a 12-byte floor")
	}
	if _, err := console.HashPassword("twelve-bytes", testIterations); err != nil {
		t.Fatalf("a 12-byte password was refused: %v", err)
	}
}

// TestNewRecordsUseTheShippedCost pins the documented work factor. The number is a
// constant this file cannot read, so it is asserted through its effect: a record at the
// shipped cost is at least as expensive as one at the floor, and the floor is refused.
func TestNewRecordsUseTheShippedCost(t *testing.T) {
	if console.CurrentIterations < 600_000 {
		t.Fatalf("new records use %d iterations, below the documented 600,000",
			console.CurrentIterations)
	}
	if _, err := console.HashPassword("correct-horse-battery", 1_000); err == nil {
		t.Fatal("a cost below the floor was accepted by HashPassword")
	}
}

// TestSocketIsSingleton is the property the whole daemon design rests on, and it is a
// property of the operating system rather than of this package - which is exactly why
// it is worth asserting rather than assuming.
func TestSocketIsSingleton(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "console.sock")

	first, err := console.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	if err := console.Probe(path); err != nil {
		t.Fatalf("a probe against a live listener must succeed: %v", err)
	}

	if _, err := console.Listen(path); err == nil {
		t.Fatal("a second listener bound the same path; two daemons could own one kernel")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("the socket has mode %04o, want 0600", got)
	}
}

// TestStaleSocketIsReclaimed pins the recovery path: a daemon killed without cleanup
// leaves a path that bind refuses, and the only safe response is to prove nobody is
// listening before removing it.
func TestStaleSocketIsReclaimed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "console.sock")

	first, err := console.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	// Close removes the path, so the file is recreated to model a crash that left one.
	_ = first.Close()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := console.Probe(path); !errors.Is(err, console.ErrNoDaemon) {
		t.Fatalf("a stale path must probe as ErrNoDaemon, got %v", err)
	}

	ln, err := console.Listen(path)
	if err != nil {
		t.Fatalf("a stale path must be reclaimed: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if err := console.Probe(path); err != nil {
		t.Fatalf("the reclaimed socket must accept: %v", err)
	}
}

// TestCloseRemovesThePath pins the other half: a clean stop must not leave a path the
// next start has to guess about.
func TestCloseRemovesThePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "console.sock")
	ln, err := console.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the socket path survived Close: %v", err)
	}
}

// TestProbeOnAnAbsentPath pins that a missing path is "not running" rather than an
// error a caller has to classify: the attach-or-start decision turns on that one bit.
func TestProbeOnAnAbsentPath(t *testing.T) {
	if err := console.Probe(filepath.Join(t.TempDir(), "nothing.sock")); !errors.Is(err, console.ErrNoDaemon) {
		t.Fatalf("an absent socket probed as %v, want ErrNoDaemon", err)
	}
}
