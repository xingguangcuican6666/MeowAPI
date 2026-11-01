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

// Package console is the operator's tty: the daemon that holds a booted kernel,
// the unix socket sessions attach to, the command table those sessions run, and
// the password gate in front of all of it.
//
// It is host code and not kernel code, and the distinction is the whole design.
// The kernel owns the policy; this package owns the terminal. Nothing here makes
// an authorization decision of its own - a privileged act goes through ktty's
// syscalls, which re-check the operation and the credential inside the kernel and
// put the act on the audit chain before the caller sees a result. What this
// package adds is the part the kernel cannot see: who is at the keyboard.
package console

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The credential record is shadow-style: a hash, a salt and a cost, and never the
// password. Nothing here stores the plaintext or returns it.
//
// What this package cannot promise, and does not claim, is wiping it. A Go string
// is immutable, so a password read off the terminal and passed as a string cannot
// be zeroed by the callee - that is why the kernel's own credential entry points
// take []byte and wipe it, which is the right shape for a caller that owns the
// buffer. The reader in this package keeps the plaintext off disk and off every
// log line, which is the part that is in its control.
//
// The file is written 0600 inside a directory written 0700, so the socket and the
// hash have the same trust boundary: the owning user. That boundary is what makes
// first-boot provisioning safe - with no record on disk yet, whoever can reach the
// socket is whoever can read the directory, and that is the operator.
const (
	// hashScheme identifies the construction. A record naming its scheme is one a
	// future version can upgrade without guessing, and one an auditor can read.
	hashScheme = "pbkdf2-sha256"
	// CurrentIterations is the cost a NEW record is written at. OWASP's 2023
	// guidance for PBKDF2-HMAC-SHA256 is 600,000. The number is stored in the
	// record rather than assumed at verify time, so raising it later re-costs new
	// passwords without invalidating old ones.
	CurrentIterations = 600_000
	// minIterations is the floor a stored record is accepted at. A record below it
	// is refused rather than verified, because a hand-edited file that lowered the
	// cost would otherwise silently weaken the gate.
	minIterations = 100_000
	saltBytes     = 16
	keyLen        = 32
	// minPasswordBytes is the operator-facing floor. It is not a complexity rule:
	// a length floor is the one constraint that costs an attacker work rather than
	// costing the operator a memorable string.
	minPasswordBytes = 12
	maxPasswordBytes = 1024
	// operatorName is the single record this file holds. Multi-user is an external
	// module's business; the format is a shadow file so that module can extend it
	// rather than replace it.
	operatorName = "operator"
)

// ErrNoCredential is returned when no record exists yet, which is the
// first-boot case rather than an error. Callers turn it into a prompt to set one.
var ErrNoCredential = errors.New("console: no operator password is set")

// credential is one parsed shadow record.
type credential struct {
	name       string
	scheme     string
	iterations int
	salt       []byte
	hash       []byte
}

// HashPassword derives a record from a plaintext password. The password is not
// retained: the returned credential holds only derived material.
func HashPassword(password string, iterations int) (*credential, error) {
	if n := len(password); n < minPasswordBytes {
		return nil, fmt.Errorf("a password must be at least %d bytes, not %d", minPasswordBytes, n)
	}
	if n := len(password); n > maxPasswordBytes {
		return nil, fmt.Errorf("a password must be at most %d bytes, not %d", maxPasswordBytes, n)
	}
	if iterations < minIterations {
		return nil, fmt.Errorf("iterations must be at least %d, not %d", minIterations, iterations)
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("reading entropy for the password salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving the password hash: %w", err)
	}
	return &credential{
		name:       operatorName,
		scheme:     hashScheme,
		iterations: iterations,
		salt:       salt,
		hash:       key,
	}, nil
}

// deriveForKernel returns the secret this record installs in ktty.
//
// It is a derivation of the stored hash rather than the password, and the reason
// is that the daemon should never have to keep a plaintext around in order to
// satisfy a syscall. ktty's requirement is a value a module cannot read and that
// the host can present; a second PBKDF2 pass over the stored hash with a fixed
// label meets it, and it means a leak of the derived value does not leak the
// password an operator types.
//
// The label is fixed rather than per-boot on purpose: the value must be
// reproducible across daemon restarts so a shadow file written by one run is
// accepted by the next without re-deriving anything the operator typed.
//
// The returned buffer belongs to the caller, and InstallConsoleCredential wipes it.
func (c *credential) deriveForKernel() []byte {
	// The stored hash is the password input here, so the string conversion is a
	// byte-for-byte copy of binary material rather than text. pbkdf2.Key takes a
	// string and that is the only reason for the conversion.
	key, err := pbkdf2.Key(sha256.New, string(c.hash), []byte(kernelCredentialLabel),
		kernelCredentialIterations, keyLen)
	if err != nil {
		// Unreachable with a fixed label, a 32-byte salt and a legal length, but a
		// nil return here would be indistinguishable from "no credential" to the
		// caller, so the derivation falls back to the stored hash itself, which is
		// still a value no module can read.
		out := make([]byte, len(c.hash))
		copy(out, c.hash)
		return out
	}
	return key
}

const (
	// kernelCredentialLabel separates this derivation from the password one. Two
	// derivations of the same secret with the same parameters would be the same
	// secret, and the whole point is that the value the kernel holds is not the
	// value an operator types.
	kernelCredentialLabel = "meowapi/console-credential/v1"
	// kernelCredentialIterations is lower than the password cost because this
	// derivation runs over an already-expensive hash, not over a human-chosen
	// password. Its job is separation, not slowing a guess.
	kernelCredentialIterations = 4096
)

// Check reports whether password matches this record. The comparison is constant
// time, and the derivation runs at the record's own cost so a file written by an
// older version verifies unchanged.
func (c *credential) Check(password string) bool {
	if c == nil || c.scheme != hashScheme {
		return false
	}
	if len(password) > maxPasswordBytes {
		return false
	}
	derived, err := pbkdf2.Key(sha256.New, password, c.salt, c.iterations, keyLen)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derived, c.hash) == 1
}

// encode renders the record in shadow form:
// $pbkdf2-sha256$<iterations>$<b64 salt>$<b64 hash>.
func (c *credential) encode() string {
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("%s:$%s$%d$%s$%s", c.name, c.scheme, c.iterations, b64(c.salt), b64(c.hash))
}

// decode parses one shadow line. A malformed line is an error rather than a
// skipped record: silently ignoring an unreadable credential file is how a gate
// becomes open without anyone deciding to open it.
func decode(line string) (*credential, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}
	name, rest, ok := strings.Cut(line, ":")
	if !ok {
		return nil, fmt.Errorf("a credential line must be name:hash, got %q", truncate(line))
	}
	// Five fields: "", scheme, iterations, salt, hash. The leading empty field is
	// the part before the first "$".
	f := strings.Split(rest, "$")
	if len(f) != 5 || f[0] != "" {
		return nil, fmt.Errorf("credential for %q is not $scheme$iterations$salt$hash", name)
	}
	if f[1] != hashScheme {
		return nil, fmt.Errorf("credential for %q uses scheme %q, which this build does not support", name, f[1])
	}
	iters, err := strconv.Atoi(f[2])
	if err != nil {
		return nil, fmt.Errorf("credential for %q has a non-numeric cost %q", name, f[2])
	}
	if iters < minIterations {
		return nil, fmt.Errorf("credential for %q has a cost of %d, below the floor of %d", name, iters, minIterations)
	}
	b64 := base64.RawStdEncoding.DecodeString
	salt, err := b64(f[3])
	if err != nil || len(salt) < saltBytes {
		return nil, fmt.Errorf("credential for %q has an unusable salt", name)
	}
	hash, err := b64(f[4])
	if err != nil || len(hash) != keyLen {
		return nil, fmt.Errorf("credential for %q has an unusable hash", name)
	}
	return &credential{name: name, scheme: f[1], iterations: iters, salt: salt, hash: hash}, nil
}

// CredentialStore is the shadow file: where it lives, and the read/write rules
// around it. It is a struct rather than a bare path so the directory permissions
// are set by the same code that writes the file, and neither can be forgotten.
type CredentialStore struct {
	path string
}

// NewCredentialStore returns a store for path. Nothing is read or created yet.
func NewCredentialStore(path string) *CredentialStore { return &CredentialStore{path: path} }

// Path reports where the record lives, for a status line an operator can act on.
func (s *CredentialStore) Path() string { return s.path }

// Load reads the operator record. A missing file returns ErrNoCredential, which
// is the first-boot case; a malformed file returns an error naming it.
func (s *CredentialStore) Load() (*credential, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoCredential
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.path, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		c, err := decode(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.path, err)
		}
		if c != nil && c.name == operatorName {
			return c, nil
		}
	}
	return nil, ErrNoCredential
}

// Save writes the record, replacing the file rather than appending to it.
//
// The write is atomic-or-nothing: a temporary file in the same directory, then a
// rename. A credential file truncated by a crash between open and write is worse
// than the old one surviving, because an absent record reads as first-boot and
// first-boot is the one moment the gate is open to whoever holds the socket.
func (s *CredentialStore) Save(c *credential) error {
	if c == nil {
		return errors.New("refusing to write a nil credential")
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("tightening %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".shadow-*")
	if err != nil {
		return fmt.Errorf("creating a temporary credential file: %w", err)
	}
	tmpName := tmp.Name()
	// Closed and removed on every failure path, so a partial write is never left
	// beside the real file for the next Load to find.
	defer func() { _ = os.Remove(tmpName) }()

	content := "# MeowAPI operator credential. A hash, never the password.\n" +
		"# Format: name:$scheme$iterations$base64salt$base64hash\n" +
		c.encode() + "\n"
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing the credential file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing the credential file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing the credential file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("setting the credential file's mode: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("installing the credential file: %w", err)
	}
	return nil
}

// CheckPassword loads the record and verifies against it. ErrNoCredential passes
// through so the caller can tell "not set up yet" from "wrong password" - and the
// two must stay distinguishable to the daemon while staying indistinguishable to a
// client, which is what the server does with them.
func (s *CredentialStore) CheckPassword(password string) error {
	c, err := s.Load()
	if err != nil {
		return err
	}
	if !c.Check(password) {
		return errWrongPassword
	}
	return nil
}

// errWrongPassword is a single value, compared by identity rather than rendered,
// so no caller can accidentally leak which check failed.
var errWrongPassword = errors.New("console: the password is wrong")

// truncate keeps an error message from echoing a whole credential line back into a
// log. Twelve bytes is enough to recognise a record and not enough to use one.
func truncate(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "..."
}
