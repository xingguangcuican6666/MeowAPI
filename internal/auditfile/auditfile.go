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

// Package auditfile writes the kernel audit chain to a JSON Lines file, one sealed
// entry per line.
//
// It exists because the kernel's in-memory audit window is bounded: entries past it
// are evicted, and everything in memory is lost when the process exits. The sink is
// what makes the chain an investigation artifact rather than a diagnostic. Reading
// the file back and verifying it with kernel.VerifyChain reconstructs the trail
// without access to kernel memory, which is the property that makes the hash chain
// worth having.
//
// The format is deliberately append-only and line-oriented. A crash mid-write
// truncates one line rather than corrupting the file, and a truncated line is
// detectable: it fails to parse, and the chain stops verifying at that point, which
// is exactly what an investigator needs to know.
package auditfile

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// Sink appends audit entries to a file. It satisfies kernel.AuditSink and is
// safe for concurrent use, which matters because the kernel writes from whatever
// goroutine triggered the event.
type Sink struct {
	mu    sync.Mutex
	f     *os.File
	w     *bufio.Writer
	path  string
	every int64

	written int64
	failed  int64
	synced  bool
}

// Options configures a Sink.
type Options struct {
	// Path is the file to append to. Required.
	Path string
	// SyncEvery flushes and fsyncs after this many entries. One means every entry
	// is durable before WriteAudit returns, which is the right setting when the
	// audit trail is the point of the deployment and the throughput cost is
	// acceptable. Zero uses the default.
	//
	// The tradeoff is real and belongs to the operator: a larger batch loses up to
	// that many entries on a power cut, but each fsync is a disk round trip on the
	// kernel's own event path.
	SyncEvery int64
	// BufferSize is the writer buffer in bytes. Zero uses the default.
	BufferSize int
}

const (
	defaultSyncEvery  = int64(1)
	defaultBufferSize = 64 * 1024
)

// ErrNoPath is returned when Options.Path is empty.
var ErrNoPath = errors.New("auditfile: a path is required")

// New opens the audit file for appending and creates parent directories as needed.
//
// It appends rather than truncates. Overwriting an existing audit trail on startup
// would destroy the record of the previous run, which is precisely the record an
// investigation following a restart needs. An operator who wants a fresh file
// rotates it out of the way first.
func New(opts Options) (*Sink, error) {
	if opts.Path == "" {
		return nil, ErrNoPath
	}
	if opts.SyncEvery <= 0 {
		opts.SyncEvery = defaultSyncEvery
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = defaultBufferSize
	}

	if dir := filepath.Dir(opts.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("auditfile: creating %s: %w", dir, err)
		}
	}

	// 0o600 rather than 0o644: the chain records every denial, every module that
	// ran and every secret alias that was used. It is an operator artifact and
	// must not be world-readable by default.
	f, err := os.OpenFile(opts.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("auditfile: opening %s: %w", opts.Path, err)
	}

	return &Sink{
		f:     f,
		w:     bufio.NewWriterSize(f, opts.BufferSize),
		path:  opts.Path,
		every: opts.SyncEvery,
	}, nil
}

// syncEvery reports the durability interval. A zero or negative value falls back to
// the default rather than disabling syncs, so a misconfigured sink is durable rather
// than silently lossy.
func (s *Sink) syncEvery() int64 {
	if s.every <= 0 {
		return defaultSyncEvery
	}
	return s.every
}

// WriteAudit appends one sealed entry. It never returns a panic into the kernel and
// it never blocks the kernel on a full disk beyond the write itself: an error is
// counted and returned, and the kernel records a fault.
func (s *Sink) WriteAudit(e kernel.AuditEntry) error {
	line, err := json.Marshal(e)
	if err != nil {
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		return fmt.Errorf("auditfile: encoding seq %d: %w", e.Seq, err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.f == nil {
		s.failed++
		return errors.New("auditfile: sink is closed")
	}

	if _, err := s.w.Write(line); err != nil {
		s.failed++
		return fmt.Errorf("auditfile: writing seq %d: %w", e.Seq, err)
	}
	s.written++

	if s.written%s.syncEvery() == 0 {
		if err := s.flushLocked(); err != nil {
			s.failed++
			return err
		}
		s.synced = true
	}
	return nil
}

func (s *Sink) flushLocked() error {
	if err := s.w.Flush(); err != nil {
		return fmt.Errorf("auditfile: flush: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("auditfile: fsync: %w", err)
	}
	return nil
}

// Flush forces buffered entries to disk. Call it before a planned shutdown, or at
// any point where losing the tail would matter.
func (s *Sink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return errors.New("auditfile: sink is closed")
	}
	if err := s.flushLocked(); err != nil {
		return err
	}
	s.synced = true
	return nil
}

// Close flushes and closes the file. It is idempotent.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.flushLocked()
	cerr := s.f.Close()
	s.f = nil
	s.w = nil
	if err != nil {
		return err
	}
	return cerr
}

// Path returns the file this sink writes to.
func (s *Sink) Path() string { return s.path }

// Stats reports how many entries were written, how many writes failed, and whether
// at least one fsync completed. A non-zero failure count means the trail has a hole,
// and the hole is visible here rather than only inferable from a gap in sequence
// numbers.
func (s *Sink) Stats() (written int64, failed int64, synced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written, s.failed, s.synced
}

// Read loads a chain from a file written by this package.
//
// A line that fails to parse is reported rather than skipped, because a truncated
// or edited line is the interesting case: silently skipping it would turn evidence
// of tampering into a shorter chain that still verifies.
func Read(path string) ([]kernel.AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return parse(f, path)
}

// ReadFrom parses a chain from any reader, for tests and for an investigator
// working from a piped or downloaded file.
func ReadFrom(r io.Reader, name string) ([]kernel.AuditEntry, error) { return parse(r, name) }

func parse(r io.Reader, name string) ([]kernel.AuditEntry, error) {
	var out []kernel.AuditEntry
	sc := bufio.NewScanner(r)
	// Audit entries carry arbitrary fields, so a single line can exceed the
	// default 64KiB scanner buffer. Raise it rather than fail on a legitimate
	// long record.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e kernel.AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return out, fmt.Errorf("%s:%d: unparseable audit line: %w", name, line, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("auditfile: reading %s: %w", name, err)
	}
	return out, nil
}

// Segments splits a file's entries into per-boot chains.
//
// The file is append-only across restarts, and each boot starts a fresh chain from
// the genesis anchor with sequence numbering reset to zero. So a long-lived file is
// a sequence of chains, not one chain, and verifying it as one chain reports a
// break at the second boot even though nothing was tampered with.
//
// This is the honest way to verify a real deployment's audit file, and it also
// keeps tampering detectable: an entry deleted or edited inside a segment still
// fails that segment's verification, and a segment that does not start at genesis
// is itself suspicious, because an attacker who splices a forged boot into the
// middle of the file has to invent a genesis anchor to do it.
func Segments(entries []kernel.AuditEntry) [][]kernel.AuditEntry {
	var out [][]kernel.AuditEntry
	var cur []kernel.AuditEntry
	for _, e := range entries {
		if e.Prev == kernel.AuditGenesis && len(cur) > 0 {
			out = append(out, cur)
			cur = nil
		}
		cur = append(cur, e)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// VerifyFile checks every boot segment in a file. It returns the first failing
// segment index and the entry index within it, or -1 for both when every segment
// verifies. The segment count is returned so a caller can report how many boots
// the file covers.
//
// Checking each segment from genesis is what makes restarts work without giving up
// detection: an edit anywhere breaks the segment it is in.
func VerifyFile(entries []kernel.AuditEntry) (segments int, badSegment int, badEntry int) {
	segs := Segments(entries)
	for i, seg := range segs {
		if idx := kernel.VerifyChain(seg, kernel.AuditGenesis); idx != -1 {
			return len(segs), i, idx
		}
	}
	return len(segs), -1, -1
}
