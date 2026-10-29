/*
Copyright (C) 2023-2026 xingguangcuican6666

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

package auditfile_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/internal/auditfile"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// bootWithSink boots a kernel whose audit chain spills to path and returns the
// kernel plus the sink. The caller shuts both down.
func bootWithSink(t *testing.T, path string, opts auditfile.Options) (*kernel.Kernel, *auditfile.Sink) {
	t.Helper()
	opts.Path = path
	sink, err := auditfile.New(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	k, err := kernel.Boot(kernel.BootConfig{
		AuditSink: sink,
		TrustRoot: kernel.BootTrustRoot{NodeID: "auditfile-test"},
	})
	require.NoError(t, err)
	return k, sink
}

// TestFileChainVerifiesIndependently is the reason this package exists. An
// investigator reads the file after the process is gone, with no access to kernel
// memory, and can still prove the trail was not edited.
func TestFileChainVerifiesIndependently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	k, sink := bootWithSink(t, path, auditfile.Options{})

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid))
	require.NoError(t, k.Shutdown())

	require.NoError(t, sink.Flush())

	fromFile, err := auditfile.Read(path)
	require.NoError(t, err)
	require.NotEmpty(t, fromFile)

	assert.Equal(t, -1, kernel.VerifyChain(fromFile, kernel.AuditGenesis),
		"the chain read back from disk must verify from genesis")
	for _, e := range fromFile {
		assert.True(t, kernel.VerifyEntry(e), "seq %d must recompute", e.Seq)
	}

	// The kinds an investigation actually asks for are present.
	kinds := map[kernel.AuditKind]int{}
	for _, e := range fromFile {
		kinds[e.Kind]++
	}
	assert.Positive(t, kinds[kernel.AuditBoot])
	assert.Positive(t, kinds[kernel.AuditLoad])
	assert.Positive(t, kinds[kernel.AuditUnload])
	assert.Positive(t, kinds[kernel.AuditShutdown])
	assert.Positive(t, kinds[kernel.AuditDenial],
		"diag trips metadata:write on purpose, so a denial must be on disk")
}

// TestFileChainMatchesMemory asserts the file is not a lossy summary. Every entry
// the kernel held in memory must be on disk, byte-identical in the fields that
// matter, and in the same order.
func TestFileChainMatchesMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	k, sink := bootWithSink(t, path, auditfile.Options{})

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid))

	// Snapshot memory while running. Shutdown afterwards writes one more entry, so
	// the file legitimately holds more than this snapshot; what must hold is that
	// the snapshot is an exact prefix of the file, in order.
	inMemory := kernel.AuditQuery(kernel.AuditFilter{})
	require.NoError(t, k.Shutdown())
	require.NoError(t, sink.Flush())

	fromFile, err := auditfile.Read(path)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(fromFile), len(inMemory),
		"the file must hold every entry memory held, not a windowed subset")
	for i := range inMemory {
		assert.Equal(t, inMemory[i].Seq, fromFile[i].Seq)
		assert.Equal(t, inMemory[i].Kind, fromFile[i].Kind)
		assert.Equal(t, inMemory[i].Hash, fromFile[i].Hash,
			"hashes must survive the round trip, or the file cannot be verified against memory")
		assert.Equal(t, inMemory[i].Prev, fromFile[i].Prev)
		assert.Equal(t, inMemory[i].Msg, fromFile[i].Msg)
		assert.Equal(t, inMemory[i].PID, fromFile[i].PID)
		assert.Equal(t, inMemory[i].Domain, fromFile[i].Domain)
	}
}

// TestFileSurvivesWindowEviction is the property that makes the bounded memory
// window safe. Entries evicted from memory must still be on disk, so shrinking the
// window loses nothing an investigator needs.
func TestFileSurvivesWindowEviction(t *testing.T) {
	dir := t.TempDir()
	// The second boot gets its own file, the way a real deployment rotates on
	// restart. Two chains in one file is legitimate but is what
	// TestAppendDoesNotTruncate covers; this test is about the window.
	path := filepath.Join(dir, "small-window.log")
	small, err := auditfile.New(auditfile.Options{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = small.Close() })

	k2, err := kernel.Boot(kernel.BootConfig{
		AuditSink:   small,
		AuditWindow: kernel.MinAuditWindow(),
		TrustRoot:   kernel.BootTrustRoot{NodeID: "evict-test"},
	})
	require.NoError(t, err)

	for range 60 {
		k2.Publish("k", "v")
	}

	// Assert the window while the kernel is live, because shutdown resets it.
	retained, evicted := kernel.AuditLen()
	assert.LessOrEqual(t, retained, kernel.MinAuditWindow(),
		"the memory window must be capped")
	assert.Positive(t, evicted, "entries beyond the window must be evicted, and the eviction counted")
	oldest := kernel.AuditQuery(kernel.AuditFilter{Limit: 1})
	require.NotEmpty(t, oldest)
	require.NoError(t, k2.Shutdown())
	require.NoError(t, small.Flush())

	fromFile, err := auditfile.Read(path)
	require.NoError(t, err)

	// The file holds the whole history, including everything the window evicted,
	// which is the property under test: bounding memory loses nothing that an
	// investigation needs.
	assert.Greater(t, len(fromFile), retained,
		"the file must hold more than the memory window ever could")
	require.NotEmpty(t, fromFile)

	// It verifies from its own first entry. The chain in the file starts at the
	// genesis of the second boot, so use the first line's Prev as the anchor
	// rather than the genesis constant: a chain read from the middle of a stream is
	// still a chain, it just has a different anchor.
	assert.Equal(t, kernel.AuditGenesis, fromFile[0].Prev,
		"this file holds exactly one boot, so its chain starts at genesis")
	assert.Equal(t, -1, kernel.VerifyChain(fromFile, kernel.AuditGenesis),
		"the on-disk chain must verify from genesis")

	// What memory still held is on disk too, so eviction dropped nothing live.
	assert.True(t, hasSeq(fromFile, oldest[0].Seq),
		"the oldest retained entry must be on disk")

	// And the sequence numbers in the file are contiguous, so a dropped line would
	// show as a gap here as well as a broken link.
	for i := 1; i < len(fromFile); i++ {
		assert.Equal(t, fromFile[i-1].Seq+1, fromFile[i].Seq,
			"the file's sequence numbers must be contiguous")
	}
}

func hasSeq(entries []kernel.AuditEntry, seq int64) bool {
	for _, e := range entries {
		if e.Seq == seq {
			return true
		}
	}
	return false
}

// TestTamperingWithTheFileIsDetected is the negative control. Each mutation is
// something an attacker with write access to the audit file would try, and each
// must break verification rather than pass.
func TestTamperingWithTheFileIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	k, sink := bootWithSink(t, path, auditfile.Options{})

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid))
	require.NoError(t, k.Shutdown())
	require.NoError(t, sink.Flush())

	clean, err := auditfile.Read(path)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(clean), 4)
	require.Equal(t, -1, kernel.VerifyChain(clean, kernel.AuditGenesis))

	cases := []struct {
		name   string
		mutate func(e []kernel.AuditEntry) []kernel.AuditEntry
	}{
		{"rewrite a message", func(e []kernel.AuditEntry) []kernel.AuditEntry {
			out := append([]kernel.AuditEntry(nil), e...)
			out[1].Msg = "nothing happened"
			return out
		}},
		{"drop the denial", func(e []kernel.AuditEntry) []kernel.AuditEntry {
			var out []kernel.AuditEntry
			for _, x := range e {
				if x.Kind != kernel.AuditDenial {
					out = append(out, x)
				}
			}
			return out
		}},
		{"change a hash", func(e []kernel.AuditEntry) []kernel.AuditEntry {
			out := append([]kernel.AuditEntry(nil), e...)
			out[1].Hash = strings.Repeat("a", 64)
			return out
		}},
		{"relink the chain", func(e []kernel.AuditEntry) []kernel.AuditEntry {
			out := append([]kernel.AuditEntry(nil), e...)
			out[2].Prev = out[0].Hash
			return out
		}},
		{"append a forged entry", func(e []kernel.AuditEntry) []kernel.AuditEntry {
			out := append([]kernel.AuditEntry(nil), e...)
			return append(out, kernel.AuditEntry{
				Seq: int64(len(out)), Kind: kernel.AuditLoad, Msg: "forged load",
				Prev: out[len(out)-1].Hash, Hash: strings.Repeat("b", 64),
			})
		}},
		{"reorder", func(e []kernel.AuditEntry) []kernel.AuditEntry {
			out := append([]kernel.AuditEntry(nil), e...)
			out[1], out[2] = out[2], out[1]
			return out
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tampered := c.mutate(clean)
			idx := kernel.VerifyChain(tampered, kernel.AuditGenesis)
			assert.NotEqual(t, -1, idx, "%s must break chain verification", c.name)
		})
	}
}

// TestRawFileTamperingIsDetected works at the byte level, which is the level an
// attacker actually operates at. Editing the file with a text editor must not
// produce a chain that verifies.
func TestRawFileTamperingIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	k, sink := bootWithSink(t, path, auditfile.Options{})
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid))
	require.NoError(t, k.Shutdown())
	require.NoError(t, sink.Close())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, -1, kernel.VerifyChain(mustParse(t, raw), kernel.AuditGenesis))

	// Rewrite a message in place, keeping the JSON valid.
	edited := bytes.Replace(raw, []byte("module loaded"), []byte("module LOADED"), 1)
	require.NotEqual(t, raw, edited, "the fixture must actually contain the target string")
	tampered := mustParse(t, edited)
	assert.NotEqual(t, -1, kernel.VerifyChain(tampered, kernel.AuditGenesis),
		"a byte-level edit must break the chain")

	// Delete a whole line, which is the cheapest way to hide an event.
	lines := bytes.Split(raw, []byte("\n"))
	require.Greater(t, len(lines), 3)
	shortened := bytes.Join(append(append([][]byte{}, lines[:2]...), lines[3:]...), []byte("\n"))
	assert.NotEqual(t, -1, kernel.VerifyChain(mustParse(t, shortened), kernel.AuditGenesis),
		"deleting a line must break the chain")
}

func mustParse(t *testing.T, raw []byte) []kernel.AuditEntry {
	t.Helper()
	entries, err := auditfile.ReadFrom(bytes.NewReader(raw), "fixture")
	require.NoError(t, err)
	return entries
}

// TestUnparseableLineIsReportedNotSkipped covers the truncation case. A partially
// written line means the process died mid-write or someone edited the file, and
// silently skipping it would turn either into a shorter chain that still verifies.
func TestUnparseableLineIsReportedNotSkipped(t *testing.T) {
	good := `{"seq":0,"time":1,"kind":"boot","pid":0,"msg":"x","prev":"0","hash":"h"}`
	cases := []struct {
		name string
		body string
	}{
		{"truncated json", good + "\n{\"seq\":1,\"kin"},
		{"not json at all", good + "\nthis is not an audit entry"},
		{"binary garbage", good + "\n\x00\x01\x02\xff"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := auditfile.ReadFrom(strings.NewReader(c.body), "fixture")
			require.Error(t, err, "an unparseable line must be reported, not skipped")
			assert.Contains(t, err.Error(), "unparseable audit line")
		})
	}
}

// TestAppendDoesNotTruncate covers the restart behavior. Overwriting the trail on
// startup would destroy the record of the previous run, which is the record an
// investigation following a restart needs.
func TestAppendDoesNotTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	k1, s1 := bootWithSink(t, path, auditfile.Options{})
	require.NoError(t, k1.Shutdown())
	require.NoError(t, s1.Close())

	first, err := auditfile.Read(path)
	require.NoError(t, err)
	require.NotEmpty(t, first)

	s2, err := auditfile.New(auditfile.Options{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })
	k2, err := kernel.Boot(kernel.BootConfig{
		AuditSink: s2, TrustRoot: kernel.BootTrustRoot{NodeID: "second-run"},
	})
	require.NoError(t, err)
	require.NoError(t, k2.Shutdown())
	require.NoError(t, s2.Close())

	both, err := auditfile.Read(path)
	require.NoError(t, err)
	assert.Greater(t, len(both), len(first), "a restart must append, not overwrite")

	// The first run's entries are still at the front, untouched.
	for i := range first {
		assert.Equal(t, first[i].Hash, both[i].Hash, "the previous run's entries must be intact")
	}

	// Each run's chain verifies on its own, from its own genesis. The second run
	// restarts sequence numbering, so the concatenation is two chains rather than
	// one; that is correct, and an investigator splices with the second run's first
	// Prev as the anchor.
	assert.Equal(t, -1, kernel.VerifyChain(first, kernel.AuditGenesis))
	secondRun := both[len(first):]
	require.NotEmpty(t, secondRun)
	assert.Equal(t, -1, kernel.VerifyChain(secondRun, secondRun[0].Prev))
}

// TestConcurrentWritesAreNotInterleaved covers the kernel writing from whatever
// goroutine triggered an event. A torn line would be indistinguishable from
// tampering, so the sink must serialize.
func TestConcurrentWritesAreNotInterleaved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := auditfile.New(auditfile.Options{Path: path, SyncEvery: 8})
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	const writers, each = 16, 200
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range each {
				e := kernel.AuditEntry{
					Seq: int64(w*each + i), Kind: kernel.AuditRequest,
					Msg: strings.Repeat("x", 64), Prev: "p", Hash: "h",
					Fields: map[string]any{"w": w, "i": i},
				}
				assert.NoError(t, sink.WriteAudit(e))
			}
		}(w)
	}
	wg.Wait()
	require.NoError(t, sink.Flush())

	got, err := auditfile.Read(path)
	require.NoError(t, err, "every line must parse, so no write was torn")
	assert.Len(t, got, writers*each)

	written, failed, synced := sink.Stats()
	assert.Equal(t, int64(writers*each), written)
	assert.Zero(t, failed)
	assert.True(t, synced)
}

// TestSyncIntervalIsHonored covers the durability knob.
func TestSyncIntervalIsHonored(t *testing.T) {
	dir := t.TempDir()

	every := filepath.Join(dir, "every.log")
	s1, err := auditfile.New(auditfile.Options{Path: every, SyncEvery: 1})
	require.NoError(t, err)
	require.NoError(t, s1.WriteAudit(kernel.AuditEntry{Seq: 0, Kind: kernel.AuditBoot, Msg: "x", Hash: "h"}))
	_, _, synced := s1.Stats()
	assert.True(t, synced, "SyncEvery 1 must fsync on the first entry")
	require.NoError(t, s1.Close())

	batched := filepath.Join(dir, "batched.log")
	s2, err := auditfile.New(auditfile.Options{Path: batched, SyncEvery: 10})
	require.NoError(t, err)
	for i := range 5 {
		require.NoError(t, s2.WriteAudit(kernel.AuditEntry{Seq: int64(i), Kind: kernel.AuditRequest, Msg: "x"}))
	}
	_, _, synced = s2.Stats()
	assert.False(t, synced, "a batch of 10 must not have fsynced after 5 entries")
	require.NoError(t, s2.Flush())
	_, _, synced = s2.Stats()
	assert.True(t, synced, "an explicit Flush must fsync")
	require.NoError(t, s2.Close())
}

// TestZeroSyncEveryDefaultsToDurable covers the misconfiguration case: a zero
// interval must fall back to syncing every entry rather than never syncing, because
// a silently lossy audit trail is worse than a slow one.
func TestZeroSyncEveryDefaultsToDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := auditfile.New(auditfile.Options{Path: path, SyncEvery: 0})
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	require.NoError(t, sink.WriteAudit(kernel.AuditEntry{Seq: 0, Kind: kernel.AuditBoot, Msg: "x"}))
	_, _, synced := sink.Stats()
	assert.True(t, synced, "a zero interval must default to syncing, not to never syncing")

	// Negative is treated the same way.
	path2 := filepath.Join(t.TempDir(), "audit2.log")
	sink2, err := auditfile.New(auditfile.Options{Path: path2, SyncEvery: -5})
	require.NoError(t, err)
	defer func() { _ = sink2.Close() }()
	require.NoError(t, sink2.WriteAudit(kernel.AuditEntry{Seq: 0, Kind: kernel.AuditBoot, Msg: "x"}))
	_, _, synced = sink2.Stats()
	assert.True(t, synced)
}

// TestFileIsNotWorldReadable covers the permission choice. The chain records every
// denial, every module that ran and every secret alias used, so it is an operator
// artifact.
func TestFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := auditfile.New(auditfile.Options{Path: path})
	require.NoError(t, err)
	require.NoError(t, sink.WriteAudit(kernel.AuditEntry{Seq: 0, Kind: kernel.AuditBoot, Msg: "x"}))
	require.NoError(t, sink.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"the audit file must be owner-only: it records denials and secret aliases")
}

// TestSecretValuesNeverReachTheFile is the leakage assertion for this package. The
// signing key lives in the sealed trust root and must not appear anywhere on disk,
// including through a module that tries to publish it into metadata first.
func TestSecretValuesNeverReachTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := auditfile.New(auditfile.Options{Path: path})
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	const secret = "SECRET-KEY-MATERIAL"
	k, err := kernel.Boot(kernel.BootConfig{
		AuditSink: sink,
		TrustRoot: kernel.BootTrustRoot{NodeID: "leak-test", SigningKeyPEM: secret},
	})
	require.NoError(t, err)

	// Publishing is audited by key only, so even an operator publishing a secret
	// under a metadata key does not put the value in the chain.
	k.Publish("provider.api_key", secret)
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid))
	require.NoError(t, k.Shutdown())
	require.NoError(t, sink.Close())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), secret,
		"key material must never reach the audit file, by any path")
	assert.Contains(t, string(raw), "provider.api_key",
		"the key name is recorded; only the value is withheld")
}

// TestNewValidatesItsArguments covers the failure modes at construction.
func TestNewValidatesItsArguments(t *testing.T) {
	_, err := auditfile.New(auditfile.Options{})
	assert.ErrorIs(t, err, auditfile.ErrNoPath)

	// Parent directories are created, so a nested path works.
	nested := filepath.Join(t.TempDir(), "a", "b", "c", "audit.log")
	sink, err := auditfile.New(auditfile.Options{Path: nested})
	require.NoError(t, err)
	require.NoError(t, sink.Close())
	_, err = os.Stat(nested)
	assert.NoError(t, err)

	// An unwritable path is an error, not a panic.
	_, err = auditfile.New(auditfile.Options{Path: filepath.Join(os.DevNull, "impossible", "x.log")})
	assert.Error(t, err)
}

// TestClosedSinkRefusesWrites covers the lifecycle. A write after Close must fail
// with a counted error rather than panic on a nil file.
func TestClosedSinkRefusesWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := auditfile.New(auditfile.Options{Path: path})
	require.NoError(t, err)
	require.NoError(t, sink.WriteAudit(kernel.AuditEntry{Seq: 0, Kind: kernel.AuditBoot, Msg: "x"}))
	require.NoError(t, sink.Close())
	assert.NoError(t, sink.Close(), "Close must be idempotent")

	err = sink.WriteAudit(kernel.AuditEntry{Seq: 1, Kind: kernel.AuditRequest, Msg: "late"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
	assert.Error(t, sink.Flush())

	_, failed, _ := sink.Stats()
	assert.Equal(t, int64(1), failed, "the refused write must be counted")

	assert.Equal(t, path, sink.Path())
}

// TestReadMissingFileIsAnError distinguishes "no trail" from "empty trail", which
// an investigation has to be able to tell apart.
func TestReadMissingFileIsAnError(t *testing.T) {
	_, err := auditfile.Read(filepath.Join(t.TempDir(), "absent.log"))
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err), "a missing file must surface as not-exist")

	// An existing but empty file is a valid empty chain, not an error.
	empty := filepath.Join(t.TempDir(), "empty.log")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))
	got, err := auditfile.Read(empty)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, -1, kernel.VerifyChain(got, kernel.AuditGenesis))
}

// TestLongFieldsDoNotBreakTheScanner covers a legitimate long record. Audit fields
// are arbitrary, so a single line can exceed the default 64KiB scanner buffer and
// must not be reported as corrupt.
func TestLongFieldsDoNotBreakTheScanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := auditfile.New(auditfile.Options{Path: path})
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	big := strings.Repeat("y", 200*1024)
	require.NoError(t, sink.WriteAudit(kernel.AuditEntry{
		Seq: 0, Kind: kernel.AuditRequest, Msg: "large payload",
		Prev: kernel.AuditGenesis, Hash: "h",
		Fields: map[string]any{"blob": big},
	}))
	require.NoError(t, sink.Close())

	got, err := auditfile.Read(path)
	require.NoError(t, err, "a long line must parse")
	require.Len(t, got, 1)
	assert.Equal(t, big, got[0].Fields["blob"])
}

// TestVerifyFileSplitsBoots covers the restart case end to end through the helper a
// real deployment uses. Without it, a second boot appended to the same file looks
// like a broken chain, and an operator who sees that once stops trusting the check.
func TestVerifyFileSplitsBoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	for i := range 3 {
		sink, err := auditfile.New(auditfile.Options{Path: path})
		require.NoError(t, err)
		k, err := kernel.Boot(kernel.BootConfig{
			AuditSink: sink,
			TrustRoot: kernel.BootTrustRoot{NodeID: "boot-" + string(rune('a'+i))},
		})
		require.NoError(t, err)
		pid, err := k.Load(diag.Manifest())
		require.NoError(t, err)
		require.NoError(t, k.Unload(pid))
		require.NoError(t, k.Shutdown())
		require.NoError(t, sink.Close())
	}

	entries, err := auditfile.Read(path)
	require.NoError(t, err)

	segs, badSeg, badEntry := auditfile.VerifyFile(entries)
	assert.Equal(t, -1, badSeg, "every boot segment must verify")
	assert.Equal(t, -1, badEntry)
	assert.Equal(t, 3, segs, "three boots must produce three segments")

	// Verifying the whole file as one chain would report a break at the second
	// boot, which is the false positive this helper exists to avoid.
	assert.NotEqual(t, -1, kernel.VerifyChain(entries, kernel.AuditGenesis),
		"a multi-boot file is not one chain")

	// And each segment verifies from genesis on its own.
	for i, seg := range auditfile.Segments(entries) {
		require.NotEmpty(t, seg)
		assert.Equal(t, kernel.AuditGenesis, seg[0].Prev, "segment %d must start at genesis", i)
		assert.Equal(t, -1, kernel.VerifyChain(seg, kernel.AuditGenesis))
		assert.Equal(t, int64(0), seg[0].Seq, "sequence numbering restarts each boot")
	}
}

// TestVerifyFileDetectsTamperingInsideASegment is the other half: splitting by boot
// must not weaken detection. An edit in the middle segment must be found, and the
// report must say which boot it is in.
func TestVerifyFileDetectsTamperingInsideASegment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	for range 2 {
		sink, err := auditfile.New(auditfile.Options{Path: path})
		require.NoError(t, err)
		k, err := kernel.Boot(kernel.BootConfig{AuditSink: sink, TrustRoot: kernel.BootTrustRoot{NodeID: "n"}})
		require.NoError(t, err)
		pid, err := k.Load(diag.Manifest())
		require.NoError(t, err)
		require.NoError(t, k.Unload(pid))
		require.NoError(t, k.Shutdown())
		require.NoError(t, sink.Close())
	}

	entries, err := auditfile.Read(path)
	require.NoError(t, err)
	segs := auditfile.Segments(entries)
	require.Len(t, segs, 2)
	require.GreaterOrEqual(t, len(segs[1]), 3)

	// Tamper inside the second boot.
	segs[1][1].Msg = "rewritten history"
	var flat []kernel.AuditEntry
	for _, s := range segs {
		flat = append(flat, s...)
	}

	gotSegs, badSeg, badEntry := auditfile.VerifyFile(flat)
	assert.Equal(t, len(segs), gotSegs)
	assert.Equal(t, 1, badSeg, "the tampering must be attributed to the second boot")
	assert.Equal(t, 1, badEntry)
}

// TestSegmentsOnAnEmptyFile covers the degenerate input. An empty file is not a
// broken chain: it is a kernel that has not booted, and reporting it as tampering
// would make the check cry wolf on a fresh deployment.
func TestSegmentsOnAnEmptyFile(t *testing.T) {
	assert.Empty(t, auditfile.Segments(nil))

	segs, badSeg, badEntry := auditfile.VerifyFile(nil)
	assert.Zero(t, segs)
	assert.Equal(t, -1, badSeg)
	assert.Equal(t, -1, badEntry)

	// Splitting is a structural operation and does not care whether hashes are
	// valid, so it can be asserted on synthetic entries.
	synthetic := []kernel.AuditEntry{
		{Seq: 0, Prev: kernel.AuditGenesis},
		{Seq: 1, Prev: "a"},
		{Seq: 0, Prev: kernel.AuditGenesis}, // a second boot starts here
		{Seq: 1, Prev: "b"},
	}
	split := auditfile.Segments(synthetic)
	require.Len(t, split, 2)
	assert.Len(t, split[0], 2)
	assert.Len(t, split[1], 2)

	// A single boot is one segment.
	assert.Len(t, auditfile.Segments(synthetic[:2]), 1)
}

// TestASplicedBootIsAttributable is the attack the segment model has to survive: an
// attacker who appends a forged boot to the file. The forged segment must still
// verify internally or be reported, and it cannot retroactively change the segments
// before it.
func TestASplicedBootIsAttributable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := auditfile.New(auditfile.Options{Path: path})
	require.NoError(t, err)
	k, err := kernel.Boot(kernel.BootConfig{AuditSink: sink, TrustRoot: kernel.BootTrustRoot{NodeID: "real"}})
	require.NoError(t, err)
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid))
	require.NoError(t, k.Shutdown())
	require.NoError(t, sink.Close())

	entries, err := auditfile.Read(path)
	require.NoError(t, err)
	require.Equal(t, 1, len(auditfile.Segments(entries)))
	// Shutdown writes the last entry, so the file's final hash is the real head.
	realHead := entries[len(entries)-1].Hash

	// Append a forged boot that starts at genesis but whose internal hashes are
	// garbage. It is detectable, and the real segment before it is untouched.
	forged := append(append([]kernel.AuditEntry(nil), entries...),
		kernel.AuditEntry{Seq: 0, Kind: kernel.AuditBoot, Msg: "forged boot",
			Prev: kernel.AuditGenesis, Hash: strings.Repeat("f", 64)})

	segs, badSeg, _ := auditfile.VerifyFile(forged)
	assert.Equal(t, 2, segs, "the forged boot reads as a second segment")
	assert.Equal(t, 1, badSeg, "the forged segment must fail verification")

	// The real segment still verifies, so the operator knows exactly where the
	// problem is rather than being told the whole file is bad.
	split := auditfile.Segments(forged)
	require.Len(t, split, 2)
	assert.Equal(t, -1, kernel.VerifyChain(split[0], kernel.AuditGenesis))
	assert.Equal(t, realHead, split[0][len(split[0])-1].Hash,
		"the forged boot must not alter the real one's last entry")
}
