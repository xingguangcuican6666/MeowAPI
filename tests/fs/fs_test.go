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

// Package fs tests the fs syscall surface for kvfs: the read, write, list, stat and
// delete operations layered on kv.go's resolver, and the data-root configuration that
// makes per-module isolation structural rather than a string comparison.
//
// The properties here are the ones that would let a module reach outside its own
// data area: containment through a symlink or a "..", a boundary matched by string
// prefix rather than by path segment, an atomic write whose temporary name escapes
// the boundary, and two modules sharing a directory. Each is asserted separately
// rather than folded into one happy-path test, because a containment check that
// passes one escape test and fails another is the exact defect this suite exists to
// catch.
package fs

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// fsCounter gives every test a unique module name. It matters for two reasons: a
// module name is the key the data root is installed under, and resetFS() is not yet
// wired into resetKernel(), so roots installed by an earlier test are still present.
// Unique names keep one test's root from being another test's.
var fsCounter int

func fsNextName(prefix string) string {
	fsCounter++
	return prefix + harness.Itoa(fsCounter)
}

// fsBoot boots a kernel with a node id and no ceilings under test.
func fsBoot(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-fs"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// fsLoad loads one module with a root installed for it and returns its context. The
// context is kept so a test can drive syscalls after OnLoad, which is the only place
// a module can be driven at all: manifest-scoped state is published by the loader
// before OnLoad runs, but the module's own record is published after it returns, so
// anything consulting that record fails closed during initialization.
func fsLoad(t *testing.T, k *kernel.Kernel, name, root string, m kernel.Manifest) kernel.SContext {
	t.Helper()
	require.NoError(t, kernel.FSSetDataRoot(name, root))

	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)

	m.Name = name
	if m.Version == "" {
		m.Version = "1"
	}
	m.MinKernelAPI = kernel.KernelAPI
	m.MaxKernelAPI = kernel.KernelAPI
	pid, err := k.Load(m)
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })

	require.NotNil(t, probe.Ctx)
	return probe.Ctx
}

// fsManifest is the declaration a module needs for the whole fs surface.
func fsManifest() kernel.Manifest {
	return kernel.Manifest{
		Require:    []kernel.Op{kernel.OpFSRead, kernel.OpFSWrite},
		ReadPaths:  []string{"cache"},
		WritePaths: []string{"cache"},
	}
}

// fsRoot builds a data root with cache/ present, so an in-scope operation has
// somewhere to succeed.
func fsRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cache"), 0o755))
	return root
}

// fsAuditOutcomes collects the outcome field of every fs record on the chain, so a
// test can assert a refusal was recorded rather than merely returned.
func fsAuditOutcomes() []string {
	var out []string
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditRequest}) {
		if op, _ := e.Fields["op"].(string); op != "fs:read" && op != "fs:write" {
			continue
		}
		if outcome, ok := e.Fields["outcome"].(string); ok {
			out = append(out, outcome)
		}
	}
	return out
}

// TestFSWriteReadRoundTrip is the basic contract: what a module wrote is what it
// reads back, byte for byte, including the content shapes that a naive
// string-oriented implementation gets wrong.
func TestFSWriteReadRoundTrip(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	ctx := fsLoad(t, k, fsNextName("fsrt"), fsRoot(t), fsManifest())

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"plain", []byte("a chat completion")},
		{"nul bytes", []byte{0x00, 0x01, 0x00, 'x', 0x00}},
		{"utf8", []byte("中文 and éè")},
		{"binary", []byte{0x89, 'P', 'N', 'G', 0x00, 0xFF, 0xC3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.NoError(t, kernel.FSWriteFile(ctx, "cache/blob", c.data))
			got, err := kernel.FSReadFile(ctx, "cache/blob")
			require.NoError(t, err)
			assert.Equal(t, c.data, got)
		})
	}

	// Overwriting replaces rather than appends, which is what a module means by write.
	require.NoError(t, kernel.FSWriteFile(ctx, "cache/blob", []byte("short")))
	got, err := kernel.FSReadFile(ctx, "cache/blob")
	require.NoError(t, err)
	assert.Equal(t, []byte("short"), got)
}

// TestFSWriteIsAtomic asserts the property the temporary-name-plus-rename shape
// exists for: a write that fails partway leaves no partial file behind. A module
// that believed a truncated file was complete would serve it.
func TestFSWriteIsAtomic(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)
	ctx := fsLoad(t, k, fsNextName("fsatomic"), root, fsManifest())

	require.NoError(t, kernel.FSWriteFile(ctx, "cache/good", []byte("original")))

	// Turn the target into a directory, so the rename onto it fails after the
	// temporary file has been written.
	target := filepath.Join(root, "cache", "blocked")
	require.NoError(t, os.MkdirAll(target, 0o755))
	err := kernel.FSWriteFile(ctx, "cache/blocked", []byte("should not land"))
	require.Error(t, err)

	// The failure left no partial file and, crucially, no temporary file: a stray
	// ".kfs-tmp" is how an atomic write that was not atomic shows up later.
	entries, rerr := os.ReadDir(filepath.Join(root, "cache"))
	require.NoError(t, rerr)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "kfs-tmp",
			"a failed write must not leave its temporary file behind")
	}

	// And the file that was already there is untouched.
	got, err := kernel.FSReadFile(ctx, "cache/good")
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), got)
}

// TestFSContainmentRefusesEveryEscape walks each escape form kv.go's resolver
// refuses, through this surface rather than through the resolver directly, because
// what matters is that every operation routes through it. A new syscall that forgot
// to call FSCheckRead would pass a resolver-only test and fail here.
func TestFSContainmentRefusesEveryEscape(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)

	// A file outside the root, which is what every escape is trying to reach.
	outside := filepath.Join(filepath.Dir(root), "outside-secret")
	require.NoError(t, os.WriteFile(outside, []byte("not yours"), 0o600))

	// Note what this declaration cannot be: manifest validation refuses a read path
	// shaped like an escape, so ".." and "/" are not declarable boundaries in the
	// first place. That is the first of the two layers, and it is asserted
	// separately below. What is tested here is the second layer, containment, which
	// is what has to hold for a path that is inside the declared boundary as spelled
	// and still resolves outside the root.
	ctx := fsLoad(t, k, fsNextName("fsesc"), root, kernel.Manifest{
		Require:    []kernel.Op{kernel.OpFSRead, kernel.OpFSWrite},
		ReadPaths:  []string{"cache"},
		WritePaths: []string{"cache"},
	})

	// The containment cases. Each of these is lexically inside cache/, so the
	// declared boundary admits it and only resolving the name can catch it. A
	// resolver that was skipped would pass every other test in this file and fail
	// these.
	t.Run("symlink as the final component", func(t *testing.T) {
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "cache", "escape-link")))
		_, err := kernel.FSReadFile(ctx, "cache/escape-link")
		require.Error(t, err, "a symlink out of the root must be refused")
		err = kernel.FSWriteFile(ctx, "cache/escape-link", []byte("x"))
		require.Error(t, err, "and it must not be writable either")
	})

	t.Run("symlink in the middle of the path", func(t *testing.T) {
		outsideDir := filepath.Join(filepath.Dir(root), "outside-dir")
		require.NoError(t, os.MkdirAll(outsideDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "blob"), []byte("no"), 0o600))
		require.NoError(t, os.Symlink(outsideDir, filepath.Join(root, "cache", "mid")))
		_, err := kernel.FSReadFile(ctx, "cache/mid/blob")
		require.Error(t, err, "a linked directory in the middle of the path must be refused")
	})

	t.Run("dangling symlink", func(t *testing.T) {
		require.NoError(t, os.Symlink(filepath.Join(root, "cache", "never"),
			filepath.Join(root, "cache", "dangling")))
		_, err := kernel.FSReadFile(ctx, "cache/dangling")
		require.Error(t, err,
			"a dangling symlink is refused rather than treated as absent, because its target may appear later")
	})

	// The cases the boundary catches first. They are refused too, and asserting the
	// refusal is still worth doing: which layer caught it is not something a module
	// gets to choose.
	for _, c := range []struct {
		name string
		path string
	}{
		{"dotdot segment", "../outside-secret"},
		{"absolute path", outside},
		{"the root itself", "."},
		{"empty path", ""},
	} {
		t.Run("read "+c.name, func(t *testing.T) {
			_, err := kernel.FSReadFile(ctx, c.path)
			require.Error(t, err, "read of %q must be refused", c.path)
		})
		t.Run("write "+c.name, func(t *testing.T) {
			err := kernel.FSWriteFile(ctx, c.path, []byte("x"))
			require.Error(t, err, "write of %q must be refused", c.path)
		})
	}

	// Nothing outside the root was created or modified by any of the above.
	got, gerr := os.ReadFile(outside)
	require.NoError(t, gerr)
	assert.Equal(t, "not yours", string(got))
}

// TestFSAtomicWriteTempStaysInsideTheBoundary is the escape the atomic-write shape
// invites. The temporary name is derived from the resolved path rather than accepted
// from the caller, so it cannot land outside the declared boundary; this asserts that
// by watching the whole root for any file that is not one the test itself created.
func TestFSAtomicWriteTempStaysInsideTheBoundary(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)
	ctx := fsLoad(t, k, fsNextName("fstmp"), root, kernel.Manifest{
		Require:    []kernel.Op{kernel.OpFSRead, kernel.OpFSWrite},
		ReadPaths:  []string{"cache"},
		WritePaths: []string{"cache"},
	})

	before := map[string]bool{}
	require.NoError(t, filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			before[p] = true
		}
		return nil
	}))

	require.NoError(t, kernel.FSWriteFile(ctx, "cache/one", []byte("a")))
	require.NoError(t, kernel.FSWriteFile(ctx, "cache/nested/two", []byte("b")))

	var stray []string
	require.NoError(t, filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || before[p] {
			return nil
		}
		stray = append(stray, p)
		return nil
	}))
	for _, p := range stray {
		rel, rerr := filepath.Rel(root, p)
		require.NoError(t, rerr)
		assert.Equal(t, "cache", firstSegment(rel),
			"a write produced %q, outside the declared cache boundary", rel)
		assert.NotContains(t, filepath.Base(p), "kfs-tmp",
			"a temporary file survived the write that created it")
	}
}

// TestFSTwoModulesCannotReadEachOther is the isolation property, and the reason it
// holds must be structural: the other module's directory is not inside this module's
// root at all, so there is no path spelling that reaches it.
func TestFSTwoModulesCannotReadEachOther(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)

	base := t.TempDir()
	rootA := filepath.Join(base, "module-a")
	rootB := filepath.Join(base, "module-b")
	for _, r := range []string{rootA, rootB} {
		require.NoError(t, os.MkdirAll(filepath.Join(r, "cache"), 0o755))
	}

	nameA, nameB := fsNextName("fsA"), fsNextName("fsB")
	ctxA := fsLoad(t, k, nameA, rootA, fsManifest())
	ctxB := fsLoad(t, k, nameB, rootB, fsManifest())

	require.NoError(t, kernel.FSWriteFile(ctxA, "cache/secret", []byte("A private")))
	require.NoError(t, kernel.FSWriteFile(ctxB, "cache/secret", []byte("B private")))

	// Each module reads its own value, which is what makes the next two assertions
	// meaningful rather than trivially true.
	got, err := kernel.FSReadFile(ctxA, "cache/secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("A private"), got)

	// B cannot reach A's file by any spelling: not by relative traversal, not by
	// absolute path.
	_, err = kernel.FSReadFile(ctxB, "../module-a/cache/secret")
	require.Error(t, err)
	_, err = kernel.FSReadFile(ctxB, filepath.Join(rootA, "cache", "secret"))
	require.Error(t, err)

	// And B's own file is untouched, which is the part that distinguishes isolation
	// from a broken resolver.
	got, err = kernel.FSReadFile(ctxB, "cache/secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("B private"), got)
}

// TestFSUndeclaredOperationIsRefusedAsADenial and
// TestFSOutOfBoundaryIsRefusedAsAnEscalation are the pair that must not be
// conflated. A module that never declared fs:read holds no grant and gets a policy
// denial; a module that declared it and reached past its own boundary is attempting
// to act beyond a grant, which is recorded as an escalation because it is evidence
// about the module rather than a typo.
func TestFSUndeclaredOperationIsRefusedAsADenial(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := fsBoot(t)

	ctx := fsLoad(t, k, fsNextName("fsnodecl"), fsRoot(t), kernel.Manifest{
		Require:   []kernel.Op{kernel.OpKVRead},
		ReadPaths: []string{"cache"},
	})

	_, err := kernel.FSReadFile(ctx, "cache/blob")
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "an undeclared operation is a policy denial: %v", err)
	// fs:read is a scoped operation, so the refusal names the missing declaration
	// rather than the domain ceiling. That is the more useful of the two: "your
	// domain lacks this" can only be fixed by a kernel change, while "you forgot to
	// declare it" is something the module author can act on, and a scoped operation
	// is exactly the case where the author can.
	assert.Contains(t, kernel.DenialReason(err), "not declared in the manifest")
	assert.Positive(t, len(harness.Faults(buf)), "a denial must be visible as a fault")

	// And the operation a module cannot ask for at all still reads as a ceiling
	// refusal, with no actionable reason because there is nothing the author can do.
	_, err = kernel.SecretRead(ctx, "provider.api.key")
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.Empty(t, kernel.DenialReason(err),
		"secret:read is not grantable to a module at any scope, so there is no declaration to suggest")
}

func TestFSOutOfBoundaryIsRefusedAsAnEscalation(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)

	// cache2 shares a string prefix with cache, so a boundary matched by prefix
	// rather than by path segment would wrongly admit it.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cache2"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cache2", "blob"), []byte("no"), 0o600))

	ctx := fsLoad(t, k, fsNextName("fsbound"), root, kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	before := len(fsAuditOutcomes())

	_, err := kernel.FSReadFile(ctx, "cache2/blob")
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "outside the declared boundary is a denial")
	assert.NotEmpty(t, kernel.DenialReason(err),
		"the module holds fs:read; what it lacks is this path, and the reason says so")

	esc := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation})
	assert.NotEmpty(t, esc, "reaching past a grant is recorded as an escalation")

	// In-scope still works, which is what makes the refusal above meaningful.
	require.NoError(t, os.WriteFile(filepath.Join(root, "cache", "ok"), []byte("yes"), 0o600))
	got, err := kernel.FSReadFile(ctx, "cache/ok")
	require.NoError(t, err)
	assert.Equal(t, []byte("yes"), got)

	assert.Greater(t, len(fsAuditOutcomes()), before, "every attempt lands on the chain")
}

// TestFSReadCeilingIsTypedAndEnforced pins that the size bound is a kernel constant
// rather than something the caller supplies. A module that could ask for an
// unbounded read of a file it wrote itself could still exhaust kernel memory.
func TestFSReadCeilingIsTypedAndEnforced(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)
	ctx := fsLoad(t, k, fsNextName("fsceil"), root, fsManifest())

	// Write past the ceiling directly, bypassing the syscall: the file exists on
	// disk and the read is what must refuse it.
	big := make([]byte, 1<<20+1)
	require.NoError(t, os.WriteFile(filepath.Join(root, "cache", "big"), big, 0o600))

	_, err := kernel.FSReadFile(ctx, "cache/big")
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrFSReadTooLarge,
		"the ceiling is a sentinel a caller checks, not a message it matches")
	assert.Contains(t, err.Error(), "ceiling")

	// The bound is the kernel's, not the caller's: a file just under it reads fine.
	ok := make([]byte, 1<<20)
	require.NoError(t, os.WriteFile(filepath.Join(root, "cache", "exact"), ok, 0o600))
	got, err := kernel.FSReadFile(ctx, "cache/exact")
	require.NoError(t, err, "the ceiling is inclusive at its own value")
	assert.Len(t, got, 1<<20)
}

// TestFSListIsSortedBoundedAndACopy asserts the three properties of a listing that
// make it safe to hand to a module: sorted so a caller can compare two, bounded to
// the declared area, and a copy so mutating it cannot reach kernel state.
func TestFSListIsSortedBoundedAndACopy(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)
	ctx := fsLoad(t, k, fsNextName("fslist"), root, kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	for _, n := range []string{"zeta", "alpha", "mid"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, "cache", n), []byte("x"), 0o600))
	}
	// A sibling directory outside the boundary must not be listable.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cache2"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cache2", "hidden"), []byte("x"), 0o600))

	got, err := kernel.FSList(ctx, "cache")
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "mid", "zeta"}, got, "a listing is sorted")

	got[0] = "mutated"
	again, err := kernel.FSList(ctx, "cache")
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "mid", "zeta"}, again, "a listing is a copy")

	_, err = kernel.FSList(ctx, "cache2")
	require.Error(t, err, "a directory outside the boundary is not listable")

	_, err = kernel.FSList(ctx, ".")
	require.Error(t, err, "the data root itself is never in scope")
}

// TestFSStatReportsSizeAndDirOnly checks the two facts FSStat exposes. It
// deliberately does not expose timestamps or permissions, which a module has no use
// for and which would render host-side detail the boundary exists to keep out.
func TestFSStatReportsSizeAndDirOnly(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)
	ctx := fsLoad(t, k, fsNextName("fsstat"), root, fsManifest())

	require.NoError(t, kernel.FSWriteFile(ctx, "cache/blob", []byte("seven!!")))
	info, err := kernel.FSStat(ctx, "cache/blob")
	require.NoError(t, err)
	assert.Equal(t, int64(7), info.Size)
	assert.False(t, info.IsDir)

	info, err = kernel.FSStat(ctx, "cache")
	require.NoError(t, err)
	assert.True(t, info.IsDir)

	_, err = kernel.FSStat(ctx, "cache/absent")
	require.Error(t, err)
}

// TestFSDeleteRemovesAndReportsAnAbsentFile covers both halves of the contract: a
// delete removes the file, and a second delete reports "already gone" as a typed
// error rather than succeeding silently or looping.
func TestFSDeleteRemovesAndReportsAnAbsentFile(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	ctx := fsLoad(t, k, fsNextName("fsdel"), fsRoot(t), fsManifest())

	require.NoError(t, kernel.FSWriteFile(ctx, "cache/blob", []byte("x")))
	require.NoError(t, kernel.FSDelete(ctx, "cache/blob"))

	_, err := kernel.FSReadFile(ctx, "cache/blob")
	require.Error(t, err, "a deleted file does not read back")

	err = kernel.FSDelete(ctx, "cache/blob")
	require.Error(t, err, "a second delete reports rather than silently succeeds")
	assert.Contains(t, err.Error(), "gone")
}

// TestFSWithoutARootRefusesAndLeavesTheWorkingDirectoryAlone pins the refusal that
// replaces a fallback. Falling back to the process working directory would put
// module data wherever the operator happened to launch the binary, and silence
// about it would make that look like a decision.
func TestFSWithoutARootRefusesAndLeavesTheWorkingDirectoryAlone(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := fsBoot(t)

	ctx := fsLoadNoRoot(t, k, fsNextName("fsnoroot"), fsManifest())

	cwd, err := os.Getwd()
	require.NoError(t, err)
	before := fsSnapshotDir(t, cwd)

	_, err = kernel.FSReadFile(ctx, "cache/blob")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no data root")

	err = kernel.FSWriteFile(ctx, "cache/blob", []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no data root")

	assert.Equal(t, before, fsSnapshotDir(t, cwd),
		"a missing root must not fall back to the process working directory")
	assert.Positive(t, len(harness.Faults(buf)), "the refusal is visible as a fault")
}

// fsLoadNoRoot loads a module with no data root installed for it.
func fsLoadNoRoot(t *testing.T, k *kernel.Kernel, name string, m kernel.Manifest) kernel.SContext {
	t.Helper()
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	m.Name = name
	m.Version = "1"
	m.MinKernelAPI = kernel.KernelAPI
	m.MaxKernelAPI = kernel.KernelAPI
	pid, err := k.Load(m)
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, probe.Ctx)
	return probe.Ctx
}

// firstSegment returns the leading path element, for asserting a produced file is
// inside a declared directory. filepath.HasPrefix is deprecated and, more to the
// point, matched by string prefix, which is the exact confusion the boundary tests
// are here to avoid.
func firstSegment(rel string) string {
	if i := strings.IndexRune(rel, filepath.Separator); i >= 0 {
		return rel[:i]
	}
	return rel
}

// fsSnapshotDir lists a directory's names, for asserting nothing appeared in it.
func fsSnapshotDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestFSRootCannotChangeWhileTheModuleIsLoaded is the seal. A root in use is part of
// what makes containment mean something: paths already resolved against it are on the
// audit chain, and a swapped root would make those records describe a directory that
// is no longer the one that was checked.
func TestFSRootCannotChangeWhileTheModuleIsLoaded(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)
	name := fsNextName("fsseal")
	ctx := fsLoad(t, k, name, root, fsManifest())

	require.NoError(t, kernel.FSWriteFile(ctx, "cache/blob", []byte("x")))

	err := kernel.FSSetDataRoot(name, t.TempDir())
	require.Error(t, err, "a root cannot be swapped under running code")
	assert.Contains(t, err.Error(), "while that module is loaded")

	// And the module still reads through the root it was given.
	got, err := kernel.FSReadFile(ctx, "cache/blob")
	require.NoError(t, err)
	assert.Equal(t, []byte("x"), got)
}

// TestFSRootRejectsAnEmptyInstallation covers the setter's own validation, which is
// the half that stops a deployment silently configuring nothing.
func TestFSRootRejectsAnEmptyInstallation(t *testing.T) {
	harness.QuietConsole(t)
	require.Error(t, kernel.FSSetDataRoot("", t.TempDir()), "a root is installed for a name")
	require.Error(t, kernel.FSSetDataRoot("some-module", ""), "an empty root is not a root")
}

// TestFSConcurrentWritesDoNotInterleave is the property that makes the atomic write
// worth its cost. Many goroutines writing distinct files must all land intact, and
// many writing the same file must each leave a whole value rather than a splice of
// two.
func TestFSConcurrentWritesDoNotInterleave(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	ctx := fsLoad(t, k, fsNextName("fsconc"), fsRoot(t), fsManifest())

	const writers = 16
	done := make(chan struct{}, writers)

	// Distinct files: every one must hold exactly what its writer put there.
	for i := range writers {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			payload := bytes.Repeat([]byte{byte('a' + i%26)}, 4096)
			name := "cache/file" + harness.Itoa(i)
			if err := kernel.FSWriteFile(ctx, name, payload); err != nil {
				return
			}
			got, err := kernel.FSReadFile(ctx, name)
			if err != nil || !bytes.Equal(got, payload) {
				t.Errorf("file %d did not survive concurrent writing", i)
			}
		}(i)
	}

	// One shared file: each write must land whole, so the final value is one of the
	// payloads and not a splice.
	shared := make([][]byte, 0, writers)
	for i := range writers {
		shared = append(shared, bytes.Repeat([]byte{byte('A' + i%26)}, 2048))
	}
	for i := range writers {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			_ = kernel.FSWriteFile(ctx, "cache/shared", shared[i])
		}(i)
	}

	for range writers * 2 {
		<-done
	}

	got, err := kernel.FSReadFile(ctx, "cache/shared")
	require.NoError(t, err)
	matched := false
	for _, p := range shared {
		if bytes.Equal(got, p) {
			matched = true
			break
		}
	}
	assert.True(t, matched, "a concurrent write left a spliced value of %d bytes", len(got))
}

// TestFSAuditRecordsOperationsAndRefusals pins that this surface is visible. Reads
// are audited as well as writes, and the reason is the one that decides it: the
// alternative is that an exfiltration through this surface is invisible, and one
// record per read from a bounded module set is a volume the audit window is built to
// hold.
func TestFSAuditRecordsOperationsAndRefusals(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	ctx := fsLoad(t, k, fsNextName("fsaudit"), fsRoot(t), fsManifest())

	require.NoError(t, kernel.FSWriteFile(ctx, "cache/blob", []byte("x")))
	_, err := kernel.FSReadFile(ctx, "cache/blob")
	require.NoError(t, err)
	_, err = kernel.FSReadFile(ctx, "cache/absent")
	require.Error(t, err)

	var sawWrite, sawRead, sawMiss bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditRequest}) {
		op, _ := e.Fields["op"].(string)
		outcome, _ := e.Fields["outcome"].(string)
		path, _ := e.Fields["path"].(string)
		if e.Fields["module"] == nil {
			continue
		}
		switch {
		case op == "fs:write" && outcome == "ok" && path == "cache/blob":
			sawWrite = true
		case op == "fs:read" && outcome == "ok" && path == "cache/blob":
			sawRead = true
		case op == "fs:read" && outcome == "miss":
			sawMiss = true
		}
	}
	assert.True(t, sawWrite, "a write is on the chain with its module, op, path and outcome")
	assert.True(t, sawRead, "a read is on the chain, because an unaudited read is an invisible exfiltration")
	assert.True(t, sawMiss, "a failed read is on the chain too")
}

// TestSyscallFSSurfaceIsReachable pins that this surface is reachable through the
// sealed SContext rather than only through the package-level functions. The package
// functions are what the rest of this suite drives, and they would keep passing if
// SyscallFS were missing from the SContext composition in context.go, which is the
// exact way a subsystem gets built and never wired.
func TestSyscallFSSurfaceIsReachable(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)
	ctx := fsLoad(t, k, fsNextName("fswire"), root, fsManifest())

	require.NoError(t, ctx.SyscallFSWrite("cache/blob", []byte("wired")))

	got, err := ctx.SyscallFSRead("cache/blob")
	require.NoError(t, err)
	assert.Equal(t, []byte("wired"), got)

	names, err := ctx.SyscallFSList("cache")
	require.NoError(t, err)
	assert.Equal(t, []string{"blob"}, names)

	info, err := ctx.SyscallFSStat("cache/blob")
	require.NoError(t, err)
	assert.Equal(t, int64(5), info.Size)
	assert.False(t, info.IsDir)

	require.NoError(t, ctx.SyscallFSDelete("cache/blob"))
	names, err = ctx.SyscallFSList("cache")
	require.NoError(t, err)
	assert.Empty(t, names)

	// The boundary holds through the syscall surface too, which is the point of
	// routing every operation through FSCheckRead and FSCheckWrite. A path that
	// escapes the data root is refused by containment rather than by policy: the
	// module does hold fs:read, so this is not a denial, and asserting that it is
	// would hide the difference between "you may not read files" and "that is not
	// your file".
	_, err = ctx.SyscallFSRead("../escape")
	require.Error(t, err)
	assert.False(t, kernel.IsDenied(err), "containment refuses it, policy does not")
	var pathErr *kernel.FSPathError
	assert.ErrorAs(t, err, &pathErr, "the refusal is the resolver's typed error")
}

// TestFSNothingSurvivesRestart pins the reset. Data roots are host configuration
// rather than per-boot state, so they do survive a restart on purpose - what must not
// survive is the record of which module was live, because a root that could be
// changed while its module is loaded is a root that can be swapped under running code.
func TestFSNothingSurvivesRestart(t *testing.T) {
	harness.QuietConsole(t)
	k := fsBoot(t)
	root := fsRoot(t)
	name := fsNextName("fsrestart")
	ctx := fsLoad(t, k, name, root, fsManifest())
	require.NoError(t, kernel.FSWriteFile(ctx, "cache/blob", []byte("x")))

	require.NoError(t, k.Shutdown())

	// The module is gone, so its root is installable again - which is what lets a
	// deployment re-point a stopped module's data area after a crash.
	require.NoError(t, kernel.FSSetDataRoot(name, t.TempDir()))

	k2 := fsBoot(t)
	ctx2 := fsLoadNoRoot(t, k2, fsNextName("fsrestart2"), fsManifest())
	_, err := kernel.FSReadFile(ctx2, "cache/blob")
	require.Error(t, err, "a fresh boot has no roots of its own")
	assert.Contains(t, err.Error(), "no data root")
}
