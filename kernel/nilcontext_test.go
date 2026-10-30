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

package kernel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// These tests are in package kernel rather than kernel_test because the value they exercise
// cannot be constructed from outside: SContext is sealed and *sContext is unexported. That is
// the same reason export_test.go exists, and the same reason AGENT.md keeps these two files
// here rather than under tests/.
//
// What they cover is the guard behind the guard. InitContext now returns an UNTYPED nil on a
// foreign receiver, which every entry point's existing `!ok` branch refuses, so the reachable
// path is fixed and tests/security asserts it. The guards in alive() and contextOf are for a
// typed nil, which nothing in the tree produces today - and "nothing produces it today" is
// exactly the kind of statement that stops being true when someone adds a code path. A guard
// that cannot be reached by any test is a guard nobody will notice removing.

// TestATypedNilContextIsRefusedNotPanicked pins the property the assertion shape hides: a nil
// *sContext inside an SContext satisfies ctx.(*sContext) with ok == true, so the branch that
// refuses a foreign context does not run and the first dereference panics instead.
func TestATypedNilContextIsRefusedNotPanicked(t *testing.T) {
	ctx := ProbeTypedNilContext()

	// The trap, stated plainly, because it is the whole reason these guards exist. The raw
	// comparison is what a kernel entry point writes and it says this is a context; testify's
	// NotNil would not, because it reflects through the interface, which is why the assertion
	// below is on == and not on NotNil.
	assert.False(t, ctx == nil, "a typed nil in an interface reads as non-nil")
	c, ok := ctx.(*sContext)
	assert.True(t, ok, "and the type assertion succeeds")
	assert.Nil(t, c, "while the pointer behind it is nil")

	// alive() is the prologue of every syscall, so this one check is what covers the majority
	// of entry points: they call c.syscall(op), which calls alive().
	assert.NotPanics(t, func() {
		assert.ErrorIs(t, c.alive(), errForeignContext,
			"a nil context is refused with the error that already means this one")
	})

	// contextOf is the shape the dereference-first entry points use.
	got, err := contextOf(ctx)
	assert.ErrorIs(t, err, errForeignContext)
	assert.Nil(t, got)

	// And an untyped nil goes the same way, so both spellings of "not a context" get one
	// answer rather than one refusal and one panic.
	got, err = contextOf(nil)
	assert.ErrorIs(t, err, errForeignContext)
	assert.Nil(t, got)
}

// TestEveryDereferenceFirstEntryPointRefusesATypedNil covers the entry points that read a
// field of the context before anything calls alive(). These are the ones a nil guard on
// alive() alone would not protect, which is why they take contextOf instead of a bare
// assertion: fs reads the module name to find a data root, seccomp compares the pid to the
// target, and net resolves the fd through the pid.
func TestEveryDereferenceFirstEntryPointRefusesATypedNil(t *testing.T) {
	ctx := ProbeTypedNilContext()

	cases := []struct {
		name string
		call func() error
	}{
		{"FSReadFile", func() error { _, err := FSReadFile(ctx, "x"); return err }},
		{"FSWriteFile", func() error { return FSWriteFile(ctx, "x", []byte("y")) }},
		{"SeccompAllow", func() error { return SeccompAllow(ctx, OpFSRead, "x") }},
		{"SeccompInstall", func() error {
			_, err := SeccompInstall(ctx, 1, SeccompFilter{Label: "x"})
			return err
		}},
		{"NetRelease", func() error { return NetRelease(ctx, 1) }},
		{"NetClose", func() error { return NetClose(ctx, 1) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			assert.NotPanics(t, func() { err = tc.call() },
				"%s dereferences the context before any gate, so it must check for nil", tc.name)
			assert.ErrorIs(t, err, errForeignContext)
		})
	}
}

// TestTheGuardsBehindTheGuards covers the two nil checks that no exported call path can reach
// any more, because the entry points above them now refuse first.
//
// They are kept rather than deleted, and the reason is the failure mode that produced them: a
// guard at the point where the dereference happens protects every caller including one added
// later, while a guard at each entry point protects only the entry points someone remembered.
// fsRootFor reads c.name and netSocketFor reads c.pid; those are the lines that would panic,
// so those are where the checks live. What that costs is reachability from outside, which is
// what this test buys back - and only this package can write it.
func TestTheGuardsBehindTheGuards(t *testing.T) {
	// fsRootFor is unreachable with a nil context through FSReadFile, FSWriteFile, FSList,
	// FSStat and FSDelete, all of which call contextOf first.
	_, err := fsRootFor(nil)
	assert.ErrorIs(t, err, errForeignContext,
		"fsRootFor refuses a nil context, so a sixth entry point inherits the guard")

	// netSocketFor is still reachable with a nil context through NetRead and NetWrite, which
	// use a bare comma-ok assertion and reach it before any gate. Those two are in the sweep
	// above, and this asserts the guard they depend on rather than only its effect.
	_, err = netSocketFor(nil, 1)
	assert.ErrorIs(t, err, errForeignContext,
		"netSocketFor refuses a nil context before lookup reads its pid")
}

// TestNoEntryPointPanicsOnATypedNil is the sweep over the rest of the surface. It is a
// blunt instrument and deliberately so: it does not know which entry points dereference first
// and which reach alive() first, so it calls a representative set and asserts that none of
// them panic. A new entry point added with a dereference before its gate fails here, which is
// the failure the two tests above cannot see because they name their cases.
func TestNoEntryPointPanicsOnATypedNil(t *testing.T) {
	ctx := ProbeTypedNilContext()

	// Each call is wrapped so a panic names the entry point rather than aborting the test with
	// a stack trace the reader has to match against a list.
	assertNoPanic := func(name string, f func() error) {
		t.Helper()
		var err error
		assert.NotPanics(t, func() { err = f() }, "%s panicked on a nil context", name)
		assert.Error(t, err, "%s must refuse rather than succeed", name)
	}

	assertNoPanic("FSList", func() error { _, err := FSList(ctx, "x"); return err })
	assertNoPanic("FSStat", func() error { _, err := FSStat(ctx, "x"); return err })
	assertNoPanic("FSDelete", func() error { return FSDelete(ctx, "x") })
	assertNoPanic("NetWrite", func() error { _, err := NetWrite(ctx, 1, []byte("x")); return err })
	assertNoPanic("KVGet", func() error { _, err := KVGet(ctx, "k"); return err })
	assertNoPanic("KVPut", func() error { return KVPut(ctx, "k", []byte("v")) })
	assertNoPanic("KVDelete", func() error { return KVDelete(ctx, "k") })
	assertNoPanic("KVKeys", func() error { _, err := KVKeys(ctx); return err })
	assertNoPanic("TTYOpen", func() error { _, err := TTYOpen(ctx); return err })
	assertNoPanic("EventWait", func() error { _, err := EventWait(ctx, 1, 0); return err })
	assertNoPanic("EventSubscribe", func() error {
		_, err := EventSubscribe(ctx, []KernelEventName{EventDraining})
		return err
	})
	assertNoPanic("EventPending", func() error { _, _, err := EventPending(ctx, 1); return err })
	assertNoPanic("ShmAlloc", func() error { _, err := ShmAlloc(ctx, 4096, "s"); return err })
	assertNoPanic("LockTake", func() error {
		_, err := LockTake(ctx, "l", true, 1_000_000_000)
		return err
	})
	assertNoPanic("RouteRegister", func() error {
		return RouteRegister(ctx, "/x", func(SContext, RouteRequest) (RouteResponse, error) {
			return RouteResponse{}, nil
		})
	})
	assertNoPanic("NetRead", func() error { _, err := NetRead(ctx, 1, 64); return err })
	assertNoPanic("PeerDial", func() error {
		_, err := PeerDial(ctx, PeerDialSpec{Endpoint: "h.example"})
		return err
	})
	// VerifyManifestLoad is the one entry point here for which a nil context is a LEGAL call
	// shape rather than a foreign one: verifier.go's VerifyManifest passes an untyped nil so a
	// host can appraise a manifest before there is a module to attribute it to, and
	// verifierAttribPID and verifierAttribDomain read attribution without dereferencing nil so
	// that shape produces pid 0 instead of a panic. It is in this sweep because it must not
	// panic, and it is asserted separately from the refusals because refusing it would break
	// the host path that depends on it.
	assert.NotPanics(t, func() {
		_ = VerifyManifestLoad(ctx, Manifest{Name: "x", Version: "1"}, nil)
	}, "VerifyManifestLoad tolerates a nil context by design")
}
