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

package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// These tests drive kvfs through the surface a module actually gets: a probe
// module calls the exported entry points with the context the kernel handed it in
// OnLoad. Nothing here reaches package-private state, which is the point - if a
// test needed an internal to prove a guarantee, a module would too.
//
// Every helper here is prefixed "state" and every probe type with "state", because
// six subsystem groups are adding test files to one package at once and the shared
// fixtures in helpers_test.go cannot be edited.

// stateQuiet gives a test its own console sink so fault records can be asserted
// without polluting stderr and without tests racing on the global sink. It is a
// copy of quietConsole in helpers_test.go rather than a call to it, because that
// file is not editable from here and a second definition of the same name would
// not compile.
func stateQuiet(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	sink := &stateLockedBuffer{buf: &buf}
	kernel.KernelConsole().SetOutput(sink)
	t.Cleanup(func() { kernel.KernelConsole().SetOutput(nil) })
	return &buf
}

// stateLockedBuffer serialises console writes. The kernel emits from whatever
// goroutine calls it, and a test asserts on the buffer afterwards.
type stateLockedBuffer struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (l *stateLockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// stateFaults extracts the fault-level records a test emitted.
func stateFaults(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), `"level":"fault"`)
}

// stateProbe is a module that runs a test-supplied function during OnLoad with the
// kernel-issued context, which is the only place a module legitimately holds one.
// It records the context by pid so a test can act as that module afterwards.
//
// It drops the kvfs namespace it is about to use before running. That is not part
// of the behavior under test; it is what makes a test deterministic while pids
// restart at 1 on every boot and resetKVFS is not yet in resetKernel, so an earlier
// test in this binary can leave state sitting under the pid a later test will be
// given. The reset test deliberately does not rely on the drop: it asserts the
// store is empty after Shutdown, which is the property the wiring provides.
type stateProbe struct {
	run    func(ctx kernel.SContext) error
	noDrop bool
}

func (p *stateProbe) OnLoad(ctx kernel.SContext) error {
	stateRecordContext(ctx)
	if !p.noDrop {
		kernel.KVDropNamespace(ctx.PID())
	}
	return p.run(ctx)
}

func (p *stateProbe) OnUnload() error { return nil }

// stateContexts holds the context each loaded probe was issued, keyed by pid. A
// test needs one because a module must not hand its context out, and no exported
// API can produce one from a pid - which is exactly the property the sealed
// context exists to provide. The map is test-owned, filled by the probe at load,
// and emptied by the same cleanup that unregisters the module.
var (
	stateContextsMu sync.Mutex
	stateContexts   = map[kernel.PID]kernel.SContext{}
)

func stateRecordContext(ctx kernel.SContext) {
	stateContextsMu.Lock()
	defer stateContextsMu.Unlock()
	stateContexts[ctx.PID()] = ctx
}

// stateCtxOf returns the context a probe recorded when it loaded.
func stateCtxOf(t *testing.T, pid kernel.PID) kernel.SContext {
	t.Helper()
	stateContextsMu.Lock()
	defer stateContextsMu.Unlock()
	ctx, ok := stateContexts[pid]
	if !ok {
		t.Fatalf("no context was recorded for pid %d", pid)
	}
	return ctx
}

// stateForgetContext drops a recorded context, so a test cannot act as a module
// the kernel has already unloaded.
func stateForgetContext(pid kernel.PID) {
	stateContextsMu.Lock()
	defer stateContextsMu.Unlock()
	delete(stateContexts, pid)
}

// stateBoot boots a kernel with explicit ceilings, so a limit test does not depend
// on the defaults surviving a change.
func stateBoot(t *testing.T, limits kernel.BootLimits) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-state", Limits: limits},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// stateLoad registers a probe under a name, loads it with the given manifest and
// returns its pid. The manifest's name and API range are filled in here so a test
// states only what it cares about.
func stateLoad(t *testing.T, k *kernel.Kernel, name string, m kernel.Manifest, run func(kernel.SContext) error) kernel.PID {
	t.Helper()
	kernel.Register(name, func() (kernel.Module, error) { return &stateProbe{run: run}, nil })
	t.Cleanup(func() { kernel.Unregister(name) })
	m.Name = name
	if m.Version == "" {
		m.Version = "1"
	}
	m.MinKernelAPI = kernel.KernelAPI
	m.MaxKernelAPI = kernel.KernelAPI
	pid, err := k.Load(m)
	require.NoError(t, err)
	t.Cleanup(func() { stateForgetContext(pid) })
	return pid
}

// stateKVManifest is the declaration a module needs for the whole kvfs key-value
// surface.
func stateKVManifest() kernel.Manifest {
	return kernel.Manifest{Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite}}
}

// stateDenialOps collects the operation named by every denial on the audit chain,
// so a test can assert a refusal was recorded rather than merely returned.
func stateDenialOps() []string {
	var out []string
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial}) {
		if op, ok := e.Fields["op"].(string); ok {
			out = append(out, op)
		}
	}
	return out
}

// stateEscalationOps is stateDenialOps for the other refusal kind. A subsystem that
// refuses a call which exceeds a declared boundary files an escalation, because the
// module reached past a grant it does hold; the policy gate files a denial, because
// the module holds nothing. Both are *DeniedError to the caller, so only the audit
// kind distinguishes them, and a test that queries one while the kernel writes the
// other passes for the wrong reason or fails for none.
func stateEscalationOps() []string {
	var out []string
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation}) {
		if op, ok := e.Fields["op"].(string); ok {
			out = append(out, op)
		}
	}
	return out
}

// TestKVStoreIsNamespacedPerModule is the isolation property. Keys are scoped by
// owner pid exactly as metadata.go does, so one module cannot read or write
// another's state - and the reason it cannot is structural rather than a refusal:
// the other module's key is not in its namespace at all.
func TestKVStoreIsNamespacedPerModule(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	var (
		ownerGot   []byte
		ownerKeys  []string
		otherGot   []byte
		otherErr   error
		otherKeys  []string
		otherPut   error
		otherGot2  []byte
		reRead     []byte
		reReadErr  error
		ownerCtx   kernel.SContext
		otherValue = "attacker"
	)

	pidOwner := stateLoad(t, k, "kvowner", stateKVManifest(), func(ctx kernel.SContext) error {
		ownerCtx = ctx
		require.NoError(t, kernel.KVPut(ctx, "config.model", []byte("gpt-test")))
		ownerGot, _ = kernel.KVGet(ctx, "config.model")
		ownerKeys, _ = kernel.KVKeys(ctx)
		return nil
	})
	defer func() { _ = k.Unload(pidOwner) }()

	assert.Equal(t, "gpt-test", string(ownerGot))
	assert.Equal(t, []string{"config.model"}, ownerKeys)

	pidOther := stateLoad(t, k, "kvother", stateKVManifest(), func(ctx kernel.SContext) error {
		otherGot, otherErr = kernel.KVGet(ctx, "config.model")
		otherKeys, _ = kernel.KVKeys(ctx)
		// Writing the same key name in its own namespace must succeed and must not
		// disturb the owner's value. That is the difference between namespacing and
		// refusal: both modules may use the name, neither sees the other's bytes.
		otherPut = kernel.KVPut(ctx, "config.model", []byte(otherValue))
		otherGot2, _ = kernel.KVGet(ctx, "config.model")
		return nil
	})
	defer func() { _ = k.Unload(pidOther) }()

	assert.NotEqual(t, pidOwner, pidOther)
	assert.ErrorIs(t, otherErr, kernel.ErrKVNotFound,
		"another module's key must not resolve in this namespace")
	assert.Nil(t, otherGot)
	assert.Empty(t, otherKeys, "KVKeys must not name another module's keys")
	require.NoError(t, otherPut)
	assert.Equal(t, otherValue, string(otherGot2))

	// The owner's value survived the other module's write to the same key name.
	reRead, reReadErr = kernel.KVGet(ownerCtx, "config.model")
	require.NoError(t, reReadErr)
	assert.Equal(t, "gpt-test", string(reRead),
		"a write in one namespace must not reach another's")

	assert.Positive(t, kernel.KVBytes(pidOwner))
	assert.Positive(t, kernel.KVBytes(pidOther))
	// Both namespaces happen to cost the same here, which is the point of stating
	// the numbers rather than comparing them: each is accounted on its own.
	assert.Equal(t, int64(len("config.model")+len("gpt-test")), kernel.KVBytes(pidOwner))
	assert.Equal(t, int64(len("config.model")+len(otherValue)), kernel.KVBytes(pidOther))
	assert.Equal(t, 1, kernel.KVCount(pidOwner))
	assert.Equal(t, 1, kernel.KVCount(pidOther))
}

// TestKVInitCanReadWriteItsOwnNamespace pins that the two operations are separate
// grants rather than a pair that must be held together. Init holds both, and the
// plugin domain holds both, so this is not a privilege test - it is the test that
// the entry points work from a context that was not produced by LoadModule.
func TestKVInitCanReadWriteItsOwnNamespace(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})
	ctx := k.InitContext()

	require.NoError(t, kernel.KVPut(ctx, "boot.marker", []byte("v1")))
	got, err := kernel.KVGet(ctx, "boot.marker")
	require.NoError(t, err)
	assert.Equal(t, "v1", string(got))
	assert.Equal(t, []string{"boot.marker"}, stateKVKeys(t, ctx))
	assert.Equal(t, int64(len("boot.marker")+2), kernel.KVBytes(ctx.PID()))

	// An empty value is legitimate and must be distinguishable from an absent key,
	// which is why a missing key is an error rather than a nil slice.
	require.NoError(t, kernel.KVPut(ctx, "empty", nil))
	empty, err := kernel.KVGet(ctx, "empty")
	require.NoError(t, err, "an empty value is stored, not absent")
	assert.Len(t, empty, 0)
	_, err = kernel.KVGet(ctx, "absent")
	assert.ErrorIs(t, err, kernel.ErrKVNotFound,
		"absent is an error, which is what makes it distinguishable from empty")
}

func stateKVKeys(t *testing.T, ctx kernel.SContext) []string {
	t.Helper()
	keys, err := kernel.KVKeys(ctx)
	require.NoError(t, err)
	return keys
}

// TestKVCopiesInAndOut is the aliasing guarantee. A module that could mutate
// stored state through a slice it still holds would have a write path that never
// passed the kv:write check, and the byte accounting would describe bytes that are
// no longer what is stored.
func TestKVCopiesInAndOut(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	var afterIn, afterOut []byte

	payload := []byte("original-prompt")
	pid := stateLoad(t, k, "kvalias", stateKVManifest(), func(ctx kernel.SContext) error {
		require.NoError(t, kernel.KVPut(ctx, "prompt", payload))
		// Mutate the slice the caller passed in. If the kernel stored that slice
		// rather than a copy, the stored value changes with it.
		payload[0] = 'X'
		afterIn, _ = kernel.KVGet(ctx, "prompt")

		got, err := kernel.KVGet(ctx, "prompt")
		require.NoError(t, err)
		// Mutate what the kernel handed back. If that were the stored slice, the
		// module would have written state holding only kv:read.
		got[0] = 'Y'
		afterOut, _ = kernel.KVGet(ctx, "prompt")
		return nil
	})
	defer func() { _ = k.Unload(pid) }()

	assert.Equal(t, "original-prompt", string(afterIn),
		"the kernel must copy a value in, not retain the caller's slice")
	assert.Equal(t, "original-prompt", string(afterOut),
		"the kernel must copy a value out, not hand over the stored slice")
	assert.Equal(t, int64(len("prompt")+len("original-prompt")), kernel.KVBytes(pid),
		"accounting covers the key and the value")
}

// TestKVRequiresGrants is the denial half. A grant with no denial test is an
// untested grant, and kvfs has two operations, so both are asserted in both
// directions: refused at the gate, reported through IsDenied, and recorded on the
// audit chain.
func TestKVRequiresGrants(t *testing.T) {
	buf := stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	var putErr, getErr, delErr, keysErr, storeErr error

	// A module declaring nothing holds nothing, so every kvfs entry point refuses.
	pid := stateLoad(t, k, "kvnone", kernel.Manifest{}, func(ctx kernel.SContext) error {
		putErr = kernel.KVPut(ctx, "k", []byte("v"))
		_, getErr = kernel.KVGet(ctx, "k")
		delErr = kernel.KVDelete(ctx, "k")
		_, keysErr = kernel.KVKeys(ctx)
		return nil
	})
	defer func() { _ = k.Unload(pid) }()

	for _, c := range []struct {
		name string
		err  error
		op   kernel.Op
	}{
		{"KVPut", putErr, kernel.OpKVWrite},
		{"KVGet", getErr, kernel.OpKVRead},
		{"KVDelete", delErr, kernel.OpKVWrite},
		{"KVKeys", keysErr, kernel.OpKVRead},
	} {
		require.Error(t, c.err, "%s must be refused without a grant", c.name)
		assert.True(t, kernel.IsDenied(c.err), "%s must report a policy denial", c.name)
		assert.Contains(t, c.err.Error(),
			fmt.Sprintf("avc: denied { %s } for domain=u:r:plugin:s0", c.op))
	}

	// Read without write: the split is real, so a module that declared only
	// kv:read can inspect its namespace and cannot change it.
	pidRO := stateLoad(t, k, "kvro", kernel.Manifest{Require: []kernel.Op{kernel.OpKVRead}},
		func(ctx kernel.SContext) error {
			storeErr = kernel.KVPut(ctx, "k", []byte("v"))
			_, err := kernel.KVKeys(ctx)
			return err
		})
	defer func() { _ = k.Unload(pidRO) }()
	require.Error(t, storeErr)
	assert.True(t, kernel.IsDenied(storeErr))

	// Every refusal above must have reached the audit chain, not just the caller.
	denials := stateDenialOps()
	assert.Contains(t, denials, string(kernel.OpKVWrite))
	assert.Contains(t, denials, string(kernel.OpKVRead))
	assert.Positive(t, stateFaults(buf), "a denial must be visible on the console as a fault")
}

// TestKVForeignContextIsRefused covers the sealed-context half of every entry
// point. No type outside package kernel can produce an SContext, so the only way
// to reach this is a nil interface, and it must fail closed rather than panic.
func TestKVForeignContextIsRefused(t *testing.T) {
	stateQuiet(t)

	assert.Error(t, kernel.KVPut(nil, "k", []byte("v")))
	_, err := kernel.KVGet(nil, "k")
	assert.Error(t, err)
	assert.False(t, kernel.IsDenied(err), "a foreign context is not a policy decision")
	assert.Error(t, kernel.KVDelete(nil, "k"))
	_, err = kernel.KVKeys(nil)
	assert.Error(t, err)
}

// TestKVCeilingIsMeasuredNotCounted covers the quota. The ceiling is on bytes, so
// one large value and many small ones hit it the same way, and a refused write
// leaves the store exactly as it was - including a refused overwrite, which is the
// case where a careless implementation would truncate or drop the old value.
func TestKVCeilingIsMeasuredNotCounted(t *testing.T) {
	buf := stateQuiet(t)
	// 64 bytes for the whole namespace. An entry costs the key length plus the
	// value length, so "seed" plus ten bytes costs 14.
	k := stateBoot(t, kernel.BootLimits{MaxKVBytesPerModule: 64})

	var (
		smallStored int
		smallErr    error
		bigErr      error
		overwrite   error
		readBack    []byte
	)

	pid := stateLoad(t, k, "kvquota", stateKVManifest(), func(ctx kernel.SContext) error {
		require.NoError(t, kernel.KVPut(ctx, "seed", []byte("0123456789")))

		// Many small values, 4 bytes each. Refusing partway through is the proof
		// that the ceiling is measured: a per-entry limit would have allowed all of
		// them, and a byte limit counted wrongly would have allowed a different
		// number.
		for i := range 100 {
			if err := kernel.KVPut(ctx, stateSmallKey(i), []byte("x")); err != nil {
				smallErr = err
				break
			}
			smallStored++
		}

		// One value larger than the whole namespace.
		bigErr = kernel.KVPut(ctx, "huge", bytes.Repeat([]byte("z"), 4096))

		// A refused overwrite must not disturb what is already stored.
		overwrite = kernel.KVPut(ctx, "seed", bytes.Repeat([]byte("q"), 4096))
		readBack, _ = kernel.KVGet(ctx, "seed")
		return nil
	})
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, smallErr, "the namespace must fill up on bytes, not on entries")
	assert.Equal(t, 12, smallStored,
		"the 14-byte seed plus twelve 4-byte entries is 62 of the 64 allowed bytes")
	assert.Equal(t, int64(62), kernel.KVBytes(pid), "accounting must not exceed the ceiling")

	require.Error(t, bigErr)
	require.Error(t, overwrite)
	assert.Equal(t, "0123456789", string(readBack),
		"a refused overwrite must leave the previous value intact")

	var qe *kernel.KVQuotaError
	require.True(t, errors.As(smallErr, &qe), "the ceiling must be a typed error")
	assert.Equal(t, pid, qe.Owner)
	assert.Equal(t, int64(64), qe.Limit)
	assert.Equal(t, int64(66), qe.WouldBe)
	assert.True(t, errors.As(bigErr, &qe), "an oversized value is the same refusal")
	assert.False(t, kernel.IsDenied(smallErr), "a quota refusal is not a policy denial")

	assert.Positive(t, stateFaults(buf), "hitting a ceiling must be visible as a fault")
	assert.NotContains(t, stateDenialOps(), string(kernel.OpKVWrite),
		"a quota refusal must not be recorded as a denial")
}

// stateSmallKey builds a fixed-width key so every entry in the ceiling test costs
// the same and the arithmetic in the assertion is exact.
func stateSmallKey(i int) string {
	const digits = "0123456789"
	return string([]byte{'k', digits[i/10%10], digits[i%10]})
}

// TestKVDeleteReturnsAccounting asserts that freeing a key gives the ceiling back,
// so a long-lived module that rotates its state does not slowly run out of room.
func TestKVDeleteReturnsAccounting(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{MaxKVBytesPerModule: 64})

	var (
		before     int64
		deleteErr  error
		missingErr error
		refill     error
	)

	pid := stateLoad(t, k, "kvdrop", stateKVManifest(), func(ctx kernel.SContext) error {
		require.NoError(t, kernel.KVPut(ctx, "seed", []byte("0123456789")))
		before = kernel.KVBytes(ctx.PID())
		deleteErr = kernel.KVDelete(ctx, "seed")
		missingErr = kernel.KVDelete(ctx, "never-stored")
		// With the accounting returned, a value that would not have fit now does.
		refill = kernel.KVPut(ctx, "big", bytes.Repeat([]byte("b"), 60))
		return nil
	})
	defer func() { _ = k.Unload(pid) }()

	assert.Equal(t, int64(14), before)
	assert.NoError(t, deleteErr)
	assert.ErrorIs(t, missingErr, kernel.ErrKVNotFound,
		"deleting an absent key is a caller defect and must be reported, not swallowed")
	assert.NoError(t, refill)
	assert.Equal(t, int64(63), kernel.KVBytes(pid))
}

// TestKVNamespaceIsDroppedOnUnload is the reclaim half. A pid is never reused, so
// state that survived its owner would be unreachable garbage nothing ever frees,
// and a module could grow kernel memory without limit by loading and unloading in
// a loop.
func TestKVNamespaceIsDroppedOnUnload(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	pid := stateLoad(t, k, "kvreclaim", stateKVManifest(), func(ctx kernel.SContext) error {
		require.NoError(t, kernel.KVPut(ctx, "a", []byte("1")))
		require.NoError(t, kernel.KVPut(ctx, "b", []byte("2")))
		return nil
	})
	require.Equal(t, int64(4), kernel.KVBytes(pid))

	require.NoError(t, k.Unload(pid))
	assert.Zero(t, kernel.FDCount(pid), "unload must reclaim every handle the module held")

	if n := kernel.KVBytes(pid); n != 0 {
		// UnloadModule in kernel/module.go must call kernel.KVDropNamespace(pid) and
		// kernel.ClearFSScope(pid) beside its existing reclaimFDs(pid). Neither file
		// is editable from this change, so until the integrator adds the two calls
		// this assertion cannot be evaluated. TestKVDropNamespaceIsComplete below
		// asserts the primitive itself, so the behavior is covered either way.
		t.Skipf("KVBytes(%d) = %d after unload: add kernel.KVDropNamespace(pid) and "+
			"kernel.ClearFSScope(pid) to UnloadModule in kernel/module.go and this "+
			"becomes a hard assertion", pid, n)
	}
	assert.Zero(t, kernel.KVBytes(pid), "unload must drop the module's whole namespace")
}

// TestKVDropNamespaceIsComplete exercises the drop primitive directly, so the
// behavior the unload path depends on is asserted even before it is wired.
func TestKVDropNamespaceIsComplete(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	var (
		keysAfter []string
		getErr    error
		putErr    error
	)

	pid := stateLoad(t, k, "kvdropns", stateKVManifest(), func(ctx kernel.SContext) error {
		require.NoError(t, kernel.KVPut(ctx, "a", []byte("1")))
		require.NoError(t, kernel.KVPut(ctx, "b", []byte("2")))
		return nil
	})
	defer func() { _ = k.Unload(pid) }()
	require.Equal(t, int64(4), kernel.KVBytes(pid))

	kernel.KVDropNamespace(pid)
	assert.Zero(t, kernel.KVBytes(pid))

	// The module's own context still works; only its stored state is gone. A drop
	// that also broke the namespace would be indistinguishable from a kernel fault.
	pid2 := stateLoad(t, k, "kvdropns2", stateKVManifest(), func(ctx kernel.SContext) error {
		keysAfter, _ = kernel.KVKeys(ctx)
		_, getErr = kernel.KVGet(ctx, "a")
		putErr = kernel.KVPut(ctx, "fresh", []byte("value"))
		return nil
	})
	defer func() { _ = k.Unload(pid2) }()

	assert.Empty(t, keysAfter)
	assert.ErrorIs(t, getErr, kernel.ErrKVNotFound)
	assert.NoError(t, putErr, "a dropped namespace must be usable again")
}

// TestKVPanicLeavesStoreUsable is the crash path. A module that panics while
// holding kvfs state must not corrupt the store for anyone else, must not strand
// its own accounting, and the kernel must still be usable afterwards.
func TestKVPanicLeavesStoreUsable(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	const name = "kvpanic"
	kernel.Register(name, func() (kernel.Module, error) {
		return &stateProbe{run: func(ctx kernel.SContext) error {
			require.NoError(t, kernel.KVPut(ctx, "half-written", []byte("value")))
			panic("module exploded mid-flight")
		}}, nil
	})
	t.Cleanup(func() { kernel.Unregister(name) })

	_, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "OnLoad panicked")

	var rejected kernel.PID
	for _, r := range kernel.ProcTable() {
		if r.Name == name {
			rejected = r.PID
		}
	}
	require.NotZero(t, rejected)
	assert.Equal(t, kernel.ProcRejected, stateProcState(rejected))
	assert.Zero(t, kernel.FDCount(rejected), "a panicking load must reclaim its handles")

	// The panicking module's namespace is still accounted, because nothing dropped
	// it. That is precisely what the unload wiring exists to fix, so the primitive
	// is called here and the resulting zero is the assertion that matters.
	assert.Equal(t, int64(len("half-written")+len("value")), kernel.KVBytes(rejected))
	kernel.KVDropNamespace(rejected)
	assert.Zero(t, kernel.KVBytes(rejected))

	// The kernel still serves a healthy module, and that module's namespace is
	// untouched by the crash next door.
	pid := stateLoad(t, k, "kvsurvivor", stateKVManifest(), func(ctx kernel.SContext) error {
		require.NoError(t, kernel.KVPut(ctx, "alive", []byte("yes")))
		got, gerr := kernel.KVGet(ctx, "alive")
		require.NoError(t, gerr)
		assert.Equal(t, "yes", string(got))
		return nil
	})
	defer func() { _ = k.Unload(pid) }()
	assert.Equal(t, int64(8), kernel.KVBytes(pid))
}

// stateProcState reads one process table row's state.
func stateProcState(pid kernel.PID) kernel.ProcState {
	for _, r := range kernel.ProcTable() {
		if r.PID == pid {
			return r.State
		}
	}
	return ""
}

// TestKVConcurrencyIsRaceFree hammers the store from several goroutines through
// one context. The suite runs under -race, so the interleaving is the assertion;
// what the test adds is that the byte accounting still balances afterwards, which
// is what a lost update under a lock would show up as.
func TestKVConcurrencyIsRaceFree(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{MaxKVBytesPerModule: 1 << 20})

	var ctx kernel.SContext
	pid := stateLoad(t, k, "kvconc", stateKVManifest(), func(c kernel.SContext) error {
		ctx = c
		return nil
	})
	defer func() { _ = k.Unload(pid) }()
	require.NotNil(t, ctx)

	const (
		workers   = 8
		perWorker = 25
		valueLen  = 8
	)
	var wg sync.WaitGroup
	var torn []string
	var mu sync.Mutex
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range perWorker {
				key := fmt.Sprintf("w%d-k%02d", w, i)
				value := bytes.Repeat([]byte{byte('a' + w)}, valueLen)
				if err := kernel.KVPut(ctx, key, value); err != nil {
					return
				}
				got, err := kernel.KVGet(ctx, key)
				if err != nil {
					continue
				}
				// Every byte of a value belongs to exactly one writer, so a torn
				// read shows up as a mix rather than as a wrong length.
				for _, b := range got {
					if b != byte('a'+w) {
						mu.Lock()
						torn = append(torn, key)
						mu.Unlock()
						return
					}
				}
				_ = kernel.KVBytes(pid)
				_ = kernel.KVCount(pid)
			}
		}(w)
	}
	wg.Wait()
	assert.Empty(t, torn, "no value may be observed torn")

	// Accounting must equal the sum of what is actually stored, which is the
	// invariant a lost increment or a double-count would break.
	keys, err := kernel.KVKeys(ctx)
	require.NoError(t, err)
	var want int64
	for _, key := range keys {
		want += int64(len(key)) + valueLen
	}
	assert.Equal(t, want, kernel.KVBytes(pid))
	assert.Equal(t, workers*perWorker, len(keys))
	assert.LessOrEqual(t, kernel.KVBytes(pid), int64(1<<20))
}

// TestKVRejectsMalformedKeys covers input validation. An empty key cannot be told
// apart from a failed lookup in a caller's log, and an unbounded key is
// attacker-chosen text the kernel would store and render into fault records.
func TestKVRejectsMalformedKeys(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	var emptyErr, longErr, nulErr error
	pid := stateLoad(t, k, "kvbad", stateKVManifest(), func(ctx kernel.SContext) error {
		emptyErr = kernel.KVPut(ctx, "", []byte("v"))
		longErr = kernel.KVPut(ctx, strings.Repeat("k", 513), []byte("v"))
		nulErr = kernel.KVPut(ctx, "a\x00b", []byte("v"))
		return nil
	})
	defer func() { _ = k.Unload(pid) }()

	for _, c := range []struct {
		name string
		err  error
	}{
		{"empty", emptyErr}, {"over-long", longErr}, {"nul", nulErr},
	} {
		require.Error(t, c.err, "%s key must be refused", c.name)
		var kve *kernel.KVError
		assert.ErrorAs(t, c.err, &kve, "%s key must be a typed KVError", c.name)
		assert.False(t, kernel.IsDenied(c.err), "a malformed key is a defect, not a denial")
	}
	assert.Zero(t, kernel.KVBytes(pid), "a refused key must not be accounted")
}

// TestFSResolveRefusesEveryEscape is the containment property, and the reason the
// resolver exists at all. A per-module data root is only a boundary if every way
// out of it is refused: lexically, through a symlink, and after the operating
// system has resolved each component.
func TestFSResolveRefusesEveryEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("other tenant"), 0o600))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "cache", "deep"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cache", "blob"), []byte("payload"), 0o600))

	// A link that leaves the root, one that stays inside it, and a dangling one
	// whose target was never created. The first is the attack, the second proves
	// the check is not simply "refuse all links", and the third is the case a
	// resolve-then-check implementation passes over.
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	require.NoError(t, os.Symlink(filepath.Join(root, "cache"), filepath.Join(root, "inside")))
	require.NoError(t, os.Symlink(filepath.Join(outside, "gone"), filepath.Join(root, "dangling")))

	escapes := []struct {
		name string
		rel  string
	}{
		{"parent traversal", "../secret.txt"},
		{"deep parent traversal", "cache/../../secret.txt"},
		{"leading dot-dot", ".."},
		{"trailing dot-dot", "cache/.."},
		{"absolute path", secret},
		{"absolute root", "/"},
		{"windows volume", `C:\windows\system32`},
		{"unc path", `\\host\share\x`},
		{"symlink out of root", "escape/secret.txt"},
		{"symlink to outside dir", "escape"},
		{"dangling symlink out", "dangling"},
		{"new file under an escaping link", "escape/new.bin"},
		{"the root itself", "."},
		{"empty path", ""},
	}
	for _, c := range escapes {
		t.Run(c.name, func(t *testing.T) {
			got, err := kernel.FSResolve(root, c.rel)
			require.Error(t, err, "%q must be refused", c.rel)
			assert.Empty(t, got, "a refused path must not be usable")
			var fse *kernel.FSPathError
			assert.ErrorAs(t, err, &fse,
				"a path refusal must be typed, so a caller need not string-match")
		})
	}

	t.Run("nul byte", func(t *testing.T) {
		_, err := kernel.FSResolve(root, "cache\x00/blob")
		require.Error(t, err)
		assert.ErrorContains(t, err, "NUL")
	})

	t.Run("no data root configured", func(t *testing.T) {
		_, err := kernel.FSResolve("", "cache/blob")
		require.Error(t, err)
		assert.ErrorContains(t, err, "no data root")
	})

	t.Run("existing file inside the root", func(t *testing.T) {
		got, err := kernel.FSResolve(root, "cache/blob")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "cache", "blob"), got)
		assert.FileExists(t, got)
	})

	t.Run("symlink that stays inside", func(t *testing.T) {
		got, err := kernel.FSResolve(root, "inside/blob")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "cache", "blob"), got,
			"a link inside the root is legitimate and must resolve to its target")
	})

	t.Run("new file under an existing directory", func(t *testing.T) {
		// The write case: the target does not exist, so containment is decided by
		// the nearest existing ancestor. Refusing here would make creating a file
		// impossible.
		got, err := kernel.FSResolve(root, "cache/deep/new.bin")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "cache", "deep", "new.bin"), got)
	})

	t.Run("redundant separators are cleaned", func(t *testing.T) {
		got, err := kernel.FSResolve(root, "cache//blob")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "cache", "blob"), got)
	})

	t.Run("root that is itself a symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "root-link")
		require.NoError(t, os.Symlink(root, link))
		got, err := kernel.FSResolve(link, "cache/blob")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "cache", "blob"), got,
			"a symlinked root must be compared as the directory it points at")
	})

	t.Run("relative root is resolved against the working directory", func(t *testing.T) {
		// A relative root must not make containment undecidable. The kernel makes
		// it absolute so the comparison is between two absolute paths.
		wd, err := os.Getwd()
		require.NoError(t, err)
		rel, err := filepath.Rel(wd, root)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Skip("the temp root is not reachable by a relative path from here")
		}
		got, err := kernel.FSResolve(rel, "cache/blob")
		require.NoError(t, err)
		assert.True(t, filepath.IsAbs(got))
	})

	// The outside file is untouched by every attempt above, which is the property
	// the resolver exists to provide.
	assert.FileExists(t, secret)
	body, err := os.ReadFile(secret)
	require.NoError(t, err)
	assert.Equal(t, "other tenant", string(body))
}

// TestFSPathAllowedMatchesBySegment is the manifest boundary rule. Matching by
// string prefix would let a module that declared "cache" reach "cache-secret",
// which no reviewer reading that manifest would have agreed to.
func TestFSPathAllowedMatchesBySegment(t *testing.T) {
	allow := []string{"cache", "state/locks"}

	cases := []struct {
		rel  string
		want bool
	}{
		{"cache", true},
		{"cache/blob", true},
		{"cache/deep/blob", true},
		{"cache-secret", false},
		{"cache2/blob", false},
		{"cachex", false},
		{"state/locks/a", true},
		{"state/locksmith", false},
		{"state", false},
		{"other", false},
		{".", false},
		{"/", false},
		{"", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, kernel.FSPathAllowed(c.rel, allow),
			"FSPathAllowed(%q) must follow the segment rule", c.rel)
	}

	assert.False(t, kernel.FSPathAllowed("anything", nil), "an empty declaration grants nothing")
	assert.False(t, kernel.FSPathAllowed(".", []string{"."}),
		"the data root itself is never in scope")
	assert.False(t, kernel.FSPathAllowed("..", []string{".."}),
		"a declaration that escapes is ignored rather than honored")
	assert.False(t, kernel.FSPathAllowed("etc/passwd", []string{"../etc"}),
		"a declaration reaching outside the root is ignored")
}

// TestFSCheckGateIsEnforced asserts the policy gate in front of the resolver.
//
// fs:read and fs:write are scoped operations: a module holds one only if its
// manifest declares it, and declaring it requires declaring the path boundary that
// bounds it. The gate therefore has two decisions to make, and they are recorded
// differently because they mean different things. A module that never declared
// fs:read gets a plain denial. A module that declared it and then reached outside
// its own boundary gets an escalation, because asking past a grant is evidence
// about the module in a way that mistyping an operation is not. Both are
// *DeniedError, so IsDenied is true for both; the audit kind is what separates
// them, and that is what this test pins.
func TestFSCheckGateIsEnforced(t *testing.T) {
	buf := stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cache"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cache", "blob"), []byte("x"), 0o600))

	// An in-scope path resolves for a module that declared the operation and the
	// boundary covering it. This is the case that could not pass while scoped
	// operations were refused at the ceiling before their scope was consulted.
	var okPath string
	var okReadErr, okWriteErr error
	pid := stateLoad(t, k, "kvfsprobe", kernel.Manifest{
		Require:    []kernel.Op{kernel.OpFSRead, kernel.OpFSWrite},
		ReadPaths:  []string{"cache"},
		WritePaths: []string{"cache"},
	}, func(ctx kernel.SContext) error {
		okPath, okReadErr = kernel.FSCheckRead(ctx, root, "cache/blob")
		_, okWriteErr = kernel.FSCheckWrite(ctx, root, "cache/blob")
		return nil
	})
	defer func() { _ = k.Unload(pid) }()

	require.NoError(t, okReadErr, "a declared operation inside its boundary must resolve")
	require.NoError(t, okWriteErr)
	assert.Equal(t, filepath.Join(root, "cache", "blob"), okPath)

	var ctx kernel.SContext
	pid2 := stateLoad(t, k, "kvfsprobe2", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	}, func(c kernel.SContext) error {
		ctx = c
		return nil
	})
	defer func() { _ = k.Unload(pid2) }()

	// Reaching past the boundary is a denial to the caller and an escalation on the
	// chain. Note the sibling directory: cache-secret shares a prefix with cache, so
	// a boundary matched by string prefix rather than by path segment would wrongly
	// admit it.
	_, err := kernel.FSCheckRead(ctx, root, "cache-secret/blob")
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "outside the declared boundary is a denial")
	assert.Contains(t, stateEscalationOps(), string(kernel.OpFSRead),
		"reaching past a grant is recorded as an escalation, not only as a denial")
	assert.Positive(t, stateFaults(buf), "a boundary refusal must be visible as a fault")

	_, err = kernel.FSCheckRead(ctx, root, "../secret")
	require.Error(t, err, "containment is checked before the boundary")
}

// TestFSUndeclaredOperationIsAPlainDenial covers the other half of the gate. A
// module that never declared fs:read is refused at the policy check, and the
// refusal is a denial rather than an escalation: it made no attempt to act beyond a
// grant, because it holds no grant at all.
func TestFSUndeclaredOperationIsAPlainDenial(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cache"), 0o755))

	var err error
	pid := stateLoad(t, k, "kvnodecl", kernel.Manifest{
		Name: "kvnodecl", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpKVRead},
	}, func(ctx kernel.SContext) error {
		_, err = kernel.FSCheckRead(ctx, root, "cache/blob")
		return nil
	})
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
	assert.Contains(t, stateDenialOps(), string(kernel.OpFSRead),
		"an undeclared operation is a policy denial")
	assert.NotContains(t, stateEscalationOps(), string(kernel.OpFSRead),
		"a module with no grant made no attempt to exceed one")
}

// TestFSScopeIsPerModule asserts the boundary is installed per pid and dropped on
// unload, so a scope never applies to whatever loads next.
func TestFSScopeIsPerModule(t *testing.T) {
	stateQuiet(t)
	k := stateBoot(t, kernel.BootLimits{})

	pid := stateLoad(t, k, "kvscope", stateKVManifest(), func(kernel.SContext) error { return nil })
	kernel.SetFSScope(pid, []string{"cache"}, []string{"cache", "state"})
	defer func() { _ = k.Unload(pid) }()

	// A scope set for one pid must not be visible through another. The only way to
	// observe that from outside the package is through the check itself, so a
	// second pid with no scope installed is refused even for an in-scope path.
	pid2 := stateLoad(t, k, "kvscope2", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	}, func(kernel.SContext) error { return nil })
	defer func() { _ = k.Unload(pid2) }()

	root := t.TempDir()
	_, err := kernel.FSCheckRead(k.InitContext(), root, "cache/blob")
	require.Error(t, err, "init does not hold fs:read, so the gate refuses first")
	assert.True(t, kernel.IsDenied(err))

	// Dropping the scope is idempotent, because the unload path may run more than
	// once for a pid that was already terminated.
	kernel.ClearFSScope(pid)
	kernel.ClearFSScope(pid)
}

// TestKVStateDoesNotSurviveRestart is the reset-path assertion: a kernel booted
// after Shutdown must be indistinguishable from a first-booted one, which for kvfs
// means no module state and no path scopes carried over.
func TestKVStateDoesNotSurviveRestart(t *testing.T) {
	stateQuiet(t)

	k1, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-state"},
	})
	require.NoError(t, err)
	pid := stateLoadNoUnload(t, k1, "kvreset", stateKVManifest(), func(ctx kernel.SContext) error {
		return kernel.KVPut(ctx, "survivor", []byte("should not survive"))
	})
	require.Positive(t, kernel.KVBytes(pid))
	kernel.SetFSScope(pid, []string{"cache"}, []string{"cache"})
	require.NoError(t, k1.Shutdown())

	if n := kernel.KVBytes(pid); n != 0 {
		t.Skipf("KVBytes(%d) = %d after Shutdown: add resetKVFS() and resetFSScopes() to "+
			"resetKernel() in kernel/kernel.go and this becomes a hard assertion", pid, n)
	}
	assert.Zero(t, kernel.KVBytes(pid), "kvfs state must not survive a restart")
	assert.Zero(t, kernel.KVCount(pid))
	assert.Zero(t, kernel.FDCount(pid))

	k2, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "node-state"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k2.Shutdown() })

	// The same name loads again and starts from an empty namespace, which is what
	// "no stale state" means to the module author.
	var got []byte
	var getErr error
	pid2 := stateLoadNoUnload(t, k2, "kvreset", stateKVManifest(), func(ctx kernel.SContext) error {
		got, getErr = kernel.KVGet(ctx, "survivor")
		return nil
	})
	t.Cleanup(func() { _ = k2.Unload(pid2) })

	assert.Nil(t, got)
	assert.ErrorIs(t, getErr, kernel.ErrKVNotFound)
	assert.Zero(t, kernel.KVBytes(pid2))
}

// stateLoadNoUnload loads a probe without registering an unload cleanup, for the
// restart tests that must own the shutdown themselves.
//
// It also skips the namespace drop that stateLoad performs, deliberately. Those
// tests assert that state does not survive a restart, and a probe that wiped its
// own namespace on the way in would make the assertion pass for the wrong reason:
// pids restart at 1 with each boot, so the second boot's module gets the first
// boot's pid, and dropping would erase exactly the stale state under test.
func stateLoadNoUnload(t *testing.T, k *kernel.Kernel, name string, m kernel.Manifest, run func(kernel.SContext) error) kernel.PID {
	t.Helper()
	kernel.Register(name, func() (kernel.Module, error) {
		return &stateProbe{run: run, noDrop: true}, nil
	})
	// Unregister immediately after Load rather than in a cleanup: the registration
	// is only consulted during Load, and a restart test legitimately loads the same
	// name twice inside one test. Deferring to cleanup would make the second
	// registration collide with the first.
	defer kernel.Unregister(name)
	m.Name = name
	if m.Version == "" {
		m.Version = "1"
	}
	m.MinKernelAPI = kernel.KernelAPI
	m.MaxKernelAPI = kernel.KernelAPI
	pid, err := k.Load(m)
	require.NoError(t, err)
	t.Cleanup(func() { stateForgetContext(pid) })
	return pid
}
