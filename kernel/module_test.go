package kernel_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestUnloadIsIdempotent matches the prototype: unloading an unknown pid is a
// no-op, so a boot path that unwinds a partial failure cannot fail twice.
func TestUnloadIsIdempotent(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)

	require.NoError(t, k.Unload(pid), "first unload must succeed")
	require.NoError(t, k.Unload(pid), "second unload of the same pid must be a no-op")
	require.NoError(t, k.Unload(kernel.PID(999999)), "unload of an unknown pid must be a no-op")

	// The record survives as terminated. Append-only means the audit trail
	// keeps what ran even after it stopped.
	var found bool
	for _, r := range kernel.ProcTable() {
		if r.PID == pid {
			found = true
			assert.Equal(t, kernel.ProcTerminated, r.State)
			assert.False(t, r.Terminated.IsZero(), "a terminated record must carry a timestamp")
		}
	}
	assert.True(t, found, "unload must not delete the process table record")
	assert.Empty(t, kernel.LoadedModules(), "no module may remain live after unload")
}

// TestDoubleLoadSameNameIsRefused prevents two instances of one module from
// sharing a name, which would make the process table and any name-based lookup
// ambiguous.
func TestDoubleLoadSameNameIsRefused(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	_, err = k.Load(diag.Manifest())
	require.Error(t, err, "loading the same module name twice must be refused")
	assert.Contains(t, err.Error(), "already loaded")
	assert.Len(t, kernel.LoadedModules(), 1)
}

// TestLoadFailureUnwinds proves that a module whose OnLoad fails does not leave
// a live entry behind: it is terminated in the table and absent from the live
// set. A half-loaded module is worse than no module.
func TestLoadFailureUnwinds(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	kernel.Register("failload", func() (kernel.Module, error) { return &failLoad{}, nil })
	t.Cleanup(func() { kernel.Unregister("failload") })

	pid, err := k.Load(kernel.Manifest{
		Name: "failload", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "OnLoad")
	assert.Equal(t, kernel.PID(0), pid)

	assert.Empty(t, kernel.LoadedModules(), "a failed load must not leave a live module")

	var rec *kernel.ProcSnapshot
	tbl := kernel.ProcTable()
	for i := range tbl {
		if tbl[i].Name == "failload" {
			rec = &tbl[i]
		}
	}
	require.NotNil(t, rec, "the attempted load must still be recorded")
	assert.Equal(t, kernel.ProcRejected, rec.State)
	assert.NotEmpty(t, rec.ManifestDigest, "the record must carry the manifest digest it was loaded from")
	assert.NotEmpty(t, faults(buf))

	// The name is free again: a failed load must not poison the registry.
	kernel.Register("failload2", func() (kernel.Module, error) { return &diagOK{}, nil })
	t.Cleanup(func() { kernel.Unregister("failload2") })
	pid2, err := k.Load(kernel.Manifest{
		Name: "failload2", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid2) }()
}

// TestPanickingModuleDoesNotKillKernel asserts crash containment: a module that
// panics during unload is reported and abandoned, and the kernel keeps running.
func TestPanickingModuleDoesNotKillKernel(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	kernel.Register("panics", func() (kernel.Module, error) { return &panics{}, nil })
	t.Cleanup(func() { kernel.Unregister("panics") })

	pid, err := k.Load(kernel.Manifest{
		Name: "panics", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	require.NoError(t, err)

	require.Error(t, k.Unload(pid), "a panicking OnUnload must be reported")

	// The kernel survives and can still load.
	pid2, err := k.Load(diag.Manifest())
	require.NoError(t, err, "the kernel must remain usable after a module panicked")
	defer func() { _ = k.Unload(pid2) }()
}

// TestEffectiveOpsAreNarrowed asserts that what a module is granted is the
// request intersected with what its domain can hold.
func TestEffectiveOpsAreNarrowed(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	mods := kernel.LoadedModules()
	require.Len(t, mods, 1)
	assert.ElementsMatch(t,
		[]kernel.Op{kernel.OpMetadataRead, kernel.OpLogWrite, kernel.OpUsageEmit},
		mods[0].Effective)
	assert.NotContains(t, mods[0].Effective, kernel.OpMetadataWrite)
}

// TestConcurrentLoadIsRaceFree drives parallel loads and unloads. Run with
// -race; this is the test that catches unsynchronized kernel state.
func TestConcurrentLoadIsRaceFree(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	for i := range 8 {
		name := "conc" + string(rune('a'+i))
		n := name
		kernel.Register(n, func() (kernel.Module, error) { return &diagOK{}, nil })
		t.Cleanup(func() { kernel.Unregister(n) })
	}

	var wg sync.WaitGroup
	pids := make([]kernel.PID, 8)
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "conc" + string(rune('a'+i))
			pid, err := k.Load(kernel.Manifest{
				Name: name, Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
			})
			if err == nil {
				pids[i] = pid
			}
		}(i)
	}
	wg.Wait()

	seen := map[kernel.PID]bool{}
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		assert.False(t, seen[pid], "concurrent loads must not collide on a pid")
		seen[pid] = true
	}
	assert.Len(t, seen, 8, "all eight modules must have loaded")

	var wg2 sync.WaitGroup
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		wg2.Add(1)
		go func(pid kernel.PID) {
			defer wg2.Done()
			_ = k.Unload(pid)
		}(pid)
	}
	wg2.Wait()

	assert.Empty(t, kernel.LoadedModules(), "every module must be gone after concurrent unload")
}

// TestPanickingOnLoadDoesNotKillKernel covers the load path, which is where
// untrusted code runs for the first time. A panic there must be contained exactly
// as a panic in OnUnload is: the load fails, the record is rejected, and the
// kernel stays usable.
func TestPanickingOnLoadDoesNotKillKernel(t *testing.T) {
	buf := quietConsole(t)
	k := bootOne(t)

	registerProbe(t, "boom", &probeModule{onLoad: func(kernel.SContext) error {
		panic("module exploded during OnLoad")
	}})

	pid, err := k.Load(kernel.Manifest{
		Name: "boom", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	require.Error(t, err, "a panicking OnLoad must fail the load")
	require.ErrorContains(t, err, "OnLoad panicked")
	assert.Equal(t, kernel.PID(0), pid)

	// The rejection is recorded, not merely returned.
	var rec *kernel.ProcSnapshot
	tbl := kernel.ProcTable()
	for i := range tbl {
		if tbl[i].Name == "boom" {
			rec = &tbl[i]
		}
	}
	require.NotNil(t, rec)
	assert.Equal(t, kernel.ProcRejected, rec.State)
	assert.Empty(t, kernel.LoadedModules())
	assert.NotEmpty(t, faults(buf))

	// The kernel still works.
	pid2, err := k.Load(diag.Manifest())
	require.NoError(t, err, "the kernel must remain usable after a module panicked in OnLoad")
	defer func() { _ = k.Unload(pid2) }()
}
