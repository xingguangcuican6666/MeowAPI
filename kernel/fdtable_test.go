package kernel_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// These tests reach the fd table through the module-reachable surface: a probe
// module opens handles in OnLoad, and the assertions read FDCount, FDList and the
// reclaim-on-unload behavior. The table itself is package-private, which is correct:
// a handle is only meaningful inside the pid that owns it.

// fdProbeModule opens a configurable number of handles and records what it got.
type fdProbeModule struct {
	open    int
	got     []kernel.FD
	openErr error
	// closeOne, when non-zero, closes that many handles from inside OnLoad so the
	// test can assert explicit close as well as reclamation.
	closeOne int
	ctx      kernel.SContext
	// allEver keeps every handle this module was issued, including ones it has
	// since closed, so a test can assert none of them is ever reissued.
	allEver []kernel.FD
}

func (m *fdProbeModule) OnLoad(ctx kernel.SContext) error {
	m.ctx = ctx
	for range m.open {
		fd, err := kernel.ProbeOpenHandle(ctx, "probe")
		if err != nil {
			m.openErr = err
			return nil
		}
		m.got = append(m.got, fd)
		m.allEver = append(m.allEver, fd)
	}
	for range m.closeOne {
		if len(m.got) == 0 {
			break
		}
		fd := m.got[0]
		m.got = m.got[1:]
		if err := ctx.SyscallClose(fd); err != nil {
			return err
		}
	}
	return nil
}

func (m *fdProbeModule) OnUnload() error { return nil }

// fdProbeCounter gives each probe registration a distinct name, because two live
// modules cannot share one name and several tests load more than one probe.
var fdProbeCounter int

func loadFDProbe(t *testing.T, k *kernel.Kernel, m kernel.Module) kernel.PID {
	t.Helper()
	fdProbeCounter++
	name := fmt.Sprintf("fdprobe%d", fdProbeCounter)
	kernel.Register(name, func() (kernel.Module, error) { return m, nil })
	t.Cleanup(func() { kernel.Unregister(name) })
	pid, err := k.Load(kernel.Manifest{Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.NoError(t, err)
	return pid
}

// TestHandlesArePerPidIsTheIsolationProperty is the reason the fd table exists. A
// handle is an int valid only inside its own pid's table, so a module cannot lend
// capability it was granted by handing another module a pointer to a kernel object.
// With integers, the receiving module's lookup simply fails.
func TestHandlesArePerPidIsTheIsolationProperty(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	owner := &fdProbeModule{open: 3}
	pidOwner := loadFDProbe(t, k, owner)
	defer func() { _ = k.Unload(pidOwner) }()

	require.Len(t, owner.got, 3)
	assert.Equal(t, 3, kernel.FDCount(pidOwner))

	// A different pid cannot resolve the owner's handles. The second probe closes
	// the first probe's fd numbers from its own table, which must fail rather than
	// reach across.
	thief := &thiefModule{stolen: owner.got}
	kernel.Register("fdthief", func() (kernel.Module, error) { return thief, nil })
	t.Cleanup(func() { kernel.Unregister("fdthief") })
	pidThief, err := k.Load(kernel.Manifest{Name: "fdthief", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pidThief) }()

	for _, fd := range owner.got {
		assert.Error(t, thief.results[fd], "pid %d must not resolve pid %d's handle %d",
			pidThief, pidOwner, fd)
	}
	// And the owner's handles are untouched by the attempt.
	assert.Equal(t, 3, kernel.FDCount(pidOwner))
}

type thiefModule struct {
	stolen  []kernel.FD
	results map[kernel.FD]error
}

func (m *thiefModule) OnLoad(ctx kernel.SContext) error {
	m.results = map[kernel.FD]error{}
	for _, fd := range m.stolen {
		m.results[fd] = ctx.SyscallClose(fd)
	}
	return nil
}
func (m *thiefModule) OnUnload() error { return nil }

// TestHandlesAreReclaimedOnUnload is the second reason the table exists: no
// resource's only reference lives inside module code, so unloading closes all of
// them. A module that panics or hangs during teardown must not leak.
func TestHandlesAreReclaimedOnUnload(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	m := &fdProbeModule{open: 5}
	pid := loadFDProbe(t, k, m)
	require.Equal(t, 5, kernel.FDCount(pid))

	require.NoError(t, k.Unload(pid))
	assert.Zero(t, kernel.FDCount(pid), "unload must reclaim every handle the module held")
	assert.Empty(t, kernel.FDList(pid))
}

// TestHandlesAreReclaimedWhenOnLoadFails covers the path that is easy to forget: a
// module that opens handles and then fails to load. Its cleanup must be as complete
// as a successful unload's.
func TestHandlesAreReclaimedWhenOnLoadFails(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	m := &fdProbeModule{open: 4}
	const name = "fdpartial"
	kernel.Register(name, func() (kernel.Module, error) {
		return &failingAfterOpen{inner: m}, nil
	})
	t.Cleanup(func() { kernel.Unregister(name) })

	_, err := k.Load(kernel.Manifest{Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.Error(t, err, "OnLoad must be allowed to fail")

	// The pid is not returned on failure, so find it in the process table.
	var pid kernel.PID
	for _, r := range kernel.ProcTable() {
		if r.Name == name {
			pid = r.PID
		}
	}
	require.NotZero(t, pid)
	assert.Equal(t, kernel.ProcRejected, kernel.ProcTable()[len(kernel.ProcTable())-1].State)
	assert.Zero(t, kernel.FDCount(pid),
		"a failed load must reclaim the handles it already opened")
}

type failingAfterOpen struct{ inner *fdProbeModule }

func (m *failingAfterOpen) OnLoad(ctx kernel.SContext) error {
	if err := m.inner.OnLoad(ctx); err != nil {
		return err
	}
	return errors.New("probe failed after opening handles")
}
func (m *failingAfterOpen) OnUnload() error { return nil }

// TestHandlesAreReclaimedWhenOnLoadPanics is the crash path. A module that panics
// after taking resources is exactly the module whose resources most need closing.
func TestHandlesAreReclaimedWhenOnLoadPanics(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	m := &fdProbeModule{open: 3}
	const name = "fdpanic"
	kernel.Register(name, func() (kernel.Module, error) {
		return &panicsAfterOpen{inner: m}, nil
	})
	t.Cleanup(func() { kernel.Unregister(name) })

	_, err := k.Load(kernel.Manifest{Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.Error(t, err)
	require.ErrorContains(t, err, "OnLoad panicked")

	var pid kernel.PID
	for _, r := range kernel.ProcTable() {
		if r.Name == name {
			pid = r.PID
		}
	}
	require.NotZero(t, pid)
	assert.Zero(t, kernel.FDCount(pid), "a panicking load must still reclaim its handles")

	// The kernel remains usable.
	pid2, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid2) }()
}

type panicsAfterOpen struct{ inner *fdProbeModule }

func (m *panicsAfterOpen) OnLoad(ctx kernel.SContext) error {
	_ = m.inner.OnLoad(ctx)
	panic("probe panicked after opening handles")
}
func (m *panicsAfterOpen) OnUnload() error { return nil }

// TestHandleCeilingComesFromSealedRoot proves the limit is not a constant a module
// can argue with, and that exhausting it fails cleanly rather than corrupting the
// table.
func TestHandleCeilingComesFromSealedRoot(t *testing.T) {
	buf := quietConsole(t)

	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{
		NodeID: "n", Limits: kernel.BootLimits{MaxOpenFDsPerModule: 4},
	}})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	// Asking for more than the ceiling must fail during OnLoad without failing the
	// load itself, so the test can inspect the partial state.
	m := &fdProbeModule{open: 10}
	pid := loadFDProbe(t, k, m)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, m.openErr, "opening past the ceiling must fail")
	assert.Contains(t, m.openErr.Error(), "maximum")
	assert.Len(t, m.got, 4, "exactly the ceiling's worth of handles were granted")
	assert.Equal(t, 4, kernel.FDCount(pid))
	assert.NotEmpty(t, faults(buf), "hitting a ceiling should be visible")
}

// TestExplicitCloseIsDistinctFromReclaim covers the module-driven path.
func TestExplicitCloseIsDistinctFromReclaim(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	m := &fdProbeModule{open: 3, closeOne: 2}
	pid := loadFDProbe(t, k, m)
	defer func() { _ = k.Unload(pid) }()

	assert.Len(t, m.got, 1, "two handles were closed explicitly inside OnLoad")
	assert.Equal(t, 1, kernel.FDCount(pid))

	// Closing the same handle twice is an error, not a silent no-op: a module
	// double-closing is a defect worth seeing, unlike unloading an unknown pid
	// during boot cleanup.
	require.NotNil(t, m.ctx)
	closed := m.got[0]
	require.NoError(t, m.ctx.SyscallClose(closed))
	assert.Error(t, m.ctx.SyscallClose(closed))
	assert.Zero(t, kernel.FDCount(pid))

	// An invalid handle is refused.
	assert.Error(t, m.ctx.SyscallClose(0))
	assert.Error(t, m.ctx.SyscallClose(-1))
	assert.Error(t, m.ctx.SyscallClose(999999))
}

// TestFDListIsSortedAndDescriptive covers the diagnostic view.
func TestFDListIsSortedAndDescriptive(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	m := &fdProbeModule{open: 6}
	pid := loadFDProbe(t, k, m)
	defer func() { _ = k.Unload(pid) }()

	list := kernel.FDList(pid)
	require.Len(t, list, 6)
	for i := 1; i < len(list); i++ {
		assert.Less(t, list[i-1].FD, list[i].FD, "FDList must be sorted by handle")
	}
	for _, e := range list {
		assert.Equal(t, "probe", e.Kind, "the resource kind must be reported")
		assert.Positive(t, e.OpenedAt, "the open time must come from the monotonic clock")
	}

	// A copy, so a caller cannot mutate the table through it.
	list[0].Kind = "tampered"
	assert.Equal(t, "probe", kernel.FDList(pid)[0].Kind)
}

// TestClosedHandlesAreNeverReissuedInPid is the property that makes a stale handle
// safe. If a closed number were reassigned within the same table, a module holding
// the old number would silently operate on a different resource.
//
// The property is per pid. Numbers do repeat across pids and must, because that
// repetition is the isolation: two modules each holding handle 1 are holding
// unrelated resources, which is what makes a handle untransferable.
func TestClosedHandlesAreNeverReissuedInPid(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	// One module closes three handles and then opens three more, so both sets live
	// in the same table and the numbering is directly comparable.
	m := &reopenProbe{first: 3, second: 3}
	pid := loadFDProbe(t, k, m)
	defer func() { _ = k.Unload(pid) }()

	require.Len(t, m.firstBatch, 3)
	require.Len(t, m.secondBatch, 3)
	assert.Zero(t, kernel.FDCount(pid), "all six were closed by the end of OnLoad")

	seen := map[kernel.FD]bool{}
	for _, fd := range append(append([]kernel.FD{}, m.firstBatch...), m.secondBatch...) {
		assert.False(t, seen[fd], "handle %d was issued twice in one pid", fd)
		seen[fd] = true
	}
	for _, fd := range m.firstBatch {
		assert.NotContains(t, m.secondBatch, fd,
			"handle %d was reissued after being closed in the same pid", fd)
	}

	// A different pid starts its own numbering, which is the isolation property
	// and not a bug.
	other := &fdProbeModule{open: 3}
	pid2 := loadFDProbe(t, k, other)
	defer func() { _ = k.Unload(pid2) }()
	assert.NotEqual(t, pid, pid2)
	assert.Equal(t, 3, kernel.FDCount(pid2))
}

// reopenProbe opens a batch, closes it, then opens another, all inside one pid.
type reopenProbe struct {
	first, second int
	firstBatch    []kernel.FD
	secondBatch   []kernel.FD
}

func (m *reopenProbe) OnLoad(ctx kernel.SContext) error {
	for range m.first {
		fd, err := kernel.ProbeOpenHandle(ctx, "first")
		if err != nil {
			return err
		}
		m.firstBatch = append(m.firstBatch, fd)
	}
	for _, fd := range m.firstBatch {
		if err := ctx.SyscallClose(fd); err != nil {
			return err
		}
	}
	for range m.second {
		fd, err := kernel.ProbeOpenHandle(ctx, "second")
		if err != nil {
			return err
		}
		m.secondBatch = append(m.secondBatch, fd)
	}
	for _, fd := range m.secondBatch {
		if err := ctx.SyscallClose(fd); err != nil {
			return err
		}
	}
	return nil
}

func (m *reopenProbe) OnUnload() error { return nil }

// TestConcurrentHandleUseIsRaceFree drives the table from several goroutines. The
// suite runs under -race, so this is the assertion.
func TestConcurrentHandleUseIsRaceFree(t *testing.T) {
	quietConsole(t)
	k := bootOne(t)

	m := &fdProbeModule{open: 40}
	pid := loadFDProbe(t, k, m)
	defer func() { _ = k.Unload(pid) }()
	require.Len(t, m.got, 40)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 20 {
				_ = kernel.FDCount(pid)
				_ = kernel.FDList(pid)
				idx := (g*20 + i) % len(m.got)
				_ = m.ctx.SyscallClose(m.got[idx])
			}
		}(g)
	}
	wg.Wait()

	assert.Zero(t, kernel.FDCount(pid), "every handle was closed exactly once")
	require.NoError(t, k.Unload(pid))
}

// TestFDTablesAreClearedAcrossRestart is the reset-path assertion for this
// subsystem, so a stale table cannot survive into a second boot.
func TestFDTablesAreClearedAcrossRestart(t *testing.T) {
	quietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	m := &fdProbeModule{open: 3}
	pid := loadFDProbe(t, k1, m)
	require.Equal(t, 3, kernel.FDCount(pid))
	require.NoError(t, k1.Shutdown())

	assert.Zero(t, kernel.FDCount(pid), "the fd table must not survive a shutdown")

	k2, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	defer func() { _ = k2.Shutdown() }()
	assert.Zero(t, kernel.FDCount(pid))
}
