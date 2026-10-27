package kernel_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// TestBootReentrancyGuard asserts the first invariant from the prototype: a
// second concurrent boot is a loud failure, not a silent no-op.
func TestBootReentrancyGuard(t *testing.T) {
	buf := quietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err, "first boot must succeed")
	defer func() { _ = k1.Shutdown() }()

	k2, err := kernel.Boot(kernel.BootConfig{})
	require.Error(t, err, "second boot must fail, not silently succeed")
	require.Nil(t, k2)
	assert.Contains(t, err.Error(), "already booted")

	var found bool
	for _, r := range records(t, buf) {
		if r.Level == kernel.LogFault && strings.Contains(r.Msg, "Re-entrant or duplicate boot") {
			found = true
		}
	}
	assert.True(t, found, "a duplicate boot must emit a fault record")
}

// TestBootAfterShutdownIsFresh proves the guard is released and that a second
// boot does not inherit the first boot's process table. Without this, the
// security invariants below would only be testable once per process.
func TestBootAfterShutdownIsFresh(t *testing.T) {
	quietConsole(t)

	k1, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	_, err = k1.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k1.Shutdown())

	k2, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err, "boot after shutdown must succeed")
	defer func() { _ = k2.Shutdown() }()

	table := kernel.ProcTable()
	require.NotEmpty(t, table)
	assert.Equal(t, kernel.PID(0), table[0].PID, "a fresh boot starts at pid 0")
	assert.Len(t, table, 2, "pid 0 and init only; the previous boot's modules must not survive")
}

// TestRootContextHandoffIsOnceOnly is the second prototype invariant: the root
// context can be transferred exactly once.
func TestRootContextHandoffIsOnceOnly(t *testing.T) {
	quietConsole(t)

	k, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	// The root context is retired the moment init exists. No exported
	// reference to it survives Boot, so the invariant is tested through the
	// observable consequence: nothing outside the kernel can reach pid 0, and
	// the process table shows init running in the init domain, not the kernel
	// domain.
	var initRec, rootRec *kernel.ProcSnapshot
	tbl := kernel.ProcTable()
	for i := range tbl {
		switch tbl[i].PID {
		case 0:
			rootRec = &tbl[i]
		case 1:
			initRec = &tbl[i]
		}
	}
	require.NotNil(t, rootRec)
	require.NotNil(t, initRec)
	assert.Equal(t, kernel.DomainInit, initRec.Domain, "init must run in its own domain, not the kernel domain")
	assert.Equal(t, kernel.PID(0), initRec.PPID, "init is spawned by pid 0")

	// A second boot inside the same process is where the handoff guard is
	// observable: it must refuse rather than hand out a second root. It fails
	// at the boot guard, before the handoff is ever attempted again, which is
	// the stronger ordering - a caller cannot reach the handoff twice.
	_, err = kernel.Boot(kernel.BootConfig{})
	require.Error(t, err)
}
