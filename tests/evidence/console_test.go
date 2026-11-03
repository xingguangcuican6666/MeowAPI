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

package evidence

import (
	"bytes"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// TestPluginCannotEmitFaultRecord asserts that the audit trail cannot be forged
// or flooded by a module. A plugin that could emit fault records could bury a
// real denial in noise or fabricate evidence.
func TestPluginCannotEmitFaultRecord(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)

	probe := &harness.FaultProbe{}
	kernel.Register("faultprobe", func() (kernel.Module, error) { return probe, nil })
	t.Cleanup(func() { kernel.Unregister("faultprobe") })

	pid, err := k.Load(kernel.Manifest{
		Name: "faultprobe", Version: "0.1.0", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, probe.Err, "a plugin emitting a fault-level record must be refused")
	assert.True(t, kernel.IsDenied(probe.Err), "the refusal must be a denial, got %v", probe.Err)

	var sawReserved bool
	for _, r := range harness.Faults(buf) {
		if strings.Contains(r.Msg, "fault level reserved") || strings.Contains(r.Msg, "emit fault record from unprivileged domain") {
			sawReserved = true
		}
	}
	assert.True(t, sawReserved, "the attempt to emit a fault record must itself be recorded")
}

// TestConsoleRetentionIsBounded proves the diagnostic stream cannot grow
// without limit. The process table is the audit log; the console is not.
func TestConsoleRetentionIsBounded(t *testing.T) {
	buf := harness.QuietConsole(t)
	c := kernel.KernelConsole()
	c.SetLimit(8)
	t.Cleanup(func() { c.SetLimit(4096) })

	k := harness.BootOne(t)
	for i := range 40 {
		require.NoError(t, k.InitContext().SyscallLog(kernel.LogInfo, "noise"))
		_ = i
	}

	assert.LessOrEqual(t, len(c.History()), 8, "retention must cap the console")
	assert.Greater(t, c.Dropped(), int64(0), "evictions must be counted, not silent")
	assert.NotEmpty(t, buf.String())
}

// TestConsoleTextFormat asserts the human-readable rendering is aligned and
// carries every field the JSON form does, minus structure.
func TestConsoleTextFormat(t *testing.T) {
	inner := &bytes.Buffer{}
	c := kernel.KernelConsole()
	c.SetOutput(harness.Locked(inner))
	c.SetFormat(kernel.FormatText)
	t.Cleanup(func() {
		c.SetFormat(kernel.FormatJSON)
		c.SetOutput(nil)
	})

	k, err := kernel.Boot(kernel.BootConfig{
		VerifierPolicy: kernel.VerifierOff})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	require.NoError(t, k.InitContext().SyscallLog(kernel.LogWarn, "something notable"))

	out := inner.String()
	assert.Contains(t, out, "WARN")
	assert.Contains(t, out, "u:r:init:s0")
	assert.Contains(t, out, "pid=1")
	assert.Contains(t, out, "something notable")
	assert.NotContains(t, out, `{"time"`, "text format must not emit JSON")

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		assert.True(t, strings.Contains(line, "INFO") || strings.Contains(line, "WARN") ||
			strings.Contains(line, "DEBUG") || strings.Contains(line, "FAULT"),
			"every text line must carry a severity tag: %q", line)
	}
}

// TestConsoleLevelFilter asserts the sink filter cannot filter the audit trail.
// A developer quiets debug noise; the fault history must survive intact.
func TestConsoleLevelFilter(t *testing.T) {
	inner := &bytes.Buffer{}
	c := kernel.KernelConsole()
	c.SetOutput(harness.Locked(inner))
	c.SetLevel(kernel.LogError)
	t.Cleanup(func() {
		c.SetLevel(kernel.LogDebug)
		c.SetOutput(nil)
	})

	k, err := kernel.Boot(kernel.BootConfig{
		VerifierPolicy: kernel.VerifierOff})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	require.NoError(t, k.InitContext().SyscallLog(kernel.LogDebug, "quiet please"))
	require.NoError(t, k.InitContext().SyscallLog(kernel.LogError, "loud"))

	out := inner.String()
	assert.NotContains(t, out, "quiet please", "below-threshold records must not reach the sink")
	assert.Contains(t, out, "loud")

	var retainedDebug bool
	for _, r := range c.History() {
		if r.Level == kernel.LogDebug && r.Msg == "quiet please" {
			retainedDebug = true
		}
	}
	assert.True(t, retainedDebug, "filtering the sink must not filter history")
}

// TestConsoleRejectsUnknownFormat proves an unrecognized format is ignored
// rather than silently changing output shape, which would look like a broken
// kernel to whatever parses the log.
func TestConsoleRejectsUnknownFormat(t *testing.T) {
	c := kernel.KernelConsole()
	before := c.Format()
	c.SetFormat("yaml")
	assert.Equal(t, before, c.Format())
	c.SetLevel("shout")
	assert.Equal(t, kernel.LogDebug, c.Level())
}

// TestTextConsoleCannotForgeARecord pins that a module's message cannot manufacture a
// second console record.
//
// The text format wrote the message verbatim, so a newline in it started a line that
// looked like a kernel record. JSON mode escaped by construction, which is what made
// the text format the one place nobody looked. The message is the field a module
// controls most freely - SyscallLog gates the LEVEL and nothing else - so this was the
// cheapest header in the whole trail to forge.
func TestTextConsoleCannotForgeARecord(t *testing.T) {
	var buf bytes.Buffer
	sink := harness.Locked(&buf)

	// The FORMAT is process-global console state, so the value that was there before
	// this test is captured and put back rather than asserting the documented default.
	// The difference is not pedantry: restoring FormatJSON is correct only while every
	// other test in this package leaves the console in JSON, which makes the cleanup a
	// dependency on the rest of the file rather than a guarantee of its own - the same
	// shape as a gitignore premise that is true until someone adds a fixture. Capturing
	// prev costs one line and cannot be broken by a neighbour.
	prev := kernel.KernelConsole().Format()

	k, err := kernel.Boot(kernel.BootConfig{
		VerifierPolicy: kernel.VerifierOff,
		Console:        sink,
		LogFormat:      kernel.FormatText,
		LogLevel:       kernel.LogDebug,
	})
	require.NoError(t, err)
	// Measured before this existed: leaving the format at text made three tests in this
	// package fail in the full run and pass alone.
	t.Cleanup(func() {
		_ = k.Shutdown()
		kernel.KernelConsole().SetFormat(prev)
	})

	harness.RegisterProbe(t, "forger", &harness.Probe{Load: func(ctx kernel.SContext) error {
		return ctx.SyscallLog(kernel.LogInfo,
			"benign\n00:00:00.000 FAULT [u:r:kernel:s0 pid=0] all clear")
	}})
	_, err = k.Load(kernel.Manifest{
		Name: "forger", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.NoError(t, err)

	out := buf.String()
	// The assertion is on WHERE the forged text sits, not that it is absent: escaped,
	// it is still visible on one line, which is the point - an operator can still read
	// what the module said. What must not happen is a line that STARTS like a kernel
	// record and carries the forged payload. The first version of this test failed on
	// its own escaped output because it searched the whole line for both markers.
	if strings.Contains(out, "\n00:00:00.000 FAULT") {
		t.Fatalf("the message broke the line structure:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if strings.Contains(trimmed, "FAULT") && !strings.Contains(trimmed, "benign") {
			t.Fatalf("a line begins as a kernel fault and is not a module record:\n%s", out)
		}
	}
	if !strings.Contains(out, `\n`) {
		t.Fatalf("the newline was not escaped, so the message stayed multi-line:\n%s", out)
	}
}
