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

// Package harness holds the fixtures the kernel's external test suites share.
//
// It exists because the suites live in separate packages under tests/, layered by
// architecture, and a package-level helper in one of them is invisible to the
// others. While every suite sat in kernel/ they could share helpers by being in the
// same package; splitting them by layer made a shared importable home necessary.
//
// Two rules keep this package honest.
//
// It imports the kernel and the standard library only. testify stays inside the
// _test.go files that use it, so no production build path reaches a test assertion
// library. Assertions inside these fixtures use t.Fatalf, which is also the correct
// behavior for a fixture: a fixture that cannot set up is not a soft failure.
//
// Nothing here reaches kernel internals. Every fixture goes through the exported
// kernel API, which is the property the suites exist to protect. The white-box probes
// in kernel/export_test.go compile only into the kernel package's own test binary, so
// they are deliberately unreachable from here, and the three suites that need them
// stay in kernel/ rather than moving under tests/.
package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// QuietConsole gives a test its own console sink, so records can be asserted without
// polluting stderr and without two tests racing on the global sink. The sink is
// restored at cleanup.
//
// The returned buffer is safe for concurrent writers: the kernel emits from whatever
// goroutine calls it, and the test reads the buffer afterwards.
func QuietConsole(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	kernel.KernelConsole().SetOutput(&lockedBuffer{buf: &buf})
	t.Cleanup(func() { kernel.KernelConsole().SetOutput(nil) })
	return &buf
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// Locked wraps one owned buffer as a console sink. It is the same mutex-guarded
// writer QuietConsole installs, exposed for suites that need to hold the inner
// buffer themselves - to read it mid-test, or to install format and level settings
// the plain fixture does not carry.
//
// It returns io.Writer rather than the concrete type so the wrapper stays private.
// A caller that named the type would be depending on the fixture's internals, which
// is exactly what a fixture should not have.
func Locked(inner *bytes.Buffer) io.Writer { return &lockedBuffer{buf: inner} }

// Records parses every console line the sink captured as a kernel record. A line that
// is not valid JSON fails the test, because a console emitting unparseable output is
// a defect in the console rather than in the suite reading it.
func Records(t *testing.T, buf *bytes.Buffer) []kernel.Record {
	t.Helper()
	var out []kernel.Record
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r kernel.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("console line is not valid JSON: %s (%v)", line, err)
		}
		out = append(out, r)
	}
	return out
}

// Faults returns only the fault-level records. Unparseable lines are skipped rather
// than fatal, because a suite asserting on faults is usually asserting that one
// specific refusal happened, and an unrelated malformed line should not mask it.
func Faults(buf *bytes.Buffer) []kernel.Record {
	var out []kernel.Record
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(line, `"level":"fault"`) {
			var r kernel.Record
			if json.Unmarshal([]byte(line), &r) == nil {
				out = append(out, r)
			}
		}
	}
	return out
}

// BootOne boots a kernel with default configuration and shuts it down at cleanup. It
// is the fixture most suites start from.
//
// The cleanup matters more than it looks: the boot guard is process-wide, so a suite
// that leaves a kernel booted makes every later test in the binary fail with "already
// booted", which reads as a cascade of unrelated failures rather than as one leaked
// fixture.
func BootOne(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{})
	if err != nil {
		t.Fatalf("boot failed: %v", err)
	}
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// BootTrust is a trust root with every field populated, for suites that need a sealed
// configuration rather than the defaults.
//
// SigningKeyPEM holds a placeholder, not key material. It is spelled
// SECRET-KEY-MATERIAL on purpose so that a test which accidentally renders it is
// obviously wrong at a glance.
func BootTrust() kernel.BootTrustRoot {
	return kernel.BootTrustRoot{
		NodeID:          "node-test",
		ClusterRootKeys: []string{"root-key-a", "root-key-b"},
		SigningKeyPEM:   "SECRET-KEY-MATERIAL",
		Extra:           map[string]string{"region": "local"},
	}
}

// FaultProbe is a module that tries to emit a fault record during OnLoad. The log
// syscall must fail closed, so OnLoad still succeeds and the suite inspects the
// recorded error rather than the load result.
//
// It also logs at info level, which must succeed: that is what proves the refusal is
// about the level rather than about log:write in general.
type FaultProbe struct{ Err error }

// OnLoad attempts a forged fault record and then a permitted info record.
func (f *FaultProbe) OnLoad(ctx kernel.SContext) error {
	f.Err = ctx.SyscallLog(kernel.LogFault, "forged fault from a plugin")
	if e := ctx.SyscallLog(kernel.LogInfo, "info level is permitted"); e != nil {
		return e
	}
	return nil
}

// OnUnload succeeds.
func (f *FaultProbe) OnUnload() error { return nil }

// MetadataProbe keeps its context so a suite can drive metadata calls after the load.
type MetadataProbe struct{ Ctx kernel.SContext }

// OnLoad records the context.
func (p *MetadataProbe) OnLoad(ctx kernel.SContext) error { p.Ctx = ctx; return nil }

// OnUnload succeeds.
func (p *MetadataProbe) OnUnload() error { return nil }

// FailLoad is a module whose OnLoad fails, for the failed-load paths.
type FailLoad struct{}

// OnLoad always fails.
func (FailLoad) OnLoad(kernel.SContext) error { return errFixture }

// OnUnload succeeds.
func (FailLoad) OnUnload() error { return nil }

// DiagOK is a module whose OnLoad succeeds, used as the loadable half of a pair.
type DiagOK struct{}

// OnLoad succeeds.
func (DiagOK) OnLoad(kernel.SContext) error { return nil }

// OnUnload succeeds.
func (DiagOK) OnUnload() error { return nil }

// Panics is a module whose OnLoad succeeds and whose OnUnload panics, for the crash
// path during teardown.
type Panics struct{}

// OnLoad succeeds.
func (Panics) OnLoad(kernel.SContext) error { return nil }

// OnUnload panics.
func (Panics) OnUnload() error { panic("module exploded") }

// MetaReader reads one published key and one init-private key during OnLoad, so a
// suite can assert on the metadata visibility rule from inside module code.
type MetaReader struct {
	Published   any
	InitPrivate any
	Err         error
}

// OnLoad performs both reads.
func (r *MetaReader) OnLoad(ctx kernel.SContext) error {
	r.Published, r.Err = ctx.SyscallMetadataGet("kernel.boot.id")
	if r.Err != nil {
		return r.Err
	}
	r.InitPrivate, r.Err = ctx.SyscallMetadataGet("init.private")
	return r.Err
}

// OnUnload succeeds.
func (r *MetaReader) OnUnload() error { return nil }

// errFixture is the error FailLoad returns. It is a package-level value rather than
// an assertion-library error so this file imports nothing but the kernel and the
// standard library.
var errFixture = errors.New("harness: this module always fails to load")

// Probe is a module that runs one callback during OnLoad and keeps the context it was
// loaded under, so a suite can drive further syscalls as that module after the load
// completes.
//
// The callback field is named Load rather than OnLoad because OnLoad is the method
// that satisfies kernel.Module, and Go does not allow a field and a method to share a
// name. A suite needing more than a callback defines its own module type instead of
// widening this one: a fixture with a hook for every case stops being a fixture.
type Probe struct {
	// Load runs inside OnLoad, under the module's own context.
	Load func(ctx kernel.SContext) error
	// Ctx is the context the kernel handed to OnLoad. It is the handle a suite uses
	// to make syscalls as that module afterwards.
	Ctx kernel.SContext
}

// OnLoad records the context and runs the callback.
func (p *Probe) OnLoad(ctx kernel.SContext) error {
	p.Ctx = ctx
	if p.Load != nil {
		return p.Load(ctx)
	}
	return nil
}

// OnUnload does nothing.
func (p *Probe) OnUnload() error { return nil }

// NoopModule is a module that does nothing, for suites that need something loaded
// without caring what it does.
type NoopModule struct{}

// OnLoad succeeds.
func (NoopModule) OnLoad(kernel.SContext) error { return nil }

// OnUnload succeeds.
func (NoopModule) OnUnload() error { return nil }

// RegisterProbe registers a module under a name and unregisters it at cleanup.
//
// Unregistering at cleanup rather than leaving it registered is what lets two tests
// in one binary load a module under the same name without the second failing on a
// duplicate registration.
func RegisterProbe(t *testing.T, name string, m kernel.Module) {
	t.Helper()
	kernel.Register(name, func() (kernel.Module, error) { return m, nil })
	t.Cleanup(func() { kernel.Unregister(name) })
}

// ContainsOp reports whether an operation set holds one operation. Several suites
// assert on a grant list, and a helper reads better than the same loop in each.
func ContainsOp(ops []kernel.Op, want kernel.Op) bool {
	for _, o := range ops {
		if o == want {
			return true
		}
	}
	return false
}

// Itoa renders a small integer, for building unique module names. Several suites need
// one, and a helper defined in one suite's file cannot be found by a reader of
// another's.
func Itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if negative {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
