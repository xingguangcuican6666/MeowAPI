package kernel_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// quietConsole gives each test its own console sink so records can be asserted
// without polluting stderr and without tests racing on the global sink.
func quietConsole(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	// A mutex guards concurrent writers: the kernel emits from whatever
	// goroutine calls it, and tests assert on the buffer afterwards.
	sink := &lockedBuffer{buf: &buf}
	kernel.KernelConsole().SetOutput(sink)
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

func records(t *testing.T, buf *bytes.Buffer) []kernel.Record {
	t.Helper()
	var out []kernel.Record
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r kernel.Record
		require.NoError(t, json.Unmarshal([]byte(line), &r), "console line is not valid JSON: %s", line)
		out = append(out, r)
	}
	return out
}

func faults(buf *bytes.Buffer) []kernel.Record {
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

func bootOne(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

type faultProbe struct{ err error }

func (f *faultProbe) OnLoad(ctx kernel.SContext) error {
	// The log syscall must fail closed; OnLoad still succeeds so the test can
	// inspect the recorded error rather than the load result.
	f.err = ctx.SyscallLog(kernel.LogFault, "forged fault from a plugin")
	// Info level must work, proving the refusal is about the level and not
	// about log:write in general.
	if e := ctx.SyscallLog(kernel.LogInfo, "info level is permitted"); e != nil {
		return e
	}
	return nil
}

func (f *faultProbe) OnUnload() error { return nil }

type metadataProbe struct{ ctx kernel.SContext }

func (p *metadataProbe) OnLoad(ctx kernel.SContext) error { p.ctx = ctx; return nil }
func (p *metadataProbe) OnUnload() error                  { return nil }

type failLoad struct{}

func (failLoad) OnLoad(kernel.SContext) error { return assert.AnError }
func (failLoad) OnUnload() error              { return nil }

type diagOK struct{}

func (diagOK) OnLoad(kernel.SContext) error { return nil }
func (diagOK) OnUnload() error              { return nil }

type panics struct{}

func (panics) OnLoad(kernel.SContext) error { return nil }
func (panics) OnUnload() error              { panic("module exploded") }

type metaReader struct {
	published   any
	initPrivate any
	err         error
}

func (r *metaReader) OnLoad(ctx kernel.SContext) error {
	r.published, r.err = ctx.SyscallMetadataGet("kernel.boot.id")
	if r.err != nil {
		return r.err
	}
	r.initPrivate, r.err = ctx.SyscallMetadataGet("init.private")
	return r.err
}
func (r *metaReader) OnUnload() error { return nil }

// probeModule records what it was allowed to do during OnLoad, so a test can
// assert on the outcome of a syscall made from inside module code.
type probeModule struct {
	onLoad func(ctx kernel.SContext) error
}

func (p *probeModule) OnLoad(ctx kernel.SContext) error {
	if p.onLoad != nil {
		return p.onLoad(ctx)
	}
	return nil
}
func (p *probeModule) OnUnload() error { return nil }

func registerProbe(t *testing.T, name string, m kernel.Module) {
	t.Helper()
	kernel.Register(name, func() (kernel.Module, error) { return m, nil })
	t.Cleanup(func() { kernel.Unregister(name) })
}

func containsOp(ops []kernel.Op, want kernel.Op) bool {
	for _, o := range ops {
		if o == want {
			return true
		}
	}
	return false
}

// itoa renders a small integer for building unique module names in tests. It lives
// here rather than in the file that first needed it, because several subsystem suites
// share it and a helper whose definition is in one subsystem's file cannot be found
// by a reader of another's.
func itoa(n int) string {
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
