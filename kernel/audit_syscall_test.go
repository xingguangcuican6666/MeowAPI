package kernel_test

import (
	"errors"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// These tests drive the audit syscall surface, which is the module-reachable half
// of kaudit. The chain construction and tamper detection are in audit_clock_test.go.

// auditProbe records what a module was allowed to do with the audit chain.
type auditProbe struct {
	readErr   error
	readCount int
	appendErr error
	appended  kernel.AuditEntry
	entries   []kernel.AuditEntry
}

func (p *auditProbe) OnLoad(ctx kernel.SContext) error {
	p.entries, p.readErr = ctx.SyscallAuditRead(kernel.AuditFilter{})
	p.readCount = len(p.entries)
	p.appended, p.appendErr = ctx.SyscallAuditAppend(
		kernel.AuditRequest, "trace-1", "module note", map[string]any{"route": "/v1/x"})
	return nil
}
func (p *auditProbe) OnUnload() error { return nil }

func loadAuditProbe(t *testing.T, k *kernel.Kernel, m kernel.Module, ops ...kernel.Op) kernel.PID {
	t.Helper()
	auditProbeCounter++
	name := "auditprobe" + string(rune('a'+auditProbeCounter%26)) + string(rune('0'+auditProbeCounter/26))
	kernel.Register(name, func() (kernel.Module, error) { return m, nil })
	t.Cleanup(func() { kernel.Unregister(name) })
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1, Require: ops,
	})
	require.NoError(t, err)
	return pid
}

var auditProbeCounter int

// TestModuleCannotReachTheAuditChainAtAll is stronger than a runtime denial: the
// plugin domain holds neither audit:read nor audit:append, so a manifest that
// requests either fails validation and the module never runs.
//
// Both refusals matter and for different reasons. Writing would let a module
// record its own good behavior as fact, turning evidence into testimony. Reading
// would leak every other module's denials and escalation attempts to any module
// that asked, which is an information channel between modules that the metadata
// store deliberately does not have either.
func TestModuleCannotReachTheAuditChainAtAll(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)

	for _, op := range []kernel.Op{kernel.OpAuditRead, kernel.OpAuditAppend} {
		assert.False(t, kernel.Allowed(kernel.DomainPlugin, op),
			"the plugin domain must never hold %s", op)

		_, err := k.Load(kernel.Manifest{
			Name: "audacious-" + string(op), Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
			Require: []kernel.Op{op},
		})
		require.Error(t, err, "requesting %s must fail validation", op)
		assert.Contains(t, err.Error(), "not grantable")

		rejects := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditReject})
		require.NotEmpty(t, rejects, "a refused manifest must still be recorded")
		assert.Equal(t, "audacious-"+string(op), rejects[len(rejects)-1].Fields["module"])
	}

	// A module that declares neither still gets a denial if it calls the syscall,
	// which is the ceiling rather than a manifest narrowing, so DenialReason is
	// empty: there is no declaration that would fix it.
	p := &auditProbe{}
	pid := loadAuditProbe(t, k, p, kernel.OpLogWrite)
	defer func() { _ = k.Unload(pid) }()

	require.Error(t, p.readErr)
	assert.True(t, kernel.IsDenied(p.readErr))
	assert.Contains(t, p.readErr.Error(), "audit:read")
	assert.Nil(t, p.entries)
	assert.Empty(t, kernel.DenialReason(p.readErr),
		"a ceiling denial has no manifest fix, so the reason must be empty")

	require.Error(t, p.appendErr)
	assert.True(t, kernel.IsDenied(p.appendErr))
	assert.NotEmpty(t, harness.Faults(buf), "both denials must be recorded on the console")

	denials := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditDenial})
	require.NotEmpty(t, denials, "both denials must reach the audit chain")
}

// TestInitCanAppendAudit covers the holder path. Init has audit:append, and the
// restriction that still applies to it is the kind restriction: the kinds that
// describe kernel decisions are refused even to a holder.
func TestInitCanAppendAudit(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	ctx := k.InitContext()

	e, err := ctx.SyscallAuditAppend(kernel.AuditRequest, "trace-init", "init note", nil)
	require.NoError(t, err)
	assert.Equal(t, kernel.AuditRequest, e.Kind)
	assert.Equal(t, "trace-init", e.Trace)
	assert.True(t, kernel.VerifyEntry(e))
	assert.Equal(t, kernel.PID(1), e.PID, "the entry is attributed to the caller and cannot be attributed elsewhere")

	// Kernel-only kinds are refused even to init, so no non-kernel context can
	// record a denial, an escalation, a rejection or a panic as fact.
	for _, kind := range []kernel.AuditKind{
		kernel.AuditBoot, kernel.AuditShutdown, kernel.AuditDenial,
		kernel.AuditEscalation, kernel.AuditReject, kernel.AuditPolicy,
		kernel.AuditPanic,
	} {
		_, err := ctx.SyscallAuditAppend(kind, "t", "forged", nil)
		require.Error(t, err, "%s must be refused to a non-kernel domain", kind)
		assert.True(t, kernel.IsDenied(err))
		assert.Contains(t, err.Error(), "reserved to the kernel")
	}

	// An unknown kind is refused rather than recorded as a generic event, so the
	// set stays queryable.
	_, err = ctx.SyscallAuditAppend(kernel.AuditKind("made:up"), "t", "x", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown audit kind")

	esc := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation})
	assert.GreaterOrEqual(t, len(esc), 7, "each refused kind must be recorded")
}

// TestAuditCheckpointAnchorsAnInvestigation covers the operator-facing use: take a
// checkpoint before a deployment so a later investigation can prove the trail was
// intact to that point.
func TestAuditCheckpointAnchorsAnInvestigation(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	defer func() { _ = k.Unload(pid) }()

	head, err := kernel.AuditCheckpoint(k.InitContext(), "pre-deploy")
	require.NoError(t, err)
	assert.Len(t, head, 64)
	assert.Equal(t, head, kernel.AuditHead(), "the checkpoint returns the new head")

	// The checkpoint itself is an audited policy event, so taking one is visible.
	policy := kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPolicy})
	require.NotEmpty(t, policy)
	found := false
	for _, e := range policy {
		if e.Msg == "audit checkpoint: pre-deploy" {
			found = true
			assert.Equal(t, head, e.Hash)
		}
	}
	assert.True(t, found)

	// A module cannot take one: it does not hold audit:append, so the syscall is
	// refused before the kind restriction is even reached.
	moduleCtx := pid2Ctx(t, k)
	_, err = moduleCtx.SyscallAuditAppend(kernel.AuditRequest, "t", "module note", nil)
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
}

// pid2Ctx loads diag and returns its context-equivalent by way of a probe, since a
// module's context is not reachable from outside OnLoad.
func pid2Ctx(t *testing.T, k *kernel.Kernel) kernel.SContext {
	t.Helper()
	var captured kernel.SContext
	kernel.Register("ctxcapture", func() (kernel.Module, error) {
		return &captureModule{into: &captured}, nil
	})
	t.Cleanup(func() { kernel.Unregister("ctxcapture") })
	pid, err := k.Load(kernel.Manifest{Name: "ctxcapture", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, captured)
	return captured
}

type captureModule struct{ into *kernel.SContext }

func (m *captureModule) OnLoad(ctx kernel.SContext) error { *m.into = ctx; return nil }
func (m *captureModule) OnUnload() error                  { return nil }

// TestRegisteredListsFactories covers the registry view an operator uses to see
// what is loadable before loading it.
func TestRegisteredListsFactories(t *testing.T) {
	before := kernel.Registered()

	kernel.Register("zeta-probe", func() (kernel.Module, error) { return &harness.NoopModule{}, nil })
	kernel.Register("alpha-probe", func() (kernel.Module, error) { return &harness.NoopModule{}, nil })
	t.Cleanup(func() {
		kernel.Unregister("zeta-probe")
		kernel.Unregister("alpha-probe")
	})

	after := kernel.Registered()
	assert.Contains(t, after, "alpha-probe")
	assert.Contains(t, after, "zeta-probe")
	assert.Len(t, after, len(before)+2)

	// Sorted, so the list is stable across runs and diffable.
	for i := 1; i < len(after); i++ {
		assert.Less(t, after[i-1], after[i])
	}

	kernel.Unregister("alpha-probe")
	assert.NotContains(t, kernel.Registered(), "alpha-probe")
	assert.Contains(t, kernel.Registered(), "zeta-probe",
		"unregistering one factory must not disturb another")
}

// TestRegisterPanicsOnSupplyChainDefects covers the three cases that must fail
// loudly at init rather than resolve silently at load time.
func TestRegisterPanicsOnSupplyChainDefects(t *testing.T) {
	f := func() (kernel.Module, error) { return &harness.NoopModule{}, nil }

	assert.PanicsWithValue(t, "kernel: Register with empty module name",
		func() { kernel.Register("", f) })

	assert.PanicsWithValue(t, "kernel: Register with nil factory for nilfactory-probe",
		func() { kernel.Register("nilfactory-probe", nil) },
		"a nil factory must fail at registration rather than at load time")

	kernel.Register("dup-probe", f)
	t.Cleanup(func() { kernel.Unregister("dup-probe") })
	assert.PanicsWithValue(t, "kernel: duplicate module registration for dup-probe",
		func() { kernel.Register("dup-probe", f) },
		"a duplicate name must panic rather than silently replace the first factory")
	assert.Len(t, kernel.Registered(), len(kernel.Registered()),
		"a refused duplicate must not have altered the registry")
}

// TestCloseResourceContainsPanics covers reclamation against a module whose Close
// panics. Reclamation runs during teardown, and teardown is exactly when a broken
// module is most likely to misbehave.
func TestCloseResourceContainsPanics(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	m := &panicCloseProbe{}
	pid := loadFDProbeNamed(t, k, m, "panicclose")
	defer func() { _ = k.Unload(pid) }()
	require.Equal(t, 2, kernel.FDCount(pid))

	// Unload must complete and must reclaim both handles even though one Close
	// panics. A panic that aborted reclamation would strand the handle opened
	// after it.
	require.NoError(t, k.Unload(pid))
	assert.Zero(t, kernel.FDCount(pid))
	assert.Equal(t, 1, m.closedCleanly, "the healthy resource was still closed")
	assert.Equal(t, 1, m.panics, "the broken resource panicked exactly once")
}

type panicCloseProbe struct {
	closedCleanly int
	panics        int
}

func (m *panicCloseProbe) OnLoad(ctx kernel.SContext) error {
	if _, err := kernel.ProbeOpenPanicHandle(ctx, "bad"); err != nil {
		return err
	}
	m.panics = 1
	// A second, healthy handle opened after the broken one. If reclamation
	// aborted at the panic, this one would be stranded.
	if _, err := kernel.ProbeOpenCountedHandle(ctx, "good", &m.closedCleanly); err != nil {
		return err
	}
	return nil
}
func (m *panicCloseProbe) OnUnload() error { return nil }

func loadFDProbeNamed(t *testing.T, k *kernel.Kernel, m kernel.Module, name string) kernel.PID {
	t.Helper()
	kernel.Register(name, func() (kernel.Module, error) { return m, nil })
	t.Cleanup(func() { kernel.Unregister(name) })
	pid, err := k.Load(kernel.Manifest{Name: name, Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1})
	require.NoError(t, err)
	return pid
}

// TestReclaimFDsReportsCloseErrors covers the non-panic failure path, so a resource
// that fails to close is reported rather than silently dropped from the table.
func TestReclaimFDsReportsCloseErrors(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	m := &errorCloseProbe{}
	pid := loadFDProbeNamed(t, k, m, "errorclose")
	require.Equal(t, 1, kernel.FDCount(pid))

	closed, errs := kernel.ProbeReclaimFDs(pid)
	assert.Equal(t, 1, closed, "the table entry is dropped either way")
	require.Len(t, errs, 1)
	assert.True(t, errors.Is(errs[0], errProbeClose))
	assert.Zero(t, kernel.FDCount(pid))
	require.NoError(t, k.Unload(pid))
}

var errProbeClose = errors.New("probe close failed")

type errorCloseProbe struct{}

func (m *errorCloseProbe) OnLoad(ctx kernel.SContext) error {
	_, err := kernel.ProbeOpenFailingHandle(ctx, "bad", errProbeClose)
	return err
}
func (m *errorCloseProbe) OnUnload() error { return nil }

// TestIdentityAccessorsAreKernelSet covers the fields a module can read about
// itself, and that none of them is chosen by the module.
func TestIdentityAccessorsAreKernelSet(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	init := k.InitContext()
	assert.Equal(t, kernel.PID(1), init.PID())
	assert.Equal(t, kernel.UID(1), init.UID())
	assert.Equal(t, kernel.DomainInit, init.Domain())
	assert.Equal(t, "init", init.Name())

	var got struct {
		pid  kernel.PID
		uid  kernel.UID
		dom  kernel.Domain
		name string
	}
	m := &captureModule2{into: &got}
	pid := loadFDProbeNamed(t, k, m, "identity")
	defer func() { _ = k.Unload(pid) }()

	assert.Equal(t, pid, got.pid)
	assert.GreaterOrEqual(t, int(got.uid), 1000, "modules get a uid from the plugin range")
	assert.Equal(t, kernel.DomainPlugin, got.dom)
	assert.Equal(t, "identity", got.name, "the name is the one the kernel spawned it under")
}

type captureModule2 struct {
	into *struct {
		pid  kernel.PID
		uid  kernel.UID
		dom  kernel.Domain
		name string
	}
}

func (m *captureModule2) OnLoad(ctx kernel.SContext) error {
	m.into.pid = ctx.PID()
	m.into.uid = ctx.UID()
	m.into.dom = ctx.Domain()
	m.into.name = ctx.Name()
	return nil
}
func (m *captureModule2) OnUnload() error { return nil }

// TestSigningKeyIsUnreachableFromTheModuleSurface is the negative assertion for
// kcrypto's precondition: the node signing key exists in the sealed trust root and
// there is no exported accessor for it.
func TestSigningKeyIsUnreachableFromTheModuleSurface(t *testing.T) {
	harness.QuietConsole(t)
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: harness.BootTrust()})
	require.NoError(t, err)
	defer func() { _ = k.Shutdown() }()

	// The value must not appear in any exported view.
	for _, e := range kernel.BootAll() {
		assert.NotEqual(t, "SECRET-KEY-MATERIAL", e.Value)
	}
	for _, e := range kernel.MetadataSnapshot() {
		assert.NotEqual(t, "SECRET-KEY-MATERIAL", e)
	}
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{}) {
		assert.NotContains(t, e.Msg, "SECRET-KEY-MATERIAL")
		for kk, v := range e.Fields {
			assert.NotContains(t, kk, "signing")
			assert.NotEqual(t, "SECRET-KEY-MATERIAL", v)
		}
	}

	var buf []byte
	require.NoError(t, kernel.Dump(&dumpWriter{into: &buf}))
	assert.NotContains(t, string(buf), "SECRET-KEY-MATERIAL",
		"the debug dump must not print key material")
}

type dumpWriter struct{ into *[]byte }

func (w *dumpWriter) Write(p []byte) (int, error) {
	*w.into = append(*w.into, p...)
	return len(p), nil
}
