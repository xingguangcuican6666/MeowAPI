package kernel

import (
	"errors"
	"sync/atomic"
)

// PID identifies a loaded unit of code within one boot. PIDs increase
// monotonically from 1 and are never reused, so an audit record always refers to
// exactly one thing that ran.
type PID int

// UID is the kernel-allocated owner id of a context. It is assigned by the
// kernel from the domain, never supplied by the caller: a module that could
// choose its own uid could choose 0.
type UID int

// Domain is the SELinux-form security domain of a context. Domains are the
// subject of every policy decision.
type Domain string

const (
	// DomainKernel is pid 0 only, and only until init has been spawned.
	DomainKernel Domain = "u:r:kernel:s0"
	// DomainInit is the boot sequence after it has dropped the root context.
	DomainInit Domain = "u:r:init:s0"
	// DomainPlugin is a validated, loaded module.
	DomainPlugin Domain = "u:r:plugin:s0"
	// DomainUntrusted holds modules that failed validation. They get nothing.
	DomainUntrusted Domain = "u:r:untrusted:s0"
)

// Reserved kernel uids.
const (
	uidKernel UID = 0
	uidInit   UID = 1
	// firstPluginUID is the base of the range handed to modules.
	firstPluginUID UID = 1000
)

// SContext is the only view of a security context that leaves package kernel,
// and the only way for a module to reach a syscall.
//
// It is sealed: the unexported sealed method means no type outside this package
// can implement it, so a module cannot forge a context and present it to a
// kernel entry point. The implementing struct is unexported and its fields are
// unreachable, so a module cannot read or mutate an identity. No kernel entry
// point takes a context as a parameter besides these methods, so there is no
// call shape in which a module acts as another.
//
// This is the Go substitute for the prototype's StackWalker caller check. Java
// needed runtime stack inspection because every class shares one classloader
// namespace; here package visibility gives a stronger guarantee at compile time.
// Do not port the stack walk as the primary control.
type SContext interface {
	// PID returns the context's process id.
	PID() PID
	// UID returns the context's kernel-allocated owner id.
	UID() UID
	// Domain returns the context's security domain.
	Domain() Domain
	// Name returns the module name this context was spawned for, or "init" and
	// "kernel" for the two kernel-owned contexts. It is a diagnostic label
	// chosen by the kernel, never by the module.
	Name() string

	// SyscallMetadataGet reads a key from the kernel metadata store.
	// Requires metadata:read. A module sees its own entries and
	// kernel-published ones, never another module's.
	SyscallMetadataGet(key string) (any, error)
	// SyscallMetadataSet writes a key to the kernel metadata store.
	// Requires metadata:write, which no module domain holds.
	SyscallMetadataSet(key string, value any) error
	// SyscallSpawn creates a child context. Requires process:fork, and the
	// target domain must be permitted by the transition rule: nothing spawns
	// into the kernel domain, and a module can only spawn modules or untrusted
	// contexts.
	SyscallSpawn(dom Domain, name string) (SContext, error)
	// SyscallLog writes to the kernel console. Requires log:write. A context
	// outside the kernel and init domains may not emit fault records, because
	// the fault stream is the kernel's own audit trail.
	SyscallLog(level Level, msg string) error
	// SyscallUsageEmit reports one usage fact. Requires usage:emit. The kernel
	// validates the kind and quantity before recording anything; an unknown kind
	// or an out-of-range quantity is refused rather than accumulated. The kernel
	// counts quantities and never prices them.
	SyscallUsageEmit(f UsageFact) error
	// SyscallClose releases a handle this context opened. Handles are per pid,
	// so a handle another module holds does not resolve here. Requires no
	// operation of its own: closing what you opened is not a capability.
	SyscallClose(fd FD) error
	// SyscallAuditRead queries the audit chain. Requires audit:read.
	SyscallAuditRead(f AuditFilter) ([]AuditEntry, error)
	// SyscallAuditAppend attaches a note to a request trace. Requires
	// audit:append, which the plugin domain does not hold by default, and
	// kernel-only kinds are refused even to a holder.
	SyscallAuditAppend(kind AuditKind, trace, msg string, fields map[string]any) (AuditEntry, error)
	// SyscallNow returns kernel time. Mono is the only value any subsystem may
	// use to measure an interval or a deadline; Wall is for records a human reads.
	// Requires no operation: every module needs a clock and a module that could
	// not read time could not implement a timeout.
	SyscallNow() KernelTime

	sealed()
}

// sContext is the kernel-private implementation of SContext.
type sContext struct {
	pid  PID
	uid  UID
	dom  Domain
	name string

	// retired marks a context that has been deliberately withdrawn. The root
	// context is retired the moment init exists, so a retained reference to it
	// is inert rather than privileged.
	retired atomic.Bool
}

// errRetired is returned by every syscall on a withdrawn context.
var errRetired = errors.New("kernel: context retired")

// newRootContext creates the pid 0 context. Only the context manager calls this,
// once per boot, and only the bootloader ever holds the result.
func newRootContext(name string) *sContext {
	return &sContext{pid: 0, uid: uidKernel, dom: DomainKernel, name: name}
}

func (c *sContext) PID() PID       { return c.pid }
func (c *sContext) UID() UID       { return c.uid }
func (c *sContext) Domain() Domain { return c.dom }
func (c *sContext) Name() string   { return c.name }
func (c *sContext) sealed()        {}

// retire withdraws the context. Idempotent.
func (c *sContext) retire() { c.retired.Store(true) }

// alive is the liveness half of every syscall's prologue. Retired is not the
// same as unauthorized: a retired context is one the kernel deliberately
// withdrew, and using it is a defect in the holder rather than a policy event,
// so it is reported as a fault and refused without a policy decision.
func (c *sContext) alive() error {
	if c.retired.Load() {
		fault(c, "syscall on retired context", nil)
		return errRetired
	}
	return nil
}

func (c *sContext) SyscallMetadataGet(key string) (any, error) {
	if err := c.alive(); err != nil {
		return nil, err
	}
	return kmeta.read(c, key)
}

func (c *sContext) SyscallMetadataSet(key string, value any) error {
	if err := c.alive(); err != nil {
		return err
	}
	return kmeta.write(c, key, value)
}

func (c *sContext) SyscallSpawn(dom Domain, name string) (SContext, error) {
	if err := c.alive(); err != nil {
		return nil, err
	}
	return kscm.spawn(c, dom, name)
}

func (c *sContext) SyscallLog(level Level, msg string) error {
	if err := c.alive(); err != nil {
		return err
	}
	if err := check(c, OpLogWrite); err != nil {
		return err
	}
	// Fault records are the kernel's own audit trail. Letting a module emit
	// them would let it forge evidence or bury a real denial in noise.
	if level == LogFault && c.dom != DomainKernel && c.dom != DomainInit {
		fault(c, "attempt to emit fault record from unprivileged domain", map[string]any{"msg": msg})
		kaudit.record(AuditEscalation, c, "denied fault-record emission", map[string]any{"msg": msg})
		return &DeniedError{Op: OpLogWrite, Ctx: c, Reason: "fault level reserved for the kernel"}
	}
	kconsole.Emit(level, c.pid, c.dom, msg, nil)
	return nil
}

func (c *sContext) SyscallUsageEmit(f UsageFact) error {
	if err := c.alive(); err != nil {
		return err
	}
	if err := check(c, OpUsageEmit); err != nil {
		return err
	}
	return emitUsage(c, f)
}

func (c *sContext) SyscallClose(fd FD) error {
	if err := c.alive(); err != nil {
		return err
	}
	return closeFD(c.pid, fd)
}

func (c *sContext) SyscallNow() KernelTime {
	return KernelTime{Mono: mono(), Wall: nowUTC()}
}

// canSpawnInto is the domain transition rule. It lives with the context rather
// than with the policy table because it constrains what a grant means: holding
// process:fork must not imply the ability to create a context more privileged
// than the holder.
//
// Domains are ordered by privilege, and a spawn may go sideways or down, never
// up. The untrusted domain is reachable from anywhere because a rejected load
// needs a place to be recorded.
func canSpawnInto(parent, child Domain) bool {
	// Nothing spawns into the kernel domain. Pid 0 is created by the context
	// manager alone, once per boot.
	if child == DomainKernel {
		return false
	}
	if child == DomainUntrusted {
		return parent == DomainKernel || parent == DomainInit || parent == DomainPlugin
	}
	switch parent {
	case DomainKernel:
		return child == DomainInit || child == DomainPlugin
	case DomainInit:
		return child == DomainPlugin
	case DomainPlugin:
		return child == DomainPlugin
	}
	return false
}
