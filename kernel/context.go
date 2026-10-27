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
//
// The syscall surface is composed of per-subsystem groups, each declared in the
// file that implements it. A new subsystem adds its own group interface and its
// own methods on *sContext, and lists the group here; it does not rewrite this
// file. Keeping the groups separate is what lets two subsystems be written at
// once without either touching the other's code, and it makes the syscall surface
// of any one subsystem readable in one place.
type SContext interface {
	// Identity is what a module may learn about itself.
	Identity

	SyscallClock
	SyscallMeta
	SyscallLog
	SyscallAudit
	SyscallProc
	SyscallMeter
	SyscallFD

	sealed()
}

// Identity is what a context can report about itself. Every field is set by the
// kernel at spawn time; none of it is chosen by the module.
type Identity interface {
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

// The syscall methods themselves live in the file of the subsystem they serve,
// next to the group interface they satisfy: metadata.go, console.go, audit.go,
// proc.go, usage.go, fdtable.go and clock.go. What stays here is the identity,
// the liveness gate every syscall shares, and the domain transition rule.

// syscall is the shared prologue. Every syscall begins with it, so the liveness
// and policy checks cannot be forgotten in one of them and remembered in another.
//
// op is optional: a syscall that needs no capability (reading the clock, closing
// a handle you opened) passes "", and only liveness is checked. Passing an op
// means the denial is recorded on the audit chain as well as the console.
func (c *sContext) syscall(op Op) error {
	if err := c.alive(); err != nil {
		return err
	}
	if op == "" {
		return nil
	}
	return check(c, op)
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
