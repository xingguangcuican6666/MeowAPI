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

package kernel

import (
	"errors"
	"sync/atomic"

	"github.com/xingguangcuican6666/MeowAPI/abi"
)

// PID identifies a loaded unit of code within one boot. PIDs increase
// monotonically from 1 and are never reused, so an audit record always refers to
// exactly one thing that ran.
// The identity types are aliases of the abi package's, not new types. That is what
// lets a module compiled against abi hold a PID the kernel accepts, without the
// module importing the kernel - and without a kernel change invalidating every
// plugin ever built against it. See abi/abi.go for why that matters.
type PID = abi.PID

// UID is the kernel-allocated owner id of a context. It is assigned by the
// kernel from the domain, never supplied by the caller: a module that could
// choose its own uid could choose 0.
type UID = abi.UID

// Domain is the SELinux-form security domain of a context. Domains are the
// subject of every policy decision.
type Domain = abi.Domain

// The domain constants are re-exported rather than redeclared. A `const X = abi.X`
// is a constant, so every switch and comparison in this package still works at
// compile time, and there is exactly one place the strings are written down.
const (
	DomainKernel    = abi.DomainKernel
	DomainInit      = abi.DomainInit
	DomainPlugin    = abi.DomainPlugin
	DomainUntrusted = abi.DomainUntrusted
)

// Reserved kernel uids.
const (
	uidKernel UID = 0
	uidInit   UID = 1
	// firstPluginUID is the base of the range handed to modules.
	firstPluginUID UID = 1000
)

// SContext is abi.SContext. The kernel keeps the alias
// so it can still write the concrete methods on its own context type.
type SContext = abi.SContext

// Identity is abi.Identity: a module passes it to or receives it from the
// kernel, so the shape lives in the package the module compiles against.
type Identity = abi.Identity

// sContext is the kernel-private implementation of SContext. The assertion is
// compile-time on purpose: a group added to abi.SContext without its methods here
// then breaks the kernel's own build, rather than a module author's.
var _ SContext = (*sContext)(nil)

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

// errForeignContext is returned when something that is not a kernel-issued context
// reaches an internal entry point. abi.SContext is an interface any type can be
// declared to satisfy, so a module CAN hand the kernel a value that passes the
// static check; what it cannot do is make that value the kernel's own *sContext.
// The assertion below is the gate, it fails closed, and it is why moving the
// interface out of this package was not a weakening.
var errForeignContext = errors.New("kernel: context was not issued by this kernel")

// contextOf resolves an SContext to the kernel's own implementation, refusing a foreign type
// and a nil pointer behind one.
//
// The nil case is the one `c, ok := ctx.(*sContext)` misses, and it is missed silently: a
// typed nil *sContext stored in an SContext satisfies that assertion with ok == true, so the
// !ok branch never runs and the first dereference of c.pid or c.name panics instead of
// refusing. Most entry points are covered anyway because their first act is c.syscall(op),
// which calls alive(), which checks for nil. The ones this exists for are the entry points
// that dereference the context FIRST - reading a data root by module name, resolving a
// socket by pid - where the panic would arrive before any gate.
//
// Use this at any new entry point rather than a bare type assertion, so the shape a future
// author copies is the safe one.
func contextOf(ctx SContext) (*sContext, error) {
	c, ok := ctx.(*sContext)
	if !ok || c == nil {
		return nil, errForeignContext
	}
	return c, nil
}

// newRootContext creates the pid 0 context. Only the context manager calls this,
// once per boot, and only the bootloader ever holds the result.
func newRootContext(name string) *sContext {
	return &sContext{pid: 0, uid: uidKernel, dom: DomainKernel, name: name}
}

func (c *sContext) PID() PID       { return c.pid }
func (c *sContext) UID() UID       { return c.uid }
func (c *sContext) Domain() Domain { return c.dom }
func (c *sContext) Name() string   { return c.name }

// retire withdraws the context. Idempotent.
func (c *sContext) retire() { c.retired.Store(true) }

// alive is the liveness half of every syscall's prologue. Retired is not the
// same as unauthorized: a retired context is one the kernel deliberately
// withdrew, and using it is a defect in the holder rather than a policy event,
// so it is reported as a fault and refused without a policy decision.
func (c *sContext) alive() error {
	// A nil receiver is refused here rather than left to panic, and the reason is a property
	// of Go that makes the obvious guard insufficient: a typed nil *sContext stored in an
	// SContext interface satisfies `c, ok := ctx.(*sContext)` with ok == true, so the !ok
	// branch every entry point uses for a foreign context never runs and the first
	// dereference below panics instead. That turns "this is not a context the kernel issued"
	// into a crash, and a crash is not distinguishable from a refusal by the party that
	// caused it. Returning errForeignContext makes the two the same answer they always
	// should have been, and covers every syscall whose prologue calls this.
	//
	// verifier.go's verifierAttribPID and verifierAttribDomain guard nil for the same reason
	// on the path that does not call alive().
	if c == nil {
		return errForeignContext
	}
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

// SyscallCrypto is abi.SyscallCrypto. The kernel keeps the alias
// so it can still write the concrete methods on its own context type.
type SyscallCrypto = abi.SyscallCrypto

func (c *sContext) SyscallCryptoRandom(n int) ([]byte, error) { return CryptoRandom(c, n) }
func (c *sContext) SyscallCryptoRandomHex(n int) (string, error) {
	return CryptoRandomHex(c, n)
}
func (c *sContext) SyscallCryptoHash(algo HashAlgo, data []byte) (string, error) {
	return CryptoHash(c, algo, data)
}
func (c *sContext) SyscallCryptoSign(msg []byte) (Signature, error) { return CryptoSign(c, msg) }
func (c *sContext) SyscallCryptoVerify(key string, msg, sig []byte) (bool, error) {
	return CryptoVerify(c, key, msg, sig)
}
func (c *sContext) SyscallCryptoVerifyCluster(msg, sig []byte) (bool, string, error) {
	return CryptoVerifyCluster(c, msg, sig)
}

// SyscallKeyring is abi.SyscallKeyring. The kernel keeps the alias
// so it can still write the concrete methods on its own context type.
type SyscallKeyring = abi.SyscallKeyring

func (c *sContext) SyscallSecretAliases() ([]string, error) { return SecretAliases(c) }
func (c *sContext) SyscallSecretUse(alias string, action SecretAction, data []byte) (SecretResult, error) {
	return SecretUse(c, alias, action, data)
}
func (c *sContext) SyscallSecretRead(alias string) ([]byte, error) { return SecretRead(c, alias) }
func (c *sContext) SyscallSecretRegister(spec SecretSpec) error {
	return SecretRegister(c, spec)
}
func (c *sContext) SyscallSecretRevoke(alias string) error { return SecretRevoke(c, alias) }

// SyscallReceipt is abi.SyscallReceipt. The kernel keeps the alias
// so it can still write the concrete methods on its own context type.
type SyscallReceipt = abi.SyscallReceipt

func (c *sContext) SyscallReceiptIssue(spec ReceiptSpec) (Receipt, error) {
	return ReceiptIssue(c, spec)
}
func (c *sContext) SyscallReceiptVerify(r Receipt) (ReceiptVerdict, error) {
	return ReceiptVerify(c, r)
}
func (c *sContext) SyscallReceiptOpen(r Receipt) (FD, ReceiptVerdict, error) {
	return ReceiptOpen(c, r)
}

// SyscallKV is abi.SyscallKV. The kernel keeps the alias
// so it can still write the concrete methods on its own context type.
type SyscallKV = abi.SyscallKV

func (c *sContext) SyscallKVGet(key string) ([]byte, error) { return KVGet(c, key) }
func (c *sContext) SyscallKVPut(key string, value []byte) error {
	return KVPut(c, key, value)
}
func (c *sContext) SyscallKVDelete(key string) error { return KVDelete(c, key) }
func (c *sContext) SyscallKVKeys() ([]string, error) { return KVKeys(c) }

// SyscallShm is abi.SyscallShm. The kernel keeps the alias
// so it can still write the concrete methods on its own context type.
type SyscallShm = abi.SyscallShm

func (c *sContext) SyscallShmAlloc(size int, label string) (ShmDescriptor, error) {
	return ShmAlloc(c, size, label)
}
func (c *sContext) SyscallShmWrite(fd FD, offset int, p []byte) (int, error) {
	return ShmWrite(c, fd, offset, p)
}
func (c *sContext) SyscallShmRead(fd FD, offset int, dst []byte) (int, error) {
	return ShmRead(c, fd, offset, dst)
}
func (c *sContext) SyscallShmBytes(fd FD) ([]byte, error) { return ShmBytes(c, fd) }
func (c *sContext) SyscallShmSize(fd FD) (int, error)     { return ShmSize(c, fd) }
func (c *sContext) SyscallShmGrant(fd FD, peer PID) error { return ShmGrant(c, fd, peer) }
func (c *sContext) SyscallShmMap(id SHMID, label string) (ShmMapping, error) {
	return ShmMap(c, id, label)
}
func (c *sContext) SyscallShmSeal(fd FD) error { return ShmSeal(c, fd) }

// The SyscallSched and SyscallSignal group interfaces are declared in sched.go and
// signal.go respectively, beside the subsystems that implement them. Only the
// methods live here, and they are one line each: the policy check and the panic
// containment are inside the subsystem, so a syscall entry point has no logic of its
// own to get wrong.

func (c *sContext) SyscallSchedSpawn(job SchedJob) (FD, error) { return SchedSpawn(c, job) }
func (c *sContext) SyscallSchedTimer(spec TimerSpec) (FD, error) {
	return SchedTimer(c, spec)
}
func (c *sContext) SyscallSchedWait(fd FD) (SchedOutcome, error) { return SchedWait(c, fd) }

func (c *sContext) SyscallSignalSend(target PID, kind SignalKind) error {
	return SignalSend(c, target, kind)
}
func (c *sContext) SyscallSignalHandle(h SignalHandler) error { return SignalHandle(c, h) }
