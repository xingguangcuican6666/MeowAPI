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

	// Every group below is declared in the file of the subsystem it serves, so a
	// new subsystem adds its own group and its own methods without rewriting this
	// file. Keeping them separate is what lets two subsystems be written at once.
	SyscallClock
	SyscallMeta
	SyscallLog
	SyscallAudit
	SyscallProc
	SyscallMeter
	SyscallFD
	SyscallBoot

	SyscallLimit
	SyscallQos
	SyscallCPU
	SyscallPipe
	SyscallShm
	SyscallKV
	SyscallCrypto
	SyscallKeyring
	SyscallReceipt
	SyscallSched
	SyscallSignal
	SyscallLock
	SyscallEvent
	SyscallTrace
	SyscallRoute
	SyscallRequest

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

// errForeignContext is returned when something that is not a kernel-issued context
// reaches an internal entry point. Because SContext is sealed, no module can
// produce one; this guards the host process and future internal callers, and it
// fails closed rather than assuming the caller is legitimate.
var errForeignContext = errors.New("kernel: context was not issued by this kernel")

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

// SyscallCrypto is the primitives half of the syscall surface. Key material does
// not cross this boundary in either direction: a module asks for a signature and
// receives the signature, never the key.
type SyscallCrypto interface {
	// SyscallCryptoRandom returns n cryptographically secure random bytes from
	// crypto/rand. Requires crypto:random.
	SyscallCryptoRandom(n int) ([]byte, error)
	// SyscallCryptoRandomHex returns n random bytes as 2n lowercase hex
	// characters, for tokens and nonces. Requires crypto:random.
	SyscallCryptoRandomHex(n int) (string, error)
	// SyscallCryptoHash digests data with a kernel-approved algorithm and returns
	// the hex digest. Requires crypto:hash.
	SyscallCryptoHash(algo HashAlgo, data []byte) (string, error)
	// SyscallCryptoSign signs msg with this node's key and returns only the
	// signature. Requires crypto:sign, which no module domain holds.
	SyscallCryptoSign(msg []byte) (Signature, error)
	// SyscallCryptoVerify checks a signature against one named verification key
	// and reports only the verdict. Requires crypto:verify.
	SyscallCryptoVerify(key string, msg, sig []byte) (bool, error)
	// SyscallCryptoVerifyCluster checks a signature against the sealed cluster
	// roots and reports the verdict with the matching key id. Requires
	// crypto:verify.
	SyscallCryptoVerifyCluster(msg, sig []byte) (bool, string, error)
}

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

// SyscallKeyring is the secret-custody half of the syscall surface. No method here
// hands a plaintext credential to a module: the module names an alias and an action,
// the kernel applies the secret and returns the result.
type SyscallKeyring interface {
	// SyscallSecretAliases lists the aliases visible to this context, narrowed to
	// the secret prefixes the manifest declared. Requires secret:use.
	SyscallSecretAliases() ([]string, error)
	// SyscallSecretUse applies a custodied secret on this context's behalf and
	// returns only the result. Requires secret:use, scoped by prefix.
	SyscallSecretUse(alias string, action SecretAction, data []byte) (SecretResult, error)
	// SyscallSecretRead returns a plaintext credential. Requires secret:read,
	// which no module domain holds.
	SyscallSecretRead(alias string) ([]byte, error)
	// SyscallSecretRegister takes custody of a credential. Requires secret:read.
	SyscallSecretRegister(spec SecretSpec) error
	// SyscallSecretRevoke destroys a custodied credential. Requires secret:read.
	SyscallSecretRevoke(alias string) error
}

func (c *sContext) SyscallSecretAliases() ([]string, error) { return SecretAliases(c) }
func (c *sContext) SyscallSecretUse(alias string, action SecretAction, data []byte) (SecretResult, error) {
	return SecretUse(c, alias, action, data)
}
func (c *sContext) SyscallSecretRead(alias string) ([]byte, error) { return SecretRead(c, alias) }
func (c *sContext) SyscallSecretRegister(spec SecretSpec) error {
	return SecretRegister(c, spec)
}
func (c *sContext) SyscallSecretRevoke(alias string) error { return SecretRevoke(c, alias) }

// SyscallReceipt is the settlement half of the syscall surface. A module may verify
// any receipt and take custody of one; only a context holding receipt:issue may mint
// one, and no module domain does.
type SyscallReceipt interface {
	// SyscallReceiptIssue mints and signs one settlement receipt. Requires
	// receipt:issue, which is held by the kernel domain alone.
	SyscallReceiptIssue(spec ReceiptSpec) (Receipt, error)
	// SyscallReceiptVerify recomputes a receipt's canonical encoding and checks
	// its signature against the sealed cluster roots. Requires receipt:verify.
	SyscallReceiptVerify(r Receipt) (ReceiptVerdict, error)
	// SyscallReceiptOpen verifies a receipt and returns a per-pid handle to the
	// verdict. Requires receipt:verify.
	SyscallReceiptOpen(r Receipt) (FD, ReceiptVerdict, error)
}

func (c *sContext) SyscallReceiptIssue(spec ReceiptSpec) (Receipt, error) {
	return ReceiptIssue(c, spec)
}
func (c *sContext) SyscallReceiptVerify(r Receipt) (ReceiptVerdict, error) {
	return ReceiptVerify(c, r)
}
func (c *sContext) SyscallReceiptOpen(r Receipt) (FD, ReceiptVerdict, error) {
	return ReceiptOpen(c, r)
}

// SyscallKV is the namespaced-state half of the syscall surface. Keys are scoped by
// owner pid, so one module cannot read or write another's state.
type SyscallKV interface {
	// SyscallKVGet reads one value from this module's namespace. Requires
	// kv:read. The returned slice is a copy the caller owns.
	SyscallKVGet(key string) ([]byte, error)
	// SyscallKVPut stores one value in this module's namespace. Requires
	// kv:write. The value is copied in, and a write over the per-module ceiling
	// is refused with a *KVQuotaError.
	SyscallKVPut(key string, value []byte) error
	// SyscallKVDelete removes one key. Requires kv:write.
	SyscallKVDelete(key string) error
	// SyscallKVKeys lists this module's own keys, sorted. Requires kv:read.
	SyscallKVKeys() ([]string, error)
}

func (c *sContext) SyscallKVGet(key string) ([]byte, error) { return KVGet(c, key) }
func (c *sContext) SyscallKVPut(key string, value []byte) error {
	return KVPut(c, key, value)
}
func (c *sContext) SyscallKVDelete(key string) error { return KVDelete(c, key) }
func (c *sContext) SyscallKVKeys() ([]string, error) { return KVKeys(c) }

// SyscallShm is the shared-buffer half of the syscall surface. The kernel owns the
// bytes and never hands out the underlying slice on either side, so there is no call
// shape in which a reader obtains a writable alias into a prompt in flight.
type SyscallShm interface {
	// SyscallShmAlloc allocates a shared buffer and returns a descriptor for it.
	// Requires shm:alloc. The payload is written through SyscallShmWrite and
	// never handed back as a slice.
	SyscallShmAlloc(size int, label string) (ShmDescriptor, error)
	// SyscallShmWrite copies bytes into a segment this context owns. Requires
	// shm:alloc, and refuses a sealed segment.
	SyscallShmWrite(fd FD, offset int, p []byte) (int, error)
	// SyscallShmRead copies bytes out of a segment this context owns or was
	// granted. Requires shm:map.
	SyscallShmRead(fd FD, offset int, dst []byte) (int, error)
	// SyscallShmBytes returns a fresh copy of a segment's whole payload. Requires
	// shm:map.
	SyscallShmBytes(fd FD) ([]byte, error)
	// SyscallShmSize reports a segment's payload size. Requires shm:map.
	SyscallShmSize(fd FD) (int, error)
	// SyscallShmGrant authorises one peer to map a segment, and seals it. Requires
	// shm:alloc.
	SyscallShmGrant(fd FD, peer PID) error
	// SyscallShmMap maps a granted segment read-only. Requires shm:map and a grant
	// from the owner.
	SyscallShmMap(id SHMID, label string) (ShmMapping, error)
	// SyscallShmSeal makes this context's own segment immutable without granting
	// it. Requires shm:alloc.
	SyscallShmSeal(fd FD) error
}

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
