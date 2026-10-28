package kernel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// kfs: the fs syscall surface for kvfs (subsystem: kfs).
//
// What it is for. kv.go already owns the security-relevant half of the filesystem:
// FSResolve refuses every lexical and symlink escape from a data root, FSPathAllowed
// matches the manifest's declared paths by segment, and FSCheckRead and FSCheckWrite
// compose them behind the policy gate. Those functions are complete and tested, and
// kv.go's own header says why the resolver must not be written twice: path escape is
// the whole risk of a per-module data root, and a second implementation is a second
// chance to get it wrong.
//
// What was missing is everything above them: no syscall read a file, wrote one,
// listed a directory, or removed one, so a module that needed a file had no
// sanctioned path at all. This file is that surface. Every operation routes through
// FSCheckRead or FSCheckWrite, so the containment and boundary decisions are the
// ones already reviewed rather than new ones.
//
// The data root comes from the host and is sealed at first use. A module cannot name
// its own root, because then it could name someone else's; the host is the only party
// that knows where a deployment puts module data, which is why the setter takes a
// pid and the resolver looks the root up per module. Roots are one directory per
// module identity under the host's template, so two modules never share a directory
// and isolation is structural - the other module's files are simply not inside this
// module's root - rather than a string comparison a crafted path could fool.
//
// This is not a sandbox. An in-process Go module can call os.ReadFile directly and
// nothing here stops it; what this file provides is the sanctioned path: contained,
// bounded, audited, and reclaimed on unload. A module that goes around it does so
// with the standard library and leaves the audit chain without an fs record, which
// is itself evidence.

// ErrFSReadTooLarge is what a read over the ceiling looks like. It is a sentinel
// rather than a message to match because it is the one refusal a caller should act
// on differently: it means the data is there and the bound is the kernel's, so
// retrying is pointless and streaming or a smaller read is the answer.
var ErrFSReadTooLarge = errors.New("kernel: fs: read exceeds the size ceiling")

// fsError reports a refusal from this file's own surface. It is a distinct type for
// the same reason kv.go's KVError is: "your read exceeds the size ceiling" is a
// module defect, and a caller should not have to string-match to learn that.
type fsError struct {
	Msg string
	Err error
}

func (e *fsError) Error() string {
	if e.Err != nil {
		return "kernel: fs: " + e.Msg + ": " + e.Err.Error()
	}
	return "kernel: fs: " + e.Msg
}

func (e *fsError) Unwrap() error { return e.Err }

func fsErr(format string, args ...any) error {
	return &fsError{Msg: fmt.Sprintf(format, args...)}
}

// The size ceiling for a single read. It comes from a documented constant rather
// than the caller, because the caller is the module: an unbounded read of a file the
// module itself wrote is still a way to exhaust kernel memory, and a bound a module
// could supply is not a bound.
const fsMaxReadBytes = 1 << 20

// fsState holds the data roots, keyed by module name because a name is what the host
// names a root for and what survives a restart.
type fsState struct {
	mu    sync.RWMutex
	roots map[string]string
}

var kfs = fsState{roots: map[string]string{}}

// fsModuleIsLive reports whether a module of that name is loaded right now. It takes
// modulesMu and releases it before returning, and callers must not hold kfs.mu
// across it: every other path takes those two locks one at a time, and nesting them
// here would fix a lock order across two subsystems for no benefit.
func fsModuleIsLive(module string) bool {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	_, live := byName[module]
	return live
}

// FSSetDataRoot installs the data root for one module name. It belongs to the host:
// it takes a name rather than a pid because a root is a deployment decision that
// outlives any single boot, and it must be called before the module loads so the
// module's first fs call already resolves against the root it will run under.
//
// The root is resolved and symlink-evaluated immediately rather than at use time,
// so a directory swapped for a link after installation cannot redirect a contained
// path: FSResolve compares against the root as it was sealed.
func FSSetDataRoot(module, root string) error {
	if module == "" {
		return fsErr("a data root is installed for a module name, which is empty")
	}
	if root == "" {
		return fsErr("the data root for %q is empty", module)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return fsErr("the data root for %q is not resolvable: %v", module, err)
	}
	if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
		abs = resolved
	}
	// Refused while the module is live, and the reason is not distrust of the host.
	// A root in use is part of what makes containment mean something: paths already
	// resolved against it are on the audit chain, and a swapped root would make those
	// records describe a directory that is no longer the one that was checked.
	//
	// Liveness rather than a one-shot latch is the right test for two reasons. It
	// permits the host to re-point a stopped module's root after a crash, which a
	// latch would forbid forever, and it needs no host call at a moment only the host
	// knows - after the last module of a boot has loaded - which a latch would.
	if fsModuleIsLive(module) {
		return fsErr("the data root for %q cannot change while that module is loaded", module)
	}
	kfs.mu.Lock()
	defer kfs.mu.Unlock()
	kfs.roots[module] = abs
	return nil
}

// The liveness check above runs before kfs.mu is taken rather than inside it, so a
// module can be loaded between the two. That window is deliberate: closing it would
// mean holding kfs.mu across modulesMu and fixing a lock order between this file and
// module.go for no benefit, and the window fails closed. A module that starts inside
// it and reaches for a file before the root lands gets "no data root is configured",
// which is a refusal rather than a fallback to somewhere else.

// resetFS clears the roots for a fresh boot. It runs alongside resetFSScopes in
// resetKernel, and the relationship is deliberate: resetFSScopes clears what each
// pid may touch inside its root, resetFS clears where the roots themselves are.
// Both must be empty before a new boot installs its own.
func resetFS() {
	kfs.mu.Lock()
	defer kfs.mu.Unlock()
	kfs.roots = map[string]string{}
}

// fsRootFor returns the module's data root, or a typed error when none was
// installed. Refusing is the only honest option: a fallback to the process working
// directory would put module data wherever the operator happened to launch the
// binary from, and silence about it would make that look like a decision.
func fsRootFor(c *sContext) (string, error) {
	kfs.mu.RLock()
	defer kfs.mu.RUnlock()
	root, ok := kfs.roots[c.name]
	if !ok {
		return "", fsErr("no data root is configured for module %q", c.name)
	}
	return root, nil
}

// FSReadFile reads one file inside this module's data root and declared boundary.
// Requires fs:read. The returned slice is a fresh allocation the caller owns; no
// kernel state retains a reference to it, which is the same guarantee kpipe makes
// and for the same reason.
func FSReadFile(ctx SContext, rel string) ([]byte, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	root, err := fsRootFor(c)
	if err != nil {
		fault(c, "fs read refused: no data root", map[string]any{"module": c.name, "path": rel})
		return nil, err
	}
	abs, err := FSCheckRead(c, root, rel)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		// A path that resolves but does not exist reads as absent rather than as a
		// containment failure, because it already passed both checks. The audit
		// record is the read attempt, not the absence.
		fsAudit(c, OpFSRead, rel, "miss")
		return nil, fsErr("read of %q failed: %v", rel, err)
	}
	if st.IsDir() {
		fsAudit(c, OpFSRead, rel, "refused: directory")
		return nil, fsErr("%q is a directory, not a file", rel)
	}
	if st.Size() > fsMaxReadBytes {
		fault(c, "fs read refused by size ceiling", map[string]any{
			"module": c.name, "path": rel, "size": st.Size(), "ceiling": fsMaxReadBytes,
		})
		fsAudit(c, OpFSRead, rel, "refused: over ceiling")
		return nil, &fsError{
			Msg: fmt.Sprintf("read of %q is %d bytes, over the ceiling %d", rel, st.Size(), fsMaxReadBytes),
			Err: ErrFSReadTooLarge,
		}
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		fsAudit(c, OpFSRead, rel, "failed")
		return nil, fsErr("read of %q failed: %v", rel, err)
	}
	fsAudit(c, OpFSRead, rel, "ok")
	return data, nil
}

// FSWriteFile writes one file atomically. Requires fs:write.
//
// Atomic means atomic-or-nothing, not best-effort: the data goes to a temporary
// name in the same directory and is renamed onto the target, so a crash mid-write
// leaves either the old file or the new one, never a truncated file the module
// believes is complete. The temporary name is derived from the resolved path, which
// means it is inside the data root and inside the declared boundary already -
// writing outside the boundary and renaming in would be an escape, and deriving
// rather than accepting a name is what closes it.
func FSWriteFile(ctx SContext, rel string, data []byte) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	root, err := fsRootFor(c)
	if err != nil {
		fault(c, "fs write refused: no data root", map[string]any{"module": c.name, "path": rel})
		return err
	}
	abs, err := FSCheckWrite(c, root, rel)
	if err != nil {
		return err
	}
	if st, serr := os.Stat(abs); serr == nil && st.IsDir() {
		fsAudit(c, OpFSWrite, rel, "refused: directory")
		return fsErr("%q is a directory, not a file", rel)
	}

	// There is a window between the resolve above and the write below, and it is
	// worth being explicit about why it is not closed. If a component of this path
	// was missing, FSResolve returned the lexical join, so a symlink created in that
	// window would be followed by the write. Nothing here prevents that, and the
	// reason is that nothing needs to: a module can already call os.Symlink and
	// os.WriteFile itself, because this is a mandatory access control kernel and not
	// a sandbox, so a symlink race here grants no capability the module lacks.
	// Re-resolving after the mkdir would cost a path walk on every nested write to
	// defend against an attack the module can perform directly in one call.
	//
	// Missing parent directories are created here rather than refused. This surface
	// has no mkdir, so a module that could not have its parents created could never
	// write to a nested path at all, and "organize your data in subdirectories" is a
	// normal thing for a module to do. Creating them is safe because abs came from
	// FSCheckWrite, so it is already inside the data root and inside the declared
	// write boundary; the parents of a contained path are contained. The alternative
	// - refusing - would push a module toward whatever directory it can reach
	// without creating one.
	if dir := filepath.Dir(abs); dir != abs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fsAudit(c, OpFSWrite, rel, "failed")
			return fsErr("write of %q failed: cannot create its directory: %v", rel, err)
		}
	}

	// The temporary name lives in the same directory so the rename is a same-
	// filesystem move, which is atomic. It is derived from the resolved path rather
	// than accepted from the caller, so it cannot be aimed outside the boundary:
	// writing a temporary file somewhere else and renaming it in is an escape, and
	// deriving the name is what closes it. It never appears on the audit chain
	// because it is an implementation detail of this one write, not a file.
	tmp := abs + ".kfs-tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		os.Remove(tmp)
		fsAudit(c, OpFSWrite, rel, "failed")
		return fsErr("write of %q failed: %v", rel, err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		os.Remove(tmp)
		fsAudit(c, OpFSWrite, rel, "failed")
		return fsErr("write of %q failed: %v", rel, err)
	}
	fsAudit(c, OpFSWrite, rel, "ok")
	return nil
}

// FSList lists a directory inside this module's data root and declared boundary.
// Requires fs:read, because a listing is a read of the directory's names. The
// result is sorted and a copy; names outside the boundary are not reachable by
// construction, since only contained paths can be listed at all.
func FSList(ctx SContext, rel string) ([]string, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	root, err := fsRootFor(c)
	if err != nil {
		return nil, err
	}
	abs, err := FSCheckRead(c, root, rel)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		fsAudit(c, OpFSRead, rel, "failed")
		return nil, fsErr("list of %q failed: %v", rel, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	fsAudit(c, OpFSRead, rel, "list")
	return out, nil
}

// FSStat reports one entry's size and directory flag. Requires fs:read.
func FSStat(ctx SContext, rel string) (FSInfo, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return FSInfo{}, errForeignContext
	}
	root, err := fsRootFor(c)
	if err != nil {
		return FSInfo{}, err
	}
	abs, err := FSCheckRead(c, root, rel)
	if err != nil {
		return FSInfo{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		fsAudit(c, OpFSRead, rel, "miss")
		return FSInfo{}, fsErr("stat of %q failed: %v", rel, err)
	}
	fsAudit(c, OpFSRead, rel, "stat")
	return FSInfo{Size: st.Size(), IsDir: st.IsDir()}, nil
}

// FSInfo is what FSStat reports: the two facts a module needs and no more. It
// deliberately omits timestamps and permissions, which a module has no use for and
// which would render host-side details the boundary was meant to keep out.
type FSInfo struct {
	Size  int64 `json:"size"`
	IsDir bool  `json:"is_dir"`
}

// FSDelete removes one file. Requires fs:write, because removal is a mutation of
// the module's data area. A missing file is a typed, checkable "already gone"
// rather than a retry loop.
func FSDelete(ctx SContext, rel string) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	root, err := fsRootFor(c)
	if err != nil {
		return err
	}
	abs, err := FSCheckWrite(c, root, rel)
	if err != nil {
		return err
	}
	if err := os.Remove(abs); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fsAudit(c, OpFSWrite, rel, "delete: absent")
			return fsErr("%q is already gone", rel)
		}
		if isDirRemovalError(err) {
			// A directory holds other files whose containment was never individually
			// checked, so removing one is refused rather than recursed: a recursive
			// delete would need to verify every contained path against the boundary,
			// and refusing is the honest single-step answer.
			fsAudit(c, OpFSWrite, rel, "refused: directory")
			return fsErr("%q is a directory; deletion of directories is not supported", rel)
		}
		fsAudit(c, OpFSWrite, rel, "delete: failed")
		return fsErr("delete of %q failed: %v", rel, err)
	}
	fsAudit(c, OpFSWrite, rel, "deleted")
	return nil
}

// fsAudit records one fs operation on the chain. Writes and refusals always land;
// successful reads land too, because the alternative is that an exfiltration
// through this surface is invisible, and one record per read from a bounded module
// set is a volume the 8192-entry window is built to hold.
func fsAudit(c *sContext, op Op, rel, outcome string) {
	kaudit.record(AuditRequest, c, "fs operation", map[string]any{
		"module": c.name, "op": string(op), "path": rel, "outcome": outcome,
	})
}

// isDirRemovalError reports whether os.Remove refused because the target is a
// non-empty directory. Checked with a message probe rather than a syscall errno
// because the kernel builds for every GOOS and the errno differs; the probe runs
// only on the error path where the alternative is already a refusal.
func isDirRemovalError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// "directory not empty" appears on linux and darwin; ENOTDIR-shaped messages
	// mean something else and must not match.
	return strings.Contains(msg, "directory not empty") || strings.Contains(msg, "is a directory")
}

// SyscallFS is the module-facing half of this surface. Wiring it needs two lines:
// SyscallFS in the SContext composition in context.go, and resetFS() in resetKernel()
// next to resetFSScopes(). Until then the exported package-level functions above are
// the surface, and they are what the tests call.
type SyscallFS interface {
	// SyscallFSRead reads one file. Requires fs:read, a configured data root, and a
	// path inside the manifest's ReadPaths.
	SyscallFSRead(rel string) ([]byte, error)
	// SyscallFSWrite writes one file atomically. Requires fs:write and a path
	// inside the manifest's WritePaths.
	SyscallFSWrite(rel string, data []byte) error
	// SyscallFSList lists a directory, sorted. Requires fs:read.
	SyscallFSList(rel string) ([]string, error)
	// SyscallFSStat reports size and directory flag. Requires fs:read.
	SyscallFSStat(rel string) (FSInfo, error)
	// SyscallFSDelete removes one file. Requires fs:write.
	SyscallFSDelete(rel string) error
}

func (c *sContext) SyscallFSRead(rel string) ([]byte, error) {
	return FSReadFile(c, rel)
}

func (c *sContext) SyscallFSWrite(rel string, data []byte) error {
	return FSWriteFile(c, rel, data)
}

func (c *sContext) SyscallFSList(rel string) ([]string, error) {
	return FSList(c, rel)
}

func (c *sContext) SyscallFSStat(rel string) (FSInfo, error) {
	return FSStat(c, rel)
}

func (c *sContext) SyscallFSDelete(rel string) error {
	return FSDelete(c, rel)
}
