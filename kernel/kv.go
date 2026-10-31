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

// kvfs: namespaced per-module state, and the bounded file access that lives
// under each module's data root.
//
// RESET: resetKVFS() and resetFSScopes() must be added to resetKernel() in
// kernel/kernel.go.
//
// UNLOAD: UnloadModule must call KVDropNamespace(pid) and ClearFSScope(pid).
//
// WIRING: the syscall entry points are plain functions here. The group interface
// and the *sContext methods that belong in kernel/context.go are in a comment
// block at the bottom of this file.
//
// What this subsystem is. Two stores, one guarantee each:
//
//   - The KV store is per-module namespaced state. A module keeps its own state
//     between calls without inventing a place to put it, and without seeing
//     anyone else's. The analogue is a private configuration namespace, not a
//     shared one.
//   - The file store is a read/write path under a chroot. Each module gets a data
//     root, its manifest names the relative paths inside it, and every access
//     resolves against that root and is refused if it would leave.
//
// What it is not. This is mandatory access control over what a module may ask the
// kernel to do. It is not an address-space sandbox: a module that calls os.Open
// itself never comes through the kernel, so nothing here stops it. That is a
// review and signing concern, and describing it as containment would describe a
// boundary that does not exist.
//
// One deliberate divergence from metadata.go. Metadata entries survive the unload
// of the pid that wrote them, which leaks memory for every module loaded and
// unloaded in a loop. kvfs drops the namespace on unload instead. The store is
// in-memory only, so there is no durability to preserve, and a pid is never
// reused, which means the surviving state is unreachable garbage that nothing
// will ever free.
package kernel

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// KVError reports a malformed kvfs request. It is a distinct type so a caller can
// tell "your request is unusable" from "the kernel broke", which matters because
// the first is the module author's defect and the second is not theirs.
type KVError struct{ Msg string }

// Error renders the refusal with the kvfs prefix, so an operator reading a log line
// can see which subsystem refused without opening the code.
func (e *KVError) Error() string { return "kernel: kvfs: " + e.Msg }

// ErrKVNotFound is returned by a read or delete of a key that does not exist. It
// is distinct from a denial, which IsDenied reports, and from an empty value,
// which is a legitimate thing for a module to have stored. A caller that cannot
// tell "absent" from "stored as empty" cannot implement a cache.
var ErrKVNotFound = errors.New("kernel: kvfs: key not found")

// KVQuotaError is the typed ceiling error, so a module can recognise "over the
// limit" and shed load rather than string-match a message that may be reworded.
type KVQuotaError struct {
	// Owner is the module whose namespace ran out.
	Owner PID `json:"owner"`
	// Limit is the per-module ceiling from the sealed trust root.
	Limit int64 `json:"limit"`
	// WouldBe is the owner's accounted total had the write been applied.
	WouldBe int64 `json:"would_be"`
}

// Error renders the ceiling that was hit and the total that would have exceeded it,
// because those two numbers are what tells a module author whether to shrink the
// value or to ask for a larger limit.
func (e *KVQuotaError) Error() string {
	return fmt.Sprintf("kernel: kvfs: pid %d would hold %d bytes, over the ceiling of %d",
		e.Owner, e.WouldBe, e.Limit)
}

// kvKey scopes a kvfs entry to its owner, exactly as metadataKey does. One module
// cannot read or write another's state, and that is a property of the key rather
// than of a check that could be remembered on one call path and forgotten on
// another.
type kvKey struct {
	owner PID
	key   string
}

// kvEntry is one stored value plus the byte cost it is accounted at.
type kvEntry struct {
	value []byte
	cost  int64
}

// kvStore is the namespaced state store. It owns its lock rather than sharing the
// metadata store's, because a module reading its own state must not serialize
// behind a kernel-published metadata read.
type kvStore struct {
	mu      sync.RWMutex
	entries map[kvKey]*kvEntry
	// bytes is the accounted total per owner, kept beside the map so a write can
	// check its ceiling without walking the owner's whole namespace.
	bytes map[PID]int64
}

var kvfs = &kvStore{entries: map[kvKey]*kvEntry{}, bytes: map[PID]int64{}}

// maxKVKeyLen bounds a key. A key is attacker-chosen text that the kernel stores
// and renders into fault records, so it is bounded rather than trusted, and the
// bound is charged to the owner like a value is.
const maxKVKeyLen = 512

// kvCost is what one entry costs against its owner's ceiling. Both halves of the
// key and the value are charged, because a module that cannot grow a value could
// otherwise grow an unbounded number of long keys.
//
// Cost is measured rather than counted. A module storing one 8 MiB value and a
// module storing eight thousand 1 KiB values must hit the same ceiling; counting
// entries would let the first through while refusing the second.
func kvCost(key string, value []byte) int64 {
	return int64(len(key)) + int64(len(value))
}

// KVPut stores a value in the calling module's namespace. Requires kv:write.
//
// The value is copied in. Storing the caller's slice would let the module mutate
// kernel state by writing to a buffer it still holds, which is the same escape a
// read-only shared buffer closes from the other side: the guarantee holds only if
// the kernel owns the bytes.
//
// A write that would push the owner over Limits().MaxKVBytesPerModule is refused
// with a *KVQuotaError and leaves the store untouched. Refusing rather than
// truncating or evicting is deliberate: silent eviction would make a module's
// state disappear under it, and an invisible loss is worse than a visible error
// the module can handle.
func KVPut(ctx SContext, key string, value []byte) error {
	c, err := kvfsContext(ctx, OpKVWrite)
	if err != nil {
		return err
	}
	if err := kvValidKey(key); err != nil {
		return err
	}
	// The filter decides which well-formed keys this instance may use, so it runs after
	// the shape check. Filtering first would put a filter refusal on the audit chain for a
	// key that was going to be rejected as malformed anyway, and a misleading entry is
	// worse than no entry.
	if err := SeccompAllow(c, OpKVWrite, key); err != nil {
		return err
	}

	cost := kvCost(key, value)
	limit := Limits().MaxKVBytesPerModule

	k := kvKey{owner: c.pid, key: key}

	kvfs.mu.Lock()
	defer kvfs.mu.Unlock()

	total := kvfs.bytes[c.pid]
	if prev, ok := kvfs.entries[k]; ok {
		total -= prev.cost
	}
	if total+cost > limit {
		return kvRefuseQuota(c, &KVQuotaError{Owner: c.pid, Limit: limit, WouldBe: total + cost})
	}

	stored := make([]byte, len(value))
	copy(stored, value)
	kvfs.entries[k] = &kvEntry{value: stored, cost: cost}
	kvfs.bytes[c.pid] = total + cost
	return nil
}

// KVGet reads a value from the calling module's namespace. Requires kv:read.
//
// The value is copied out, so a module never holds a slice the kernel also holds.
// Returning the stored slice would let a module rewrite its own recorded state
// without a kv:write grant, and would make the byte accounting describe bytes
// that are no longer what is stored.
func KVGet(ctx SContext, key string) ([]byte, error) {
	c, err := kvfsContext(ctx, OpKVRead)
	if err != nil {
		return nil, err
	}
	if err := SeccompAllow(c, OpKVRead, key); err != nil {
		return nil, err
	}

	kvfs.mu.RLock()
	defer kvfs.mu.RUnlock()

	e, ok := kvfs.entries[kvKey{owner: c.pid, key: key}]
	if !ok {
		return nil, fmt.Errorf("%w: %q for pid %d", ErrKVNotFound, key, c.pid)
	}
	out := make([]byte, len(e.value))
	copy(out, e.value)
	return out, nil
}

// KVDelete removes one key and returns its accounting to the ceiling. Requires
// kv:write, because releasing space is a write to the namespace even though it
// stores nothing.
func KVDelete(ctx SContext, key string) error {
	c, err := kvfsContext(ctx, OpKVWrite)
	if err != nil {
		return err
	}
	// The filter is consulted on the key as given. KVDelete does not re-validate the key's
	// shape, and did not before this change: a malformed key can never have been stored, so
	// it resolves to not-found on its own, and adding a validation here would change the
	// error a caller sees for a reason this work has nothing to do with.
	if err := SeccompAllow(c, OpKVWrite, key); err != nil {
		return err
	}

	k := kvKey{owner: c.pid, key: key}

	kvfs.mu.Lock()
	defer kvfs.mu.Unlock()

	e, ok := kvfs.entries[k]
	if !ok {
		return fmt.Errorf("%w: %q for pid %d", ErrKVNotFound, key, c.pid)
	}
	delete(kvfs.entries, k)
	kvfs.bytes[c.pid] -= e.cost
	if kvfs.bytes[c.pid] <= 0 {
		delete(kvfs.bytes, c.pid)
	}
	return nil
}

// KVKeys lists the calling module's own keys, sorted. Requires kv:read. It never
// names another module's key, so a module cannot learn which namespaces exist.
func KVKeys(ctx SContext) ([]string, error) {
	c, err := kvfsContext(ctx, OpKVRead)
	if err != nil {
		return nil, err
	}

	kvfs.mu.RLock()
	defer kvfs.mu.RUnlock()

	out := make([]string, 0, 8)
	for k := range kvfs.entries {
		if k.owner == c.pid {
			out = append(out, k.key)
		}
	}
	slices.Sort(out)
	return out, nil
}

// KVBytes reports what one module's namespace costs against its ceiling. It takes
// a pid rather than a context because it is a diagnostic read of kernel state for
// the console dump and for tests, not a syscall, and it reports only a number: no
// value is reachable through it.
func KVBytes(pid PID) int64 {
	kvfs.mu.RLock()
	defer kvfs.mu.RUnlock()
	return kvfs.bytes[pid]
}

// KVCount reports how many keys one module holds. It is the entry count beside
// KVBytes' byte count, and the pair is what makes a quota test exact: bytes alone
// cannot distinguish one large value from many small ones, which is the difference
// the ceiling is meant to be indifferent to.
func KVCount(pid PID) int {
	kvfs.mu.RLock()
	defer kvfs.mu.RUnlock()
	n := 0
	for k := range kvfs.entries {
		if k.owner == pid {
			n++
		}
	}
	return n
}

// KVDropNamespace removes everything one module stored and returns its
// accounting. Called on unload, so a module replaced by a fresh load of the same
// name does not inherit the previous instance's state, and so a module cannot
// grow kernel memory by loading and unloading in a loop.
func KVDropNamespace(pid PID) {
	kvfs.mu.Lock()
	defer kvfs.mu.Unlock()
	for k := range kvfs.entries {
		if k.owner == pid {
			delete(kvfs.entries, k)
		}
	}
	delete(kvfs.bytes, pid)
}

// kvfsContext is the shared prologue for every entry point in this file: assert
// the context is kernel-issued, run the liveness gate, then the policy gate. One
// prologue means the checks cannot be applied to some syscalls and not others.
func kvfsContext(ctx SContext, op Op) (*sContext, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if err := c.alive(); err != nil {
		return nil, err
	}
	if err := check(c, op); err != nil {
		return nil, err
	}
	return c, nil
}

// kvValidKey refuses the key forms that would make the namespace ambiguous. An
// empty key is indistinguishable from a failed lookup in a caller's log, an
// over-long key is unbounded attacker-chosen text the kernel would store and
// render, and a NUL is not a usable key character anywhere.
func kvValidKey(key string) error {
	if key == "" {
		return &KVError{Msg: "empty key"}
	}
	if len(key) > maxKVKeyLen {
		return &KVError{Msg: fmt.Sprintf("key longer than %d bytes", maxKVKeyLen)}
	}
	if strings.IndexByte(key, 0) >= 0 {
		return &KVError{Msg: "key contains a NUL byte"}
	}
	return nil
}

// kvRefuseQuota emits the fault alongside the typed error. Hitting a ceiling is an
// operational event rather than a policy denial, so it lands on the console as a
// fault and not as an avc line: nothing was refused for want of a grant.
func kvRefuseQuota(c *sContext, err *KVQuotaError) error {
	fault(c, "kvfs write refused by quota", map[string]any{
		"module": c.name, "limit": err.Limit, "would_be": err.WouldBe,
	})
	return err
}

// resetKVFS clears the namespaced state for a fresh boot. Called only from
// resetKernel, so a restarted kernel does not inherit the previous boot's module
// state under pids that no longer exist.
func resetKVFS() {
	kvfs.mu.Lock()
	defer kvfs.mu.Unlock()
	kvfs.entries = map[kvKey]*kvEntry{}
	kvfs.bytes = map[PID]int64{}
}

// ---------------------------------------------------------------------------
// Bounded file access under a per-module data root.
//
// WIRED TO NOTHING. There is no fs syscall group yet: OpFSRead and OpFSWrite are
// declared in policy.go and are scoped operations whose boundary is the manifest's
// ReadPaths and WritePaths, but no syscall calls them. What follows is the
// resolver and the checks, complete and tested, so that whoever adds the fs
// syscall gets the security-relevant half already written. The resolver is the
// part that must not be written twice: path escape is the whole risk of a
// per-module data root, and a second implementation is a second chance to get it
// wrong.
//
// The data root is not chosen here. It comes from the host process, which is the
// only party that knows where a deployment puts module data. A module must not be
// able to name its own root, because then it could name someone else's.
// ---------------------------------------------------------------------------

// FSPathError reports a path the resolver refused. It is a distinct type for the
// same reason KVError is: "your path escapes the data root" is a module defect,
// and a caller should not have to string-match to learn that.
type FSPathError struct{ Msg string }

// Error renders the refusal with the fs prefix.
func (e *FSPathError) Error() string { return "kernel: fs: " + e.Msg }

// FSResolve turns a module-supplied path into an absolute path inside root, or
// refuses. It is the containment check, and it is deliberately biased toward
// refusing: every form of escape it can see is an error rather than a cleaned-up
// path, because a cleaned-up path is one the caller did not ask for and did not
// review.
//
// Three escapes are refused:
//
//   - Lexical: an absolute path, a volume path, or a ".." segment. Checked before
//     any filesystem access, so a malformed path costs nothing.
//   - Symlink: any component of the path that is a link resolving outside the
//     root. Each component is examined, so the check covers a linked directory in
//     the middle of the path and a dangling link whose target is not there yet.
//   - Post-resolution: the final path is verified to still sit under root once the
//     operating system has had its say about every component.
//
// Reading the filesystem is unavoidable here and is the one place the kernel does
// it: containment cannot be decided lexically, because a directory the module did
// not create may be a link. Nothing else in the kernel opens a file, and this
// function opens none either - it stats and resolves names.
//
// root is trusted; it belongs to the host, not to the module. A relative root is
// made absolute against the process working directory so that containment is
// decided between two absolute paths.
func FSResolve(root, rel string) (string, error) {
	if root == "" {
		return "", &FSPathError{Msg: "no data root configured for this module"}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", &FSPathError{Msg: "data root is not resolvable: " + err.Error()}
	}
	// Resolve the root itself, so a root that is a symlink is compared as the
	// directory it points at. Without this, a root under /var/data pointing at
	// /srv/data would make every legitimate path look like an escape.
	if resolved, rerr := filepath.EvalSymlinks(absRoot); rerr == nil {
		absRoot = resolved
	}

	if rel == "" {
		return "", &FSPathError{Msg: "empty path"}
	}
	if filepath.IsAbs(rel) || isVolumePath(rel) {
		return "", &FSPathError{Msg: fmt.Sprintf("path %q must be relative to the data root", rel)}
	}
	if strings.IndexByte(rel, 0) >= 0 {
		return "", &FSPathError{Msg: "path contains a NUL byte"}
	}

	slash := filepath.ToSlash(rel)
	for seg := range strings.SplitSeq(slash, "/") {
		if seg == ".." {
			return "", &FSPathError{Msg: fmt.Sprintf("path %q escapes the data root", rel)}
		}
	}

	clean := path.Clean(slash)
	if clean == "." || clean == "/" {
		return "", &FSPathError{Msg: "path resolves to the data root itself"}
	}

	joined := filepath.Join(absRoot, filepath.FromSlash(clean))
	if !fsWithinRoot(absRoot, joined) {
		return "", &FSPathError{Msg: fmt.Sprintf("path %q escapes the data root", rel)}
	}

	if err := fsCheckLinkEscape(absRoot, joined, clean); err != nil {
		return "", err
	}

	// The lexical and per-component checks are not sufficient on their own,
	// because resolving a chain can land somewhere no single step predicted.
	// EvalSymlinks asks the filesystem what the path really is, and the answer is
	// re-checked for containment. A path that does not exist yet has no symlinks
	// to follow, so its nearest existing ancestor is checked instead: that is the
	// write case, and refusing it would make creating a file impossible.
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		ancestor, aerr := fsNearestAncestor(joined)
		if aerr != nil {
			return "", &FSPathError{Msg: fmt.Sprintf("path %q is not resolvable: %v", rel, err)}
		}
		if !fsWithinRoot(absRoot, ancestor) {
			return "", &FSPathError{Msg: fmt.Sprintf("path %q escapes the data root through a missing component", rel)}
		}
		return joined, nil
	}
	if !fsWithinRoot(absRoot, resolved) {
		return "", &FSPathError{Msg: fmt.Sprintf("path %q escapes the data root through a symlink", rel)}
	}
	return resolved, nil
}

// fsCheckLinkEscape examines every component of a lexically-contained path for a
// symlink that leaves the root. clean is the slash-separated relative path that
// produced joined, so the two are walked in step.
//
// A link whose target does not exist is judged on the target it names rather than
// passed over. Refusing to judge it would be the hole: a dangling link pointing at
// /etc is exactly what a module would plant before asking the kernel to write
// through it, and the write would create the file outside the root.
func fsCheckLinkEscape(absRoot, joined, clean string) error {
	prefix := absRoot
	for seg := range strings.SplitSeq(clean, "/") {
		prefix = filepath.Join(prefix, filepath.FromSlash(seg))

		fi, err := os.Lstat(prefix)
		if err != nil {
			// This component does not exist, so nothing below it can be a link out
			// of the root either. The ancestor check in FSResolve covers the rest.
			return nil
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, err := os.Readlink(prefix)
		if err != nil {
			return &FSPathError{Msg: "path component is an unreadable symlink"}
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(prefix), target)
		}
		if full, ferr := filepath.EvalSymlinks(target); ferr == nil {
			target = full
		} else {
			target = filepath.Clean(target)
		}
		if !fsWithinRoot(absRoot, target) {
			return &FSPathError{Msg: fmt.Sprintf("path %q escapes the data root through a symlink", clean)}
		}
	}
	return nil
}

// isVolumePath recognises a Windows-style volume or UNC path. Checking only for a
// leading slash would call "C:\data\x" relative and then join it onto the root,
// which on Windows yields an absolute path outside it.
func isVolumePath(p string) bool {
	return strings.HasPrefix(p, `\\`) || (len(p) >= 2 && p[1] == ':')
}

// fsWithinRoot reports whether p is root or sits under it. Both must be absolute
// and clean. The separator is appended to root so that "/var/data" does not
// appear to contain "/var/data-other".
func fsWithinRoot(root, p string) bool {
	if p == root {
		return true
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(p, prefix)
}

// fsNearestAncestor walks up from p to the first component that exists and resolves
// it. This is what makes a write to a not-yet-created file checkable: the part that
// exists is the part that could be a symlink out of the root.
//
// It returns an error only when nothing on the path exists, which for a data root the
// host created cannot happen; the check is there so the caller is not relying on that.
func fsNearestAncestor(p string) (string, error) {
	cur := filepath.Clean(p)
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return resolved, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", errors.New("kernel: fs: no existing ancestor")
		}
		cur = parent
	}
}

// FSPathAllowed reports whether a resolved relative path is inside one of the
// declared boundaries. It takes the manifest lists directly rather than reading
// them back out of the module record, so the boundary rule is a pure function of
// its arguments and is testable without loading a module. Exported for the fs
// syscall that does not exist yet and for tests.
//
// Matching is by path segment, not by string prefix. A declared directory "cache"
// must cover "cache/blob" and must not cover "cache2/blob"; string prefixing would
// let a module that declared "cache" reach "cache-secret".
func FSPathAllowed(rel string, allow []string) bool {
	if rel == "" || rel == "." || rel == "/" {
		// The data root itself is never in scope. Manifest validation refuses a
		// whole-tree declaration for the same reason: a grant that names the root
		// is a grant over everything, which is not what a reviewer reads as a path.
		return false
	}
	for _, a := range allow {
		if a == "" {
			continue
		}
		base := path.Clean(filepath.ToSlash(a))
		if base == "." || base == "/" || base == ".." || strings.HasPrefix(base, "../") {
			continue
		}
		if rel == base || strings.HasPrefix(rel, base+"/") {
			return true
		}
	}
	return false
}

// FSCheckRead authorises and resolves one read. It is the shape the fs syscall
// will have: policy gate first, then containment, then the manifest boundary.
//
// The order matters. Checking the boundary before the policy gate would tell a
// module holding no fs:read at all whether a path fell inside some grant, and the
// gate is the part that must not be skippable.
func FSCheckRead(ctx SContext, root, rel string) (string, error) {
	c, err := kvfsContext(ctx, OpFSRead)
	if err != nil {
		return "", err
	}
	abs, err := FSResolve(root, rel)
	if err != nil {
		fault(c, "fs read refused by path check", map[string]any{
			"module": c.name, "path": rel, "reason": err.Error(),
		})
		return "", err
	}
	if !FSPathAllowed(path.Clean(filepath.ToSlash(rel)), readPathsFor(c.pid)) {
		return "", fsScopeRefused(c, OpFSRead, rel)
	}
	// The instance filter is consulted AFTER the manifest scope, never before, because
	// the three layers are ceiling, scope, filter and a filter that answered first would
	// stand in for a grant the module does not have. seccomp.go gives the full ordering.
	if err := SeccompAllow(c, OpFSRead, rel); err != nil {
		return "", err
	}
	return abs, nil
}

// FSCheckWrite authorises and resolves one write. Same shape and same ordering as
// FSCheckRead, against the manifest's write boundary.
func FSCheckWrite(ctx SContext, root, rel string) (string, error) {
	c, err := kvfsContext(ctx, OpFSWrite)
	if err != nil {
		return "", err
	}
	abs, err := FSResolve(root, rel)
	if err != nil {
		fault(c, "fs write refused by path check", map[string]any{
			"module": c.name, "path": rel, "reason": err.Error(),
		})
		return "", err
	}
	if !FSPathAllowed(path.Clean(filepath.ToSlash(rel)), writePathsFor(c.pid)) {
		return "", fsScopeRefused(c, OpFSWrite, rel)
	}
	// Instance filter, after the scope check. See FSCheckRead for the ordering.
	if err := SeccompAllow(c, OpFSWrite, rel); err != nil {
		return "", err
	}
	return abs, nil
}

// fsScopeRefused records a boundary violation as an escalation. Reaching for a
// path outside the declared boundary is an attempt to act beyond a grant, which
// is what AuditEscalation is for, and it is audited rather than only faulted
// because a module probing its boundary is evidence about the module.
func fsScopeRefused(c *sContext, op Op, rel string) error {
	reason := fmt.Sprintf("%q is outside the declared %s boundary", rel, op)
	fault(c, "fs path outside declared boundary", map[string]any{
		"module": c.name, "op": string(op), "path": rel, "reason": reason,
	})
	kaudit.record(AuditEscalation, c, "fs path outside declared boundary", map[string]any{
		"module": c.name, "op": string(op), "path": rel,
	})
	return &DeniedError{Op: op, Ctx: c, Reason: reason}
}

// fsScopes holds the manifest path boundaries per pid. They are installed at load
// and cleared at unload, alongside the operation grants in policy.go, because a
// scope that outlived the module it was declared for would apply to whatever
// loaded next.
var (
	fsScopesMu sync.RWMutex
	fsScopes   = map[PID]fsScope{}
)

type fsScope struct {
	read  []string
	write []string
}

// SetFSScope installs a module's declared path boundaries. It takes a pid rather
// than a context because the module loader is the only caller that has a validated
// manifest in hand, and the loader is what allocates pids: a module cannot call
// this for itself, and cannot call it for anyone else.
func SetFSScope(pid PID, readPaths, writePaths []string) {
	fsScopesMu.Lock()
	defer fsScopesMu.Unlock()
	fsScopes[pid] = fsScope{
		read:  append([]string(nil), readPaths...),
		write: append([]string(nil), writePaths...),
	}
}

// ClearFSScope drops a module's boundaries. Called on unload.
//
// It does not take a context and it does not check one, so it is a bookkeeping call
// rather than a control: LoadModule calls SetFSScope unconditionally, so a pid that
// reaches an fs check has its scope overwritten from its own manifest first and a
// surviving scope is unreachable through any exported path - the same argument
// resetFSScopes carries in resetKernel. What this protects is residency: a scope is
// a slice of strings held for a pid that will never be reused, and without the delete
// the only thing that frees it is a wholesale reset at the next shutdown.
//
// It is pinned by an in-package test because no external one can reach it: there is
// no exported reader for the scope map, by design, since a module must not be able to
// enumerate the boundaries it is being held to.
func ClearFSScope(pid PID) {
	fsScopesMu.Lock()
	defer fsScopesMu.Unlock()
	delete(fsScopes, pid)
}

func readPathsFor(pid PID) []string {
	fsScopesMu.RLock()
	defer fsScopesMu.RUnlock()
	return fsScopes[pid].read
}

func writePathsFor(pid PID) []string {
	fsScopesMu.RLock()
	defer fsScopesMu.RUnlock()
	return fsScopes[pid].write
}

func resetFSScopes() {
	fsScopesMu.Lock()
	defer fsScopesMu.Unlock()
	fsScopes = map[PID]fsScope{}
}

// ---------------------------------------------------------------------------
// Syscall wiring for the integrator. Add SyscallKV to the SContext group list in
// kernel/context.go, then paste the interface and methods beside the other groups.
//
//	type SyscallKV interface {
//		// SyscallKVGet reads one value from this module's namespace. Requires
//		// kv:read. The returned slice is a copy the caller owns.
//		SyscallKVGet(key string) ([]byte, error)
//		// SyscallKVPut stores one value in this module's namespace. Requires
//		// kv:write. The value is copied in, and a write over the per-module
//		// ceiling is refused with a *KVQuotaError.
//		SyscallKVPut(key string, value []byte) error
//		// SyscallKVDelete removes one key. Requires kv:write.
//		SyscallKVDelete(key string) error
//		// SyscallKVKeys lists this module's own keys, sorted. Requires kv:read.
//		SyscallKVKeys() ([]string, error)
//	}
//
//	func (c *sContext) SyscallKVGet(key string) ([]byte, error) { return KVGet(c, key) }
//	func (c *sContext) SyscallKVPut(key string, value []byte) error {
//		return KVPut(c, key, value)
//	}
//	func (c *sContext) SyscallKVDelete(key string) error { return KVDelete(c, key) }
//	func (c *sContext) SyscallKVKeys() ([]string, error) { return KVKeys(c) }
//
// The fs resolver is deliberately not part of this group. It has no syscall yet,
// and wiring FSCheckRead and FSCheckWrite to a group now would publish a surface
// whose data root nobody has decided how to configure.
// ---------------------------------------------------------------------------
