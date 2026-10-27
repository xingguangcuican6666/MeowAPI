package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// Manifest declares what a module needs. It is data, it is validated before any
// module code runs, and it is enforced at every call through grant narrowing.
//
// A manifest is the reviewable artifact. Reading one tells a reviewer what a
// module can do, and the kernel refuses to let the module do anything the
// manifest does not say, so the declaration cannot be narrower than the behavior.
//
// The scoped fields are only meaningful alongside their operation. Requesting
// net:dial without an allowed host, or secret:read with an empty prefix, is
// rejected rather than interpreted generously, because the generous reading of a
// scope field is a hole.
type Manifest struct {
	// Name must match the registration name.
	Name string `json:"name"`
	// Version is the module's own version.
	Version string `json:"version"`
	// MinKernelAPI and MaxKernelAPI bound the kernel API this module supports. A
	// kernel API version outside the range is a load failure, not a runtime
	// surprise.
	MinKernelAPI int `json:"min_kernel_api"`
	MaxKernelAPI int `json:"max_kernel_api"`
	// Require lists the operations the module needs.
	Require []Op `json:"require,omitempty"`
	// AllowedHosts bounds net:dial. Empty means no outbound network.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	// ListenAddr bounds net:listen. Empty means no listening socket.
	ListenAddr string `json:"listen_addr,omitempty"`
	// ReadPaths and WritePaths bound fs:read and fs:write, relative to a
	// per-module data root.
	ReadPaths  []string `json:"read_paths,omitempty"`
	WritePaths []string `json:"write_paths,omitempty"`
	// SecretPrefixes bound secret:read. There is no wildcard and no
	// read-everything grant.
	SecretPrefixes []string `json:"secret_prefixes,omitempty"`
}

// scopedOps are granted by manifest scope rather than by the domain ceiling.
// Each one is meaningless without a declared scope, so a manifest requesting one
// must also declare the boundary.
//
// This is the difference between the plugin domain's unscoped grants
// (metadata:read, log:write, ipc:call, usage:emit) and capabilities that reach
// outside the process. A scoped operation is not in Allowed(DomainPlugin), so the
// ceiling check passes it through to per-call scope enforcement instead of
// rejecting it outright.
var scopedOps = map[Op]bool{
	OpNetDial:    true,
	OpNetListen:  true,
	OpFSRead:     true,
	OpFSWrite:    true,
	OpSecretRead: true,
	OpSecretUse:  true,
	OpPeerDial:   true,
}

// IsScoped reports whether an operation is scope-enforced per call rather than
// granted whole. Exported so a module author can tell from the docs which fields
// they must fill in.
func IsScoped(op Op) bool { return scopedOps[op] }

// ManifestError reports why a manifest was rejected. It is a distinct type so a
// caller can tell "your declaration is unacceptable" from "the kernel failed".
type ManifestError struct{ Msg string }

func (e *ManifestError) Error() string { return "kernel: invalid manifest: " + e.Msg }

func manifestErr(format string, a ...any) error {
	return &ManifestError{Msg: fmt.Sprintf(format, a...)}
}

// Validate checks a manifest against the kernel's policy ceiling. A module whose
// manifest fails never runs.
func (m *Manifest) Validate() error {
	if m.Name == "" {
		return manifestErr("name is required")
	}
	if strings.ContainsAny(m.Name, " \t\n/") {
		return manifestErr("name %q contains whitespace or a path separator", m.Name)
	}
	if m.Version == "" {
		return manifestErr("version is required")
	}
	if m.MinKernelAPI > KernelAPI || m.MaxKernelAPI < KernelAPI {
		return manifestErr("kernel API %d outside module range [%d,%d]",
			KernelAPI, m.MinKernelAPI, m.MaxKernelAPI)
	}

	seen := make(map[Op]bool, len(m.Require))
	for _, op := range m.Require {
		if !knownOp(op) {
			return manifestErr("unknown operation %q", op)
		}
		if seen[op] {
			// Duplicates would let a manifest look narrower in review than it
			// behaves, and hide a copy-paste error.
			return manifestErr("duplicate operation %q", op)
		}
		seen[op] = true

		if scopedOps[op] {
			continue
		}
		// The domain ceiling applies to unscoped operations. A module cannot ask
		// for metadata:write or module:load, because the plugin domain does not
		// hold them and no manifest can widen a domain.
		if !Allowed(DomainPlugin, op) {
			return manifestErr("operation %q is not grantable to domain %s", op, DomainPlugin)
		}
	}

	if err := m.checkScopes(); err != nil {
		return err
	}

	hosts := make(map[string]bool, len(m.AllowedHosts))
	for _, h := range m.AllowedHosts {
		if hosts[h] {
			return manifestErr("duplicate allowed host %q", h)
		}
		hosts[h] = true
	}
	return nil
}

// checkScopes enforces that every scoped operation carries its boundary, and that
// each boundary is in a form that cannot be widened by interpretation.
func (m *Manifest) checkScopes() error {
	if m.requires(OpNetDial) {
		if len(m.AllowedHosts) == 0 {
			return manifestErr("%s requires at least one allowed host", OpNetDial)
		}
		for _, h := range m.AllowedHosts {
			if err := validateHost(h); err != nil {
				return err
			}
		}
	}
	if m.requires(OpNetListen) && m.ListenAddr == "" {
		return manifestErr("%s requires a listen address", OpNetListen)
	}
	if m.requires(OpFSRead) {
		if len(m.ReadPaths) == 0 {
			return manifestErr("%s requires at least one read path", OpFSRead)
		}
		for _, p := range m.ReadPaths {
			if err := validatePath(p, "read"); err != nil {
				return err
			}
		}
	}
	if m.requires(OpFSWrite) {
		if len(m.WritePaths) == 0 {
			return manifestErr("%s requires at least one write path", OpFSWrite)
		}
		for _, p := range m.WritePaths {
			if err := validatePath(p, "write"); err != nil {
				return err
			}
		}
	}
	if m.requires(OpSecretRead) {
		if len(m.SecretPrefixes) == 0 {
			return manifestErr("%s requires at least one secret key prefix", OpSecretRead)
		}
		for _, p := range m.SecretPrefixes {
			if p == "" {
				return manifestErr("empty secret prefix is a read-all grant and is rejected")
			}
		}
	}
	return nil
}

func (m *Manifest) requires(op Op) bool {
	for _, o := range m.Require {
		if o == op {
			return true
		}
	}
	return false
}

// validateHost rejects the forms that turn a host allowlist into a hole.
//
// A wildcard is rejected because "any host" is the absence of an allowlist. A
// port, scheme, path, userinfo or fragment is rejected because the value is
// compared against a dialed hostname, and a host entry carrying more than a
// hostname either never matches (so the module is broken) or matches in a way the
// reviewer did not read. Loopback is rejected because it reaches every other
// service on the host, including the kernel's own ports.
func validateHost(h string) error {
	if h == "" {
		return manifestErr("empty host in allowed_hosts")
	}
	if strings.Contains(h, "*") {
		return manifestErr("wildcard host %q is not allowed; net:dial is deny-by-default", h)
	}
	if strings.ContainsAny(h, "/@:?#") {
		return manifestErr("host %q must be a bare hostname, without scheme, port, path, userinfo or fragment", h)
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return manifestErr("host %q is loopback and is not grantable to a module", h)
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return manifestErr("host %q has an empty label", h)
		}
	}
	return nil
}

// validatePath rejects absolute paths, parent traversal and the data root itself.
// Module paths are relative to a per-module data root, so an absolute path is an
// escape and ".." walks out of it.
func validatePath(p, kind string) error {
	if p == "" {
		return manifestErr("empty %s path", kind)
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return manifestErr("%s path %q must be relative, not absolute", kind, p)
	}
	clean := path.Clean(p)
	if clean == "/" || clean == "." {
		return manifestErr("%s path %q resolves to the data root; a whole-tree grant is rejected", kind, p)
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return manifestErr("%s path %q escapes the data root", kind, p)
		}
	}
	return nil
}

func knownOp(op Op) bool {
	for _, o := range AllOps {
		if o == op {
			return true
		}
	}
	return false
}

// Digest is a content hash of the manifest, recorded in the process table so a
// later investigation can prove which declaration a module actually ran under.
//
// It marshals through the struct rather than hashing the source bytes, so two
// manifests that differ only in whitespace or key order hash identically. The
// digest identifies the declaration's meaning, not its formatting.
func (m *Manifest) Digest() string {
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
