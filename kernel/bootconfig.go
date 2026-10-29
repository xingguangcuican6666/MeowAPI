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

package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// bootConfig is the sealed trust root (subsystem: kboot, the analogue of a kernel
// cmdline plus DeviceTree).
//
// It exists because some configuration must be fixed before any module runs and
// must not be changeable afterwards, by anyone. The cluster root public key is the
// case that matters: if a module, or init, or an operator with a debug console
// could replace it at runtime, then every signature check the kernel performs
// afterward would be verifying against an attacker's key, and the check would
// still pass. Sealing is what makes a signature check mean anything.
//
// The seal is one-way and irreversible within a boot. Reading stays available to
// everyone; writing stops for all callers, including init and including the
// kernel's own exported API.
type bootConfig struct {
	mu     sync.RWMutex
	values map[string]string
	sealed bool
	// digest is computed at seal time and is what an operator records to prove
	// which trust root a given kernel ran under.
	digest string

	// signingKey and limits sit beside the map rather than inside it, because the
	// map is readable by any module and the key material must not be.
	signingKey string
	limits     BootLimits
}

var kboot = &bootConfig{values: map[string]string{}}

// BootConfigValue is one entry in the trust root.
type BootConfigValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// BootTrustRoot is what the bootloader hands the kernel before Boot. It is a
// struct rather than a map so the fields the kernel depends on are named and
// reviewed, and an operator cannot smuggle an unexpected key past a reader.
type BootTrustRoot struct {
	// NodeID identifies this node to its peers.
	NodeID string `json:"node_id"`
	// ClusterRootKeys are the trusted verification keys for the mesh. A receipt
	// signed by anything outside this set is rejected by kreceipt.
	ClusterRootKeys []string `json:"cluster_root_keys"`
	// SigningKeyPEM is this node's private key material. It is held in the kernel
	// and never returned to a module; kcrypto signs with it and hands back only
	// the signature. It is never written to the configuration map, the audit log,
	// the console or a dump.
	SigningKeyPEM string `json:"signing_key_pem"`
	// Limits are the initial resource quotas.
	Limits BootLimits `json:"limits"`
	// Extra carries operator-defined string configuration.
	Extra map[string]string `json:"extra"`
}

// BootLimits are the resource ceilings the kernel enforces. They come from the
// trust root rather than from module configuration, because a quota a module could
// raise is not a quota.
type BootLimits struct {
	// MaxModules caps how many modules may be live at once.
	MaxModules int `json:"max_modules"`
	// MaxSlotsPerModule caps concurrent in-flight operations for one module.
	MaxSlotsPerModule int `json:"max_slots_per_module"`
	// MaxTotalSlots caps concurrency across the kernel.
	MaxTotalSlots int `json:"max_total_slots"`
	// MaxOpenFDsPerModule caps handles one module may hold at once.
	MaxOpenFDsPerModule int `json:"max_open_fds_per_module"`
	// MaxSharedBytes caps the shared buffer pool (kshm and kslab).
	MaxSharedBytes int64 `json:"max_shared_bytes"`
	// MaxKVBytesPerModule caps one module's namespaced state.
	MaxKVBytesPerModule int64 `json:"max_kv_bytes_per_module"`
	// CallTimeoutMillis bounds a single synchronous module call.
	CallTimeoutMillis int64 `json:"call_timeout_millis"`
}

// defaultLimits is used for any ceiling the operator left at zero. Each default is
// chosen to be survivable rather than generous: a limit that is too low is a
// visible error, a limit that is too high is an outage.
func defaultLimits() BootLimits {
	return BootLimits{
		MaxModules:          64,
		MaxSlotsPerModule:   256,
		MaxTotalSlots:       4096,
		MaxOpenFDsPerModule: 1024,
		MaxSharedBytes:      256 << 20,
		MaxKVBytesPerModule: 16 << 20,
		CallTimeoutMillis:   30_000,
	}
}

func (l *BootLimits) withDefaults() {
	d := defaultLimits()
	if l.MaxModules <= 0 {
		l.MaxModules = d.MaxModules
	}
	if l.MaxSlotsPerModule <= 0 {
		l.MaxSlotsPerModule = d.MaxSlotsPerModule
	}
	if l.MaxTotalSlots <= 0 {
		l.MaxTotalSlots = d.MaxTotalSlots
	}
	if l.MaxOpenFDsPerModule <= 0 {
		l.MaxOpenFDsPerModule = d.MaxOpenFDsPerModule
	}
	if l.MaxSharedBytes <= 0 {
		l.MaxSharedBytes = d.MaxSharedBytes
	}
	if l.MaxKVBytesPerModule <= 0 {
		l.MaxKVBytesPerModule = d.MaxKVBytesPerModule
	}
	if l.CallTimeoutMillis <= 0 {
		l.CallTimeoutMillis = d.CallTimeoutMillis
	}
}

// ErrBootSealed is returned by any write to the trust root after sealing. It is
// not a policy denial: no domain holds the ability to write a sealed root, so
// there is nothing to grant and no avc line to emit.
var ErrBootSealed = errors.New("kernel: boot trust root is sealed")

// loadBootConfig installs the trust root and seals it. Called once from Boot,
// before init is spawned, so nothing that runs later can have observed an unsealed
// configuration.
//
// Sealing is not deferred to the end of boot. If it were, a module loaded during
// boot could observe the pre-seal state and the guarantee would depend on load
// order.
func loadBootConfig(tr BootTrustRoot) error {
	if err := validateTrustRoot(&tr); err != nil {
		return err
	}
	tr.Limits.withDefaults()

	values := make(map[string]string, 8+len(tr.Extra))
	values["node.id"] = tr.NodeID
	for i, k := range tr.ClusterRootKeys {
		values[fmt.Sprintf("cluster.root.%d", i)] = k
	}
	values["limits.max_modules"] = fmt.Sprint(tr.Limits.MaxModules)
	values["limits.max_slots_per_module"] = fmt.Sprint(tr.Limits.MaxSlotsPerModule)
	values["limits.max_total_slots"] = fmt.Sprint(tr.Limits.MaxTotalSlots)
	values["limits.max_open_fds_per_module"] = fmt.Sprint(tr.Limits.MaxOpenFDsPerModule)
	values["limits.max_shared_bytes"] = fmt.Sprint(tr.Limits.MaxSharedBytes)
	values["limits.max_kv_bytes_per_module"] = fmt.Sprint(tr.Limits.MaxKVBytesPerModule)
	values["limits.call_timeout_millis"] = fmt.Sprint(tr.Limits.CallTimeoutMillis)
	for k, v := range tr.Extra {
		values["extra."+k] = v
	}

	kboot.mu.Lock()
	defer kboot.mu.Unlock()
	kboot.values = values
	kboot.limits = tr.Limits
	kboot.signingKey = tr.SigningKeyPEM
	kboot.sealed = true
	kboot.digest = hashBootConfig(values)
	return nil
}

// hashBootConfig digests the configuration in key order, so the digest does not
// depend on map iteration order and two kernels with the same root agree.
func hashBootConfig(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s\n", k, values[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validateTrustRoot(tr *BootTrustRoot) error {
	if tr.NodeID == "" {
		return errors.New("kernel: boot trust root requires a node id")
	}
	for _, k := range tr.ClusterRootKeys {
		if k == "" {
			return errors.New("kernel: boot trust root has an empty cluster root key")
		}
	}
	for k := range tr.Extra {
		if k == "" {
			return errors.New("kernel: boot trust root has an empty extra key")
		}
	}
	return nil
}

// BootSet writes a trust root entry before sealing. It is exported for the host
// process, which builds the root from its own configuration files and environment.
// After sealing it returns ErrBootSealed for every caller.
func BootSet(key, value string) error {
	if key == "" {
		return errors.New("kernel: empty boot config key")
	}
	kboot.mu.Lock()
	defer kboot.mu.Unlock()
	if kboot.sealed {
		return ErrBootSealed
	}
	kboot.values[key] = value
	return nil
}

// BootGet reads one trust root entry. It requires no operation and is available to
// every module: configuration is not a capability, and a module that cannot read
// its own quota cannot respect it. Key material is not in this map and is not
// reachable from here.
func BootGet(key string) (string, bool) {
	kboot.mu.RLock()
	defer kboot.mu.RUnlock()
	v, ok := kboot.values[key]
	return v, ok
}

// BootAll returns a copy of the trust root sorted by key. It never contains the
// signing key.
func BootAll() []BootConfigValue {
	kboot.mu.RLock()
	out := make([]BootConfigValue, 0, len(kboot.values))
	for k, v := range kboot.values {
		out = append(out, BootConfigValue{Key: k, Value: v})
	}
	kboot.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// BootDigest is the hash of the sealed trust root. An operator records it in the
// deployment log so a later investigation can prove which root a kernel ran under.
func BootDigest() string {
	kboot.mu.RLock()
	defer kboot.mu.RUnlock()
	return kboot.digest
}

// BootSealed reports whether the trust root is sealed.
func BootSealed() bool {
	kboot.mu.RLock()
	defer kboot.mu.RUnlock()
	return kboot.sealed
}

// Limits returns the effective resource ceilings. They are fixed at seal time, so
// every subsystem that enforces a quota reads the same number.
func Limits() BootLimits {
	kboot.mu.RLock()
	defer kboot.mu.RUnlock()
	return kboot.limits
}

// nodeSigningKey returns this node's private key material. It is unexported on
// purpose: only kcrypto and kreceipt may hold it, and neither returns it to a
// module. A module asks for a signature and receives the signature.
func nodeSigningKey() string {
	kboot.mu.RLock()
	defer kboot.mu.RUnlock()
	return kboot.signingKey
}

// ClusterRootKeys returns the trusted mesh verification keys, in the order the
// operator declared them.
func ClusterRootKeys() []string {
	kboot.mu.RLock()
	defer kboot.mu.RUnlock()
	var out []string
	for i := 0; ; i++ {
		v, ok := kboot.values[fmt.Sprintf("cluster.root.%d", i)]
		if !ok {
			return out
		}
		out = append(out, v)
	}
}

// resetBoot unseals and clears the trust root. Called only from resetKernel, so a
// restart re-reads its own configuration rather than inheriting the previous
// boot's root.
func (b *bootConfig) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values = map[string]string{}
	b.sealed = false
	b.digest = ""
	b.signingKey = ""
	b.limits = BootLimits{}
}

// SyscallBoot is the trust-root half of the syscall surface. Every method is a
// read; there is no write, because there is nothing to write to after sealing.
type SyscallBoot interface {
	// SyscallBootGet reads one sealed trust root entry. It never returns key
	// material.
	SyscallBootGet(key string) (string, bool)
	// SyscallBootAll returns the whole trust root, sorted by key.
	SyscallBootAll() []BootConfigValue
	// SyscallBootLimits returns the effective resource ceilings.
	SyscallBootLimits() BootLimits
	// SyscallBootDigest returns the hash of the sealed trust root.
	SyscallBootDigest() string
}

func (c *sContext) SyscallBootGet(key string) (string, bool) { return BootGet(key) }
func (c *sContext) SyscallBootAll() []BootConfigValue        { return BootAll() }
func (c *sContext) SyscallBootLimits() BootLimits            { return Limits() }
func (c *sContext) SyscallBootDigest() string                { return BootDigest() }
