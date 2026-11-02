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

package abi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// PID is a process id. Pids are allocated by the kernel and never reused within a
// boot, which is what makes a pid safe to record and reason about afterwards.
type PID int

// UID is the kernel-allocated owner id of a context. It is assigned by the kernel
// from the domain, never supplied by the caller: a module that could choose its own
// uid could choose 0.
type UID int

// Domain is the SELinux-form security domain of a context. Domains are the subject
// of every policy decision.
type Domain string

// FD is a handle into one pid's file table. A handle is meaningful only inside the
// pid that opened it, which is the shell's fd model rather than Go's.
type FD int

// Level is the severity of a kernel console record.
type Level string

// Op is a policy operation, spelled class:permission so denials read like SELinux
// and so a policy table can be reviewed by anyone who knows it.
//
// The type lives here because a manifest names operations and a module therefore
// has to be able to name them too. The TABLE - which domain holds which operation,
// and what a manifest may narrow it to - stays in the kernel, which is the whole
// distinction this package exists to keep.
type Op string

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

const (
	LogDebug Level = "debug"
	LogInfo  Level = "info"
	LogWarn  Level = "warn"
	LogError Level = "error"
	// LogFault is reserved for kernel-detected violations: policy denials,
	// caller-trap faults, boot panics. Faults are the audit trail.
	LogFault Level = "fault"
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
	// ServeRoutes lists the exact paths this module may register in the kernel
	// route table, each absolute and normalized. It bounds route:register the way
	// ReadPaths bounds fs:read.
	//
	// There is no wildcard, and that is the control. A module that could register
	// any path could register a path another module was about to serve, or a
	// shorter prefix of one, and the table would stop being a reviewed surface. An
	// empty list means the module serves nothing, which is the right default.
	ServeRoutes []string `json:"serve_routes,omitempty"`
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

// KernelAPI is the ABI version this package describes. A manifest declares the range
// of API versions it supports, and the kernel refuses one whose range excludes this
// number - so the number has to be visible to the module that writes the range as
// well as to the kernel that checks it.
//
// # What this number does not cover, and why it is still worth having
//
// Go's plugin package is stricter than this constant and in a way no constant can
// express. A .so records a hash of the source of every package it imports, and
// plugin.Open refuses a mismatch with "plugin was built with a different version of
// package". So a component built against a previous revision of THIS package will be
// refused by the loader even when the number below is unchanged - measured: adding
// one field to Command invalidated Example.so with no ABI change at all.
//
// That check is exact, which is good, and it means a component is only ever valid
// against the tree it was built from. KernelAPI is therefore not a compatibility
// window for .so files; it is the version a STATICALLY linked module's manifest is
// checked against, where no such hash exists, and it is the number a deployment
// record quotes. Raise it when a module written against an older tree could notice a
// behavioural difference, and do not expect raising it to help a stale .so - rebuilding
// the component is the only thing that does.
const KernelAPI = 1
