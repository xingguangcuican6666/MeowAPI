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
