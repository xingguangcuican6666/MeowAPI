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

// The sealed trust root as a module sees it: read-only values and ceilings.

// BootConfigValue is one entry in the trust root.
type BootConfigValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
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

	// The five fields below are koom's, and adding them widens the trust root, which is a
	// kboot change rather than a subsystem's. They are here rather than package constants for
	// a reason worth stating, because the distinction decides the question for the next
	// subsystem author too:
	//
	// A resource CEILING belongs in the sealed root. It is operator policy about how much of
	// the machine one tenant may take, it differs per deployment - a 512MiB container and a
	// 512GiB host need different numbers - and the comment above this struct gives the rule:
	// a quota a module could raise is not a quota. MaxKVBytesPerModule, MaxSharedBytes and
	// MaxOpenFDsPerModule are already here on exactly that basis, and
	// MaxAccountedBytesPerModule is the same class of number rather than a new one.
	//
	// A subsystem's own SHAPE does not. koom's ledger bound is a package constant
	// (maxOomHistory) the way kslashing's and kpeer's are, and its patrol interval is derived
	// from the sealed call ceiling the way watchdogInterval is. Neither is something an
	// operator should have to get right, and both would be a second knob for a decision
	// already made elsewhere.
	//
	// MaxAccountedBytesPerModule caps the memory the KERNEL handed one module: its
	// namespaced state, its reserved pipe capacity and the shared segments it owns. It is
	// a sum across three subsystems rather than a fourth ceiling on one of them, and the
	// combination is what it is for - a module inside every individual ceiling can still
	// exceed this by holding all three at once. What it cannot see is a module's own heap,
	// which no kernel accounting reaches; oom.go says so where it matters.
	MaxAccountedBytesPerModule int64 `json:"max_accounted_bytes_per_module"`
	// OomHostWarnBP and OomHostKillBP are the host-pressure thresholds in basis points,
	// measured against what the process has reserved from the OS. At warn the sweep records
	// and escalates; at kill it terminates. Two thresholds rather than one because the
	// useful response to a host at 80% is a record an operator can act on.
	OomHostWarnBP int `json:"oom_host_warn_bp"`
	OomHostKillBP int `json:"oom_host_kill_bp"`
	// OomMaxVictimsPerSweep bounds one sweep. A pressure response that terminates
	// everything eligible is not a response to pressure, it is a shutdown, and bounding it
	// lets the kernel try again next sweep if the first victim was not the cause.
	OomMaxVictimsPerSweep int `json:"oom_max_victims_per_sweep"`
}
