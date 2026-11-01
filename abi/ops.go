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

// The operation set. These are the names a manifest lists and a denial quotes;
// which domain holds one, and what a manifest may narrow it to, is the kernel's
// policy table and stays there.
const (
	// Core context and lifecycle.
	OpMetadataRead  Op = "metadata:read"
	OpMetadataWrite Op = "metadata:write"
	OpProcessFork   Op = "process:fork"
	OpModuleLoad    Op = "module:load"
	OpModuleUnload  Op = "module:unload"
	// ipc:bind and ipc:call are reserved and gate nothing. No syscall checks either
	// one; the live module-to-module mechanism is kservice's route:register and
	// route:call. They stay declared because they are granted to two domains and a
	// manifest in the wild may require one, so removing them is a policy surface
	// change rather than a cleanup. Do not add a check against them without first
	// deciding what they mean, because a check nobody reasoned about is a refusal
	// nobody can diagnose.
	OpIPCBind  Op = "ipc:bind"
	OpIPCCall  Op = "ipc:call"
	OpLogWrite Op = "log:write"

	// kaudit: the tamper-evident record. Distinct from log:write, because an
	// audit entry is evidence and a log line is commentary.
	OpAuditAppend Op = "audit:append"
	OpAuditRead   Op = "audit:read"

	// kmeter and ktokenizer: usage accounting and the kernel's own token count.
	OpUsageEmit   Op = "usage:emit"
	OpMeterRecord Op = "meter:record"
	OpMeterRead   Op = "meter:read"
	OpTokenCount  Op = "token:count"

	// kreceipt: signed settlement records.
	OpReceiptIssue  Op = "receipt:issue"
	OpReceiptVerify Op = "receipt:verify"

	// kqos and krlimit: admission and concurrency.
	OpQosAdmit    Op = "qos:admit"
	OpSlotAcquire Op = "slot:acquire"

	// kpipe, kshm, klock, kepoll: resource handles.
	OpPipeOpen  Op = "pipe:open"
	OpPipeWrite Op = "pipe:write"
	OpPipeRead  Op = "pipe:read"
	OpShmAlloc  Op = "shm:alloc"
	OpShmMap    Op = "shm:map"
	OpLockTake  Op = "lock:acquire"
	OpEventWait Op = "event:wait"

	// kservice: the route table.
	OpRouteRegister Op = "route:register"
	OpRouteCall     Op = "route:call"

	// knet, kpeer, kslashing: controlled egress and the node mesh.
	OpNetDial         Op = "net:dial"
	OpNetListen       Op = "net:listen"
	OpPeerDial        Op = "peer:dial"
	OpPeerAnnounce    Op = "peer:announce"
	OpSlashReport     Op = "slash:report"
	OpSlashAdjudicate Op = "slash:adjudicate"

	// kvfs: namespaced state and bounded file access.
	OpKVRead  Op = "kv:read"
	OpKVWrite Op = "kv:write"
	OpFSRead  Op = "fs:read"
	OpFSWrite Op = "fs:write"

	// kkeyring and kcrypto: secret custody and primitives.
	OpSecretRead   Op = "secret:read"
	OpSecretUse    Op = "secret:use"
	OpCryptoRandom Op = "crypto:random"
	OpCryptoHash   Op = "crypto:hash"
	OpCryptoSign   Op = "crypto:sign"
	OpCryptoVerify Op = "crypto:verify"

	// ksched, ksignal, kwatchdog, koom, kcputime: execution control.
	OpSchedSpawn  Op = "sched:spawn"
	OpSchedTimer  Op = "sched:timer"
	OpSignalSend  Op = "signal:send"
	OpCPUTimeRead Op = "cputime:read"

	// ktrace and ktty: observability.
	OpTraceSpan Op = "trace:span"
	OpTTYOpen   Op = "tty:open"
)
