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

// The per-request record and the query that selects it.

// MeterFilter selects retained records to query.
type MeterFilter struct {
	// Route narrows to one path. Empty means any.
	Route string
	// PID narrows to the module that served the request. Zero means any.
	PID PID
	// Caller narrows to the module that asked. Zero means any.
	Caller PID
	// Trace narrows to one request's trace.
	Trace TraceID
	// Abandoned returns only records the kernel closed at teardown.
	Abandoned bool
	// Since returns only records opened at or after this Mono() reading.
	Since int64
	// Limit caps the result, newest first.
	Limit int
}

// MeterRecord is one request's facts. Every field is an observation.
type MeterRecord struct {
	// ID is kernel-assigned and unguessable.
	ID RequestID `json:"id"`
	// Trace links the request to its spans in ktrace. Like RouteRequest.Trace it is
	// a correlation id the caller may propagate, and it carries no authority: the
	// pid that served the request and the pid that asked are both kernel-assigned,
	// so the ledger cannot be misattributed by choosing a label.
	Trace TraceID `json:"trace,omitempty"`
	// Route is the path that served it, when the request came through kservice.
	Route string `json:"route,omitempty"`
	// PID is the module that served it, kernel-assigned.
	PID PID `json:"pid"`
	// Module is that module's name, for logs.
	Module string `json:"module,omitempty"`
	// Caller is the module that asked, when the call crossed a route.
	//
	// It identifies a local context, not an originating party. A request forwarded
	// in from another mesh node is dispatched by kpeer under init's context, so
	// Caller reads as init's pid. Nothing about a MeterRecord says whether the work
	// was local or inbound, and that is deliberate rather than an oversight: adding
	// an origin field would let a module attribute its own traffic to somewhere
	// else, and a field a module can influence is not evidence. The distinction
	// lives on the audit chain, where kpeer records "peer forward accepted" with
	// the sending node's id before dispatch, so an investigator can join the two by
	// trace id. Code that reads Caller as "the module that decided to make this
	// request" is wrong for inbound traffic and should join on the chain instead.
	Caller PID `json:"caller,omitempty"`
	// Opened and Closed are Mono() readings. The interval is measured on the
	// kernel clock so an NTP step cannot change a billable duration.
	Opened int64 `json:"opened"`
	Closed int64 `json:"closed,omitempty"`
	// Tokens and Requests are the usage facts recorded against this request. They
	// are the same closed kinds usage.go enforces, so a meter record cannot carry a
	// quantity the kernel refused to count.
	TokensIn  int64 `json:"tokens_in,omitempty"`
	TokensOut int64 `json:"tokens_out,omitempty"`
	Requests  int64 `json:"requests,omitempty"`
	// Status is the handler's own result code, recorded as reported. The kernel
	// does not interpret it.
	Status int `json:"status,omitempty"`
	// Abandoned marks a request the kernel closed at module teardown because the
	// module never closed it. Its duration is a lower bound, and saying so is what
	// keeps the number honest.
	Abandoned bool `json:"abandoned,omitempty"`
	// Settled marks a record whose facts were handed to a settlement receipt, so a
	// second settlement of the same request is visible.
	Settled bool `json:"settled,omitempty"`
}

// ElapsedNanos is the request's duration on the kernel clock.
func (r MeterRecord) ElapsedNanos() int64 {
	if r.Closed <= r.Opened {
		return 0
	}
	return r.Closed - r.Opened
}
