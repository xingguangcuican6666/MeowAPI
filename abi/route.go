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

// The route table request, response and handler signature.

// RouteRequest is one inbound call. The payload crosses as bytes, never as a Go
// value, so a caller cannot hand a handler a live reference into its own heap.
type RouteRequest struct {
	// Path is the normalized route that was matched.
	Path string `json:"path"`
	// CallerPID is who asked. It is kernel-assigned and cannot be forged, so a
	// handler may make a decision based on it.
	CallerPID PID `json:"caller_pid"`
	// CallerModule is the caller's registered name, for logs.
	CallerModule string `json:"caller_module,omitempty"`
	// Trace is a correlation id. The caller may propagate one it was given, which
	// is how a trace crosses a module boundary at all: without it the caller's span
	// tree and the handler's could never be joined. It carries no authority. Every
	// field in the audit record that identifies who did what - CallerPID, the
	// handler's pid - is kernel-assigned, so a caller that invents a trace id
	// mislabels its own correlation and cannot attribute anything to anyone else.
	// A fresh span opened by the handler gets its id from ktrace, not from here.
	Trace TraceID `json:"trace,omitempty"`
	// Method is a verb the caller chose, for a REST-shaped surface. It is not
	// part of the route key: two modules cannot serve the same path with different
	// methods, because that would make the table's uniqueness rule a lie.
	Method string `json:"method,omitempty"`
	// Payload is a copy of the caller's bytes.
	Payload []byte `json:"payload,omitempty"`
}

// RouteResponse is one outbound reply.
type RouteResponse struct {
	// Status is the handler's own code. The kernel does not interpret it.
	Status int `json:"status"`
	// Payload is copied out to the caller, so the handler may reuse its buffer.
	Payload []byte `json:"payload,omitempty"`
	// Header carries small string pairs, for a provider-shaped response.
	Header map[string]string `json:"header,omitempty"`
}

// RouteHandler serves one path. It runs on the handler module's own goroutine and
// under the handler module's own context, which is the whole point of the design.
type RouteHandler func(ctx SContext, req RouteRequest) (RouteResponse, error)
