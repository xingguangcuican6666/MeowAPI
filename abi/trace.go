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

// Spans, their ids, and the filter that queries them.

// Span is one finished or live interval. It is a value type: a module gets a copy
// and cannot reach the kernel's record through it.
type Span struct {
	Trace  TraceID  `json:"trace"`
	Span   SpanID   `json:"span"`
	Parent SpanID   `json:"parent,omitempty"`
	Kind   SpanKind `json:"kind"`
	Name   string   `json:"name"`
	PID    PID      `json:"pid"`
	Module string   `json:"module,omitempty"`
	Start  int64    `json:"start"`
	End    int64    `json:"end,omitempty"`
	// Abandoned is set when the kernel closed the span during unload because the
	// module never ended it. An abandoned span's duration is a lower bound on the
	// real one, and marking it is what keeps that number honest.
	Abandoned bool `json:"abandoned,omitempty"`
	// Attrs are kernel-recorded facts about the span, never module-supplied
	// content, so a module cannot smuggle a payload through the trace.
	Attrs map[string]string `json:"attrs,omitempty"`
}

// SpanSpec describes a span to open.
//
// There is deliberately no Trace field. A module cannot name the trace it belongs
// to, because a module-chosen id is a module-chosen identity for a request: it could
// collide with another request's timeline, corrupting both, or be chosen to attach
// this module's work to a request it never served. The id comes from one of two
// places and both are the kernel: a fresh span from crypto/rand, a child span
// inherited from the parent the kernel already resolved. Propagation across a module
// boundary is therefore through Parent, which is checked against the process table,
// rather than through a string the caller controls.
type SpanSpec struct {
	// Parent is the enclosing span, empty for a root span. It must be a span this
	// pid can see, so a module cannot attach its work to another module's timeline
	// and inherit that module's attribution.
	Parent SpanID
	Kind   SpanKind
	Name   string
}

// TraceFilter selects spans to query.
type TraceFilter struct {
	// Trace narrows to one request. Empty means any.
	Trace TraceID
	// Kind narrows to one span kind. Empty means any.
	Kind SpanKind
	// PID narrows to one module. Zero means any.
	PID PID
	// Abandoned, when true, returns only spans the kernel closed at teardown. This
	// is the query that finds modules that leak work.
	Abandoned bool
	// MinNanos returns only spans at least this long, for finding slow stages.
	MinNanos int64
	// Limit caps the result, newest first.
	Limit int
}

// ElapsedNanos is the span's duration on the kernel clock.
func (s Span) ElapsedNanos() int64 {
	if s.End <= s.Start {
		return 0
	}
	return s.End - s.Start
}
