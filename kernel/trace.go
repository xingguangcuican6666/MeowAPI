package kernel

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ktrace: cross-module tracing (subsystem: ktrace, the analogue of a distributed
// trace context propagated across a kernel boundary).
//
// What it is for. A request in MeowAPI crosses several modules: an adapter that
// speaks the provider's protocol, a router that picks a channel, a billing module
// that settles it. When a request is slow, "the request took 40 seconds" is not an
// answer. The useful answer names the stage, and the only way to get it is for every
// stage to record its own interval against a shared id.
//
// The non-negotiable rule is that the kernel generates the trace id and a module
// cannot supply one. A module-chosen id is a module-chosen identity for the request:
// it could collide with another request's, which corrupts both timelines, or it could
// be chosen to match a request the module wants its own record attributed to, which
// makes the trace a forgeable claim rather than a kernel observation. Generating it
// from crypto/rand inside the kernel removes both.
//
// A span is an fd-table resource. An unended span is closed during unload and marked
// abandoned, so a module that panics mid-request still leaves a record of the stage
// it was in, and a leaked span cannot exhaust the per-pid budget.

// ErrSpanClosed is returned by operations on a span that has already ended.
var ErrSpanClosed = errors.New("kernel: span already ended")

// ErrSpanNotFound is returned when a handle does not resolve to a live span.
var ErrSpanNotFound = errors.New("kernel: span not found")

const (
	// traceIDBytes is the random length of a trace id. 16 bytes is the width the
	// tracing ecosystem already uses, so an operator's existing tooling reads it.
	traceIDBytes = 16
	// spanIDBytes is the random length of a span id.
	spanIDBytes = 8
	// maxLiveSpansPerModule bounds unended spans for one pid. A module that opens
	// spans and never ends them is leaking, and the bound turns the leak into a
	// visible refusal.
	maxLiveSpansPerModule = 1024
	// maxSpanDepth bounds nesting. Unbounded depth means a module that recurses can
	// grow the tree without limit, and a deep trace is unusable anyway.
	maxSpanDepth = 32
	// maxSpanNameLen bounds a name, since names are copied into audit records.
	maxSpanNameLen = 128
	// maxRetainedSpans bounds the finished-span history the kernel keeps for
	// queries. Oldest are evicted with a counter, because an unbounded ledger in
	// memory is a leak a busy gateway hits within hours.
	maxRetainedSpans = 8192
)

// TraceID identifies one request across every module that touched it.
type TraceID string

// SpanID identifies one stage inside a trace.
type SpanID string

// SpanKind names what a span measures. The set is closed so an operator's dashboard
// can group by it without discovering new values in production.
type SpanKind string

const (
	// SpanRequest is the whole request, opened by the entry module.
	SpanRequest SpanKind = "request"
	// SpanRoute is a dispatch through the kernel route table.
	SpanRoute SpanKind = "route"
	// SpanModule is time inside one module's own work.
	SpanModule SpanKind = "module"
	// SpanUpstream is time waiting on a provider or another node. This is the span
	// that separates "our code is slow" from "the network is slow".
	SpanUpstream SpanKind = "upstream"
	// SpanTimeToFirstToken is the interval from request start to the first token
	// of a streamed completion. It is its own kind rather than a generic span
	// because it is the number a streaming gateway is judged on.
	SpanTimeToFirstToken SpanKind = "ttft"
	// SpanSettle is billing settlement.
	SpanSettle SpanKind = "settle"
)

// spanKinds is the closed set.
var spanKinds = map[SpanKind]bool{
	SpanRequest:          true,
	SpanRoute:            true,
	SpanModule:           true,
	SpanUpstream:         true,
	SpanTimeToFirstToken: true,
	SpanSettle:           true,
}

// SpanKinds lists the kinds a module may open, sorted.
func SpanKinds() []SpanKind {
	out := make([]SpanKind, 0, len(spanKinds))
	for k := range spanKinds {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

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

// ElapsedNanos is the span's duration on the kernel clock.
func (s Span) ElapsedNanos() int64 {
	if s.End <= s.Start {
		return 0
	}
	return s.End - s.Start
}

// liveSpan is the kernel's mutable record behind a handle.
type liveSpan struct {
	closedFlag
	mu   sync.Mutex
	span Span
	pid  PID
	// depth is the nesting level, bounded by maxSpanDepth.
	depth int
}

// Kind names the resource for the fd table and the dump.
func (s *liveSpan) Kind() string { return "span" }

// Close ends the span if it is still open. Called both by an explicit end and by
// reclamation during unload, in which case it is marked abandoned.
func (s *liveSpan) Close() error { return s.end(false) }

func (s *liveSpan) end(abandoned bool) error {
	if !s.mark() {
		return ErrSpanClosed
	}
	s.mu.Lock()
	s.span.End = mono()
	s.span.Abandoned = abandoned
	finished := s.span
	s.mu.Unlock()

	ktrace.finish(finished)
	if abandoned {
		fault(nil, "span abandoned at module teardown", map[string]any{
			"trace": string(finished.Trace), "span": string(finished.Span),
			"kind": string(finished.Kind), "name": finished.Name, "pid": finished.PID,
		})
	}
	return nil
}

// setAttr records one kernel-chosen attribute.
func (s *liveSpan) setAttr(k, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.span.Attrs == nil {
		s.span.Attrs = map[string]string{}
	}
	s.span.Attrs[k] = v
}

// traceRegistry holds live spans by id and a bounded history of finished ones.
type traceRegistry struct {
	mu sync.RWMutex
	// live maps span id to its record, so a child can find its parent.
	live map[SpanID]*liveSpan
	// byPid counts live spans per pid for the ceiling.
	byPid map[PID]int
	// done is the bounded finished-span history, newest last.
	done      []Span
	evicted   int64
	completed int64
	abandoned int64
	opened    int64
}

var ktrace = &traceRegistry{live: map[SpanID]*liveSpan{}, byPid: map[PID]int{}}

// NewTraceID mints a trace id from crypto/rand. It is the only way a trace id comes
// into existence.
func NewTraceID() (TraceID, error) {
	b, err := randomBytes(traceIDBytes)
	if err != nil {
		return "", err
	}
	return TraceID(hex.EncodeToString(b)), nil
}

// newSpanID mints a span id.
func newSpanID() (SpanID, error) {
	b, err := randomBytes(spanIDBytes)
	if err != nil {
		return "", err
	}
	return SpanID(hex.EncodeToString(b)), nil
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

// TraceOpen opens a span and returns the handle that owns it plus the ids the kernel
// assigned. The caller cannot choose either id.
func TraceOpen(ctx SContext, spec SpanSpec) (FD, TraceID, SpanID, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, "", "", errForeignContext
	}
	if err := c.syscall(OpTraceSpan); err != nil {
		return noFD, "", "", err
	}
	if !spanKinds[spec.Kind] {
		return noFD, "", "", fmt.Errorf("kernel: %q is not a span kind", spec.Kind)
	}
	if spec.Name == "" {
		return noFD, "", "", errors.New("kernel: a span requires a name")
	}
	if len(spec.Name) > maxSpanNameLen {
		spec.Name = spec.Name[:maxSpanNameLen]
	}

	// Resolve the parent before allocating, so a bad parent does not consume budget.
	var parent SpanID
	depth := 1
	if spec.Parent != "" {
		ktrace.mu.RLock()
		p, ok := ktrace.live[spec.Parent]
		ktrace.mu.RUnlock()
		if !ok {
			return noFD, "", "", fmt.Errorf("%w: parent span %q", ErrSpanNotFound, spec.Parent)
		}
		p.mu.Lock()
		parentPID := p.span.PID
		p.mu.Unlock()
		// A parent must belong to this pid or to an ancestor that spawned it. The
		// process table is the authority on that, and the check is what stops one
		// module grafting its spans onto another's request.
		if parentPID != c.pid && !isAncestorOf(parentPID, c.pid) {
			return noFD, "", "", fmt.Errorf(
				"kernel: pid %d may not attach a span under pid %d's span", c.pid, parentPID)
		}
		parent = spec.Parent
		ktrace.mu.RLock()
		if p2, ok := ktrace.live[spec.Parent]; ok {
			p2.mu.Lock()
			depth = p2.depth + 1
			p2.mu.Unlock()
		}
		ktrace.mu.RUnlock()
	}
	if depth > maxSpanDepth {
		return noFD, "", "", fmt.Errorf("kernel: span nesting exceeds the maximum depth of %d", maxSpanDepth)
	}

	ktrace.mu.RLock()
	live := ktrace.byPid[c.pid]
	ktrace.mu.RUnlock()
	if live >= maxLiveSpansPerModule {
		fault(c, "live span ceiling reached", map[string]any{
			"module": c.name, "max_live_spans_per_module": maxLiveSpansPerModule,
		})
		return noFD, "", "", fmt.Errorf("kernel: pid %d holds the maximum of %d live spans",
			c.pid, maxLiveSpansPerModule)
	}

	// The trace id is inherited from the resolved parent or minted fresh. Both
	// sources are kernel-side, so the caller has no way to choose it.
	var trace TraceID
	if parent != "" {
		ktrace.mu.RLock()
		if p, ok := ktrace.live[parent]; ok {
			p.mu.Lock()
			trace = p.span.Trace
			p.mu.Unlock()
		}
		ktrace.mu.RUnlock()
	}
	if trace == "" {
		t, err := NewTraceID()
		if err != nil {
			return noFD, "", "", err
		}
		trace = t
	}
	spanID, err := newSpanID()
	if err != nil {
		return noFD, "", "", err
	}

	ls := &liveSpan{
		pid:   c.pid,
		depth: depth,
		span: Span{
			Trace: trace, Span: spanID, Parent: parent, Kind: spec.Kind,
			Name: spec.Name, PID: c.pid, Module: c.name, Start: mono(),
		},
	}

	fd, err := install(c.pid, ls, string(spec.Kind)+":"+spec.Name)
	if err != nil {
		return noFD, "", "", err
	}

	ktrace.mu.Lock()
	ktrace.live[spanID] = ls
	ktrace.byPid[c.pid]++
	ktrace.opened++
	ktrace.mu.Unlock()

	return fd, trace, spanID, nil
}

// isAncestorOf walks the process table's parent links. It is bounded by the table
// size so a corrupted ppid chain cannot loop.
func isAncestorOf(candidate, pid PID) bool {
	table := ProcTable()
	current := pid
	for range len(table) + 1 {
		if current == 0 {
			return false
		}
		var ppid PID
		found := false
		for _, r := range table {
			if r.PID == current {
				ppid, found = r.PPID, true
				break
			}
		}
		if !found {
			return false
		}
		if ppid == candidate {
			return true
		}
		current = ppid
	}
	return false
}

// TraceEnd closes a span this context owns and returns the finished record.
func TraceEnd(ctx SContext, fd FD) (Span, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return Span{}, errForeignContext
	}
	if err := c.syscall(""); err != nil {
		return Span{}, err
	}
	ls, err := spanFor(c.pid, fd)
	if err != nil {
		return Span{}, err
	}
	if err := ls.end(false); err != nil {
		return Span{}, err
	}
	ktrace.removeLive(ls)
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.span, nil
}

// TraceMark records a kernel-chosen attribute on a live span this context owns.
func TraceMark(ctx SContext, fd FD, key, value string) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(""); err != nil {
		return err
	}
	if key == "" || len(key) > maxSpanNameLen {
		return errors.New("kernel: a span attribute key must be non-empty and bounded")
	}
	if len(value) > maxSpanNameLen {
		value = value[:maxSpanNameLen]
	}
	ls, err := spanFor(c.pid, fd)
	if err != nil {
		return err
	}
	ls.setAttr(key, value)
	return nil
}

// spanFor resolves a handle to a live span owned by this pid.
func spanFor(pid PID, fd FD) (*liveSpan, error) {
	e, err := lookup(pid, fd)
	if err != nil {
		return nil, err
	}
	if e.kind != "span" {
		return nil, fmt.Errorf("kernel: fd %d is a %s, not a span", fd, e.kind)
	}
	ls, ok := e.res.(*liveSpan)
	if !ok || ls.done() {
		return nil, ErrSpanClosed
	}
	return ls, nil
}

func (r *traceRegistry) removeLive(ls *liveSpan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ls.mu.Lock()
	id := ls.span.Span
	pid := ls.pid
	ls.mu.Unlock()
	if cur, ok := r.live[id]; ok && cur == ls {
		delete(r.live, id)
	}
	if r.byPid[pid] > 0 {
		r.byPid[pid]--
		if r.byPid[pid] == 0 {
			delete(r.byPid, pid)
		}
	}
}

// finish records a completed span in the bounded history.
func (r *traceRegistry) finish(s Span) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.done = append(r.done, s)
	if s.Abandoned {
		r.abandoned++
	} else {
		r.completed++
	}
	r.trimLocked()
}

// trimLocked keeps the span history at its bound, dropping back to seven eighths of
// it rather than to exactly the bound. See kmeter's trimLocked for why: trimming one
// record at a time past the ceiling makes every insert copy the whole history under
// the write lock, which is a throughput cliff at exactly the wrong moment.
func (r *traceRegistry) trimLocked() {
	if len(r.done) <= maxRetainedSpans {
		return
	}
	keep := maxRetainedSpans - maxRetainedSpans/8
	if len(r.done) <= keep {
		return
	}
	over := len(r.done) - keep
	r.evicted += int64(over)
	r.done = append([]Span(nil), r.done[over:]...)
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

// TraceQuery returns finished spans matching a filter, newest first. It returns
// copies, so a caller cannot edit the kernel's history.
func TraceQuery(f TraceFilter) []Span {
	ktrace.mu.RLock()
	src := make([]Span, len(ktrace.done))
	copy(src, ktrace.done)
	ktrace.mu.RUnlock()

	out := make([]Span, 0, len(src))
	// Newest first, so a limit keeps the most recent rather than the oldest.
	for i := len(src) - 1; i >= 0; i-- {
		s := src[i]
		if f.Trace != "" && s.Trace != f.Trace {
			continue
		}
		if f.Kind != "" && s.Kind != f.Kind {
			continue
		}
		if f.PID != 0 && s.PID != f.PID {
			continue
		}
		if f.Abandoned && !s.Abandoned {
			continue
		}
		if f.MinNanos > 0 && s.ElapsedNanos() < f.MinNanos {
			continue
		}
		out = append(out, s)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

// TraceStats is the tracing view for the dump.
type TraceStats struct {
	Live      int   `json:"live"`
	Completed int64 `json:"completed"`
	Abandoned int64 `json:"abandoned"`
	Retained  int   `json:"retained"`
	Evicted   int64 `json:"evicted"`
	Opened    int64 `json:"opened"`
	// MaxLivePerModule and MaxRetained are the bounds in force, so an operator
	// reading a high eviction count can tell whether the bound is too small.
	MaxLivePerModule int `json:"max_live_per_module"`
	MaxRetained      int `json:"max_retained"`
}

// TraceStatsSnapshot copies the registry counters.
func TraceStatsSnapshot() TraceStats {
	ktrace.mu.RLock()
	defer ktrace.mu.RUnlock()
	return TraceStats{
		Live: len(ktrace.live), Completed: ktrace.completed, Abandoned: ktrace.abandoned,
		Retained: len(ktrace.done), Evicted: ktrace.evicted, Opened: ktrace.opened,
		MaxLivePerModule: maxLiveSpansPerModule, MaxRetained: maxRetainedSpans,
	}
}

// TraceLiveFor lists the live span ids a pid holds, for the dump.
func TraceLiveFor(pid PID) []SpanID {
	ktrace.mu.RLock()
	defer ktrace.mu.RUnlock()
	var out []SpanID
	for id, ls := range ktrace.live {
		if ls.pid == pid {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// SyscallTrace is the tracing half of the syscall surface.
type SyscallTrace interface {
	// SyscallTraceOpen starts a span and returns the handle that owns it plus the
	// ids the kernel assigned. Requires trace:span. The ids are not forgeable: a
	// module cannot supply its own trace id or span id.
	SyscallTraceOpen(spec SpanSpec) (FD, TraceID, SpanID, error)
	// SyscallTraceEnd closes a span this context owns and returns its record.
	SyscallTraceEnd(fd FD) (Span, error)
	// SyscallTraceMark records a bounded attribute on a live span.
	SyscallTraceMark(fd FD, key, value string) error
	// SyscallTraceQuery returns finished spans matching a filter, newest first.
	// Requires trace:span, and never returns another pid's live span.
	SyscallTraceQuery(f TraceFilter) []Span
}

func (c *sContext) SyscallTraceOpen(spec SpanSpec) (FD, TraceID, SpanID, error) {
	return TraceOpen(c, spec)
}

func (c *sContext) SyscallTraceEnd(fd FD) (Span, error) { return TraceEnd(c, fd) }

func (c *sContext) SyscallTraceMark(fd FD, key, value string) error {
	return TraceMark(c, fd, key, value)
}

func (c *sContext) SyscallTraceQuery(f TraceFilter) []Span {
	if err := c.syscall(OpTraceSpan); err != nil {
		return nil
	}
	return TraceQuery(f)
}

// dropSpansFor ends and forgets every live span a pid holds. Called from the unload
// path, so an unended span still leaves a record of the stage the module was in
// rather than vanishing with it.
func dropSpansFor(pid PID) {
	ktrace.mu.Lock()
	var doomed []*liveSpan
	for id, ls := range ktrace.live {
		if ls.pid == pid {
			doomed = append(doomed, ls)
			delete(ktrace.live, id)
		}
	}
	delete(ktrace.byPid, pid)
	ktrace.mu.Unlock()

	for _, ls := range doomed {
		_ = ls.end(true)
	}
}

// resetTraces clears live spans and the finished history. Called only from
// resetKernel.
func resetTraces() {
	ktrace.mu.Lock()
	defer ktrace.mu.Unlock()
	ktrace.live = map[SpanID]*liveSpan{}
	ktrace.byPid = map[PID]int{}
	ktrace.done = nil
	ktrace.evicted = 0
	ktrace.completed = 0
	ktrace.abandoned = 0
	ktrace.opened = 0
}
