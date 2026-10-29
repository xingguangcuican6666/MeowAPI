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

package kernel

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// kservice: the route table and the capability bus (subsystem: kservice, the
// analogue of a service manager's D-Bus name registry plus a Binder dispatch).
//
// What it is for. Everything in MeowAPI is a module, so the moment two modules need
// to talk there has to be a way to address one from the other. The naive answer is
// for a module to hold a Go function value registered by another module, and that
// answer destroys the architecture: the caller's goroutine runs the callee's code
// under the caller's own authority, so a privileged caller lends its grants to
// whoever it calls, and nothing records that a call happened at all.
//
// The rule this file enforces is that a dispatch runs under the handler module's own
// context and its own grants, never under the caller's. That single choice is what
// makes the route table a security boundary rather than a convenience. A module with
// secret:use that calls a route registered by a module without it does not thereby
// give that module access to secrets; the handler runs as itself and is refused.
//
// Consequences that follow from it, each of which is asserted in tests:
//
//   - One handler per path. A second registration of the same path is refused rather
//     than replacing the first, because silent replacement is how a module takes over
//     another module's route.
//   - A path must be absolute, normalized, and free of "..". A path that traverses is
//     a path that can be made to alias another route.
//   - A module may only register paths its manifest declares, so the route table is
//     bounded by what was reviewed.
//   - Unloading a module unregisters its routes, and a call to a route whose module is
//     gone fails with a typed error rather than panicking on a nil handler.
//   - Every dispatch is recorded on the audit chain with the trace id, so a request
//     can be followed end to end across module boundaries.

// ErrRouteNotFound is returned when no module serves a path. It is typed so the
// gateway can answer 404 rather than 500.
var ErrRouteNotFound = errors.New("kernel: no module serves this route")

// ErrRouteGone is returned when a route's module was unloaded between lookup and
// dispatch. It is distinct from ErrRouteNotFound because the correct responses
// differ: nothing ever served this path, versus something did and no longer exists.
var ErrRouteGone = errors.New("kernel: the module serving this route is gone")

// ErrRouteTaken is returned when a path is already registered.
var ErrRouteTaken = errors.New("kernel: route already registered")

// ErrRouteDenied is returned when a manifest does not declare a path.
var ErrRouteDenied = errors.New("kernel: route not declared in the manifest")

const (
	// maxRoutesPerModule bounds how many paths one module may serve.
	maxRoutesPerModule = 64
	// maxRoutePathLen bounds a path, since paths are copied into audit records.
	maxRoutePathLen = 256
	// maxCallPayloadBytes bounds one dispatched payload. A route call is an
	// in-process boundary, not a transport, and an unbounded payload here would let
	// one module pin the kernel's memory through another.
	maxCallPayloadBytes = 8 * 1024 * 1024
)

// RouteHandler serves one path. It runs on the handler module's own goroutine and
// under the handler module's own context, which is the whole point of the design.
type RouteHandler func(ctx SContext, req RouteRequest) (RouteResponse, error)

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

// route is one registered path.
type route struct {
	path    string
	pid     PID
	module  string
	handler RouteHandler
	// registered is a Mono() reading, for the dump.
	registered int64
	calls      int64
	failures   int64
}

// routeTable holds the registry.
type routeTable struct {
	mu     sync.RWMutex
	byPath map[string]*route
	byPid  map[PID]map[string]bool
	calls  int64
	denied int64
	misses int64
}

var kroutes = &routeTable{byPath: map[string]*route{}, byPid: map[PID]map[string]bool{}}

// normalizeRoutePath validates and normalizes a path. It refuses the forms that
// would make the table ambiguous or forgeable.
func normalizeRoutePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("kernel: a route path must not be empty")
	}
	if len(p) > maxRoutePathLen {
		return "", fmt.Errorf("kernel: route path longer than %d bytes", maxRoutePathLen)
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("kernel: route path %q must be absolute", p)
	}
	for _, r := range p {
		// Control characters and spaces are refused because a path is written into
		// audit lines and console output verbatim, and a path carrying a newline
		// can forge a log line.
		if r <= 0x20 || r >= 0x7f {
			return "", fmt.Errorf("kernel: route path %q contains a control or non-ASCII character", p)
		}
	}
	if strings.Contains(p, "//") {
		return "", fmt.Errorf("kernel: route path %q contains an empty segment", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("kernel: route path %q traverses above the root", p)
		}
		if seg == "." {
			return "", fmt.Errorf("kernel: route path %q contains a relative segment", p)
		}
	}
	// The path is already normalized by the checks above: absolute, no empty
	// segments, no . or .., so a cleaning pass would be a no-op. Asserting that is
	// cheaper and clearer than calling path.Clean and comparing.
	if strings.HasSuffix(p, "/") && p != "/" {
		return "", fmt.Errorf("kernel: route path %q must not end in a slash", p)
	}
	return p, nil
}

// RouteDeclare lists the paths a manifest permits a module to register. It lives here
// rather than in manifest.go because the route table is the authority on what a path
// is, and a declaration checked against a different normalizer than the registry
// would be a rule with a gap in it.
//
// An empty declaration means the module serves no routes. There is no wildcard: a
// module that wants to serve everything has to say everything, because a wildcard
// would let one module claim a path another module was about to register.
func RouteDeclare(m Manifest) []string {
	var out []string
	for _, p := range m.ServeRoutes {
		if n, err := normalizeRoutePath(p); err == nil {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// RouteRegister adds a path to the table under the caller's own pid.
func RouteRegister(ctx SContext, path string, h RouteHandler) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpRouteRegister); err != nil {
		return err
	}
	if h == nil {
		return errors.New("kernel: a route requires a handler")
	}

	norm, err := normalizeRoutePath(path)
	if err != nil {
		kroutes.refuse(c, "invalid route path", map[string]any{"path": path, "error": err.Error()})
		return err
	}

	// The manifest is the authority on what this module may serve. Checking after
	// normalization means a declaration and a registration are compared in the same
	// form, so a path cannot slip through by differing in spelling.
	manifest, live := manifestOf(c.pid)
	if !live {
		return fmt.Errorf("kernel: pid %d is not a loaded module", c.pid)
	}
	declared := RouteDeclare(manifest)
	if !containsString(declared, norm) {
		kroutes.refuse(c, "route not declared in the manifest", map[string]any{"path": norm})
		return fmt.Errorf("%w: %q", ErrRouteDenied, norm)
	}
	// The instance filter is consulted on the NORMALIZED path, the same string the
	// declaration was compared against. Filtering the raw path would let a spelling
	// difference decide the answer, which is the same reason the declaration check runs
	// after normalization.
	if err := SeccompAllow(c, OpRouteRegister, norm); err != nil {
		kroutes.refuse(c, "route outside the instance filter", map[string]any{"path": norm})
		return err
	}

	kroutes.mu.Lock()
	if len(kroutes.byPid[c.pid]) >= maxRoutesPerModule {
		kroutes.mu.Unlock()
		kroutes.refuse(c, "route ceiling reached", map[string]any{
			"path": norm, "max_routes_per_module": maxRoutesPerModule,
		})
		return fmt.Errorf("kernel: pid %d serves the maximum of %d routes", c.pid, maxRoutesPerModule)
	}
	if _, taken := kroutes.byPath[norm]; taken {
		kroutes.mu.Unlock()
		// Refusing rather than replacing is the rule. A silent replacement would
		// let a module loaded later take over an earlier module's route, and the
		// earlier module would keep believing it served that path.
		kroutes.refuse(c, "route already registered", map[string]any{"path": norm})
		return fmt.Errorf("%w: %q", ErrRouteTaken, norm)
	}

	kroutes.byPath[norm] = &route{
		path: norm, pid: c.pid, module: c.name, handler: h, registered: mono(),
	}
	if kroutes.byPid[c.pid] == nil {
		kroutes.byPid[c.pid] = map[string]bool{}
	}
	kroutes.byPid[c.pid][norm] = true
	kroutes.mu.Unlock()

	kconsole.Emit(LogDebug, c.pid, c.dom, "route registered", map[string]any{"path": norm})
	kaudit.record(AuditPolicy, c, "route registered", map[string]any{"path": norm})
	return nil
}

func (t *routeTable) refuse(c *sContext, msg string, fields map[string]any) {
	t.mu.Lock()
	t.denied++
	t.mu.Unlock()
	fault(c, msg, fields)
	kaudit.record(AuditReject, c, msg, fields)
}

// RouteCall dispatches one call. The handler runs under its own context.
//
// The trace is opened by the kernel here rather than left to the caller, so a
// dispatch is always on a timeline even if the calling module never opened a span.
func RouteCall(ctx SContext, req RouteRequest) (RouteResponse, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return RouteResponse{}, errForeignContext
	}
	if err := c.syscall(OpRouteCall); err != nil {
		return RouteResponse{}, err
	}

	norm, err := normalizeRoutePath(req.Path)
	if err != nil {
		kroutes.mu.Lock()
		kroutes.misses++
		kroutes.mu.Unlock()
		return RouteResponse{}, err
	}
	if len(req.Payload) > maxCallPayloadBytes {
		return RouteResponse{}, fmt.Errorf(
			"kernel: route payload of %d bytes exceeds the ceiling %d", len(req.Payload), maxCallPayloadBytes)
	}

	kroutes.mu.RLock()
	r, ok := kroutes.byPath[norm]
	kroutes.mu.RUnlock()
	if !ok {
		kroutes.mu.Lock()
		kroutes.misses++
		kroutes.mu.Unlock()
		return RouteResponse{}, fmt.Errorf("%w: %q", ErrRouteNotFound, norm)
	}

	// The handler's context, not the caller's. This is the line that makes the
	// route table a boundary: the handler's grants decide what the handler may do.
	handlerCtx := moduleContextOf(r.pid)
	if handlerCtx == nil {
		kroutes.mu.Lock()
		kroutes.misses++
		kroutes.mu.Unlock()
		return RouteResponse{}, fmt.Errorf("%w: %q was served by pid %d", ErrRouteGone, norm, r.pid)
	}

	// Copy the payload in, so the handler cannot retain a slice of the caller's
	// buffer and observe the caller mutating it afterwards.
	payload := append([]byte(nil), req.Payload...)

	trace := req.Trace
	if trace == "" {
		t, err := NewTraceID()
		if err != nil {
			return RouteResponse{}, err
		}
		trace = t
	}

	start := mono()
	resp, callErr := dispatchRoute(r, handlerCtx, RouteRequest{
		Path: norm, CallerPID: c.pid, CallerModule: c.name,
		Trace: trace, Method: req.Method, Payload: payload,
	})
	elapsed := mono() - start

	kroutes.mu.Lock()
	kroutes.calls++
	if live, ok := kroutes.byPath[norm]; ok && live == r {
		live.calls++
		if callErr != nil {
			live.failures++
		}
	}
	kroutes.mu.Unlock()

	fields := map[string]any{
		"path": norm, "caller_pid": c.pid, "handler_pid": r.pid,
		"elapsed_nanos": elapsed, "trace": string(trace),
	}
	if callErr != nil {
		fields["error"] = callErr.Error()
		kaudit.record(AuditRequest, c, "route call failed", fields)
		// Copy the payload out on the way back too, so the caller cannot hold a
		// slice into a buffer the handler may reuse.
		return RouteResponse{}, callErr
	}
	kaudit.record(AuditRequest, c, "route call", fields)

	out := RouteResponse{Status: resp.Status, Payload: append([]byte(nil), resp.Payload...)}
	if len(resp.Header) > 0 {
		out.Header = make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			out.Header[k] = v
		}
	}
	return out, nil
}

// dispatchRoute runs one handler with panic containment and CPU accounting. A
// handler that panics must not take the kernel down, and the time it burned is
// charged to the handler's pid, not the caller's, because the handler is the module
// that ran the code.
func dispatchRoute(r *route, handlerCtx *sContext, req RouteRequest) (resp RouteResponse, err error) {
	start := mono()
	defer func() {
		wall := mono() - start
		exhausted, after := kcpu.charge(handlerCtx.pid, wall)
		if exhausted {
			fault(handlerCtx, "cpu budget exhausted during a route call", map[string]any{
				"path": req.Path, "cpu_nanos_estimate": after.CPUNanos, "budget": after.Budget,
			})
			kaudit.record(AuditEscalation, handlerCtx, "cpu budget exhausted", map[string]any{
				"path": req.Path, "cpu_nanos_estimate": after.CPUNanos,
			})
		}
	}()
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("kernel: route %q panicked: %v", req.Path, rec)
			fault(handlerCtx, "route handler panicked", map[string]any{
				"path": req.Path, "panic": fmt.Sprint(rec),
			})
			kaudit.record(AuditPanic, handlerCtx, "route handler panicked", map[string]any{
				"path": req.Path, "panic": fmt.Sprint(rec), "caller_pid": req.CallerPID,
			})
		}
	}()

	// A module in drain stops accepting new work. Finishing what is already in
	// flight is drain's whole meaning, so the refusal happens before the handler
	// runs rather than inside it.
	if draining, _ := SignalState(handlerCtx.pid); draining {
		return RouteResponse{}, fmt.Errorf("%w: pid %d is draining", ErrRouteGone, handlerCtx.pid)
	}

	return r.handler(handlerCtx, req)
}

// RouteInfo describes one registered route for the dump.
type RouteInfo struct {
	Path       string `json:"path"`
	PID        PID    `json:"pid"`
	Module     string `json:"module"`
	Registered int64  `json:"registered"`
	Calls      int64  `json:"calls"`
	Failures   int64  `json:"failures"`
}

// RouteTable lists every registered route, sorted by path.
func RouteTable() []RouteInfo {
	kroutes.mu.RLock()
	paths := make([]string, 0, len(kroutes.byPath))
	for p := range kroutes.byPath {
		paths = append(paths, p)
	}
	kroutes.mu.RUnlock()
	sort.Strings(paths)

	out := make([]RouteInfo, 0, len(paths))
	kroutes.mu.RLock()
	for _, p := range paths {
		r, ok := kroutes.byPath[p]
		if !ok {
			continue
		}
		out = append(out, RouteInfo{
			Path: r.path, PID: r.pid, Module: r.module,
			Registered: r.registered, Calls: r.calls, Failures: r.failures,
		})
	}
	kroutes.mu.RUnlock()
	return out
}

// RouteStats is the registry view for the dump.
type RouteStats struct {
	Routes       int   `json:"routes"`
	Calls        int64 `json:"calls"`
	Misses       int64 `json:"misses"`
	Denied       int64 `json:"denied"`
	MaxPerModule int   `json:"max_per_module"`
}

// RouteStatsSnapshot copies the counters.
func RouteStatsSnapshot() RouteStats {
	kroutes.mu.RLock()
	defer kroutes.mu.RUnlock()
	return RouteStats{
		Routes: len(kroutes.byPath), Calls: kroutes.calls,
		Misses: kroutes.misses, Denied: kroutes.denied,
		MaxPerModule: maxRoutesPerModule,
	}
}

// unregisterRoutesFor drops every route a pid served. Called from the unload path,
// so a route cannot outlive the module that could handle it.
func unregisterRoutesFor(pid PID) {
	kroutes.mu.Lock()
	paths := make([]string, 0, len(kroutes.byPid[pid]))
	for p := range kroutes.byPid[pid] {
		paths = append(paths, p)
	}
	for _, p := range paths {
		if r, ok := kroutes.byPath[p]; ok && r.pid == pid {
			delete(kroutes.byPath, p)
		}
	}
	delete(kroutes.byPid, pid)
	kroutes.mu.Unlock()

	if len(paths) > 0 {
		sort.Strings(paths)
		kconsole.Emit(LogDebug, pid, DomainPlugin, "routes unregistered on unload", map[string]any{
			"pid": pid, "paths": paths,
		})
	}
}

// SyscallRoute is the routing half of the syscall surface.
type SyscallRoute interface {
	// SyscallRouteRegister serves a path from this module. Requires route:register
	// and a manifest declaration of that exact path. A second registration of the
	// same path is refused rather than replacing the first.
	SyscallRouteRegister(path string, h RouteHandler) error
	// SyscallRouteCall dispatches one call. Requires route:call. The handler runs
	// under its own context and its own grants, never under the caller's.
	SyscallRouteCall(req RouteRequest) (RouteResponse, error)
	// SyscallRoutes lists the paths this module serves. Requires no operation, and
	// never lists another module's routes.
	SyscallRoutes() []string
}

func (c *sContext) SyscallRouteRegister(path string, h RouteHandler) error {
	return RouteRegister(c, path, h)
}

func (c *sContext) SyscallRouteCall(req RouteRequest) (RouteResponse, error) {
	return RouteCall(c, req)
}

func (c *sContext) SyscallRoutes() []string {
	kroutes.mu.RLock()
	defer kroutes.mu.RUnlock()
	own := make([]string, 0, len(kroutes.byPid[c.pid]))
	for p := range kroutes.byPid[c.pid] {
		own = append(own, p)
	}
	sort.Strings(own)
	return own
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// resetRoutes clears the registry. Called only from resetKernel.
func resetRoutes() {
	kroutes.mu.Lock()
	defer kroutes.mu.Unlock()
	kroutes.byPath = map[string]*route{}
	kroutes.byPid = map[PID]map[string]bool{}
	kroutes.calls = 0
	kroutes.misses = 0
	kroutes.denied = 0
}
