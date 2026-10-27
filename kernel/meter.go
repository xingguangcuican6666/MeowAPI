package kernel

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// kmeter: request-scoped metering (subsystem: kmeter, the analogue of a call-detail
// record).
//
// usage.go already counts totals per pid with a closed set of kinds and a ceiling per
// event. That answers "how much did this module consume" but not "how much did this
// request consume", and the second question is the one a gateway has to answer: a
// slow request, a disputed invoice, a customer asking why a call cost what it cost.
// kmeter is the per-request view, keyed by a request id the kernel assigns.
//
// The boundary that matters, and the reason this file has no pricing in it: the
// kernel records the fact that a request was served and what it consumed. It never
// prices it. There is no unit price, no ratio, no discount and no multiplier field
// anywhere in this file, and the absence is the control. A module cannot ask the
// kernel to apply a multiplier, because no such call exists, and an operator reading
// a meter record is reading an observation rather than a calculation the kernel
// endorsed. A module that needs pricing keeps its own books from these records and
// owns the arithmetic.
//
// The request id is kernel-assigned for the same reason a trace id is: a
// module-chosen id is a module-chosen identity for a billable event, and one that
// could collide or be chosen deliberately makes the ledger a claim rather than a
// record.

// ErrRequestNotFound is returned when a request id is not in the ledger.
var ErrRequestNotFound = errors.New("kernel: request not in the meter ledger")

// ErrMeterFull is returned when the ledger is at its ceiling and a caller asked for
// a reservation rather than accepting eviction.
var ErrMeterFull = errors.New("kernel: meter ledger is full")

const (
	// maxRetainedRequests bounds the ledger. A busy gateway writes one record per
	// request, so an unbounded ledger is a leak that fills memory within hours.
	// Oldest records are evicted with a counter, because the alternative - refusing
	// to meter - would silently drop the fact that a request was served.
	maxRetainedRequests = 65536
	// maxRequestIDBytes is the random width of a request id.
	maxRequestIDBytes = 16
	// maxMeterLabelLen bounds the route and note strings copied into a record.
	maxMeterLabelLen = 256
)

// RequestID identifies one billable request. The kernel assigns it.
type RequestID string

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

// openRequest is the mutable kernel record behind a live request id.
type openRequest struct {
	closedFlag
	mu sync.Mutex
	r  MeterRecord
}

// meterLedger holds the live and retained records.
type meterLedger struct {
	mu sync.RWMutex
	// open holds in-flight requests by id.
	open map[RequestID]*openRequest
	// byPid counts in-flight requests per pid, so one module cannot hold the whole
	// ledger open.
	byPid map[PID]int
	// done is the finished ledger, oldest first.
	done      []MeterRecord
	evicted   int64
	recorded  int64
	abandoned int64
}

var kmeter = &meterLedger{open: map[RequestID]*openRequest{}, byPid: map[PID]int{}}

// NewRequestID mints a request id from crypto/rand.
func NewRequestID() (RequestID, error) {
	b, err := randomBytes(maxRequestIDBytes)
	if err != nil {
		return "", err
	}
	return RequestID(fmt.Sprintf("%x", b)), nil
}

// MeterOpen starts metering one request and returns its kernel-assigned id.
func MeterOpen(ctx SContext, trace TraceID, route string) (RequestID, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return "", errForeignContext
	}
	if err := c.syscall(OpMeterRecord); err != nil {
		return "", err
	}

	id, err := NewRequestID()
	if err != nil {
		return "", err
	}
	if len(route) > maxMeterLabelLen {
		route = route[:maxMeterLabelLen]
	}

	rec := &openRequest{r: MeterRecord{
		ID: id, Trace: trace, Route: route, PID: c.pid, Module: c.name, Opened: mono(),
	}}

	kmeter.mu.Lock()
	kmeter.open[id] = rec
	kmeter.byPid[c.pid]++
	kmeter.mu.Unlock()

	return id, nil
}

// MeterAdd records a usage fact against an open request.
//
// It goes through the same validation usage.go applies - a closed kind set and a
// per-event ceiling - so a meter record cannot carry a quantity the kernel would have
// refused to count. That matters because the record is what settlement reads: a fact
// that bypasses validation on the way in becomes an unbounded multiplier on the way
// out, which is the specific hole the upstream project left open.
func MeterAdd(ctx SContext, id RequestID, f UsageFact) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpMeterRecord); err != nil {
		return err
	}

	// Validate against the same closed kind set and per-event ceiling usage.go
	// applies, so a meter record cannot carry a quantity the kernel would have
	// refused to count. That matters because the record is what settlement reads: a
	// fact that bypasses validation on the way in becomes an unbounded multiplier on
	// the way out, which is the specific hole the upstream project left open.
	if err := validateMeterFact(f); err != nil {
		fault(c, "meter fact rejected", map[string]any{
			"request": string(id), "kind": string(f.Kind), "reason": err.Error(),
		})
		return err
	}

	rec, err := openRequestFor(c.pid, id)
	if err != nil {
		return err
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	switch f.Kind {
	case UsageTokensIn:
		rec.r.TokensIn += f.Quantity
	case UsageTokensOut:
		rec.r.TokensOut += f.Quantity
	case UsageRequests:
		rec.r.Requests += f.Quantity
	default:
		// validateMeterFact already refused anything outside the closed set, so
		// this branch is unreachable. It stays explicit rather than folded into a
		// default that accumulates, because a default that accumulates is exactly
		// the hole this file exists to not have.
		return &UsageError{Msg: fmt.Sprintf("unknown usage kind %q", f.Kind)}
	}
	return nil
}

// validateMeterFact applies the closed kind set and the per-event ceiling that
// usage.go enforces. It is separate from emitUsage because a meter fact is recorded
// against a request rather than against a pid total, but the validation must be
// identical: two paths into the same ledger cannot disagree on what a valid quantity
// is, or the stricter one becomes a way around the looser one.
func validateMeterFact(f UsageFact) error {
	spec, known := usageSpecs[f.Kind]
	if !known {
		return &UsageError{Msg: fmt.Sprintf("unknown usage kind %q", f.Kind)}
	}
	if f.Quantity < 0 {
		return &UsageError{Msg: fmt.Sprintf("negative quantity %d for %s", f.Quantity, f.Kind)}
	}
	if f.Quantity == 0 {
		return &UsageError{Msg: fmt.Sprintf("zero quantity for %s is not recorded", f.Kind)}
	}
	if f.Quantity > spec.ceiling {
		return &UsageError{Msg: fmt.Sprintf(
			"quantity %d exceeds the per-event ceiling %d for %s", f.Quantity, spec.ceiling, f.Kind)}
	}
	if len(f.Label) > maxUsageLabelLen {
		return &UsageError{Msg: fmt.Sprintf("label longer than %d bytes", maxUsageLabelLen)}
	}
	return nil
}

// MeterClose finishes a request, records its duration and moves it to the ledger.
func MeterClose(ctx SContext, id RequestID, status int) (MeterRecord, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return MeterRecord{}, errForeignContext
	}
	if err := c.syscall(OpMeterRecord); err != nil {
		return MeterRecord{}, err
	}

	rec, err := openRequestFor(c.pid, id)
	if err != nil {
		return MeterRecord{}, err
	}
	if !rec.mark() {
		return MeterRecord{}, fmt.Errorf("kernel: request %q was already closed", id)
	}

	rec.mu.Lock()
	rec.r.Closed = mono()
	rec.r.Status = status
	finished := rec.r
	rec.mu.Unlock()

	kmeter.finish(finished, false)
	return finished, nil
}

// MeterGet reads one retained record by id. Requires meter:read.
func MeterGet(ctx SContext, id RequestID) (MeterRecord, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return MeterRecord{}, errForeignContext
	}
	if err := c.syscall(OpMeterRead); err != nil {
		return MeterRecord{}, err
	}
	return meterLookup(id)
}

func meterLookup(id RequestID) (MeterRecord, error) {
	kmeter.mu.RLock()
	defer kmeter.mu.RUnlock()

	if rec, ok := kmeter.open[id]; ok {
		rec.mu.Lock()
		out := rec.r
		rec.mu.Unlock()
		return out, nil
	}
	for i := len(kmeter.done) - 1; i >= 0; i-- {
		if kmeter.done[i].ID == id {
			return kmeter.done[i], nil
		}
	}
	return MeterRecord{}, fmt.Errorf("%w: %q", ErrRequestNotFound, id)
}

// openRequestFor resolves an id to a live request owned by this pid. The pid check
// is what stops one module closing or padding another module's request.
func openRequestFor(pid PID, id RequestID) (*openRequest, error) {
	kmeter.mu.RLock()
	rec, ok := kmeter.open[id]
	kmeter.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q is not open", ErrRequestNotFound, id)
	}
	rec.mu.Lock()
	owner := rec.r.PID
	rec.mu.Unlock()
	if owner != pid {
		return nil, fmt.Errorf("kernel: pid %d may not meter request %q owned by pid %d", pid, id, owner)
	}
	return rec, nil
}

// finish moves a record into the bounded ledger.
func (l *meterLedger) finish(r MeterRecord, abandoned bool) {
	r.Abandoned = abandoned

	l.mu.Lock()
	defer l.mu.Unlock()

	if rec, ok := l.open[r.ID]; ok {
		rec.mu.Lock()
		pid := rec.r.PID
		rec.mu.Unlock()
		delete(l.open, r.ID)
		if l.byPid[pid] > 0 {
			l.byPid[pid]--
			if l.byPid[pid] == 0 {
				delete(l.byPid, pid)
			}
		}
	}

	l.done = append(l.done, r)
	if abandoned {
		l.abandoned++
	} else {
		l.recorded++
	}
	if over := len(l.done) - maxRetainedRequests; over > 0 {
		l.evicted += int64(over)
		l.done = append([]MeterRecord(nil), l.done[over:]...)
	}
}

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

// MeterQuery returns retained records matching a filter, newest first. Results are
// copies, so a caller cannot edit the ledger.
func MeterQuery(f MeterFilter) []MeterRecord {
	kmeter.mu.RLock()
	src := make([]MeterRecord, len(kmeter.done))
	copy(src, kmeter.done)
	kmeter.mu.RUnlock()

	out := make([]MeterRecord, 0, 64)
	for i := len(src) - 1; i >= 0; i-- {
		r := src[i]
		if f.Route != "" && r.Route != f.Route {
			continue
		}
		if f.PID != 0 && r.PID != f.PID {
			continue
		}
		if f.Caller != 0 && r.Caller != f.Caller {
			continue
		}
		if f.Trace != "" && r.Trace != f.Trace {
			continue
		}
		if f.Abandoned && !r.Abandoned {
			continue
		}
		if f.Since != 0 && r.Opened < f.Since {
			continue
		}
		out = append(out, r)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

// MeterTotals is the aggregate view of the retained ledger. It sums quantities only.
type MeterTotals struct {
	Requests  int   `json:"requests"`
	TokensIn  int64 `json:"tokens_in"`
	TokensOut int64 `json:"tokens_out"`
	// Abandoned counts records the kernel closed at teardown. A nonzero number
	// means some module is not closing its own requests, which is a defect worth
	// seeing rather than a rounding error.
	Abandoned int64 `json:"abandoned"`
	// Evicted counts records dropped from the bounded ledger, so a query that
	// returns nothing is distinguishable from one that returned nothing retained.
	Evicted int64 `json:"evicted"`
	// Retained and Open are the ledger's current size.
	Retained int `json:"retained"`
	Open     int `json:"open"`
}

// MeterTotalsSnapshot sums the retained ledger.
func MeterTotalsSnapshot() MeterTotals {
	kmeter.mu.RLock()
	src := make([]MeterRecord, len(kmeter.done))
	copy(src, kmeter.done)
	open := len(kmeter.open)
	evicted := kmeter.evicted
	abandoned := kmeter.abandoned
	kmeter.mu.RUnlock()

	t := MeterTotals{Retained: len(src), Open: open, Evicted: evicted, Abandoned: abandoned}
	for _, r := range src {
		t.Requests++
		t.TokensIn += r.TokensIn
		t.TokensOut += r.TokensOut
	}
	return t
}

// MeterMarkSettled records that a request's facts were handed to a settlement
// receipt. It requires receipt:issue, which no module domain holds, so the flag
// cannot be set by the module that benefits from setting it: a second settlement of
// the same request stays visible to whoever audits.
func MeterMarkSettled(ctx SContext, id RequestID) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	if err := c.syscall(OpReceiptIssue); err != nil {
		return err
	}

	kmeter.mu.Lock()
	defer kmeter.mu.Unlock()
	for i := range kmeter.done {
		if kmeter.done[i].ID == id {
			if kmeter.done[i].Settled {
				return fmt.Errorf("kernel: request %q was already settled", id)
			}
			kmeter.done[i].Settled = true
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrRequestNotFound, id)
}

// SyscallMeter is the request-metering half of the syscall surface. usage.go's
// SyscallMeter group covers the pid totals; this one covers the per-request view.
// Both are named SyscallMeter* by prefix, and the two groups are distinct interfaces
// so a subsystem can be wired without editing the other's file.
type SyscallRequest interface {
	// SyscallMeterOpen starts metering one request and returns the kernel-assigned
	// id. Requires meter:record.
	SyscallMeterOpen(trace TraceID, route string) (RequestID, error)
	// SyscallMeterAdd records a validated usage fact against an open request this
	// context owns. Requires meter:record.
	SyscallMeterAdd(id RequestID, f UsageFact) error
	// SyscallMeterClose finishes a request and returns its record. Requires
	// meter:record.
	SyscallMeterClose(id RequestID, status int) (MeterRecord, error)
	// SyscallMeterGet reads one record by id. Requires meter:read.
	SyscallMeterGet(id RequestID) (MeterRecord, error)
	// SyscallMeterQuery returns retained records matching a filter, newest first.
	// Requires meter:read.
	SyscallMeterQuery(f MeterFilter) []MeterRecord
}

func (c *sContext) SyscallMeterOpen(trace TraceID, route string) (RequestID, error) {
	return MeterOpen(c, trace, route)
}

func (c *sContext) SyscallMeterAdd(id RequestID, f UsageFact) error { return MeterAdd(c, id, f) }

func (c *sContext) SyscallMeterClose(id RequestID, status int) (MeterRecord, error) {
	return MeterClose(c, id, status)
}

func (c *sContext) SyscallMeterGet(id RequestID) (MeterRecord, error) { return MeterGet(c, id) }

func (c *sContext) SyscallMeterQuery(f MeterFilter) []MeterRecord {
	if err := c.syscall(OpMeterRead); err != nil {
		return nil
	}
	return MeterQuery(f)
}

// closeRequestsFor ends every open request a pid held and marks them abandoned.
// Called from the unload path, so a module that dies mid-request still leaves a
// record of what it consumed rather than an entry that stays open forever and
// quietly eats the ledger's ceiling.
func closeRequestsFor(pid PID) {
	kmeter.mu.Lock()
	var doomed []RequestID
	for id, rec := range kmeter.open {
		rec.mu.Lock()
		owner := rec.r.PID
		rec.mu.Unlock()
		if owner == pid {
			doomed = append(doomed, id)
		}
	}
	kmeter.mu.Unlock()

	if len(doomed) == 0 {
		return
	}
	sort.Slice(doomed, func(i, j int) bool { return doomed[i] < doomed[j] })

	for _, id := range doomed {
		kmeter.mu.RLock()
		rec, ok := kmeter.open[id]
		kmeter.mu.RUnlock()
		if !ok {
			continue
		}
		if !rec.mark() {
			continue
		}
		rec.mu.Lock()
		rec.r.Closed = mono()
		finished := rec.r
		rec.mu.Unlock()
		kmeter.finish(finished, true)
	}

	fault(nil, "open meter requests closed at module teardown", map[string]any{
		"pid": pid, "requests": len(doomed),
	})
}

// resetMeter clears the ledger. Called only from resetKernel.
func resetMeter() {
	kmeter.mu.Lock()
	defer kmeter.mu.Unlock()
	kmeter.open = map[RequestID]*openRequest{}
	kmeter.byPid = map[PID]int{}
	kmeter.done = nil
	kmeter.evicted = 0
	kmeter.recorded = 0
	kmeter.abandoned = 0
}
