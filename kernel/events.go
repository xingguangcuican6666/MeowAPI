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
	"sync"
	"sync/atomic"
)

// kepoll: event subscription and waiting (subsystem: kepoll, the analogue of epoll
// over a set of conditions rather than over file descriptors).
//
// What it is for. A module needs to learn when something happened outside its own
// call stack: a pipe became readable, a peer disconnected, a scheduled job
// finished, a deadline passed, a stream was aborted. Without a kernel-managed event
// path the module's only options are polling, which burns CPU and adds latency, or
// holding a Go channel handed to it by another module, which is exactly the
// cross-module reference kpipe exists to avoid.
//
// What it guarantees. Delivery is bounded: a subscription holds at most
// maxPendingEvents pending events, and when it is full the oldest is dropped and the
// drop is counted. That bound is the point. An unbounded queue behind a slow consumer
// is a memory leak the consumer controls the timing of, and a module that simply
// stops draining its own subscription would grow the kernel's heap until the process
// died. Counting the drops keeps the failure visible instead of silent.
//
// Events are named strings chosen by the kernel, never by a subscribing module. A
// module may wait on a name; it may not invent one and have the kernel deliver it,
// because then one module could signal another and the recipient could not tell a
// kernel fact from a peer's claim.

// ErrNoEvents is returned when a wait's deadline passed with nothing pending. It is
// distinct from a closed subscription so a caller can retry rather than tear down.
var ErrNoEvents = errors.New("kernel: no events before the deadline")

// ErrEventDropped is not returned to anyone: a dropped event is counted and reported
// through EventStats, because there is no waiter to tell. It is defined so the drop
// has a name in the code that reports it.
var ErrEventDropped = errors.New("kernel: event dropped, subscription pending queue full")

const (
	// maxPendingEvents bounds one subscription's backlog.
	maxPendingEvents = 256
	// maxSubscriptionsPerModule bounds how many subscriptions one module may hold.
	maxSubscriptionsPerModule = 64
	// maxEventNameLen bounds a name, since names are copied into records.
	maxEventNameLen = 128
)

// KernelEventName identifies a kind of thing that can happen. The set is closed and
// declared here so a module cannot mint one.
type KernelEventName string

const (
	// EventPipeReadable fires when a pipe this module reads from has data or ended.
	EventPipeReadable KernelEventName = "pipe.readable"
	// EventPeerDisconnected fires when a peer module was unloaded or terminated.
	EventPeerDisconnected KernelEventName = "peer.disconnected"
	// EventDeadlinePassed fires when a registered deadline expired unmet.
	EventDeadlinePassed KernelEventName = "deadline.passed"
	// EventJobFinished fires when a supervised run reached a terminal state.
	EventJobFinished KernelEventName = "job.finished"
	// EventStreamAborted fires when a stream this module serves was cancelled.
	EventStreamAborted KernelEventName = "stream.aborted"
	// EventSignalDelivered fires when a signal arrived for this pid.
	EventSignalDelivered KernelEventName = "signal.delivered"
	// EventDraining fires when this pid entered drain.
	EventDraining KernelEventName = "draining"
	// EventConfigReloaded fires when the kernel published new configuration.
	EventConfigReloaded KernelEventName = "config.reloaded"
)

// kernelEventNames is the closed set, used for validation.
var kernelEventNames = map[KernelEventName]bool{
	EventPipeReadable:     true,
	EventPeerDisconnected: true,
	EventDeadlinePassed:   true,
	EventJobFinished:      true,
	EventStreamAborted:    true,
	EventSignalDelivered:  true,
	EventDraining:         true,
	EventConfigReloaded:   true,
}

// IsKernelEvent reports whether a name is in the closed set.
func IsKernelEvent(n KernelEventName) bool { return kernelEventNames[n] }

// KernelEvents lists the event names a module may wait on, sorted.
func KernelEvents() []KernelEventName {
	out := make([]KernelEventName, 0, len(kernelEventNames))
	for n := range kernelEventNames {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Event is one delivered notification.
type Event struct {
	// Name is from the closed kernel set.
	Name KernelEventName `json:"name"`
	// Seq is monotonic within one subscription, so a consumer can detect a gap and
	// know it missed something rather than assuming nothing happened.
	Seq int64 `json:"seq"`
	// At is the Mono() reading when the event was posted.
	At int64 `json:"at"`
	// Subject is the pid the event is about: the peer that disconnected, the job
	// that finished. Zero when the event is about the subscriber itself.
	Subject PID `json:"subject,omitempty"`
	// Detail carries a small kernel-chosen string, for example a pipe name. It is
	// never module-supplied content, so it cannot be used to smuggle a payload
	// through the event path.
	Detail string `json:"detail,omitempty"`
}

// subscription is one module's interest in a set of event names.
type subscription struct {
	mu sync.Mutex
	// cond wakes a waiter when an event arrives or the subscription closes.
	cond *sync.Cond

	pid     PID
	names   map[KernelEventName]bool
	pending []Event
	next    int64
	dropped int64
	closed  bool
}

func newSubscription(pid PID, names []KernelEventName) *subscription {
	s := &subscription{pid: pid, names: make(map[KernelEventName]bool, len(names)), next: 1}
	s.cond = sync.NewCond(&s.mu)
	for _, n := range names {
		s.names[n] = true
	}
	return s
}

// post enqueues one event if this subscription wants it. It never blocks the poster:
// a full backlog drops the oldest rather than applying backpressure to the kernel's
// own event path, because the alternative is one slow consumer stalling every other
// subsystem that posts events.
func (s *subscription) post(e Event) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || !s.names[e.Name] {
		return false
	}
	e.Seq = s.next
	s.next++
	e.At = mono()

	s.pending = append(s.pending, e)
	if len(s.pending) > maxPendingEvents {
		// Drop oldest. The newest event is the one a consumer can still act on;
		// the oldest is the one whose deadline has probably already passed.
		s.pending = s.pending[1:]
		s.dropped++
	}
	s.cond.Broadcast()
	return true
}

// wait blocks until an event is pending or the deadline passes.
func (s *subscription) wait(deadline int64) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		if s.closed {
			return nil, errClosed
		}
		if len(s.pending) > 0 {
			out := make([]Event, len(s.pending))
			copy(out, s.pending)
			s.pending = nil
			return out, nil
		}
		if deadline > 0 && kclock.Expired(deadline) {
			return nil, ErrNoEvents
		}
		if deadline > 0 {
			waitWithDeadline(s.cond, deadline)
		} else {
			s.cond.Wait()
		}
	}
}

func (s *subscription) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.pending = nil
	s.mu.Unlock()
	s.cond.Broadcast()
}

func (s *subscription) stats() (pending, dropped int, next int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending), int(s.dropped), s.next
}

// eventHandle is the fd-table resource for a subscription. Closing it unsubscribes,
// which is what makes a module that dies without cleaning up still stop receiving.
type eventHandle struct {
	closedFlag
	sub *subscription
}

// Kind names the resource for the fd table and the dump.
func (h *eventHandle) Kind() string { return "event" }

// Close unsubscribes. Idempotent, so reclamation after an explicit close is a no-op.
func (h *eventHandle) Close() error {
	if !h.mark() {
		return errClosed
	}
	h.sub.close()
	kevents.drop(h.sub.pid, h.sub)
	return nil
}

// eventBus holds every live subscription.
type eventBus struct {
	mu   sync.RWMutex
	subs map[PID][]*subscription
	// posts is atomic because it is incremented under the read lock: two posters
	// run concurrently by design, and a plain counter under RLock is a race.
	posts atomic.Int64
}

var kevents = &eventBus{subs: map[PID][]*subscription{}}

func (b *eventBus) add(pid PID, s *subscription) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.subs[pid]) >= maxSubscriptionsPerModule {
		return fmt.Errorf("kernel: pid %d holds the maximum of %d event subscriptions",
			pid, maxSubscriptionsPerModule)
	}
	b.subs[pid] = append(b.subs[pid], s)
	return nil
}

func (b *eventBus) drop(pid PID, s *subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()
	list := b.subs[pid]
	out := list[:0]
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		delete(b.subs, pid)
	} else {
		b.subs[pid] = out
	}
}

// dropAll unsubscribes everything a pid held. Called from the unload path.
func (b *eventBus) dropAll(pid PID) {
	b.mu.Lock()
	subs := b.subs[pid]
	delete(b.subs, pid)
	b.mu.Unlock()

	for _, s := range subs {
		s.close()
	}
}

// postEvent delivers one event to every subscription that wants it.
//
// Unexported on purpose, and the reason is not that there is no post syscall - there is no
// post syscall, but that alone would protect nothing. A module is Go code in this address
// space importing this package, so any exported function here is callable by one, and a
// module holding zero operations could post `job.finished` about a job that never ran and
// `peer.disconnected` about a peer that is still alive. The closed name set does not help:
// it stops a module inventing a name, not a module using a real one to assert a false fact,
// and Event carries no origin field a subscriber could check.
//
// The host reaches this through (*Kernel).PostEvent, which is gated on the receiver being
// the booted kernel. That is the same construction peer.go gives for PeerDeliver and the one
// bootconfig.go gives for nodeSigningKey: where a package-level function would be an oracle,
// the capability moves onto a handle only the host holds.
func postEvent(name KernelEventName, subject PID, detail string) {
	if !kernelEventNames[name] {
		// An unknown name is a defect in the kernel, not in a module, so it is a
		// fault rather than a quiet no-op: a subsystem that posts a name nobody
		// defined would otherwise produce a subscription that never fires and
		// nobody would know why.
		fault(nil, "post of an undefined kernel event name", map[string]any{
			"name": string(name),
		})
		return
	}
	if len(detail) > maxEventNameLen {
		detail = detail[:maxEventNameLen]
	}

	kevents.mu.RLock()
	var targets []*subscription
	for _, subs := range kevents.subs {
		targets = append(targets, subs...)
	}
	kevents.posts.Add(1)
	kevents.mu.RUnlock()

	e := Event{Name: name, Subject: subject, Detail: detail}
	for _, s := range targets {
		s.post(e)
	}
}

// postEventToPid delivers one event only to a specific pid's subscriptions. Used where the
// event is about one module and waking every subscriber would be noise. Unexported for the
// reason postEvent is.
func postEventToPid(name KernelEventName, pid PID, subject PID, detail string) {
	if !kernelEventNames[name] {
		fault(nil, "post of an undefined kernel event name", map[string]any{
			"name": string(name),
		})
		return
	}
	if len(detail) > maxEventNameLen {
		detail = detail[:maxEventNameLen]
	}

	kevents.mu.RLock()
	subs := append([]*subscription(nil), kevents.subs[pid]...)
	kevents.posts.Add(1)
	kevents.mu.RUnlock()

	e := Event{Name: name, Subject: subject, Detail: detail}
	for _, s := range subs {
		s.post(e)
	}
}

// PostEvent delivers one kernel event to every subscription that asked for its name. It is
// a method on the booted kernel rather than a package function so that a module cannot
// assert a kernel fact it did not observe; see postEvent.
func (k *Kernel) PostEvent(name KernelEventName, subject PID, detail string) error {
	if err := k.hostOnly(); err != nil {
		return err
	}
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return errors.New("kernel: already shut down")
	}
	postEvent(name, subject, detail)
	return nil
}

// PostEventToPid delivers one kernel event to a single pid's subscriptions. Same reasoning as
// PostEvent.
func (k *Kernel) PostEventToPid(name KernelEventName, pid PID, subject PID, detail string) error {
	if err := k.hostOnly(); err != nil {
		return err
	}
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return errors.New("kernel: already shut down")
	}
	postEventToPid(name, pid, subject, detail)
	return nil
}

// SyscallEvent is the event half of the syscall surface.
type SyscallEvent interface {
	// SyscallEventSubscribe registers interest in a set of kernel event names and
	// returns the handle that owns the subscription. Requires event:wait. Closing
	// the handle unsubscribes.
	SyscallEventSubscribe(names []KernelEventName) (FD, error)
	// SyscallEventWait blocks until an event is pending on a subscription this
	// context owns, or the deadline passes. Requires event:wait.
	SyscallEventWait(fd FD, deadline int64) ([]Event, error)
	// SyscallEventPending reports how many events are queued and how many were
	// dropped, without blocking. Requires no operation, and only for this
	// context's own subscriptions.
	SyscallEventPending(fd FD) (pending int, dropped int, err error)
}

// EventSubscribe registers a subscription for a context.
func EventSubscribe(ctx SContext, names []KernelEventName) (FD, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return noFD, errForeignContext
	}
	if err := c.syscall(OpEventWait); err != nil {
		return noFD, err
	}
	if len(names) == 0 {
		return noFD, errors.New("kernel: a subscription requires at least one event name")
	}
	for _, n := range names {
		if !kernelEventNames[n] {
			return noFD, fmt.Errorf("kernel: %q is not a kernel event name", n)
		}
	}

	sub := newSubscription(c.pid, names)
	if err := kevents.add(c.pid, sub); err != nil {
		fault(c, "event subscription refused", map[string]any{"reason": err.Error()})
		return noFD, err
	}

	fd, err := install(c.pid, &eventHandle{sub: sub}, "event")
	if err != nil {
		kevents.drop(c.pid, sub)
		return noFD, err
	}
	return fd, nil
}

// EventWait waits on a subscription this context owns.
func EventWait(ctx SContext, fd FD, deadline int64) ([]Event, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if err := c.syscall(OpEventWait); err != nil {
		return nil, err
	}
	sub, err := eventSubscription(c.pid, fd)
	if err != nil {
		return nil, err
	}
	return sub.wait(deadline)
}

// eventSubscription resolves an fd to the subscription it owns, and refuses a handle
// belonging to another pid. The check is structural rather than policy: the fd table
// is per pid, so a foreign handle does not resolve.
func eventSubscription(pid PID, fd FD) (*subscription, error) {
	e, err := lookup(pid, fd)
	if err != nil {
		return nil, err
	}
	if e.kind != "event" {
		return nil, fmt.Errorf("kernel: fd %d is a %s, not an event subscription", fd, e.kind)
	}
	res, ok := e.res.(*eventHandle)
	if !ok || res.done() {
		return nil, fmt.Errorf("kernel: fd %d is not an open subscription", fd)
	}
	return res.sub, nil
}

// EventPending reports a subscription's backlog without blocking.
func EventPending(ctx SContext, fd FD) (int, int, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return 0, 0, errForeignContext
	}
	if err := c.syscall(""); err != nil {
		return 0, 0, err
	}
	sub, err := eventSubscription(c.pid, fd)
	if err != nil {
		return 0, 0, err
	}
	pending, dropped, _ := sub.stats()
	return pending, dropped, nil
}

func (c *sContext) SyscallEventSubscribe(names []KernelEventName) (FD, error) {
	return EventSubscribe(c, names)
}

func (c *sContext) SyscallEventWait(fd FD, deadline int64) ([]Event, error) {
	return EventWait(c, fd, deadline)
}

func (c *sContext) SyscallEventPending(fd FD) (int, int, error) {
	return EventPending(c, fd)
}

// EventStats is the bus view for the dump.
type EventStats struct {
	Subscriptions int   `json:"subscriptions"`
	Posts         int64 `json:"posts"`
	Pending       int   `json:"pending"`
	Dropped       int64 `json:"dropped"`
	// MaxPendingPerSubscription is the bound in force, so an operator reading the
	// dump can tell whether a drop count means the consumer is too slow or the
	// bound is too small.
	MaxPendingPerSubscription int `json:"max_pending_per_subscription"`
}

// EventStatsSnapshot copies the bus state.
func EventStatsSnapshot() EventStats {
	kevents.mu.RLock()
	subs := make([]*subscription, 0)
	for _, list := range kevents.subs {
		subs = append(subs, list...)
	}
	kevents.mu.RUnlock()
	posts := kevents.posts.Load()

	st := EventStats{
		Subscriptions:             len(subs),
		Posts:                     posts,
		MaxPendingPerSubscription: maxPendingEvents,
	}
	for _, s := range subs {
		pending, dropped, _ := s.stats()
		st.Pending += pending
		st.Dropped += int64(dropped)
	}
	return st
}

// resetEvents clears every subscription. Called only from resetKernel.
func resetEvents() {
	kevents.mu.Lock()
	subs := make([]*subscription, 0)
	for _, list := range kevents.subs {
		subs = append(subs, list...)
	}
	kevents.subs = map[PID][]*subscription{}
	kevents.posts.Store(0)
	kevents.mu.Unlock()

	for _, s := range subs {
		s.close()
	}
}
