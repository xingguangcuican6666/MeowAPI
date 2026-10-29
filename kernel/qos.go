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
)

// kqos is rate limiting at the kernel boundary (subsystem: kqos, the analogue of a
// token bucket qdisc).
//
// A request is admitted or refused before it reaches module code, so a module that
// ignores its own limits cannot exhaust the process on its behalf. Two ceilings are
// enforced per key: requests per minute and tokens per minute. Keys are chosen by
// the kernel from the caller's identity, never supplied by the caller.
//
// The single non-negotiable rule is that time comes from kclock and from nowhere
// else. A caller that could pass its own "now" could pass one from the past and
// refill its own bucket forever, which turns the limiter into a formality. There is
// no time parameter on any exported function in this file.

// ErrRateLimited is returned when a key is over its ceiling. It is typed so the
// gateway can answer 429 with a Retry-After rather than treating saturation as a
// fault.
var ErrRateLimited = errors.New("kernel: rate limited")

// qosKey identifies one bucket. The Kind keeps a uid bucket and a domain bucket
// from colliding when they happen to share a value.
type qosKey struct {
	kind string
	id   string
}

// qosBucket is one token bucket pair: requests and tokens refill independently.
type qosBucket struct {
	// reqTokens and tokTokens are the current balance, in thousandths so the
	// refill arithmetic stays in integers. Integer arithmetic matters: a float
	// bucket drifts under high-frequency refill and the drift is in the direction
	// that admits extra requests.
	reqTokens int64
	tokTokens int64
	// lastRefill is a Mono() reading. Nothing else sets it.
	lastRefill int64
	// admitted and refused are counters for the operator.
	admitted int64
	refused  int64
}

// qosState holds every bucket plus the global ceiling on how many buckets may
// exist. The bound is what stops a key-space a module can influence from becoming a
// memory leak.
type qosState struct {
	mu       sync.Mutex
	buckets  map[qosKey]*qosBucket
	maxKeys  int
	evicted  int64
	admitted int64
	refused  int64
}

// maxQosKeys caps the bucket count. Keys come from uid and domain, both
// kernel-allocated, so this is a backstop rather than a live limit - but a backstop
// that is absent is a backstop that will be needed eventually.
const maxQosKeys = 4096

var kqos = &qosState{buckets: map[qosKey]*qosBucket{}}

// QosPolicy is the ceiling set applied to one key. Zero fields mean "unlimited for
// this dimension", which is deliberate: a deployment that only cares about request
// rate should not have to invent a token ceiling.
type QosPolicy struct {
	// RequestsPerMinute and TokensPerMinute are the ceilings.
	RequestsPerMinute int64
	TokensPerMinute   int64
	// Burst is how far above the steady rate a key may spike. Zero means the
	// bucket capacity equals one minute of the rate, which is the conventional
	// choice and the one that survives a short idle period without granting a
	// double burst.
	Burst int64
}

// policies maps a key kind to its ceiling. It is kernel state set by the host
// process at boot, not module state, so a module cannot raise its own rate.
var (
	policiesMu sync.RWMutex
	policies   = map[string]QosPolicy{}
)

// SetQosPolicy installs the ceiling for a key kind, for example "uid" or "domain".
// It is exported for the bootloader only; there is no syscall for it, and a module
// that needs a different rate needs a different deployment.
func SetQosPolicy(kind string, p QosPolicy) error {
	if kind == "" {
		return errors.New("kernel: empty qos policy kind")
	}
	if p.RequestsPerMinute < 0 || p.TokensPerMinute < 0 || p.Burst < 0 {
		return fmt.Errorf("kernel: negative qos ceiling for %q", kind)
	}
	policiesMu.Lock()
	defer policiesMu.Unlock()
	policies[kind] = p
	return nil
}

// QosPolicyFor returns the installed ceiling for a key kind.
func QosPolicyFor(kind string) (QosPolicy, bool) {
	policiesMu.RLock()
	defer policiesMu.RUnlock()
	p, ok := policies[kind]
	return p, ok
}

// QosDecision is the result of an admission attempt.
type QosDecision struct {
	// Admitted is whether the request may proceed.
	Admitted bool
	// RetryAfterMillis is how long the caller should wait before the bucket can
	// serve this request. Zero when admitted. It is computed from the deficit and
	// the refill rate, not guessed, so a client that honors it is not punished.
	RetryAfterMillis int64
	// Reason names the ceiling that refused, for logs and for the response body.
	Reason string
}

// scale is the fixed-point factor. Thousandths of a token gives sub-request
// resolution at a rate of one request per minute without floats.
const scale = int64(1000)

// admit is the bucket arithmetic. nowMono is passed in by the caller, which always
// reads it from kclock, so the function is pure and testable while the module-facing
// surface still cannot choose the time.
func (s *qosState) admit(k qosKey, cost int64, p QosPolicy, nowMono int64) QosDecision {
	if p.RequestsPerMinute == 0 && p.TokensPerMinute == 0 {
		// No ceiling configured for this key: admit, and count it, so an operator
		// can see the traffic that is not being limited.
		s.mu.Lock()
		s.admitted++
		s.mu.Unlock()
		return QosDecision{Admitted: true}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[k]
	if !ok {
		if len(s.buckets) >= s.maxKeys {
			// Evict the least recently refilled bucket rather than refusing the
			// request. Refusing here would let one module that churns keys lock
			// every other module out of admission.
			s.evictOldestLocked()
		}
		b = &qosBucket{
			reqTokens: p.RequestsPerMinute * scale,
			tokTokens: p.TokensPerMinute * scale,
		}
		if p.Burst > 0 {
			b.reqTokens = p.Burst * scale
			b.tokTokens = p.Burst * scale
		}
		b.lastRefill = nowMono
		s.buckets[k] = b
	}

	s.refillLocked(b, p, nowMono)

	reqCost := scale
	tokCost := cost * scale
	if tokCost < 0 {
		tokCost = 0
	}

	if p.RequestsPerMinute > 0 && b.reqTokens < reqCost {
		b.refused++
		s.refused++
		return QosDecision{
			Admitted:         false,
			RetryAfterMillis: millisForDeficit(reqCost-b.reqTokens, p.RequestsPerMinute),
			Reason:           "requests per minute",
		}
	}
	if p.TokensPerMinute > 0 && b.tokTokens < tokCost {
		b.refused++
		s.refused++
		return QosDecision{
			Admitted:         false,
			RetryAfterMillis: millisForDeficit(tokCost-b.tokTokens, p.TokensPerMinute),
			Reason:           "tokens per minute",
		}
	}

	b.reqTokens -= reqCost
	b.tokTokens -= tokCost
	b.admitted++
	s.admitted++
	return QosDecision{Admitted: true}
}

// refillLocked adds what has accrued since the last refill. Caller holds s.mu.
//
// The elapsed time is clamped at zero, so a monotonic clock that somehow read
// backwards cannot subtract tokens. It is also capped at one minute of refill, so a
// bucket idle for a day does not come back with a day's worth of burst: the ceiling
// is a rate, and a rate that can be banked indefinitely is not a ceiling.
func (s *qosState) refillLocked(b *qosBucket, p QosPolicy, nowMono int64) {
	elapsed := nowMono - b.lastRefill
	if elapsed <= 0 {
		return
	}
	b.lastRefill = nowMono

	const minuteNanos = int64(60_000_000_000)
	if elapsed > minuteNanos {
		elapsed = minuteNanos
	}

	capacity := p.RequestsPerMinute
	if p.Burst > 0 {
		capacity = p.Burst
	}
	if p.RequestsPerMinute > 0 {
		b.reqTokens += p.RequestsPerMinute * scale * elapsed / minuteNanos
		if max := capacity * scale; b.reqTokens > max {
			b.reqTokens = max
		}
	}

	tokCapacity := p.TokensPerMinute
	if p.Burst > 0 {
		tokCapacity = p.Burst
	}
	if p.TokensPerMinute > 0 {
		b.tokTokens += p.TokensPerMinute * scale * elapsed / minuteNanos
		if max := tokCapacity * scale; b.tokTokens > max {
			b.tokTokens = max
		}
	}
}

func (s *qosState) evictOldestLocked() {
	var oldest qosKey
	var oldestAt int64 = 1 << 62
	found := false
	for k, b := range s.buckets {
		if !found || b.lastRefill < oldestAt {
			oldest, oldestAt, found = k, b.lastRefill, true
		}
	}
	if found {
		delete(s.buckets, oldest)
		s.evicted++
	}
}

// millisForDeficit converts a fixed-point deficit into a wait, rounding up so the
// caller is never told to retry before the bucket can actually serve it.
func millisForDeficit(deficit, perMinute int64) int64 {
	if perMinute <= 0 || deficit <= 0 {
		return 0
	}
	const minuteMillis = int64(60_000)
	ms := deficit * minuteMillis / (perMinute * scale)
	if deficit*minuteMillis%(perMinute*scale) != 0 {
		ms++
	}
	return ms
}

// SyscallQos is the admission half of the syscall surface.
type SyscallQos interface {
	// SyscallQosAdmit asks whether a request may proceed, costing the given number
	// of tokens. Requires qos:admit. The time is read from the kernel clock, never
	// from the caller.
	SyscallQosAdmit(cost int64) (QosDecision, error)
}

// QosAdmit checks admission for a context. The key is derived from the context's
// uid and domain, both kernel-allocated, so a module cannot pick a key that has a
// generous ceiling or collide with another module's bucket.
func QosAdmit(ctx SContext, cost int64) (QosDecision, error) {
	c, ok := ctx.(*sContext)
	if !ok {
		return QosDecision{}, errForeignContext
	}
	if err := c.syscall(OpQosAdmit); err != nil {
		return QosDecision{}, err
	}
	if cost < 0 {
		return QosDecision{}, fmt.Errorf("kernel: negative qos cost %d", cost)
	}

	// Two buckets are charged: this uid and this uid's domain. Charging the domain
	// too is what stops N modules under one domain from each taking a full
	// allowance and collectively exhausting the upstream.
	uidKey := qosKey{kind: "uid", id: fmt.Sprint(c.uid)}
	domKey := qosKey{kind: "domain", id: string(c.dom)}

	now := mono()
	uidPolicy, uidOK := QosPolicyFor("uid")
	domPolicy, domOK := QosPolicyFor("domain")

	var uidDec, domDec QosDecision
	if uidOK {
		uidDec = kqos.admit(uidKey, cost, uidPolicy, now)
	} else {
		uidDec = QosDecision{Admitted: true}
	}

	// Only charge the domain bucket if the uid bucket admitted, so a refused
	// request does not consume domain capacity it never used.
	if uidDec.Admitted && domOK {
		domDec = kqos.admit(domKey, cost, domPolicy, now)
	} else if !uidDec.Admitted {
		domDec = QosDecision{Admitted: false, Reason: "skipped: uid refused"}
	} else {
		domDec = QosDecision{Admitted: true}
	}

	if !uidDec.Admitted {
		return uidDec, nil
	}
	if !domDec.Admitted {
		return domDec, nil
	}
	return QosDecision{Admitted: true}, nil
}

func (c *sContext) SyscallQosAdmit(cost int64) (QosDecision, error) {
	return QosAdmit(c, cost)
}

// QosStats is the admission view for the dump and for an operator watching a
// saturation event.
type QosStats struct {
	Buckets  int                  `json:"buckets"`
	MaxKeys  int                  `json:"max_keys"`
	Admitted int64                `json:"admitted"`
	Refused  int64                `json:"refused"`
	Evicted  int64                `json:"evicted"`
	Policies map[string]QosPolicy `json:"policies"`
}

// QosStatsSnapshot copies the limiter state.
func QosStatsSnapshot() QosStats {
	kqos.mu.Lock()
	st := QosStats{
		Buckets:  len(kqos.buckets),
		MaxKeys:  kqos.maxKeys,
		Admitted: kqos.admitted,
		Refused:  kqos.refused,
		Evicted:  kqos.evicted,
	}
	kqos.mu.Unlock()

	policiesMu.RLock()
	st.Policies = make(map[string]QosPolicy, len(policies))
	for k, v := range policies {
		st.Policies[k] = v
	}
	policiesMu.RUnlock()
	return st
}

// QosKeys lists the live bucket keys, sorted, for the dump.
func QosKeys() []string {
	kqos.mu.Lock()
	defer kqos.mu.Unlock()
	out := make([]string, 0, len(kqos.buckets))
	for k := range kqos.buckets {
		out = append(out, k.kind+":"+k.id)
	}
	sort.Strings(out)
	return out
}

// resetQos clears buckets. Called only from resetKernel.
//
// Policies are operator configuration and are kept across a restart, for the same
// reason the audit window is: a reboot should not silently change what rate the
// gateway admits at.
func resetQos() {
	kqos.mu.Lock()
	defer kqos.mu.Unlock()
	kqos.buckets = map[qosKey]*qosBucket{}
	kqos.admitted = 0
	kqos.refused = 0
	kqos.evicted = 0
	if kqos.maxKeys == 0 {
		kqos.maxKeys = maxQosKeys
	}
}
