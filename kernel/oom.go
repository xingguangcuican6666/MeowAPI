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
	"runtime/metrics"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// koom: memory pressure and forced teardown (subsystem: koom).
//
// What it is for. Every other bound in this kernel is a refusal: a module asks for
// something past its ceiling and the answer is no. That works when the module asks. It
// does not work when memory grows without a request - a module that accumulates state in
// its own heap, or one that holds buffers it will never release, or four modules each
// inside their own ceiling and together past the host's. koom is the part that acts
// without being asked: it watches what the kernel has accounted for and what the host is
// actually using, and when the host is in danger it terminates the module that is costing
// the most, so the kernel survives.
//
// What it cannot see, stated plainly because a pressure detector that overstates its own
// reach is worse than one that admits its limits. The tallies here are the bytes the
// KERNEL handed out: namespaced state, reserved pipe capacity, shared segments. A module
// that allocates two gigabytes of its own Go heap and never asks the kernel for anything
// is invisible to every number in this file. What still catches it is the host sample: the
// process is running out of memory whether or not the kernel can attribute the cause, and
// under host pressure this subsystem terminates the largest accounted consumer, which is
// the best available guess and is recorded as a guess rather than as a finding. AGENT.md's
// statement about this kernel holds here unchanged - it is a mandatory access control
// kernel, not a sandbox, and a real memory limit on a module needs a real address space,
// which is the out-of-process tier that file defers.
//
// The priority order is a policy statement and not an accident:
//
//	untrusted, then plugin, then never init, never the kernel.
//
// Killing the module that costs the most would sometimes mean killing init, and a kernel
// that terminates its own bootloader to save memory has traded a recoverable outage for an
// unrecoverable one. The host is what is being protected, so the host's own long-lived
// context is the one thing this file will not touch.

// OomMemorySampler reads the host's memory. The kernel cannot know the machine's total
// RAM - it is not in any Go API, and reading it from /proc or sysctl would make this file
// platform-specific for a number it uses in one comparison - so the host supplies it,
// following the same shape as PeerTransport and NetResolver.
//
// The process figure is read from the Go runtime's own accounting by default, which needs no
// platform code and is exactly the memory this process holds. A host may supply it instead,
// and the reason that is worth a method rather than a fixed internal read is a container: a
// process inside a cgroup limit is not using the machine's memory, it is using its quota, and
// a detector measuring the wrong one will fire late or never.
type OomMemorySampler interface {
	// TotalMemoryBytes returns the memory the kernel should treat as the whole, or zero if
	// unknown. Zero disables the host-pressure path rather than being read as "the host has
	// no memory", and OomPressure.OomHostPressureKnown is how a caller tells the two apart.
	TotalMemoryBytes() uint64
	// ReservedBytes returns what this process has reserved from the OS. It is consulted only
	// when TotalMemoryBytes is non-zero, so a sampler that reports no total cannot have its
	// process figure read for nothing.
	ReservedBytes() uint64
}

type oomSamplerState struct {
	mu sync.RWMutex
	s  OomMemorySampler
}

var oomSampler = oomSamplerState{}

// OomSetMemorySampler installs the host's memory sampler. A nil sampler removes it and
// disables the host-pressure path, which is the same reasoning net.go's NetSetResolver
// gives for accepting nil: "use the default" is a legitimate configuration for a sampler
// that has a safe no-op, unlike a transport that has no default at all.
func (k *Kernel) OomSetMemorySampler(s OomMemorySampler) error {
	k.shutdownM.Lock()
	shutdown := k.shutdown
	k.shutdownM.Unlock()
	if shutdown {
		return errors.New("kernel: already shut down")
	}
	oomSampler.mu.Lock()
	oomSampler.s = s
	oomSampler.mu.Unlock()
	if s != nil {
		kaudit.record(AuditPolicy, nil, "oom memory sampler installed", map[string]any{
			"sampler": fmt.Sprintf("%T", s),
		})
	}
	return nil
}

// oomSamplerMemory reads the installed sampler, or zeros when there is none. A sampler that
// reports no total is treated as absent for the process figure too, so the two halves of a
// reading always come from the same source and a fraction is never computed from one
// sampler's numerator over another's denominator.
func oomSamplerMemory() (total, reserved uint64) {
	oomSampler.mu.RLock()
	s := oomSampler.s
	oomSampler.mu.RUnlock()
	if s == nil {
		return 0, 0
	}
	total = s.TotalMemoryBytes()
	if total == 0 {
		return 0, 0
	}
	return total, s.ReservedBytes()
}

// ---------------------------------------------------------------------------
// What the kernel can see.

// OomTally is one pid's accounted memory, broken out by source. The breakdown is the
// point of the type: a single total would let an operator see that a module is large
// without seeing whether it is holding state, pipes or shared buffers, and those three
// have three different fixes.
type OomTally struct {
	PID    PID    `json:"pid"`
	Module string `json:"module,omitempty"`
	Domain Domain `json:"domain,omitempty"`
	// StateBytes is namespaced KV state, tallied by kvfs against its own per-module
	// ceiling.
	StateBytes int64 `json:"state_bytes"`
	// PipeBytes is reserved pipe capacity. It is a reservation rather than what happens
	// to be buffered, for the reason pipe.go gives: an empty pipe can fill to its
	// capacity at any moment, so counting current contents would let a module open every
	// pipe first and fill them all second.
	PipeBytes int64 `json:"pipe_bytes"`
	// SegmentBytes is shared-buffer class bytes this pid owns.
	SegmentBytes int64 `json:"segment_bytes"`
	// Handles is the count of open fds, which costs little per handle but is the number
	// that explains a module holding many small resources.
	Handles int `json:"handles"`
}

// Total is the accounted bytes, which is what victim ordering compares.
func (t OomTally) Total() int64 { return t.StateBytes + t.PipeBytes + t.SegmentBytes }

// NewOomTally builds a tally from its parts. It exists so the victim order can be tested as
// a pure function of domain and size: asserting the order through a real sweep needs modules
// actually holding different amounts of memory under different domains, and the untrusted
// domain holds no operations, so it cannot accumulate accounted state at all. A test that
// could only reach the order through a sweep would therefore never be able to compare an
// untrusted module against a plugin one, which is the comparison the priority exists to
// decide.
func NewOomTally(pid PID, module string, dom Domain, state, pipe, segment int64) OomTally {
	return OomTally{
		PID: pid, Module: module, Domain: dom,
		StateBytes: state, PipeBytes: pipe, SegmentBytes: segment,
	}
}

// OomSortVictims applies the victim order to a caller's own list and returns it sorted. It
// is the same ordering the sweep and the console use, exported so a test can assert the order
// directly rather than inferring it from which module a sweep happened to kill.
func OomSortVictims(in []OomTally) []OomTally {
	out := append([]OomTally(nil), in...)
	oomSortVictims(out)
	return out
}

// OomVictimEligible reports whether a pid's domain may be terminated under memory pressure.
// Exported for the same reason as the sort: the exclusion of init and the kernel is the
// property that decides whether this subsystem protects the host or destroys it, and it is
// worth asserting on its own rather than only through a sweep that has to arrange for init to
// be the largest consumer first.
func OomVictimEligible(t OomTally) bool { return oomVictimEligible(t) }

// OomPressure is one reading of the host and the kernel together.
type OomPressure struct {
	// HeapInUse is this process's live heap, from the Go runtime's own accounting.
	HeapInUse uint64 `json:"heap_in_use"`
	// TotalReserved is everything the runtime has reserved from the OS for this process.
	TotalReserved uint64 `json:"total_reserved"`
	// HostTotal is what the sampler reported, or zero when no sampler is installed.
	HostTotal uint64 `json:"host_total"`
	// HostFraction is TotalReserved over HostTotal, as a percentage times one hundred so
	// it stays an integer. Zero when the host total is unknown, and a caller must not read
	// zero as "no pressure": OomHostPressureKnown says whether the number means anything.
	HostFraction int `json:"host_fraction_bp"`
	// Accounted is the sum of every pid's tally, which is the part the kernel handed out
	// and can therefore attribute.
	Accounted int64 `json:"accounted"`
	// Tallies is the per-pid breakdown, sorted by total descending so the first entry is
	// the largest consumer.
	Tallies []OomTally `json:"tallies,omitempty"`
	At      int64      `json:"at"`
}

// OomHostPressureKnown reports whether HostFraction is a measurement or a zero that means
// "no sampler". Conflating them is the failure mode that makes a pressure detector
// dangerous: a reading of zero that looks like calm is worse than no reading at all.
func (p OomPressure) OomHostPressureKnown() bool { return p.HostTotal > 0 }

// oomRuntimeMemory reads the process's own memory from the runtime's accounting. It uses
// runtime/metrics rather than runtime.ReadMemStats because metrics is documented as
// stop-the-world-free for these samples, and a pressure detector that pauses every
// goroutine to measure pressure would itself be a source of it.
func oomRuntimeMemory() (heapInUse, totalReserved uint64) {
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/total:bytes"},
	}
	metrics.Read(samples)
	for _, s := range samples {
		if s.Value.Kind() != metrics.KindUint64 {
			continue
		}
		switch s.Name {
		case "/memory/classes/heap/objects:bytes":
			heapInUse = s.Value.Uint64()
		case "/memory/classes/total:bytes":
			totalReserved = s.Value.Uint64()
		}
	}
	return heapInUse, totalReserved
}

// OomTallyFor reads one pid's accounted memory, decorated with the identity fields from the
// process table. Each subsystem's lock is taken one at a time and never nested, because a
// lock order spanning kvfs, kpipes and kshm does not exist anywhere else in this kernel and
// inventing one here would be a deadlock waiting for the first caller that holds two of them.
//
// The decoration happens here rather than only in OomTallies, so the two exported readers of
// one fact cannot disagree about whether a tally names its module. A number with no name is
// not actionable, which is the whole reason the type carries one.
func OomTallyFor(pid PID) OomTally {
	t := OomTally{PID: pid}

	kvfs.mu.RLock()
	t.StateBytes = kvfs.bytes[pid]
	kvfs.mu.RUnlock()

	kpipes.mu.RLock()
	t.PipeBytes = kpipes.bytes[pid]
	kpipes.mu.RUnlock()

	kshm.mu.Lock()
	for id := range kshm.byOwner[pid] {
		if seg, ok := kshm.live[id]; ok {
			t.SegmentBytes += seg.class
		}
	}
	kshm.mu.Unlock()

	t.Handles = len(FDList(pid))
	return oomDecorate(t)
}

// oomDecorate fills in the identity fields, which come from the process table rather than
// from any subsystem's tally. A pid that is gone from the table decorates to nothing, and
// that is correct rather than an error: the sweep can race a teardown, and a tally for a
// process on its way out should carry no name rather than a stale one.
func oomDecorate(t OomTally) OomTally {
	for _, r := range ProcTable() {
		if r.PID == t.PID {
			t.Module = r.Name
			t.Domain = r.Domain
			return t
		}
	}
	return t
}

// OomTallies returns every live pid's tally, sorted by accounted bytes descending. It is a
// snapshot of copies, and it is what the console dump and the victim ordering both read, so
// there is one enumeration rather than two that could disagree about who is largest.
func OomTallies() []OomTally {
	out := make([]OomTally, 0, 8)
	for _, r := range ProcTable() {
		if r.State != ProcRunning {
			continue
		}
		out = append(out, OomTallyFor(r.PID))
	}
	oomSortVictims(out)
	return out
}

// oomSortVictims is the victim order, in one place so the console and the sweep cannot
// disagree about who is next.
//
// Domain first, then size. The domain ordering is the priority the operator means by
// "protect the host": an untrusted module is terminated before a plugin of any size, and
// neither is terminated before init or the kernel, which are excluded entirely by
// oomVictimEligible rather than merely sorted last. Sorting by size alone would eventually
// reach init, and sorting by domain alone would make the choice among equals arbitrary and
// therefore unexplainable in an incident report.
func oomSortVictims(in []OomTally) {
	sort.SliceStable(in, func(i, j int) bool {
		pi, pj := oomDomainPriority(in[i].Domain), oomDomainPriority(in[j].Domain)
		if pi != pj {
			return pi > pj
		}
		if ti, tj := in[i].Total(), in[j].Total(); ti != tj {
			return ti > tj
		}
		// Equal size falls back to pid, so the order is total and a second sweep over an
		// unchanged set picks the same victim. An arbitrary tiebreak would make the
		// subsystem's behaviour depend on map iteration.
		return in[i].PID < in[j].PID
	})
}

// oomDomainPriority ranks domains for termination, higher first. The kernel and init get
// zero and are separately excluded, so the numbers here order only what is eligible.
func oomDomainPriority(d Domain) int {
	switch d {
	case DomainUntrusted:
		return 3
	case DomainPlugin:
		return 2
	default:
		return 0
	}
}

// oomVictimEligible reports whether a pid may be terminated under memory pressure. This is
// the guard the whole priority order exists to express, and it is a separate predicate
// rather than a sort weight because a sort weight can be outranked by a large enough
// number while a predicate cannot.
func oomVictimEligible(t OomTally) bool {
	switch t.Domain {
	case DomainKernel, DomainInit:
		// Never. A kernel that terminates its own bootloader to save memory trades a
		// recoverable outage for an unrecoverable one, and the thing being protected here
		// is the host, whose long-lived context is init.
		return false
	case DomainPlugin, DomainUntrusted:
		return true
	default:
		// An unknown domain is not eligible. Failing closed on an unrecognized identity is
		// the only safe answer when the consequence of being wrong is terminating something
		// the kernel needs.
		return false
	}
}

// OomPressureSnapshot reads the host and every pid's tally once.
//
// The runtime figures are always read, sampler or not, because they are this process's own
// accounting and cost nothing platform-specific. The FRACTION is only computed when the
// sampler supplies both halves: a denominator from a sampler and a numerator from the
// runtime would be a comparison between two different notions of memory, and the number
// would look like a measurement while being an artifact.
func OomPressureSnapshot() OomPressure {
	heap, runtimeReserved := oomRuntimeMemory()
	p := OomPressure{HeapInUse: heap, TotalReserved: runtimeReserved, At: mono()}

	sampledTotal, sampledReserved := oomSamplerMemory()
	p.HostTotal = sampledTotal
	if p.HostTotal > 0 {
		p.TotalReserved = sampledReserved
		// Basis points rather than a float percentage, so the number is comparable and
		// printable without a rounding decision at every read site. The at-or-above-total
		// case is handled first, which is both the correct answer under memory overcommit
		// and what keeps the multiply from overflowing on a host large enough to make it
		// matter.
		if sampledReserved >= p.HostTotal {
			p.HostFraction = 10000
		} else {
			p.HostFraction = int(sampledReserved * 10000 / p.HostTotal)
		}
	}

	p.Tallies = OomTallies()
	for _, t := range p.Tallies {
		p.Accounted += t.Total()
	}
	return p
}

// ---------------------------------------------------------------------------
// Thresholds.

// OomThresholds is the effective pressure configuration, derived from the sealed boot
// limits. It is a value rather than three globals so a caller sees one coherent set, and
// it is read-only: every number in it comes from a ceiling the operator sealed at boot.
type OomThresholds struct {
	// MaxPerModule is the accounted-byte ceiling for one module, from the sealed limits.
	// A module over it is a candidate regardless of what the host is doing, because the
	// host sample cannot attribute the cause and this ceiling can.
	MaxPerModule int64 `json:"max_per_module"`
	// HostWarnBP and HostKillBP are the host-pressure thresholds in basis points. At warn
	// the sweep records and escalates without terminating; at kill it terminates. Two
	// thresholds rather than one because the useful response to "the host is at 80%" is a
	// record an operator can act on, and the useful response to "the host is at 95%" is a
	// terminated module.
	HostWarnBP int `json:"host_warn_bp"`
	HostKillBP int `json:"host_kill_bp"`
	// MaxVictimsPerSweep bounds one sweep. A pressure response that terminates everything
	// eligible is not a response to pressure, it is a shutdown, and bounding it keeps the
	// kernel able to try again on the next sweep if the first victim was not the cause.
	MaxVictimsPerSweep int `json:"max_victims_per_sweep"`
	// Interval is how often the background patrol runs. It is DERIVED from the sealed call
	// ceiling rather than configured, following watchdogInterval: a subsystem's own timing
	// is an implementation detail, and a second knob for it is a second thing an operator has
	// to get right for no policy benefit.
	Interval time.Duration `json:"-"`
}

const (
	// oomDefaultMaxPerModule is the accounted-byte ceiling used when the sealed limits do
	// not set one. It is deliberately below the sum of the per-subsystem defaults, because
	// a module inside every individual ceiling can still exceed this by holding all three
	// at once, and that combination is what this ceiling is for.
	oomDefaultMaxPerModule = int64(64 << 20)
	// oomDefaultHostWarn and oomDefaultHostKill are the host thresholds. Kill is high
	// because a false termination is an outage for the module's users while a late one is
	// a slower host, and the second is recoverable in a way the first is not.
	oomDefaultHostWarn = 8000
	oomDefaultHostKill = 9500
	// oomDefaultMaxVictims bounds one sweep.
	oomDefaultMaxVictims = 2
	// oomMinInterval and oomMaxInterval clamp the derived patrol period, the way
	// minWatchdogInterval and maxWatchdogInterval clamp the watchdog's. The floor keeps a
	// tight call ceiling from turning the sweep's own cost - three subsystem locks and a
	// process-table walk - into part of the pressure it measures. The ceiling keeps a
	// generous one from making the detector slower than the thing it detects.
	oomMinInterval = 500 * time.Millisecond
	oomMaxInterval = 10 * time.Second
)

// EffectiveOomThresholds reports the configuration in force.
func EffectiveOomThresholds() OomThresholds {
	l := Limits()
	t := OomThresholds{
		MaxPerModule:       l.MaxAccountedBytesPerModule,
		HostWarnBP:         l.OomHostWarnBP,
		HostKillBP:         l.OomHostKillBP,
		MaxVictimsPerSweep: l.OomMaxVictimsPerSweep,
	}
	if t.MaxPerModule <= 0 {
		t.MaxPerModule = oomDefaultMaxPerModule
	}
	if t.HostWarnBP <= 0 {
		t.HostWarnBP = oomDefaultHostWarn
	}
	if t.HostKillBP <= 0 {
		t.HostKillBP = oomDefaultHostKill
	}
	if t.MaxVictimsPerSweep <= 0 {
		t.MaxVictimsPerSweep = oomDefaultMaxVictims
	}
	// Derived, not configured: the call ceiling is how long the kernel is prepared to wait
	// on one module operation, so patrolling at a tenth of it gives a sweep roughly ten
	// chances to catch a module on its way to exhausting memory. The same reasoning and the
	// same clamping shape as watchdogInterval, so the two patrols in this kernel are timed
	// by one rule rather than by two that could drift apart.
	ceiling := time.Duration(l.CallTimeoutMillis) * time.Millisecond
	if ceiling <= 0 {
		ceiling = defaultCallCeiling
	}
	t.Interval = max(oomMinInterval, min(ceiling/10, oomMaxInterval))
	// A kill threshold at or below the warn threshold would mean the sweep escalates and
	// terminates in the same breath, which makes the warn record useless as an early
	// signal. Clamping rather than refusing, because the sweep must still run under a
	// misconfigured ceiling and a refusal here would leave the host unprotected.
	if t.HostKillBP <= t.HostWarnBP {
		t.HostKillBP = t.HostWarnBP + 1
	}
	if t.HostKillBP > 10000 {
		t.HostKillBP = 10000
	}
	return t
}

// ---------------------------------------------------------------------------
// The sweep.

// OomAction is one thing a sweep did.
type OomAction struct {
	PID        PID    `json:"pid"`
	Module     string `json:"module,omitempty"`
	Domain     Domain `json:"domain,omitempty"`
	Total      int64  `json:"total_bytes"`
	Reason     string `json:"reason"`
	Terminated bool   `json:"terminated"`
}

// OomPatrol runs one sweep now and returns what it did. The background loop calls it; an
// operator console and tests call it directly, which is what makes the decision verifiable
// without waiting on a timer.
//
// It is safe to call from a module and deliberately so, for the reason WatchdogPatrol
// gives: it takes no pid and grants no ability, so the worst a caller can do is sweep
// early. What it must never be is a way for a module to have a neighbour terminated on
// purpose, and it is not, because the victim is chosen by the kernel from its own tallies
// and never from an argument.
//
// The sweep collects under locks and acts outside them, following the watchdog's shape:
// acting means terminating, which reclaims handles, which takes the same locks a tally
// reads.
func OomPatrol() []OomAction {
	koom.sweeps.Add(1)
	th := EffectiveOomThresholds()
	p := OomPressureSnapshot()

	var actions []OomAction

	// Host pressure first, because it is the condition that cannot wait for the next
	// request to be refused. Warn is recorded without terminating: a host at 80% is an
	// operator signal, not an incident.
	hostKill := p.OomHostPressureKnown() && p.HostFraction >= th.HostKillBP
	if p.OomHostPressureKnown() && p.HostFraction >= th.HostWarnBP {
		koom.warns.Add(1)
		fault(nil, "host memory pressure", map[string]any{
			"host_fraction_bp": p.HostFraction, "reserved": p.TotalReserved,
			"host_total": p.HostTotal, "heap_in_use": p.HeapInUse,
			"accounted": p.Accounted, "kill_threshold_bp": th.HostKillBP,
		})
		kaudit.record(AuditPolicy, nil, "host memory pressure", map[string]any{
			"host_fraction_bp": p.HostFraction, "reserved": p.TotalReserved,
			"accounted": p.Accounted,
		})
	}

	// Candidates: everything eligible that is over its own ceiling, plus - under host
	// kill pressure - the largest consumers even when each is inside its ceiling, because
	// four modules inside their ceilings can together be past the host's and the ceiling
	// is not the only thing worth enforcing.
	type candidate struct {
		tally  OomTally
		reason string
	}
	var candidates []candidate
	for _, t := range p.Tallies {
		if !oomVictimEligible(t) {
			continue
		}
		switch {
		case t.Total() > th.MaxPerModule:
			candidates = append(candidates, candidate{t, fmt.Sprintf(
				"accounted %d bytes over the per-module ceiling %d", t.Total(), th.MaxPerModule)})
		case hostKill:
			candidates = append(candidates, candidate{t, fmt.Sprintf(
				"host at %d.%02d%% and this is the largest accounted consumer at %d bytes",
				p.HostFraction/100, p.HostFraction%100, t.Total())})
		}
	}
	if len(candidates) == 0 {
		return actions
	}

	// The candidate list inherits p.Tallies' order, which is already the victim order, so
	// one ordering decides both the console's view and the sweep's choice. That dependency
	// is worth stating because it is invisible: if the walk above ever became a map range
	// the sweep would start choosing victims arbitrarily, and every test that loads one
	// module would still pass.

	limit := th.MaxVictimsPerSweep
	if hostKill && limit < 1 {
		limit = 1
	}
	for _, c := range candidates {
		if len(actions) >= limit {
			break
		}
		// Under warn-only pressure a module over its own ceiling is still terminated,
		// because that ceiling is the kernel's own accounting and needs no host sample to
		// be trustworthy. What warn-only changes is that modules inside their ceilings are
		// left alone.
		if !hostKill && c.tally.Total() <= th.MaxPerModule {
			continue
		}
		if c.tally.Total() <= 0 {
			// Terminating a module that is accounted at zero bytes would be terminating it
			// for existing. Under host pressure with nothing attributable there is no
			// honest victim, and the record says so rather than picking one arbitrarily.
			koom.noVictim.Add(1)
			fault(nil, "host under pressure with nothing attributable", map[string]any{
				"host_fraction_bp": p.HostFraction, "accounted": p.Accounted,
			})
			continue
		}
		// A pid already being torn down is not a victim, whoever started the teardown. This
		// is checked before the condemnation mark because the mark is oom-private: a module
		// the watchdog condemned for hanging, or one an operator sent SIGKILL to, would
		// otherwise be terminated a second time and counted twice.
		if _, terminating := SignalState(c.tally.PID); terminating {
			continue
		}
		if _, already := oomCondemned.LoadOrStore(c.tally.PID, struct{}{}); already {
			// Another sweep - the background patrol, or a concurrent manual call - already
			// decided on this pid. Skipping rather than recording a second time is what makes
			// one termination produce exactly one ledger entry. Marked AFTER the zero-accounted
			// and already-terminating checks, since a pid that cannot be a victim must not be
			// recorded as already decided on.
			continue
		}
		actions = append(actions, oomTerminate(c.tally, c.reason))
	}
	return actions
}

// oomTerminate ends one module under memory pressure and records it.
func oomTerminate(t OomTally, reason string) OomAction {
	koom.kills.Add(1)
	// The condemnation mark is NOT released here and not on a defer. terminateModule starts
	// the teardown on its own goroutine, so releasing the mark when this function returns
	// would let the next sweep pick the same pid again while it is still draining.
	// oomReleaseCondemned drops it from the unload sequence, once the process record is gone.
	// A mark that outlives the sweep is the point: it is what makes "terminate once" hold
	// across a teardown that takes longer than one patrol interval.

	// The record is written BEFORE the teardown, because the teardown ends the process
	// record this entry describes and an operator reading the chain afterwards needs the
	// numbers as they were at the decision, not as they are after the memory is freed.
	kaudit.record(AuditPolicy, nil, "oom terminated a module", map[string]any{
		"target": t.PID, "module": t.Module, "domain": string(t.Domain),
		"state_bytes": t.StateBytes, "pipe_bytes": t.PipeBytes,
		"segment_bytes": t.SegmentBytes, "total_bytes": t.Total(),
		"handles": t.Handles, "reason": reason,
	})
	fault(nil, "oom terminating a module", map[string]any{
		"target": t.PID, "module": t.Module, "total_bytes": t.Total(), "reason": reason,
	})

	act := OomAction{
		PID: t.PID, Module: t.Module, Domain: t.Domain,
		Total: t.Total(), Reason: reason, Terminated: true,
	}
	oomRecord(act)

	// immediate=true: a module being terminated for memory is not given a drain window,
	// because the drain window is spent allocating. The watchdog uses the same call for the
	// same reason when a module has stopped responding.
	terminateModule(t.PID, "oom: "+reason, true)
	return act
}

// oomReleaseCondemned drops a pid's condemnation mark once the process is gone. Called from
// the unload sequence, beside seccompDropFor and netDropAllFor.
//
// It is not there to stop a mark landing on a reused pid - pids are never reused within a
// boot, and resetOom clears the set across boots. It is there to bound the set. A mark is
// deliberately held for the whole teardown, which is longer than one sweep, so a host that
// loads and terminates modules repeatedly over a long uptime would otherwise accumulate one
// entry per termination forever. That is a leak in the one subsystem whose job is to stop
// leaks, and it is why the count below is exported: an unobservable bound is an unasserted
// one, and this file already contains the lesson that a number reported but never enforced is
// worse than no number at all.
func oomReleaseCondemned(pid PID) { oomCondemned.Delete(pid) }

// OomCondemned reports how many pids are currently marked as decided-on by a sweep. It is
// nonzero only while a teardown is in flight, so a nonzero reading that does not fall back to
// zero is the leak the release above prevents.
func OomCondemned() int {
	n := 0
	oomCondemned.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// ---------------------------------------------------------------------------
// Ledger.

// OomRecord is one retained action, for an operator reading what the kernel did.
type OomRecord struct {
	Seq        int64  `json:"seq"`
	PID        PID    `json:"pid"`
	Module     string `json:"module,omitempty"`
	Domain     Domain `json:"domain,omitempty"`
	Total      int64  `json:"total_bytes"`
	Reason     string `json:"reason"`
	Terminated bool   `json:"terminated"`
	At         int64  `json:"at"`
}

type oomLedger struct {
	mu       sync.Mutex
	entries  []OomRecord
	seq      int64
	evicted  int64
	sweeps   atomic.Int64
	kills    atomic.Int64
	warns    atomic.Int64
	noVictim atomic.Int64
}

// maxOomHistory bounds the retained ledger. Terminations are rare and each one is an
// incident, so the bound is small; what it protects against is a pathological sweep loop
// growing kernel memory while trying to reduce it, which would be this subsystem causing
// the condition it exists to prevent.
const maxOomHistory = 512

// koom is the ledger. Its counters are addressed as koom.kills and so on rather than
// through package-level aliases: an alias of an atomic.Int64 is a COPY of one, and a copy
// carries its own noCopy guard for exactly that reason. Aliasing would have compiled, read
// back zero forever, and looked like a subsystem that never terminated anything.
var koom = oomLedger{}

// oomCondemned holds the pids a sweep has already decided to terminate. It exists for the
// reason the watchdog removes an overdue entry from its registry before acting on it: the
// background patrol and a manual sweep run concurrently, and without a guard both can pick
// the same largest consumer, producing two ledger entries for one termination and an
// operator's count of terminations that is wrong.
//
// A pid is marked when the decision is made and unmarked when the process is gone, so a pid
// the next boot reassigns is not born pre-condemned. resetOom clears the whole set.
var oomCondemned sync.Map

func oomRecord(a OomAction) {
	koom.mu.Lock()
	koom.seq++
	koom.entries = append(koom.entries, OomRecord{
		Seq: koom.seq, PID: a.PID, Module: a.Module, Domain: a.Domain,
		Total: a.Total, Reason: a.Reason, Terminated: a.Terminated, At: mono(),
	})
	// Trimmed after the insert, the way every other bounded ledger in this kernel does it.
	// Trimming before cannot work: at exactly the bound the ledger is still within it, so
	// the trim is a no-op and the insert takes it one past the ceiling every time after.
	koom.trimLocked()
	koom.mu.Unlock()
}

// trimLocked drops the ledger back to seven eighths of its bound in ONE step. Caller holds
// koom.mu. Trimming exactly to the bound would reallocate and copy the whole ledger on
// every insert past the ceiling, under the write lock.
func (l *oomLedger) trimLocked() {
	if len(l.entries) <= maxOomHistory {
		return
	}
	keep := maxOomHistory - maxOomHistory/8
	if len(l.entries) <= keep {
		return
	}
	over := len(l.entries) - keep
	l.evicted += int64(over)
	l.entries = append([]OomRecord(nil), l.entries[over:]...)
}

// OomHistory returns retained actions, oldest first, as copies.
func OomHistory() []OomRecord {
	koom.mu.Lock()
	defer koom.mu.Unlock()
	return append([]OomRecord(nil), koom.entries...)
}

// OomStats is the subsystem's totals.
type OomStats struct {
	Sweeps       int64 `json:"sweeps"`
	Kills        int64 `json:"kills"`
	Warns        int64 `json:"warns"`
	NoVictim     int64 `json:"no_victim"`
	Retained     int   `json:"retained"`
	Evicted      int64 `json:"evicted"`
	MaxPerModule int64 `json:"max_per_module"`
	HostKillBP   int   `json:"host_kill_bp"`
	Sampler      bool  `json:"sampler_installed"`
}

// OomStatsSnapshot returns the totals. Counters only, so it is cheap enough for a status
// path that runs while the host is under pressure.
func OomStatsSnapshot() OomStats {
	koom.mu.Lock()
	retained, evicted := len(koom.entries), koom.evicted
	koom.mu.Unlock()
	th := EffectiveOomThresholds()
	return OomStats{
		Sweeps: koom.sweeps.Load(), Kills: koom.kills.Load(),
		Warns: koom.warns.Load(), NoVictim: koom.noVictim.Load(),
		Retained: retained, Evicted: evicted,
		MaxPerModule: th.MaxPerModule, HostKillBP: th.HostKillBP,
		Sampler: func() bool { t, _ := oomSamplerMemory(); return t > 0 }(),
	}
}

// ---------------------------------------------------------------------------
// The patrol loop.

var (
	oomStartMu sync.Mutex
	oomStop    chan struct{}
	oomRunning atomic.Bool
)

// oomInterval re-derives the period each time rather than fixing it for the life of the
// goroutine, so a restart under different sealed limits patrols at those limits' rate. The
// derivation lives in EffectiveOomThresholds, beside the numbers it is derived from.
func oomInterval() time.Duration { return EffectiveOomThresholds().Interval }

// oomEnsureRunning starts the patrol if it is not already running. It is called when the
// kernel boots and again whenever a host installs a sampler, because a patrol that started
// before the sampler existed would still be running and there is no need to restart it -
// but a patrol that was never started because nothing had a sampler is worth starting once
// the accounted ceilings alone are worth enforcing.
func oomEnsureRunning() {
	if oomRunning.Load() {
		return
	}
	oomStartMu.Lock()
	defer oomStartMu.Unlock()
	if oomRunning.Load() {
		return
	}
	oomStop = make(chan struct{})
	oomRunning.Store(true)
	go oomPatrolLoop(oomStop)
}

func oomPatrolLoop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(oomInterval()):
		}
		OomPatrol()
	}
}

// resetOom stops the patrol and clears the ledger for a fresh boot. The sampler is dropped
// too, matching resetPeers dropping the transport and resetNet dropping the resolver: host
// configuration does not survive a boot, and a restarted kernel that inherited the previous
// boot's sampler would be reading a machine it has not been told about.
func resetOom() {
	oomStartMu.Lock()
	if oomRunning.Swap(false) && oomStop != nil {
		close(oomStop)
	}
	oomStop = nil
	oomStartMu.Unlock()

	oomSampler.mu.Lock()
	oomSampler.s = nil
	oomSampler.mu.Unlock()

	koom.mu.Lock()
	koom.entries = nil
	koom.seq = 0
	koom.evicted = 0
	koom.mu.Unlock()
	oomCondemned.Range(func(k, _ any) bool {
		oomCondemned.Delete(k)
		return true
	})
	koom.sweeps.Store(0)
	koom.kills.Store(0)
	koom.warns.Store(0)
	koom.noVictim.Store(0)
}

// ---------------------------------------------------------------------------
// INTEGRATION.
//
// 1. bootconfig.go: BootLimits gains the five fields OomThresholds reads -
//    MaxAccountedBytesPerModule, OomHostWarnBP, OomHostKillBP, OomMaxVictimsPerSweep and
//    OomPatrolMillis - plus their entries in defaultLimits and withDefaults. They are
//    limits rather than globals so the operator seals them with the rest of the trust root,
//    and hashBootConfig hashes only the values map, so adding them does not change
//    BootDigest.
//
// 2. kernel.go: resetOom() is in resetKernel(), AFTER resetModules, because a termination
//    started by a late sweep would otherwise have no module table to tear down against.
//    module.go calls oomReleaseCondemned(pid) in the unload sequence beside seccompDropFor
//    and netDropAllFor, so a condemnation mark cannot outlive its process and land on a pid
//    the next boot reassigns.
//
// 3. boot.go: oomEnsureRunning() belongs where the boot sequence finishes, beside whatever
//    starts the watchdog, so the patrol is live for the whole boot rather than only after
//    the first module asks for memory.
//
// 4. dump.go should render OomStatsSnapshot, OomPressureSnapshot and the top few
//    OomTallies under a "--- memory pressure ---" heading. The per-source breakdown is the
//    part worth rendering: a single total tells an operator that a module is large, and
//    the breakdown tells them which of three different fixes applies.
//
// 5. There is deliberately no Syscall group and no entry in the SContext composition.
//    kpanic is the precedent: a subsystem whose whole job is deciding when to end a module
//    must not be callable by one. A module that could invoke the sweep could not choose the
//    victim - the kernel does that from its own tallies and never from an argument - but it
//    could force sweeps at a rate that made the subsystem's own cost part of the pressure
//    it measures. The read-only exports above are the same shape as WatchdogPatrol's: they
//    report what the kernel already recorded and grant no ability to change it.
//
// 6. The host calls OomSetMemorySampler after Boot. Without a sampler the accounted
//    ceilings are still enforced and the host-pressure path is disabled, which is a working
//    configuration rather than a degraded one - the tallies are the part the kernel can
//    attribute, and they need no platform-specific code.
