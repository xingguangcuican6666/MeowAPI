/*
Copyright (C) 2023-2026 xingguangcuican6666

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
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// kseccomp: per-instance argument filters (subsystem: kseccomp).
//
// What it is for. policy.go decides WHICH OPERATIONS a domain may perform. manifest.go
// decides THE OUTER BOUNDARY of a scoped operation, fixed at load and signed by whoever
// reviewed the manifest. Neither can express "this one running instance may touch only
// the cache/ half of the paths it declared", because both are decided before the process
// exists and apply to every instance of the module alike.
//
// This subsystem is the third layer: per pid, attachable after load, deciding which
// ARGUMENTS one instance may pass. The relationship to the other two is the same as
// seccomp-bpf's to the syscall table - the table says which calls exist and who may make
// them, the filter says what those calls may be pointed at.
//
// It is NOT Linux seccomp-bpf and does not touch the process's syscall filter. A module
// in this kernel is Go code in the same address space, and there is no instruction it can
// be prevented from executing; kernel/sandbox.go is the file that hardens the host
// process, and it is a different mechanism with different limits. What this file filters
// is the kernel's own syscall surface, which is the surface that matters for the
// guarantees this kernel makes.
//
// The one invariant, and the reason the design is shaped the way it is.
//
//	A FILTER CAN ONLY NARROW. IT CAN NEVER WIDEN.
//
// If the manifest says cache/ and logs/, a filter may restrict to cache/. A filter may
// never add secrets/. If the domain ceiling does not grant an operation, no filter can
// grant it. This is enforced structurally rather than by convention, at install time
// rather than at check time: SeccompInstall intersects every rule against the pid's own
// manifest declaration and stores ONLY the intersection. A rule naming something outside
// the declaration is recorded as an exceeded entry, escalated on the audit chain, and
// then never consulted again - the check path has no access to it, so there is no branch
// a future maintainer could add that would make a filter additive.

// SeccompRuleKind is what a rule's patterns are matched against.
type SeccompRuleKind int

const (
	// SeccompRuleKey matches a metadata or KV key by prefix.
	SeccompRuleKey SeccompRuleKind = iota
	// SeccompRulePath matches a filesystem path by segment, reusing kv.go's
	// FSPathAllowed rather than reimplementing prefix matching: a declared "cache" must
	// cover "cache/blob" and must NOT cover "cache2/blob", and getting that right twice
	// is how two implementations end up disagreeing.
	SeccompRulePath
	// SeccompRuleHost matches a dial target's hostname, normalized the way net.go
	// normalizes it, so a filter cannot be evaded by respelling a declared host.
	SeccompRuleHost
	// SeccompRuleSecret matches a credential alias by prefix.
	SeccompRuleSecret
)

// String renders a rule kind for the console and the audit chain.
func (k SeccompRuleKind) String() string {
	switch k {
	case SeccompRuleKey:
		return "key"
	case SeccompRulePath:
		return "path"
	case SeccompRuleHost:
		return "host"
	case SeccompRuleSecret:
		return "secret"
	default:
		return fmt.Sprintf("rule-kind(%d)", int(k))
	}
}

// SeccompRule is one narrowing rule for one operation.
//
// Patterns are an allow-list, not a deny-list: a rule with patterns ["cache/"] permits
// arguments starting with "cache/" and refuses everything else. A deny-list would be
// wrong here because the default has to be refuse - a filter whose purpose is to narrow
// must fail closed, and a deny-list fails open for anything its author did not think of.
type SeccompRule struct {
	// Op is the operation this rule narrows. It must be filterable; see
	// SeccompFilterableOps.
	Op Op `json:"op"`
	// Kind selects what Patterns are matched against. It must agree with Op: a path
	// rule on metadata:read is refused rather than ignored, because an author who
	// mismatched them has a mental model that does not match the kernel's and silently
	// accepting it would leave them believing a filter is in force.
	Kind SeccompRuleKind `json:"kind"`
	// Patterns are the permitted argument prefixes. Empty means the operation is
	// refused entirely for this instance, which is a legitimate narrowing.
	Patterns []string `json:"patterns,omitempty"`
	// Budget caps how many times this instance may perform the operation, over the
	// lifetime of the filter. Zero means uncapped by budget.
	//
	// This is an absolute count and not a rate, deliberately: kqos already shapes
	// requests-per-minute and tokens-per-minute at the admission boundary, and a second
	// rate limiter here would be a second answer to the same question. What a filter can
	// express that kqos cannot is "this instance gets N of these, ever", which is a
	// containment statement about one running module rather than a shaping statement
	// about traffic.
	Budget int64 `json:"budget,omitempty"`
}

// SeccompFilter is the set of rules installed on one pid.
type SeccompFilter struct {
	// Label names the filter for the console and the audit chain. It is
	// operator-chosen prose and is never interpreted. Bounded.
	Label string `json:"label,omitempty"`
	// Rules are the narrowing rules. Two rules for one operation intersect: the
	// instance must satisfy both.
	Rules []SeccompRule `json:"rules"`
}

// SeccompExceeded is one rule that named something outside the pid's own declaration. It
// is reported so an operator can see an attempt to widen rather than only that the
// attempt did not take effect.
type SeccompExceeded struct {
	Op       Op     `json:"op"`
	Pattern  string `json:"pattern"`
	Reason   string `json:"reason"`
	KindName string `json:"kind"`
}

// SeccompInstallReport is what installing a filter returns. It says what took effect and
// what did not, because "installed" alone would let an operator believe a rule is in
// force when it was discarded for exceeding the declaration.
type SeccompInstallReport struct {
	PID    PID    `json:"pid"`
	Module string `json:"module,omitempty"`
	// Installed counts the rules that took effect.
	Installed int `json:"installed"`
	// Exceeded lists the patterns that named something outside this pid's own
	// declaration. They did not take effect, and the list is what makes an attempt to
	// widen visible rather than silently discarded.
	Exceeded []SeccompExceeded `json:"exceeded,omitempty"`
	// Applied renders each rule that took effect. It is named for what it holds rather
	// than "dropped", which would read as the opposite of the truth.
	Applied []string `json:"applied,omitempty"`
	Label   string   `json:"label,omitempty"`
}

// ErrSeccompRefused is the sentinel for an argument a filter does not permit. It is not a
// policy denial and IsDenied reports false for it, because the module does hold the
// operation - what it lacks is this argument.
//
// Callers must not turn this into a message that distinguishes "filtered out" from "does
// not exist". A module that can tell those apart can enumerate the filter's contents by
// probing, which is the same oracle kkeyring refuses to provide for credential aliases.
var ErrSeccompRefused = errors.New("kernel: seccomp: this argument is outside the instance filter")

// SeccompError reports a failure of this subsystem's own surface: an uninstallable
// filter, a rule that does not agree with its operation, an attempt by a module to touch
// its own filter.
type SeccompError struct {
	Msg string
	Err error
}

func (e *SeccompError) Error() string {
	if e.Err == nil {
		return "kernel: seccomp: " + e.Msg
	}
	return "kernel: seccomp: " + e.Msg + ": " + e.Err.Error()
}

func (e *SeccompError) Unwrap() error { return e.Err }

func seccompErr(format string, a ...any) error {
	return &SeccompError{Msg: fmt.Sprintf(format, a...)}
}

// ErrSeccompSelfModification is what a module gets for trying to install, change, remove
// or read its own filter. It is a distinct sentinel because the reason matters: this is
// not a missing grant, it is a thing no grant can provide.
var ErrSeccompSelfModification = errors.New(
	"kernel: seccomp: a module may not install, modify, remove or read its own filter")

// seccompFilterableOps is the set of operations a filter may narrow. It is a subset of
// the scoped operations plus the key-shaped ones, and it is explicit rather than derived
// from scopedOps because the two answer different questions: scopedOps says which
// operations carry a manifest boundary, this says which arguments the kernel can actually
// compare against a pattern. An operation whose argument is an fd or a byte slice has
// nothing to match, and pretending otherwise would produce a filter that looks like it
// controls something.
var seccompFilterableOps = map[Op]SeccompRuleKind{
	OpMetadataRead:  SeccompRuleKey,
	OpMetadataWrite: SeccompRuleKey,
	OpKVRead:        SeccompRuleKey,
	OpKVWrite:       SeccompRuleKey,
	OpFSRead:        SeccompRulePath,
	OpFSWrite:       SeccompRulePath,
	OpNetDial:       SeccompRuleHost,
	OpPeerDial:      SeccompRuleHost,
	OpSecretUse:     SeccompRuleSecret,
	OpRouteRegister: SeccompRulePath,
}

// SeccompFilterableOps reports which operations a filter may narrow, and what kind of
// rule each takes. It is a copy, sorted by operation name, so a module author can ask
// rather than guess - and so a test can assert the set rather than restate it.
func SeccompFilterableOps() map[Op]SeccompRuleKind {
	out := make(map[Op]SeccompRuleKind, len(seccompFilterableOps))
	for op, kind := range seccompFilterableOps {
		out[op] = kind
	}
	return out
}

// SeccompFilterableOpNames is the same set as sorted names, for the console dump.
func SeccompFilterableOpNames() []string {
	out := make([]string, 0, len(seccompFilterableOps))
	for op := range seccompFilterableOps {
		out = append(out, string(op))
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// State.

// seccompProjection is the narrowed form of one rule, computed at install time. It holds
// ONLY patterns proven to be inside the pid's manifest declaration, which is what makes
// widening structurally impossible: the check path reads this and never the original rule.
type seccompProjection struct {
	op      Op
	kind    SeccompRuleKind
	pattern []string
	budget  int64
	used    atomic.Int64
}

// seccompInstance is one pid's installed filter.
type seccompInstance struct {
	pid         PID
	module      string
	label       string
	installed   int64
	projections []*seccompProjection
	exceeded    []SeccompExceeded
	refused     atomic.Int64
	blocked     atomic.Int64
}

type seccompState struct {
	mu         sync.RWMutex
	byPid      map[PID]*seccompInstance
	installs   int64
	removals   int64
	historySeq int64
	refused    int64
	exceeded   int64
	evicted    int64
	history    []SeccompHistoryEntry
}

// maxSeccompHistory bounds the retained history. A filter install is rare and
// operator-driven, so the bound is small; what it protects against is a host that
// installs in a loop, which is a defect worth bounding rather than a workload worth
// supporting.
const maxSeccompHistory = 512

// maxSeccompRulesPerFilter and maxSeccompPatternsPerRule bound one filter. Both are
// kernel constants: a bound the filtered party could raise would not bound anything, and
// while only the host installs filters, a host bug that produced an unbounded filter
// would grow kernel memory on the hot path of every scoped call.
const (
	maxSeccompRulesPerFilter  = 64
	maxSeccompPatternsPerRule = 64
	maxSeccompLabelLen        = 128
	maxSeccompPatternLen      = 512
)

var kseccomp = seccompState{byPid: map[PID]*seccompInstance{}}

// ---------------------------------------------------------------------------
// The narrowing decision, at install time.

// seccompDeclaredPatterns is the pid's own manifest declaration for one rule kind. It is
// the ceiling a filter is intersected against, and it comes from the manifest rather than
// from anything the filter author wrote, which is the whole point: the declaration was
// reviewed and signed, the filter was not.
func seccompDeclaredPatterns(pid PID, op Op, kind SeccompRuleKind) ([]string, bool) {
	manifest, live := manifestOf(pid)
	if !live {
		return nil, false
	}
	switch kind {
	case SeccompRuleKey:
		// Metadata and KV keys have no manifest boundary: there is no key field in
		// Manifest, and the ceiling grants these operations over every key. The baseline a
		// key filter narrows against is therefore the ceiling rather than a declaration,
		// which seccompProject handles. Reporting "no declaration" here is what lets that
		// branch tell the two cases apart instead of guessing from the operation.
		return nil, false
	case SeccompRulePath:
		switch op {
		case OpFSRead:
			return manifest.ReadPaths, true
		case OpFSWrite:
			return manifest.WritePaths, true
		case OpRouteRegister:
			return manifest.ServeRoutes, true
		}
	case SeccompRuleHost:
		return manifest.AllowedHosts, true
	case SeccompRuleSecret:
		return manifest.SecretPrefixes, true
	}
	return nil, false
}

// seccompInsideDeclaration reports whether one pattern is inside the declaration, and
// says why if not. This is where the invariant lives.
//
// The comparison is containment in the declaration's sense rather than string equality:
// a filter pattern of "cache/blob" is inside a declared "cache" because everything under
// cache/blob is also under cache, and a filter pattern of "cache" is inside a declared
// "cache/blob" only if cache/blob covers it, which it does not. Getting the direction
// right is what makes narrowing narrowing.
func seccompInsideDeclaration(pattern string, declared []string, kind SeccompRuleKind) (bool, string) {
	if pattern == "" {
		// An empty pattern would match everything, so it is refused rather than
		// honoured. keyring.go's aliasInScope and kv.go's FSPathAllowed both skip an
		// empty entry for the same reason, and manifest validation already refuses an
		// empty declaration.
		return false, "an empty pattern matches every argument"
	}
	if len(declared) == 0 {
		return false, "this instance declared no boundary to narrow inside"
	}
	for _, d := range declared {
		if d == "" {
			continue
		}
		switch kind {
		case SeccompRulePath:
			// Paths use the same segment rule FSPathAllowed applies, so "cache2" is not
			// inside "cache" and "cache/blob" is. Both sides are cleaned, because a
			// declaration of "cache/" and a filter of "cache" are the same directory and
			// comparing them uncleaned would refuse a legitimate narrowing.
			if seccompPathInside(path.Clean(filepath.ToSlash(pattern)),
				path.Clean(filepath.ToSlash(d))) {
				return true, ""
			}
		case SeccompRuleHost:
			if netNormalizeHost(pattern) == netNormalizeHost(d) {
				return true, ""
			}
		default:
			// Keys and secret aliases are prefix-shaped, so containment is prefix
			// containment in the direction that narrows: the pattern must start with a
			// declared prefix.
			if strings.HasPrefix(pattern, d) {
				return true, ""
			}
		}
	}
	return false, fmt.Sprintf("%q is outside the declared boundary", pattern)
}

// seccompPathInside reports whether everything under `rel` is also under `base`, using the
// same segment rule kv.go applies to path scope. Both arguments are expected to be cleaned
// already; the root spellings are refused because a filter naming the data root is a filter
// over everything, which is what FSPathAllowed refuses for the same reason.
func seccompPathInside(rel, base string) bool {
	for _, root := range []string{".", "/", ".."} {
		if rel == root || base == root {
			return false
		}
	}
	if rel == base {
		return true
	}
	if strings.HasPrefix(base, "../") || strings.HasPrefix(rel, "../") {
		return false
	}
	return strings.HasPrefix(rel, base+"/")
}

// SeccompInstall attaches a filter to one running pid. It is host- and init-side only,
// and there is no syscall for it: a module that could install its own filter could
// install an empty one.
//
// The ctx argument is the installer's context, used for the audit attribution and for the
// liveness check. Passing nil means the host itself, which is what a boot-time or
// operator-console install does.
//
// It replaces any filter already installed on that pid, atomically: a caller holding a
// reference to the old instance sees the old rules until the swap, and no call sees half
// of two filters.
func SeccompInstall(ctx SContext, pid PID, f SeccompFilter) (SeccompInstallReport, error) {
	report := SeccompInstallReport{PID: pid, Label: f.Label}

	installer, err := seccompCheckInstaller(ctx, pid, "install")
	if err != nil {
		return report, err
	}
	if len(f.Label) > maxSeccompLabelLen {
		return report, seccompErr("a label of %d bytes exceeds the ceiling %d", len(f.Label), maxSeccompLabelLen)
	}
	if strings.ContainsAny(f.Label, "\n\r") {
		return report, seccompErr("a label must not contain a line break")
	}
	if len(f.Rules) > maxSeccompRulesPerFilter {
		return report, seccompErr("a filter of %d rules exceeds the ceiling %d", len(f.Rules), maxSeccompRulesPerFilter)
	}
	if len(f.Rules) == 0 {
		// An empty filter is refused rather than accepted as "no narrowing". Installing
		// one would look like a hardening step in the audit chain while changing
		// nothing, and a reader of that chain would believe the instance was filtered.
		return report, seccompErr("a filter with no rules narrows nothing and is refused")
	}

	// One pass, and the projections it builds are the ones that get stored. Projecting
	// twice - once to report and once to install - makes the stored filter a second
	// computation, and a divergence between the two would be invisible: the report would
	// describe a filter that is not the one in force. The manifest lookups happen outside
	// the write lock, which is the part that actually needed care.
	var projections []*seccompProjection
	for _, r := range f.Rules {
		proj, exceeded, derr := seccompProject(pid, r)
		if derr != nil {
			return report, derr
		}
		report.Exceeded = append(report.Exceeded, exceeded...)
		if proj != nil {
			projections = append(projections, proj)
			report.Installed++
			report.Applied = append(report.Applied, seccompProjectionLabel(proj))
		}
	}
	if len(projections) == 0 && len(report.Exceeded) == 0 {
		return report, seccompErr("every rule was dropped; nothing would be narrowed")
	}

	sort.Slice(projections, func(i, j int) bool { return projections[i].op < projections[j].op })
	inst := &seccompInstance{
		pid: pid, module: seccompModuleName(pid), label: f.Label, installed: mono(),
		projections: projections,
		exceeded:    append([]SeccompExceeded(nil), report.Exceeded...),
	}

	kseccomp.mu.Lock()
	kseccomp.byPid[pid] = inst
	kseccomp.installs++
	kseccomp.exceeded += int64(len(report.Exceeded))
	seq := kseccomp.seqLocked()
	kseccomp.history = append(kseccomp.history, SeccompHistoryEntry{
		Seq: seq, PID: pid, Module: inst.module, Label: inst.label, Action: "installed",
		Rules: report.Installed, Exceeded: len(report.Exceeded), At: mono(),
	})
	kseccomp.trimLocked()
	kseccomp.mu.Unlock()

	// A filter that discarded rules is escalated rather than only reported, because the
	// discarded rules were an attempt to reach past the declaration and the operator
	// needs that on the chain rather than in a return value they may not read.
	if len(report.Exceeded) > 0 {
		for _, e := range report.Exceeded {
			kaudit.record(AuditEscalation, installer, "instance filter exceeded the declared boundary", map[string]any{
				"target": pid, "module": inst.module, "op": string(e.Op),
				"kind": e.KindName, "pattern": e.Pattern, "reason": e.Reason,
				"label": f.Label,
			})
		}
		fault(installer, "instance filter exceeded the declared boundary", map[string]any{
			"target": pid, "module": inst.module, "exceeded": len(report.Exceeded),
		})
	}
	kaudit.record(AuditPolicy, installer, "instance filter installed", map[string]any{
		"target": pid, "module": inst.module, "label": f.Label,
		"rules": report.Installed, "exceeded": len(report.Exceeded),
	})
	return report, nil
}

// seccompProjectionLabel renders one projection for the install report.
func seccompProjectionLabel(p *seccompProjection) string {
	if len(p.pattern) == 0 {
		return fmt.Sprintf("%s: refused entirely", p.op)
	}
	return fmt.Sprintf("%s: %s %v", p.op, p.kind, p.pattern)
}

// seccompProject turns one author-written rule into the narrowed form the check path
// reads. It is where the invariant is enforced, and it is a separate function from
// SeccompInstall so a test can exercise the narrowing without installing anything.
func seccompProject(pid PID, r SeccompRule) (*seccompProjection, []SeccompExceeded, error) {
	kind, filterable := seccompFilterableOps[r.Op]
	if !filterable {
		return nil, nil, seccompErr("%q is not filterable; a filter narrows arguments, and this operation has none the kernel can compare", r.Op)
	}
	if r.Kind != kind {
		// Refused rather than corrected. Silently reinterpreting an author's rule would
		// leave them believing a path filter was in force on a key operation, which is
		// worse than an error they can fix.
		return nil, nil, seccompErr("%q takes a %s rule, not a %s rule", r.Op, kind, r.Kind)
	}
	if len(r.Patterns) > maxSeccompPatternsPerRule {
		return nil, nil, seccompErr("a rule with %d patterns exceeds the ceiling %d",
			len(r.Patterns), maxSeccompPatternsPerRule)
	}
	if r.Budget < 0 {
		return nil, nil, seccompErr("a budget of %d is not a count", r.Budget)
	}

	declared, hasDeclaration := seccompDeclaredPatterns(pid, r.Op, kind)
	proj := &seccompProjection{op: r.Op, kind: kind, budget: r.Budget}

	// A rule with no manifest declaration to intersect against is not refused, and the
	// reasoning is worth being explicit about because it looks like the invariant being
	// relaxed when it is not.
	//
	// Narrowing needs a baseline. For a path, host or secret rule the baseline is the
	// manifest declaration, so the projection is the intersection and a pattern outside it
	// is a widening attempt. For a key-shaped rule there is no declaration at all: the
	// domain ceiling grants metadata:read, kv:read and kv:write over EVERY key, so the
	// baseline is the whole key space and any pattern list is a strict reduction of it.
	// The invariant is that a filter cannot grant anything beyond ceiling AND declaration;
	// where the declaration is absent, "beyond" means beyond the ceiling, and a prefix list
	// never exceeds it.
	//
	// This is also the case the subsystem was specified for - confining a module to
	// metadata keys under one prefix - so refusing it would leave the one requirement
	// unimplementable while the rest looked finished.
	if !hasDeclaration {
		for _, p := range r.Patterns {
			if len(p) > maxSeccompPatternLen {
				return nil, nil, seccompErr("a pattern of %d bytes exceeds the ceiling %d", len(p), maxSeccompPatternLen)
			}
			if p == "" {
				// An empty prefix matches every key, which is not a narrowing of
				// anything and would silently install a rule that does nothing while the
				// audit chain said a filter was applied.
				return nil, nil, seccompErr("an empty key pattern matches every argument and narrows nothing")
			}
			proj.pattern = append(proj.pattern, p)
		}
		sort.Strings(proj.pattern)
		return proj, nil, nil
	}

	var exceeded []SeccompExceeded
	for _, p := range r.Patterns {
		if len(p) > maxSeccompPatternLen {
			return nil, nil, seccompErr("a pattern of %d bytes exceeds the ceiling %d", len(p), maxSeccompPatternLen)
		}
		inside, reason := seccompInsideDeclaration(p, declared, kind)
		if inside {
			proj.pattern = append(proj.pattern, p)
			continue
		}
		exceeded = append(exceeded, SeccompExceeded{
			Op: r.Op, KindName: kind.String(), Pattern: p, Reason: reason,
		})
	}
	sort.Strings(proj.pattern)

	// A rule whose patterns all exceeded keeps its budget but permits nothing, which is
	// the narrowing the declaration already implies. Returning a projection here rather
	// than nil is deliberate: the author asked for a rule, the declaration refused all of
	// its patterns, and the instance should end up refusing that operation rather than
	// falling through to the declaration's full scope.
	return proj, exceeded, nil
}

// seccompModuleName reads a pid's module name from the process table. It is read at
// install time and stored, because a filter outlives the module's live record in the
// history and a report naming an empty module is not actionable.
func seccompModuleName(pid PID) string {
	for _, r := range ProcTable() {
		if r.PID == pid {
			return r.Name
		}
	}
	return ""
}

// seccompCheckInstaller decides who may touch a pid's filter. It is the access rule, in
// one place, because the same rule has to hold for install, remove and read and three
// copies of it would drift.
//
// A nil context is the host. Init may filter a module it loaded. A module may not touch
// its own filter, and the reason is not that it lacks a grant: if a module could read its
// filter it would learn exactly what it is restricted from, and if it could modify it the
// subsystem would be a formality. There is no operation that would permit this and no
// domain that holds one.
func seccompCheckInstaller(ctx SContext, target PID, action string) (*sContext, error) {
	if ctx == nil {
		return nil, nil
	}
	c, ok := ctx.(*sContext)
	if !ok {
		return nil, errForeignContext
	}
	if c.pid == target {
		return nil, fmt.Errorf("%w (%s)", ErrSeccompSelfModification, action)
	}
	if c.dom == DomainKernel || c.dom == DomainInit {
		return c, nil
	}
	// Any other domain is refused outright. This is not a scoped operation and there is
	// no manifest field that could declare it, so a plugin domain has no path here at
	// all; returning a denial would imply one exists.
	return nil, &DeniedError{
		Op: Op("seccomp:" + action), Ctx: c,
		Reason: "only the kernel and init may " + action + " an instance filter",
	}
}

// SeccompRemove detaches a pid's filter. Host- and init-side only, for the same reason as
// install. Removing a filter is a widening of what the instance may do, so it is audited
// as a policy change rather than as bookkeeping.
func SeccompRemove(ctx SContext, pid PID) error {
	installer, err := seccompCheckInstaller(ctx, pid, "remove")
	if err != nil {
		return err
	}

	kseccomp.mu.Lock()
	inst, ok := kseccomp.byPid[pid]
	if !ok {
		kseccomp.mu.Unlock()
		return seccompErr("pid %d has no instance filter", pid)
	}
	delete(kseccomp.byPid, pid)
	kseccomp.removals++
	seq := kseccomp.seqLocked()
	label, module := inst.label, inst.module
	kseccomp.history = append(kseccomp.history, SeccompHistoryEntry{
		Seq: seq, PID: pid, Module: module, Label: label, Action: "removed",
		Rules: len(inst.projections), At: mono(),
	})
	kseccomp.trimLocked()
	kseccomp.mu.Unlock()

	fault(installer, "instance filter removed", map[string]any{
		"target": pid, "module": module, "label": label,
	})
	kaudit.record(AuditPolicy, installer, "instance filter removed", map[string]any{
		"target": pid, "module": module, "label": label,
	})
	return nil
}

// seccompDropFor removes a filter when its pid is gone. Called from the unload sequence,
// beside the other per-pid drops. It does not audit: the unload path already records the
// termination, and a filter dying with its process is the expected lifetime rather than a
// policy change.
func seccompDropFor(pid PID) {
	kseccomp.mu.Lock()
	defer kseccomp.mu.Unlock()
	delete(kseccomp.byPid, pid)
}

// ---------------------------------------------------------------------------
// The check path.

// SeccompAllow is the decision every scoped syscall consults, AFTER the policy check and
// AFTER the manifest scope check. The order matters and is not interchangeable:
//
//	domain ceiling  ->  manifest scope  ->  instance filter
//
// Consulting the filter first would let a filter's answer stand in for a grant the module
// does not have, and consulting it instead of the manifest scope would let a filter widen
// the declaration, which is the invariant this file exists to hold.
//
// It returns three distinct outcomes and the third never permits:
//
//	nil                          - the argument is inside the filter
//	ErrSeccompRefused (wrapped)  - the argument is outside the filter
//	a SeccompError               - the filter itself could not be consulted
//
// The op argument is checked against the projection's own op rather than used to look up
// a rule, so a caller cannot pass one operation and be judged by another's filter.
func SeccompAllow(ctx SContext, op Op, arg string) error {
	c, ok := ctx.(*sContext)
	if !ok {
		return errForeignContext
	}
	return seccompAllowFor(c.pid, c.name, op, arg)
}

// seccompAllowFor is the decision against a pid, so the kernel's own call sites - which
// have a context but are conceptually acting on a pid - and the tests share one path.
func seccompAllowFor(pid PID, module string, op Op, arg string) error {
	kseccomp.mu.RLock()
	inst := kseccomp.byPid[pid]
	kseccomp.mu.RUnlock()
	if inst == nil {
		// No filter installed is permitted. That is the correct default and not a hole:
		// the manifest scope already applied, and a filter is an additional narrowing an
		// operator chose to attach. Failing closed here would break every module on a
		// deployment that never installed a filter.
		return nil
	}

	var matched *seccompProjection
	for _, p := range inst.projections {
		if p.op == op {
			matched = p
			break
		}
	}
	if matched == nil {
		// The filter narrows other operations and says nothing about this one, so the
		// declaration's scope stands. A filter that refused every unlisted operation
		// would make installing one rule equivalent to revoking the module's other
		// grants, which is not what an operator means by narrowing one argument.
		return nil
	}

	// The budget is consumed before the argument is judged, because a call that is
	// refused still happened and still cost the kernel a decision. Counting only
	// permitted calls would let a module spend an unbounded number of refusals against a
	// budget meant to bound its activity.
	if matched.budget > 0 {
		if n := matched.used.Add(1); n > matched.budget {
			inst.blocked.Add(1)
			seccompRecordRefusal(pid, module, op, arg, "budget")
			return fmt.Errorf("%w: the budget of %d calls to %s is spent",
				ErrSeccompRefused, matched.budget, op)
		}
	}

	if len(matched.pattern) == 0 {
		// Every pattern this rule carried exceeded the declaration, so the operation is
		// refused entirely for this instance.
		inst.refused.Add(1)
		seccompRecordRefusal(pid, module, op, arg, "no permitted argument")
		return fmt.Errorf("%w: this instance may not perform %s at all", ErrSeccompRefused, op)
	}

	if seccompArgumentInside(arg, matched) {
		return nil
	}
	inst.refused.Add(1)
	seccompRecordRefusal(pid, module, op, arg, "outside the filter")
	return fmt.Errorf("%w", ErrSeccompRefused)
}

// seccompArgumentInside matches one argument against one projection, using the matching
// semantics that already exist for that argument shape rather than a new set.
func seccompArgumentInside(arg string, p *seccompProjection) bool {
	switch p.kind {
	case SeccompRulePath:
		// kv.go's own matcher, on the argument cleaned the way kv.go cleans it. Both
		// halves of that matter. Using FSPathAllowed keeps one implementation of segment
		// matching, so a filter and the manifest scope agree on what "cache" covers. And
		// cleaning first is what stops "cache/x/../logs/y" from prefix-matching "cache":
		// FSCheckRead passes path.Clean(filepath.ToSlash(rel)) to the same function, so
		// matching the raw string would permit an argument the manifest scope refuses.
		// Two matchers that disagree is a bypass rather than a stylistic difference.
		return FSPathAllowed(path.Clean(filepath.ToSlash(arg)), p.pattern)
	case SeccompRuleHost:
		normalized := netNormalizeHost(arg)
		for _, pattern := range p.pattern {
			if netNormalizeHost(pattern) == normalized {
				return true
			}
		}
		return false
	default:
		// Keys and secret aliases are prefix-shaped. An empty argument is refused: a
		// prefix match against "" would permit everything, and keyring.go skips an empty
		// prefix for the same reason.
		if arg == "" {
			return false
		}
		for _, pattern := range p.pattern {
			if pattern == "" {
				continue
			}
			if strings.HasPrefix(arg, pattern) {
				return true
			}
		}
		return false
	}
}

// seccompRecordRefusal faults and audits one refusal. It does NOT distinguish "filtered
// out" from "does not exist" in the message it returns to the caller, because that
// distinction is an enumeration oracle: a module that can tell them apart can map its own
// filter by probing, and a filter whose contents a module can read is a filter the module
// can plan around.
//
// The audit chain and the console DO carry the argument, since both are operator-visible
// and neither is readable by the module. That asymmetry is deliberate.
func seccompRecordRefusal(pid PID, module string, op Op, arg, reason string) {
	kseccomp.mu.Lock()
	kseccomp.refused++
	kseccomp.mu.Unlock()

	fault(nil, "instance filter refused an argument", map[string]any{
		"pid": pid, "module": module, "op": string(op), "argument": arg, "reason": reason,
	})
	kaudit.record(AuditDenial, nil, "instance filter refusal", map[string]any{
		"pid": pid, "module": module, "op": string(op), "argument": arg, "reason": reason,
	})
}

// SeccompFiltered reports whether a pid has a filter installed. It is the one thing a
// module may learn about its own confinement, and it is a boolean rather than the rules:
// knowing that a filter exists is useful to a module that wants to shed load or report
// its own state, and knowing what it says is the oracle this file refuses to provide.
//
// It is also how init and the host check whether a filter took, which is the other reason
// the answer is a boolean rather than the contents - the caller that needs the contents is
// SeccompSnapshot, which is host-side.
func SeccompFiltered(pid PID) bool {
	kseccomp.mu.RLock()
	defer kseccomp.mu.RUnlock()
	_, ok := kseccomp.byPid[pid]
	return ok
}

// ---------------------------------------------------------------------------
// Snapshots.

// SeccompRuleView is one projection as a host sees it.
type SeccompRuleView struct {
	Op       Op       `json:"op"`
	Kind     string   `json:"kind"`
	Patterns []string `json:"patterns"`
	Budget   int64    `json:"budget,omitempty"`
	Used     int64    `json:"used"`
}

// SeccompSnapshot is one pid's filter as a host sees it.
type SeccompSnapshot struct {
	PID        PID               `json:"pid"`
	Module     string            `json:"module,omitempty"`
	Label      string            `json:"label,omitempty"`
	Installed  int64             `json:"installed_at"`
	Rules      []SeccompRuleView `json:"rules"`
	Exceeded   []SeccompExceeded `json:"exceeded,omitempty"`
	Refused    int64             `json:"refused"`
	BudgetHits int64             `json:"budget_hits"`
}

// SeccompSnapshotFor returns one pid's filter, as a copy. Host- and init-side only, for
// the reason SeccompFiltered gives: the contents are the thing a module must not be able
// to read.
func SeccompSnapshotFor(ctx SContext, pid PID) (SeccompSnapshot, error) {
	if _, err := seccompCheckInstaller(ctx, pid, "read"); err != nil {
		return SeccompSnapshot{}, err
	}
	kseccomp.mu.RLock()
	inst, ok := kseccomp.byPid[pid]
	kseccomp.mu.RUnlock()
	if !ok {
		return SeccompSnapshot{}, seccompErr("pid %d has no instance filter", pid)
	}

	out := SeccompSnapshot{
		PID: inst.pid, Module: inst.module, Label: inst.label,
		Installed: inst.installed, Refused: inst.refused.Load(),
		BudgetHits: inst.blocked.Load(),
		Exceeded:   append([]SeccompExceeded(nil), inst.exceeded...),
	}
	for _, p := range inst.projections {
		out.Rules = append(out.Rules, SeccompRuleView{
			Op: p.op, Kind: p.kind.String(),
			Patterns: append([]string(nil), p.pattern...),
			Budget:   p.budget, Used: p.used.Load(),
		})
	}
	return out, nil
}

// SeccompStats is the subsystem's totals.
type SeccompStats struct {
	Filtered int   `json:"filtered"`
	Installs int64 `json:"installs"`
	Removals int64 `json:"removals"`
	Refused  int64 `json:"refused"`
	Exceeded int64 `json:"exceeded"`
	History  int   `json:"history"`
	Evicted  int64 `json:"evicted"`
	MaxRules int   `json:"max_rules"`
}

// SeccompStatsSnapshot returns the totals. Counters only, so it is cheap enough for a
// status path, and it exposes no filter contents.
func SeccompStatsSnapshot() SeccompStats {
	kseccomp.mu.RLock()
	defer kseccomp.mu.RUnlock()
	return SeccompStats{
		Filtered: len(kseccomp.byPid), Installs: kseccomp.installs,
		Removals: kseccomp.removals, Refused: kseccomp.refused,
		Exceeded: kseccomp.exceeded, History: len(kseccomp.history),
		Evicted: kseccomp.evicted, MaxRules: maxSeccompRulesPerFilter,
	}
}

// SeccompHistoryEntry is one retained install or removal. It is declared once and used as
// the ledger's own element type rather than being mirrored by an internal struct, which is
// what meter.go does with MeterRecord: two shapes of the same record eventually differ by a
// field name, and then a snapshot silently loses it.
type SeccompHistoryEntry struct {
	Seq      int64  `json:"seq"`
	PID      PID    `json:"pid"`
	Module   string `json:"module,omitempty"`
	Label    string `json:"label,omitempty"`
	Action   string `json:"action"`
	Rules    int    `json:"rules"`
	Exceeded int    `json:"exceeded"`
	At       int64  `json:"at"`
}

// SeccompHistory returns retained installs and removals, oldest first, as copies.
func SeccompHistory() []SeccompHistoryEntry {
	kseccomp.mu.RLock()
	defer kseccomp.mu.RUnlock()
	return append([]SeccompHistoryEntry(nil), kseccomp.history...)
}

// seqLocked allocates a history sequence number. Caller holds kseccomp.mu.
func (s *seccompState) seqLocked() int64 {
	s.historySeq++
	return s.historySeq
}

// trimLocked drops the history back to seven eighths of its bound in ONE step. Caller
// holds kseccomp.mu.
//
// Trimming exactly to the bound would reallocate and copy the whole history on every
// install past the ceiling, under the write lock.
func (s *seccompState) trimLocked() {
	if len(s.history) <= maxSeccompHistory {
		return
	}
	keep := maxSeccompHistory - maxSeccompHistory/8
	if len(s.history) <= keep {
		return
	}
	over := len(s.history) - keep
	s.evicted += int64(over)
	s.history = append([]SeccompHistoryEntry(nil), s.history[over:]...)
}

// resetSeccomp clears every filter and the history for a fresh boot.
func resetSeccomp() {
	kseccomp.mu.Lock()
	defer kseccomp.mu.Unlock()
	kseccomp.byPid = map[PID]*seccompInstance{}
	kseccomp.history = nil
	kseccomp.historySeq = 0
	kseccomp.installs = 0
	kseccomp.removals = 0
	kseccomp.refused = 0
	kseccomp.exceeded = 0
	kseccomp.evicted = 0
}

// ---------------------------------------------------------------------------
// Syscall surface.

// SyscallSeccomp is the module-facing half, and it is one method.
//
// A module may learn that it is filtered and nothing more. The contents are withheld for
// the same reason SeccompSnapshotFor refuses a self-read: a module that can read its filter
// knows exactly what it is restricted from, and a module that can modify it makes the
// subsystem a formality. Knowing that a filter exists is useful - a module can shed load or
// report its own confinement - so the boolean is granted and the rules are not.
//
// There is no Op for this in policy.go and none is needed: the answer is about the caller's
// own pid and reveals nothing about anybody else, so the liveness check c.syscall("")
// performs is the whole of the gate.
type SyscallSeccomp interface {
	// SyscallSeccompFiltered reports whether an instance filter is installed on the
	// caller's own pid.
	SyscallSeccompFiltered() (bool, error)
}

func (c *sContext) SyscallSeccompFiltered() (bool, error) {
	if err := c.syscall(""); err != nil {
		return false, err
	}
	return SeccompFiltered(c.pid), nil
}

// ---------------------------------------------------------------------------
// WHERE THIS IS WIRED, and the ordering rule the call sites follow.
//
// Every site consults SeccompAllow AFTER the policy gate and AFTER the manifest scope
// check, so the layers are ceiling, scope, filter. A filter consulted first would have its
// answer stand in for a declaration that was never checked, which is the widening this
// subsystem exists to be unable to do.
//
//	kv.go        FSCheckRead / FSCheckWrite    the relative path
//	kv.go        KVGet / KVPut / KVDelete      the key, after the shape check
//	metadata.go  SyscallMetadataGet / Set      the key
//	net.go       NetDial                       the host, after NetHostAllowed
//	peer.go      PeerDial                      the endpoint's host, after peerEndpointAllowed
//	keyring.go   SecretUse                     the alias, after the prefix scope check
//	service.go   RouteRegister                 the NORMALIZED path, after the declaration check
//
// Three of those carry a reason worth repeating at the site rather than only here. KVPut
// checks the key's shape before the filter, because a filter refusal audited for a key that
// was going to be rejected as malformed anyway is a misleading entry on the chain.
// RouteRegister filters the normalized path, the same string the declaration was compared
// against, so a spelling difference cannot decide the answer. And SecretUse folds a filter
// refusal into the same message as an unknown alias, because unlike every other site the
// alias inventory belongs to the deployment rather than to the manifest, so a distinct
// refusal there would answer a question the module could not otherwise answer.
//
// tests/seccomp's end-to-end cases drive every one of these through the public syscall,
// and each was verified by removing the call site and watching that test fail. A test that
// calls SeccompAllow directly cannot detect an unwired site, which is the exact way this
// subsystem could have shipped looking complete and enforcing nothing.
//
// The rest of the wiring: resetSeccomp() is in resetKernel(), seccompDropFor(pid) is in
// module.go's unload sequence beside netDropAllFor, SyscallSeccomp is in the SContext
// composition in context.go, and dump.go renders an "--- instance filters ---" section. The
// dump is host-side, so showing patterns there is safe; showing them through a
// module-readable surface is not, which is why SyscallSeccompFiltered returns a boolean.
