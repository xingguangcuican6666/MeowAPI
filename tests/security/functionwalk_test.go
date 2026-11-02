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

package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryPackageLevelFunctionIsClassified is the walk that TestAZeroKernelCannotAct
// already runs over *Kernel's METHOD set, extended to the package's exported FUNCTIONS.
//
// Why it matters, stated as the thing it would have prevented. package kernel exports
// 262 functions. Ninety take an SContext and are gated by the check inside them. The
// rest are reachable by any code that imports the package - which today includes a
// component that chooses to import it - and nothing in this suite looked at them. That
// is a real surface: an audit reproduced reading the chain, dumping kernel state and
// revoking another pid's grants from a probe with no context at all. Those are not
// escalations of a boundary the kernel claims, because the contract says a module
// imports abi and not kernel; they are that boundary's enforcement being absent.
//
// What this test does NOT do is call the functions. It classifies them from the source,
// so a new one fails the build with a message saying what to do about it, and the
// classification below is a decision on the record rather than a default. Calling them
// would need a probe per shape and would still not answer "is this host-only".
//
// The same rule as the method walk: an exemption must carry a reason. A list of bare
// names becomes the hole it was meant to close, because the next author adds one and
// nobody can tell whether it belongs.

// hostOnlyFunctions are exported package-level functions that act on kernel state and
// are NOT safe for module code to call, each with the reason.
//
// These are the functions a module must never be able to reach. The gate keeping them
// out of a module's hands is the import boundary - a module imports abi - plus the
// signing review that is supposed to enforce it. Enumerating them is what makes that a
// checked property rather than a convention: if one is ever re-shaped to be module
// reachable, it moves out of this list and the test says so.
var hostOnlyFunctions = map[string]string{
	"Boot":                  "creates the booted kernel; only a host process can call it and the handle it returns is the authority",
	"Register":              "publishes a module factory; a module that could call it would ship code under a name it chose",
	"Unregister":            "removes a factory; same reason as Register",
	"RouteDeclare":          "declares a route outside a load; the manifest path is the reviewed one",
	"Dump":                  "renders every subsystem's state; a read of everything is the audit trail's equal",
	"FSSetDataRoot":         "chooses where a module's files are; a module that chose its own root would choose the boundary",
	"SetFSScope":            "grants a pid's path scope; the loader calls it from the manifest and nothing else may",
	"ClearFSScope":          "drops a pid's path scope; paired with SetFSScope",
	"DropPipesFor":          "reclaims a dead pid's pipes; a reclamation primitive a module could aim at another pid",
	"KVDropNamespace":       "drops a KV namespace by pid; the unload path calls it, a module must not drop another's",
	"ShmDropNamespace":      "drops shared segments by pid; same reason as KVDropNamespace",
	"BootSet":               "writes the trust root, which is sealed after boot; a write here is a trust-root rewrite",
	"VerifierSetPolicy":     "changes the appraisal posture; the posture can only tighten and a module must not tighten it for others",
	"VerifierRecord":        "appends to the appraisal ledger; the ledger is evidence and a module that wrote to it could launder a refusal",
	"SetQosPolicy":          "sets an admission policy; a module that could set one could raise its own rate",
	"TokenSetStrictFloor":   "loosens or tightens the usage floor; a module that could loosen it would loosen its own check",
	"NetAllowPrivateRanges": "widens egress to private ranges; a module that could widen it would reach the metadata service",
	"OomPatrol":             "terminates modules under memory pressure; a module that could run a patrol could terminate its neighbours",
	"WatchdogPatrol":        "captures stacks and reports overdue work; a module that could run one could name another as overdue",
	"PanicRegister":         "installs a crash notifier; a notifier a module installed would run at kernel exit",
	"PanicUnregister":       "removes a crash notifier; paired with PanicRegister",
	"PanicRegisterBuiltins": "installs the built-in flush chain; called on every exit path",
	"PanicSetCrashWriter":   "redirects the crash dump; a module that redirected it could erase the evidence of a crash",
	"PanicFlush":            "runs the exit flush; called from a crash path where no *Kernel exists, which is why the panic group cannot be handle methods",
	"PanicLastFlush":        "reports the last flush; the record of what survived",

	// The seven below are reads of other pids' activity with NO operator-facing reader
	// anywhere: they appear in neither kernel.Dump nor internal/console, and their only
	// non-test references are their own definitions. They were classified module-reachable
	// on the reasoning that the console already shows them to an authenticated operator,
	// which is false for these seven - the peer who checked every member found it, and
	// checking is the only reason it surfaced. There is no disclosure argument left to
	// make for them, so they are host-only.
	"NetHistory":        "egress history with no operator-facing reader; it is in neither Dump nor the console, so nothing shows it to anyone and a module reaching it would be the only reader",
	"TraceQuery":        "span history with no operator-facing reader; the one in-package caller is TraceStatsSnapshot, which is a count and not a query",
	"SeccompHistory":    "instance-filter history with no operator-facing reader",
	"VerifierLedger":    "the appraisal ledger, which is evidence; VerifierRecord is already host-only for writing to it, and a reader that can enumerate every admission is the same exposure from the other side",
	"VerifierLedgerFor": "one module's appraisal ledger; same reason as VerifierLedger, and it is keyed by a module NAME a caller chooses",
	"VerifierLedgerLen": "the ledger's length; the smallest of the three and still host-only for consistency with the ledger itself",
	"TokenLedger":       "per-module usage accounting with no operator-facing reader",

	// TokenMeasureFlow is the one member of the former pid-keyed group that MUTATES
	// rather than reads: it increments ktokenizer.byPid[pid].FlowBytes and FlowTokens
	// under the lock and creates the entry when absent. A module calling it with a
	// neighbour's pid would charge that neighbour's flow budget rather than observe it,
	// which is a write into another module's accounting and belongs here, not in a
	// group whose stated reason is about what a caller learns.
	"TokenMeasureFlow": "writes into the pid's flow accounting under the lock and creates the entry if absent, so a caller with a neighbour's pid charges that neighbour's budget rather than reading it",
}

// identityKeyedFunctions are exported functions keyed by an identity the CALLER supplies
// rather than by the caller's own pid - a mesh node id, a module name, a string key -
// with no context to check it against.
//
// They are listed apart from pidKeyedFunctions because the reason is genuinely different
// and the first version of this file had them wrong: it said "takes an arbitrary pid"
// about PeerLatencyOf(nodeID string) and ReceiptCursor(nodeID string), which take no pid
// at all. A reason that does not describe the function it is attached to is worse than
// no reason, because a reader who trusts it stops checking - and the signature assertion
// below is what makes that specific mistake impossible to repeat.
var identityKeyedFunctions = map[string]string{
	"PeerLatencyOf": "takes a mesh node identity the caller supplies and no context, so it answers for any peer in the table; a module that could reach it would learn the mesh's latency view of nodes it has no business knowing about",
	"ReceiptCursor": "takes a mesh node identity the caller supplies and no context, so it answers for any peer's replay cursor; the cursor is what stops a receipt being replayed, and enumerating cursors is reconnaissance for that",
	"QosPolicyFor":  "takes a policy key the caller supplies and no context, so it answers for any class's admission policy including one it does not run under",
}

// pidKeyedFunctions are exported functions that take a pid and no SContext, so they
// answer for a pid whose owner they cannot verify. They are listed separately from
// hostOnlyFunctions only because the reason is one sentence for all of them and it is
// worth saying once rather than nineteen times.
//
// They are not a hole the kernel has chosen: a syscall that takes a pid takes one the
// kernel checks against the caller's own. These do the checking at a level that does not
// exist for them, which is exactly why a module must not reach them.
var pidKeyedFunctions = map[string]string{
	"CPUStatOf":        "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"FDCount":          "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"FDList":           "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"GrantsFor":        "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"KVBytes":          "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"KVCount":          "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"NetHostAllowed":   "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"NetSockets":       "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"OomTallyFor":      "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"SchedCount":       "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"SeccompFiltered":  "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"SignalPending":    "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"SignalState":      "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"SignalTerminated": "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"TTYList":          "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
	"TraceLiveFor":     "takes an arbitrary pid and no context, so it answers for a pid whose owner it cannot verify; a module calling it with a neighbour's pid learns that neighbour's state",
}

// reachableGroups is the module-reachable half of the classification, kept as groups so
// a reason and the names it covers cannot drift apart.
//
// The distinction from hostOnlyFunctions is not "reads versus writes" - several of these
// take a lock and copy a map. It is whether the ANSWER is already visible to the caller
// through a syscall it holds, and whether calling it reveals anything a module could not
// otherwise reach. A module that reached one of these still had to import package kernel,
// which the contract forbids; the point of the list is that if that contract is ever
// relaxed, these are the ones that are already safe and hostOnlyFunctions is the set that
// has to be re-gated first.
//
// Adding a name to a group is asserting the group's reason applies to it. That is exactly
// the decision this file exists to force.
var reachableGroups = []struct {
	reason string
	names  []string
}{
	{
		"A pure predicate over a compiled table, or a bounded constant. A module already " +
			"knows which operation it asked for, and these are the tables its own manifest was " +
			"validated against, so reading them tells it nothing about any other module.",
		[]string{
			"Allowed", "OpsFor", "IsScoped", "IsKernelEvent", "KernelEvents", "IsDenied",
			"DenialReason", "IsSchedLimit", "IsSignalQueueFull", "DefaultAuditWindow",
			"MinAuditWindow", "AuditWindow", "MaxCryptoInputBytes", "MaxCryptoRandomBytes",
			"MaxPeers", "MaxReceiptLabelLen", "MaxSecretValueBytes", "MaxSecrets",
			"MaxSlashRecords", "MaxVerifyLedgerEntries", "HashAlgos", "SecretActions",
			"SignalKinds", "SlashKinds", "SpanKinds", "UsageKinds", "PeerFrameKinds",
			"VerifierPolicies", "VerifierFindingCodes", "SeccompFilterableOps",
			"SeccompFilterableOpNames", "FSPathAllowed", "FSResolve",
		},
	},
	{
		"Whole-kernel aggregates that are not keyed by pid: totals, counters, the " +
			"posture, the metadata namespace. A module learns a number about the kernel, not a " +
			"fact about a specific neighbour, and the operator's console prints the same numbers " +
			"to an unauthenticated session on purpose.",
		[]string{
			"UsageTotal", "UsageRejected", "UsageSnapshot", "CPUStats", "CPUDenied",
			"MetadataSnapshot", "Narrowed", "PolicyNarrowing", "TokenStrictFloor", "QosKeys",
		},
	},
	{
		"A read of OTHER pids' activity: the process table, the route table, the module " +
			"registry, the audit window, the memory tallies, the lock table. This is the group " +
			"whose safety rests entirely on the import boundary rather than on anything the " +
			"function checks, and it is separated out so the reason is not hidden inside a " +
			"larger one. It is acceptable because every member is already shown to an " +
			"AUTHENTICATED operator - by the console's ps, ls and audit commands, or by " +
			"kernel.Dump, which is gated on the same credential. If that boundary is ever " +
			"relaxed, THIS group is the one that needs a pid check added first. " +
			"The reason used to claim this for seven more functions - NetHistory, TraceQuery, " +
			"SeccompHistory, the three VerifierLedger readers and TokenLedger - and it was " +
			"false: those appear in neither Dump nor the console, so there was no operator " +
			"already reading them and no disclosure argument to make. They are in " +
			"hostOnlyFunctions now, which is where a read with no reader belongs.",
		[]string{
			"ProcTable", "RouteTable", "LoadedModules", "Registered", "AuditQuery",
			"AuditHead", "AuditLen", "PeerTableSnapshot", "OomTallies", "SecretInventory", "SlashLedger",
			"TokenTotalsByModule", "WatchdogSnapshot", "LockSnapshot",
		},
	},
	{
		"A pure function of its arguments, or of bytes the caller supplied. Nothing with " +
			"kernel state behind it: the receipt encoding, the chain verifier, the binding " +
			"payloads and the token measurement are all deterministic and take their input as " +
			"a parameter.",
		[]string{
			"ReceiptPayload", "ReceiptDigest", "DecodeReceipt", "SequenceGaps", "VerifyEntry",
			"VerifyChain", "TokenMeasure", "NewRequestID", "NewTraceID",
			"NewOomTally", "OomSortVictims", "OomVictimEligible", "PeerHandshakePayload",
			"PeerAnnouncePayload", "PeerForwardDigest", "VerifierBindingPayload",
		},
	},
	{
		"A bounded counter or aggregate about the kernel as a whole rather than about one " +
			"pid: how many sockets are pooled, how many segments exist, how many spans were " +
			"abandoned. Each is capped by its own ceiling and each answers a question a module " +
			"could already answer about itself by counting its own calls. Nothing in this group " +
			"is keyed by an identity the caller supplies - those are in identityKeyedFunctions.",
		[]string{
			"NetAddressAllowed",
			"NetPrivateRanges", "NetStatsSnapshot", "PipeStatsSnapshot",
			"RouteStatsSnapshot", "EventStatsSnapshot", "MeterQuery", "MeterTotalsSnapshot", "OomCondemned", "OomHistory",
			"OomPressureSnapshot", "OomStatsSnapshot",
			"PanicNotifiers", "PeerEvents", "PeerStatsSnapshot", "QosStatsSnapshot", "ReceiptStats", "SeccompStatsSnapshot", "SecretCount",
			"SecretUseStats", "ShmPoolBytes", "ShmSnapshot", "SlashStatsSnapshot", "SlotStatsSnapshot",
			"TTYStatsSnapshot", "TokenStatsSnapshot", "TraceStatsSnapshot",
			"VerifierPolicyCurrent", "VerifierPolicyExplicit", "WatchdogLive",
		},
	},
	{
		"A decision a module must be able to make for itself: is this manifest valid, does " +
			"this signature verify, is this peer's announcement genuine. Refusing these would " +
			"leave the module trusting unsigned data instead, which is not a safety property.",
		[]string{
			"ValidateManifest", "VerifyManifest", "VerifierAuditDeclaration",
			"VerifyPeerHandshake", "VerifyPeerAnnouncement",
		},
	},
	{
		"The sealed trust root and the kernel's own read-only accessors. A module's manifest " +
			"is checked against these ceilings and roots, and every one of them is already echoed " +
			"in the boot record the audit chain holds. There is no writer in this group: BootSet " +
			"is in hostOnlyFunctions.",
		[]string{
			"BootGet", "BootAll", "BootDigest", "BootSealed", "ClusterRootKeys", "NodeKeyID",
			"NodeVerificationKey", "Limits", "EffectiveOomThresholds", "KernelClock",
			"KernelConsole", "CrashReport",
		},
	},
}

// moduleReachableFunctions is built from reachableGroups rather than written twice, so a
// name cannot be in one and missing from the other.
var moduleReachableFunctions = func() map[string]string {
	m := make(map[string]string, 256)
	for _, g := range reachableGroups {
		for _, n := range g.names {
			if _, dup := m[n]; dup {
				// A duplicate is an error the map would otherwise silently absorb.
				panic("reachableGroups lists " + n + " twice")
			}
			m[n] = g.reason
		}
	}
	return m
}()

// TestEveryPackageLevelFunctionIsClassified parses package kernel and fails on any
// exported function that is neither a context-taking syscall nor in one of the two
// lists above.
func TestEveryPackageLevelFunctionIsClassified(t *testing.T) {
	dir := "../../kernel"
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no source files under kernel/; the glob is wrong")
	}

	fset := token.NewFileSet()
	var (
		checked  int
		syscalls int
	)
	var unclassified []string
	// sigs records every exported function's declaration so the shape assertions at
	// the bottom can check a classification against the signature it claims to describe.
	sigs := map[string]*ast.FuncDecl{}

	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		checked++

		for _, decl := range af.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			name := fn.Name.Name
			sigs[name] = fn

			// A function whose first parameter is an SContext resolves that context
			// against the kernel's own type before doing anything, which is the gate.
			// This is the same rule abi's SContext documents and the one the
			// nilcontext sweep relies on.
			if takesContext(fn) {
				syscalls++
				continue
			}
			if _, ok := hostOnlyFunctions[name]; ok {
				continue
			}
			if _, ok := pidKeyedFunctions[name]; ok {
				continue
			}
			if _, ok := identityKeyedFunctions[name]; ok {
				continue
			}
			if _, ok := moduleReachableFunctions[name]; ok {
				continue
			}
			unclassified = append(unclassified, name)
		}
	}

	sort.Strings(unclassified)
	for _, name := range unclassified {
		t.Errorf("kernel.%s is exported, takes no SContext, and is in no list.\n"+
			"  If a module must never reach it, add it to hostOnlyFunctions with the reason;\n"+
			"  if calling it teaches a module nothing it cannot already reach, add it to the\n"+
			"  matching reachableGroups entry. Silence is not an exemption.", name)
	}

	// A classification must match the signature it claims to describe.
	//
	// Without this, a name can sit in a group whose stated reason is simply false about
	// it, and both tests pass. That is not hypothetical: moving DefaultAuditWindow, which
	// takes no parameters at all, into pidKeyedFunctions left the suite green, and the
	// first draft of this file said "takes an arbitrary pid" about PeerLatencyOf and
	// ReceiptCursor, which take a node id. A reason nobody checks is a decoration.
	//
	// The checks are the ones the reasons actually assert, and nothing more: a pid-keyed
	// function must have a PID parameter, an identity-keyed one a string parameter, and no
	// member of any of the three host-side lists may take an SContext, because taking one
	// is what makes the other three categories unnecessary.
	for name := range pidKeyedFunctions {
		fn, ok := sigs[name]
		if !ok {
			continue // the staleness test reports a name that is not a function
		}
		if takesContext(fn) {
			t.Errorf("%s is in pidKeyedFunctions but takes an SContext, so it is gated by "+
				"its own check and belongs in neither host list", name)
		}
		if !hasParamOfType(fn, "PID") {
			t.Errorf("%s is in pidKeyedFunctions but takes no PID parameter, so the reason "+
				"attached to it does not describe it; check the signature and move it to the "+
				"list whose reason does", name)
		}
	}
	for name := range identityKeyedFunctions {
		fn, ok := sigs[name]
		if !ok {
			continue
		}
		if takesContext(fn) {
			t.Errorf("%s is in identityKeyedFunctions but takes an SContext", name)
		}
		if !hasParamOfType(fn, "string") {
			t.Errorf("%s is in identityKeyedFunctions but takes no string parameter, so the "+
				"reason attached to it does not describe it", name)
		}
	}
	for name := range hostOnlyFunctions {
		fn, ok := sigs[name]
		if !ok {
			continue
		}
		if takesContext(fn) {
			t.Errorf("%s is in hostOnlyFunctions but takes an SContext; a context-taking "+
				"function is already gated by its own check, so listing it here hides which "+
				"gate actually applies", name)
		}
	}
	for name := range moduleReachableFunctions {
		fn, ok := sigs[name]
		if !ok {
			continue
		}
		if takesContext(fn) {
			t.Errorf("%s is in reachableGroups but takes an SContext; it is a syscall and is "+
				"counted as one, so it should not be classified here as well", name)
		}
	}

	// The walk found what it expected. Without these the test passes on an empty parse
	// or on a parameter walk that matched nothing, which is the failure mode a census
	// has and a behavioural assertion does not.
	if checked == 0 {
		t.Fatal("no source files were parsed")
	}
	if syscalls < 80 {
		t.Fatalf("found %d context-taking functions; the package has around 90, so the "+
			"parameter walk is wrong", syscalls)
	}
	if len(hostOnlyFunctions) < 20 {
		t.Fatalf("the host-only list holds %d entries, fewer than the audit found",
			len(hostOnlyFunctions))
	}
	if len(pidKeyedFunctions) < 10 {
		t.Fatalf("the pid-keyed list holds %d entries; a census of the package finds "+
			"around nineteen", len(pidKeyedFunctions))
	}
	if len(moduleReachableFunctions) < 100 {
		t.Fatalf("the module-reachable list holds %d entries; the package exports 262 "+
			"functions and around 130 of them touch state, so this walk is undercounting",
			len(moduleReachableFunctions))
	}
}

// hasParamOfType reports whether any parameter has the named type, spelled either bare
// (PID) or qualified (abi.PID). It answers the shape question a group's reason asserts,
// so a classification cannot claim a parameter the function does not have.
func hasParamOfType(fn *ast.FuncDecl, want string) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		switch typ := field.Type.(type) {
		case *ast.Ident:
			if typ.Name == want {
				return true
			}
		case *ast.SelectorExpr:
			if typ.Sel != nil && typ.Sel.Name == want {
				return true
			}
		case *ast.Ellipsis:
			// A variadic parameter's element type is what a caller passes.
			if id, ok := typ.Elt.(*ast.Ident); ok && id.Name == want {
				return true
			}
		}
	}
	return false
}

// takesContext reports whether a function's first parameter is an SContext, which is the
// marker that its body resolves and refuses a foreign caller before acting.
func takesContext(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return false
	}
	switch typ := fn.Type.Params.List[0].Type.(type) {
	case *ast.Ident:
		return typ.Name == "SContext"
	case *ast.SelectorExpr:
		// The type may be spelled abi.SContext in a file that has not been converted to
		// the alias, so both spellings are accepted rather than one.
		return typ.Sel != nil && typ.Sel.Name == "SContext"
	default:
		return false
	}
}

// TestTheClassificationListsAreNotStale fails when a name in either list is no longer an
// exported package-level function, so a rename cannot leave an exemption behind that
// silently starts covering a different function - which is the way a classification
// list quietly becomes a hole.
func TestTheClassificationListsAreNotStale(t *testing.T) {
	dir := "../../kernel"
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	real := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, decl := range af.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.IsExported() {
				real[fn.Name.Name] = true
			}
		}
	}

	for name := range hostOnlyFunctions {
		if !real[name] {
			t.Errorf("hostOnlyFunctions names %q, which is not an exported function in package kernel", name)
		}
	}
	for name := range pidKeyedFunctions {
		if !real[name] {
			t.Errorf("pidKeyedFunctions names %q, which is not an exported function in package kernel", name)
		}
	}
	for name := range identityKeyedFunctions {
		if !real[name] {
			t.Errorf("identityKeyedFunctions names %q, which is not an exported function in package kernel", name)
		}
	}
	for name := range moduleReachableFunctions {
		if !real[name] {
			t.Errorf("reachableGroups names %q, which is not an exported function in package kernel", name)
		}
	}

	// A host-only function that also takes an SContext is classified twice, and the
	// syscall gate would win silently. Naming it here is the honest outcome.
	for name := range hostOnlyFunctions {
		if _, ok := moduleReachableFunctions[name]; ok {
			t.Errorf("%q is in both lists; pick one", name)
		}
		if _, ok := pidKeyedFunctions[name]; ok {
			t.Errorf("%q is in both host lists; pick one", name)
		}
	}
	for name := range pidKeyedFunctions {
		if _, ok := moduleReachableFunctions[name]; ok {
			t.Errorf("%q is in both lists; pick one", name)
		}
		if _, ok := identityKeyedFunctions[name]; ok {
			t.Errorf("%q is in both host lists; pick one", name)
		}
	}
	for name := range identityKeyedFunctions {
		if _, ok := moduleReachableFunctions[name]; ok {
			t.Errorf("%q is in both lists; pick one", name)
		}
		if _, ok := hostOnlyFunctions[name]; ok {
			t.Errorf("%q is in both host lists; pick one", name)
		}
	}
}
