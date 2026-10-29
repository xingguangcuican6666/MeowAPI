package kernel

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Dump renders a snapshot of kernel state as text, for a debugging console. It
// is read-only and takes no context: it exposes nothing that is not already
// readable through ProcTable, LoadedModules, UsageSnapshot and the console
// history, so it grants no privilege. It exists so an operator can answer "what
// is loaded, under which grants, and what has been denied" in one screen.
func Dump(w io.Writer) error {
	if w == nil {
		return errors.New("kernel: Dump requires a writer")
	}

	var b strings.Builder
	b.WriteString("=== MeowAPI kernel ===\n")
	b.WriteString(fmt.Sprintf("kernel api: %d   console: %s (min %s)   retained: %d   dropped: %d\n",
		KernelAPI, kconsole.Format(), kconsole.Level(), len(kconsole.History()), kconsole.Dropped()))

	b.WriteString("\n--- process table ---\n")
	b.WriteString(fmt.Sprintf("%-5s %-6s %-5s %-17s %-16s %-11s %s\n",
		"pid", "uid", "ppid", "domain", "name", "state", "digest"))
	for _, r := range ProcTable() {
		digest := r.ManifestDigest
		if len(digest) > 12 {
			digest = digest[:12]
		}
		b.WriteString(fmt.Sprintf("%-5d %-6d %-5d %-17s %-16s %-11s %s\n",
			r.PID, r.UID, r.PPID, r.Domain, r.Name, r.State, digest))
	}

	b.WriteString("\n--- loaded modules ---\n")
	mods := LoadedModules()
	if len(mods) == 0 {
		b.WriteString("(none)\n")
	}
	for _, m := range mods {
		b.WriteString(fmt.Sprintf("%-16s v%-8s pid=%-4d\n", m.Name, m.Manifest.Version, m.PID))
		// Both lines are sorted, so a declaration that exceeds the effective set
		// is visible as a line difference rather than as a reordering.
		declared := append([]Op(nil), m.Manifest.Require...)
		sortOps(declared)
		b.WriteString(fmt.Sprintf("  declared : %s\n", joinOps(declared)))
		b.WriteString(fmt.Sprintf("  effective: %s\n", joinOps(m.Effective)))
		if len(m.Manifest.AllowedHosts) > 0 {
			b.WriteString(fmt.Sprintf("  hosts    : %s\n", strings.Join(m.Manifest.AllowedHosts, ", ")))
		}
	}

	b.WriteString("\n--- usage ---\n")
	usage := UsageSnapshot()
	if len(usage) == 0 {
		b.WriteString("(no usage recorded)\n")
	} else {
		nameByPid := map[PID]string{}
		for _, r := range ProcTable() {
			nameByPid[r.PID] = r.Name
		}
		pids := make([]PID, 0, len(usage))
		for pid := range usage {
			pids = append(pids, pid)
		}
		sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
		for _, pid := range pids {
			c := usage[pid]
			b.WriteString(fmt.Sprintf("pid=%-4d %-16s events=%-6d %s\n",
				pid, nameByPid[pid], c.Events, formatTotals(c.Total)))
		}
	}
	b.WriteString(fmt.Sprintf("rejected usage facts: %d\n", UsageRejected()))

	b.WriteString("\n--- policy ---\n")
	for _, dom := range []Domain{DomainKernel, DomainInit, DomainPlugin, DomainUntrusted} {
		held := OpsFor(dom)
		if len(held) == 0 {
			b.WriteString(fmt.Sprintf("%-17s (none)\n", dom))
			continue
		}
		b.WriteString(fmt.Sprintf("%-17s %s\n", dom, joinOps(held)))
	}

	b.WriteString("\n--- admission ---\n")
	slots := SlotStatsSnapshot()
	b.WriteString(fmt.Sprintf("slots: live=%d per-module-ceiling=%d kernel-ceiling=%d refused=%d released=%d\n",
		slots.Total, slots.PerModuleCeiling, slots.TotalCeiling, slots.Refused, slots.Released))
	for _, pid := range sortedPIDs(slots.PerPid) {
		b.WriteString(fmt.Sprintf("  pid=%-4d holds=%d\n", pid, slots.PerPid[pid]))
	}
	qos := QosStatsSnapshot()
	b.WriteString(fmt.Sprintf("qos: buckets=%d of %d admitted=%d refused=%d evicted=%d\n",
		qos.Buckets, qos.MaxKeys, qos.Admitted, qos.Refused, qos.Evicted))
	for _, kind := range sortedPolicyKinds(qos.Policies) {
		p := qos.Policies[kind]
		b.WriteString(fmt.Sprintf("  %-8s rpm=%d tpm=%d burst=%d\n",
			kind, p.RequestsPerMinute, p.TokensPerMinute, p.Burst))
	}

	b.WriteString("\n--- cpu accounting ---\n")
	cpu := CPUStats()
	if len(cpu) == 0 {
		b.WriteString("(no supervised work recorded)\n")
	}
	for _, s := range cpu {
		b.WriteString(fmt.Sprintf("pid=%-4d calls=%-5d wall=%-14s cpu~=%-14s budget=%-14s%s\n",
			s.PID, s.Calls, nanos(s.WallNanos), nanos(s.CPUNanos), nanos(s.Budget),
			exhaustedMark(s.Exhausted)))
	}
	b.WriteString(fmt.Sprintf("refused for budget: %d\n", CPUDenied()))

	b.WriteString("\n--- channels ---\n")
	pipes := PipeStatsSnapshot()
	if len(pipes) == 0 {
		b.WriteString("(no pipes open)\n")
	}
	for _, p := range pipes {
		b.WriteString(fmt.Sprintf("pid=%-4d fd=%-4d %-16s cap=%-8d buffered=%-7d written=%-6d read=%-6d dropped=%d%s%s\n",
			p.Owner, p.FD, p.Name, p.Cap, p.Buffered, p.Written, p.Read, p.Dropped,
			closedMark(p.Closed), abortedMark(p.Aborted)))
	}
	locks := LockSnapshot()
	if len(locks) == 0 {
		b.WriteString("(no locks known)\n")
	}
	for _, l := range locks {
		b.WriteString(fmt.Sprintf("lock %-20s held=%-5v owner=%-4d readers=%-3d waiters=%-3d taken=%-5d timedOut=%d%s\n",
			l.Name, l.Held, l.Owner, l.Readers, l.Waiters, l.Taken, l.TimedOut, deadMark(l.Dead)))
	}
	ev := EventStatsSnapshot()
	b.WriteString(fmt.Sprintf("events: subscriptions=%d posts=%d pending=%d dropped=%d (bound %d per subscription)\n",
		ev.Subscriptions, ev.Posts, ev.Pending, ev.Dropped, ev.MaxPendingPerSubscription))

	b.WriteString("\n--- routes ---\n")
	routes := RouteTable()
	if len(routes) == 0 {
		b.WriteString("(none registered)\n")
	}
	for _, r := range routes {
		b.WriteString(fmt.Sprintf("%-28s pid=%-4d %-16s calls=%-6d failures=%d\n",
			r.Path, r.PID, r.Module, r.Calls, r.Failures))
	}
	rs := RouteStatsSnapshot()
	b.WriteString(fmt.Sprintf("dispatches=%d misses=%d registrations-refused=%d (max %d per module)\n",
		rs.Calls, rs.Misses, rs.Denied, rs.MaxPerModule))

	b.WriteString("\n--- egress ---\n")
	// Reachability, beside the mesh section that also describes it. The address a dial
	// actually reached is rendered rather than only the hostname, because a name resolving
	// somewhere unexpected is the thing an operator needs to be able to see here.
	ns := NetStatsSnapshot()
	b.WriteString(fmt.Sprintf("dialed=%d refused=%d blocked=%d pooled=%d/%d listeners=%d/%d retained=%d evicted=%d (max %d per module, %d pooled)\n",
		ns.Dialed, ns.Refused, ns.Blocked, ns.Pooled, ns.MaxPooled,
		ns.Listeners, ns.MaxPerPID, ns.Retained, ns.Evicted, ns.MaxPerPID, ns.MaxPooled))
	if ranges := NetPrivateRanges(); len(ranges) > 0 {
		b.WriteString(fmt.Sprintf("private ranges permitted by the host: %s\n", strings.Join(ranges, ", ")))
	} else {
		b.WriteString("private ranges: none permitted, so every private address is refused\n")
	}
	sockets := 0
	for _, p := range ProcTable() {
		for _, s := range NetSockets(p.PID) {
			sockets++
			b.WriteString(fmt.Sprintf("  pid=%-4d fd=%-3d %-28s %s pooled=%t in=%dB out=%dB\n",
				s.PID, s.FD, s.Remote, s.Label, s.Pooled, s.BytesIn, s.BytesOut))
		}
	}
	if sockets == 0 {
		b.WriteString("(no sockets open)\n")
	}

	b.WriteString("\n--- peers ---\n")
	peers := PeerTableSnapshot()
	if len(peers) == 0 {
		b.WriteString("(none in the mesh table)\n")
	}
	for _, pe := range peers {
		state := "open"
		if pe.Closed {
			state = "closed"
		}
		// Endpoint and label are operator-supplied names, already validated to carry
		// no control characters, so rendering them cannot forge a line.
		b.WriteString(fmt.Sprintf("%-20s %-24s %-6s rtt=%-10dns samples=%-4d timeouts=%-3d fwd=%-4d refused=%d\n",
			pe.NodeID, pe.Endpoint, state, pe.LastRTTNanos, pe.Samples,
			pe.Timeouts, pe.Forwarded, pe.Refused))
	}
	ps := PeerStatsSnapshot()
	b.WriteString(fmt.Sprintf("peers=%d/%d announced=%d accepted=%d refused=%d probes=%d probe-timeouts=%d forwarded=%d forward-refused=%d events=%d evicted=%d\n",
		ps.Peers, ps.MaxPeers, ps.Announced, ps.Accepted, ps.Refused, ps.Probes,
		ps.ProbeTimeouts, ps.Forwarded, ps.ForwardRefused, ps.Events, ps.EventEvicted))

	b.WriteString("\n--- slashing ---\n")
	// A fraud case is named by its evidence rather than by its reporter's prose, so
	// the note is rendered bounded and only for pending cases: a decided one has a
	// finding on the audit chain, and echoing reporter text into an operator's
	// terminal makes the dump a place unvalidated input can reach.
	slashes := SlashLedger()
	if len(slashes) == 0 {
		b.WriteString("(no fraud proofs filed)\n")
	}
	for _, s := range slashes {
		b.WriteString(fmt.Sprintf("%-18s %-14s node=%-20s verdict=%-10s reporters=%d\n",
			s.ID, s.Kind, s.NodeID, s.Verdict, len(s.Reporters)))
	}
	ss := SlashStatsSnapshot()
	b.WriteString(fmt.Sprintf("pending=%d confirmed=%d unproven=%d filed=%d corroborated=%d refused=%d records=%d/%d evicted=%d\n",
		ss.Pending, ss.Confirmed, ss.Unproven, ss.Filed, ss.Corroborated,
		ss.Refused, ss.Records, ss.MaxRecords, ss.RecordEvicted))

	b.WriteString("\n--- shared memory ---\n")
	shm := ShmSnapshot()
	b.WriteString(fmt.Sprintf("segments=%d pool=%dB cached=%dB allocs=%d reused=%d evictions=%d refused=%d zeroed=%d\n",
		shm.Segments, shm.PoolBytes, shm.CachedBytes, shm.Allocations,
		shm.Reused, shm.Evictions, shm.Refused, shm.Zeroed))

	b.WriteString("\n--- tracing ---\n")
	tr := TraceStatsSnapshot()
	b.WriteString(fmt.Sprintf("live=%d completed=%d abandoned=%d retained=%d evicted=%d (bounds: %d live/module, %d retained)\n",
		tr.Live, tr.Completed, tr.Abandoned, tr.Retained, tr.Evicted,
		tr.MaxLivePerModule, tr.MaxRetained))

	b.WriteString("\n--- metering ---\n")
	mt := MeterTotalsSnapshot()
	b.WriteString(fmt.Sprintf("retained=%d open=%d requests=%d tokens:in=%d tokens:out=%d abandoned=%d evicted=%d\n",
		mt.Retained, mt.Open, mt.Requests, mt.TokensIn, mt.TokensOut, mt.Abandoned, mt.Evicted))

	b.WriteString("\n--- token accounting ---\n")
	// The measurement side of billing: what the kernel computed about bytes that
	// crossed it, beside what modules reported about them. Rendering the two together
	// is the point, because either half alone is not a finding.
	tok := TokenStatsSnapshot()
	strict := "non-strict"
	if tok.StrictFloor {
		strict = "strict"
	}
	b.WriteString(fmt.Sprintf("checked=%d consistent=%d suspicious=%d impossible=%d retained=%d evicted=%d (max %d) floor=%s\n",
		tok.Checked, tok.Consistent, tok.Suspicious, tok.Impossible,
		tok.Retained, tok.Evicted, tok.MaxRecords, strict))
	for _, m := range TokenTotalsByModule() {
		b.WriteString(fmt.Sprintf("  pid=%-4d %-20s checked=%-5d consistent=%-5d suspicious=%-4d impossible=%-4d flow=%dB/%dtok\n",
			m.PID, m.Module, m.Checked, m.Consistent, m.Suspicious, m.Impossible,
			m.FlowBytes, m.FlowTokens))
	}

	b.WriteString("\n--- secrets ---\n")
	// Aliases and their use counts only. A value is never rendered, and neither is
	// a header name that would let an operator's terminal scrollback become a place
	// a credential can be found later.
	inv := SecretInventory()
	if len(inv) == 0 {
		b.WriteString("(none in custody)\n")
	}
	for _, s := range inv {
		b.WriteString(fmt.Sprintf("%-28s owner=%-4d uses=%d\n", s.Alias, s.Owner, s.Uses))
	}
	uses, refused := SecretUseStats()
	b.WriteString(fmt.Sprintf("uses=%d refused=%d (ceiling %d credentials, %d bytes each)\n",
		uses, refused, MaxSecrets(), MaxSecretValueBytes()))

	b.WriteString("\n--- receipts ---\n")
	rc := ReceiptStats()
	b.WriteString(fmt.Sprintf("issued=%d refused=%d\n", rc.Issued, rc.Refused))
	for _, node := range sortedNodes(rc.Cursor) {
		b.WriteString(fmt.Sprintf("  node %-20s cursor=%d\n", node, rc.Cursor[node]))
	}

	b.WriteString("\n--- console ---\n")
	// Whether a credential is installed, and nothing else about it. The value is
	// never rendered and neither is its length, for the reason the secrets section
	// gives: a dump is read by whoever has the host's console or its log access, and
	// a length narrows a brute-force search that would otherwise be the whole
	// key space.
	ts := TTYStatsSnapshot()
	cred := "not installed"
	if ts.Credential {
		cred = "installed"
	}
	b.WriteString(fmt.Sprintf("handles=%d credential=%s issued=%d refused=%d reads=%d writes=%d (max %d handles per pid)\n",
		ts.Open, cred, ts.Issued, ts.Refused, ts.Reads, ts.Writes, ts.MaxPerPID))

	b.WriteString("\n--- supervision ---\n")
	events, sweeps, detected := WatchdogSnapshot()
	b.WriteString(fmt.Sprintf("watchdog: live=%d sweeps=%d overdue-detected=%d\n",
		WatchdogLive(), sweeps, detected))
	for _, e := range events {
		b.WriteString(fmt.Sprintf("  seq=%-4d pid=%-4d %-8s %-20s overdue-by=%dns run=%d stack=%dB\n",
			e.Seq, e.PID, e.Kind, e.Label, e.OverdueNanos, e.RunID, len(e.Stack)))
	}
	for _, r := range ProcTable() {
		if r.State != ProcRunning {
			continue
		}
		running, timers := SchedCount(r.PID)
		draining, terminating := SignalState(r.PID)
		pending := SignalPending(r.PID)
		if running == 0 && timers == 0 && pending == 0 && !draining && !terminating {
			continue
		}
		b.WriteString(fmt.Sprintf("pid=%-4d runs=%-3d timers=%-3d signals-pending=%-3d draining=%-5v terminating=%v\n",
			r.PID, running, timers, pending, draining, terminating))
	}

	b.WriteString("\n--- handles ---\n")
	// FDList is per pid and FDInfo carries no pid, so the walk starts from the
	// process table rather than from a global snapshot. A handle is only ever
	// resolvable inside its own table, and the dump reflects that rather than
	// inventing a cross-pid view the kernel does not have.
	totalHandles := 0
	for _, r := range ProcTable() {
		if r.State != ProcRunning {
			continue
		}
		fds := FDList(r.PID)
		if len(fds) == 0 {
			continue
		}
		totalHandles += len(fds)
		kinds := map[string]int{}
		for _, f := range fds {
			kinds[f.Kind]++
		}
		b.WriteString(fmt.Sprintf("pid=%-4d %-16s open=%d\n", r.PID, r.Name, len(fds)))
		for _, kind := range sortedKinds(kinds) {
			b.WriteString(fmt.Sprintf("  %-8s %d\n", kind, kinds[kind]))
		}
	}
	if totalHandles == 0 {
		b.WriteString("(no handles open)\n")
	}

	b.WriteString(fmt.Sprintf("\n--- faults (%d) ---\n", countFaults()))
	for _, r := range kconsole.History() {
		if r.Level == LogFault {
			b.WriteString("  " + renderText(r) + "\n")
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func countFaults() int {
	n := 0
	for _, r := range kconsole.History() {
		if r.Level == LogFault {
			n++
		}
	}
	return n
}

func joinOps(ops []Op) string {
	if len(ops) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(ops))
	for _, o := range ops {
		out = append(out, string(o))
	}
	return strings.Join(out, " ")
}

func formatTotals(t map[UsageKind]int64) string {
	if len(t) == 0 {
		return ""
	}
	// Fixed order so the line does not reshuffle between two identical dumps.
	kinds := UsageKinds()
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if v, ok := t[k]; ok && v != 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, v))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

// exhaustedMark and its neighbours are the one-character annotations that make a
// dump scannable. A plain boolean column in a wall of aligned text is easy to miss,
// and these are the columns an operator is looking for.
func exhaustedMark(exhausted bool) string {
	if exhausted {
		return "  EXHAUSTED"
	}
	return ""
}

func deadMark(dead bool) string {
	if dead {
		return "  OWNER-GONE"
	}
	return ""
}

func closedMark(closed bool) string {
	if closed {
		return " closed"
	}
	return ""
}

func abortedMark(aborted bool) string {
	if aborted {
		return " aborted"
	}
	return ""
}

func sortedPIDs(m map[PID]int) []PID {
	out := make([]PID, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedPolicyKinds(m map[string]QosPolicy) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNodes(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKinds(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nanos renders a duration in the largest unit that keeps it readable, with the unit
// inside the padded field so the columns line up. A raw nanosecond count next to a
// thirty-second budget is twelve digits the reader has to count.
func nanos(n int64) string {
	switch {
	case n >= 1_000_000_000 && n%1_000_000_000 == 0:
		return fmt.Sprintf("%ds", n/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fms", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fus", float64(n)/1_000)
	default:
		return fmt.Sprintf("%dns", n)
	}
}
