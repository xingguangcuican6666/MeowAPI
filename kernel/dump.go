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
