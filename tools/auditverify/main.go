// Command auditverify checks a MeowAPI audit file without running the kernel.
//
// It exists as a separate binary so an investigator can verify a trail on a machine
// that has no MeowAPI source tree, no network access and no way to boot the kernel
// that wrote it. A verification tool that requires the thing it verifies to be
// running is not a tool for the situation it matters in.
//
// Usage:
//
//	auditverify [-json] [-quiet] [-show] [-kind denial] [-pid 2] [-since 100] [-limit N] file.log ...
//
// Exit codes:
//
//	0  every file verified
//	1  at least one file is broken, truncated, tampered with or unreadable
//	2  usage error
//
// An unreadable file is a finding rather than a usage mistake, so it shares the
// exit code with a broken chain. Both mean the evidence cannot be trusted; only
// "you invoked this wrong" gets its own code.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/xingguangcuican6666/MeowAPI/internal/auditfile"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is the whole program behind an injectable argv and output, so it is testable
// without a subprocess and without intercepting os.Exit. It returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("auditverify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		asJSON = fs.Bool("json", false, "emit a machine-readable report")
		quiet  = fs.Bool("quiet", false, "print nothing when every file verifies")
		show   = fs.Bool("show", false, "print the entries, not only the verdict")
		kind   = fs.String("kind", "", "filter to one audit kind, e.g. denial, load, escalation")
		pid    = fs.Int("pid", 0, "filter to one pid")
		since  = fs.Int64("since", 0, "filter to entries with seq at or after this value")
		limit  = fs.Int("limit", 0, "print at most this many matching entries")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "auditverify: at least one audit file is required")
		fs.Usage()
		return 2
	}

	f := filter{kind: *kind, pid: *pid, since: *since, limit: *limit}
	// showAll is -show with no filter active, meaning "print every entry".
	showAll := *show && !f.active()
	reports := make([]report, 0, fs.NArg())
	broken := 0
	for _, path := range fs.Args() {
		r := verify(path, f, showAll)
		reports = append(reports, r)
		if !r.OK {
			broken++
		}
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"files":  len(reports),
			"broken": broken,
			"report": reports,
		}); err != nil {
			fmt.Fprintln(stderr, "auditverify:", err)
			return 2
		}
		return exitCodeFor(broken)
	}

	// A filter implies the caller wants to see entries, so it turns -show on
	// rather than silently reporting only a verdict. And -show with no filter means
	// every entry, not only the ones a filter would have kept: the point of the
	// flag is to read the trail, and a flag that prints nothing without a second
	// flag would be a trap.
	showEntries := *show || f.active()
	if broken > 0 || !*quiet || showEntries {
		for _, r := range reports {
			printReport(stdout, r, showEntries)
		}
	}
	return exitCodeFor(broken)
}

func exitCodeFor(broken int) int {
	if broken > 0 {
		return 1
	}
	return 0
}

type filter struct {
	kind  string
	pid   int
	since int64
	limit int
}

func (f filter) active() bool { return f.kind != "" || f.pid != 0 || f.since != 0 }

func (f filter) matches(e kernel.AuditEntry) bool {
	if f.kind != "" && string(e.Kind) != f.kind {
		return false
	}
	if f.pid != 0 && int(e.PID) != f.pid {
		return false
	}
	if f.since != 0 && e.Seq < f.since {
		return false
	}
	return true
}

type report struct {
	Path     string         `json:"path"`
	OK       bool           `json:"ok"`
	Entries  int            `json:"entries"`
	Boots    int            `json:"boots"`
	BadBoot  int            `json:"bad_boot"`
	BadEntry int            `json:"bad_entry"`
	Reason   string         `json:"reason,omitempty"`
	Kinds    map[string]int `json:"kinds,omitempty"`
	ReadErr  string         `json:"read_error,omitempty"`
	Filtered []entryRow     `json:"filtered,omitempty"`
}

type entryRow struct {
	Seq    int64          `json:"seq"`
	Kind   string         `json:"kind"`
	PID    int            `json:"pid"`
	Domain string         `json:"domain,omitempty"`
	Msg    string         `json:"msg"`
	Trace  string         `json:"trace,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
	Hash   string         `json:"hash"`
	Prev   string         `json:"prev"`
}

func verify(path string, f filter, showAll bool) report {
	r := report{Path: path, BadBoot: -1, BadEntry: -1}

	// One read serves both the verdict and any printed entries. Reading twice would
	// be wasteful and racy: the file could change in between, and then the entries
	// printed would not be the entries that were verified.
	entries, err := auditfile.Read(path)
	if err != nil {
		// A read error is reported as not-OK rather than as a usage error, because
		// an unreadable audit file is a finding: it means the evidence cannot be
		// checked, which is the same conclusion as a broken chain.
		r.ReadErr = err.Error()
		r.Reason = err.Error()
		return r
	}

	r.Entries = len(entries)
	if len(entries) == 0 {
		r.OK = true
		r.Reason = "empty file: a kernel that has not booted, not a broken chain"
		return r
	}

	boots, badBoot, badEntry := auditfile.VerifyFile(entries)
	r.Boots = boots
	r.BadBoot = badBoot
	r.BadEntry = badEntry
	r.OK = badBoot == -1

	if !r.OK {
		seg := auditfile.Segments(entries)
		if badBoot >= 0 && badBoot < len(seg) && badEntry >= 0 && badEntry < len(seg[badBoot]) {
			e := seg[badBoot][badEntry]
			r.Reason = fmt.Sprintf(
				"chain broken in boot %d at seq %d: kind=%s msg=%q hash=%s prev=%s",
				badBoot, e.Seq, e.Kind, e.Msg, truncate(e.Hash, 16), truncate(e.Prev, 16))
		} else {
			r.Reason = fmt.Sprintf("chain broken in boot %d at entry %d", badBoot, badEntry)
		}
	}

	r.Kinds = map[string]int{}
	for _, e := range entries {
		r.Kinds[string(e.Kind)]++
	}

	if f.active() || showAll {
		r.collect(entries, f, showAll)
	}
	return r
}

// collect fills the printed rows, either filtered or complete.
func (r *report) collect(entries []kernel.AuditEntry, f filter, showAll bool) {
	for _, e := range entries {
		if !showAll && !f.matches(e) {
			continue
		}
		r.Filtered = append(r.Filtered, entryRow{
			Seq: e.Seq, Kind: string(e.Kind), PID: int(e.PID), Domain: string(e.Domain),
			Msg: e.Msg, Trace: e.Trace, Fields: e.Fields, Hash: e.Hash, Prev: e.Prev,
		})
		if f.limit > 0 && len(r.Filtered) >= f.limit {
			return
		}
	}
}

func printReport(w io.Writer, r report, showEntries bool) {
	switch {
	case r.ReadErr != "":
		fmt.Fprintf(w, "%s: UNREADABLE: %s\n", r.Path, r.ReadErr)
		return
	case r.OK:
		fmt.Fprintf(w, "%s: OK (%d entries across %d boot(s))\n", r.Path, r.Entries, r.Boots)
	default:
		fmt.Fprintf(w, "%s: BROKEN: %s\n", r.Path, r.Reason)
	}

	if len(r.Kinds) > 0 {
		kinds := make([]string, 0, len(r.Kinds))
		for k, n := range r.Kinds {
			kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
		}
		sort.Strings(kinds)
		fmt.Fprintf(w, "  kinds: %s\n", strings.Join(kinds, " "))
	}

	if showEntries {
		for _, e := range r.Filtered {
			line := fmt.Sprintf("  seq=%-6d %-11s pid=%-4d %s", e.Seq, e.Kind, e.PID, e.Msg)
			if e.Trace != "" {
				line += " trace=" + e.Trace
			}
			if len(e.Fields) > 0 {
				line += " " + encodeFields(e.Fields)
			}
			fmt.Fprintln(w, line)
		}
	}
}

func encodeFields(fields map[string]any) string {
	b, err := json.Marshal(fields)
	if err != nil {
		return ""
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
