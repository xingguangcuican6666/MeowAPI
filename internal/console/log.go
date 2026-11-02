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

package console

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xingguangcuican6666/MeowAPI/kernel"
)

// `log`: the kernel console, rendered for a terminal.
//
// It reads through ktty rather than through kernel.KernelConsole() directly, and
// the reason is not that the host lacks access - it has both. It is that the read
// goes through the same bounded window, the same level filter and the same
// accounting as every other reader, so a console session cannot become the one
// place that sees records the kernel decided to withhold, and so the read is
// counted where an operator can see it in `status`.

const (
	// defaultLogLines is what a bare `log` shows.
	defaultLogLines = 20
	// maxLogLines caps one render. ktty caps a single read at its own ceiling, so
	// a larger count is several reads stitched together, and this is where that
	// stops: an operator asking for a million lines is asking for the daemon to
	// spend its memory on one session.
	maxLogLines = 2000
	// followInterval is how often `log -f` polls. It is a poll and not a
	// subscription because the kernel console has one sink and the daemon is
	// already it; taking the sink over for one session would stop the daemon's own
	// log from reaching stderr.
	followInterval = 250 * time.Millisecond
)

// logCommand implements `log`, `log -n N` and `log -f`.
func (d *Daemon) logCommand(s *Session, args []string) (string, error) {
	n := defaultLogLines
	follow := false
	level := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f", "-follow":
			follow = true
		case "-n":
			if i+1 >= len(args) {
				return "", errors.New("-n needs a count")
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 1 {
				return "", fmt.Errorf("%q is not a count", args[i+1])
			}
			i++
			n = v
		case "-l":
			if i+1 >= len(args) {
				return "", errors.New("-l needs a level")
			}
			level = strings.ToLower(args[i+1])
			i++
			if !knownLevel(level) {
				return "", fmt.Errorf("%q is not a level; try debug, info, warn, error or fault", level)
			}
		default:
			return "", fmt.Errorf("%q is not a flag this command takes", args[i])
		}
	}
	if n > maxLogLines {
		n = maxLogLines
	}

	if follow {
		return "", d.follow(s, level)
	}

	records, err := d.tail(n, level)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "the console is empty\n", nil
	}
	return renderRecords(records), nil
}

// tail returns the last n records at or above level, oldest first.
//
// ktty has no "how many records are there" query and no reverse read: a read
// returns a window from an index, capped at its own per-read ceiling. So the end has
// to be walked to, and the walk is forward from zero - which means this reads the
// retained history once to find where it stops and once more backwards to collect
// the tail. That is two passes over a bounded buffer, and the bound is the console's
// retention limit, not the session's count.
func (d *Daemon) tail(n int, level string) ([]kernel.Record, error) {
	min := levelRank(level)

	// Pass one: find the end of retained history.
	var cursor int
	for {
		w, err := d.ttyRead(cursor)
		if err != nil {
			return nil, err
		}
		if len(w.Records) == 0 {
			break
		}
		cursor = w.Base + len(w.Records)
	}

	// Pass two: walk backwards from the end, keeping matching records.
	out := make([]kernel.Record, 0, n)
	for cursor > 0 && len(out) < n {
		want := n - len(out)
		if want > kernelTTYReadLines {
			want = kernelTTYReadLines
		}
		from := cursor - want
		if from < 0 {
			from = 0
		}
		w, err := d.ttyRead(from)
		if err != nil {
			return nil, err
		}
		if len(w.Records) == 0 {
			break
		}
		// A window read at `from` may extend past `cursor` if history is still
		// being appended, so only the part strictly before the cursor is used.
		end := cursor - w.Base
		if end > len(w.Records) {
			end = len(w.Records)
		}
		if end <= 0 {
			break
		}
		for i := end - 1; i >= 0 && len(out) < n; i-- {
			if min == 0 || rankOf(w.Records[i].Level) >= min {
				out = append(out, w.Records[i])
			}
		}
		cursor = w.Base + 0
		if w.Base == 0 {
			break
		}
	}

	// Collected newest-first; rendered oldest-first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// kernelTTYReadLines is ktty's per-read ceiling, duplicated here because the
// constant is unexported in the kernel. The value is asserted by a test rather
// than trusted: if the kernel lowers it, a read here silently returns fewer
// records than asked and `log -n` would under-report.
const kernelTTYReadLines = 256

// ttyRead is one bounded console read through init's handle.
func (d *Daemon) ttyRead(since int) (kernel.TTYWindow, error) {
	if d.init == nil {
		return kernel.TTYWindow{}, errors.New("the kernel is not booted")
	}
	return kernel.TTYRead(d.init, d.ttyFD, since)
}

// follow streams new records until the session ends or the daemon stops.
//
// It ends when the connection breaks, which is what an operator pressing Ctrl-C
// does, and when the daemon stops. What it does NOT do is return control to the
// prompt: a session is one command at a time, and a follower that also read
// commands would have to multiplex a single connection two ways. The honest
// contract is that `log -f` owns the session until it is interrupted, and the
// prompt says so before it starts.
func (d *Daemon) follow(s *Session, level string) error {
	s.following.Store(true)
	defer s.following.Store(false)

	// Start at the end of history so the operator sees new records rather than a
	// replay of what `log` would have shown. The walk to find the end is the same
	// one tail does; doing it here keeps follow from depending on tail's shape.
	cursor, err := d.endCursor()
	if err != nil {
		return err
	}

	if err := s.write("--- following the kernel console; interrupt to stop ---\n"); err != nil {
		return nil
	}

	ticker := time.NewTicker(followInterval)
	defer ticker.Stop()

	droppedSeen := int64(-1)
	for {
		select {
		case <-ticker.C:
		case <-d.stopped:
			return nil
		}
		if d.stopping.Load() || s.isClosed() {
			return nil
		}

		w, err := d.ttyRead(cursor)
		if err != nil {
			// A failed read ends the follow rather than spinning on it: the
			// session gets one message and its prompt back, which is recoverable,
			// where a retry loop against a broken handle is not.
			_ = s.printf("the console read failed: %v\n", err)
			return nil
		}
		if w.Dropped != droppedSeen {
			if droppedSeen >= 0 && w.Dropped > droppedSeen {
				_ = s.printf("note: %d console record(s) were evicted while following\n",
					w.Dropped-droppedSeen)
			}
			droppedSeen = w.Dropped
		}
		if len(w.Records) == 0 {
			continue
		}
		cursor = w.Base + len(w.Records)
		min := levelRank(level)
		var keep []kernel.Record
		for _, r := range w.Records {
			if min == 0 || rankOf(r.Level) >= min {
				keep = append(keep, r)
			}
		}
		if len(keep) == 0 {
			continue
		}
		if err := s.write(renderRecords(keep)); err != nil {
			return nil
		}
	}
}

// endCursor returns the index just past the last retained record.
func (d *Daemon) endCursor() (int, error) {
	cursor := 0
	for {
		w, err := d.ttyRead(cursor)
		if err != nil {
			return 0, err
		}
		if len(w.Records) == 0 {
			return cursor, nil
		}
		cursor = w.Base + len(w.Records)
	}
}

// renderRecords formats records as aligned text.
func renderRecords(records []kernel.Record) string {
	var b strings.Builder
	for _, r := range records {
		dom := string(r.Domain)
		if dom == "" {
			dom = "-"
		}
		fmt.Fprintf(&b, "%s %-5s pid=%-4d %-18s %s\n",
			r.Time.Format("15:04:05.000"), r.Level, r.Pid, dom, r.Msg)
		if len(r.Fields) > 0 {
			keys := sortedKeys(r.Fields)
			for _, k := range keys {
				fmt.Fprintf(&b, "    %s=%v\n", k, r.Fields[k])
			}
		}
	}
	return b.String()
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// levelRank maps a level name to its severity, zero meaning "no filter". The
// kernel has its own copy for the sink filter; this one is for a session's -l flag
// and matches the same ordering, which the test below pins against the kernel's
// own Level constants.
func levelRank(level string) int {
	switch level {
	case "":
		return 0
	case string(kernel.LogDebug):
		return 1
	case string(kernel.LogInfo):
		return 2
	case string(kernel.LogWarn):
		return 3
	case string(kernel.LogError):
		return 4
	case string(kernel.LogFault):
		return 5
	default:
		return 0
	}
}

func rankOf(l kernel.Level) int { return levelRank(string(l)) }

// knownLevel reports whether a string names one of the kernel's levels.
func knownLevel(s string) bool {
	switch kernel.Level(s) {
	case kernel.LogDebug, kernel.LogInfo, kernel.LogWarn, kernel.LogError, kernel.LogFault:
		return true
	}
	return false
}

// dmesg renders the kernel's own messages: `dmesg [-n N] [-l level] [-H]`.
//
// It exists as a builtin because reading the kernel console requires tty:open, which
// only the init domain holds - so no component can do it however it is written, and
// dmesg is the first thing an operator reaches for when the kernel starts refusing
// things.
//
// Why not a method on the kernel handle, which is where every other host privilege
// lives? Because the read already exists and is already audited: TTYRead is the
// syscall a console handle exists to make, it is bounded, it is counted, and it
// appears on the chain. A second host-side reader would be a second path to the same
// buffer with none of that, and the whole point of ktty is that there is one.
//
// -H is not a GNU flag and the help says so: the kernel console is a bounded ring, and
// -H asks for everything still retained rather than the default window.
func (d *Daemon) dmesg(args []string) (string, error) {
	n := 20
	level := ""
	all := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n":
			if i+1 >= len(args) {
				return "", fmt.Errorf("-n needs a count")
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 0 {
				return "", fmt.Errorf("%q is not a count", args[i+1])
			}
			n = v
			i++
		case "-l":
			if i+1 >= len(args) {
				return "", fmt.Errorf("-l needs a level")
			}
			level = strings.ToLower(args[i+1])
			if !knownLevel(level) {
				return "", fmt.Errorf("%q is not a level; try debug, info, warn, error or fault", args[i+1])
			}
			i++
		case "-H", "--history":
			all = true
		default:
			return "", fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if all {
		// The ring is bounded by the console's retention limit, so "everything" is a
		// finite read rather than a request for unbounded output.
		n = maxLogLines
	}
	if n > maxLogLines {
		n = maxLogLines
	}

	records, err := d.tail(n, level)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "the kernel console is empty\n", nil
	}
	return renderRecords(records), nil
}
