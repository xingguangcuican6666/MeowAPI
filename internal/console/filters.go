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
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The GNU-style text filters, as builtins.
//
// They are builtins rather than only a component because of what an operator reaches
// for when something is wrong: `log | grep error` has to work before any .so has been
// loaded, and `dmesg | tail -20` has to work after a component has failed to load.
// plugins/gnu offers the same filters as a component, which is where they belong once
// the console is healthy - but the console's own tooling cannot depend on the thing it
// is diagnosing.
//
// The semantics are the familiar ones, and where they are not, the help text says so.
// A filter that silently differs from the GNU tool an operator has used for twenty
// years is worse than no filter, because the operator will trust it.

// maxFilterInput bounds what one stage will process. Each stage holds its whole input
// in memory, so an unbounded one is an unbounded allocation driven by the previous
// stage's output - and a console view can be large.
const maxFilterInput = 8 << 20

// filterInput validates and returns the input a filter was given.
func filterInput(stdin string) (string, error) {
	if stdin == "" {
		return "", fmt.Errorf("no input; pipe something into this command")
	}
	if len(stdin) > maxFilterInput {
		return "", fmt.Errorf("input is %d bytes, above the %d-byte ceiling for one stage",
			len(stdin), maxFilterInput)
	}
	return stdin, nil
}

// splitLines splits without inventing a trailing empty line for a final newline,
// which is what a line-oriented tool wants: "a\nb\n" is two lines, not three.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// headFilter prints the first n lines, "head -n N" with a default of 10.
func headFilter(args []string, stdin string) (string, error) {
	n, err := countFlag(args, 10)
	if err != nil {
		return "", err
	}
	in, err := filterInput(stdin)
	if err != nil {
		return "", err
	}
	lines := splitLines(in)
	if n < len(lines) {
		lines = lines[:n]
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// tailFilter prints the last n lines, "tail -n N" with a default of 10.
func tailFilter(args []string, stdin string) (string, error) {
	n, err := countFlag(args, 10)
	if err != nil {
		return "", err
	}
	in, err := filterInput(stdin)
	if err != nil {
		return "", err
	}
	lines := splitLines(in)
	if n < len(lines) {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// countFlag reads "-n N" out of an argument list and returns N, defaulting when the
// flag is absent. A count of zero is legal - head -n 0 is useful for testing, and
// refusing it would be a surprise - but a negative one is not.
func countFlag(args []string, def int) (int, error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--lines":
			if i+1 >= len(args) {
				return 0, fmt.Errorf("%s needs a count", args[i])
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 0 {
				return 0, fmt.Errorf("%q is not a count", args[i+1])
			}
			return v, nil
		default:
			// "-n5" is the GNU spelling an operator's fingers produce.
			if strings.HasPrefix(args[i], "-n") && len(args[i]) > 2 {
				v, err := strconv.Atoi(args[i][2:])
				if err != nil || v < 0 {
					return 0, fmt.Errorf("%q is not a count", args[i][2:])
				}
				return v, nil
			}
			return 0, fmt.Errorf("unknown flag %q", args[i])
		}
	}
	return def, nil
}

// grepFilter is "grep [-i] [-v] [-c] [-n] PATTERN".
//
// The pattern is a Go regular expression, which is a superset of what an operator
// expects from basic grep for everything except backreferences - and those are worth
// not having, because the alternative is a backtracking engine whose worst case is
// exponential on input a module controls. The help says "regular expression" so this
// is a promise rather than a surprise.
func grepFilter(args []string, stdin string) (string, error) {
	var (
		ignoreCase bool
		invert     bool
		countOnly  bool
		lineNo     bool
		pattern    string
		havePat    bool
	)
	for _, a := range args {
		switch a {
		case "-i", "--ignore-case":
			ignoreCase = true
		case "-v", "--invert-match":
			invert = true
		case "-c", "--count":
			countOnly = true
		case "-n", "--line-number":
			lineNo = true
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				return "", fmt.Errorf("unknown flag %q", a)
			}
			if havePat {
				return "", fmt.Errorf("more than one pattern; a pipeline stage takes one")
			}
			pattern, havePat = a, true
		}
	}
	if !havePat {
		return "", fmt.Errorf("usage: grep [-i] [-v] [-c] [-n] PATTERN")
	}

	expr := pattern
	if ignoreCase {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return "", fmt.Errorf("bad pattern: %v", err)
	}

	in, err := filterInput(stdin)
	if err != nil {
		return "", err
	}

	var (
		b     strings.Builder
		n     int
		lines = splitLines(in)
	)
	for i, line := range lines {
		match := re.MatchString(line)
		if match == invert {
			continue
		}
		n++
		switch {
		case countOnly:
		case lineNo:
			fmt.Fprintf(&b, "%d:%s\n", i+1, line)
		default:
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if countOnly {
		return fmt.Sprintf("%d\n", n), nil
	}
	return b.String(), nil
}

// wcFilter is "wc [-l] [-w] [-c]". With no flags it prints all three, in the GNU
// order, and it reports the count of the input as one record because that is what a
// pipeline stage can usefully pass on.
func wcFilter(args []string, stdin string) (string, error) {
	var showL, showW, showC bool
	for _, a := range args {
		switch a {
		case "-l", "--lines":
			showL = true
		case "-w", "--words":
			showW = true
		case "-c", "--bytes":
			showC = true
		default:
			return "", fmt.Errorf("unknown flag %q", a)
		}
	}
	if !showL && !showW && !showC {
		showL, showW, showC = true, true, true
	}

	in, err := filterInput(stdin)
	if err != nil {
		return "", err
	}
	lines := len(splitLines(in))
	words := len(strings.Fields(in))
	var parts []string
	if showL {
		parts = append(parts, strconv.Itoa(lines))
	}
	if showW {
		parts = append(parts, strconv.Itoa(words))
	}
	if showC {
		parts = append(parts, strconv.Itoa(len(in)))
	}
	return strings.Join(parts, " ") + "\n", nil
}

// cutFilter is "cut -d SEP -f N", one-based field selection.
//
// It selects exactly one field, not a range, and the help says so. A range is the
// next thing an operator would ask for and it is not here because a half-implemented
// range is a correctness trap: `cut -f 1-3` that silently returned only field 1 would
// look like it worked.
func cutFilter(args []string, stdin string) (string, error) {
	var (
		sep   = "\t"
		field int
		haveF bool
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--delimiter":
			if i+1 >= len(args) {
				return "", fmt.Errorf("-d needs a delimiter")
			}
			if args[i+1] == "" {
				return "", fmt.Errorf("the delimiter must not be empty")
			}
			sep = args[i+1]
			i++
		case "-f", "--fields":
			if i+1 >= len(args) {
				return "", fmt.Errorf("-f needs a field number")
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 1 {
				return "", fmt.Errorf("%q is not a field number (fields start at 1)", args[i+1])
			}
			field, haveF = v, true
			i++
		default:
			return "", fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if !haveF {
		return "", fmt.Errorf("usage: cut -d SEP -f N")
	}

	in, err := filterInput(stdin)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, line := range splitLines(in) {
		// A line with no delimiter prints as itself when field 1 was asked for and as
		// an empty line otherwise, which is what GNU cut does: the whole line is
		// field 1 and there is nothing after it to select.
		parts := strings.Split(line, sep)
		if field <= len(parts) {
			b.WriteString(parts[field-1])
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// sortFilter is "sort [-r] [-u]". Byte order, stable, which is what an operator
// comparing two runs of the same log wants.
func sortFilter(args []string, stdin string) (string, error) {
	var reverse, unique bool
	for _, a := range args {
		switch a {
		case "-r", "--reverse":
			reverse = true
		case "-u", "--unique":
			unique = true
		default:
			return "", fmt.Errorf("unknown flag %q", a)
		}
	}
	in, err := filterInput(stdin)
	if err != nil {
		return "", err
	}
	lines := splitLines(in)
	sort.Strings(lines)
	if reverse {
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
	}
	if unique {
		out := lines[:0]
		for i, l := range lines {
			if i == 0 || l != lines[i-1] {
				out = append(out, l)
			}
		}
		lines = out
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// uniqFilter is "uniq [-c]". It collapses ADJACENT repeats, which is the GNU
// behaviour and the one thing about it people get wrong; the help says so.
func uniqFilter(args []string, stdin string) (string, error) {
	var withCount bool
	for _, a := range args {
		switch a {
		case "-c", "--count":
			withCount = true
		default:
			return "", fmt.Errorf("unknown flag %q", a)
		}
	}
	in, err := filterInput(stdin)
	if err != nil {
		return "", err
	}

	var (
		b     strings.Builder
		prev  string
		count int
		flush = func() {
			if count == 0 {
				return
			}
			if withCount {
				fmt.Fprintf(&b, "%7d %s\n", count, prev)
			} else {
				b.WriteString(prev)
				b.WriteByte('\n')
			}
		}
	)
	for _, line := range splitLines(in) {
		if count > 0 && line == prev {
			count++
			continue
		}
		flush()
		prev, count = line, 1
	}
	flush()
	return b.String(), nil
}
