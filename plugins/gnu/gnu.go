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

// Package main is the gnu component: a text-toolkit a deployment can drop into
// root/bin.
//
// Every command here is a pure filter - stdin in, stdout out - and that is deliberate.
// A filter needs no kernel capability at all: it does not read the console, does not
// load anything, does not touch a credential. Its manifest therefore requires NOTHING,
// which makes it the cleanest demonstration of the component contract: a module's
// authority is exactly its manifest and no more.
//
// The names are prefixed `gnu-` and not `grep`, `head`, `tail`. The console already
// has builtins under those names, because `log | grep error` has to work before any
// component has loaded and after one has failed to load - so the console's own tooling
// cannot depend on the thing it is diagnosing. A component may not shadow a builtin,
// and the prefixed names are also what a script should use: they cannot collide with a
// future builtin.
//
// Build it with:
//
//	go build -buildmode=plugin -o root/bin/gnu.so ./plugins/gnu
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xingguangcuican6666/MeowAPI/abi"
)

// MeowAPIManifest declares no operations. A component that asks for nothing cannot do
// anything, and that is the point of shipping this one: it proves the loader, the
// registration and the command surface all work with zero authority.
var MeowAPIManifest = abi.Manifest{
	Name:         "gnu",
	Version:      "0.1.0",
	MinKernelAPI: abi.KernelAPI,
	MaxKernelAPI: abi.KernelAPI,
}

// MeowAPICommands is the toolkit. All of them are filters, so all of them take input.
var MeowAPICommands = []abi.Command{
	{Name: "gnu-grep", Help: "grep -i -v -c -n PATTERN over the input", Run: runGrep},
	{Name: "gnu-head", Help: "the first -n lines", Run: func(_ abi.SContext, a []string, in string) (string, error) {
		return headTail(a, in, true)
	}},
	{Name: "gnu-tail", Help: "the last -n lines", Run: func(_ abi.SContext, a []string, in string) (string, error) {
		return headTail(a, in, false)
	}},
	{Name: "gnu-wc", Help: "count lines, words and bytes: -l -w -c", Run: runWC},
	{Name: "gnu-cut", Help: "select a field: -d SEP -f N", Run: runCut},
	{Name: "gnu-sort", Help: "sort the lines: -r reverse, -u unique", Run: runSort},
	{Name: "gnu-uniq", Help: "collapse adjacent repeats: -c with a count", Run: runUniq},
	{Name: "gnu-nl", Help: "number the lines", Run: runNL},
	{Name: "gnu-tac", Help: "the lines in reverse order", Run: runTac},
	{Name: "gnu-fmt", Help: "reflow paragraphs at -w width", Run: runFmt},
	{Name: "gnu-factor", Help: "prime factors of each integer on the input", Run: runFactor},
	{Name: "gnu-rev", Help: "reverse the characters of each line", Run: runRev},
}

// maxInput bounds one command's input. A component holds its input in memory, and
// unlike a builtin it was loaded from disk by an operator, so the ceiling is this
// component's own responsibility rather than the daemon's.
const maxInput = 8 << 20

// input validates what a filter was given.
func input(stdin string) (string, error) {
	if stdin == "" {
		return "", fmt.Errorf("no input; pipe something into this command")
	}
	if len(stdin) > maxInput {
		return "", fmt.Errorf("input is %d bytes, above this component's %d-byte ceiling",
			len(stdin), maxInput)
	}
	return stdin, nil
}

// lines splits without inventing a trailing empty line for a final newline.
func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func runGrep(_ abi.SContext, args []string, stdin string) (string, error) {
	var ignoreCase, invert, countOnly, lineNo bool
	var pattern string
	found := false
	for _, a := range args {
		switch a {
		case "-i":
			ignoreCase = true
		case "-v":
			invert = true
		case "-c":
			countOnly = true
		case "-n":
			lineNo = true
		default:
			if strings.HasPrefix(a, "-") && len(a) > 1 {
				return "", fmt.Errorf("unknown flag %q", a)
			}
			if found {
				return "", fmt.Errorf("one pattern per invocation")
			}
			pattern, found = a, true
		}
	}
	if !found {
		return "", fmt.Errorf("usage: gnu-grep [-i] [-v] [-c] [-n] PATTERN")
	}
	expr := pattern
	if ignoreCase {
		// A leading (?i) is the pattern's own flag, so a caller-supplied pattern that
		// already begins with an inline flag group still compiles under this one.
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return "", fmt.Errorf("bad pattern: %v", err)
	}
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	for i, line := range lines(in) {
		if re.MatchString(line) == invert {
			continue
		}
		n++
		if countOnly {
			continue
		}
		if lineNo {
			fmt.Fprintf(&b, "%d:%s\n", i+1, line)
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if countOnly {
		return fmt.Sprintf("%d\n", n), nil
	}
	return b.String(), nil
}

func headTail(args []string, stdin string, first bool) (string, error) {
	n := 10
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-n":
			if i+1 >= len(args) {
				return "", fmt.Errorf("-n needs a count")
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 0 {
				return "", fmt.Errorf("%q is not a count", args[i+1])
			}
			n = v
			i++
		case strings.HasPrefix(args[i], "-n") && len(args[i]) > 2:
			v, err := strconv.Atoi(args[i][2:])
			if err != nil || v < 0 {
				return "", fmt.Errorf("%q is not a count", args[i][2:])
			}
			n = v
		default:
			return "", fmt.Errorf("unknown flag %q", args[i])
		}
	}
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	ls := lines(in)
	if n < len(ls) {
		if first {
			ls = ls[:n]
		} else {
			ls = ls[len(ls)-n:]
		}
	}
	if len(ls) == 0 {
		return "", nil
	}
	return strings.Join(ls, "\n") + "\n", nil
}

func runWC(_ abi.SContext, args []string, stdin string) (string, error) {
	showL, showW, showC := false, false, false
	for _, a := range args {
		switch a {
		case "-l":
			showL = true
		case "-w":
			showW = true
		case "-c":
			showC = true
		default:
			return "", fmt.Errorf("unknown flag %q", a)
		}
	}
	if !showL && !showW && !showC {
		showL, showW, showC = true, true, true
	}
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	var parts []string
	if showL {
		parts = append(parts, strconv.Itoa(len(lines(in))))
	}
	if showW {
		parts = append(parts, strconv.Itoa(len(strings.Fields(in))))
	}
	if showC {
		parts = append(parts, strconv.Itoa(len(in)))
	}
	return strings.Join(parts, " ") + "\n", nil
}

func runCut(_ abi.SContext, args []string, stdin string) (string, error) {
	sep := "\t"
	field := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d":
			if i+1 >= len(args) || args[i+1] == "" {
				return "", fmt.Errorf("-d needs a non-empty delimiter")
			}
			sep = args[i+1]
			i++
		case "-f":
			if i+1 >= len(args) {
				return "", fmt.Errorf("-f needs a field number")
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 1 {
				return "", fmt.Errorf("%q is not a field number (fields start at 1)", args[i+1])
			}
			field = v
			i++
		default:
			return "", fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if field == 0 {
		return "", fmt.Errorf("usage: gnu-cut -d SEP -f N")
	}
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, line := range lines(in) {
		parts := strings.Split(line, sep)
		if field <= len(parts) {
			b.WriteString(parts[field-1])
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func runSort(_ abi.SContext, args []string, stdin string) (string, error) {
	reverse, unique := false, false
	for _, a := range args {
		switch a {
		case "-r":
			reverse = true
		case "-u":
			unique = true
		default:
			return "", fmt.Errorf("unknown flag %q", a)
		}
	}
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	ls := lines(in)
	sort.Strings(ls)
	if reverse {
		for i, j := 0, len(ls)-1; i < j; i, j = i+1, j-1 {
			ls[i], ls[j] = ls[j], ls[i]
		}
	}
	if unique {
		out := ls[:0]
		for i, l := range ls {
			if i == 0 || l != ls[i-1] {
				out = append(out, l)
			}
		}
		ls = out
	}
	if len(ls) == 0 {
		return "", nil
	}
	return strings.Join(ls, "\n") + "\n", nil
}

func runUniq(_ abi.SContext, args []string, stdin string) (string, error) {
	withCount := false
	for _, a := range args {
		if a != "-c" {
			return "", fmt.Errorf("unknown flag %q", a)
		}
		withCount = true
	}
	in, err := input(stdin)
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
	for _, line := range lines(in) {
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

func runNL(_ abi.SContext, _ []string, stdin string) (string, error) {
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i, line := range lines(in) {
		fmt.Fprintf(&b, "%6d\t%s\n", i+1, line)
	}
	return b.String(), nil
}

func runTac(_ abi.SContext, _ []string, stdin string) (string, error) {
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	ls := lines(in)
	for i, j := 0, len(ls)-1; i < j; i, j = i+1, j-1 {
		ls[i], ls[j] = ls[j], ls[i]
	}
	if len(ls) == 0 {
		return "", nil
	}
	return strings.Join(ls, "\n") + "\n", nil
}

func runRev(_ abi.SContext, _ []string, stdin string) (string, error) {
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, line := range lines(in) {
		rs := []rune(line)
		for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
			rs[i], rs[j] = rs[j], rs[i]
		}
		b.WriteString(string(rs))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// runFmt re-wraps paragraphs at a width, keeping blank-line-separated blocks apart,
// which is what makes it usable on a pasted comment as well as on a log.
func runFmt(_ abi.SContext, args []string, stdin string) (string, error) {
	width := 75
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-w":
			if i+1 >= len(args) {
				return "", fmt.Errorf("-w needs a width")
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 10 {
				return "", fmt.Errorf("%q is not a width of at least 10", args[i+1])
			}
			width = v
			i++
		default:
			return "", fmt.Errorf("unknown flag %q", args[i])
		}
	}
	in, err := input(stdin)
	if err != nil {
		return "", err
	}

	var out strings.Builder
	words := make([]string, 0, 16)
	flush := func() {
		line := ""
		for _, w := range words {
			switch {
			case line == "":
				line = w
			case len(line)+1+len(w) > width:
				out.WriteString(line)
				out.WriteByte('\n')
				line = w
			default:
				line += " " + w
			}
		}
		if line != "" {
			out.WriteString(line)
			out.WriteByte('\n')
		}
		words = words[:0]
	}
	for _, l := range lines(in) {
		if strings.TrimSpace(l) == "" {
			flush()
			out.WriteByte('\n')
			continue
		}
		words = append(words, strings.Fields(l)...)
	}
	flush()
	return strings.TrimSuffix(out.String(), "\n") + "\n", nil
}

// runFactor prints the prime factors of every integer on the input, one line each, in
// the shape GNU factor uses: "N: p q r".
//
// Trial division, bounded by the input's magnitude rather than by a timer. A component
// that ran a long division loop on a number a session chose would occupy the daemon's
// goroutine for as long as the number said, which is exactly what the command deadline
// exists to stop - but it is better not to reach it.
func runFactor(_ abi.SContext, _ []string, stdin string) (string, error) {
	const maxValue = 1 << 40
	in, err := input(stdin)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(in))
	sc.Buffer(make([]byte, 0, 1024), maxInput)
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		v, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return "", fmt.Errorf("%q is not an integer", text)
		}
		if v > maxValue {
			return "", fmt.Errorf("%d is above this command's ceiling of %d", v, maxValue)
		}
		if v < 2 {
			fmt.Fprintf(&b, "%d:\n", v)
			continue
		}
		fmt.Fprintf(&b, "%d:", v)
		n := v
		for d := int64(2); d*d <= n; d++ {
			for n%d == 0 {
				fmt.Fprintf(&b, " %d", d)
				n /= d
			}
		}
		if n > 1 {
			fmt.Fprintf(&b, " %d", n)
		}
		b.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return b.String(), nil
}

// main is never called; it exists so `go build ./...` keeps compiling this file.
func main() {
	fmt.Fprintln(os.Stderr,
		"this package is a plugin: build it with\n"+
			"  go build -buildmode=plugin -o root/bin/gnu.so ./plugins/gnu\n"+
			"and let the console load it")
	os.Exit(2)
}
