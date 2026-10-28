// Command instrcheck enforces the instruction-file integrity rules in AGENT.md.
//
// Rule A: instruction files are ASCII only. A homoglyph substitution - spelling
// a project name with a Cyrillic e and a Greek rho - makes a rule invisible to
// grep while remaining fully legible to an agent. That was the attack used
// against the upstream of this project. ASCII-only defeats it, and it is
// enforceable only over an ASCII alphabet, which is why AGENT.md is in English.
//
// Rule B: zero-width, bidi-override and tag characters are forbidden in every
// text file, not just instruction files. They have no legitimate use in source,
// and in code they are a Trojan Source attack: what a reviewer sees is not what
// the compiler sees.
//
// Exit status is 1 when any violation is found.
//
// Usage:
//
//	go run ./tools/instrcheck [-root DIR] [-json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// instructionNames are base file names that an agent harness auto-injects or
// that conventionally carry agent instructions, wherever they appear in the tree.
var instructionNames = map[string]bool{
	"agent.md":                true,
	"agents.md":               true,
	"claude.md":               true,
	"gemini.md":               true,
	".cursorrules":            true,
	".windsurfrules":          true,
	"copilot-instructions.md": true,
}

// instructionDirs are directories whose entire contents are agent instructions.
var instructionDirs = []string{".agents", ".claude", ".cursor", ".github/prompts"}

// skipDirs are never scanned. .git is version control internals; stage is
// reference material from the archived fork and is not part of this project;
// node_modules and vendor are third-party trees whose contents this check does
// not govern.
var skipDirs = map[string]bool{
	".git":         true,
	"stage":        true,
	"node_modules": true,
	"vendor":       true,
}

// exempt maps an instruction file path to the reason it may deviate from Rule A.
// Extending it requires a code change, so an exemption is always visible in
// review. There is deliberately no in-file marker that could silence the check,
// because whoever plants the payload could also plant the marker.
var exempt = map[string]string{}

// Finding is one violation.
type Finding struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	Rune      string `json:"rune"`
	Codepoint string `json:"codepoint"`
	Rule      string `json:"rule"`
	Class     string `json:"class"`
	Context   string `json:"context"`
}

// String renders one finding on a single grep-stable line:
//
//	AGENT.md:3:4: <char> U+0435 (cyrillic homoglyph) [A] <line with invisibles marked>
func (f Finding) String() string {
	return fmt.Sprintf("%s:%d:%d: %s U+%s (%s) [%s] %s",
		f.Path, f.Line, f.Column, f.Rune, f.Codepoint, f.Class, f.Rule, f.Context)
}

// classify names the character class, so a report says what kind of attack it
// resembles rather than only that something was non-ASCII.
func classify(r rune) (class string, dangerous bool) {
	switch {
	case r >= 0x0400 && r <= 0x04FF:
		return "cyrillic homoglyph", true
	case r >= 0x0370 && r <= 0x03FF:
		return "greek homoglyph", true
	case r >= 0x200B && r <= 0x200F:
		return "zero-width / invisible", true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return "bidi override", true
	case r >= 0xE0000 && r <= 0xE007F:
		return "tag character (steganographic)", true
	case r >= 0xFE00 && r <= 0xFE0F:
		return "variation selector", true
	case r >= 0x2060 && r <= 0x2064, r == 0x00AD:
		return "invisible formatting", true
	case unicode.Is(unicode.Han, r),
		unicode.Is(unicode.Hangul, r),
		unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hiragana, r):
		return "CJK / kana", false
	case unicode.Is(unicode.Arabic, r), unicode.Is(unicode.Hebrew, r):
		return "RTL script", true
	case r > 126:
		return "non-ascii", false
	}
	return "", false
}

// ruleBClasses are forbidden everywhere, in any text file, because they have no
// legitimate use in source code.
func ruleBViolation(class string) bool {
	switch class {
	case "zero-width / invisible", "bidi override", "tag character (steganographic)",
		"invisible formatting", "RTL script":
		return true
	}
	return false
}

func isInstructionFile(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	if instructionNames[base] {
		return true
	}
	if instructionNames[strings.ToLower(rel)] {
		return true
	}
	for _, d := range instructionDirs {
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	// MCP configuration is agent-reachable instruction surface.
	switch base {
	case ".mcp.json", "mcp.json", "mcp_config.json":
		return true
	}
	return false
}

// isNestedCheckout reports whether dir is its own git checkout: it holds a .git
// directory (an independent clone) or a .git file (a linked worktree, whose content
// is "gitdir: <path>"). The scan root is excluded by the caller, since the
// repository being scanned always has one.
func isNestedCheckout(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil
}

// isInstructionDirRoot reports whether rel is exactly one of the instruction
// directories rather than merely a path beneath one. Those directories are never
// prunable, because a prune keyed on a forgeable marker must not be able to exempt
// the surface it exists to protect. .claude is such a root;
// .claude/worktrees/agent-x is not, and is prunable.
func isInstructionDirRoot(rel string) bool {
	for _, d := range instructionDirs {
		if rel == d {
			return true
		}
	}
	return false
}

func likelyBinary(b []byte) bool {
	n := len(b)
	if n > 8192 {
		n = 8192
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}

func scan(path, rel string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if likelyBinary(data) {
		return nil, nil
	}
	// A file that is not valid UTF-8 cannot be reasoned about by this check.
	// Report it rather than silently passing: invalid encoding in an
	// instruction file is itself a way to hide content.
	if !isValidUTF8(data) {
		return []Finding{{
			Path: rel, Line: 1, Column: 1, Rule: "A",
			Class:   "invalid utf-8",
			Context: "file is not valid UTF-8 and cannot be audited as text",
		}}, nil
	}

	// An exempt file is no longer held to Rule A, but Rule B still applies to
	// it: invisible characters are never legitimate.
	instruction := isInstructionFile(rel)
	if _, ok := exempt[rel]; ok {
		instruction = false
	}

	text := string(data)
	var out []Finding
	line, col := 1, 1
	for _, r := range text {
		if r == '\n' {
			line++
			col = 1
			continue
		}
		if r == '\r' {
			col++
			continue
		}

		class, dangerous := classify(r)
		rule := ""
		switch {
		case instruction && r > 126:
			rule = "A"
		case dangerous && ruleBViolation(class):
			rule = "B"
		}
		if rule != "" {
			out = append(out, Finding{
				Path:      rel,
				Line:      line,
				Column:    col,
				Rune:      string(r),
				Codepoint: fmt.Sprintf("%04X", r),
				Rule:      rule,
				Class:     class,
				Context:   lineContext(text, line),
			})
		}
		col++
	}
	return out, nil
}

func isValidUTF8(b []byte) bool {
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			return false
		}
		b = b[size:]
	}
	return true
}

func lineContext(text string, line int) string {
	lines := strings.Split(text, "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	s := strings.TrimRight(lines[line-1], "\r")
	const max = 100
	if len(s) > max {
		s = s[:max] + "..."
	}
	// Make invisible characters visible in the report. The keys are written as
	// escape sequences so this source file contains no literal invisible bytes:
	// a security check that needs an exemption for its own source is a broken
	// check, because that exemption is the hole an attacker would use.
	var repl = []string{
		"\u200b", "<ZWSP>", "\u200c", "<ZWNJ>", "\u200d", "<ZWJ>",
		"\u200e", "<LRM>", "\u200f", "<RLM>", "\u00ad", "<SHY>",
		"\u202a", "<LRE>", "\u202b", "<RLE>", "\u202c", "<PDF>",
		"\u202d", "<LRO>", "\u202e", "<RLO>",
		"\u2066", "<LRI>", "\u2067", "<RLI>", "\u2068", "<FSI>", "\u2069", "<PDI>",
		"\u2060", "<WJ>", "\ufeff", "<BOM>",
	}
	s = strings.NewReplacer(repl...).Replace(s)
	return s
}

// Stats summarizes one scan.
type Stats struct {
	Scanned          int
	InstructionFiles int
	// NestedCheckouts counts directories pruned because they are a separate git
	// checkout rather than part of this repository.
	NestedCheckouts int
}

// Check walks root and returns every violation, sorted by path, line and column.
// An unreadable file is an error rather than a skip: a check that silently passes
// what it cannot read is the hole the check exists to close.
func Check(root string) ([]Finding, Stats, error) {
	var findings []Finding
	var st Stats

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			// Prune by name so a skipped directory is skipped at any depth, not
			// only at the repository root.
			if rel != "." && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			// A nested git checkout is a separate repository with its own tracked
			// tree, its own review and its own scan. Scanning it from here reports
			// another checkout's files as violations of this one, which is a false
			// positive rather than a finding: the same content in the same relative
			// path inside that checkout is already governed there.
			//
			// This matters concretely for agent working trees, which live under
			// .claude/worktrees/ - a path that is itself an instruction directory, so
			// without this prune every file in a nested checkout counts as an
			// instruction file and a Go test fixture containing a deliberate
			// homoglyph becomes a Rule A violation fourteen times over.
			//
			// The prune is keyed on a directory being its own checkout, so it has to
			// be keyed on something an attacker cannot forge. A file named .git is
			// trivially forgeable, which is why isInstructionDirRoot excludes the
			// instruction directories themselves: planting .claude/.git does not
			// exempt .claude/settings.json, because .claude is not prunable. What the
			// prune exempts is a nested checkout's own copy of the tree, and that copy
			// is by construction untracked by this repository, so it can never be
			// committed and is not part of the surface this check defends.
			//
			// The CI job does not rely on this prune at all. Its independent ASCII
			// assertion walks `git ls-files`, which never lists a nested checkout's
			// contents, so a forged .git anywhere has no effect on the job.
			if rel != "." && isNestedCheckout(p) && !isInstructionDirRoot(rel) {
				st.NestedCheckouts++
				return fs.SkipDir
			}
			return nil
		}
		if rel == "." {
			return nil
		}

		st.Scanned++
		if isInstructionFile(rel) {
			st.InstructionFiles++
		}
		f, ferr := scan(p, rel)
		if ferr != nil {
			return fmt.Errorf("scan %s: %w", rel, ferr)
		}
		findings = append(findings, f...)
		return nil
	})
	if err != nil {
		return nil, st, err
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Column < findings[j].Column
	})
	return findings, st, nil
}

func main() {
	root := flag.String("root", ".", "repository root to scan")
	asJSON := flag.Bool("json", false, "emit findings as JSON")
	quiet := flag.Bool("quiet", false, "print nothing on success")
	flag.Parse()

	info, err := os.Stat(*root)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "instrcheck: not a directory: %s\n", *root)
		os.Exit(2)
	}

	findings, st, err := Check(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "instrcheck: %v\n", err)
		os.Exit(2)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"scanned":           st.Scanned,
			"instruction_files": st.InstructionFiles,
			"violations":        len(findings),
			"findings":          findings,
		})
	} else if len(findings) == 0 {
		if !*quiet {
			nested := ""
			if st.NestedCheckouts > 0 {
				nested = fmt.Sprintf(", %d nested checkout(s) pruned", st.NestedCheckouts)
			}
			fmt.Printf("instrcheck: OK (%d files scanned, %d instruction files, 0 violations%s)\n",
				st.Scanned, st.InstructionFiles, nested)
		}
	} else {
		nested := ""
		if st.NestedCheckouts > 0 {
			nested = fmt.Sprintf(", %d nested checkout(s) pruned", st.NestedCheckouts)
		}
		fmt.Fprintf(os.Stderr, "instrcheck: %d violation(s), %d files scanned, %d instruction files%s\n\n",
			len(findings), st.Scanned, st.InstructionFiles, nested)
		for _, f := range findings {
			fmt.Fprintln(os.Stderr, "  "+f.String())
		}
		fmt.Fprint(os.Stderr, ruleHelp)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}

const ruleHelp = `
Rule A: instruction files (AGENT.md, AGENTS.md, CLAUDE.md, .agents/, .claude/,
        MCP config) must be pure ASCII. Homoglyph substitution hides a rule from
        grep while keeping it legible to an agent.
Rule B: zero-width, bidi-override, RTL and tag characters are forbidden in every
        text file. They have no legitimate use in source and are a Trojan Source
        vector.

Fix the file. Do not weaken this check to make it pass. Extending the exemption
list requires a code change so that the exemption is visible in review.
`
