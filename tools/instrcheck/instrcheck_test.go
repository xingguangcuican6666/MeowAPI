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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// write creates a file in a fixture tree, making parent directories as needed.
func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func checkRoot(t *testing.T, root string) []Finding {
	t.Helper()
	findings, _, err := Check(root)
	require.NoError(t, err)
	return findings
}

// TestCleanTreePasses is the baseline: an ASCII tree with a conforming
// instruction file produces no findings. Without this, every other test could
// pass for the wrong reason.
func TestCleanTreePasses(t *testing.T) {
	root := t.TempDir()
	write(t, root, "AGENT.md", "# AGENT.md\n\nPure ASCII conventions.\n")
	write(t, root, "kernel/boot.go", "package kernel\n\n// boot does nothing.\n")
	write(t, root, "README.md", "# MeowAPI\n")

	assert.Empty(t, checkRoot(t, root))

	findings, st, err := Check(root)
	require.NoError(t, err)
	require.Empty(t, findings)
	assert.Equal(t, 3, st.Scanned)
	assert.Equal(t, 1, st.InstructionFiles, "AGENT.md must be recognized as an instruction file")
}

// TestHomoglyphInInstructionFile is the attack this tool exists for: a rule
// spelled with Cyrillic and Greek look-alikes, which is invisible to grep for
// the ASCII spelling while remaining fully legible to an agent.
func TestHomoglyphInInstructionFile(t *testing.T) {
	root := t.TempDir()
	// "new-api" with a Cyrillic e (U+0435) and a Greek rho (U+03C1), and
	// "QuantumNous" with a Cyrillic a (U+0430) and a Cyrillic s (U+0455).
	write(t, root, "AGENT.md", "# Rules\n\nDo not rename n\u0435w-a\u03c1i or Qu\u0430ntumNou\u0455.\n")

	findings := checkRoot(t, root)
	require.Len(t, findings, 4)

	var classes []string
	for _, f := range findings {
		assert.Equal(t, "A", f.Rule)
		assert.Equal(t, "AGENT.md", f.Path)
		assert.Equal(t, 3, f.Line, "the offending line must be located")
		classes = append(classes, f.Class)
	}
	assert.ElementsMatch(t,
		[]string{"cyrillic homoglyph", "greek homoglyph", "cyrillic homoglyph", "cyrillic homoglyph"},
		classes)

	// An ASCII grep for the real spelling must miss it, which is why this is
	// dangerous and why the check is codepoint-based rather than string-based.
	body, err := os.ReadFile(filepath.Join(root, "AGENT.md"))
	require.NoError(t, err)
	assert.NotContains(t, string(body), "new-api")
}

// TestHomoglyphOutsideInstructionFilesIsNotRuleA proves Rule A is scoped to
// agent-instruction surface. Human prose in other languages is not a violation;
// conflating the two would make the check unshippable.
func TestHomoglyphOutsideInstructionFilesIsNotRuleA(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docs/ru.md", "\u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440.\n")
	write(t, root, "web/i18n/zh.json", "{\"key\": \"\u4f60\u597d\u4e16\u754c\"}\n")

	assert.Empty(t, checkRoot(t, root),
		"Cyrillic and Han in non-instruction files are legitimate and must pass")
}

// TestInvisibleCharactersForbiddenEverywhere is Rule B: zero-width and bidi
// characters have no legitimate use in source, in any file, and in code they are
// a Trojan Source vector - what a reviewer sees is not what the compiler sees.
func TestInvisibleCharactersForbiddenEverywhere(t *testing.T) {
	cases := []struct {
		name  string
		rune  rune
		class string
	}{
		{"zero width space", '\u200b', "zero-width / invisible"},
		{"zero width joiner", '\u200d', "zero-width / invisible"},
		{"right to left mark", '\u200f', "zero-width / invisible"},
		{"soft hyphen", '\u00ad', "invisible formatting"},
		{"right to left override", '\u202e', "bidi override"},
		{"left to right override", '\u202d', "bidi override"},
		{"first strong isolate", '\u2068', "bidi override"},
		{"pop directional isolate", '\u2069', "bidi override"},
		{"word joiner", '\u2060', "invisible formatting"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			// Embedded in ordinary Go source, the realistic Trojan Source shape.
			write(t, root, "kernel/auth.go",
				"package kernel\n\nvar token = \"abc"+string(c.rune)+"def\"\n")

			findings := checkRoot(t, root)
			require.Len(t, findings, 1)
			assert.Equal(t, "B", findings[0].Rule)
			assert.Equal(t, c.class, findings[0].Class)
			assert.Equal(t, "kernel/auth.go", findings[0].Path)
			assert.Equal(t, 3, findings[0].Line)
		})
	}
}

// TestTagCharactersForbidden covers the U+E0000 block used to hide text that
// renders as nothing in most viewers.
func TestTagCharactersForbidden(t *testing.T) {
	root := t.TempDir()
	write(t, root, "AGENT.md", "# Rules\n\n"+string(rune(0xE0041))+string(rune(0xE0042))+"\n")

	findings := checkRoot(t, root)
	require.Len(t, findings, 2)
	for _, f := range findings {
		assert.Equal(t, "A", f.Rule, "an instruction file violates Rule A on any non-ASCII byte")
		assert.Equal(t, "tag character (steganographic)", f.Class)
	}
}

// TestTagCharacterInSourceIsRuleB proves the tag block is caught outside
// instruction files too, where Rule A does not reach.
func TestTagCharacterInSourceIsRuleB(t *testing.T) {
	root := t.TempDir()
	write(t, root, "kernel/x.go", "package kernel\n\nvar _ = \""+string(rune(0xE0041))+"\"\n")

	findings := checkRoot(t, root)
	require.Len(t, findings, 1)
	assert.Equal(t, "B", findings[0].Rule)
	assert.Equal(t, "tag character (steganographic)", findings[0].Class)
}

// TestInstructionSurfaceIsDetected enumerates every path shape the check treats
// as agent instructions. Missing one is a hole: a payload planted in an
// unrecognized instruction file passes silently.
func TestInstructionSurfaceIsDetected(t *testing.T) {
	paths := []string{
		"AGENT.md",
		"AGENTS.md",
		"CLAUDE.md",
		"GEMINI.md",
		"web/AGENTS.md",
		".cursorrules",
		".windsurfrules",
		".github/copilot-instructions.md",
		".agents/rules/billing.md",
		".claude/settings.json",
		".cursor/rules/style.md",
		".github/prompts/dev.md",
		".mcp.json",
		"config/mcp.json",
	}

	for _, rel := range paths {
		t.Run(rel, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, rel, "# x\n\nDo not rename n\u0435w-api.\n")

			findings := checkRoot(t, root)
			require.Len(t, findings, 1, "%s must be treated as an instruction file", rel)
			assert.Equal(t, "A", findings[0].Rule)
			assert.Equal(t, filepath.ToSlash(rel), findings[0].Path)
		})
	}
}

// TestSkippedDirectoriesArePruned proves the check does not audit vendored or
// reference trees it does not govern, and that pruning works at depth.
func TestSkippedDirectoriesArePruned(t *testing.T) {
	root := t.TempDir()
	payload := "var _ = \"n\u0435w\"\n"
	write(t, root, "stage/controller/x.go", payload)
	write(t, root, "vendor/lib/x.go", payload)
	write(t, root, "web/node_modules/pkg/x.js", payload)
	write(t, root, ".git/hooks/x.sh", payload)
	write(t, root, "kernel/x.go", payload) // Han, not a violation anywhere

	assert.Empty(t, checkRoot(t, root), "skipped trees must not be scanned")

	// The same payload outside a skipped tree is caught, proving the emptiness
	// above came from pruning and not from a broken check. Rule B applies to
	// every text file, so an invisible character is the payload to use here.
	write(t, root, "tools/x.go", "var _ = \"n\u200bw\"\n")
	findings := checkRoot(t, root)
	require.Len(t, findings, 1)
	assert.Equal(t, "tools/x.go", findings[0].Path)
	assert.Equal(t, "B", findings[0].Rule)
}

// TestSkippedDirAtDepthPrunesByName confirms skipDirs matches on directory name
// at any depth, not only at the repository root. A nested node_modules is the
// realistic case.
func TestSkippedDirAtDepthPrunesByName(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a/b/stage/c/x.go", "var _ = \"n\u0435w\"\n")
	assert.Empty(t, checkRoot(t, root))
}

// TestNestedCheckoutIsPruned covers a separate git checkout living inside the scan
// root. It is a different repository with its own tracked tree and its own review, so
// its files are not this repository's instruction surface. The realistic case is an
// agent working tree under .claude/worktrees/, which is an instruction directory: every
// file in the nested checkout would otherwise count as an instruction file, and a Go
// test fixture holding a deliberate homoglyph would be reported as a Rule A violation
// once per checkout.
func TestNestedCheckoutIsPruned(t *testing.T) {
	for _, c := range []struct {
		name string
		git  string
	}{
		{"linked worktree", "gitdir: /elsewhere/.git/worktrees/x\n"},
		{"independent clone", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "AGENT.md", "# ok\n")

			nested := filepath.Join(root, ".claude/worktrees/agent-x")
			require.NoError(t, os.MkdirAll(nested, 0o755))
			if c.git == "" {
				require.NoError(t, os.MkdirAll(filepath.Join(nested, ".git"), 0o755))
			} else {
				require.NoError(t, os.WriteFile(filepath.Join(nested, ".git"),
					[]byte(c.git), 0o644))
			}
			// A file that would be a Rule A violation if it were scanned: it sits
			// under an instruction directory and holds a Cyrillic homoglyph.
			write(t, root, ".claude/worktrees/agent-x/tools/x/x_test.go",
				"var _ = \"n\u0435w\"\n")

			findings, st, err := Check(root)
			require.NoError(t, err)
			assert.Empty(t, findings, "a nested checkout is not this repository's instruction surface")
			assert.Equal(t, 1, st.NestedCheckouts, "the prune must be counted, not silent")
		})
	}
}

// TestNestedCheckoutPruneDoesNotExemptRealInstructionSurface is the other half, and
// it is the one that keeps the prune honest. The prune is keyed on a directory being
// its own checkout, so an instruction file that is part of THIS repository must still
// be reported even when it sits in the same .claude/ tree that contains the nested
// checkouts.
func TestNestedCheckoutPruneDoesNotExemptRealInstructionSurface(t *testing.T) {
	root := t.TempDir()
	write(t, root, "AGENT.md", "# ok\n")

	// A real, tracked instruction file in this repository.
	write(t, root, ".claude/settings.json", "{\"model\": \"n\u0435w\"}\n")

	// A nested checkout beside it, holding the same payload.
	nested := filepath.Join(root, ".claude/worktrees/agent-y")
	require.NoError(t, os.MkdirAll(filepath.Join(nested, ".git"), 0o755))
	write(t, root, ".claude/worktrees/agent-y/.claude/settings.json",
		"{\"model\": \"n\u0435w\"}\n")

	findings, st, err := Check(root)
	require.NoError(t, err)
	require.Len(t, findings, 1, "only this repository's own file is a finding")
	assert.Contains(t, findings[0].Path, ".claude/settings.json")
	assert.NotContains(t, findings[0].Path, "worktrees")
	assert.Equal(t, 1, st.NestedCheckouts)
}

// TestForgedGitInsideAnInstructionDirDoesNotExemptIt is the abuse case, and it is the
// reason the prune is keyed on isInstructionDirRoot. The prune marker is a file named
// .git, which is forgeable, so a planted one must not be able to exempt the directory
// it sits in when that directory is itself instruction surface.
func TestForgedGitInsideAnInstructionDirDoesNotExemptIt(t *testing.T) {
	root := t.TempDir()
	write(t, root, "AGENT.md", "# ok\n")

	// .claude is an instruction directory. Planting a .git marker inside it must not
	// make its own contents unscannable.
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".claude"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".claude/.git"),
		[]byte("gitdir: /forged\n"), 0o644))
	write(t, root, ".claude/settings.json", "{\"model\": \"n\u0435w\"}\n")

	findings, st, err := Check(root)
	require.NoError(t, err)
	require.Len(t, findings, 1, "an instruction directory is never prunable")
	assert.Contains(t, findings[0].Path, ".claude/settings.json")
	assert.Zero(t, st.NestedCheckouts, "a forged marker must not be counted as a prune")
}

// TestScanRootIsNotPrunedAsNested pins the one exclusion the walk makes: the root
// being scanned is always this repository, so its own .git must not cause the whole
// scan to prune itself away and report a vacuous pass.
func TestScanRootIsNotPrunedAsNested(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".git"), 0o755))
	write(t, root, "AGENT.md", "# z n\u0435w\n")

	findings, st, err := Check(root)
	require.NoError(t, err)
	require.Len(t, findings, 1, "the scan root must be scanned even though it holds .git")
	assert.Zero(t, st.NestedCheckouts)
}

// TestBinaryFilesAreSkipped prevents false positives on images, archives and
// compiled artifacts, which legitimately contain bytes above 0x7E.
func TestBinaryFilesAreSkipped(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "assets/logo.png")
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte{0x89, 'P', 'N', 'G', 0x00, 0xFF, 0xC3}, 0o644))
	write(t, root, "AGENT.md", "# ok\n")

	findings, st, err := Check(root)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, 2, st.Scanned, "a binary file is scanned and skipped, not counted as instruction surface")
}

// TestInvalidUTF8IsReported covers the encoding hole: a file that is not valid
// UTF-8 cannot be reasoned about, so it is reported rather than silently passed.
func TestInvalidUTF8IsReported(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "AGENT.md")
	require.NoError(t, os.WriteFile(p, []byte("# Rules\n\nbroken: \xff\xfe\n"), 0o644))

	findings := checkRoot(t, root)
	require.Len(t, findings, 1)
	assert.Equal(t, "A", findings[0].Rule)
	assert.Equal(t, "invalid utf-8", findings[0].Class)
}

// TestLineContextRendersInvisiblesVisibly asserts the report shows what was
// found. A finding that prints an invisible character is a finding a human
// cannot read, which defeats the purpose of the report.
func TestLineContextRendersInvisiblesVisibly(t *testing.T) {
	root := t.TempDir()
	write(t, root, "kernel/x.go", "package kernel\n\nvar s = \"a\u200bb\u202ec\"\n")

	findings := checkRoot(t, root)
	require.Len(t, findings, 2)

	var contexts []string
	for _, f := range findings {
		contexts = append(contexts, f.Context)
	}
	assert.Contains(t, contexts[0], "<ZWSP>")
	assert.Contains(t, contexts[0], "a")
	assert.Contains(t, contexts[1], "<RLO>")
	for _, f := range findings {
		assert.NotContains(t, f.Context, "\u200b")
		assert.NotContains(t, f.Context, "\u202e")
	}
}

// TestFindingStringIsGrepStable pins the report format, so CI output can be
// parsed and so a changed format is a deliberate act.
func TestFindingStringIsGrepStable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "AGENT.md", "x\ny\nz n\u0435w\n")

	findings := checkRoot(t, root)
	require.Len(t, findings, 1)
	s := findings[0].String()

	assert.Equal(t,
		"AGENT.md:3:4: е U+0435 (cyrillic homoglyph) [A] z nеw",
		s)
}

// TestExemptFileStillGetsRuleB proves an exemption narrows Rule A only. An
// exempt instruction file is still not allowed to carry invisible characters,
// because that would make the exemption a general-purpose hole.
func TestExemptFileStillGetsRuleB(t *testing.T) {
	exempt["EXEMPTED.md"] = "test fixture"
	t.Cleanup(func() { delete(exempt, "EXEMPTED.md") })

	// EXEMPTED.md is not an instruction name anyway, so assert the mechanism
	// through a real instruction path instead.
	exempt["AGENT.md"] = "test fixture"
	t.Cleanup(func() { delete(exempt, "AGENT.md") })

	root := t.TempDir()
	write(t, root, "AGENT.md", "# ok\n\nHan is fine here now: \u4f60\u597d\n")
	assert.Empty(t, checkRoot(t, root), "an exempt file is not held to Rule A")

	write(t, root, "AGENT.md", "# ok\n\nvar s = \"a\u200bb\"\n")
	findings := checkRoot(t, root)
	require.Len(t, findings, 1)
	assert.Equal(t, "B", findings[0].Rule, "Rule B still applies to an exempt file")
}

// TestToolOwnSourceIsClean is the self-test. The check must not need an
// exemption for its own source, because that exemption would be the first place
// an attacker hides a payload. This test fails if anyone reintroduces a literal
// invisible byte into tools/instrcheck/main.go.
func TestToolOwnSourceIsClean(t *testing.T) {
	findings := checkRoot(t, ".")
	for _, f := range findings {
		assert.NotEqual(t, "tools/instrcheck/main.go", f.Path,
			"instrcheck's own source must contain no literal invisible or non-ASCII byte: %s", f)
	}
}

// TestRepoAgentMdIsASCII pins the project's own conformance: the instruction
// file at the repository root passes both rules. This is the file an agent reads
// first, so it is the one that must never regress.
func TestRepoAgentMdIsASCII(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "AGENT.md"))
	require.NoError(t, err, "AGENT.md must exist at the repository root")

	for i, r := range string(body) {
		if r > 126 {
			t.Fatalf("AGENT.md contains non-ASCII at byte offset %d: %#U", i, r)
		}
	}
	assert.True(t, isInstructionFile("AGENT.md"))
	assert.NotContains(t, string(body), "\u200b")
	assert.Greater(t, len(body), 1000, "AGENT.md must not be an empty stub")
}

// TestRepoTreeIsClean runs the check over the real repository. stage/ and
// .git/ are pruned; everything else must pass.
func TestRepoTreeIsClean(t *testing.T) {
	findings, st, err := Check(filepath.Join("..", ".."))
	require.NoError(t, err)
	require.Empty(t, findings, "repository must satisfy its own integrity rules")
	assert.Greater(t, st.Scanned, 10)
	assert.GreaterOrEqual(t, st.InstructionFiles, 1)
}

// TestClassifyCoversTheAuditedRanges guards the classifier itself. If a range
// boundary is edited wrong, homoglyphs start passing.
func TestClassifyCoversTheAuditedRanges(t *testing.T) {
	cases := []struct {
		r         rune
		class     string
		dangerous bool
	}{
		{'a', "", false},
		{'~', "", false},
		{'\u0400', "cyrillic homoglyph", true},
		{'\u04ff', "cyrillic homoglyph", true},
		{'\u0370', "greek homoglyph", true},
		{'\u03ff', "greek homoglyph", true},
		{'\u03c1', "greek homoglyph", true},
		{'\u0435', "cyrillic homoglyph", true},
		{'\u200b', "zero-width / invisible", true},
		{'\u200f', "zero-width / invisible", true},
		{'\u202a', "bidi override", true},
		{'\u202e', "bidi override", true},
		{'\u2066', "bidi override", true},
		{'\u2069', "bidi override", true},
		{'\u00ad', "invisible formatting", true},
		{'\u2060', "invisible formatting", true},
		{rune(0xE0000), "tag character (steganographic)", true},
		{rune(0xE007F), "tag character (steganographic)", true},
		{'\ufe0f', "variation selector", true},
		{'\u4f60', "CJK / kana", false},
		{'\u0627', "RTL script", true},
		{'\u00e9', "non-ascii", false},
	}

	for _, c := range cases {
		class, dangerous := classify(c.r)
		assert.Equal(t, c.class, class, "classify(%#U) class", c.r)
		assert.Equal(t, c.dangerous, dangerous, "classify(%#U) dangerous", c.r)
	}
}

// TestRuleBScope asserts exactly which classes are forbidden everywhere. The
// variation selector and plain non-ASCII are not: they appear in legitimate
// source, and banning them would make the check noise.
func TestRuleBScope(t *testing.T) {
	forbidden := []string{
		"zero-width / invisible", "bidi override", "tag character (steganographic)",
		"invisible formatting", "RTL script",
	}
	for _, c := range forbidden {
		assert.True(t, ruleBViolation(c), "%s must be a Rule B violation", c)
	}
	for _, c := range []string{"cyrillic homoglyph", "greek homoglyph", "variation selector", "CJK / kana", "non-ascii", ""} {
		assert.False(t, ruleBViolation(c), "%s must not be a Rule B violation", c)
	}
}

// TestHomoglyphInNonInstructionGoFileIsNotAViolation documents a real gap so it
// is not mistaken for coverage. A Cyrillic look-alike in ordinary Go source is
// caught by the compiler (an invalid identifier does not build) or is harmless
// in a string literal, so it is not a Rule B violation. Rule A is about agent
// instructions, not about all source.
func TestHomoglyphInNonInstructionGoFileIsNotAViolation(t *testing.T) {
	root := t.TempDir()
	write(t, root, "kernel/x.go", "package kernel\n\nvar label = \"n\u0435w-api\"\n")

	assert.Empty(t, checkRoot(t, root),
		"a homoglyph in a plain string is not invisible to a reader the way one in an instruction file is")

	// In an identifier it will not compile, which is its own protection.
	// instrcheck does not parse Go, so it reports nothing either way.
	write(t, root, "kernel/y.go", "package kernel\n\nvar n\u0435w = 1\n")
	assert.Empty(t, checkRoot(t, root), "instrcheck does not parse Go; the compiler is the control here")
}
