package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/internal/auditfile"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/plugins/diag"
)

// buildTrail boots a kernel writing to path, loads and unloads diag, and shuts
// down. This is a real trail produced by the real kernel, not a fixture, so the
// tool is tested against exactly what it will be pointed at in the field.
func buildTrail(t *testing.T, path string) {
	t.Helper()
	sink, err := auditfile.New(auditfile.Options{Path: path})
	require.NoError(t, err)
	k, err := kernel.Boot(kernel.BootConfig{
		AuditSink: sink,
		TrustRoot: kernel.BootTrustRoot{NodeID: "verify-test"},
	})
	require.NoError(t, err)
	pid, err := k.Load(diag.Manifest())
	require.NoError(t, err)
	require.NoError(t, k.Unload(pid))
	require.NoError(t, k.Shutdown())
	require.NoError(t, sink.Close())
}

// runTool invokes the program in-process and returns its exit code plus stdout and
// stderr. Because run() takes argv and writers and returns a code, no subprocess and
// no os.Exit interception is needed.
func runTool(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVerifyCleanTrailExitsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clean.log")
	buildTrail(t, path)

	code, out, _ := runTool(t, path)

	assert.Equal(t, 0, code)
	assert.Contains(t, out, "OK (")
	assert.Contains(t, out, "entries across 1 boot(s)")
	assert.Contains(t, out, "denial=1", "the kind summary is part of the verdict")
}

func TestVerifyMultipleBoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multi.log")
	buildTrail(t, path)
	buildTrail(t, path)
	buildTrail(t, path)

	code, out, _ := runTool(t, path)

	assert.Equal(t, 0, code, "a multi-boot file must verify when each segment does")
	assert.Contains(t, out, "3 boot(s)")
}

func TestVerifyTamperedTrailExitsOneAndNamesTheEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tampered.log")
	buildTrail(t, path)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	edited := bytes.Replace(raw, []byte("module loaded"), []byte("module was never loaded"), 1)
	require.NotEqual(t, raw, edited)
	require.NoError(t, os.WriteFile(path, edited, 0o600))

	code, out, _ := runTool(t, path)

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "BROKEN")
	assert.Contains(t, out, "chain broken in boot 0")
	assert.Contains(t, out, "kind=load")
	assert.Contains(t, out, "module was never loaded",
		"the report must show the forged content, so an investigator sees what was claimed")
}

func TestVerifyDeletedLineExitsOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shortened.log")
	buildTrail(t, path)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := bytes.Split(raw, []byte("\n"))
	require.Greater(t, len(lines), 4)
	shortened := bytes.Join(append(append([][]byte{}, lines[:3]...), lines[4:]...), []byte("\n"))
	require.NoError(t, os.WriteFile(path, shortened, 0o600))

	code, out, _ := runTool(t, path)

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "BROKEN")
}

func TestVerifyUnparseableLineExitsOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "truncated.log")
	buildTrail(t, path)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString(`{"seq":99,"kind":"loa`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	code, out, _ := runTool(t, path)

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "UNREADABLE")
	assert.Contains(t, out, "unparseable audit line",
		"a truncated line must be reported as such, not as a broken hash")
}

func TestVerifyMissingFileExitsOne(t *testing.T) {
	code, out, _ := runTool(t, filepath.Join(t.TempDir(), "absent.log"))

	assert.Equal(t, 1, code, "an unreadable file is a finding, not a usage mistake")
	assert.Contains(t, out, "UNREADABLE")
}

func TestVerifyEmptyFileExitsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.log")
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	code, out, _ := runTool(t, path)

	assert.Equal(t, 0, code, "an empty file is not a broken chain")
	assert.Contains(t, out, "OK (0 entries across 0 boot(s))",
		"an empty file is not a broken chain")
}

func TestVerifyMixedFilesReportPerFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.log")
	bad := filepath.Join(dir, "bad.log")
	buildTrail(t, good)
	buildTrail(t, bad)

	raw, err := os.ReadFile(bad)
	require.NoError(t, err)
	edited := bytes.Replace(raw, []byte("kernel booting"), []byte("nothing happened"), 1)
	require.NotEqual(t, raw, edited)
	require.NoError(t, os.WriteFile(bad, edited, 0o600))

	code, out, _ := runTool(t, good, bad)

	assert.Equal(t, 1, code, "one broken file in a set must fail the run")
	assert.Contains(t, out, filepath.Base(good)+": OK")
	assert.Contains(t, out, filepath.Base(bad)+": BROKEN")
}

func TestJSONReportIsMachineReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "json.log")
	buildTrail(t, path)

	code, out, _ := runTool(t, "-json", path)
	require.Equal(t, 0, code)

	var doc struct {
		Files  int `json:"files"`
		Broken int `json:"broken"`
		Report []struct {
			Path     string         `json:"path"`
			OK       bool           `json:"ok"`
			Entries  int            `json:"entries"`
			Boots    int            `json:"boots"`
			BadBoot  int            `json:"bad_boot"`
			BadEntry int            `json:"bad_entry"`
			Kinds    map[string]int `json:"kinds"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	assert.Equal(t, 1, doc.Files)
	assert.Equal(t, 0, doc.Broken)
	require.Len(t, doc.Report, 1)

	r := doc.Report[0]
	assert.True(t, r.OK)
	assert.Equal(t, -1, r.BadBoot)
	assert.Positive(t, r.Entries)
	assert.Equal(t, 1, r.Boots)
	assert.Contains(t, r.Kinds, "boot")
	assert.Contains(t, r.Kinds, "load")
	assert.Contains(t, r.Kinds, "shutdown")
	assert.Contains(t, r.Kinds, "denial")
}

func TestKindFilterShowsMatchingEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter.log")
	buildTrail(t, path)

	code, out, _ := runTool(t, "-kind", "denial", path)

	assert.Equal(t, 0, code)
	assert.Contains(t, out, "denial")
	assert.Contains(t, out, "avc: denied",
		"specifying a filter must show the matching entries, not only a verdict")
	assert.Contains(t, out, "metadata:write")
	// And only the denials.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "seq=") {
			assert.Contains(t, line, "denial")
		}
	}
}

func TestPIDFilterAndLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pid.log")
	buildTrail(t, path)

	code, out, _ := runTool(t, "-pid", "2", "-limit", "2", path)

	assert.Equal(t, 0, code)
	assert.Contains(t, out, "pid=2")

	entryLines := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "seq=") {
			entryLines++
			assert.Contains(t, line, "pid=2")
			assert.NotContains(t, line, "pid=1")
		}
	}
	assert.LessOrEqual(t, entryLines, 2, "the limit must cap how many entries print")
}

func TestSinceFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "since.log")
	buildTrail(t, path)

	code, out, _ := runTool(t, "-since", "3", path)
	assert.Equal(t, 0, code)

	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "seq=") {
			continue
		}
		seq := parseSeq(t, line)
		assert.GreaterOrEqual(t, seq, int64(3))
	}
}

func parseSeq(t *testing.T, line string) int64 {
	t.Helper()
	i := strings.Index(line, "seq=")
	require.GreaterOrEqual(t, i, 0)
	rest := strings.TrimSpace(line[i+len("seq="):])
	end := strings.IndexAny(rest, " \t")
	if end > 0 {
		rest = rest[:end]
	}
	seq, err := strconv.ParseInt(rest, 10, 64)
	require.NoError(t, err, "seq field must parse: %q", rest)
	return seq
}

func TestQuietModePrintsNothingOnSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quiet.log")
	buildTrail(t, path)

	code, out, _ := runTool(t, "-quiet", path)

	assert.Equal(t, 0, code)
	assert.Empty(t, out)
}

func TestQuietModeStillPrintsOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quiet-broken.log")
	buildTrail(t, path)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path,
		bytes.Replace(raw, []byte("module loaded"), []byte("module faked"), 1), 0o600))

	code, out, _ := runTool(t, "-quiet", path)

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "BROKEN", "-quiet must never hide a broken chain")
}

func TestTamperingIsAttributedToTheRightBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "twoboots.log")
	buildTrail(t, path)
	buildTrail(t, path)

	entries, err := auditfile.Read(path)
	require.NoError(t, err)
	segs := auditfile.Segments(entries)
	require.Len(t, segs, 2)
	require.GreaterOrEqual(t, len(segs[1]), 3)

	// Tamper inside the second boot only.
	segs[1][1].Msg = "rewritten"
	var flat []kernel.AuditEntry
	for _, s := range segs {
		flat = append(flat, s...)
	}
	writeLines(t, path, flat)

	code, out, _ := runTool(t, path)

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "boot 1",
		"the report must attribute the tampering to the boot it is in")
	assert.NotContains(t, out, "boot 0",
		"and not to the first boot, which is intact")
}

func TestNoArgumentsIsAUsageError(t *testing.T) {
	code, _, errOut := runTool(t)

	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "at least one audit file is required")
}

func TestUnknownFlagIsAUsageError(t *testing.T) {
	code, _, _ := runTool(t, "-nope", "x.log")
	assert.Equal(t, 2, code)
}

func TestShowWithoutFilterPrintsTheWholeTrail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "show.log")
	buildTrail(t, path)

	entries, err := auditfile.Read(path)
	require.NoError(t, err)

	code, out, _ := runTool(t, "-show", path)
	assert.Equal(t, 0, code)

	shown := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "seq=") {
			shown++
		}
	}
	assert.Equal(t, len(entries), shown, "-show with no filter must print every entry")
}

func writeLines(t *testing.T, path string, entries []kernel.AuditEntry) {
	t.Helper()
	var b bytes.Buffer
	for _, e := range entries {
		line, err := json.Marshal(e)
		require.NoError(t, err)
		b.Write(line)
		b.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(path, b.Bytes(), 0o600))
}
