// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

const corpusDir = "../../testdata/corpus"

// corpusHeaderRe matches one header line of a case. A case describes the shape
// it reproduces and the issues behind it, never the repository it came from.
var corpusHeaderRe = regexp.MustCompile(`(?m)^(Pattern|Issues|Flags): *(.*)$`)

var corpusIssueRe = regexp.MustCompile(`^#\d+(, #\d+)*$`)

// corpusHeader reads the comment of a case: the part of the archive before the
// first file. It returns the extra scan flags, or a reason the header is wrong.
func corpusHeader(archive string) (flags []string, problem string) {
	comment, _, _ := strings.Cut("\n"+strings.ReplaceAll(archive, "\r\n", "\n"), "\n-- ")
	fields := map[string]string{}
	for _, m := range corpusHeaderRe.FindAllStringSubmatch(comment, -1) {
		fields[m[1]] = strings.TrimSpace(m[2])
	}
	if fields["Pattern"] == "" {
		return nil, "no Pattern: line saying which shape this case reproduces"
	}
	if !corpusIssueRe.MatchString(fields["Issues"]) {
		return nil, "no Issues: line naming the issues behind this case, as #1, #2"
	}
	return strings.Fields(fields["Flags"]), ""
}

// corpusReport is what a case pins: the exit code and one line per finding,
// sorted. It leaves the message out, so rewording a rule touches no case.
func corpusReport(code int, dir string, findings []finding.Finding) string {
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		rel, err := filepath.Rel(dir, f.File)
		if err != nil {
			rel = f.File
		}
		lines = append(lines, fmt.Sprintf("%s %s %s:%d", f.RuleID, f.Severity, filepath.ToSlash(rel), f.Line))
	}
	slices.Sort(lines)
	return fmt.Sprintf("exit %d\n%s", code, strings.Join(append(lines, ""), "\n"))
}

// scanCorpusCase unpacks a case and runs one whole scan through the CLI, from
// discovery to the JSON report.
func scanCorpusCase(t *testing.T, archive string, flags []string) string {
	t.Helper()
	dir := t.TempDir()
	files := parseTxtar(archive)
	if len(files) == 0 {
		t.Fatal("case has no files")
	}
	for name, content := range files {
		writeAdvisoryFile(t, dir, name, content)
	}
	args := []string{"cfgaudit", "--config", os.DevNull, "--format", "json", "--claude-version", advisoryClaudeVersion}
	var out, errb bytes.Buffer
	code := run(append(append(args, flags...), dir), nil, &out, &errb)
	var findings []finding.Finding
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("exit %d, report %q, stderr %q: %v", code, out.String(), errb.String(), err)
	}
	return corpusReport(code, dir, findings)
}

// TestCorpus scans every case in testdata/corpus. A clean-* case must report
// nothing, and has no golden that -update could rewrite. Any other case must
// match its .golden file. TESTING.md says how a case gets here.
func TestCorpus(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(corpusDir, "*.txtar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no corpus cases found")
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".txtar")
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(path) // #nosec G304 -- fixture in this repository
			if err != nil {
				t.Fatal(err)
			}
			flags, problem := corpusHeader(string(b))
			if problem != "" {
				t.Fatal(problem)
			}
			got := scanCorpusCase(t, string(b), flags)
			golden := strings.TrimSuffix(path, ".txtar") + ".golden"
			if strings.HasPrefix(name, "clean-") {
				if got != "exit 0\n" {
					t.Errorf("a clean case must report nothing, got:\n%s", got)
				}
				if _, err := os.Stat(golden); err == nil {
					t.Errorf("%s: a clean case has no golden", golden)
				}
				return
			}
			if *updateGolden {
				if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden) // #nosec G304 -- fixture in this repository
			if err != nil {
				t.Fatalf("%v (write it with go test ./cmd/cfgaudit -run TestCorpus -update)", err)
			}
			if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Errorf("the scan differs from %s\ngot:\n%s\nwant:\n%s", filepath.Base(golden), got, want)
			}
		})
	}
}

// A golden without a case would pin nothing.
func TestCorpus_NoOrphanGolden(t *testing.T) {
	goldens, err := filepath.Glob(filepath.Join(corpusDir, "*.golden"))
	if err != nil {
		t.Fatal(err)
	}
	for _, golden := range goldens {
		if _, err := os.Stat(strings.TrimSuffix(golden, ".golden") + ".txtar"); err != nil {
			t.Errorf("%s has no case", filepath.Base(golden))
		}
	}
}

func TestCorpusHeader(t *testing.T) {
	flags, problem := corpusHeader("Pattern: a shape\r\nIssues: #1, #22\r\nFlags: --plugins\r\n-- a --\nIssues: #x\n")
	if problem != "" || !slices.Equal(flags, []string{"--plugins"}) {
		t.Errorf("got %v, %q", flags, problem)
	}
	for _, bad := range []string{
		"Issues: #1\n-- a --\n",
		"Pattern: a shape\n-- a --\n",
		"Pattern: a shape\nIssues: 12\n-- a --\n",
		"-- a --\nPattern: a shape\nIssues: #1\n",
	} {
		if _, problem := corpusHeader(bad); problem == "" {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestCorpusReport(t *testing.T) {
	dir := t.TempDir()
	got := corpusReport(1, dir, []finding.Finding{
		{RuleID: "CFG2", Severity: finding.Warn, File: filepath.Join(dir, "b", "c.md"), Line: 2},
		{RuleID: "CFG1", Severity: finding.Error, File: filepath.Join(dir, "a.json")},
	})
	if want := "exit 1\nCFG1 error a.json:0\nCFG2 warn b/c.md:2\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := corpusReport(0, dir, nil); got != "exit 0\n" {
		t.Errorf("no findings: got %q", got)
	}
}
