// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// A baseline file records the findings a repository accepted when it adopted
// cfgaudit, so CI fails only on new ones (#998). `cfgaudit baseline` writes
// it; `cfgaudit --baseline <file>` drops the findings it lists and reports
// the rest, with a count of what it dropped and the entries that no longer
// match anything.
type baselineFile struct {
	Version  int             `json:"version"`
	Findings []baselineEntry `json:"findings"`
}

// baselineEntry is one accepted finding. Rule and File are there for the
// reader of the file and for the stale list; Fingerprint decides the match.
type baselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	File        string `json:"file,omitempty"`
	// Count is how many findings share the fingerprint, when more than one:
	// the same entry written twice in one list.
	Count int `json:"count,omitempty"`
}

const baselineVersion = 1

// defaultBaselineFile is where `cfgaudit baseline` writes without -o.
const defaultBaselineFile = ".cfgaudit-baseline.json"

// neverBaselined are the rules that report a secret written into a file.
// A baseline is for adopting cfgaudit, and a committed secret is not a
// finding to accept: it is leaked whether or not CI fails, so it stays
// reported and out of the file.
var neverBaselined = map[string]bool{
	"CFG007": true, // hardcoded secret in env
	"CFG050": true, // hardcoded secret in an MCP server, header or command
	"CFG054": true, // high-entropy value
	"CFG065": true, // Continue inline apiKey
	"CFG073": true, // cryptocurrency signing credential
}

// fingerprintLineRe matches the line numbers some rules put into their
// message ("CLAUDE.md line 12 contains ..."), which change when a line is
// added above the finding.
var fingerprintLineRe = regexp.MustCompile(`\blines? \d+(?:\s*[-–]\s*\d+)?\b`)

// baselineFingerprint identifies a finding across unrelated edits: the rule,
// the file relative to the scanned directory (or to the home directory for a
// user-scope file), the key it reports and its message without line numbers.
// Unlike the Code Climate fingerprint it leaves out the line, so a line added
// above a finding does not make it new.
func baselineFingerprint(dir string, f finding.Finding) string {
	h := sha256.New()
	for _, part := range []string{f.RuleID, baselinePath(dir, f.File), f.Key, fingerprintLineRe.ReplaceAllString(f.Message, "line N")} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// baselinePath is file as the baseline records it: relative to dir, or
// ~/-relative for a file in the home directory, with forward slashes.
func baselinePath(dir, file string) string {
	if file == "" {
		return ""
	}
	abs := absPath(file)
	if rel, err := filepath.Rel(absPath(dir), abs); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, abs); err == nil && !strings.HasPrefix(rel, "..") {
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(abs)
}

// buildBaseline returns the baseline for findings, sorted by file and rule,
// and how many secret findings it left out.
func buildBaseline(dir string, findings []finding.Finding) (baselineFile, int) {
	byFP := map[string]*baselineEntry{}
	secrets := 0
	for _, f := range findings {
		if neverBaselined[f.RuleID] {
			secrets++
			continue
		}
		fp := baselineFingerprint(dir, f)
		if e, ok := byFP[fp]; ok {
			e.Count++
			continue
		}
		byFP[fp] = &baselineEntry{Fingerprint: fp, Rule: f.RuleID, File: baselinePath(dir, f.File), Count: 1}
	}
	b := baselineFile{Version: baselineVersion, Findings: []baselineEntry{}}
	for _, e := range byFP {
		if e.Count == 1 {
			e.Count = 0
		}
		b.Findings = append(b.Findings, *e)
	}
	sort.Slice(b.Findings, func(i, j int) bool {
		x, y := b.Findings[i], b.Findings[j]
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Rule != y.Rule {
			return x.Rule < y.Rule
		}
		return x.Fingerprint < y.Fingerprint
	})
	return b, secrets
}

// writeBaseline writes the baseline for findings to path.
func writeBaseline(path, dir string, findings []finding.Finding) (written, secrets int, err error) {
	b, secrets := buildBaseline(dir, findings)
	data, _ := json.MarshalIndent(b, "", "  ")                            // strings and ints only
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil { // #nosec G306,G703 -- the user names the file; it is committed with the repository
		return 0, 0, err
	}
	for _, e := range b.Findings {
		written += max(e.Count, 1)
	}
	return written, secrets, nil
}

// loadBaseline reads a baseline file written by writeBaseline.
func loadBaseline(path string) (*baselineFile, error) {
	data, err := os.ReadFile(path) // #nosec G304,G703 -- the user names the baseline file
	if err != nil {
		return nil, err
	}
	var b baselineFile
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if b.Version != baselineVersion {
		return nil, fmt.Errorf("%s: unsupported baseline version %d (want %d)", path, b.Version, baselineVersion)
	}
	return &b, nil
}

// applyBaseline drops the findings b lists, each fingerprint as many times
// as it was recorded, and returns the rest, how many it dropped and the
// entries that matched nothing. Secret findings are never dropped.
func applyBaseline(b *baselineFile, dir string, findings []finding.Finding) (kept []finding.Finding, suppressed int, stale []baselineEntry) {
	left := map[string]int{}
	for _, e := range b.Findings {
		if !neverBaselined[e.Rule] {
			left[e.Fingerprint] += max(e.Count, 1)
		}
	}
	matched := map[string]bool{}
	for _, f := range findings {
		fp := baselineFingerprint(dir, f)
		if !neverBaselined[f.RuleID] && left[fp] > 0 {
			left[fp]--
			matched[fp] = true
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	for _, e := range b.Findings {
		if !matched[e.Fingerprint] && !neverBaselined[e.Rule] {
			stale = append(stale, e)
		}
	}
	return kept, suppressed, stale
}

// baselineArgs turns `cfgaudit baseline [-o file] [scan flags] [dir]` into the
// scan command line that writes the baseline.
func baselineArgs(args []string) []string {
	out := []string{args[0], "--write-baseline", defaultBaselineFile}
	rest := args[2:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case (a == "-o" || a == "--output") && i+1 < len(rest):
			out[2] = rest[i+1]
			i++
		case strings.HasPrefix(a, "-o="), strings.HasPrefix(a, "--output="):
			out[2] = a[strings.IndexByte(a, '=')+1:]
		default:
			out = append(out, a)
		}
	}
	return out
}
