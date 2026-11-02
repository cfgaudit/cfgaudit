// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// textEntry is one block of the text output: a finding and the paths of the
// byte-identical files that got the same finding.
type textEntry struct {
	finding.Finding
	copies []string
}

// maxListedCopies caps the paths named after a grouped finding.
const maxListedCopies = 3

// groupIdenticalCopies folds the findings of byte-identical files into the
// first one, for the text output only (#1346). Repositories keep the same
// skill at .claude/skills/x and .agents/skills/x, or a plugin source beside its
// installed copy, and every rule reports each copy: 203 of 2,137 CFG051
// findings in the pre-release corpus run for v1.20.0 were such copies. Two
// findings fold when their files have the same content and the findings have
// the same rule, severity, position and message once the file's own path is
// taken out. A file that cannot be read, such as a member of a scanned
// archive, is never folded. JSON, SARIF and baselines keep one finding per
// file.
func groupIdenticalCopies(dir string, all []finding.Finding) []textEntry {
	hashes := map[string]string{}
	hashOf := func(file string) string {
		if h, ok := hashes[file]; ok {
			return h
		}
		h := ""
		path := file
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		if data, err := scanroot.ReadFile(path); err == nil && len(data) > 0 {
			sum := sha256.Sum256(data)
			h = string(sum[:])
		}
		hashes[file] = h
		return h
	}

	var out []textEntry
	first := map[string]int{} // group key -> index in out
	for _, f := range all {
		h := ""
		if f.File != "" {
			h = hashOf(f.File)
		}
		if h == "" {
			out = append(out, textEntry{Finding: f})
			continue
		}
		key := h + "\x00" + f.RuleID + "\x00" + f.Severity.String() + "\x00" + strconv.Itoa(f.Line) + ":" + strconv.Itoa(f.Col) + "\x00" + pathlessMessage(dir, f)
		if i, ok := first[key]; ok && out[i].File != f.File {
			out[i].copies = append(out[i].copies, f.File)
			continue
		}
		first[key] = len(out)
		out = append(out, textEntry{Finding: f})
	}
	return out
}

// pathlessMessage is the finding's message with its own file's path, in the
// forms a message names it, replaced, so the findings of two copies compare
// equal.
func pathlessMessage(dir string, f finding.Finding) string {
	msg := f.Message
	paths := []string{f.File, filepath.ToSlash(f.File)}
	if rel, err := filepath.Rel(dir, f.File); err == nil && !strings.HasPrefix(rel, "..") {
		paths = append(paths, rel, filepath.ToSlash(rel))
	}
	for _, p := range paths {
		if p != "" && p != "." {
			msg = strings.ReplaceAll(msg, p, "\x00")
		}
	}
	return msg
}

// copiesLine names the copies folded into a finding, capped.
func copiesLine(copies []string) string {
	shown := copies
	if len(shown) > maxListedCopies {
		shown = shown[:maxListedCopies]
	}
	noun := "identical copies"
	if len(copies) == 1 {
		noun = "identical copy"
	}
	line := "  also in " + strconv.Itoa(len(copies)) + " " + noun + ": " + strings.Join(shown, ", ")
	if n := len(copies) - len(shown); n > 0 {
		line += " and " + strconv.Itoa(n) + " more"
	}
	return line
}

// findingsSummary counts every finding, folded copies included, and says how
// many of them the output folded: "3 findings, 1 of them in identical
// copies".
func findingsSummary(entries []textEntry) string {
	total, folded := 0, 0
	for _, e := range entries {
		total += 1 + len(e.copies)
		folded += len(e.copies)
	}
	s := strconv.Itoa(total) + " " + pluralize("finding", total)
	if folded > 0 {
		s += ", " + strconv.Itoa(folded) + " of them in identical copies"
	}
	return s
}
