// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// maxImportHops is how far Claude Code follows `@path` imports. Measured with
// 2.1.310: CLAUDE.md -> d1 -> d2 -> d3 -> d4 loaded d4, and d4's own import of
// d5 was not loaded. The memory docs say "a maximum depth of four hops".
const maxImportHops = 4

// importTargets returns one target per file that Claude Code loads through
// `@path` imports from the project's instruction files in targets (#794), so
// the instruction-content rules see imported text too.
//
// The roots are the files Claude Code expands imports in: CLAUDE.md,
// .claude/CLAUDE.md, CLAUDE.local.md, the AGENTS.md pair and .claude/rules.
// A relative import resolves against the importing file. An import that
// resolves outside the scanned directory, including every `~/` import, is not
// read: it is recorded on the importing file's target for CFG116. A file that
// is already a target of its own is not scanned twice.
//
// The walk is breadth first, so a file reachable by several chains is reported
// with the shortest one and its own imports get the most hops left.
func importTargets(dir string, targets []*rules.Target) []*rules.Target {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}
	type item struct {
		owner *rules.Target
		file  string // absolute
		chain []string
		hops  int
	}
	seen := map[string]bool{}
	var queue []item
	for _, t := range targets {
		if t.InstructionFile == "" {
			continue
		}
		abs, err := filepath.Abs(t.InstructionFile)
		if err != nil {
			continue
		}
		seen[abs] = true
		if t.Scope != finding.ScopeProject || !isClaudeImportRoot(root, abs) {
			continue
		}
		queue = append(queue, item{owner: t, file: abs, chain: []string{relSlash(root, abs)}})
	}

	var out []*rules.Target
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if it.hops >= maxImportHops {
			continue
		}
		for _, p := range parser.InstructionImports(it.owner.InstructionContent) {
			path, ok := resolveImport(root, it.file, p)
			if !ok {
				it.owner.ExternalImports = append(it.owner.ExternalImports, p)
				continue
			}
			if seen[path] {
				continue
			}
			data, err := scanroot.ReadFile(path)
			if err != nil || !isTextFile(data) {
				continue
			}
			seen[path] = true
			rel := relSlash(root, path)
			chain := append(append([]string(nil), it.chain...), rel)
			t := &rules.Target{
				Scope:              finding.ScopeProject,
				InstructionFile:    filepath.Join(dir, filepath.FromSlash(rel)),
				InstructionContent: string(data),
				ImportChain:        chain,
			}
			out = append(out, t)
			queue = append(queue, item{owner: t, file: path, chain: chain, hops: it.hops + 1})
		}
	}
	return out
}

// isClaudeImportRoot reports whether abs is one of the project instruction
// files whose imports Claude Code expands. Measured with 2.1.310 for each of
// them; AGENTS.md also per the memory docs ("Inside each AGENTS.md: @path
// imports are expanded").
func isClaudeImportRoot(root, abs string) bool {
	rel := relSlash(root, abs)
	switch rel {
	case "CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".claude/AGENTS.md":
		return true
	}
	return strings.HasPrefix(rel, ".claude/rules/")
}

// resolveImport returns the absolute path an import names and true, or false
// when it lies outside root. Only the text decides: a link inside root that
// leads outside is caught by scanroot when the file is read.
func resolveImport(root, from, p string) (string, bool) {
	if strings.HasPrefix(p, "~/") {
		return "", false
	}
	path := filepath.FromSlash(p)
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(from), path)
	}
	path = filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return path, true
}

// isTextFile reports whether data looks like text. Claude Code skips a
// non-text file it is asked to import.
func isTextFile(data []byte) bool {
	return utf8.Valid(data) && !bytes.Contains(data, []byte{0})
}

func relSlash(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
