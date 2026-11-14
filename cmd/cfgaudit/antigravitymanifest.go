// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// antigravityManifestKinds are Antigravity CLI's discovery manifests in
// .agents/, one per kind of customization (#1639,
// antigravity.google/docs/customization-discovery).
var antigravityManifestKinds = []string{"skills", "plugins", "rules", "agents"}

// antigravityManifestDepth bounds a chain of inherits.
const antigravityManifestDepth = 8

// antigravityManifestResult is what the manifests of one kind add.
type antigravityManifestResult struct {
	// Items are SKILL.md, rule and agent files, or plugin folders.
	Items []string
	// Outside are entries that point outside the repository (CFG144).
	Outside []rules.AntigravityOutsideEntry
	// Broken are manifests that do not parse; Read are the ones that do.
	Broken map[string]error
	Read   []string
}

// antigravityManifest resolves the scanned directory's .agents/<kind>.json
// and the manifests it inherits from. Only the root .agents/ is read, like
// mcp_config.json and hooks.json. A manifest adds to the standard folders, so
// its top-level exclude applies to its own entries only: the standard folders
// are read for other agents too.
func antigravityManifest(dir, kind string) antigravityManifestResult {
	res := antigravityManifestResult{Broken: map[string]error{}}
	seen := map[string]bool{}
	var read func(path, base string, depth int)
	read = func(path, base string, depth int) {
		if seen[path] || depth > antigravityManifestDepth {
			return
		}
		seen[path] = true
		m, err := parser.ParseAntigravityManifest(path)
		if err != nil {
			if !scanroot.IsAbsent(err) {
				res.Broken[path] = err
			}
			return
		}
		res.Read = append(res.Read, path)
		for i, e := range m.Entries {
			abs, reason, ok := antigravityEntryPath(dir, base, e.Path)
			if reason != "" {
				res.Outside = append(res.Outside, rules.AntigravityOutsideEntry{File: path, Field: "entries", Index: i, Path: e.Path, Reason: reason})
			}
			if !ok {
				continue
			}
			exclude := append(slices.Clone(m.Exclude), e.Exclude...)
			for _, it := range antigravityEntryItems(kind, abs, e.IncludeOnly, exclude) {
				if !slices.Contains(res.Items, it) {
					res.Items = append(res.Items, it)
				}
			}
		}
		for i, e := range m.Inherits {
			abs, reason, ok := antigravityEntryPath(dir, base, e.Path)
			if reason != "" {
				res.Outside = append(res.Outside, rules.AntigravityOutsideEntry{File: path, Field: "inherits", Index: i, Path: e.Path, Reason: reason})
			}
			if !ok || !isRegularFile(abs) {
				continue
			}
			// Relative paths start at the folder that holds .agents/.
			next := filepath.Dir(abs)
			if filepath.Base(next) == ".agents" {
				next = filepath.Dir(next)
			}
			read(abs, next, depth+1)
		}
	}
	read(filepath.Join(dir, ".agents", kind+".json"), dir, 0)
	return res
}

// antigravityEntryPath resolves an entry's path against base, the folder that
// holds the manifest's .agents/, and then against the repository root as
// Antigravity does. reason is set when the path leaves the repository; ok when
// it is an existing path inside it.
func antigravityEntryPath(dir, base, p string) (abs, reason string, ok bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", "", false
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) || (len(p) > 1 && p[1] == ':') {
		return "", "an absolute path", false
	}
	for _, b := range []string{base, dir} {
		joined := filepath.Join(b, filepath.FromSlash(p))
		rel, err := filepath.Rel(dir, joined)
		if err != nil || rel == ".." || strings.HasPrefix(filepath.ToSlash(rel), "../") {
			return "", "it leaves the repository through ../", false
		}
		if _, err := os.Lstat(joined); err != nil { // #nosec G703 -- joined stays under dir (checked above) and is only stat'ed
			continue
		}
		if linkLeaves(dir, joined) {
			return "", "a symbolic link that leads out of the repository", false
		}
		return joined, "", true
	}
	return "", "", false
}

// linkLeaves reports whether a path under dir runs through a symbolic link
// whose text leads outside dir. The link text is read, not the machine's file
// system behind it, so a link to a folder that only exists elsewhere counts
// as well. Antigravity CLI 1.5.2 skips such an entry, and scanroot does not
// read through it.
func linkLeaves(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	cur := dir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		target, err := os.Readlink(cur) // #nosec G703 -- cur stays under dir until a link leaves it, which ends the walk
		if err != nil {
			continue // not a link
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		r, err := filepath.Rel(dir, target)
		if err != nil || r == ".." || strings.HasPrefix(filepath.ToSlash(r), "../") {
			return true
		}
		cur = target
	}
	return false
}

// antigravityEntryItems returns what one entry adds: the folder or file of a
// single item, or the items one level below a folder. include_only and
// exclude match an item by name or by its path relative to the entry; an
// include_only path with a "/" also reaches an item deeper than one level.
func antigravityEntryItems(kind, abs string, includeOnly, exclude []string) []string {
	type item struct{ name, rel, path string }
	var items []item
	single := func(path string) bool {
		name := filepath.Base(path)
		switch kind {
		case "skills":
			if p := antigravityItemFile(path, "SKILL.md"); p != "" {
				items = append(items, item{name, name, p})
				return true
			}
		case "rules":
			if isRegularFile(path) && strings.HasSuffix(name, ".md") {
				items = append(items, item{name, name, path})
				return true
			}
		case "agents":
			if isRegularFile(path) && strings.HasSuffix(name, ".md") {
				items = append(items, item{strings.TrimSuffix(name, ".md"), name, path})
				return true
			}
			if p := antigravityItemFile(path, "agent.md"); p != "" {
				items = append(items, item{name, name, p})
				return true
			}
		case "plugins":
			if isAntigravityPlugin(path) {
				items = append(items, item{name, name, path})
				return true
			}
		}
		return false
	}
	if !single(abs) {
		entries, _ := scanroot.ReadDir(abs)
		for _, e := range entries {
			child := filepath.Join(abs, e.Name())
			before := len(items)
			if kind == "plugins" && !e.IsDir() {
				continue
			}
			if single(child) {
				for i := before; i < len(items); i++ {
					items[i].rel = e.Name()
				}
			}
		}
	}
	for _, inc := range includeOnly {
		if !strings.Contains(inc, "/") {
			continue
		}
		before := len(items)
		if single(filepath.Join(abs, filepath.FromSlash(inc))) {
			for i := before; i < len(items); i++ {
				items[i].rel = inc
			}
		}
	}
	matches := func(list []string, it item) bool {
		for _, s := range list {
			s = strings.TrimSuffix(strings.TrimSpace(s), "/")
			if s == it.name || s == it.rel || s == strings.TrimSuffix(it.name, ".md") || s == strings.TrimSuffix(it.rel, ".md") {
				return true
			}
		}
		return false
	}
	var out []string
	for _, it := range items {
		if len(includeOnly) > 0 && !matches(includeOnly, it) {
			continue
		}
		if matches(exclude, it) || slices.Contains(out, it.path) {
			continue
		}
		out = append(out, it.path)
	}
	return out
}

// antigravityItemFile returns dir/name when dir is a folder holding that file.
func antigravityItemFile(dir, name string) string {
	p := filepath.Join(dir, name)
	if isRegularFile(p) {
		return p
	}
	return ""
}

// isAntigravityPlugin reports whether dir is a plugin folder rather than a
// folder of plugins: it holds a manifest, an MCP or hooks file, or one of the
// component folders a plugin bundles (docs/plugins).
func isAntigravityPlugin(dir string) bool {
	for _, f := range []string{"plugin.json", "mcp_config.json", "hooks.json", filepath.Join(".antigravity-plugin", "plugin.json"), filepath.Join(".gemini-plugin", "plugin.json")} {
		if isRegularFile(filepath.Join(dir, f)) {
			return true
		}
	}
	for _, d := range []string{"skills", "agents", "rules"} {
		if dirExists(filepath.Join(dir, d)) {
			return true
		}
	}
	return false
}
