// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// locateTextLines gives findings in Markdown frontmatter, TOML and YAML files
// a line (#977), as locateKeyLines does for JSON (#927): without one, SARIF
// has no region and GitHub shows the finding only in the Security tab. The
// line comes from the key the message names, found with a line scanner:
//
//   - frontmatter: "<file> frontmatter allowed-tools ..." or "frontmatter
//     sets permissionMode: ..." names a field of the leading --- block;
//   - TOML: "mcpServers.<name> ..." is the [mcp_servers.<name>] table (and a
//     key in it when the message names one), "Codex [table] sets key" and
//     "Codex key is" name a table and a key;
//   - otherwise the first quoted value of the message, where the file has it.
//
// A finding whose key cannot be found keeps line 0.
func locateTextLines(all []finding.Finding) {
	files := map[string][]string{}
	for i := range all {
		f := &all[i]
		kind := textKind(f.File)
		if f.Line > 0 || kind == "" {
			continue
		}
		lines, ok := files[f.File]
		if !ok {
			if data, err := os.ReadFile(f.File); err == nil { //nolint:gosec // a file the scan already read
				lines = strings.Split(string(data), "\n")
			}
			files[f.File] = lines
		}
		if len(lines) == 0 {
			continue
		}
		line := 0
		switch kind {
		case "md":
			line = frontmatterFieldLine(lines, f.Message)
		case "toml":
			line = tomlMessageLine(lines, f.Message)
		}
		if line == 0 {
			line = quotedValueLine(lines, f.Message)
		}
		if line > 0 {
			f.Line, f.Col = line, 1
		}
	}
}

// textKind returns "md", "toml" or "yaml" for the files locateTextLines
// handles, and "" for others.
func textKind(path string) string {
	switch l := strings.ToLower(path); {
	case strings.HasSuffix(l, ".md"), strings.HasSuffix(l, ".mdc"):
		return "md"
	case strings.HasSuffix(l, ".toml"):
		return "toml"
	case strings.HasSuffix(l, ".yaml"), strings.HasSuffix(l, ".yml"):
		return "yaml"
	}
	return ""
}

// frontmatterFieldRe finds the field a frontmatter finding names.
var frontmatterFieldRe = regexp.MustCompile(`\bfrontmatter (?:sets )?([A-Za-z][\w-]*)`)

// frontmatterFieldLine returns the 1-based line of the field the message
// names inside the leading --- block, accepting the camelCase spelling of a
// dashed name (allowed-tools, allowedTools).
func frontmatterFieldLine(lines []string, msg string) int {
	m := frontmatterFieldRe.FindStringSubmatch(msg)
	if m == nil || len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return 0
	}
	names := map[string]bool{strings.ToLower(m[1]): true, strings.ToLower(strings.ReplaceAll(m[1], "-", "")): true}
	for i := 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "---" {
			return 0
		}
		k, _, ok := strings.Cut(t, ":")
		k = strings.ToLower(strings.TrimSpace(k))
		top := !strings.HasPrefix(lines[i], " ") && !strings.HasPrefix(lines[i], "\t")
		if ok && top && (names[k] || names[strings.ReplaceAll(k, "-", "")]) {
			return i + 1
		}
	}
	return 0
}

var (
	tomlMCPRe   = regexp.MustCompile(`^mcpServers\.(\S+?)(?:\.([\w.]+))?[: ]`)
	tomlTableRe = regexp.MustCompile(`^Codex \[([\w.-]+)\] sets ([\w-]+)`)
	tomlKeyRe   = regexp.MustCompile(`^(?:Codex )?([a-z][\w-]*(?:\.[a-z][\w-]*)*) (?:is|sets|inserts|enables|grants|points|runs)\b`)
)

// tomlMessageLine returns the line of the table and key a TOML finding's
// message names.
func tomlMessageLine(lines []string, msg string) int {
	if m := tomlMCPRe.FindStringSubmatch(msg); m != nil {
		var key string
		if m[2] != "" {
			// headers.Authorization: the key of the [mcp_servers.x.headers]
			// sub-table, or the inline headers key of the server table.
			segs := strings.Split(m[2], ".")
			if len(segs) > 1 {
				if l := tomlLine(lines, append([]string{"mcp_servers", m[1]}, segs[:len(segs)-1]...), segs[len(segs)-1]); l > 0 {
					return l
				}
			}
			key = segs[0]
		}
		h := tomlLine(lines, []string{"mcp_servers", m[1]}, key)
		// Without a key in the message, the quoted value it reports (the
		// URL, the command) is on a line of the table.
		if key == "" && h > 0 {
			if q := firstQuotedRe.FindStringSubmatch(msg); q != nil {
				for i := h; i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "["); i++ {
					if strings.Contains(lines[i], q[1]) {
						return i + 1
					}
				}
			}
		}
		return h
	}
	if m := tomlTableRe.FindStringSubmatch(msg); m != nil {
		return tomlLine(lines, strings.Split(m[1], "."), m[2])
	}
	if m := tomlKeyRe.FindStringSubmatch(msg); m != nil {
		segs := strings.Split(m[1], ".")
		return tomlLine(lines, segs[:len(segs)-1], segs[len(segs)-1])
	}
	return 0
}

// tomlLine returns the line of key inside the table [table...], the table
// header when key is empty or not in it, or the key at the top level for an
// empty table path. Quoted table segments ([mcp_servers."a.b"]) match.
func tomlLine(lines []string, table []string, key string) int {
	want := strings.Join(table, ".")
	inTable, header := len(table) == 0, 0
	for i, raw := range lines {
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "[") {
			name := strings.TrimLeft(t, "[")
			if end := strings.Index(name, "]"); end >= 0 {
				name = name[:end]
			}
			name = strings.ReplaceAll(strings.ReplaceAll(name, `"`, ""), " ", "")
			if inTable && len(table) == 0 {
				return 0 // a top-level key comes before the first table
			}
			inTable = name == want
			if inTable {
				header = i + 1
				if key == "" {
					return header
				}
			} else if header > 0 {
				return header
			}
			continue
		}
		if inTable && key != "" {
			if k, _, ok := strings.Cut(t, "="); ok && strings.Trim(strings.TrimSpace(k), `"`) == key {
				return i + 1
			}
		}
	}
	return header
}

var firstQuotedRe = regexp.MustCompile(`"([^"]{3,})"`)

// quotedValueLine returns the first line holding the first quoted value of
// the message, or 0.
func quotedValueLine(lines []string, msg string) int {
	m := firstQuotedRe.FindStringSubmatch(msg)
	if m == nil {
		return 0
	}
	for i, l := range lines {
		if strings.Contains(l, m[1]) {
			return i + 1
		}
	}
	return 0
}
