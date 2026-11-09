// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// inventory is what `cfgaudit inventory` reports (#1000): per agent, the
// files the scan discovered and read, and the entries in them that run,
// load or approve something; then the files that could not be read. It uses
// the scan's discovery and reports no findings.
type inventory struct {
	Agents     []inventoryAgent  `json:"agents"`
	Unreadable []inventoryFailed `json:"unreadable"`
}

type inventoryAgent struct {
	Agent string          `json:"agent"`
	Files []inventoryFile `json:"files"`
}

type inventoryFile struct {
	Path    string          `json:"path"`
	SHA256  string          `json:"sha256,omitempty"`
	MCP     []rules.MCPItem `json:"mcp_servers,omitempty"`
	Entries []lockEntry     `json:"entries,omitempty"`
}

type inventoryFailed struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// pathAgents maps a path prefix, relative to the scanned directory, to the
// agent that reads it, longest prefix first. A file no prefix names is
// listed under "shared" (AGENTS.md, skills roots several agents read).
var pathAgents = []struct{ prefix, agent string }{
	{".github/copilot-instructions.md", "copilot"}, {".github/instructions/", "copilot"}, {".github/agents/", "copilot"},
	{".github/hooks/", "copilot"}, {".github/mcp.json", "copilot"}, {".github/prompts/", "copilot"}, {".github/extensions/", "copilot"},
	{".github/skills/", "copilot"}, {".github/lsp.json", "copilot"}, {".claude/", "claude-code"}, {".claude-plugin/", "claude-code"}, {"CLAUDE.md", "claude-code"},
	{"CLAUDE.local.md", "claude-code"}, {".mcp.json", "claude-code"}, {".cursor/", "cursor"}, {".cursorrules", "cursor"},
	{".vscode/", "vscode"}, {".gemini/", "gemini-cli"}, {"GEMINI.md", "gemini-cli"}, {".codex/", "codex"}, {".qwen/", "qwen-code"},
	{"QWEN.md", "qwen-code"}, {".roo/", "roo-code"}, {".roorules", "roo-code"}, {".roomodes", "roo-code"}, {".continue/", "continue"},
	{".continuerules", "continue"}, {".devin/", "devin"}, {".windsurf/", "devin-desktop"}, {".windsurfrules", "devin-desktop"},
	{".zed/", "zed"}, {".rules", "zed"}, {".opencode/", "opencode"}, {"opencode.json", "opencode"}, {"opencode.jsonc", "opencode"},
	{".kimi-code/", "kimi-code"}, {".kimi/", "kimi-cli"}, {".grok/", "grok"}, {".cline/", "cline"}, {".clinerules", "cline"}, {"cline_mcp_settings.json", "cline"},
	{"AGENT.md", "amp"}, {".gitmodules", "git"}, {".pi/", "pi"}, {"AGENTS.override.md", "pi"},
	{".goose/", "goose"}, {".junie/", "junie"}, {".goosehints", "goose"}, {".agents/recipes/", "goose"}, {".agents/plugins/", "goose"},
	{".agents/mcp_config.json", "antigravity"}, {".agents/hooks.json", "antigravity"}, {".agents/AGENTS.md", "antigravity"},
	{".agents/GEMINI.md", "antigravity"}, {".agents/rules/", "antigravity"}, {".agent/", "antigravity"},
	// Only read with --user, from the home directory.
	{".codeium/windsurf/", "devin-desktop"}, {".config/Claude/", "claude-desktop"},
	{"Library/Application Support/Claude/", "claude-desktop"}, {"AppData/Roaming/Claude/", "claude-desktop"},
}

// agentOfPath returns the agent that reads rel. A file in the home directory
// is named from there, as ~/.claude/settings.json.
func agentOfPath(rel string) string {
	rel = strings.TrimPrefix(rel, "~/")
	if strings.HasSuffix(rel, ".code-workspace") {
		return "vscode"
	}
	best, agent := 0, "shared"
	for _, p := range pathAgents {
		if (rel == p.prefix || (strings.HasSuffix(p.prefix, "/") && strings.HasPrefix(rel, p.prefix))) && len(p.prefix) > best {
			best, agent = len(p.prefix), p.agent
		}
	}
	// A CLAUDE.md in a subfolder is Claude Code's nested file, and a nested
	// rule folder belongs to the agent of the same folder at the root (#975).
	// An Antigravity workspace plugin shares .agents/plugins/ with goose's
	// plugins; its MCP and hook files are Antigravity's (#1057).
	if strings.HasPrefix(rel, ".agents/plugins/") && strings.Count(rel, "/") == 3 {
		switch path.Base(rel) {
		case "mcp_config.json", "hooks.json":
			return "antigravity"
		}
	}
	if best == 0 && path.Base(rel) == "CLAUDE.md" {
		return "claude-code"
	}
	if best == 0 {
		for _, rd := range nestedRuleDirs {
			if i := strings.Index(rel, "/"+rd.dir+"/"); i > 0 {
				return agentOfPath(rel[i+1:])
			}
		}
	}
	return agent
}

// buildInventory collects the inventory of targets.
func buildInventory(dir string, targets []*rules.Target, failed []unreadableFile) inventory {
	files := map[string]*inventoryFile{}
	// file returns the entry for p, or nil when p is not a file the scan
	// could read: a target names some paths whether or not they exist.
	file := func(p string) *inventoryFile {
		rel := baselinePath(dir, p)
		if f, ok := files[rel]; ok {
			return f
		}
		data, err := scanroot.ReadFile(p)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(data)
		f := &inventoryFile{Path: rel, SHA256: hex.EncodeToString(sum[:])}
		files[rel] = f
		return f
	}
	seenEntry := map[lockEntry]bool{}
	seenMCP := map[string]bool{}
	for _, t := range targets {
		if t.ContentPath {
			continue
		}
		for _, p := range targetFiles(t) {
			file(p)
		}
		for _, e := range rules.TrustEntries(t) {
			if e.Kind == "mcp" || e.Kind == "instructions" || (e.Kind == "command" && strings.HasPrefix(e.Name, "mcpServers.")) {
				continue // listed as MCP servers, or as the file itself
			}
			f := file(e.File)
			if f == nil {
				continue
			}
			e.File = f.Path
			if le := lockEntry(e); !seenEntry[le] {
				seenEntry[le] = true
				f.Entries = append(f.Entries, le)
			}
		}
		for _, m := range rules.MCPInventory(t) {
			f := file(m.File)
			if f == nil {
				continue
			}
			m.File = f.Path
			if k := f.Path + "\x00" + m.Name; !seenMCP[k] {
				seenMCP[k] = true
				f.MCP = append(f.MCP, m)
			}
		}
	}
	byAgent := map[string][]inventoryFile{}
	for _, f := range files {
		a := agentOfPath(f.Path)
		byAgent[a] = append(byAgent[a], *f)
	}
	inv := inventory{Agents: []inventoryAgent{}, Unreadable: []inventoryFailed{}}
	for a, fs := range byAgent {
		sort.Slice(fs, func(i, j int) bool { return fs[i].Path < fs[j].Path })
		inv.Agents = append(inv.Agents, inventoryAgent{Agent: a, Files: fs})
	}
	sort.Slice(inv.Agents, func(i, j int) bool { return inv.Agents[i].Agent < inv.Agents[j].Agent })
	for _, u := range failed {
		inv.Unreadable = append(inv.Unreadable, inventoryFailed{Path: baselinePath(dir, u.path), Reason: u.reason})
	}
	for _, p := range scanroot.ReadErrors() {
		inv.Unreadable = append(inv.Unreadable, inventoryFailed{Path: baselinePath(dir, p), Reason: "exists but could not be read"})
	}
	sort.Slice(inv.Unreadable, func(i, j int) bool { return inv.Unreadable[i].Path < inv.Unreadable[j].Path })
	return inv
}

// inventoryOutput runs `cfgaudit inventory [--format text|json|cyclonedx]
// [--plugins dir] [--user] [dir]`.
func inventoryOutput(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fset.SetOutput(stderr)
	format := fset.String("format", "text", "output format: text, json or cyclonedx (CycloneDX 1.6 JSON)")
	plugins := fset.String("plugins", "", "also list a Claude Code plugin/skill package directory")
	user := fset.Bool("user", false, "also list the user-global configuration")
	positional, err := parseInterleaved(fset, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(positional) > 1 {
		_, _ = fmt.Fprintln(stderr, "cfgaudit inventory: at most one directory")
		return 2
	}
	switch *format {
	case "text", "json", "cyclonedx":
	default:
		_, _ = fmt.Fprintf(stderr, "cfgaudit inventory: unknown format %q (text, json, cyclonedx)\n", *format)
		return 2
	}
	dir := "."
	if len(positional) == 1 {
		dir = positional[0]
	}
	if err := scanroot.Set(dir); err != nil {
		_, _ = fmt.Fprintf(stderr, "cfgaudit inventory: %v\n", err)
		return 2
	}
	defer func() { _ = scanroot.Set("") }()
	unreadable = nil
	targets, err := buildTargets(dir, *user)
	if err == nil {
		targets, err = withPackageTargets(dir, *plugins, *user, targets)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cfgaudit inventory: %v\n", err)
		return 2
	}
	inv := buildInventory(dir, targets, unreadable)
	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(inv)
	case "cyclonedx":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(cycloneDX(inv))
	default:
		writeInventoryText(stdout, inv)
	}
	return 0
}

// writeInventoryText prints the inventory grouped by agent.
func writeInventoryText(w io.Writer, inv inventory) {
	if len(inv.Agents) == 0 {
		_, _ = fmt.Fprintln(w, "no agent configuration found")
	}
	for _, a := range inv.Agents {
		name := knownAgents[a.Agent]
		if name == "" {
			name = a.Agent
		}
		_, _ = fmt.Fprintf(w, "%s\n", name)
		for _, f := range a.Files {
			_, _ = fmt.Fprintf(w, "  %s\n", f.Path)
			for _, m := range f.MCP {
				line := "MCP server " + m.Name + " (" + m.Transport + "): " + m.Command + m.URL
				if m.Pinned != "" {
					line += ", pinned: " + m.Pinned
				}
				_, _ = fmt.Fprintf(w, "    %s\n", line)
			}
			for _, e := range f.Entries {
				v := e.Value
				if e.Kind == "script" && len(v) > 12 {
					v = "sha256 " + v[:12]
				}
				_, _ = fmt.Fprintf(w, "    %s %s: %s\n", e.Kind, e.Name, v)
			}
		}
	}
	if len(inv.Unreadable) > 0 {
		_, _ = fmt.Fprintln(w, "Not read")
		for _, u := range inv.Unreadable {
			_, _ = fmt.Fprintf(w, "  %s: %s\n", u.Path, u.Reason)
		}
	}
}

// cdxBOM is the subset of CycloneDX 1.6 the inventory fills.
type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Tools cdxTools `json:"tools"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type       string         `json:"type"`
	BOMRef     string         `json:"bom-ref,omitempty"`
	Name       string         `json:"name"`
	Version    string         `json:"version,omitempty"`
	Hashes     []cdxHash      `json:"hashes,omitempty"`
	Properties []cdxProperty  `json:"properties,omitempty"`
	Components []cdxComponent `json:"components,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// cycloneDX maps the inventory to a CycloneDX 1.6 BOM: each agent file is a
// "file" component with its SHA-256, its MCP servers are nested
// "application" components, and its other entries are properties. The
// serial number is derived from the content, so the same inventory gives
// the same BOM.
func cycloneDX(inv inventory) cdxBOM {
	var comps []cdxComponent
	for _, a := range inv.Agents {
		for _, f := range a.Files {
			c := cdxComponent{Type: "file", BOMRef: "file:" + f.Path, Name: f.Path,
				Properties: []cdxProperty{{Name: "cfgaudit:agent", Value: a.Agent}}}
			if f.SHA256 != "" {
				c.Hashes = []cdxHash{{Alg: "SHA-256", Content: f.SHA256}}
			}
			for _, e := range f.Entries {
				c.Properties = append(c.Properties, cdxProperty{Name: "cfgaudit:" + e.Kind + ":" + e.Name, Value: e.Value})
			}
			for _, m := range f.MCP {
				mc := cdxComponent{Type: "application", BOMRef: "mcp:" + f.Path + "#" + m.Name, Name: m.Name,
					Properties: []cdxProperty{{Name: "cfgaudit:mcp:transport", Value: m.Transport}}}
				if m.Command != "" {
					mc.Properties = append(mc.Properties, cdxProperty{Name: "cfgaudit:mcp:command", Value: m.Command})
				}
				if m.URL != "" {
					mc.Properties = append(mc.Properties, cdxProperty{Name: "cfgaudit:mcp:url", Value: m.URL})
				}
				if m.Pinned != "" {
					mc.Properties = append(mc.Properties, cdxProperty{Name: "cfgaudit:mcp:pinned", Value: m.Pinned})
				}
				c.Components = append(c.Components, mc)
			}
			comps = append(comps, c)
		}
	}
	if comps == nil {
		comps = []cdxComponent{}
	}
	data, _ := json.Marshal(comps)
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:16])
	serial := "urn:uuid:" + h[0:8] + "-" + h[8:12] + "-5" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
	return cdxBOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", SerialNumber: serial, Version: 1,
		Metadata:   cdxMetadata{Tools: cdxTools{Components: []cdxComponent{{Type: "application", Name: "cfgaudit", Version: cfgauditVersion}}}},
		Components: comps,
	}
}
