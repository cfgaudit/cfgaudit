// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// DevinConfig is the subset of Devin CLI's project config that cfgaudit reads.
// It backs all four project files: .devin/config.json ("Project settings
// (committed)"), .devin/config.local.json ("Project local overrides
// (gitignored)"), .devin/mcp_config.json ("Project MCP servers (committed)") and
// .devin/mcp_config.local.json ("Project local MCP servers (gitignored)"). The
// committed pair is described by Devin's own docs as "shared team configuration
// committed to version control", so it is a committable surface; the gitignored
// pair is read because a committed one still applies, and wins.
//
// Only permissions, read_config_from and hooks are honoured in a *project*
// config, and mcpServers is set at both levels but lives in the dedicated
// mcp_config.json files since v3000.3 ("the Local 3.6 release"). The key is
// still decoded here: older versions read servers from the main config, and
// newer ones migrate such entries on startup, so both locations are real. The
// security-relevant keys are modelled and read_config_from is not. read_config_from is deliberately not one of them: its eight keys all
// default to true when absent, so the only thing a committed value can do is
// NARROW which other tools' files are imported. It grants a repository no
// capability it could not get by writing this file directly. What it does affect
// is documented in the README's Devin section, because it means a repository
// with no .devin/ directory can still reach a Devin session through the Claude,
// Cursor, Windsurf, Copilot, VS Code and Zed files cfgaudit already scans (#474). Keys such as `sandbox` are deliberately absent: Devin documents them as
// user-only, so reading them from a project file would invent a finding on
// configuration the CLI ignores.
type DevinConfig struct {
	MCPServers  map[string]MCPServer   `json:"mcpServers,omitempty"`
	Hooks       map[string][]HookGroup `json:"hooks,omitempty"`
	Permissions *Permissions           `json:"permissions,omitempty"`
}

// devinTop mirrors the keys DevinConfig reads, with hooks kept raw so each
// event decodes entry by entry in devinHookGroups. Keep its fields in sync
// with DevinConfig.
type devinTop struct {
	MCPServers  map[string]MCPServer       `json:"mcpServers,omitempty"`
	Hooks       map[string]json.RawMessage `json:"hooks,omitempty"`
	Permissions *Permissions               `json:"permissions,omitempty"`
}

// ParseDevinConfig reads a .devin/config.json. A missing key yields a zero value
// rather than an error; a malformed file is an error, so a config that is
// silently not being scanned is reported rather than mistaken for an empty one.
//
// Devin spells the remote-transport discriminator `transport` where the rest of
// the MCP ecosystem uses `type`, and it is frequently omitted and inferred from
// whether a url or a command is present. It is folded into Type here so the
// shared MCP rules see one field, and nothing downstream has to know the
// difference.
func ParseDevinConfig(path string) (*DevinConfig, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var top devinTop
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	hooks := map[string][]HookGroup{}
	for event, raw := range top.Hooks {
		groups, ok := devinHookGroups(raw)
		if !ok {
			return nil, fmt.Errorf("parse %s: hooks.%s is not a list of matcher groups", path, event)
		}
		if len(groups) > 0 {
			hooks[event] = groups
		}
	}
	for name, srv := range top.MCPServers {
		if srv.Type == "" && srv.Transport != "" {
			srv.Type = srv.Transport
			top.MCPServers[name] = srv
		}
	}
	return &DevinConfig{MCPServers: top.MCPServers, Hooks: hooks, Permissions: top.Permissions}, nil
}

// devinMatcher decodes a Devin hook matcher. Devin loads a matcher as a regex
// string; since the release notes entry "Hook Matchers Written as a List"
// (2026-10-21) it also loads a list of strings, matching any of them (#1393).
// A matcher of any other shape decodes as "".
func devinMatcher(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, ", ")
	}
	return ""
}

// devinHookGroups decodes one event's matcher groups the way Devin loads them:
// a group whose matcher is a list is kept with the list joined, so its hooks
// are still judged instead of the matcher costing the group a parse error or
// the event its groups (#1393). The matcher is the only lenient part: ok is
// false when raw is not a list of matcher groups, when a group is not an
// object, or when a handler entry does not decode, so a hook Devin still
// loads cannot pass unnoticed behind the loose pass.
func devinHookGroups(raw json.RawMessage) (groups []HookGroup, ok bool) {
	if json.Unmarshal(raw, &groups) == nil {
		return groups, true
	}
	var rawGroups []json.RawMessage
	if json.Unmarshal(raw, &rawGroups) != nil {
		return nil, false
	}
	// A failed strict decode can leave partial groups behind, so the loose
	// pass rebuilds the slice from scratch.
	groups = nil
	for _, rg := range rawGroups {
		var loose struct {
			Matcher json.RawMessage   `json:"matcher"`
			Hooks   []json.RawMessage `json:"hooks"`
		}
		if json.Unmarshal(rg, &loose) != nil {
			return nil, false
		}
		hg := HookGroup{Matcher: devinMatcher(loose.Matcher)}
		for _, rh := range loose.Hooks {
			var hc HookCommand
			if json.Unmarshal(rh, &hc) != nil {
				return nil, false
			}
			hg.Hooks = append(hg.Hooks, hc)
		}
		groups = append(groups, hg)
	}
	return groups, true
}

// ParseDevinHooksV1 reads a Devin CLI .devin/hooks.v1.json (#613). Devin's hooks
// reference lists it first among the project locations, as the "Standalone hooks
// file (recommended)", and: "In .devin/hooks.v1.json, the hooks object is the
// entire file (no wrapper key needed)". So the file is the event → matcher
// groups map itself, in the same shape as the hooks key of .devin/config.json,
// and it is returned as a DevinConfig carrying only Hooks.
func ParseDevinHooksV1(path string) (*DevinConfig, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Some real files wrap the table in a "hooks" key anyway, the shape of every
	// other location. Whether Devin reads that here is unverified; it is read, so
	// a wrapped file is judged rather than silently skipped.
	if inner, ok := top["hooks"]; ok {
		var wrapped map[string]json.RawMessage
		if json.Unmarshal(inner, &wrapped) == nil {
			top = wrapped
		}
	}
	// Entry by entry, so a generator's "_generated_by" string or another stray
	// key does not cost the file its hooks; anything that is not a list of
	// matcher groups is left out.
	hooks := map[string][]HookGroup{}
	for event, raw := range top {
		if groups, ok := devinHookGroups(raw); ok && len(groups) > 0 {
			hooks[event] = groups
		}
	}
	return &DevinConfig{Hooks: hooks}, nil
}

// DevinSkillPermissions returns the `permissions` block of a Devin CLI SKILL.md
// frontmatter, or nil when there is none (#644). The block has the same shape as
// .devin/config.json `permissions` (allow / deny / ask lists of strings).
func DevinSkillPermissions(content string) *Permissions {
	fm, ok := InstructionFrontmatter(content)
	if !ok {
		return nil
	}
	raw, ok := fm.Raw["permissions"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var p Permissions
	if json.Unmarshal(b, &p) != nil || (len(p.Allow) == 0 && len(p.Deny) == 0 && len(p.Ask) == 0) {
		return nil
	}
	return &p
}
