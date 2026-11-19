// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
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
// newer ones migrate such entries on startup, so both locations are real.
//
// read_config_from is modelled for exactly one of its keys: kiro. Its keys all
// default to true when absent, so a committed value can only NARROW which other
// tools' files Devin imports; for most keys that changes no finding, because the
// imported files (Claude, Cursor, Windsurf, Copilot, Codex, OpenCode, Zed and
// the AGENTS.md family) are scanned on their own account for the in-scope agent
// that owns them, so a repository with no .devin/ directory can still reach a
// Devin session through files cfgaudit already scans (#474). Kiro is the one
// exception (#1819): cfgaudit does not scan Kiro as an agent, so .kiro/skills is
// read purely because Devin imports it, and `read_config_from.kiro: false`
// removes the only in-scope reader. ReadsKiroSkills reports that one key; the
// rest stay unmodelled, as documented in the README's Devin section. Keys such
// as `sandbox` are deliberately absent: Devin documents them as user-only, so
// reading them from a project file would invent a finding on configuration the
// CLI ignores.
type DevinConfig struct {
	MCPServers  map[string]MCPServer   `json:"mcpServers,omitempty"`
	Hooks       map[string][]HookGroup `json:"hooks,omitempty"`
	Permissions *Permissions           `json:"permissions,omitempty"`
	// RequiredPlugins is the repo level's requiredPlugins (#1603): each entry
	// a source, a string ("owner/repo", a git URL, a local path) or an object
	// ({"source": "github"|"url"|"local", "repo"|"url"|"path": ...}).
	RequiredPlugins []json.RawMessage `json:"requiredPlugins,omitempty"`
	// ReadConfigFrom is the read_config_from block (#1819), kept raw. Only the
	// kiro key is consulted, through ReadsKiroSkills.
	ReadConfigFrom map[string]json.RawMessage `json:"read_config_from,omitempty"`

	// Malformed lists the entries of this file that did not decode while the rest
	// did (#1820). Since Devin v3000.13.4 "a malformed entry in an MCP config file
	// or hooks file no longer hides the other servers and hooks in that file", so
	// a bad mcpServers/hooks/permissions/requiredPlugins entry is recorded here
	// and the file still contributes its valid entries, instead of the whole file
	// being reported unreadable. CFG109 names each one. A file that is not JSON at
	// all still fails to parse and stays a whole-file CFG109.
	Malformed []DevinMalformed `json:"-"`
}

// DevinMalformed is one entry of a Devin config that did not decode: Key is the
// dotted path (e.g. "mcpServers.bad", "hooks.PreToolUse"), Reason the parser's
// own message (#1820).
type DevinMalformed struct{ Key, Reason string }

// ReadsKiroSkills reports whether this project config leaves Devin's import of
// Kiro skills (.kiro/skills/**/SKILL.md) on. It is on by default and off only
// when read_config_from.kiro is the literal false; a missing key, a nil config
// or a non-boolean value all leave it on (#1819).
func (c *DevinConfig) ReadsKiroSkills() bool {
	if c == nil {
		return true
	}
	raw, ok := c.ReadConfigFrom["kiro"]
	if !ok {
		return true
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	return true
}

// decodeDevinHookEvents decodes the event -> matcher groups map of a Devin hooks
// surface (the hooks key of config.json, or a hooks.v1.json), keeping the events
// that decode and recording the ones that do not (#1820). A value that is a JSON
// array but is not a list of matcher groups is a malformed hook event; a value
// of any other shape (a "_generated_by" string, say) is a stray key, not a hook,
// so it is ignored rather than reported.
func decodeDevinHookEvents(raw json.RawMessage) (map[string][]HookGroup, []DevinMalformed) {
	var events map[string]json.RawMessage
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, []DevinMalformed{{Key: "hooks", Reason: devinEntryReason(err)}}
	}
	hooks := map[string][]HookGroup{}
	var malformed []DevinMalformed
	for _, event := range sortedKeys(events) {
		if groups, ok := devinHookGroups(events[event]); ok {
			if len(groups) > 0 {
				hooks[event] = groups
			}
		} else if isJSONArray(events[event]) {
			malformed = append(malformed, DevinMalformed{Key: "hooks." + event, Reason: "not a list of matcher groups"})
		}
	}
	if len(hooks) == 0 {
		hooks = nil
	}
	return hooks, malformed
}

// devinEntryReason is the parser's message for one entry that did not decode,
// used verbatim in the CFG109 finding for that entry.
func devinEntryReason(err error) string {
	return err.Error()
}

// isJSONArray reports whether raw holds a JSON array.
func isJSONArray(raw json.RawMessage) bool {
	b := bytes.TrimSpace(raw)
	return len(b) > 0 && b[0] == '['
}

// ParseDevinConfig reads a .devin/config.json (and the mcp_config / .local
// twins). A missing key yields a zero value. A file that is not a JSON object is
// an error, so a config that is silently not being scanned is reported rather
// than mistaken for an empty one. Within a valid object, each entry is decoded
// on its own (#1820): since Devin v3000.13.4 a malformed mcpServers, hooks,
// permissions or requiredPlugins entry no longer discards the file, so a bad one
// is collected into Malformed (CFG109 names it) and the valid entries are kept.
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
	// The top level has to be a JSON object. A file that is not JSON at all is
	// still wholly unreadable (CFG109 names the file); entry-by-entry resilience
	// below only applies once the object itself decodes (#1820).
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg := &DevinConfig{}
	bad := func(key string, err error) {
		cfg.Malformed = append(cfg.Malformed, DevinMalformed{Key: key, Reason: devinEntryReason(err)})
	}

	// mcpServers, server by server: Devin keeps the valid servers beside a
	// malformed one, so a bad entry is recorded and the rest are kept.
	if raw, ok := top["mcpServers"]; ok {
		var servers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &servers); err != nil {
			bad("mcpServers", err)
		} else {
			kept := map[string]MCPServer{}
			for _, name := range sortedKeys(servers) {
				var srv MCPServer
				if err := json.Unmarshal(servers[name], &srv); err != nil {
					bad("mcpServers."+name, err)
					continue
				}
				if srv.Type == "" && srv.Transport != "" {
					srv.Type = srv.Transport
				}
				kept[name] = srv
			}
			if len(kept) > 0 {
				cfg.MCPServers = kept
			}
		}
	}

	// hooks, event by event, through the shared helper.
	if raw, ok := top["hooks"]; ok {
		hooks, malformed := decodeDevinHookEvents(raw)
		if len(hooks) > 0 {
			cfg.Hooks = hooks
		}
		cfg.Malformed = append(cfg.Malformed, malformed...)
	}

	// permissions and requiredPlugins are single entries: a bad one is recorded
	// without discarding the rest of the file (Devin v3000.5.20: "a single
	// invalid value in config.json no longer discards all user settings").
	if raw, ok := top["permissions"]; ok {
		var p Permissions
		if err := json.Unmarshal(raw, &p); err != nil {
			bad("permissions", err)
		} else {
			cfg.Permissions = &p
		}
	}
	if raw, ok := top["requiredPlugins"]; ok {
		var rp []json.RawMessage
		if err := json.Unmarshal(raw, &rp); err != nil {
			bad("requiredPlugins", err)
		} else {
			cfg.RequiredPlugins = rp
		}
	}
	if raw, ok := top["read_config_from"]; ok {
		var rcf map[string]json.RawMessage
		if json.Unmarshal(raw, &rcf) == nil {
			cfg.ReadConfigFrom = rcf
		}
	}
	return cfg, nil
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
	eventsRaw := data
	if inner, ok := top["hooks"]; ok && isJSONObject(inner) {
		eventsRaw = inner
	}
	// Entry by entry (#1820): a generator's "_generated_by" string or another
	// stray key does not cost the file its hooks, a hook event that does not
	// decode is recorded as malformed, and the valid events are kept.
	hooks, malformed := decodeDevinHookEvents(eventsRaw)
	return &DevinConfig{Hooks: hooks, Malformed: malformed}, nil
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

// DevinPluginSource is one requiredPlugins entry: Kind is "github", "url" or
// "local", Ref the owner/repo, URL or path as written.
type DevinPluginSource struct {
	Kind, Ref string
}

// RequiredPluginSources decodes RequiredPlugins and drops entries of another
// shape. A string is a local path when it starts with "/", "~", "." or a
// drive letter, a URL when it holds "://" or starts with "git@", and
// "owner/repo" otherwise.
func (c *DevinConfig) RequiredPluginSources() []DevinPluginSource {
	if c == nil {
		return nil
	}
	var out []DevinPluginSource
	for _, raw := range c.RequiredPlugins {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			kind := "github"
			switch {
			case strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, ".") || (len(s) > 1 && s[1] == ':'):
				kind = "local"
			case strings.Contains(s, "://") || strings.HasPrefix(s, "git@"):
				kind = "url"
			}
			out = append(out, DevinPluginSource{Kind: kind, Ref: s})
			continue
		}
		var o struct {
			Source, Repo, URL, Path string
		}
		if json.Unmarshal(raw, &o) != nil {
			continue
		}
		// Sources seen: "github" with repo, "url" with url, "git-subdir" with
		// url and the plugin's path in it, "local" with path.
		switch src := strings.ToLower(o.Source); {
		case src == "local" || src == "path":
			out = append(out, DevinPluginSource{Kind: "local", Ref: o.Path})
		case o.URL != "":
			ref := o.URL
			if o.Path != "" {
				ref += "#" + o.Path
			}
			out = append(out, DevinPluginSource{Kind: "url", Ref: ref})
		case o.Repo != "":
			ref := o.Repo
			if o.Path != "" {
				ref += "#" + o.Path
			}
			out = append(out, DevinPluginSource{Kind: "github", Ref: ref})
		}
	}
	return out
}
