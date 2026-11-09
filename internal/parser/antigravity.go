// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// Antigravity CLI (#1057), Gemini CLI's successor, keeps its workspace
// configuration in .agents/. It ships no source, so these shapes come from its
// docs (antigravity.google/docs/{mcp,hooks,plugins}).

// ParseAntigravityMCP reads an Antigravity mcp_config.json: a root mcpServers
// map whose remote URL is serverUrl ("url also works"). The docs show plain
// JSON; comments and trailing commas are tolerated, so a file Antigravity may
// read is not reported as broken.
func ParseAntigravityMCP(path string) (map[string]MCPServer, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var top struct {
		MCPServers map[string]map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(stripJSONC(data), &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := map[string]MCPServer{}
	for name, fields := range top.MCPServers {
		if _, ok := fields["url"]; !ok {
			if u, ok := fields["serverUrl"]; ok {
				fields["url"] = u
			}
		}
		one, _ := json.Marshal(map[string]map[string]map[string]json.RawMessage{"mcpServers": {name: fields}})
		cfg, err := parseMCPConfigBytes(one, path)
		if err != nil {
			continue
		}
		if s, ok := cfg.MCPServers[name]; ok {
			out[name] = s
		}
	}
	return out, nil
}

// antigravityToolEvents take [{matcher, hooks: [...]}]; the other events take
// the handlers directly ("matcher ignored").
var antigravityToolEvents = map[string]bool{"PreToolUse": true, "PostToolUse": true}

// ParseAntigravityHooks reads an Antigravity hooks.json: hook names mapped to
// an optional "enabled" (default true) and event keys. A hook set to
// enabled: false is left out. The result uses the shared event → handlers
// shape, with a tool event's matcher on each of its handlers.
func ParseAntigravityHooks(path string) (*AgentHooks, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(stripJSONC(data), &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	names := make([]string, 0, len(top))
	for name := range top {
		names = append(names, name)
	}
	sort.Strings(names)
	h := &AgentHooks{Hooks: map[string][]AgentHook{}}
	for _, name := range names {
		var hook map[string]json.RawMessage
		if json.Unmarshal(top[name], &hook) != nil || string(hook["enabled"]) == "false" {
			continue
		}
		for event, raw := range hook {
			if event == "enabled" {
				continue
			}
			if antigravityToolEvents[event] {
				var groups []struct {
					Matcher any         `json:"matcher"`
					Hooks   []AgentHook `json:"hooks"`
				}
				if json.Unmarshal(raw, &groups) != nil {
					continue
				}
				for _, g := range groups {
					for _, a := range g.Hooks {
						a.Matcher = g.Matcher
						h.Hooks[event] = append(h.Hooks[event], a)
					}
				}
				continue
			}
			var handlers []AgentHook
			if json.Unmarshal(raw, &handlers) == nil {
				h.Hooks[event] = append(h.Hooks[event], handlers...)
			}
		}
	}
	return h, nil
}
