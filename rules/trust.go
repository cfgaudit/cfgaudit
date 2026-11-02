// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

// TrustEntry is one thing in a target that decides what an agent runs, loads
// or may do without asking (#999): a command that runs on its own, an MCP
// server, a script such a command starts, an instruction file, an approval
// setting. `cfgaudit lock` records the entries, so a change that matches no
// rule still shows up as a difference in review.
type TrustEntry struct {
	// Kind is "command", "mcp", "script", "instructions" or "setting".
	Kind string `json:"kind"`
	// File is the file the entry is in, as the target names it.
	File string `json:"file"`
	// Name identifies the entry within its file: the command site's label,
	// the server name, the setting's key.
	Name string `json:"name"`
	// Value is what the entry runs or sets; for a script, the SHA-256 of its
	// content, and for an instruction file nothing: its prose may change
	// without a trust change, its appearance may not.
	Value string `json:"value,omitempty"`
}

// claudeTrustKeys are the Claude Code settings that decide what runs or is
// approved without a prompt.
var claudeTrustKeys = []string{"enableAllProjectMcpServers", "enabledMcpjsonServers", "enabledPlugins", "extraKnownMarketplaces", "apiKeyHelper", "awsCredentialExport", "awsAuthRefresh", "gcpAuthRefresh", "otelHeadersHelper", "disableAllHooks"}

// TrustEntries returns the trust-relevant entries of t, sorted.
func TrustEntries(t *Target) []TrustEntry {
	if t == nil {
		return nil
	}
	var out []TrustEntry
	for _, lc := range LaunchCommands(t) {
		out = append(out, TrustEntry{Kind: "command", File: lc.File, Name: lc.Label, Value: lc.Command})
	}
	for _, ref := range t.mcpServerRefs() {
		v := strings.TrimSpace(ref.Server.Command + " " + strings.Join(ref.Server.Args, " "))
		if ref.Server.URL != "" {
			v = strings.TrimSpace(v + " " + ref.Server.URL)
		}
		out = append(out, TrustEntry{Kind: "mcp", File: ref.File, Name: ref.Name, Value: v})
	}
	for _, s := range t.LaunchedScripts {
		sum := sha256.Sum256([]byte(s.Content))
		// The label is "script x.sh, started by the hooks.SessionStart
		// command,"; the file is the entry's File, so Name keeps what starts it.
		name := strings.TrimSuffix(s.Label, ",")
		if i := strings.Index(name, ", "); i >= 0 {
			name = name[i+2:]
		}
		out = append(out, TrustEntry{Kind: "script", File: s.File, Name: name, Value: hex.EncodeToString(sum[:])})
	}
	if t.InstructionFile != "" && !t.ContentPath {
		out = append(out, TrustEntry{Kind: "instructions", File: t.InstructionFile, Name: "instructions"})
	}
	if s := t.Settings; s != nil {
		if p := s.Permissions; p != nil {
			for _, a := range p.Allow {
				out = append(out, TrustEntry{Kind: "setting", File: t.SettingsFile, Name: "permissions.allow", Value: a})
			}
			for _, d := range p.AdditionalDirectories {
				out = append(out, TrustEntry{Kind: "setting", File: t.SettingsFile, Name: "permissions.additionalDirectories", Value: d})
			}
			if p.DefaultMode != "" {
				out = append(out, TrustEntry{Kind: "setting", File: t.SettingsFile, Name: "permissions.defaultMode", Value: p.DefaultMode})
			}
		}
		for _, k := range claudeTrustKeys {
			if raw, ok := s.Raw[k]; ok {
				out = append(out, TrustEntry{Kind: "setting", File: t.SettingsFile, Name: k, Value: compactJSON(raw)})
			}
		}
	}
	if v := t.VSCodeSettings; v != nil {
		for k, raw := range v.Raw {
			if strings.Contains(k, "autoApprove") || strings.HasPrefix(k, "chat.permissions") || strings.HasPrefix(k, "chat.useClaudeHooks") || k == "chat" {
				out = append(out, TrustEntry{Kind: "setting", File: t.VSCodeSettingsFile, Name: k, Value: compactJSON(raw)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Value < b.Value
	})
	return out
}

// compactJSON is raw without insignificant whitespace, so reformatting a
// file does not change the entry.
func compactJSON(raw json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return string(raw)
	}
	return b.String()
}

// MCPItem is one MCP server for `cfgaudit inventory` (#1000).
type MCPItem struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	Transport string `json:"transport"`
	Command   string `json:"command,omitempty"`
	URL       string `json:"url,omitempty"`
	// Pinned is "yes" or "no" for a server a package runner starts, as CFG010
	// judges it, and "" for any other server.
	Pinned string `json:"pinned,omitempty"`
}

// MCPInventory returns the MCP servers of t, sorted by file and name.
func MCPInventory(t *Target) []MCPItem {
	if t == nil {
		return nil
	}
	var out []MCPItem
	for _, ref := range t.mcpServerRefs() {
		s := ref.Server
		it := MCPItem{Name: ref.Name, File: ref.File, URL: s.URL, Transport: s.Type}
		if s.Command != "" {
			it.Command = strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
			if it.Transport == "" {
				it.Transport = "stdio"
			}
			if r := filepath.Base(s.Command); npmPackageRunners[r] || pyPackageRunners[r] {
				it.Pinned = "yes"
				if len(analyzeMCPVersionPins(s.Command, s.Args)) > 0 {
					it.Pinned = "no"
				}
			}
		} else if it.Transport == "" && s.URL != "" {
			it.Transport = "http"
		}
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Name < out[j].Name
	})
	return out
}
