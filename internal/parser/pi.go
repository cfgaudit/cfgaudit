// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// PiSettings is a project .pi/settings.json of the pi coding agent (#1055),
// read as settings-manager.ts reads it at v1.5.0 (JSON.parse after a BOM is
// dropped). Only the keys that run code or change commands are decoded; the
// rest stays raw so a shape pi rejects does not fail the file.
type PiSettings struct {
	ShellPath           json.RawMessage `json:"shellPath,omitempty"`
	ShellCommandPrefix  json.RawMessage `json:"shellCommandPrefix,omitempty"`
	NpmCommand          json.RawMessage `json:"npmCommand,omitempty"`
	Packages            json.RawMessage `json:"packages,omitempty"`
	Extensions          json.RawMessage `json:"extensions,omitempty"`
	DefaultProjectTrust json.RawMessage `json:"defaultProjectTrust,omitempty"`
}

// ParsePiSettings reads a pi settings file.
func ParsePiSettings(path string) (*PiSettings, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s PiSettings
	if err := json.Unmarshal([]byte(strings.TrimPrefix(string(data), "\ufeff")), &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}

// PiString returns a string setting, or "" when it is absent or not a string.
func PiString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// PiStrings returns the strings of an array setting, skipping other values.
func PiStrings(raw json.RawMessage) []string {
	var list []any
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []string
	for _, v := range list {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// PiPackage is one entry of the packages setting.
type PiPackage struct {
	Source string
	// Kind is "npm", "git" (a git: source or a URL) or "local".
	Kind string
	// Pinned is whether the source fixes a version: an exact npm version, or
	// a git ref. pi's packages docs: "Versioned npm specifications are
	// pinned. Git tags and commits are also pinned".
	Pinned bool
}

var piExactVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$`)

// Packages returns the packages entries: a string, or an object with a
// source key.
func (s *PiSettings) PackageSources() []PiPackage {
	var list []json.RawMessage
	if s == nil || json.Unmarshal(s.Packages, &list) != nil {
		return nil
	}
	var out []PiPackage
	for _, raw := range list {
		src := PiString(raw)
		if src == "" {
			var obj struct {
				Source string `json:"source"`
			}
			if json.Unmarshal(raw, &obj) == nil {
				src = strings.TrimSpace(obj.Source)
			}
		}
		if src != "" {
			out = append(out, classifyPiPackage(src))
		}
	}
	return out
}

func classifyPiPackage(src string) PiPackage {
	low := strings.ToLower(src)
	switch {
	case strings.HasPrefix(low, "npm:"):
		spec := src[4:]
		// The version follows the last @ that is not the scope's leading one.
		ver := ""
		if i := strings.LastIndex(spec, "@"); i > 0 {
			ver = spec[i+1:]
		}
		return PiPackage{Source: src, Kind: "npm", Pinned: piExactVersionRe.MatchString(ver)}
	case strings.HasPrefix(low, "git:"), strings.HasPrefix(low, "https://"), strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "ssh://"), strings.HasPrefix(low, "git@"):
		rest := src
		if i := strings.Index(rest, "://"); i >= 0 {
			rest = rest[i+3:]
		} else if strings.HasPrefix(low, "git:") {
			rest = rest[4:]
		}
		if strings.HasPrefix(low, "git@") {
			rest = rest[4:]
		}
		// A ref follows an @ after the repository path.
		slash := strings.Index(rest, "/")
		at := strings.LastIndex(rest, "@")
		return PiPackage{Source: src, Kind: "git", Pinned: slash >= 0 && at > slash && at < len(rest)-1}
	}
	return PiPackage{Source: src, Kind: "local"}
}

// PiBangCommand is an env or headers value of a pi MCP server that starts
// with "!": pi runs the rest as a shell command and uses its output
// (resolve-config-value.ts).
type PiBangCommand struct {
	Server, Field, Key, Command string
}

// PiMCPBangCommands returns the "!" commands of a pi mcp.json, sorted.
func PiMCPBangCommands(servers map[string]MCPServer) []PiBangCommand {
	var out []PiBangCommand
	for name, s := range servers {
		for k, v := range s.Env {
			if c, ok := piBang(v); ok {
				out = append(out, PiBangCommand{name, "env", k, c})
			}
		}
		for k, v := range s.Headers {
			if c, ok := piBang(v); ok {
				out = append(out, PiBangCommand{name, "headers", k, c})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Server+"\x00"+a.Field+"\x00"+a.Key < b.Server+"\x00"+b.Field+"\x00"+b.Key
	})
	return out
}

func piBang(v string) (string, bool) {
	// parseConfigValueReference checks config.startsWith("!") untrimmed.
	if !strings.HasPrefix(v, "!") {
		return "", false
	}
	c := strings.TrimSpace(v[1:])
	return c, c != ""
}

// WithoutPiBangValues returns the servers with every "!" env and headers
// value removed, since pi runs it as a command rather than sending it.
func WithoutPiBangValues(servers map[string]MCPServer) map[string]MCPServer {
	out := make(map[string]MCPServer, len(servers))
	for name, s := range servers {
		s.Env = withoutBang(s.Env)
		s.Headers = withoutBang(s.Headers)
		out[name] = s
	}
	return out
}

func withoutBang[M ~map[string]string](m M) M {
	if m == nil {
		return nil
	}
	out := make(M, len(m))
	for k, v := range m {
		if _, bang := piBang(v); !bang {
			out[k] = v
		}
	}
	return out
}

// ParsePiMCP reads a pi mcp.json. pi checks each server on its own: "Invalid
// entries are reported and skipped without preventing other servers from
// connecting" (docs/mcp.md, v1.5.0), so a server cfgaudit cannot decode, such
// as one with "auth": false where pi wants {"provider": ...}, is left out
// rather than failing the file. The "!" values are kept; WithoutPiBangValues
// removes them for the shared MCP rules.
func ParsePiMCP(path string) (map[string]MCPServer, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var top struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(string(data), "\ufeff")), &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := map[string]MCPServer{}
	for name, raw := range top.MCPServers {
		// pi skips a server whose auth is not an object; cfgaudit's own
		// decoder ignores such a value for the other MCP files (#1666).
		var a struct {
			Auth json.RawMessage `json:"auth"`
		}
		if json.Unmarshal(raw, &a) == nil && !piAuthObject(a.Auth) {
			continue
		}
		// raw came out of a valid document, so it marshals again.
		one, _ := json.Marshal(map[string]map[string]json.RawMessage{"mcpServers": {name: raw}})
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

// piAuthObject reports whether an MCP server's auth value is absent, null or
// an object, the shapes pi reads.
func piAuthObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null" || t[0] == '{'
}
