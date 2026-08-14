package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// OpenCodeConfig is the subset of an OpenCode `opencode.json` that cfgaudit
// reads. The project file sits at the repository root and its own docs invite
// committing it: "This is also safe to be checked into Git and uses the same
// schema as the global one."
//
// It also OUTRANKS the user's global config. The documented precedence, lowest
// to highest, is remote organizational config, global config, OPENCODE_CONFIG
// path, project config, .opencode directories, inline config, managed settings.
// So a committed value wins over the one a contributor set for themselves.
//
// Verified against opencode 1.18.18 with `opencode debug config` in a scratch
// repository: a project file declaring an mcp server resolved straight through,
// with no trust prompt and no folder-trust concept in the resolved config, whose
// keys were agent, command, mcp, mode, plugin and username.
//
// Only `mcp` is modelled here. The file also carries `agent`, `command`,
// `instructions`, `shell`, `formatter`, `lsp` and `permission`, each of which is
// a surface of its own with its own false-positive question; they are follow-ups
// rather than dead config parsed ahead of a rule (#497).
type OpenCodeConfig struct {
	MCP map[string]OpenCodeMCP `json:"mcp,omitempty"`
}

// OpenCodeMCP is one `mcp.<name>` entry. The shape differs from every other
// agent's in two ways that matter, both taken from the published schema at
// opencode.ai/config.json:
//
//   - Command is an ARRAY holding the executable and its arguments together
//     ("Command and arguments to run the MCP server"), not a command string
//     beside a separate args list.
//   - The environment key is `environment`, not `env`.
//
// Decoding it as if it were the common shape would silently read nothing.
type OpenCodeMCP struct {
	Type        string            `json:"type,omitempty"`
	Command     []string          `json:"command,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	URL         string            `json:"url,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
	CWD         string            `json:"cwd,omitempty"`
}

// Disabled reports whether the entry is switched off. `enabled` defaults to true
// when absent, so only an explicit false disables, and a disabled server is not
// a finding: it is the narrowing direction.
func (m OpenCodeMCP) Disabled() bool { return m.Enabled != nil && !*m.Enabled }

// MCPServerMap converts the mcp block to the shared MCPServer shape so the
// existing MCP rules apply unchanged. The command array is split into its
// executable and arguments, and `environment` is mapped onto Env.
//
// Entries explicitly disabled are dropped: OpenCode will not start them, so
// reporting one would be a finding on a server that never runs.
func (c *OpenCodeConfig) MCPServerMap() map[string]MCPServer {
	if c == nil || len(c.MCP) == 0 {
		return nil
	}
	out := make(map[string]MCPServer, len(c.MCP))
	for name, m := range c.MCP {
		if m.Disabled() {
			continue
		}
		srv := MCPServer{
			Type:    strings.TrimSpace(m.Type),
			Env:     m.Environment,
			URL:     m.URL,
			Headers: m.Headers,
		}
		if len(m.Command) > 0 {
			srv.Command = m.Command[0]
			if len(m.Command) > 1 {
				srv.Args = m.Command[1:]
			}
		}
		out[name] = srv
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParseOpenCodeConfig reads and decodes an opencode.json.
//
// The file is JSONC despite the extension, so comments and trailing commas are
// stripped before decoding. Verified against opencode 1.18.18: a config carrying
// both a // comment and trailing commas resolved normally through
// `opencode debug config`. Two of 79 real files in the wild carry trailing
// commas, and decoding them strictly turned an ordinary config into a scan error
// rather than auditing it.
func ParseOpenCodeConfig(path string) (*OpenCodeConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, err
	}
	var c OpenCodeConfig
	if err := json.Unmarshal(stripJSONC(data), &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}
