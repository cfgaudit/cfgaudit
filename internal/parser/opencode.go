package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
// Beyond `mcp` this reads the keys that carry a command, instruction text, or a
// permission decision (#525). `plugin` and `skills` are still unmodelled: both
// need their own false-positive measurement before a rule, and parsing them
// ahead of one would be dead config.
type OpenCodeConfig struct {
	MCP map[string]OpenCodeMCP `json:"mcp,omitempty"`

	// Shell is the "Default shell to use for terminal and bash tool", so a
	// committed value repoints the interpreter every bash tool call goes through.
	Shell string `json:"shell,omitempty"`

	// LSP and Formatter each hold a command array per entry. Upstream types both
	// blocks as `boolean | Record<string, Entry>`, so the raw form is kept and
	// decoded tolerantly: `"lsp": true` is valid config, not a parse error.
	LSP       json.RawMessage `json:"lsp,omitempty"`
	Formatter json.RawMessage `json:"formatter,omitempty"`

	// Instructions are "Additional instruction files or patterns to include", so
	// a committed value pulls more files into every request.
	Instructions []string `json:"instructions,omitempty"`

	// Agent and Command carry instruction text inline: an agent's `prompt`
	// replaces its instructions, and a command's `template` is the text the
	// command sends.
	Agent   map[string]OpenCodeAgent   `json:"agent,omitempty"`
	Command map[string]OpenCodeCommand `json:"command,omitempty"`

	// Permission is `ask | allow | deny`, either as a bare string applying to
	// "*" or as an object of rules, and it repeats per agent. It is kept raw
	// because the value is a union of three shapes; PermissionGrants decodes it.
	Permission json.RawMessage `json:"permission,omitempty"`
}

// OpenCodeAgent is one `agent.<name>` entry. Only the fields cfgaudit reads are
// modelled: Prompt is instruction text, Permission repeats the top-level block
// for that agent.
type OpenCodeAgent struct {
	Prompt     string          `json:"prompt,omitempty"`
	Permission json.RawMessage `json:"permission,omitempty"`
}

// OpenCodeCommand is one `command.<name>` entry. Template is required upstream
// and is the text the command sends.
type OpenCodeCommand struct {
	Template string `json:"template,omitempty"`
}

// OpenCodeToolEntry is one `lsp.<id>` or `formatter.<id>` entry. Both carry a
// command array; `disabled: true` switches the entry off, which is the narrowing
// direction and therefore not a command site.
type OpenCodeToolEntry struct {
	Command     []string          `json:"command,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Disabled    bool              `json:"disabled,omitempty"`
}

// toolEntries decodes a `boolean | Record<string, Entry>` block, returning the
// enabled entries by name in sorted order. A boolean (or anything else) yields
// none: `"lsp": true` means "enable the built-ins", which declares no command.
func toolEntries(raw json.RawMessage) []NamedOpenCodeToolEntry {
	if len(raw) == 0 {
		return nil
	}
	var decoded map[string]OpenCodeToolEntry
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	names := make([]string, 0, len(decoded))
	for name := range decoded {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []NamedOpenCodeToolEntry
	for _, name := range names {
		if decoded[name].Disabled || len(decoded[name].Command) == 0 {
			continue
		}
		out = append(out, NamedOpenCodeToolEntry{Name: name, Entry: decoded[name]})
	}
	return out
}

// NamedOpenCodeToolEntry pairs an lsp/formatter entry with its id.
type NamedOpenCodeToolEntry struct {
	Name  string
	Entry OpenCodeToolEntry
}

// LSPEntries and FormatterEntries return the enabled entries that declare a
// command.
func (c *OpenCodeConfig) LSPEntries() []NamedOpenCodeToolEntry {
	if c == nil {
		return nil
	}
	return toolEntries(c.LSP)
}

func (c *OpenCodeConfig) FormatterEntries() []NamedOpenCodeToolEntry {
	if c == nil {
		return nil
	}
	return toolEntries(c.Formatter)
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

	// V2Disabled is the v2 spelling `disabled: true`, lowered to `enabled: false`
	// by the v1 loader (lowerServer: `enabled: input.disabled !== true`, #580).
	// An explicit `enabled` still wins over it (normalizeServer re-applies the raw
	// `enabled` when the key is present), so Disabled reads Enabled first.
	V2Disabled bool `json:"disabled,omitempty"`
}

// Disabled reports whether the entry is switched off. An explicit `enabled` wins
// (it defaults to true when absent, so only an explicit false disables); when it
// is absent the v2 `disabled: true` spelling applies. A disabled server is not a
// finding: it is the narrowing direction.
func (m OpenCodeMCP) Disabled() bool {
	if m.Enabled != nil {
		return !*m.Enabled
	}
	return m.V2Disabled
}

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
	clean := stripJSONC(data)

	var top map[string]json.RawMessage
	if err := json.Unmarshal(clean, &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// A v2 `permissions` block (top-level or under agents/agent/mode.<name>) is a
	// hard load error in the v1 loader ("V2 permissions are not supported by
	// OpenCode V1", lower() throws InvalidError before returning), so the whole
	// file fails to load and nothing in it applies. Report nothing on it, the same
	// discipline as an unparseable file — reading its mcp or permission would fire
	// on config the agent never ran (#580). Note the v1 key is the singular
	// `permission`, which is unaffected.
	if openCodeHasV2Permissions(top) {
		return &OpenCodeConfig{}, nil
	}

	var c OpenCodeConfig
	if err := json.Unmarshal(clean, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	lowerOpenCodeV2(top, &c)
	return &c, nil
}

// openCodeHasV2Permissions reports whether the config carries a v2 `permissions`
// block, which makes the v1 loader reject the whole file. Upstream checks the
// top level plus every `agents`/`agent`/`mode` entry (lower() in v2-compat.ts).
func openCodeHasV2Permissions(top map[string]json.RawMessage) bool {
	if _, ok := top["permissions"]; ok {
		return true
	}
	for _, key := range []string{"agents", "agent", "mode"} {
		raw, ok := top[key]
		if !ok {
			continue
		}
		var agents map[string]map[string]json.RawMessage
		if json.Unmarshal(raw, &agents) != nil {
			continue
		}
		for _, agent := range agents {
			if _, ok := agent["permissions"]; ok {
				return true
			}
		}
	}
	return false
}

// lowerOpenCodeV2 folds the v2 config spelling onto the v1 shape cfgaudit reads,
// mirroring ConfigV2Compat.lower (v2-compat.ts, v1.18.28+): the `mcp.servers`
// envelope unwraps to `mcp.<name>`, `commands` folds onto `command`, and
// `agents.<name>.system` folds onto `agent.<name>.prompt`. On a same-name
// conflict the v1 entry wins, as upstream does. `disabled: true` is read by
// OpenCodeMCP.Disabled directly, so no separate fold is needed for it.
//
// v2 `skills` (a string array split into skills.paths/urls) is deliberately not
// folded: cfgaudit models no skills surface in either spelling yet. The `oauth`
// snake-case keys (client_secret) are a possible CFG050 position but are read in
// neither spelling today.
func lowerOpenCodeV2(top map[string]json.RawMessage, c *OpenCodeConfig) {
	if raw, ok := top["mcp"]; ok {
		c.MCP = lowerOpenCodeMCP(raw)
	}

	if raw, ok := top["commands"]; ok {
		var cmds map[string]OpenCodeCommand
		if json.Unmarshal(raw, &cmds) == nil && len(cmds) > 0 {
			if c.Command == nil {
				c.Command = make(map[string]OpenCodeCommand, len(cmds))
			}
			for name, cmd := range cmds {
				if _, exists := c.Command[name]; exists {
					continue // the v1 `command` entry wins on a same-name conflict
				}
				c.Command[name] = cmd
			}
		}
	}

	if raw, ok := top["agents"]; ok {
		var agents map[string]struct {
			System string `json:"system"`
		}
		if json.Unmarshal(raw, &agents) == nil && len(agents) > 0 {
			if c.Agent == nil {
				c.Agent = make(map[string]OpenCodeAgent, len(agents))
			}
			for name, a := range agents {
				if _, exists := c.Agent[name]; exists {
					continue // the v1 `agent` entry wins on a same-name conflict
				}
				c.Agent[name] = OpenCodeAgent{Prompt: a.System}
			}
		}
	}
}

// lowerOpenCodeMCP decodes the `mcp` block, unwrapping the v2 `mcp.servers`
// envelope. Upstream treats `mcp.servers` as an envelope unless it is itself a
// direct server (isDirectServer: it carries a scalar `type` or `enabled` key).
// Flat `mcp.<name>` entries are processed first and win a same-name conflict with
// an envelope entry, matching normalizeMcp.
func lowerOpenCodeMCP(raw json.RawMessage) map[string]OpenCodeMCP {
	var entries map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}

	var envelope map[string]json.RawMessage
	if serversRaw, ok := entries["servers"]; ok && !openCodeIsDirectServer(serversRaw) {
		_ = json.Unmarshal(serversRaw, &envelope)
	}

	out := make(map[string]OpenCodeMCP)
	for name, v := range entries {
		if name == "servers" && envelope != nil {
			continue
		}
		var srv OpenCodeMCP
		if json.Unmarshal(v, &srv) == nil {
			out[name] = srv
		}
	}
	for name, v := range envelope {
		if _, exists := out[name]; exists {
			continue // the flat v1 entry wins
		}
		var srv OpenCodeMCP
		if json.Unmarshal(v, &srv) == nil {
			out[name] = srv
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// openCodeIsDirectServer reports whether an object value is itself a server (so
// `mcp.servers` is not the v2 envelope). Upstream isDirectServer treats it as a
// direct server when a `type` or `enabled` key holds a non-object: null, an
// array, or a scalar. A plain object under those keys means it is the envelope.
func openCodeIsDirectServer(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	for _, key := range []string{"type", "enabled"} {
		v, ok := m[key]
		if !ok {
			continue
		}
		if t := bytes.TrimSpace(v); len(t) == 0 || t[0] != '{' {
			return true // null, array, or scalar → a server named "type"/"enabled"
		}
	}
	return false
}
