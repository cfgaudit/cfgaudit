package parser

import "encoding/json"

// SubagentBlocks holds the two nested execution blocks a Claude Code subagent
// definition (.claude/agents/*.md) can carry in its YAML frontmatter, decoded
// into the shapes the shared rule families already understand.
//
// Both are committable execution surfaces that the flat frontmatter accessors
// (StringList, Phrases, …) cannot reach, because their values are nested
// structures rather than scalars or string lists.
type SubagentBlocks struct {
	// Hooks is the frontmatter `hooks:` block: event name → matcher groups →
	// {type, command} handlers, the same schema as settings.json hooks. These run
	// while the subagent is active, so their command text is judged by the
	// command-content rules.
	Hooks map[string][]HookGroup

	// MCPServers holds only the *inline* server definitions from the frontmatter
	// `mcpServers:` list, keyed by server name. String entries in that list are
	// references to servers configured elsewhere in the session and are skipped:
	// they declare no command, url or headers of their own, so there is nothing
	// for the MCP rules to judge and reporting them would attribute another
	// file's configuration to this one.
	MCPServers map[string]MCPServer
}

// Empty reports whether neither block carried anything to scan.
func (b *SubagentBlocks) Empty() bool {
	return b == nil || (len(b.Hooks) == 0 && len(b.MCPServers) == 0)
}

// SubagentFrontmatterBlocks decodes the `hooks:` and `mcpServers:` blocks of a
// subagent definition's frontmatter. It returns nil when the frontmatter is
// absent or carries neither block.
//
// Decoding goes through JSON because Frontmatter.Raw holds the YAML as generic
// `any` values and the target structs (HookGroup, MCPServer) are already tagged
// for JSON, which is the same shape Claude Code's own settings.json and .mcp.json
// use for these blocks.
func SubagentFrontmatterBlocks(fm *Frontmatter) *SubagentBlocks {
	if fm == nil {
		return nil
	}
	out := &SubagentBlocks{}

	if raw, ok := fm.Raw["hooks"]; ok {
		var hooks map[string][]HookGroup
		if b, err := json.Marshal(raw); err == nil {
			if err := json.Unmarshal(b, &hooks); err == nil {
				// Drop events whose group list decoded to nothing, so an empty or
				// malformed block does not look like a configured event.
				for event, groups := range hooks {
					if len(groups) == 0 {
						delete(hooks, event)
					}
				}
				if len(hooks) > 0 {
					out.Hooks = hooks
				}
			}
		}
	}

	if servers := inlineSubagentMCPServers(fm.Raw["mcpServers"]); len(servers) > 0 {
		out.MCPServers = servers
	}

	if out.Empty() {
		return nil
	}
	return out
}

// inlineSubagentMCPServers decodes the frontmatter `mcpServers:` value.
//
// The documented shape is a YAML *list* whose entries are either a single-key
// mapping (an inline definition, `- playwright: {command: npx, …}`) or a bare
// string (a reference to an already-configured server, `- github`). A top-level
// mapping — the shape .mcp.json uses — is deliberately NOT accepted: Claude Code
// 2.1.220 ignores it. Verified by running a subagent whose frontmatter declared a
// server in each shape and observing which one Claude Code actually launched:
// only the list form started the process. Decoding the mapping form here would
// report a server that never connects, the false-positive class CFG087 exists to
// avoid.
func inlineSubagentMCPServers(raw any) map[string]MCPServer {
	entries, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make(map[string]MCPServer)
	for _, entry := range entries {
		// A bare string is a reference to a server configured elsewhere.
		if _, isRef := entry.(string); isRef {
			continue
		}
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		for name, cfg := range m {
			b, err := json.Marshal(cfg)
			if err != nil {
				continue
			}
			var server MCPServer
			if err := json.Unmarshal(b, &server); err != nil {
				continue
			}
			out[name] = server
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
