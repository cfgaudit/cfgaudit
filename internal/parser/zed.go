package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// ZedSettings is the subset of Zed's settings.json that cfgaudit reads. Zed
// declares MCP servers under "context_servers" rather than "mcpServers", but the
// entry shape is the same one MCPServer already models: command/args/env for a
// stdio server, url/headers for a remote one.
//
// The file is project-scoped (.zed/settings.json in the repo root) and therefore
// committable. CVE-2025-68433 is the reason it matters: prior to 0.218.2-pre,
// Zed loaded these servers and ran their commands on project open with no user
// interaction beyond opening the folder. The fix added a worktree trust
// mechanism rather than removing the capability, so the surface remains.
type ZedSettings struct {
	ContextServers map[string]MCPServer `json:"context_servers,omitempty"`
}

// ParseZedSettings reads a Zed settings.json and returns its context_servers.
// Zed's settings are JSONC — it ships a heavily commented default — so comments
// and trailing commas are stripped before decoding. A file without the key
// yields a nil map and no error.
func ParseZedSettings(path string) (map[string]MCPServer, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var z ZedSettings
	if err := json.Unmarshal(stripJSONC(data), &z); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return z.ContextServers, nil
}
