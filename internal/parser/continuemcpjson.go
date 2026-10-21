// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"path/filepath"
	"strings"
)

// ParseContinueMCPJSON reads one JSON file from a Continue .continue/mcpServers
// folder (#645) and returns its servers by name. Continue's loadJsonMcpConfigs
// (core/context/mcp/json) accepts three shapes, tried in this order, and so does
// this:
//
//   - a Claude Code style file: top-level `mcpServers`, and/or the
//     `projects.<path>.mcpServers` maps of a ~/.claude.json
//   - a Claude Desktop style file: top-level `mcpServers`
//   - a single server definition, named after the file
//
// Its docs tell users that JSON MCP configs from Claude, Cursor or Cline dropped
// into the folder are picked up. The file is JSONC. A file matching none of the
// shapes yields no servers, as Continue reports it and moves on.
func ParseContinueMCPJSON(path string) (map[string]MCPServer, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		MCPServers map[string]MCPServer `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]MCPServer `json:"mcpServers"`
		} `json:"projects"`
	}
	clean := stripJSONC(data)
	if err := json.Unmarshal(clean, &doc); err != nil {
		return nil, err
	}
	out := map[string]MCPServer{}
	for name, s := range doc.MCPServers {
		out[name] = s
	}
	for _, p := range doc.Projects {
		for name, s := range p.MCPServers {
			out[name] = s
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	var single MCPServer
	if json.Unmarshal(clean, &single) == nil && (single.Command != "" || single.URL != "") {
		out[strings.TrimSuffix(filepath.Base(path), ".json")] = single
	}
	return out, nil
}
