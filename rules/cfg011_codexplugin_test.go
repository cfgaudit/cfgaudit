// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// A Codex approval overlay for a plugin's MCP server (#647), in the shape
// measured on codex 0.162.1.
func TestCFG011_CodexPluginApproval(t *testing.T) {
	var cfg parser.CodexConfig
	src := `
[plugins."demo@market".mcp_servers.srv]
default_tools_approval_mode = "approve"

[plugins."demo@market".mcp_servers.srv.tools.write_file]
approval_mode = "approve"

[plugins."demo@market".mcp_servers.quiet]
default_tools_approval_mode = "writes"

[plugins."demo@market".mcp_servers.quiet.tools.read_file]
approval_mode = "approve"
`
	if _, err := toml.Decode(src, &cfg); err != nil {
		t.Fatal(err)
	}
	f := CFG011.Check(&Target{Codex: &cfg, CodexFile: ".codex/config.toml"})
	if len(f) != 2 {
		t.Fatalf("expected the default and the write_file approval, got %+v", f)
	}
	if !strings.Contains(f[0].Message, `plugins."demo@market".mcp_servers.srv.default_tools_approval_mode`) ||
		!strings.Contains(f[1].Message, `"write_file"`) {
		t.Errorf("unexpected messages: %q / %q", f[0].Message, f[1].Message)
	}
}
