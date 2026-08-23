package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG011_Wildcard(t *testing.T) {
	json := `{"mcpServers":{"shell":{"command":"mcp-server-shell","alwaysAllow":["*"]}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for wildcard, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "wildcard") {
		t.Errorf("expected message to mention wildcard, got: %s", f[0].Message)
	}
}

func TestCFG011_WildcardAmongOthers(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"x","alwaysAllow":["read_file","*","list_directory"]}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for wildcard mixed in list, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "wildcard") {
		t.Errorf("expected wildcard message even with other entries, got: %s", f[0].Message)
	}
}

func TestCFG011_DangerousTools(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"x","alwaysAllow":["read_file","write_file","delete_file"]}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for dangerous tools, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "write_file") || !strings.Contains(f[0].Message, "delete_file") {
		t.Errorf("expected message to name the dangerous tools, got: %s", f[0].Message)
	}
}

func TestCFG011_ExecuteCommand(t *testing.T) {
	json := `{"mcpServers":{"sh":{"command":"x","alwaysAllow":["execute_command"]}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for execute_command, got %d", len(f))
	}
}

func TestCFG011_LargeBenignList(t *testing.T) {
	// 10 read-only tools — flagged for size only, not dangerous-tool match.
	json := `{"mcpServers":{"fs":{"command":"x","alwaysAllow":["read_file","list_directory","get_file_info","search_files","find_files","get_metadata","head_file","tail_file","stat_file","resolve_path"]}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for large list, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "10 tools") {
		t.Errorf("expected message to mention the count, got: %s", f[0].Message)
	}
}

func TestCFG011_SmallReadOnly_NoFinding(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"x","alwaysAllow":["read_file","list_directory"]}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding for small read-only list, got %d: %+v", len(f), f)
	}
}

func TestCFG011_EmptyAlwaysAllow_NoFinding(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"x","alwaysAllow":[]}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding for empty alwaysAllow, got %d", len(f))
	}
}

func TestCFG011_NoAlwaysAllow_NoFinding(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"x"}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding when alwaysAllow absent, got %d", len(f))
	}
}

func TestCFG011_NoMCPServers_NoFinding(t *testing.T) {
	f := CFG011.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"],"deny":["Bash(rm *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when mcpServers absent, got %d", len(f))
	}
}

func TestCFG011_NoSettings_NoFinding(t *testing.T) {
	f := CFG011.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}

func TestCFG011_MultipleServers_SortedOutput(t *testing.T) {
	json := `{"mcpServers":{"zeta":{"command":"x","alwaysAllow":["*"]},"alpha":{"command":"x","alwaysAllow":["*"]}}}`
	f := CFG011.Check(settingsTarget(t, json))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "alpha") || !strings.Contains(f[1].Message, "zeta") {
		t.Errorf("expected sorted output, got: %s / %s", f[0].Message, f[1].Message)
	}
}

// codexMCPTarget builds the target the CLI builds for a project .codex/config.toml:
// the servers ride ProjectMCP, which is what mcpServerRefs reads.
func codexMCPTarget(servers map[string]parser.CodexMCP) *Target {
	cc := &parser.CodexConfig{MCPServers: servers}
	return &Target{
		Scope:          finding.ScopeProject,
		Codex:          cc,
		CodexFile:      ".codex/config.toml",
		ProjectMCP:     cc.MCPServerMap(),
		ProjectMCPFile: ".codex/config.toml",
	}
}

// #523: Codex spells per-server auto-approval as an approval mode rather than a
// tool list. Only "approve" never asks; "auto" is the default and
// "prompt"/"writes" narrow, so neither may produce a finding.
func TestCFG011_CodexDefaultToolsApprovalMode(t *testing.T) {
	tgt := codexMCPTarget(map[string]parser.CodexMCP{
		"remote": {URL: "https://mcp.example/mcp", DefaultToolsApprovalMode: "approve"},
	})
	f := CFG011.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn for default_tools_approval_mode=approve, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "default_tools_approval_mode") {
		t.Errorf("message should name the key, got %q", f[0].Message)
	}
	for _, quiet := range []string{"auto", "prompt", "writes", ""} {
		q := codexMCPTarget(map[string]parser.CodexMCP{
			"remote": {URL: "https://mcp.example/mcp", DefaultToolsApprovalMode: quiet},
		})
		if got := CFG011.Check(q); len(got) != 0 {
			t.Errorf("approval mode %q must not fire, got %+v", quiet, got)
		}
	}
}

// The per-tool form is judged like alwaysAllow: state-mutating names are the
// finding, a read-only one on its own is not.
func TestCFG011_CodexPerToolApprovalMode(t *testing.T) {
	tgt := codexMCPTarget(map[string]parser.CodexMCP{
		"remote": {URL: "https://mcp.example/mcp", Tools: map[string]parser.CodexMCPTool{
			"write_file": {ApprovalMode: "approve"},
			"read_file":  {ApprovalMode: "approve"},
			"list_dir":   {ApprovalMode: "prompt"},
		}},
	})
	f := CFG011.Check(tgt)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "\"write_file\"") || strings.Contains(f[0].Message, "list_dir") {
		t.Errorf("expected the state-mutating tool named and the prompt-mode one absent, got %q", f[0].Message)
	}

	readOnly := codexMCPTarget(map[string]parser.CodexMCP{
		"remote": {URL: "https://mcp.example/mcp", Tools: map[string]parser.CodexMCPTool{
			"read_file": {ApprovalMode: "approve"},
		}},
	})
	if got := CFG011.Check(readOnly); len(got) != 0 {
		t.Errorf("a single read-only approve must stay silent, got %+v", got)
	}
}
