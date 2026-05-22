package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG010_NpxAtLatest(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@latest","/tmp"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "@latest") {
		t.Errorf("expected message to name the unpinned tag, got: %s", f[0].Message)
	}
}

func TestCFG010_DockerColonLatest(t *testing.T) {
	json := `{"mcpServers":{"db":{"command":"docker","args":["run","--rm","ghcr.io/owner/server:latest"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for :latest image, got %d", len(f))
	}
}

func TestCFG010_NpxScopedPackageNoVersion(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned scoped package, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "no @version pin") {
		t.Errorf("expected message to indicate missing version pin, got: %s", f[0].Message)
	}
}

func TestCFG010_NpxUnscopedPackageNoVersion(t *testing.T) {
	json := `{"mcpServers":{"x":{"command":"npx","args":["-y","some-mcp-server","--port","3000"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned unscoped package, got %d", len(f))
	}
}

func TestCFG010_NpxWithVersion_NoFinding(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.2.3","/tmp"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding when package is pinned to a version, got %d: %+v", len(f), f)
	}
}

func TestCFG010_PnpmDlxWithVersion_NoFinding(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"pnpm","args":["dlx","@modelcontextprotocol/server-filesystem@1.2.3"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding for pnpm dlx pinned package, got %d: %+v", len(f), f)
	}
}

func TestCFG010_PnpmDlxUnpinned(t *testing.T) {
	json := `{"mcpServers":{"fs":{"command":"pnpm","args":["dlx","@modelcontextprotocol/server-filesystem"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned pnpm dlx package, got %d", len(f))
	}
}

func TestCFG010_LocalPath_NoFinding(t *testing.T) {
	json := `{"mcpServers":{"local":{"command":"npx","args":["./my-local-server","--port","3000"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding for local-path package, got %d: %+v", len(f), f)
	}
}

func TestCFG010_BinaryCommand_NoFinding(t *testing.T) {
	// A direct binary path (not an npm runner) shouldn't trigger the version-pin check.
	json := `{"mcpServers":{"native":{"command":"/usr/local/bin/mcp-server","args":["--config","/etc/mcp.toml"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding for native binary command, got %d: %+v", len(f), f)
	}
}

func TestCFG010_NoMCPServers_NoFinding(t *testing.T) {
	f := CFG010.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"],"deny":["Bash(rm *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when mcpServers absent, got %d", len(f))
	}
}

func TestCFG010_NoSettings_NoFinding(t *testing.T) {
	f := CFG010.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}

func TestCFG010_MultipleServers_SortedOutput(t *testing.T) {
	json := `{"mcpServers":{"zeta":{"command":"npx","args":["pkg-z"]},"alpha":{"command":"npx","args":["pkg-a"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "alpha") || !strings.Contains(f[1].Message, "zeta") {
		t.Errorf("expected findings in sorted order, got: %s / %s", f[0].Message, f[1].Message)
	}
}
