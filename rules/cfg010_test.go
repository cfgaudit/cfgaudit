// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

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

func TestCFG010_UvxUnpinned(t *testing.T) {
	json := `{"mcpServers":{"py":{"command":"uvx","args":["mcp-server-fetch"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for unpinned uvx package, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "no version pin") {
		t.Errorf("expected python pin message, got: %s", f[0].Message)
	}
}

func TestCFG010_PipxRunUnpinned(t *testing.T) {
	json := `{"mcpServers":{"py":{"command":"pipx","args":["run","some-mcp","--port","3000"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned pipx run package, got %+v", f)
	}
}

func TestCFG010_PythonPinned_NoFinding(t *testing.T) {
	// PEP 508 == pin, range specifiers, and the uvx @version form are all pinned.
	for _, server := range []string{
		`{"command":"uvx","args":["ruff==0.1.0"]}`,
		`{"command":"uvx","args":["ruff@0.1.0"]}`,
		`{"command":"uvx","args":["pkg>=1.2"]}`,
		`{"command":"uvx","args":["pkg~=1.0"]}`,
		`{"command":"pipx","args":["run","pycowsay==1.0"]}`,
	} {
		json := `{"mcpServers":{"py":` + server + `}}`
		if f := CFG010.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for pinned python server %s, got %+v", server, f)
		}
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

func TestCFG010_NpxPackageFlagUnpinned(t *testing.T) {
	// Two --package flags, one pinned and one not: only the unpinned extra
	// package is reported (the pinned run package stays clean).
	json := `{"mcpServers":{"s":{"command":"npx","args":["--package","a@1.0.0","--package","b","-y","a"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned --package, got %d: %+v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "\"b\"") {
		t.Errorf("expected finding to name the unpinned package b, got: %s", f[0].Message)
	}
}

func TestCFG010_NpxPackageFlagPinned_NoFinding(t *testing.T) {
	json := `{"mcpServers":{"s":{"command":"npx","args":["--package","b@1.0.0","-y","b"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding when all --package specs are pinned, got %d: %+v", len(f), f)
	}
}

func TestCFG010_NpxPackageFlagForms(t *testing.T) {
	// -p <spec> and --package=<spec> are collected; both are unpinned here.
	json := `{"mcpServers":{"s":{"command":"npx","args":["-p","b","--package=c","-y","a@1.0.0"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for -p and --package= unpinned specs, got %d: %+v", len(f), f)
	}
}

func TestCFG010_UvxWithUnpinned(t *testing.T) {
	json := `{"mcpServers":{"py":{"command":"uvx","args":["--with","ruff","mcp-server-fetch"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 2 {
		t.Fatalf("expected findings for unpinned --with and run package, got %d: %+v", len(f), f)
	}
}

func TestCFG010_UvxWithPinned_NoFinding(t *testing.T) {
	json := `{"mcpServers":{"py":{"command":"uvx","args":["--with","ruff==0.2.0","mcp-server-fetch@0.1.0"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding when uvx --with is pinned, got %d: %+v", len(f), f)
	}
}

func TestCFG010_NpxPackageFlagBinCommand_NoFinding(t *testing.T) {
	// With -p present the positional is the bin to execute, not a package:
	// npx -y -p @scope/pkg@1.2.3 pkg-bin must not report pkg-bin as unpinned.
	json := `{"mcpServers":{"s":{"command":"npx","args":["-y","-p","@scope/pkg@1.2.3","pkg-bin"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding when the positional is a bin command, got %d: %+v", len(f), f)
	}
}

func TestCFG010_NpxPackageFlagBinCommand_UnpinnedSpecStillReported(t *testing.T) {
	// The positional stays a bin command, but the unpinned -p spec is still reported.
	json := `{"mcpServers":{"s":{"command":"npx","args":["-y","-p","@scope/pkg","pkg-bin"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned -p spec, got %d: %+v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "\"@scope/pkg\"") {
		t.Errorf("expected finding to name the unpinned spec @scope/pkg, got: %s", f[0].Message)
	}
}

func TestCFG010_NpxNoPackageFlag_StillChecksRunPackage(t *testing.T) {
	// Without any --package/-p the first positional is the run package and is checked.
	json := `{"mcpServers":{"s":{"command":"npx","args":["-y","cowsay"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned run package, got %d: %+v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "\"cowsay\"") {
		t.Errorf("expected finding to name the run package cowsay, got: %s", f[0].Message)
	}
}

func TestCFG010_NpxServerFlagAfterPositional_StillChecksRunPackage(t *testing.T) {
	// `-p 3000` after the positional belongs to the executed server, not npx:
	// the run package must still be reported as unpinned.
	json := `{"mcpServers":{"s":{"command":"npx","args":["-y","@acme/mcp-server","-p","3000"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned run package, got %d: %+v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "\"@acme/mcp-server\"") {
		t.Errorf("expected finding to name the run package @acme/mcp-server, got: %s", f[0].Message)
	}
}

func TestCFG010_UvxPythonFlagNotPackageSpec(t *testing.T) {
	// For uvx, `-p` is --python, not a package flag: `-p=3.12` must not be
	// reported as an unpinned package, and the pinned run package stays clean.
	json := `{"mcpServers":{"py":{"command":"uvx","args":["-p=3.12","ruff==0.1.0"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding when uvx -p is a python flag, got %d: %+v", len(f), f)
	}
}

func TestCFG010_UvxWithEquals_UnpinnedSpecReported(t *testing.T) {
	// uvx --with=<spec> is a package spec and must be checked like --with <spec>.
	json := `{"mcpServers":{"py":{"command":"uvx","args":["--with=ruff","mcp-server-fetch@0.1.0"]}}}`
	f := CFG010.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned --with= spec, got %d: %+v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "\"ruff\"") {
		t.Errorf("expected finding to name the unpinned spec ruff, got: %s", f[0].Message)
	}
}
