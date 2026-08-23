package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func browserUseTarget(c *parser.CodexConfig) *Target {
	return &Target{Scope: finding.ScopeProject, Codex: c, CodexFile: ".codex/config.toml"}
}

func codexTrue() *bool { b := true; return &b }

// full_cdp_access is the sharp one: script execution and storage access in the
// browser session, granted by the repository.
func TestCFG106_FullCDPAccessIsError(t *testing.T) {
	f := CFG106.Check(browserUseTarget(&parser.CodexConfig{BrowserUse: &parser.CodexBrowserUse{
		DefaultOriginPolicy: &parser.CodexBrowserOriginPolicy{FullCDPAccess: "allow"},
	}}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "DevTools") {
		t.Errorf("message = %q", f[0].Message)
	}
}

// A named origin is reported with its own name, so a reader can find the table.
func TestCFG106_NamedOrigin(t *testing.T) {
	f := CFG106.Check(browserUseTarget(&parser.CodexConfig{BrowserUse: &parser.CodexBrowserUse{
		Origins: map[string]parser.CodexBrowserOrigin{
			"https://intranet.example.com": {Uploads: "allow", Downloads: "deny"},
		},
	}}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, `origins."https://intranet.example.com".uploads`) {
		t.Errorf("message should name the origin and the key, got %q", f[0].Message)
	}
}

// computer_use.default_app_access allows every application, which is the
// blanket form and an error; a single bundle id is a warn.
func TestCFG106_ComputerUseSeverities(t *testing.T) {
	blanket := CFG106.Check(browserUseTarget(&parser.CodexConfig{ComputerUse: &parser.CodexComputerUse{DefaultAppAccess: "allow"}}))
	if len(blanket) != 1 || blanket[0].Severity != finding.Error {
		t.Fatalf("expected 1 error for default_app_access, got %+v", blanket)
	}
	perApp := CFG106.Check(browserUseTarget(&parser.CodexConfig{ComputerUse: &parser.CodexComputerUse{
		Macos: &parser.CodexComputerUseMacos{BundleIDs: map[string]string{"com.apple.Terminal": "allow"}},
	}}))
	if len(perApp) != 1 || perApp[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn for a single bundle id, got %+v", perApp)
	}
}

// Windows entries are named by their binary, falling back to the product name.
func TestCFG106_WindowsExes(t *testing.T) {
	f := CFG106.Check(browserUseTarget(&parser.CodexConfig{ComputerUse: &parser.CodexComputerUse{
		Windows: &parser.CodexComputerUseWindows{Exes: []parser.CodexComputerUseWindowsExe{
			{PublisherName: "Acme", ProductName: "Acme Tool", Access: "allow"},
			{PublisherName: "Acme", ProductName: "Other", BinaryName: "other.exe", Access: "deny"},
		}},
	}}))
	if len(f) != 1 {
		t.Fatalf("expected only the allowing entry, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "Acme Tool") {
		t.Errorf("message should fall back to the product name, got %q", f[0].Message)
	}
}

// The enum has exactly two members, so deny is hardening and never a finding,
// and an absent table or a non-Codex target is silent.
func TestCFG106_DenyAndAbsent(t *testing.T) {
	deny := CFG106.Check(browserUseTarget(&parser.CodexConfig{
		BrowserUse: &parser.CodexBrowserUse{DefaultOriginPolicy: &parser.CodexBrowserOriginPolicy{
			Access: "deny", Downloads: "deny", Uploads: "deny", FullCDPAccess: "deny",
		}},
		ComputerUse: &parser.CodexComputerUse{DefaultAppAccess: "deny"},
	}))
	if len(deny) != 0 {
		t.Errorf("deny is hardening, got %+v", deny)
	}
	if f := CFG106.Check(browserUseTarget(&parser.CodexConfig{})); len(f) != 0 {
		t.Errorf("absent tables, got %+v", f)
	}
	if f := CFG106.Check(&Target{}); len(f) != 0 {
		t.Errorf("non-Codex target, got %+v", f)
	}
}

// allow_history_access is a boolean rather than the allow/deny enum.
func TestCFG106_HistoryAccess(t *testing.T) {
	f := CFG106.Check(browserUseTarget(&parser.CodexConfig{BrowserUse: &parser.CodexBrowserUse{AllowHistoryAccess: codexTrue()}}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn, got %+v", f)
	}
	if f := CFG106.Check(browserUseTarget(&parser.CodexConfig{BrowserUse: &parser.CodexBrowserUse{}})); len(f) != 0 {
		t.Errorf("absent is the default, got %+v", f)
	}
}
