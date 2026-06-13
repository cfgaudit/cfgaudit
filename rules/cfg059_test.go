package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG059_HomoglyphPackage_Error(t *testing.T) {
	// zero-for-o homoglyph in the scope folds onto the official package.
	tgt := settingsTarget(t, `{"mcpServers":{"m":{"command":"npx","args":["-y","@modelcontextprot0col/server-filesystem"]}}}`)
	f := CFG059.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for homoglyph package, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "homoglyph") {
		t.Errorf("expected homoglyph reason, got %q", f[0].Message)
	}
}

func TestCFG059_TypoPackage_Error(t *testing.T) {
	// missing 's' — one-character difference from server-filesystem.
	tgt := settingsTarget(t, `{"mcpServers":{"m":{"command":"npx","args":["@modelcontextprotocol/server-filesytem"]}}}`)
	f := CFG059.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for one-char typo, got %+v", f)
	}
}

func TestCFG059_UnofficialScope_Warn(t *testing.T) {
	tgt := settingsTarget(t, `{"mcpServers":{"m":{"command":"npx","args":["-y","@evilcorp/server-filesystem"]}}}`)
	f := CFG059.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for unofficial scope, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "non-official scope") {
		t.Errorf("expected scope reason, got %q", f[0].Message)
	}
}

func TestCFG059_HomoglyphHost_Error(t *testing.T) {
	for _, url := range []string{
		"https://mcp.anthr0pic.com/sse", // 0→o
		"https://api.0penai.com/v1/mcp", // 0→o
	} {
		tgt := settingsTarget(t, `{"mcpServers":{"m":{"type":"http","url":"`+url+`"}}}`)
		f := CFG059.Check(tgt)
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for lookalike host %q, got %+v", url, f)
		}
	}
}

func TestCFG059_KnownGoodAndUnrelated_NoFinding(t *testing.T) {
	for _, cfg := range []string{
		`{"mcpServers":{"m":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}}}`,  // exact official
		`{"mcpServers":{"m":{"command":"npx","args":["@modelcontextprotocol/server-filesystem@1.2.3"]}}}`, // exact + version
		`{"mcpServers":{"m":{"command":"npx","args":["-y","@upstash/context7-mcp"]}}}`,                    // unrelated community pkg
		`{"mcpServers":{"m":{"command":"node","args":["./local-server.js"]}}}`,                            // local script
		`{"mcpServers":{"m":{"type":"http","url":"https://api.anthropic.com/mcp"}}}`,                      // exact official host
		`{"mcpServers":{"m":{"type":"http","url":"https://mcp.mycompany.internal/sse"}}}`,                 // unrelated host
	} {
		if f := CFG059.Check(settingsTarget(t, cfg)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cfg, f)
		}
	}
}

func TestCFG059_HookTyposquat_Error(t *testing.T) {
	// "server-filesytem" missing 's' — one-char edit from the official MCP package,
	// invoked from a hook command rather than an mcpServers block.
	tgt := hookTarget(t, "npx -y @modelcontextprotocol/server-filesytem")
	f := CFG059.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for hook typosquat, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "hooks.PreToolUse command runs npm package") {
		t.Errorf("expected hook-labelled message, got %q", f[0].Message)
	}
}

func TestCFG059_HookToolTyposquat_Error(t *testing.T) {
	// "prettir" — one-char edit (insert 'e') from the common tool "prettier".
	f := CFG059.Check(hookTarget(t, "npx prettir --write ."))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for prettier typosquat, got %+v", f)
	}
}

func TestCFG059_HookChainedRunner_Error(t *testing.T) {
	// Runner sits in the second segment of a && chain; the leading eslint is legit.
	f := CFG059.Check(hookTarget(t, "eslint . && npx @modelcontextprot0col/server-filesystem"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for chained runner, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "homoglyph") {
		t.Errorf("expected homoglyph reason, got %q", f[0].Message)
	}
}

func TestCFG059_HookPnpmDlxTyposquat_Error(t *testing.T) {
	f := CFG059.Check(hookTarget(t, "pnpm dlx @modelcontextprotocol/server-filesytem"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for pnpm dlx typosquat, got %+v", f)
	}
}

func TestCFG059_HookLegitAndUnrelated_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		"npx prettier --write .",                      // exact common tool
		"npx @modelcontextprotocol/server-filesystem", // exact MCP package
		"pnpm install",                                // subcommand, not a dlx package
		"yarn build",                                  // subcommand, not a dlx package
		"npx -y @upstash/context7-mcp",                // unrelated community pkg
		"npx ./scripts/local-tool.js",                 // local script path
		"eslint . && prettier --write .",              // no runner at all
		"npm run lint",                                // npm run, not a fetched package
	} {
		if f := CFG059.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
}

func TestHookNpmPackageSpecs(t *testing.T) {
	cases := map[string][]string{
		"npx foo-pkg":                 {"foo-pkg"},
		"npx -y @scope/pkg@1.2.3":     {"@scope/pkg@1.2.3"},
		"bunx some-tool --flag":       {"some-tool"},
		"pnpm dlx a-pkg":              {"a-pkg"},
		"yarn dlx b-pkg":              {"b-pkg"},
		"pnpm install":                nil,
		"yarn add left-pad":           nil,
		"npx a && npx b":              {"a", "b"},
		"npx ./local.js":              nil,
		"prettier --write .":          nil,
		"/usr/local/bin/npx tool-pkg": {"tool-pkg"},
	}
	for in, want := range cases {
		got := hookNpmPackageSpecs(in)
		if len(got) != len(want) {
			t.Errorf("hookNpmPackageSpecs(%q)=%v want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("hookNpmPackageSpecs(%q)=%v want %v", in, got, want)
				break
			}
		}
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"server-filesystem", "server-filesytem", 1},
		{"kitten", "sitting", 3},
		{"a", "", 1},
	}
	for _, c := range cases {
		if got := levenshtein(c.a, c.b); got != c.want {
			t.Errorf("levenshtein(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNpmPackageName(t *testing.T) {
	cases := map[string]string{
		"@scope/name@1.2.3": "@scope/name",
		"@scope/name":       "@scope/name",
		"name@2":            "name",
		"name":              "name",
	}
	for in, want := range cases {
		if got := npmPackageName(in); got != want {
			t.Errorf("npmPackageName(%q)=%q want %q", in, got, want)
		}
	}
}
