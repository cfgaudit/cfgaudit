package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// marketplaceTargetFor parses a manifest body so the tests exercise the same
// decoding path the CLI uses, including the string-shorthand source form.
func marketplaceTargetFor(t *testing.T, body string) *Target {
	t.Helper()
	var m parser.Marketplace
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("bad test JSON: %v", err)
	}
	return &Target{
		Scope:           finding.ScopeProject,
		MarketplaceFile: ".claude-plugin/marketplace.json",
		Marketplace:     &m,
	}
}

// The measured case: an archive source with no sha256 is never checked, because
// the binary compares the hash only when the entry declares one.
func TestCFG098_ArchiveWithoutSHA256(t *testing.T) {
	got := onlyFinding(t, CFG098.Check(marketplaceTargetFor(t, `{
      "plugins": [{"name": "acme-helper", "source": {
        "source": "archive",
        "url": "https://example.com/releases/latest/download/plugin.zip"}}]
    }`)), finding.Error)
	for _, want := range []string{"acme-helper", "plugin.zip", "sha256"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
	// The guards Claude Code really does apply must not be claimed.
	for _, absent := range []string{"SSRF", "traversal", "loopback"} {
		if strings.Contains(got.Message, absent) {
			t.Errorf("message must not claim %q, got %q", absent, got.Message)
		}
	}
}

func TestCFG098_ArchiveWithSHA256IsSilent(t *testing.T) {
	f := CFG098.Check(marketplaceTargetFor(t, `{
      "plugins": [{"name": "pinned", "source": {
        "source": "archive", "url": "https://example.com/p.zip", "sha256": "9f2c"}}]
    }`))
	if len(f) != 0 {
		t.Errorf("a pinned archive must not be flagged, got %+v", f)
	}
}

// Unpinned git sources are deliberately not reported: under 9% of real
// marketplaces carry any sha, and upstream documents the omission as normal.
func TestCFG098_UnpinnedGitSourcesNotFlagged(t *testing.T) {
	for _, src := range []string{
		`{"source": "github", "repo": "acme/tools"}`,
		`{"source": "url", "url": "https://example.com/repo.git"}`,
		`{"source": "git-subdir", "url": "https://example.com/r.git", "path": "plugins/a"}`,
	} {
		f := CFG098.Check(marketplaceTargetFor(t, `{"plugins": [{"name": "p", "source": `+src+`}]}`))
		if len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", src, f)
		}
	}
}

// The bare string source is a path inside the marketplace repo, and it is the
// dominant form in the wild.
func TestCFG098_StringShorthandIsSilent(t *testing.T) {
	f := CFG098.Check(marketplaceTargetFor(t, `{"plugins": [{"name": "local", "source": "./plugins/local"}]}`))
	if len(f) != 0 {
		t.Errorf("a relative-path source must not be flagged, got %+v", f)
	}
}

// The only registry value in the sampled corpus is the public one spelled out,
// so recognising it is what keeps the rule off its single real occurrence.
func TestCFG098_NPMDefaultRegistryIsSilent(t *testing.T) {
	for _, reg := range []string{
		"https://registry.npmjs.org",
		"https://registry.npmjs.org/",
		"https://REGISTRY.NPMJS.ORG/",
	} {
		body, err := json.Marshal(map[string]any{"plugins": []any{map[string]any{
			"name": "p", "source": map[string]any{"source": "npm", "package": "acme", "registry": reg}}}})
		if err != nil {
			t.Fatal(err)
		}
		if f := CFG098.Check(marketplaceTargetFor(t, string(body))); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", reg, f)
		}
	}
}

func TestCFG098_NPMCustomRegistry(t *testing.T) {
	got := onlyFinding(t, CFG098.Check(marketplaceTargetFor(t, `{
      "plugins": [{"name": "internal", "source": {
        "source": "npm", "package": "acme", "registry": "https://npm.internal.example"}}]
    }`)), finding.Warn)
	if !strings.Contains(got.Message, "npm.internal.example") {
		t.Errorf("expected the registry host in the message, got %q", got.Message)
	}
}

func TestCFG098_NPMWithoutRegistryIsSilent(t *testing.T) {
	f := CFG098.Check(marketplaceTargetFor(t, `{
      "plugins": [{"name": "p", "source": {"source": "npm", "package": "acme", "version": "1.2.3"}}]
    }`))
	if len(f) != 0 {
		t.Errorf("the default registry needs no entry, got %+v", f)
	}
}

// A manifest may carry many entries; each is judged on its own.
func TestCFG098_MixedManifest(t *testing.T) {
	f := CFG098.Check(marketplaceTargetFor(t, `{
      "plugins": [
        {"name": "a", "source": {"source": "archive", "url": "https://e.com/a.zip"}},
        {"name": "b", "source": {"source": "archive", "url": "https://e.com/b.zip", "sha256": "ab"}},
        {"name": "c", "source": {"source": "npm", "package": "x", "registry": "https://npm.internal.example"}},
        {"name": "d", "source": "./local"},
        {"name": "e", "source": {"source": "github", "repo": "acme/x"}}
      ]}`))
	if sev := severities(f); sev[finding.Error] != 1 || sev[finding.Warn] != 1 {
		t.Fatalf("expected 1 Error + 1 Warn, got %+v", f)
	}
}

// A source shape this version does not model must not break the scan: the schema
// gained `archive` in 2.1.224 and will gain more.
func TestCFG098_UnknownAndMalformedShapesAreTolerated(t *testing.T) {
	for _, body := range []string{
		`{"plugins": [{"name": "p", "source": {"source": "future-type", "url": "https://e.com"}}]}`,
		`{"plugins": [{"name": "p", "source": {"url": "https://e.com"}}]}`, // no type key
		`{"plugins": [{"name": "p"}]}`, // no source
		`{"plugins": []}`,
		`{}`,
	} {
		if f := CFG098.Check(marketplaceTargetFor(t, body)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", body, f)
		}
	}
}

// An entry with no name still has to produce a readable message.
func TestCFG098_UnnamedEntry(t *testing.T) {
	got := onlyFinding(t, CFG098.Check(marketplaceTargetFor(t, `{
      "plugins": [{"source": {"source": "archive", "url": "https://e.com/a.zip"}}]
    }`)), finding.Error)
	if !strings.Contains(got.Message, "(unnamed)") {
		t.Errorf("expected a placeholder name, got %q", got.Message)
	}
}

func TestCFG098_NoMarketplace_NoFinding(t *testing.T) {
	if f := CFG098.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no findings without a manifest, got %+v", f)
	}
}

// #522: a `command` source produces the plugin directory by running a shell
// command on the installing machine. Nothing pins that, so it is reported like
// the unpinned archive, and the message states the consent gate rather than
// implying the command runs unannounced.
func TestCFG098_CommandSource(t *testing.T) {
	got := onlyFinding(t, CFG098.Check(marketplaceTargetFor(t, `{
      "plugins": [{"name": "builder", "source": {
        "source": "command",
        "command": "/opt/acme/produce.sh"}}]
    }`)), finding.Error)
	for _, want := range []string{"builder", "shell command", "install or update"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
	if strings.Contains(got.Message, "link") {
		t.Errorf("copy mode must not carry the link-mode sentence: %q", got.Message)
	}
}

// mode "link" uses the produced directory in place, so its content can change
// after the install with no re-resolve. That earns its own sentence.
func TestCFG098_CommandSourceLinkMode(t *testing.T) {
	got := onlyFinding(t, CFG098.Check(marketplaceTargetFor(t, `{
      "plugins": [{"name": "builder", "source": {
        "source": "command", "mode": "link",
        "command": "/opt/acme/produce.sh"}}]
    }`)), finding.Error)
	if !strings.Contains(got.Message, "used where it lies") {
		t.Errorf("link mode should be called out, got %q", got.Message)
	}
}
