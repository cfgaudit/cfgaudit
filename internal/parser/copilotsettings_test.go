package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCopilotSettings(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// The doubled source.source nesting is Copilot's real schema.
func TestParseCopilotSettings_DoubledSourceNesting(t *testing.T) {
	path := writeCopilotSettings(t, `{
	  "enabledPlugins": { "deploy@acme": true, "other@acme": false },
	  "extraKnownMarketplaces": {
	    "acme": { "source": { "source": "github", "repo": "acme/plugins", "ref": "main", "path": "dist" } }
	  }
	}`)
	c, err := ParseCopilotSettings(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !c.EnabledPlugins["deploy@acme"] || c.EnabledPlugins["other@acme"] {
		t.Errorf("enabledPlugins decoded wrong: %+v", c.EnabledPlugins)
	}
	src := c.ExtraKnownMarketplaces["acme"].Source
	if src.Source != "github" || src.Repo != "acme/plugins" || src.Ref != "main" || src.Path != "dist" {
		t.Errorf("source decoded wrong: %+v", src)
	}
}

func TestCopilotMarketplaceSource_Remote(t *testing.T) {
	cases := []struct {
		src  CopilotMarketplaceSource
		want bool
	}{
		{CopilotMarketplaceSource{Source: "github", Repo: "a/b"}, true},
		{CopilotMarketplaceSource{Source: "git", URL: "https://git.example.com/p.git"}, true},
		{CopilotMarketplaceSource{Source: "directory", Path: "./plugins"}, false},
		{CopilotMarketplaceSource{Repo: "a/b"}, true},  // discriminator omitted
		{CopilotMarketplaceSource{Path: "./x"}, false}, // neither repo nor url
	}
	for _, c := range cases {
		if got := c.src.Remote(); got != c.want {
			t.Errorf("%+v: Remote() = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestCopilotMarketplaceSource_Location(t *testing.T) {
	cases := []struct {
		src  CopilotMarketplaceSource
		want string
	}{
		{CopilotMarketplaceSource{Repo: "a/b"}, "a/b"},
		{CopilotMarketplaceSource{URL: "https://git.example.com/p.git"}, "https://git.example.com/p.git"},
		{CopilotMarketplaceSource{Path: "./plugins"}, "./plugins"},
	}
	for _, c := range cases {
		if got := c.src.Location(); got != c.want {
			t.Errorf("%+v: Location() = %q, want %q", c.src, got, c.want)
		}
	}
}

// A malformed file is an error, so a settings file that is silently not being
// scanned is reported rather than mistaken for an empty one.
func TestParseCopilotSettings_Malformed(t *testing.T) {
	if _, err := ParseCopilotSettings(writeCopilotSettings(t, `{not json`)); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestParseCopilotSettings_Missing(t *testing.T) {
	if _, err := ParseCopilotSettings(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

// #471: the inline hooks table is the twin of .github/hooks/*.json. From the
// shipped CLI's settings help: "hooks: inline hook definitions, keyed by event
// name (same schema as .github/hooks/*.json) ... in repo settings.json they act
// as repo-level hooks".
func TestCopilotSettings_InlineHooks(t *testing.T) {
	path := writeCopilotSettings(t, `{
      "hooks": {"sessionStart": [{"type": "command", "command": "echo hi"}]}
    }`)
	c, err := ParseCopilotSettings(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h := c.InlineHooks()
	if h == nil || len(h.Hooks["sessionStart"]) != 1 {
		t.Fatalf("expected the inline table decoded, got %+v", h)
	}
	if h.Hooks["sessionStart"][0].Command != "echo hi" {
		t.Errorf("command = %q", h.Hooks["sessionStart"][0].Command)
	}
	if h.DisableAllHooks {
		t.Errorf("hooks must not be disabled by default")
	}
	if c.HooksDisabled() {
		t.Errorf("HooksDisabled must be false by default")
	}
}

// disableAllHooks is global: "whether to disable all hooks (repo-level and
// user-level)". It rides onto the shared shape so every hook rule honours it.
func TestCopilotSettings_DisableAllHooksIsGlobal(t *testing.T) {
	path := writeCopilotSettings(t, `{
      "disableAllHooks": true,
      "hooks": {"sessionStart": [{"type": "command", "command": "echo hi"}]}
    }`)
	c, _ := ParseCopilotSettings(path)
	if !c.HooksDisabled() {
		t.Fatalf("expected HooksDisabled")
	}
	if h := c.InlineHooks(); h == nil || !h.DisableAllHooks {
		t.Errorf("the flag must ride onto the shared shape, got %+v", h)
	}
}

// A settings file with no hooks key yields no inline table rather than an empty
// one, so the CLI builds no target for it.
func TestCopilotSettings_NoInlineHooks(t *testing.T) {
	path := writeCopilotSettings(t, `{"enabledPlugins": {"a@b": true}}`)
	c, _ := ParseCopilotSettings(path)
	if h := c.InlineHooks(); h != nil {
		t.Errorf("expected no inline hooks, got %+v", h)
	}
}

// A real committed file writes `"hooks": {"enabled": true}`. A typed
// map[string][]AgentHook turned that into a parse error that discarded the whole
// settings file, so enabledPlugins and extraKnownMarketplaces went unscanned too.
// Found by the 504-repo pre-release run.
func TestCopilotSettings_HooksSwitchDoesNotBreakTheFile(t *testing.T) {
	path := writeCopilotSettings(t, `{
      "skills": {"enabled": true},
      "hooks": {"enabled": true},
      "enabledPlugins": {"p@m": true}
    }`)
	c, err := ParseCopilotSettings(path)
	if err != nil {
		t.Fatalf("a non-event key inside hooks must not fail the parse: %v", err)
	}
	if len(c.EnabledPlugins) != 1 {
		t.Errorf("the rest of the file must still decode, got %+v", c.EnabledPlugins)
	}
	if h := c.InlineHooks(); h != nil {
		t.Errorf("a switch is not a handler list, got %+v", h)
	}
}

// A real event beside the switch still decodes.
func TestCopilotSettings_HooksSwitchBesideAnEvent(t *testing.T) {
	path := writeCopilotSettings(t, `{
      "hooks": {"enabled": true, "sessionStart": [{"type": "command", "command": "echo hi"}]}
    }`)
	c, err := ParseCopilotSettings(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h := c.InlineHooks()
	if h == nil || len(h.Hooks) != 1 || len(h.Hooks["sessionStart"]) != 1 {
		t.Fatalf("expected only the event decoded, got %+v", h)
	}
}

// The file is JSONC in the wild.
func TestCopilotSettings_JSONC(t *testing.T) {
	path := writeCopilotSettings(t, "{\n  // team defaults\n  \"enabledPlugins\": {\"p@m\": true},\n}\n")
	c, err := ParseCopilotSettings(path)
	if err != nil {
		t.Fatalf("JSONC must decode: %v", err)
	}
	if len(c.EnabledPlugins) != 1 {
		t.Errorf("got %+v", c.EnabledPlugins)
	}
}
