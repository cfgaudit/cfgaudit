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
