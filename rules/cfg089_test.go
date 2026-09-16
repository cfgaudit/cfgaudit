package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func copilotSettingsTarget(cs *parser.CopilotSettings) *Target {
	return &Target{
		Scope:               finding.ScopeProject,
		CopilotSettings:     cs,
		CopilotSettingsFile: ".github/copilot/settings.json",
	}
}

// The doubled source.source nesting is Copilot's real schema, not a typo.
func TestCFG089_UnpinnedMarketplace(t *testing.T) {
	f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
		ExtraKnownMarketplaces: map[string]parser.CopilotMarketplace{
			"our-internal-marketplace": {Source: parser.CopilotMarketplaceSource{
				Source: "github", Repo: "acme-corp/copilot-plugins",
			}},
		},
	}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "acme-corp/copilot-plugins") {
		t.Errorf("message should name the source, got %q", f[0].Message)
	}
	// "unpinned", not a claim about what an omitted ref resolves to.
	if strings.Contains(strings.ToLower(f[0].Message), "default branch") {
		t.Errorf("message must not assert what an omitted ref resolves to: %q", f[0].Message)
	}
}

// A branch or tag name moves; only a full 40-character SHA pins.
func TestCFG089_PinnedMarketplaceSilent(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	for _, src := range []parser.CopilotMarketplaceSource{
		{Source: "github", Repo: "acme/plugins", SHA: sha},
		{Source: "github", Repo: "acme/plugins", Ref: sha},
		{Source: "git", URL: "https://git.example.com/plugins.git", Ref: sha},
	} {
		f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
			ExtraKnownMarketplaces: map[string]parser.CopilotMarketplace{"m": {Source: src}},
		}))
		if len(f) != 0 {
			t.Errorf("%+v: expected no finding, got %+v", src, f)
		}
	}
}

func TestCFG089_MutableRefIsNotAPin(t *testing.T) {
	f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
		ExtraKnownMarketplaces: map[string]parser.CopilotMarketplace{
			"m": {Source: parser.CopilotMarketplaceSource{Source: "github", Repo: "acme/plugins", Ref: "main"}},
		},
	}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a branch ref, got %+v", f)
	}
}

// A directory source is on disk — no upstream anyone else controls.
func TestCFG089_DirectorySourceSilent(t *testing.T) {
	f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
		ExtraKnownMarketplaces: map[string]parser.CopilotMarketplace{
			"local": {Source: parser.CopilotMarketplaceSource{Source: "directory", Path: "./plugins"}},
		},
	}))
	if len(f) != 0 {
		t.Errorf("expected no finding, got %+v", f)
	}
}

func TestCFG089_EnabledPlugins(t *testing.T) {
	f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
		EnabledPlugins: map[string]bool{"deploy-tools@acme": true, "off-plugin@acme": false},
	}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "deploy-tools@acme") {
		t.Errorf("message should name the plugin, got %q", f[0].Message)
	}
}

// A plugin enabled from a marketplace this same file registers is the fully
// self-contained supply chain — the message says so.
func TestCFG089_EnabledPluginFromSelfRegisteredMarketplace(t *testing.T) {
	f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
		EnabledPlugins: map[string]bool{"deploy-tools@acme": true},
		ExtraKnownMarketplaces: map[string]parser.CopilotMarketplace{
			"acme": {Source: parser.CopilotMarketplaceSource{Source: "github", Repo: "acme/plugins", SHA: "0123456789abcdef0123456789abcdef01234567"}},
		},
	}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (marketplace is pinned), got %+v", f)
	}
	if !strings.Contains(f[0].Message, "this same file registers") {
		t.Errorf("message should call out the self-registered marketplace, got %q", f[0].Message)
	}
}

// A user's own ~/.copilot/settings.json is their choice, as in CFG055.
func TestCFG089_UserScopeSilent(t *testing.T) {
	tgt := copilotSettingsTarget(&parser.CopilotSettings{
		EnabledPlugins: map[string]bool{"x@y": true},
	})
	tgt.Scope = finding.ScopeUser
	if f := CFG089.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding, got %+v", f)
	}
}

func TestCFG089_NoSettings(t *testing.T) {
	if f := CFG089.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding, got %+v", f)
	}
}

// #582: at the repository level Copilot's own configuration reference says
// autoUpdate is "accepted at the repository level but currently ignored", so the
// finding is info (reported because the key is a declared opt-in a future release
// could honour), not a warn claiming a live refresh.
func TestCFG089_MarketplaceAutoUpdate(t *testing.T) {
	f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
		ExtraKnownMarketplaces: map[string]parser.CopilotMarketplace{
			"acme": {AutoUpdate: true, Source: parser.CopilotMarketplaceSource{
				Source: "github", Repo: "acme/mkt", SHA: "0123456789abcdef0123456789abcdef01234567",
			}},
		},
	}))
	if len(f) != 1 || f[0].Severity != finding.Info {
		t.Fatalf("expected 1 info for autoUpdate at the repository level, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "autoUpdate") || !strings.Contains(f[0].Message, "currently ignored") {
		t.Errorf("message should name the key and the vendor's wording, got %q", f[0].Message)
	}
}

// Unpinned and auto-updating yields two separate findings: the info autoUpdate
// note and the warn about the unpinned source. The autoUpdate note no longer
// carries the pin sentence, since it refreshes nothing at this scope; the pin
// concern is the source finding's job.
func TestCFG089_MarketplaceAutoUpdateUnpinned(t *testing.T) {
	f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
		ExtraKnownMarketplaces: map[string]parser.CopilotMarketplace{
			"acme": {AutoUpdate: true, Source: parser.CopilotMarketplaceSource{
				Source: "github", Repo: "acme/mkt", Ref: "main",
			}},
		},
	}))
	if len(f) != 2 {
		t.Fatalf("expected the autoUpdate and the unpinned findings, got %+v", f)
	}
	var sawAutoUpdateInfo, sawUnpinnedWarn bool
	for _, x := range f {
		switch {
		case strings.Contains(x.Message, "autoUpdate"):
			sawAutoUpdateInfo = x.Severity == finding.Info
			if strings.Contains(x.Message, "no immutable pin") {
				t.Errorf("the autoUpdate note must not claim a live refresh / carry the pin sentence: %q", x.Message)
			}
		case strings.Contains(x.Message, "no immutable pin"):
			sawUnpinnedWarn = x.Severity == finding.Warn
		}
	}
	if !sawAutoUpdateInfo || !sawUnpinnedWarn {
		t.Errorf("expected an info autoUpdate note and a warn unpinned-source finding, got %+v", f)
	}
}

// Absent or false changes nothing.
func TestCFG089_MarketplaceAutoUpdateAbsent(t *testing.T) {
	pinned := parser.CopilotMarketplaceSource{Source: "github", Repo: "a/b", SHA: "0123456789abcdef0123456789abcdef01234567"}
	for _, entry := range []parser.CopilotMarketplace{
		{Source: pinned},
		{AutoUpdate: false, Source: pinned},
	} {
		f := CFG089.Check(copilotSettingsTarget(&parser.CopilotSettings{
			ExtraKnownMarketplaces: map[string]parser.CopilotMarketplace{"acme": entry},
		}))
		if len(f) != 0 {
			t.Errorf("expected no finding for %+v, got %+v", entry, f)
		}
	}
}
