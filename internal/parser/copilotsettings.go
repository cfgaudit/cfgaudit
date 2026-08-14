package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// CopilotSettings is the subset of GitHub Copilot's repository-level
// `.github/copilot/settings.json` that cfgaudit reads: the two keys that cause
// third-party code to be installed and enabled without the user choosing it.
//
// Committability is stated, not inferred. The CLI configuration reference says
// repository settings "are committed to the repository and shared with
// collaborators", and its repository-level table gives the merge behaviour as
// "Merged — repository overrides user for same key" for enabledPlugins,
// extraKnownMarketplaces and hooks, with "Repository takes precedence" for
// disableAllHooks. So a committed entry does not merely add to a teammate's
// configuration, it wins over their own value for the same key.
type CopilotSettings struct {
	// EnabledPlugins auto-installs plugins declaratively. Keys are plugin specs
	// of the form PLUGIN-NAME@MARKETPLACE-NAME; the value enables or disables.
	EnabledPlugins map[string]bool `json:"enabledPlugins,omitempty"`

	// ExtraKnownMarketplaces registers marketplaces plugins may be installed
	// from, keyed by marketplace name.
	ExtraKnownMarketplaces map[string]CopilotMarketplace `json:"extraKnownMarketplaces,omitempty"`

	// Hooks is the inline hook table, the twin of .github/hooks/*.json. From the
	// shipped CLI's own settings help (1.0.80):
	//
	//	`hooks`: inline hook definitions, keyed by event name (same schema as
	//	.github/hooks/*.json).
	//	  - In global config.json these act as user-level hooks; in repo
	//	    settings.json they act as repo-level hooks
	//
	// Same schema means the shared AgentHooks shape decodes it, so the whole hook
	// family applies without a second decoder. This is the Codex #431 situation:
	// a file form and an inline form of one surface, both of which have to be read.
	Hooks map[string][]AgentHook `json:"hooks,omitempty"`

	// DisableAllHooks is global rather than per-file. The same help text:
	//
	//	`disableAllHooks`: whether to disable all hooks (repo-level and
	//	user-level); defaults to `false`.
	//
	// So a repository setting it true silences the inline table above AND every
	// .github/hooks/*.json in the same repo, and the docs give it "Repository
	// takes precedence" over the user's value. Reporting hooks past it would be
	// the false positive #433 found in Continue's equivalent.
	DisableAllHooks bool `json:"disableAllHooks,omitempty"`
}

// InlineHooks returns the inline hook table as the shared AgentHooks shape, with
// the effective disable flag applied, or nil when the file declares no hooks.
func (c *CopilotSettings) InlineHooks() *AgentHooks {
	if c == nil || len(c.Hooks) == 0 {
		return nil
	}
	return &AgentHooks{DisableAllHooks: c.DisableAllHooks, Hooks: c.Hooks}
}

// HooksDisabled reports whether this file switches every Copilot hook off, its
// own inline table and the .github/hooks/*.json files alike.
func (c *CopilotSettings) HooksDisabled() bool {
	return c != nil && c.DisableAllHooks
}

// CopilotMarketplace wraps the doubled nesting Copilot's schema really uses:
// the marketplace object has one key, `source`, whose value is itself an object
// with a `source` discriminator. The repetition is genuine, not a typo.
type CopilotMarketplace struct {
	Source CopilotMarketplaceSource `json:"source,omitempty"`
}

// CopilotMarketplaceSource describes where a marketplace's contents come from.
//
// The documented source types for a *marketplace* entry are "github" (requires
// repo, optional ref/path), "git" (requires url, optional ref/path) and
// "directory" (requires path). SHA is decoded because Copilot documents `sha` as
// a full 40-character commit pin for plugin sources — an author who writes it
// here has pinned the source, and cfgaudit honours that rather than reporting an
// entry the author took care over.
type CopilotMarketplaceSource struct {
	Source string `json:"source,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Ref    string `json:"ref,omitempty"`
	SHA    string `json:"sha,omitempty"`
	Path   string `json:"path,omitempty"`
	URL    string `json:"url,omitempty"`
}

// Remote reports whether the source pulls from somewhere outside the repository.
// A "directory" source is on disk and carries no upstream trust edge.
func (s CopilotMarketplaceSource) Remote() bool {
	switch s.Source {
	case "github", "git":
		return true
	default:
		// An unset discriminator with a repo or url is still a remote pull; an
		// unrecognised type with neither is not treated as one.
		return s.Repo != "" || s.URL != ""
	}
}

// Location returns the human-readable origin of the source for a finding
// message, preferring whichever locator its type requires.
func (s CopilotMarketplaceSource) Location() string {
	switch {
	case s.Repo != "":
		return s.Repo
	case s.URL != "":
		return s.URL
	default:
		return s.Path
	}
}

// ParseCopilotSettings reads a .github/copilot/settings.json. A missing key
// yields a zero value; a malformed file is an error, so a settings file that is
// silently not being scanned is reported rather than mistaken for an empty one.
func ParseCopilotSettings(path string) (*CopilotSettings, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c CopilotSettings
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}
