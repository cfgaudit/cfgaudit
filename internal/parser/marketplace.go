package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Marketplace is a partial representation of a Claude Code plugin marketplace
// manifest (.claude-plugin/marketplace.json). It is the supply-chain document of
// the plugin system: one `source` per entry, saying where the code is fetched
// from when someone installs the plugin.
//
// This is author-side coverage, like .claude-plugin/plugin.json and
// kimi.plugin.json: the file is committed and pushed, and it describes what gets
// installed on other people's machines.
type Marketplace struct {
	Name    string              `json:"name"`
	Plugins []MarketplacePlugin `json:"plugins"`
}

// MarketplacePlugin is one entry. Source is kept raw because it has two
// spellings: a bare string, which is a path relative to the marketplace repo,
// and an object naming an external source. The string form is by far the common
// one (2,616 of the entries in a 292-file sample) and points inside the
// marketplace repository itself, so it carries no external fetch to audit.
type MarketplacePlugin struct {
	Name   string          `json:"name"`
	Source json.RawMessage `json:"source"`
}

// MarketplaceSource is the object form of a plugin source. The type discriminator
// is the `source` key; a stray `type` spelling is tolerated because the corpus
// contains one.
//
// Which field pins the fetch depends on the type:
//
//	github      repo, ref?, sha?          — sha is immutable
//	url         url, ref?, sha?           — sha is immutable
//	git-subdir  url, path, ref?, sha?     — sha is immutable
//	npm         package, version?, registry?
//	archive     url, sha256?              — sha256 is the only pin there is
//	command     command, timeout?, mode?  — nothing to pin: the directory is
//	                                        produced by running the command
type MarketplaceSource struct {
	Type     string `json:"source"`
	AltType  string `json:"type"`
	URL      string `json:"url"`
	Repo     string `json:"repo"`
	Path     string `json:"path"`
	Ref      string `json:"ref"`
	SHA      string `json:"sha"`
	SHA256   string `json:"sha256"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Registry string `json:"registry"`

	// Command is the shell command of a `command` source, documented upstream as
	// a "Shell command that prints the absolute path of the plugin directory on
	// stdout (exactly one line) and exits 0". Timeout is its budget in seconds
	// (default 60) and Mode is "copy" (default) or "link"; link uses the produced
	// directory in place, so the plugin content stays under the producer's control
	// after install.
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
	Mode    string `json:"mode"`

	// HeadersHelper is a command that mints HTTP headers for the fetch. It is
	// declared on a marketplace's own source or on a catalog entry, applies to
	// archive fetches, and runs at explicit install or update after the command
	// has been shown. Claude Code's settings validator types it as a string on
	// `extraKnownMarketplaces.<name>.source.headersHelper`.
	HeadersHelper string `json:"headersHelper"`
}

// Kind returns the normalised source type.
func (s MarketplaceSource) Kind() string {
	t := strings.TrimSpace(s.Type)
	if t == "" {
		t = strings.TrimSpace(s.AltType)
	}
	return strings.ToLower(t)
}

// NamedMarketplaceSource pairs a decoded source with the plugin entry it belongs
// to, so a finding can name the plugin rather than an index.
type NamedMarketplaceSource struct {
	Plugin string
	Source MarketplaceSource
}

// ExternalSources returns the entries whose source is an object, which are the
// ones naming an external fetch. String-shorthand entries are skipped: they are a
// path inside the marketplace repository, so the repository under review is
// already the thing being audited.
//
// A source object that fails to decode is skipped rather than reported. The
// schema gains types over time (`archive` only landed in Claude Code 2.1.224),
// and refusing to parse a newer shape would turn a forward-compatible manifest
// into a scan error.
func (m *Marketplace) ExternalSources() []NamedMarketplaceSource {
	if m == nil {
		return nil
	}
	var out []NamedMarketplaceSource
	for _, p := range m.Plugins {
		if len(p.Source) == 0 {
			continue
		}
		var src MarketplaceSource
		if err := json.Unmarshal(p.Source, &src); err != nil {
			continue // the string shorthand, or a shape this version does not model
		}
		if src.Kind() == "" {
			continue
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = "(unnamed)"
		}
		out = append(out, NamedMarketplaceSource{Plugin: name, Source: src})
	}
	return out
}

// ParseMarketplace reads and decodes a .claude-plugin/marketplace.json.
func ParseMarketplace(path string) (*Marketplace, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied plugin tree
	if err != nil {
		return nil, err
	}
	var m Marketplace
	if err := json.Unmarshal(stripJSONC(data), &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &m, nil
}
