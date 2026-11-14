// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"fmt"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// AntigravityManifest is one of Antigravity CLI's discovery manifests,
// .agents/skills.json, plugins.json, rules.json or agents.json (#1639,
// antigravity.google/docs/customization-discovery). Each adds folders or
// single items to the standard folders; it does not replace them.
type AntigravityManifest struct {
	// Entries are folders scanned one level deep, or the folder or file of a
	// single item.
	Entries []AntigravityManifestEntry `json:"entries"`
	// Inherits name other manifests whose entries are added too.
	Inherits []AntigravityManifestEntry `json:"inherits"`
	// Exclude hides items by name or relative path.
	Exclude []string `json:"exclude"`
}

// AntigravityManifestEntry is one entries or inherits object.
type AntigravityManifestEntry struct {
	Path        string   `json:"path"`
	IncludeOnly []string `json:"include_only"`
	Exclude     []string `json:"exclude"`
}

// ParseAntigravityManifest reads a discovery manifest. Comments and trailing
// commas are tolerated like in mcp_config.json; keys the docs do not name are
// ignored.
func ParseAntigravityManifest(path string) (*AntigravityManifest, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m AntigravityManifest
	if err := json.Unmarshal(stripJSONC(data), &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &m, nil
}
