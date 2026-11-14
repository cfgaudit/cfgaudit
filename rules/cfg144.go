// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"path/filepath"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg144 struct{}

// CFG144 reports an entry of an Antigravity CLI discovery manifest
// (.agents/skills.json, plugins.json, rules.json, agents.json) that points
// outside the repository: an absolute path, a path that leaves it through
// "../", or a symbolic link that leads out of it (#1639). What it names is not
// in the repository, so cfgaudit cannot check it.
var CFG144 = &cfg144{}

func init() { All = append(All, CFG144) }

func (r *cfg144) ID() string { return "CFG144" }

// AntigravityOutsideEntry is one manifest entry that points outside the
// repository.
type AntigravityOutsideEntry struct {
	// File is the manifest; Field is "entries" or "inherits", Index the
	// entry's position in it.
	File, Field string
	Index       int
	// Path is the entry's path as committed; Reason says how it leaves the
	// repository.
	Path, Reason string
}

func (r *cfg144) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	for _, e := range t.AntigravityOutside {
		name := filepath.Base(e.File)
		var effect string
		switch {
		case e.Field == "inherits":
			effect = "Antigravity CLI adds the entries of the manifest it names"
		case name == "skills.json" || name == "plugins.json":
			effect = "Antigravity CLI 1.5.2 and later skip it; earlier versions load what it names"
		default:
			effect = "The Antigravity docs show such paths loading from " + name
		}
		out = append(out, finding.Finding{
			RuleID:   "CFG144",
			Severity: finding.Info,
			File:     e.File,
			Message: fmt.Sprintf("%s %s[%d].path %q points outside the repository (%s). %s, and cfgaudit cannot check what is there. Keep the customizations in the repository, or let each user add the folder in their own ~/.gemini/config/%s",
				name, e.Field, e.Index, e.Path, e.Reason, effect, name),
		})
	}
	return out
}
