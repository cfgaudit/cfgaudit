// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg135 struct{}

// CFG135 reports a plugin.json component path that leaves the plugin root
// (#1410): absolute, starting with ~, or resolving above the root through ../.
// CVE-2026-44641 (an agent package manager) installed files from outside the
// package this way. cfgaudit does not follow such a path.
var CFG135 = &cfg135{}

func init() { All = append(All, CFG135) }

func (r *cfg135) ID() string { return "CFG135" }

func (r *cfg135) Check(t *Target) []finding.Finding {
	if t == nil || t.PluginManifest == nil {
		return nil
	}
	var findings []finding.Finding
	for _, c := range t.PluginManifest.ManifestComponentPaths() {
		if !parser.ManifestPathEscapes(c.Path) {
			continue
		}
		sev := finding.Warn
		why := "a reviewer of the plugin does not see the file it loads, and the file depends on the machine that installs it"
		hint := ""
		p := strings.ReplaceAll(strings.TrimSpace(c.Path), `\`, "/")
		if strings.HasPrefix(p, "../") {
			// The most common form in real manifests is "../hooks/hooks.json",
			// written as if paths resolved against .claude-plugin/ (#1410).
			hint = ". Paths resolve against the plugin root, the folder that holds .claude-plugin/, not against .claude-plugin/ itself"
		} else if sensitiveLinkTarget(c.Path) {
			// A relative path lands wherever the plugin is installed; an
			// absolute or ~ path names the same place on every machine.
			sev = finding.Error
			why = "it names a sensitive location on the machine that installs the plugin"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG135",
			Severity: sev,
			File:     t.PluginManifestFile,
			Key:      c.Field,
			Message: "plugin.json " + c.Field + " names \"" + c.Path + "\", which leaves the plugin root, so " + why + hint +
				". Keep component paths relative and inside the plugin (\"./" + c.Field + "/...\"); cfgaudit does not follow this path" + userScopeNote(t),
		})
	}
	return findings
}
