// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/maliciousioc"
)

type cfg128 struct{}

var CFG128 = &cfg128{}

func init() { All = append(All, CFG128) }

func (r *cfg128) ID() string { return "CFG128" }

// Check compares only exact npm package/version pairs launched by MCP runner
// forms with the reviewed offline IOC set. It deliberately shares extraction
// with CFG010/CFG059/CFG126, but not CFG126's vulnerability-range data.
func (r *cfg128) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		for _, spec := range npmPackageSpecs(ref.Server.Command, ref.Server.Args) {
			name, _, version, ok := exactNPMVersion(spec)
			if !ok {
				continue
			}
			canonical := fmt.Sprintf("%d.%d.%d", version.major, version.minor, version.patch)
			key := name + "@" + canonical
			ioc, matched := maliciousioc.MatchNPM(name, canonical)
			if !matched {
				continue
			}
			out = append(out, finding.Finding{
				RuleID: "CFG128", Severity: finding.Error, File: ref.File,
				Key: "mcpServers." + ref.Name + ".args",
				Message: "mcpServers." + ref.Name + " launches known-malicious npm artifact " + key +
					" (campaign: " + ioc.Campaign + "). This exact IOC match is evidence requiring incident-response review, not proof that the package executed or that this machine was compromised. Remove the server and artifact, inspect package-manager caches and campaign persistence, and rotate potentially exposed credentials as appropriate",
			})
		}
	}
	return out
}
