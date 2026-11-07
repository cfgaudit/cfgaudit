// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg126 struct{}

var CFG126 = &cfg126{}

func init() { All = append(All, CFG126) }

func (r *cfg126) ID() string { return "CFG126" }

type npmVersion struct {
	major, minor, patch int
}

func (v npmVersion) less(other npmVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

type mcpPackageAdvisory struct {
	packageName  string
	introduced   npmVersion // inclusive
	lastAffected npmVersion // inclusive; do not infer unpublished gaps up to fixedText
	affected     string
	fixedText    string
	advisoryID   string
	note         string
}

// reviewedMCPPackageAdvisories is deliberately small and offline. Add an entry
// only from a primary/vendor advisory, add its ID to docs/advisories.yml so the
// weekly validity job checks it, and update the reviewed date in CFG126.md.
var reviewedMCPPackageAdvisories = []mcpPackageAdvisory{
	{
		packageName: "mcp-remote", introduced: npmVersion{0, 0, 5}, lastAffected: npmVersion{0, 1, 15},
		affected: ">=0.0.5 <0.1.16", fixedText: "0.1.16", advisoryID: "CVE-2025-6514 / GHSA-6xpm-ggf7-wc3p",
	},
	{
		packageName: "@modelcontextprotocol/inspector", introduced: npmVersion{0, 0, 0}, lastAffected: npmVersion{0, 14, 0},
		affected: "<0.14.1", fixedText: "0.14.1", advisoryID: "CVE-2025-49596 / GHSA-7f8r-222p-6f5g",
	},
	{
		packageName: "@modelcontextprotocol/inspector", introduced: npmVersion{2, 0, 0}, lastAffected: npmVersion{2, 11, 0},
		affected: ">=2.0.0 <=2.11.0", fixedText: "2.12.0", advisoryID: "GHSA-q978-78c7-phqw",
		note: " The published impact is limited to Windows and WSL hosts.",
	},
}

func (r *cfg126) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		seen := map[string]bool{}
		for _, spec := range npmPackageSpecs(ref.Server.Command, ref.Server.Args) {
			name, rawVersion, version, ok := exactNPMVersion(spec)
			if !ok || seen[name+"\x00"+rawVersion] {
				continue
			}
			seen[name+"\x00"+rawVersion] = true
			for _, advisory := range reviewedMCPPackageAdvisories {
				if !strings.EqualFold(name, advisory.packageName) || version.less(advisory.introduced) || advisory.lastAffected.less(version) {
					continue
				}
				findings = append(findings, finding.Finding{
					RuleID: "CFG126", Severity: finding.Error, File: ref.File,
					Key: "mcpServers." + ref.Name + ".args",
					Message: fmt.Sprintf("mcpServers.%s launches %s@%s, which is in the known-vulnerable range %s (%s; fixed in %s). Upgrade the pinned package to %s or later.%s",
						ref.Name, name, rawVersion, advisory.affected, advisory.advisoryID, advisory.fixedText, advisory.fixedText, advisory.note),
				})
			}
		}
	}
	return findings
}

var exactNPMVersionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z.-]+)?$`)

// exactNPMVersion splits an npm package spec and accepts only a complete,
// stable, exact version. Tags, npm aliases, ranges, shortened versions,
// prereleases and malformed values remain unknown rather than being called
// vulnerable. CFG010 separately reports missing and floating pins.
func exactNPMVersion(spec string) (string, string, npmVersion, bool) {
	name := npmPackageName(spec)
	if name == spec || name == "" {
		return "", "", npmVersion{}, false
	}
	raw := spec[len(name)+1:]
	m := exactNPMVersionRe.FindStringSubmatch(raw)
	if m == nil {
		return "", "", npmVersion{}, false
	}
	parts := [3]int{}
	for i := range parts {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return "", "", npmVersion{}, false
		}
		parts[i] = n
	}
	return name, raw, npmVersion{parts[0], parts[1], parts[2]}, true
}
