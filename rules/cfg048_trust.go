// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// fixedIn11453 qualifies a value that VS Code 1.145.3 (2026-11-10) stopped
// honouring from a workspace file: 1.145.2 and earlier apply it, and so may
// forks that took the settings code before that release.
const fixedIn11453 = " Fixed in VS Code 1.145.3; 1.145.2 and earlier, and forks that read the same file, apply it."

// workspaceTrustGroups are the keys that only group the Workspace Trust
// settings. A plain value at any of them replaced every setting below it on
// 1.145.2 and earlier, so security.workspace.trust.enabled was not found and
// Workspace Trust counted as off (CVE-2026-121663).
var workspaceTrustGroups = []string{"security", "security.workspace", "security.workspace.trust"}

// checkTrustBypass reports the workspace values behind three Workspace Trust
// bypasses fixed in VS Code 1.145.3 (#1799):
//
//   - a __proto__ key (CVE-2026-121662, GHSA-fp22-hgv9-mq6q; fixes 0f9fbff and
//     e64c53e): merging the workspace configuration changed the shared object
//     prototype, and a workspace in Restricted Mode could have its own MCP
//     server started. It has no use in a settings file: error;
//   - a non-object value at a key that groups the Workspace Trust settings
//     (CVE-2026-121663, GHSA-x5cm-xmvw-73rv; fix 99c4193): Workspace Trust
//     counted as off, so a development-mode MCP server of the workspace started
//     on open: error;
//   - experiments.override.<treatment> (CVE-2026-121665, GHSA-c367-h9jc-pjr7;
//     fix 7a1a8e4): the unregistered key set the default of an
//     experiment-controlled setting, restricted ones included, in Restricted
//     Mode. It takes effect only once a feature reads such a setting: warn.
func (r *cfg048) checkTrustBypass(t *Target) []finding.Finding {
	s := t.VSCodeSettings
	var findings []finding.Finding
	add := func(sev finding.Severity, key, msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG048", Severity: sev, Scope: t.Scope, File: t.VSCodeSettingsFile, Key: key, Message: msg})
	}
	if paths := protoKeyPaths(s.Raw); len(paths) > 0 {
		add(finding.Error, "__proto__", "a __proto__ key ("+quoteList(paths)+") changed the shared object prototype while VS Code merged the workspace configuration, so a workspace in Restricted Mode could have its own MCP server started with no trust decision (CVE-2026-121662)."+fixedIn11453+" The key has no use in a settings file. Remove it")
	}
	for _, key := range workspaceTrustGroups {
		raw, ok := s.RawValue(key)
		if !ok || isJSONObjectValue(raw) || strings.TrimSpace(string(raw)) == "null" {
			continue
		}
		add(finding.Error, key, key+" is set to a plain value, which replaced every setting below it: security.workspace.trust.enabled was not found, Workspace Trust counted as off, and a development-mode MCP server of the workspace started when the folder opened (CVE-2026-121663)."+fixedIn11453+" Remove it")
		break
	}
	if overrides, ok := s.ObjectField("experiments.override"); ok && len(overrides) > 0 {
		add(finding.Warn, "experiments.override", "experiments.override sets experiment treatments ("+quoteList(sortedRawKeys(overrides))+"), which became the defaults of the settings they control, restricted ones included, even in Restricted Mode (CVE-2026-121665)."+fixedIn11453+" A committed workspace file has no use for them. Remove it")
	}
	return findings
}

// protoKeyPaths returns the paths of the __proto__ keys in a settings file,
// sorted. A top-level key counts when one of its dotted segments is
// __proto__, because VS Code splits it on "." into the value tree; a key inside
// a nested object counts only as a whole, because that one is not split.
func protoKeyPaths(raw map[string]json.RawMessage) []string {
	var paths []string
	for key, val := range raw {
		for _, seg := range strings.Split(key, ".") {
			if seg == "__proto__" {
				paths = append(paths, key)
				break
			}
		}
		paths = append(paths, nestedProtoPaths(key, val)...)
	}
	sort.Strings(paths)
	return paths
}

func nestedProtoPaths(path string, raw json.RawMessage) []string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		var paths []string
		for k, v := range obj {
			p := path + " > " + k
			if k == "__proto__" {
				paths = append(paths, p)
			}
			paths = append(paths, nestedProtoPaths(p, v)...)
		}
		return paths
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		var paths []string
		for _, v := range arr {
			paths = append(paths, nestedProtoPaths(path+" > []", v)...)
		}
		return paths
	}
	return nil
}

// isJSONObjectValue reports whether raw is a JSON object.
func isJSONObjectValue(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	return json.Unmarshal(raw, &obj) == nil && obj != nil
}
