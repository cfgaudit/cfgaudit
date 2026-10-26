// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/schema"
)

type cfg012 struct{}

var CFG012 = &cfg012{}

func init() { All = append(All, CFG012) }

func (r *cfg012) ID() string { return "CFG012" }

func (r *cfg012) Check(t *Target) []finding.Finding {
	if t.Settings == nil || len(t.Settings.Raw) == 0 {
		return nil
	}
	spec := schema.TopLevelProperties()

	keys := make([]string, 0, len(t.Settings.Raw))
	for k := range t.Settings.Raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var findings []finding.Finding
	for _, k := range keys {
		if k == "$schema" {
			continue
		}
		ps, known := spec[k]
		if !known {
			if schema.KnownButUnschemaed[k] {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG012",
				Severity: finding.Warn,
				File:     t.SettingsFile,
				Key:      k,
				Message:  "unknown top-level key \"" + k + "\" — not defined in the bundled Claude Code settings schema. The bundled schema may lag behind newer Claude Code releases; if this key was added upstream recently, the warning is safe to suppress. Otherwise it likely indicates a typo or stale configuration.",
			})
			continue
		}
		if len(ps.AllowedTypes) == 0 {
			continue
		}
		actual := jsonTypeOf(t.Settings.Raw[k])
		if !stringInSlice(actual, ps.AllowedTypes) && !singleServerName(k, t.Settings.Raw[k], t.ClaudeVersion) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG012",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Key:      k,
				Message: "key \"" + k + "\" has JSON type " + actual + " but the schema expects " + strings.Join(ps.AllowedTypes, " or ") +
					" — Claude Code does not ignore the value, it discards this settings file whole, so every permission rule, hook and env entry in it is inert, with nothing printed to say so. Fix the type (an unknown key would be tolerated; a wrong type on a known one is not)",
			})
		}
	}
	return append(findings, guardHookFindings(t)...)
}

// guardHookFindings reports the PreToolUse/PermissionRequest entries that make
// Claude Code drop the file (#639). Every defect is listed, so fixing the first
// does not reveal a second one on the next scan. A defect that only drops the
// file from a later release than the detected one is a warn: this install still
// loads the file, newer ones reading the same repository do not.
func guardHookFindings(t *Target) []finding.Finding {
	var out []finding.Finding
	for _, d := range GuardHookDefects(t.Settings, nil) {
		sev := finding.Error
		consequence := "Claude Code discards this settings file whole"
		if d.FromVersion != "" {
			consequence = "Claude Code " + d.FromVersion + " and later discard this settings file whole"
			if t.ClaudeVersion != nil && !t.ClaudeVersion.AtLeast(onFailureMinVersion) {
				sev = finding.Warn
				consequence += " (the detected " + t.ClaudeVersion.String() + " still ignores the value)"
			}
		}
		out = append(out, finding.Finding{
			RuleID:   "CFG012",
			Severity: sev,
			File:     t.SettingsFile,
			Message: d.Path + " " + d.Reason + ". A PreToolUse or PermissionRequest hook that cannot be loaded may be what guards the permissions beside it, so " +
				consequence + ": every permission rule, hook and env entry in it is inert, with nothing printed to say so (`claude doctor` names it). Fix or remove the entry; under any other hook event the same mistake only skips that one entry",
		})
	}
	return out
}

func jsonTypeOf(raw json.RawMessage) string {
	trimmed := bytes.TrimLeft(raw, " \t\n\r")
	if len(trimmed) == 0 {
		return "null"
	}
	switch trimmed[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

func stringInSlice(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
