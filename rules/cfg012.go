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
				Message:  "unknown top-level key \"" + k + "\" — not defined in the bundled Claude Code settings schema. The bundled schema may lag behind newer Claude Code releases; if this key was added upstream recently, the warning is safe to suppress. Otherwise it likely indicates a typo or stale configuration.",
			})
			continue
		}
		if len(ps.AllowedTypes) == 0 {
			continue
		}
		actual := jsonTypeOf(t.Settings.Raw[k])
		if !stringInSlice(actual, ps.AllowedTypes) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG012",
				Severity: finding.Warn,
				File:     t.SettingsFile,
				Message:  "key \"" + k + "\" has JSON type " + actual + " but the schema expects " + strings.Join(ps.AllowedTypes, " or ") + " — type mismatches usually indicate a malformed value or a deliberate attempt to confuse downstream parsers",
			})
		}
	}
	return findings
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
