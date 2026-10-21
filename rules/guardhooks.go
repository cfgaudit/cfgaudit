// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

// guardHookEvents are the hook events whose entries Claude Code treats as a
// guard over the permissions beside them. One entry under either that cannot be
// loaded makes Claude Code drop the whole settings file; under every other event
// only that entry is skipped (#639).
var guardHookEvents = []string{"PreToolUse", "PermissionRequest"}

// onFailureMinVersion is the release that added the hook field onFailure. From
// there a value outside its enum is a load failure; before it the key was
// unknown and stripped.
var onFailureMinVersion = version.Version{Major: 2, Minor: 1, Patch: 295}

// GuardHookDefect is one entry under a guard hook event that Claude Code cannot
// load. Path names the entry the way a reader finds it in the file.
type GuardHookDefect struct {
	Path   string
	Reason string
	// FromVersion is set when the defect only drops the file from that release
	// on (onFailure); empty when every release measured rejects it.
	FromVersion string
}

// hookField is one field Claude Code validates on a hook entry: its JSON type
// and, where measured, a narrower constraint on the value.
type hookField struct {
	kind     string // "string", "number", "boolean", "object", "array"
	required bool
	check    func(json.RawMessage) string // returns a reason, or "" when valid
	since    *version.Version             // validated only from this release
}

// hookCommonFields are validated on every hook type.
var hookCommonFields = map[string]hookField{
	"timeout":       {kind: "number", check: positiveNumber},
	"if":            {kind: "string"},
	"statusMessage": {kind: "string"},
	"once":          {kind: "boolean"},
}

// hookTypeFields are the fields each hook type validates on top of the common
// ones. A field that belongs to another type is stripped, not rejected: "model":
// 5 drops the file on a prompt hook and is ignored on a command hook.
//
// Measured against 2.1.296 with a SessionStart marker in settings.local.json and
// the entry under test in settings.json. Notable non-obvious results: an empty
// "command" or "prompt" loads (the bundled schema's minLength is not enforced),
// "url" must parse as an absolute URL (ftp:// and mailto: load, "" and "/h" do
// not), and timeout must be greater than zero.
var hookTypeFields = map[string]map[string]hookField{
	"command": {
		"command":     {kind: "string", required: true},
		"async":       {kind: "boolean"},
		"asyncRewake": {kind: "boolean"},
		"shell":       {kind: "string", check: oneOf("bash", "powershell")},
		"onFailure":   {kind: "string", check: oneOf("continue", "block"), since: &onFailureMinVersion},
	},
	"prompt": {
		"prompt": {kind: "string", required: true},
		"model":  {kind: "string"},
	},
	"agent": {
		"prompt": {kind: "string", required: true},
		"model":  {kind: "string"},
	},
	"http": {
		"url":            {kind: "string", required: true, check: absoluteURL},
		"headers":        {kind: "object", check: stringValues},
		"allowedEnvVars": {kind: "array", check: stringItems},
		"onFailure":      {kind: "string", check: oneOf("continue", "block"), since: &onFailureMinVersion},
	},
	"mcp_tool": {
		"server": {kind: "string", required: true},
		"tool":   {kind: "string", required: true},
		"input":  {kind: "object"},
	},
}

// GuardHookDefects returns the entries under PreToolUse and PermissionRequest
// that Claude Code cannot load, in file order.
//
// ver is the Claude Code release the scan targets. A defect that only became one
// in a later release is reported when ver is nil or at least that release: this
// detection only ever adds findings (the deny block stops counting, CFG012
// reports the discard), so an unknown version takes the reading that reports.
func GuardHookDefects(s *parser.Settings, ver *version.Version) []GuardHookDefect {
	if s == nil {
		return nil
	}
	raw, ok := s.Raw["hooks"]
	if !ok {
		return nil
	}
	var events map[string]json.RawMessage
	if json.Unmarshal(raw, &events) != nil {
		return nil // a non-object hooks value is a top-level type mismatch
	}
	var out []GuardHookDefect
	for _, ev := range guardHookEvents {
		val, ok := events[ev]
		if !ok {
			continue
		}
		out = append(out, guardEventDefects(ev, val, ver)...)
	}
	return out
}

func guardEventDefects(ev string, val json.RawMessage, ver *version.Version) []GuardHookDefect {
	path := "hooks." + ev
	var groups []json.RawMessage
	if jsonTypeOf(val) != "array" || json.Unmarshal(val, &groups) != nil {
		return []GuardHookDefect{{Path: path, Reason: "is " + jsonTypeOf(val) + ", not an array of matcher groups"}}
	}
	var out []GuardHookDefect
	for i, g := range groups {
		gpath := fmt.Sprintf("%s[%d]", path, i)
		var group map[string]json.RawMessage
		if jsonTypeOf(g) != "object" || json.Unmarshal(g, &group) != nil {
			out = append(out, GuardHookDefect{Path: gpath, Reason: "is " + jsonTypeOf(g) + ", not a matcher group object"})
			continue
		}
		if m, ok := group["matcher"]; ok && jsonTypeOf(m) != "string" {
			out = append(out, GuardHookDefect{Path: gpath + ".matcher", Reason: "is " + jsonTypeOf(m) + ", not a string"})
		}
		hooks, ok := group["hooks"]
		if !ok {
			reason := "has no \"hooks\" array"
			if _, flat := group["command"]; flat {
				// The flat {"matcher", "command"} shape, 6 of the 7 corpus files
				// this check found; the fix is mechanical, so say what it is.
				reason += " (it uses the old flat {\"matcher\", \"command\"} shape; nest the command as \"hooks\": [{\"type\": \"command\", \"command\": ...}])"
			}
			out = append(out, GuardHookDefect{Path: gpath, Reason: reason})
			continue
		}
		var entries []json.RawMessage
		if jsonTypeOf(hooks) != "array" || json.Unmarshal(hooks, &entries) != nil {
			out = append(out, GuardHookDefect{Path: gpath + ".hooks", Reason: "is " + jsonTypeOf(hooks) + ", not an array"})
			continue
		}
		for j, e := range entries {
			out = append(out, hookEntryDefects(fmt.Sprintf("%s.hooks[%d]", gpath, j), e, ver)...)
		}
	}
	return out
}

func hookEntryDefects(path string, e json.RawMessage, ver *version.Version) []GuardHookDefect {
	var entry map[string]json.RawMessage
	if jsonTypeOf(e) != "object" || json.Unmarshal(e, &entry) != nil {
		return []GuardHookDefect{{Path: path, Reason: "is " + jsonTypeOf(e) + ", not a hook object"}}
	}
	typ, ok := entry["type"]
	if !ok {
		return []GuardHookDefect{{Path: path, Reason: "has no \"type\""}}
	}
	var name string
	if jsonTypeOf(typ) != "string" || json.Unmarshal(typ, &name) != nil {
		return []GuardHookDefect{{Path: path + ".type", Reason: "is " + jsonTypeOf(typ) + ", not a string"}}
	}
	fields, known := hookTypeFields[name]
	if !known {
		return []GuardHookDefect{{Path: path + ".type", Reason: fmt.Sprintf("%q is not a hook type Claude Code knows (command, prompt, agent, http, mcp_tool)", name)}}
	}

	var out []GuardHookDefect
	check := func(key string, f hookField) {
		v, present := entry[key]
		if !present {
			if f.required {
				out = append(out, GuardHookDefect{Path: path, Reason: fmt.Sprintf("is a %s hook without the required %q", name, key)})
			}
			return
		}
		var from string
		if f.since != nil {
			if ver != nil && !ver.AtLeast(*f.since) {
				return
			}
			from = f.since.String()
		}
		reason := ""
		if got := jsonTypeOf(v); got != f.kind {
			reason = "is " + got + ", not a " + f.kind
		} else if f.check != nil {
			reason = f.check(v)
		}
		if reason != "" {
			out = append(out, GuardHookDefect{Path: path + "." + key, Reason: reason, FromVersion: from})
		}
	}
	for _, key := range sortedFieldKeys(hookCommonFields) {
		check(key, hookCommonFields[key])
	}
	for _, key := range sortedFieldKeys(fields) {
		check(key, fields[key])
	}
	return out
}

func sortedFieldKeys(m map[string]hookField) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func oneOf(allowed ...string) func(json.RawMessage) string {
	return func(v json.RawMessage) string {
		var s string
		_ = json.Unmarshal(v, &s)
		for _, a := range allowed {
			if s == a {
				return ""
			}
		}
		return fmt.Sprintf("is %q, not one of %q", s, allowed)
	}
}

func positiveNumber(v json.RawMessage) string {
	var n float64
	if json.Unmarshal(v, &n) != nil || n <= 0 {
		return "is " + string(v) + ", but it must be greater than 0"
	}
	return ""
}

// absoluteURL matches what the runtime accepts: anything with a scheme parses
// (ftp: and mailto: load), a relative reference or an empty string does not.
func absoluteURL(v json.RawMessage) string {
	var s string
	_ = json.Unmarshal(v, &s)
	if u, err := url.Parse(s); err != nil || u.Scheme == "" {
		return fmt.Sprintf("is %q, which is not an absolute URL", s)
	}
	return ""
}

func stringValues(v json.RawMessage) string {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(v, &m)
	for _, k := range sortedRawKeys(m) {
		if jsonTypeOf(m[k]) != "string" {
			return fmt.Sprintf("has %q set to a %s, not a string", k, jsonTypeOf(m[k]))
		}
	}
	return ""
}

func stringItems(v json.RawMessage) string {
	var items []json.RawMessage
	_ = json.Unmarshal(v, &items)
	for i, it := range items {
		if jsonTypeOf(it) != "string" {
			return fmt.Sprintf("has item %d as a %s, not a string", i, jsonTypeOf(it))
		}
	}
	return ""
}
