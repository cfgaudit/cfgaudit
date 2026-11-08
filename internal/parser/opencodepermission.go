// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// OpenCodePermissionRule is one rule of an OpenCode permission block, flattened
// into the shape the agent's own resolver uses: an action (the permission key,
// or "*"), a resource (the pattern inside a nested object, or "*") and an
// effect.
//
// Order is preserved because it decides the outcome. OpenCode resolves a call
// with `findLast` over the concatenated rulesets
// (packages/core/src/permission.ts), and its config parser keeps the file's key
// order on purpose: "Runtime config parsing uses Effect's `propertyOrder:
// "original"` parse option so user key order is preserved for permission
// precedence."
//
// Action uses the OpenCode 1 names the checks probe with. OpenCode 2 renamed
// some tools (normalizeAction in v1/config/migrate.ts: bash is shell, task is
// subagent), so a native rule is mapped back, and Native keeps how the file
// spelled it.
type OpenCodePermissionRule struct {
	Action   string
	Resource string
	Effect   string

	// Native is set on a rule from an OpenCode 2 `permissions` list and holds
	// its action as written.
	Native string
}

// Spelled is the action as the file wrote it.
func (r OpenCodePermissionRule) Spelled() string {
	if r.Native != "" {
		return r.Native
	}
	return r.Action
}

// OpenCodePermissionBlock is one permission declaration and where it came from.
type OpenCodePermissionBlock struct {
	// Where is "permission", "permissions", "agent.<name>.permission" or
	// "agents.<name>.permissions".
	Where string
	Rules []OpenCodePermissionRule
}

// Top reports whether the block is the top-level one, which every agent runs
// with before its own.
func (b OpenCodePermissionBlock) Top() bool {
	return b.Where == "permission" || b.Where == "permissions"
}

// PermissionBlocks returns the top-level permission block and each agent's, in
// declaration order, with the rules flattened. In each, the v1 `permission`
// rules come before the OpenCode 2 `permissions` list, as OpenCode 2 joins
// them.
func (c *OpenCodeConfig) PermissionBlocks() []OpenCodePermissionBlock {
	if c == nil {
		return nil
	}
	var out []OpenCodePermissionBlock
	add := func(v1, native json.RawMessage, where, nativeWhere string) {
		rules := decodeOpenCodePermission(v1)
		if c.V2 {
			for i := range rules {
				rules[i].Action = openCodeV1InV2Action(rules[i].Action)
			}
		}
		nr := decodeOpenCodeRuleset(native)
		if len(nr) > 0 {
			where = nativeWhere
		}
		if rules = append(rules, nr...); len(rules) > 0 {
			out = append(out, OpenCodePermissionBlock{Where: where, Rules: rules})
		}
	}
	add(c.Permission, c.Permissions, "permission", "permissions")
	names := make([]string, 0, len(c.Agent))
	for name := range c.Agent {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		a := c.Agent[name]
		add(a.Permission, a.Permissions, "agent."+name+".permission", "agents."+name+".permissions")
	}
	return out
}

// openCodeV1InV2Action is what OpenCode 2 makes of a v1 `permission` key
// (normalizeAction): write, patch and apply_patch become edit. bash and task
// become shell and subagent, which the checks spell bash and task anyway.
func openCodeV1InV2Action(action string) string {
	switch action {
	case "write", "patch", "apply_patch":
		return "edit"
	}
	return action
}

// openCodeNativeAction maps a native OpenCode 2 action onto the name the
// checks probe with. A native rule is not renamed by OpenCode, so only the two
// renamed tools are mapped.
func openCodeNativeAction(action string) string {
	switch action {
	case "shell":
		return "bash"
	case "subagent":
		return "task"
	}
	return action
}

// decodeOpenCodeRuleset decodes an OpenCode 2 `permissions` list. OpenCode
// decodes it entry by entry (decodeList), so an entry that is not a rule is
// dropped and the others still apply. The effect is one of allow, deny and
// ask, as written.
func decodeOpenCodeRuleset(raw json.RawMessage) []OpenCodePermissionRule {
	var entries []json.RawMessage
	if len(bytes.TrimSpace(raw)) == 0 || json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	var out []OpenCodePermissionRule
	for _, e := range entries {
		var r struct {
			Action   *string `json:"action"`
			Resource *string `json:"resource"`
			Effect   string  `json:"effect"`
		}
		if json.Unmarshal(e, &r) != nil || r.Action == nil || r.Resource == nil {
			continue
		}
		switch r.Effect {
		case "allow", "deny", "ask":
			out = append(out, OpenCodePermissionRule{Action: openCodeNativeAction(*r.Action), Resource: *r.Resource, Effect: r.Effect, Native: *r.Action})
		}
	}
	return out
}

// decodeOpenCodePermission flattens a permission value. The value is a union:
// a bare action string, which upstream normalizes to {"*": <action>}, or an
// object whose values are either an action or a nested pattern object.
//
// Decoded with a token walk rather than into a map, because a map would lose the
// key order the resolver depends on.
func decodeOpenCodePermission(raw json.RawMessage) []OpenCodePermissionRule {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	if action, ok := openCodeAction(trimmed); ok {
		return []OpenCodePermissionRule{{Action: "*", Resource: "*", Effect: action}}
	}
	pairs, ok := orderedJSONPairs(trimmed)
	if !ok {
		return nil
	}
	var rules []OpenCodePermissionRule
	for _, p := range pairs {
		if action, ok := openCodeAction(p.Value); ok {
			rules = append(rules, OpenCodePermissionRule{Action: p.Key, Resource: "*", Effect: action})
			continue
		}
		nested, ok := orderedJSONPairs(p.Value)
		if !ok {
			continue
		}
		for _, n := range nested {
			if action, ok := openCodeAction(n.Value); ok {
				rules = append(rules, OpenCodePermissionRule{Action: p.Key, Resource: n.Key, Effect: action})
			}
		}
	}
	return rules
}

// openCodeAction decodes a bare action string, returning false for any other
// shape. Upstream's actions are ask, allow and deny.
func openCodeAction(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "ask", "allow", "deny":
		return s, true
	}
	return "", false
}

// jsonPair is one key/value of a JSON object, in file order.
type jsonPair struct {
	Key   string
	Value json.RawMessage
}

// orderedJSONPairs decodes a JSON object preserving key order. Returns false
// when the value is not an object.
func orderedJSONPairs(raw json.RawMessage) ([]jsonPair, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, false
	}
	var pairs []jsonPair
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		pairs = append(pairs, jsonPair{Key: key, Value: value})
	}
	return pairs, true
}
