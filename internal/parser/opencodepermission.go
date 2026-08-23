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
type OpenCodePermissionRule struct {
	Action   string
	Resource string
	Effect   string
}

// OpenCodePermissionBlock is one permission declaration and where it came from.
type OpenCodePermissionBlock struct {
	// Where is "permission" or "agent.<name>.permission".
	Where string
	Rules []OpenCodePermissionRule
}

// PermissionBlocks returns the top-level permission block and each agent's, in
// declaration order, with the rules flattened.
func (c *OpenCodeConfig) PermissionBlocks() []OpenCodePermissionBlock {
	if c == nil {
		return nil
	}
	var out []OpenCodePermissionBlock
	if rules := decodeOpenCodePermission(c.Permission); len(rules) > 0 {
		out = append(out, OpenCodePermissionBlock{Where: "permission", Rules: rules})
	}
	names := make([]string, 0, len(c.Agent))
	for name := range c.Agent {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if rules := decodeOpenCodePermission(c.Agent[name].Permission); len(rules) > 0 {
			out = append(out, OpenCodePermissionBlock{Where: "agent." + name + ".permission", Rules: rules})
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
