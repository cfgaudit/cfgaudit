// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"errors"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// RulesyncRules maps a category to pattern and action: bash, read, edit, write,
// webfetch, mcp__server__tool and others, each with allow, ask or deny.
type RulesyncRules map[string]map[string]string

// RulesyncPermissions is a .rulesync/permissions.jsonc (#1519): the shared rules,
// and per tool the block whose categories replace the shared ones for that tool.
// A value of another shape is left out, since Rulesync validates the file and
// cfgaudit only reads what it can compare.
type RulesyncPermissions struct {
	Shared RulesyncRules
	Tools  map[string]RulesyncRules
}

// decodeRulesyncRules reads a permission object, skipping what is not a map of
// pattern to string.
func decodeRulesyncRules(raw json.RawMessage) RulesyncRules {
	var loose map[string]json.RawMessage
	if json.Unmarshal(raw, &loose) != nil {
		return nil
	}
	out := RulesyncRules{}
	for category, v := range loose {
		var patterns map[string]string
		if json.Unmarshal(v, &patterns) == nil {
			out[category] = patterns
			continue
		}
		var action string
		if json.Unmarshal(v, &action) == nil {
			out[category] = map[string]string{"*": action}
		}
	}
	return out
}

// ParseRulesyncPermissions reads the file, returning (nil, nil) when it does not
// exist. Unknown top-level keys such as $schema are ignored.
func ParseRulesyncPermissions(path string) (*RulesyncPermissions, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, nil // an unreadable source is left for Rulesync to report
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(stripJSONC(data), &top); err != nil {
		return nil, errors.Join(errors.New("parse "+path), err)
	}
	p := &RulesyncPermissions{Tools: map[string]RulesyncRules{}}
	for key, raw := range top {
		if key == "permission" {
			p.Shared = decodeRulesyncRules(raw)
			continue
		}
		var block struct {
			Permission json.RawMessage `json:"permission"`
		}
		if json.Unmarshal(raw, &block) == nil && block.Permission != nil {
			p.Tools[key] = decodeRulesyncRules(block.Permission)
		}
	}
	return p, nil
}
