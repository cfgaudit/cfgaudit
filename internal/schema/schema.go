// Package schema embeds a snapshot of the upstream SchemaStore "Claude Code
// settings" schema and exposes the bare-minimum structural data that the
// CFG012 rule needs: the set of top-level property names and, for each, the
// JSON types the schema accepts.
//
// Source: https://json.schemastore.org/claude-code-settings.json
// (SchemaStore content is published under Apache-2.0.)
//
// The snapshot intentionally lags behind upstream — see KnownButUnschemaed for
// keys that are widely used at runtime but not yet codified in the schema.
package schema

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed claude-code-settings.schema.json
var bundled []byte

// PropertySpec describes a single top-level property as seen in the schema.
type PropertySpec struct {
	// AllowedTypes are the JSON types the schema permits ("string", "array",
	// "object", "boolean", "number", "null"). Empty means the schema does not
	// constrain the type at the top level (e.g. $ref only).
	AllowedTypes []string
}

// KnownButUnschemaed are top-level keys that real-world Claude Code
// configurations use but that the bundled schema does not (yet) document.
// Treating them as known prevents noisy false positives for legitimate config.
//
//   - mcpServers: defined in .mcp.json per the schema, but widely embedded
//     directly in settings.json by users.
//   - defaultMode: documented in the schema only at permissions.defaultMode,
//     but accepted at the top level by older Claude Code versions and still
//     widespread in shared configs.
var KnownButUnschemaed = map[string]bool{
	"mcpServers":  true,
	"defaultMode": true,
}

var (
	once  sync.Once
	props map[string]PropertySpec
)

// TopLevelProperties returns the parsed top-level property map.
// The result is cached on first call and safe to share across goroutines.
func TopLevelProperties() map[string]PropertySpec {
	once.Do(parse)
	return props
}

func parse() {
	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(bundled, &doc); err != nil {
		props = map[string]PropertySpec{}
		return
	}
	out := make(map[string]PropertySpec, len(doc.Properties))
	for name, body := range doc.Properties {
		out[name] = PropertySpec{AllowedTypes: extractTypes(body)}
	}
	props = out
}

func extractTypes(body json.RawMessage) []string {
	var spec struct {
		Type  interface{} `json:"type"`
		AnyOf []struct {
			Type interface{} `json:"type"`
		} `json:"anyOf"`
	}
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil
	}
	var types []string
	appendType(&types, spec.Type)
	for _, a := range spec.AnyOf {
		appendType(&types, a.Type)
	}
	return normalize(types)
}

func appendType(out *[]string, v interface{}) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case []interface{}:
		for _, x := range t {
			if s, ok := x.(string); ok {
				*out = append(*out, s)
			}
		}
	}
}

// normalize collapses "integer" into "number" (JSON itself has no
// integer/number distinction) and removes duplicates.
func normalize(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		if t == "integer" {
			t = "number"
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}
