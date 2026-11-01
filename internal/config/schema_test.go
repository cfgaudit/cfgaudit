// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/safeyaml"
)

// The published schema for .cfgaudit.yml (#1106), and the JSON copies of the
// examples the schema-validation workflow checks against it with ajv.
var (
	schemaFile   = filepath.Join("..", "..", "schema", "cfgaudit.schema.json")
	examplesJSON = filepath.Join("..", "..", "testdata", "config", "json")
	update       = flag.Bool("update", false, "rewrite testdata/config/json from the YAML examples")
)

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(schemaFile) //nolint:gosec // G304: the schema of this repository
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("%s: %v", schemaFile, err)
	}
	return s
}

// at follows a path of object keys through the schema.
func at(t *testing.T, v any, path ...string) map[string]any {
	t.Helper()
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("schema: %s is not an object", strings.Join(path, "."))
		}
		v = m[k]
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("schema: no object at %s", strings.Join(path, "."))
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func propertyNames(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Every key the parser accepts is in the schema and the schema names no other,
// so a key added to the config shows up in editors with it (#1106).
func TestSchema_KeysMatchParser(t *testing.T) {
	s := loadSchema(t)
	defs := at(t, s, "definitions")
	forbid := at(t, at(t, defs, "policy", "properties", "forbid-allow")["anyOf"].([]any)[1], "properties")
	rule := at(t, defs["ruleOverride"].(map[string]any)["anyOf"].([]any)[2], "properties")
	for _, c := range []struct {
		name   string
		schema map[string]any
		parser map[string]bool
	}{
		{"top level", at(t, s, "properties"), topLevelKeys},
		{"policy", at(t, defs, "policy", "properties"), policyKeys},
		{"policy.deny", at(t, defs, "policy", "properties", "deny", "properties"), denyKeys},
		{"policy.forbid-allow", forbid, forbidKeys},
		{"rules.<ID>", rule, ruleKeys},
	} {
		if got, want := propertyNames(c.schema), sortedKeys(c.parser); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: schema has %v, parser accepts %v", c.name, got, want)
		}
	}
	var agents []string
	for _, a := range at(t, defs, "policy", "properties", "agents", "items")["enum"].([]any) {
		agents = append(agents, a.(string))
	}
	if !reflect.DeepEqual(agents, PolicyAgents) {
		t.Errorf("policy.agents: schema has %v, PolicyAgents is %v", agents, PolicyAgents)
	}
}

// configExample is one .cfgaudit.yml: a fenced example annotated
// path=.cfgaudit.yml in the docs, or a file under testdata/config.
type configExample struct {
	name, yaml string
	valid      bool
}

var cfgFenceRe = regexp.MustCompile("(?ms)^```ya?ml path=\\.cfgaudit\\.yml\\s*\\n(.*?)^```")

func configExamples(t *testing.T) []configExample {
	t.Helper()
	root := filepath.Join("..", "..")
	var docs []string
	for _, g := range []string{"README.md", "docs/*.md", "docs/rules/*.md"} {
		m, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(g)))
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, m...)
	}
	var out []configExample
	for _, doc := range docs {
		data, err := os.ReadFile(doc) //nolint:gosec // G304: docs of this repository
		if err != nil {
			t.Fatal(err)
		}
		base := strings.TrimSuffix(filepath.Base(doc), ".md")
		if base == "README" {
			base = filepath.Base(filepath.Dir(doc)) + "-README"
		}
		for i, m := range cfgFenceRe.FindAllStringSubmatch(string(data), -1) {
			out = append(out, configExample{name: "doc-" + base + "-" + string(rune('1'+i)), yaml: m[1], valid: true})
		}
	}
	for _, kind := range []string{"valid", "invalid"} {
		files, err := filepath.Glob(filepath.Join(root, "testdata", "config", kind, "*.yml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			data, err := os.ReadFile(f) //nolint:gosec // G304: fixtures of this repository
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, configExample{name: strings.TrimSuffix(filepath.Base(f), ".yml"), yaml: string(data), valid: kind == "valid"})
		}
	}
	if len(out) == 0 {
		t.Fatal("no .cfgaudit.yml examples found")
	}
	return out
}

// Each example parses or is rejected as its directory says, and its JSON copy
// under testdata/config/json is current. The schema-validation workflow checks
// that the schema accepts the valid copies and rejects the invalid ones, so
// the parser and the schema agree on all of them (#1106). Run with -update
// after changing an example.
func TestSchema_Examples(t *testing.T) {
	want := map[string]bool{}
	for _, ex := range configExamples(t) {
		_, err := parse([]byte(ex.yaml), ex.name)
		switch {
		case ex.valid && err != nil:
			t.Errorf("%s: the parser rejects a valid example: %v", ex.name, err)
		case !ex.valid && err == nil:
			t.Errorf("%s: the parser accepts an invalid example", ex.name)
		}
		var v any
		if err := safeyaml.Unmarshal([]byte(ex.yaml), &v); err != nil {
			t.Fatalf("%s: %v", ex.name, err)
		}
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("%s: %v", ex.name, err)
		}
		kind := "invalid"
		if ex.valid {
			kind = "valid"
		}
		path := filepath.Join(examplesJSON, kind, ex.name+".json")
		want[path] = true
		data = append(data, '\n')
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path) //nolint:gosec // G304: fixtures of this repository
		if err != nil || string(got) != string(data) {
			t.Errorf("%s is missing or stale; run go test ./internal/config -run TestSchema_Examples -update", path)
		}
	}
	stale, _ := filepath.Glob(filepath.Join(examplesJSON, "*", "*.json"))
	for _, f := range stale {
		if !want[f] {
			t.Errorf("%s has no example any more; delete it", f)
		}
	}
}
