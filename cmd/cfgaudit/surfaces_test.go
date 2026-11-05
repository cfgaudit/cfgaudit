// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The surface list (#1443): docs/agent-surfaces.yml says which project files
// cfgaudit reads for which agent. These tests hold it to the real discovery, in
// both directions.

type agentSurface struct {
	Agent   string `yaml:"agent"`
	Kind    string `yaml:"kind"`
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
}

func loadSurfaces(t *testing.T) []agentSurface {
	t.Helper()
	data, err := os.ReadFile("../../docs/agent-surfaces.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Surfaces []agentSurface `yaml:"surfaces"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Surfaces) == 0 {
		t.Fatal("no surfaces listed")
	}
	return doc.Surfaces
}

// Every line is true: the file alone, in an otherwise empty directory, is
// listed under that agent.
func TestAgentSurfacesAreDiscovered(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range loadSurfaces(t) {
		t.Run(s.Path, func(t *testing.T) {
			if s.Agent == "" || s.Kind == "" || s.Path == "" {
				t.Fatalf("incomplete entry: %+v", s)
			}
			if seen[s.Path] {
				t.Fatalf("%s is listed twice", s.Path)
			}
			seen[s.Path] = true
			content := s.Content
			if content == "" {
				content = "x\n"
			}
			dir := t.TempDir()
			path := filepath.Join(dir, filepath.FromSlash(s.Path))
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errb := inventoryRun(t, "--format", "json", dir)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errb)
			}
			var inv inventory
			if err := json.Unmarshal([]byte(out), &inv); err != nil {
				t.Fatal(err)
			}
			for _, a := range inv.Agents {
				for _, f := range a.Files {
					if f.Path == s.Path {
						if a.Agent != s.Agent {
							t.Errorf("listed under %q, want %q", a.Agent, s.Agent)
						}
						return
					}
				}
			}
			t.Errorf("not in the inventory:\n%s", out)
		})
	}
}

// surfacesNotListed are agent prefixes of the inventory with no line, and why.
var surfacesNotListed = map[string]string{
	".claude-plugin/": "read as a plugin package, not as a project file",
	".kimi/":          "Kimi CLI is not read yet (#1012)",
}

// Every agent prefix of the inventory has a line or a reason, so a surface
// added to the discovery cannot stay out of the list.
func TestAgentSurfacesCoverThePathAgents(t *testing.T) {
	surfaces := loadSurfaces(t)
	for _, p := range pathAgents {
		listed := slices.ContainsFunc(surfaces, func(s agentSurface) bool {
			return s.Path == p.prefix || (strings.HasSuffix(p.prefix, "/") && strings.HasPrefix(s.Path, p.prefix))
		})
		_, excused := surfacesNotListed[p.prefix]
		if listed == excused {
			t.Errorf("%s (%s): listed %v, excused %v; want exactly one", p.prefix, p.agent, listed, excused)
		}
	}
}

// VS Code reads only *.prompt.md, one level deep (#1467).
func TestCopilotPromptFiles1467(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.prompt.md", "b.md", "sub/c.prompt.md"} {
		mustWrite(t, filepath.Join(dir, ".github", "prompts", filepath.FromSlash(name)), "x\n")
	}
	code, out, errb := inventoryRun(t, "--format", "json", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(out, ".github/prompts/a.prompt.md") || strings.Contains(out, "b.md") || strings.Contains(out, "c.prompt.md") {
		t.Errorf("inventory:\n%s", out)
	}
}
