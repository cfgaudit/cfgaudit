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

// The surface list (#1443): docs/agent-surfaces.yml says which project and
// user-global files cfgaudit reads for which agent. These tests hold it to the
// real discovery, in both directions.

type agentSurface struct {
	Agent   string `yaml:"agent"`
	Scope   string `yaml:"scope"`
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
// listed under that agent. A user-global file goes into an empty home.
func TestAgentSurfacesAreDiscovered(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range loadSurfaces(t) {
		t.Run(s.Scope+"/"+s.Path, func(t *testing.T) {
			if s.Agent == "" || s.Kind == "" || s.Path == "" {
				t.Fatalf("incomplete entry: %+v", s)
			}
			if s.Scope != "" && s.Scope != "user" {
				t.Fatalf("unknown scope: %+v", s)
			}
			if seen[s.Scope+"/"+s.Path] {
				t.Fatalf("%s is listed twice", s.Path)
			}
			seen[s.Scope+"/"+s.Path] = true
			content := s.Content
			if content == "" {
				content = "x\n"
			}
			dir, home := t.TempDir(), t.TempDir()
			setHome(t, home)
			root, want, args := dir, s.Path, []string{"--format", "json"}
			if s.Scope == "user" {
				root, want, args = home, "~/"+s.Path, append(args, "--user")
			}
			mustWrite(t, filepath.Join(root, filepath.FromSlash(s.Path)), content)
			code, out, errb := inventoryRun(t, append(args, dir)...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errb)
			}
			var inv inventory
			if err := json.Unmarshal([]byte(out), &inv); err != nil {
				t.Fatal(err)
			}
			for _, a := range inv.Agents {
				for _, f := range a.Files {
					if f.Path == want {
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

// A user-global file is read only with --user.
func TestAgentSurfacesUserNeedsTheFlag(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	setHome(t, home)
	for _, s := range loadSurfaces(t) {
		if s.Scope == "user" {
			mustWrite(t, filepath.Join(home, filepath.FromSlash(s.Path)), s.Content+"\n")
		}
	}
	code, out, errb := inventoryRun(t, "--format", "json", dir)
	if code != 0 || strings.Contains(out, "~/") {
		t.Errorf("exit %d: %s\n%s", code, errb, out)
	}
}

// Every list of user paths has its lines, so a path added to one cannot stay
// out of the surface list. The single files read by name have no such list.
func TestAgentSurfacesCoverTheUserLists(t *testing.T) {
	var user []string
	for _, s := range loadSurfaces(t) {
		if s.Scope == "user" {
			user = append(user, filepath.FromSlash(s.Path))
		}
	}
	matches := func(glob string) bool {
		return slices.ContainsFunc(user, func(p string) bool {
			ok, err := filepath.Match(glob, p)
			return err == nil && ok
		})
	}
	under := func(dir string) bool {
		return slices.ContainsFunc(user, func(p string) bool { return strings.HasPrefix(p, dir+string(filepath.Separator)) })
	}
	for _, glob := range slices.Concat(userInstructionGlobs, userAgentMCPFiles) {
		if !matches(glob) {
			t.Errorf("%s has no user line", glob)
		}
	}
	for _, dir := range slices.Concat(recursiveInstructionDirs, userSkillsDirs) {
		if !under(dir) {
			t.Errorf("%s has no user line", dir)
		}
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
