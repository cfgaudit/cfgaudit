// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// capabilityPackageTargets discovers setup documents only after structural
// evidence identifies their directory as an agent capability package (#1437).
// A mention of AI/MCP, or an MCP SDK dependency on its own, is deliberately not
// evidence: ordinary applications use those dependencies too.
func capabilityPackageTargets(dir string, targets []*rules.Target) ([]*rules.Target, error) {
	roots, err := capabilityPackageRoots(dir)
	if err != nil || len(roots) == 0 {
		return nil, err
	}
	var paths []string
	for root := range roots {
		for _, rel := range capabilitySetupDocuments {
			path := filepath.Join(root, filepath.FromSlash(rel))
			if info, err := scanroot.Stat(path); err == nil && !info.IsDir() {
				if rel, err := filepath.Rel(dir, path); err == nil {
					paths = append(paths, filepath.ToSlash(rel))
				}
			}
		}
	}
	out, err := contentPathTargets(dir, paths, targets)
	for _, target := range out {
		target.CapabilityPackage = true
	}
	return out, err
}

var capabilitySetupDocuments = []string{
	"README.md", "INSTALL.md", "SETUP.md", "GETTING_STARTED.md",
	"docs/install.md", "docs/installation.md", "docs/setup.md", "docs/getting-started.md",
}

func capabilityPackageRoots(dir string) (map[string]bool, error) {
	roots := map[string]bool{}
	err := scanroot.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "SKILL.md":
			// Classify the skill directory, not the repository root. Ordinary
			// applications can ship one optional skill; that does not turn their
			// general README into capability-package setup documentation.
			roots[filepath.Dir(path)] = true
		case "server.json":
			if isMCPServerManifest(path) {
				roots[filepath.Dir(path)] = true
			}
		case "package.json":
			if isMCPNPMEntrypoint(path) {
				roots[filepath.Dir(path)] = true
			}
		case "plugin.json", "marketplace.json":
			if filepath.Base(filepath.Dir(path)) == ".claude-plugin" && validJSONFile(path) {
				roots[filepath.Dir(filepath.Dir(path))] = true
			}
		}
		return nil
	})
	return roots, err
}

func validJSONFile(path string) bool {
	data, err := scanroot.ReadFile(path)
	return err == nil && json.Valid(data)
}

func isMCPServerManifest(path string) bool {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return false
	}
	var manifest struct {
		Schema   string            `json:"$schema"`
		Name     string            `json:"name"`
		Packages []json.RawMessage `json:"packages"`
		Remotes  []json.RawMessage `json:"remotes"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return false
	}
	return strings.Contains(strings.ToLower(manifest.Schema), "modelcontextprotocol.io/") &&
		strings.Contains(manifest.Name, "/") && (len(manifest.Packages) > 0 || len(manifest.Remotes) > 0)
}

func isMCPNPMEntrypoint(path string) bool {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return false
	}
	var pkg struct {
		Name            string                     `json:"name"`
		MCPName         string                     `json:"mcpName"`
		Bin             json.RawMessage            `json:"bin"`
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
		DevDependencies map[string]json.RawMessage `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return false
	}
	if pkg.MCPName != "" {
		return true
	}
	if !hasMCPNPMBin(pkg.Name, pkg.Bin) {
		return false
	}
	_, runtime := pkg.Dependencies["@modelcontextprotocol/sdk"]
	_, dev := pkg.DevDependencies["@modelcontextprotocol/sdk"]
	return runtime || dev
}

func hasMCPNPMBin(packageName string, raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var path string
	if json.Unmarshal(raw, &path) == nil {
		return path != "" && (mcpNamed(packageName) || mcpNamed(path))
	}
	var bins map[string]string
	if json.Unmarshal(raw, &bins) != nil {
		return false
	}
	for name, path := range bins {
		if name != "" && path != "" && (mcpNamed(name) || mcpNamed(path)) {
			return true
		}
	}
	return false
}

func mcpNamed(s string) bool {
	for _, field := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if field == "mcp" || strings.HasPrefix(field, "mcpserver") || strings.HasSuffix(field, "mcpserver") {
			return true
		}
	}
	return false
}
