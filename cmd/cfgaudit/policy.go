package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"gopkg.in/yaml.v3"
)

// policyOutput implements the `policy` subcommand: it synchronises deny rules
// between .claude/settings.json (permissions.deny) and .cfgaudit.yml
// (policy.require-deny). Returns the user-facing message and an exit code.
func policyOutput(args []string) (string, int) {
	if len(args) == 0 {
		return policyUsage(), 2
	}
	sub := args[0]
	rest := args[1:]

	dir := "."
	out := ""
	dryRun := false
	expectOut := false
	for _, a := range rest {
		switch {
		case expectOut:
			out = a
			expectOut = false
		case a == "--dry-run":
			dryRun = true
		case a == "--out":
			expectOut = true
		case strings.HasPrefix(a, "--out="):
			out = strings.TrimPrefix(a, "--out=")
		case strings.HasPrefix(a, "-"):
			return fmt.Sprintf("policy: unknown flag %q\n%s", a, policyUsage()), 2
		default:
			dir = a
		}
	}
	if expectOut {
		return "policy: --out needs a path\n", 2
	}

	switch sub {
	case "generate":
		return policyGenerate(dir, out)
	case "apply":
		return policyApply(dir, dryRun)
	default:
		return fmt.Sprintf("policy: unknown subcommand %q\n%s", sub, policyUsage()), 2
	}
}

func policyUsage() string {
	return "Usage:\n" +
		"  cfgaudit policy generate [--out .cfgaudit.yml] [dir]   # settings.json deny -> .cfgaudit.yml require-deny\n" +
		"  cfgaudit policy apply [--dry-run] [dir]                # .cfgaudit.yml require-deny -> settings.json deny\n"
}

// policyGenerate merges permissions.deny from settings.json into the
// require-deny list of .cfgaudit.yml, preserving the rest of the YAML file.
func policyGenerate(dir, out string) (string, int) {
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	s, err := parser.ParseSettings(settingsPath)
	if err != nil {
		return fmt.Sprintf("policy generate: %v\n", err), 1
	}
	if s.Permissions == nil || len(s.Permissions.Deny) == 0 {
		return fmt.Sprintf("policy generate: no permissions.deny in %s; nothing to do\n", settingsPath), 0
	}

	if out == "" {
		out = filepath.Join(dir, config.FileNames[0])
	}
	added, err := mergeRequireDeny(out, s.Permissions.Deny)
	if err != nil {
		return fmt.Sprintf("policy generate: %v\n", err), 1
	}
	if len(added) == 0 {
		return fmt.Sprintf("policy generate: %s already covers all %d deny entries; no change\n", out, len(s.Permissions.Deny)), 0
	}
	return fmt.Sprintf("policy generate: added %d entry/entries to require-deny in %s:\n%s", len(added), out, bulletList(added)), 0
}

// mergeRequireDeny adds missing entries to policy.require-deny in the YAML file
// at path (creating the file/keys as needed) and returns the entries it added.
// Existing content and comments are preserved via yaml.Node editing.
func mergeRequireDeny(path string, entries []string) ([]string, error) {
	var doc yaml.Node
	if data, err := os.ReadFile(path); err == nil { // #nosec G304,G703 -- config path from a user-supplied dir/--out, by design
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	root := documentRoot(&doc)
	policy := ensureMapKey(root, "policy")
	reqDeny := ensureSeqKey(policy, "require-deny")

	existing := map[string]bool{}
	for _, n := range reqDeny.Content {
		existing[n.Value] = true
	}
	var added []string
	for _, e := range entries {
		if !existing[e] {
			existing[e] = true
			added = append(added, e)
			reqDeny.Content = append(reqDeny.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: e})
		}
	}
	if len(added) == 0 {
		return nil, nil
	}

	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	_ = enc.Close()
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil { // #nosec G304,G703 -- config path from a user-supplied dir/--out, by design
		return nil, err
	}
	return added, nil
}

// policyApply adds require-deny entries from .cfgaudit.yml that are missing from
// settings.json permissions.deny. With dryRun it only reports the diff.
func policyApply(dir string, dryRun bool) (string, int) {
	cfg, cfgPath, err := config.Discover(dir)
	if err != nil {
		return fmt.Sprintf("policy apply: %v\n", err), 1
	}
	if cfg == nil || len(cfg.Policy.RequireDeny) == 0 {
		return "policy apply: no policy.require-deny found in .cfgaudit.yml; nothing to do\n", 0
	}

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	root, err := loadJSONObject(settingsPath)
	if err != nil {
		return fmt.Sprintf("policy apply: %v\n", err), 1
	}

	existing := map[string]bool{}
	for _, d := range jsonStringSlice(root, "permissions", "deny") {
		existing[d] = true
	}
	var missing []string
	for _, e := range cfg.Policy.RequireDeny {
		if !existing[e] {
			existing[e] = true
			missing = append(missing, e)
		}
	}
	if len(missing) == 0 {
		return fmt.Sprintf("policy apply: %s already satisfies all %d require-deny entries from %s\n", settingsPath, len(cfg.Policy.RequireDeny), cfgPath), 0
	}
	if dryRun {
		return fmt.Sprintf("policy apply (dry-run): would add %d entry/entries to permissions.deny in %s:\n%s", len(missing), settingsPath, bulletList(missing)), 0
	}

	if err := appendDeny(settingsPath, root, missing); err != nil {
		return fmt.Sprintf("policy apply: %v\n", err), 1
	}
	return fmt.Sprintf("policy apply: added %d entry/entries to permissions.deny in %s:\n%s", len(missing), settingsPath, bulletList(missing)), 0
}

// --- YAML node helpers ------------------------------------------------------

func documentRoot(doc *yaml.Node) *yaml.Node {
	if len(doc.Content) == 0 {
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{root}
		return root
	}
	return doc.Content[0]
}

func ensureMapKey(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	val := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
	return val
}

func ensureSeqKey(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	val := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
	return val
}

// --- JSON helpers -----------------------------------------------------------

func loadJSONObject(path string) (map[string]any, error) {
	data, err := os.ReadFile(path) // #nosec G304,G703 -- settings path resolved from a user-supplied dir, by design
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// jsonStringSlice returns root[k1][k2] as a []string when it is a JSON array of
// strings, else nil.
func jsonStringSlice(root map[string]any, k1, k2 string) []string {
	outer, _ := root[k1].(map[string]any)
	if outer == nil {
		return nil
	}
	arr, _ := outer[k2].([]any)
	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// appendDeny adds entries to root.permissions.deny (preserving existing order,
// new entries appended) and writes the object back as indented JSON. Note: Go's
// JSON encoder sorts object keys, so the file is normalised to 2-space indent
// with alphabetically-ordered keys — review the diff (or use --dry-run first).
func appendDeny(path string, root map[string]any, entries []string) error {
	perms, _ := root["permissions"].(map[string]any)
	if perms == nil {
		perms = map[string]any{}
		root["permissions"] = perms
	}
	deny, _ := perms["deny"].([]any)
	for _, e := range entries {
		deny = append(deny, e)
	}
	perms["deny"] = deny

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { // #nosec G703 -- dir from a user-supplied path, by design
		return err
	}
	b, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o600) // #nosec G304,G703 -- settings path from a user-supplied dir, by design
}

func bulletList(items []string) string {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	var sb strings.Builder
	for _, it := range sorted {
		sb.WriteString("  - ")
		sb.WriteString(it)
		sb.WriteByte('\n')
	}
	return sb.String()
}
