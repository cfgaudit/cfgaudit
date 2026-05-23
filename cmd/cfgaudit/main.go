package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/version"
	"github.com/cfgaudit/cfgaudit/rules"
)

// cfgauditVersion is injected at build time via:
//
//	go build -ldflags "-X main.cfgauditVersion=0.1.0" ./cmd/cfgaudit
//
// Unbranded local builds (`go run`, `go build` without ldflags) report "dev".
var cfgauditVersion = "dev"

func main() {
	format := flag.String("format", "text", "output format: text, json, sarif")
	user := flag.Bool("user", false, "also scan ~/.claude/settings.json")
	claudeVersion := flag.String("claude-version", "", "override the Claude Code version used for rule gating (default: detect via `claude --version`)")
	showVersion := flag.Bool("version", false, "print cfgaudit version and exit")

	var only, skip ruleSet
	flag.Var(&only, "only", "run only these rule IDs (comma-separated; flag may be repeated)")
	flag.Var(&skip, "skip", "skip these rule IDs (comma-separated; flag may be repeated)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("cfgaudit %s\n", cfgauditVersion)
		return
	}

	if unknown := unknownRuleIDs(only, skip, rules.All); len(unknown) > 0 {
		fmt.Fprintf(os.Stderr, "cfgaudit: --only/--skip references unknown rule(s): %s\n", strings.Join(unknown, ", "))
	}
	accept := ruleFilter(only, skip)

	dir := "."
	if flag.NArg() > 0 {
		dir = flag.Arg(0)
	}

	detected := resolveClaudeVersion(*claudeVersion)

	targets, err := buildTargets(dir, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgaudit: %v\n", err)
		os.Exit(2)
	}

	var all []finding.Finding
	for _, target := range targets {
		all = append(all, rules.Run(target, detected, accept)...)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(all)
	case "sarif":
		if err := encodeSARIF(os.Stdout, all, cfgauditVersion, rules.All); err != nil {
			fmt.Fprintf(os.Stderr, "cfgaudit: sarif encode: %v\n", err)
			os.Exit(2)
		}
	default:
		for _, f := range all {
			fmt.Println(f)
		}
		fmt.Printf("\ncfgaudit %s — %d %s\n", cfgauditVersion, len(all), pluralize("finding", len(all)))
	}

	if hasError(all) {
		os.Exit(1)
	}
}

func pluralize(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// resolveClaudeVersion picks the version to use for rule gating.
// Priority: explicit --claude-version flag > `claude --version` detection > nil.
// A nil return disables version gating and runs every rule unconditionally.
func resolveClaudeVersion(override string) *version.Version {
	if override != "" {
		v, err := version.Parse(override)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cfgaudit: --claude-version %q is not a recognised version; falling back to detection\n", override)
		} else {
			fmt.Fprintf(os.Stderr, "cfgaudit: scanning with Claude Code v%s (--claude-version)\n", v)
			return &v
		}
	}
	v, found, err := version.Detect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgaudit: could not parse `claude --version` output (%v); running all rules without version gating\n", err)
		return nil
	}
	if !found {
		fmt.Fprintln(os.Stderr, "cfgaudit: `claude` binary not on PATH; running all rules without version gating")
		return nil
	}
	fmt.Fprintf(os.Stderr, "cfgaudit: scanning with Claude Code v%s (detected)\n", v)
	return &v
}

func buildTargets(dir string, includeUser bool) ([]*rules.Target, error) {
	ignorePath := filepath.Join(dir, ".claudeignore")
	ignoreLines, err := parser.ParseIgnore(ignorePath)
	if err != nil {
		return nil, err
	}

	// The project .mcp.json is parsed once and attached to the project-scope
	// target (built below), so MCP rules cover it and .gitignore/sibling-file
	// rules don't run twice.
	projectMCP, mcpFile, err := loadProjectMCP(dir)
	if err != nil {
		return nil, err
	}

	projectSettingsPath := filepath.Join(dir, ".claude", "settings.json")
	projectSettings, err := parseSettingsOptional(projectSettingsPath)
	if err != nil {
		return nil, err
	}
	projectClaudeMDPath := filepath.Join(dir, "CLAUDE.md")
	projectClaudeMD, err := loadClaudeMD(projectClaudeMDPath)
	if err != nil {
		return nil, err
	}

	var targets []*rules.Target

	// Project scope: settings.json, .mcp.json and CLAUDE.md share one target. It
	// exists when any of them is present.
	if projectSettings != nil || len(projectMCP) > 0 || projectClaudeMD != "" {
		t := &rules.Target{
			SettingsFile:   projectSettingsPath,
			Settings:       projectSettings,
			Scope:          finding.ScopeProject,
			ProjectDir:     dir,
			ProjectMCP:     projectMCP,
			ProjectMCPFile: mcpFile,
			IgnoreFile:     ignorePath,
			IgnoreLines:    ignoreLines,
		}
		if projectClaudeMD != "" {
			t.ClaudeMDFile = projectClaudeMDPath
			t.ClaudeMDContent = projectClaudeMD
		}
		targets = append(targets, t)
	}

	// Project-local scope: settings.local.json only.
	localPath := filepath.Join(dir, ".claude", "settings.local.json")
	localSettings, err := parseSettingsOptional(localPath)
	if err != nil {
		return nil, err
	}
	if localSettings != nil {
		targets = append(targets, &rules.Target{
			SettingsFile: localPath,
			Settings:     localSettings,
			Scope:        finding.ScopeProjectLocal,
			ProjectDir:   dir,
			IgnoreFile:   ignorePath,
			IgnoreLines:  ignoreLines,
		})
	}

	// User scope: ~/.claude/settings.json and ~/.claude/CLAUDE.md (only with --user).
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		userSettingsPath := filepath.Join(home, ".claude", "settings.json")
		userSettings, err := parseSettingsOptional(userSettingsPath)
		if err != nil {
			return nil, err
		}
		userClaudeMDPath := filepath.Join(home, ".claude", "CLAUDE.md")
		userClaudeMD, err := loadClaudeMD(userClaudeMDPath)
		if err != nil {
			return nil, err
		}
		if userSettings != nil || userClaudeMD != "" {
			t := &rules.Target{
				SettingsFile: userSettingsPath,
				Settings:     userSettings,
				Scope:        finding.ScopeUser,
				IgnoreFile:   ignorePath,
				IgnoreLines:  ignoreLines,
			}
			if userClaudeMD != "" {
				t.ClaudeMDFile = userClaudeMDPath
				t.ClaudeMDContent = userClaudeMD
			}
			targets = append(targets, t)
		}
	}
	return targets, nil
}

// loadClaudeMD reads a CLAUDE.md file. A missing file yields ("", nil); the raw
// text is returned otherwise. CLAUDE.md is free-form Markdown, so unlike
// settings.json there is no parse step that can fail.
func loadClaudeMD(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

// parseSettingsOptional parses a settings.json, returning (nil, nil) when the
// file does not exist so callers can treat absence as "no target".
func parseSettingsOptional(path string) (*parser.Settings, error) {
	s, err := parser.ParseSettings(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return s, nil
}

// loadProjectMCP parses dir/.mcp.json. A missing file yields (nil, "", nil); a
// malformed file is reported as an error so the user learns their .mcp.json is
// not being scanned rather than silently trusting it.
func loadProjectMCP(dir string) (map[string]parser.MCPServer, string, error) {
	path := filepath.Join(dir, ".mcp.json")
	cfg, err := parser.ParseMCPConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", err
	}
	if len(cfg.MCPServers) == 0 {
		return nil, "", nil
	}
	return cfg.MCPServers, path, nil
}

func hasError(findings []finding.Finding) bool {
	for _, f := range findings {
		if f.Severity == finding.Error {
			return true
		}
	}
	return false
}

// ruleSet is a flag.Value that collects rule IDs from one or more occurrences
// of a flag. Each occurrence may pass a comma-separated list. Whitespace and
// empty entries are tolerated. Used by `--only` and `--skip`.
type ruleSet map[string]bool

func (rs *ruleSet) String() string {
	if rs == nil || *rs == nil {
		return ""
	}
	ids := make([]string, 0, len(*rs))
	for id := range *rs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func (rs *ruleSet) Set(v string) error {
	if *rs == nil {
		*rs = ruleSet{}
	}
	for _, raw := range strings.Split(v, ",") {
		id := strings.TrimSpace(raw)
		if id != "" {
			(*rs)[id] = true
		}
	}
	return nil
}

// ruleFilter builds the `accept` predicate that rules.Run consults.
// only takes precedence: when non-empty, a rule must appear in it to run.
// skip then excludes any remaining matches.
// A nil return means "no filtering" (all rules run).
func ruleFilter(only, skip ruleSet) func(rules.Rule) bool {
	if len(only) == 0 && len(skip) == 0 {
		return nil
	}
	return func(r rules.Rule) bool {
		id := r.ID()
		if len(only) > 0 && !only[id] {
			return false
		}
		return !skip[id]
	}
}

// unknownRuleIDs returns any IDs in only or skip that no registered rule reports.
// Used to warn the user about typos like `--only CFG999`.
func unknownRuleIDs(only, skip ruleSet, all []rules.Rule) []string {
	known := make(map[string]bool, len(all))
	for _, r := range all {
		known[r.ID()] = true
	}
	seen := map[string]bool{}
	var unknown []string
	for _, set := range []ruleSet{only, skip} {
		for id := range set {
			if !known[id] && !seen[id] {
				seen[id] = true
				unknown = append(unknown, id)
			}
		}
	}
	sort.Strings(unknown)
	return unknown
}
