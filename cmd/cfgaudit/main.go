package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/version"
	"github.com/cfgaudit/cfgaudit/rules"
)

func main() {
	format := flag.String("format", "text", "output format: text, json")
	user := flag.Bool("user", false, "also scan ~/.claude/settings.json")
	claudeVersion := flag.String("claude-version", "", "override the Claude Code version used for rule gating (default: detect via `claude --version`)")
	flag.Parse()

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
		all = append(all, rules.Run(target, detected)...)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(all)
	default:
		for _, f := range all {
			fmt.Println(f)
		}
	}

	if hasError(all) {
		os.Exit(1)
	}
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

	candidates := []string{
		filepath.Join(dir, ".claude", "settings.json"),
		filepath.Join(dir, ".claude", "settings.local.json"),
	}
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		candidates = append(candidates, filepath.Join(home, ".claude", "settings.json"))
	}

	var targets []*rules.Target
	for _, path := range candidates {
		s, err := parser.ParseSettings(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		targets = append(targets, &rules.Target{
			SettingsFile: path,
			Settings:     s,
			IgnoreFile:   ignorePath,
			IgnoreLines:  ignoreLines,
		})
	}
	return targets, nil
}

func hasError(findings []finding.Finding) bool {
	for _, f := range findings {
		if f.Severity == finding.Error {
			return true
		}
	}
	return false
}
