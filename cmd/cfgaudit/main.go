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
	"github.com/cfgaudit/cfgaudit/rules"
)

func main() {
	format := flag.String("format", "text", "output format: text, json")
	user := flag.Bool("user", false, "also scan ~/.claude/settings.json")
	flag.Parse()

	dir := "."
	if flag.NArg() > 0 {
		dir = flag.Arg(0)
	}

	targets, err := buildTargets(dir, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgaudit: %v\n", err)
		os.Exit(2)
	}

	var all []finding.Finding
	for _, target := range targets {
		for _, r := range rules.All {
			all = append(all, r.Check(target)...)
		}
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
