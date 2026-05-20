package main

import (
	"encoding/json"
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
	flag.Parse()

	dir := "."
	if flag.NArg() > 0 {
		dir = flag.Arg(0)
	}

	target, err := buildTarget(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgaudit: %v\n", err)
		os.Exit(2)
	}

	var all []finding.Finding
	for _, r := range rules.All {
		all = append(all, r.Check(target)...)
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

func buildTarget(dir string) (*rules.Target, error) {
	t := &rules.Target{}

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	if s, err := parser.ParseSettings(settingsPath); err == nil {
		t.SettingsFile = settingsPath
		t.Settings = s
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	ignorePath := filepath.Join(dir, ".claudeignore")
	lines, err := parser.ParseIgnore(ignorePath)
	if err != nil {
		return nil, err
	}
	t.IgnoreFile = ignorePath
	t.IgnoreLines = lines

	return t, nil
}

func hasError(findings []finding.Finding) bool {
	for _, f := range findings {
		if f.Severity == finding.Error {
			return true
		}
	}
	return false
}
