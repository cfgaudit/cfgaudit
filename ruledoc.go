// Package cfgaudit embeds the per-rule documentation so the `cfgaudit explain`
// subcommand can render it offline, keeping docs/rules/*.md the single source.
package cfgaudit

import (
	"embed"
	"sort"
	"strings"
)

//go:embed docs/rules/*.md
var ruleDocs embed.FS

// RuleDoc returns the raw Markdown for a rule ID (e.g. "CFG001"), or ok=false.
func RuleDoc(id string) (string, bool) {
	b, err := ruleDocs.ReadFile("docs/rules/" + id + ".md")
	if err != nil {
		return "", false
	}
	return string(b), true
}

// RuleIDs returns every documented rule ID, sorted.
func RuleIDs() []string {
	entries, err := ruleDocs.ReadDir("docs/rules")
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, strings.TrimSuffix(e.Name(), ".md"))
	}
	sort.Strings(ids)
	return ids
}
