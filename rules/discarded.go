package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/schema"
)

// SchemaTypeMismatch is one top-level settings key whose JSON type the bundled
// Claude Code settings schema rejects.
type SchemaTypeMismatch struct {
	Key     string
	Actual  string
	Allowed []string
}

// SettingsTypeMismatches returns the top-level keys of a settings file whose
// JSON type the schema rejects, sorted by key.
//
// Only the top level is examined, because that is where the consequence lives:
// see SettingsDiscarded.
func SettingsTypeMismatches(s *parser.Settings) []SchemaTypeMismatch {
	if s == nil || len(s.Raw) == 0 {
		return nil
	}
	spec := schema.TopLevelProperties()
	keys := make([]string, 0, len(s.Raw))
	for k := range s.Raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []SchemaTypeMismatch
	for _, k := range keys {
		if k == "$schema" {
			continue
		}
		ps, known := spec[k]
		if !known || len(ps.AllowedTypes) == 0 {
			continue
		}
		actual := jsonTypeOf(s.Raw[k])
		if !stringInSlice(actual, ps.AllowedTypes) {
			out = append(out, SchemaTypeMismatch{Key: k, Actual: actual, Allowed: ps.AllowedTypes})
		}
	}
	return out
}

// SettingsDiscarded reports whether Claude Code drops this settings file whole
// rather than ignoring the offending value.
//
// Measured against 2.1.282 and 2.1.273 with a settings file holding a
// SessionStart hook, where the hook running is the proof that the file loaded:
//
//	nothing else                     hook ran
//	"totallyUnknownKeyXyz": 1        hook ran
//	"cleanupPeriodDays": "thirty"    hook did NOT run
//	"model": 5                       hook did NOT run
//	"apiKeyHelper": null             hook did NOT run
//	"permissions": null              hook did NOT run
//	"permissions": {"deny": [123]}   hook ran
//
// So the boundary is exactly the top-level property: a wrong scalar type, or
// null, on any one of them drops the file with every permission rule, hook and
// env entry in it, while an unknown key and a malformed value deeper inside are
// tolerated. Nothing is printed when it happens. The same holds for
// .claude/settings.local.json and for the user-scope ~/.claude/settings.json,
// both measured the same way against a valid-file control.
//
// Upstream 2.1.282 fixed the neighbouring case for managed settings ("managed
// permissions, autoMode, worktree and attribution settings being ignored
// entirely when one nested value was invalid; the rest of the block now still
// applies"), which is why the project-file behaviour reads as deliberate.
//
// This drives two things: CFG012 reports the consequence rather than a probable
// typo, and the rules that go quiet because a deny block covers a file class
// stop crediting a file that is never loaded.
func SettingsDiscarded(s *parser.Settings) bool {
	return len(SettingsTypeMismatches(s)) > 0
}

// discarded reports whether this target's settings file is one Claude Code drops
// whole. A target with no settings file is not discarded: there is nothing to
// drop, and the absence is what the other rules already reason about.
func (t *Target) discarded() bool {
	return t != nil && SettingsDiscarded(t.Settings)
}

// effectiveDeny returns the deny entries that are actually in force: the file's
// own deny block, or nothing at all when the file is discarded.
//
// Rules that report a *dangerous* value keep reading Settings directly. Treating
// a discarded file as absent everywhere would be the wrong trade: this detection
// leans on the bundled schema, which can lag upstream, and a wrong "this file is
// dead" verdict would silence findings, while a wrong verdict here only adds the
// finding that the deny block is missing. The direction that can be wrong is the
// one that reports more.
func (t *Target) effectiveDeny() []string {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil || t.discarded() {
		return nil
	}
	return t.Settings.Permissions.Deny
}

// discardedNote explains, in a clause that hangs off a finding message, why a
// deny block that is present in the file counts for nothing.
func discardedNote(t *Target) string {
	if !t.discarded() {
		return ""
	}
	var keys []string
	for _, m := range SettingsTypeMismatches(t.Settings) {
		keys = append(keys, "\""+m.Key+"\"")
	}
	return " (the file does list deny entries, but Claude Code discards this settings file whole because " +
		strings.Join(keys, ", ") + " has a type the schema rejects, so nothing in it is in force — see CFG012)"
}
