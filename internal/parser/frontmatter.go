package parser

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Frontmatter is the YAML metadata block at the top of a Markdown instruction
// file (skill SKILL.md, slash command, subagent) delimited by `---` fences. Only
// the decoded key/value map is kept; accessors normalise the loosely-typed values.
type Frontmatter struct {
	Raw map[string]any
}

// InstructionFrontmatter extracts and decodes the leading `---`-fenced YAML block
// of content. Returns ok=false when there is no frontmatter or it fails to parse.
func InstructionFrontmatter(content string) (*Frontmatter, bool) {
	s := strings.TrimLeft(content, "\ufeff \t\r\n")
	if !strings.HasPrefix(s, "---") {
		return nil, false
	}
	// Body after the opening fence line.
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return nil, false
	}
	rest := s[nl+1:]
	// Closing fence: a line that is exactly --- (or ...).
	end := -1
	for _, fence := range []string{"\n---", "\n..."} {
		if i := strings.Index(rest, fence); i >= 0 && (end < 0 || i < end) {
			end = i
		}
	}
	if end < 0 {
		return nil, false
	}
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(rest[:end]), &raw); err != nil || raw == nil {
		return nil, false
	}
	return &Frontmatter{Raw: raw}, true
}

// StringList returns a frontmatter value as a list of trimmed strings, accepting
// either a YAML list or a single string split on commas/whitespace. Missing or
// wrongly-typed keys yield nil.
func (f *Frontmatter) StringList(key string) []string {
	if f == nil {
		return nil
	}
	switch v := f.Raw[key].(type) {
	case string:
		return splitToolList(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

// Phrases returns a frontmatter value as a list of whole phrases: list elements
// verbatim, or a scalar split only on commas/newlines. Unlike StringList it does
// NOT split on spaces, so multi-word entries (e.g. a trigger "before every
// request") stay intact for phrase-level matching. Missing/wrongly-typed keys
// yield nil.
func (f *Frontmatter) Phrases(key string) []string {
	if f == nil {
		return nil
	}
	switch v := f.Raw[key].(type) {
	case string:
		var out []string
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' }) {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

// Bool returns a frontmatter value as a bool; missing/non-bool yields false.
func (f *Frontmatter) Bool(key string) bool {
	if f == nil {
		return false
	}
	b, _ := f.Raw[key].(bool)
	return b
}

// String returns a frontmatter value as a trimmed string; missing/non-string yields "".
func (f *Frontmatter) String(key string) string {
	if f == nil {
		return ""
	}
	s, _ := f.Raw[key].(string)
	return strings.TrimSpace(s)
}

func splitToolList(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
