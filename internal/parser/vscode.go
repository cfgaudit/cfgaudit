package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
)

// VSCodeTasks is a partial representation of a .vscode/tasks.json file, read by
// VS Code and its forks (Cursor, Windsurf). Only the fields cfgaudit inspects
// are decoded; unknown keys are ignored.
type VSCodeTasks struct {
	Version string       `json:"version,omitempty"`
	Tasks   []VSCodeTask `json:"tasks,omitempty"`
}

// VSCodeTask is a single task entry. A task whose RunOptions.RunOn is
// "folderOpen" executes automatically when the workspace is opened — a
// zero-click execution vector when the file is committed to a repo (CFG047).
type VSCodeTask struct {
	Label        string              `json:"label,omitempty"`
	Type         string              `json:"type,omitempty"`
	Command      string              `json:"command,omitempty"`
	RunOptions   *VSCodeRunOptions   `json:"runOptions,omitempty"`
	Presentation *VSCodePresentation `json:"presentation,omitempty"`
}

type VSCodeRunOptions struct {
	RunOn string `json:"runOn,omitempty"`
}

type VSCodePresentation struct {
	Reveal string `json:"reveal,omitempty"`
}

// ParseVSCodeTasks reads and decodes a .vscode/tasks.json file. The file format
// is JSONC (JSON with comments and trailing commas), so comments and trailing
// commas are stripped before decoding.
func ParseVSCodeTasks(path string) (*VSCodeTasks, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var v VSCodeTasks
	if err := json.Unmarshal(stripJSONC(data), &v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &v, nil
}

// VSCodeSettings is a .vscode/settings.json file, read by VS Code and its forks
// (Cursor, Windsurf). Settings are queried by their dotted name
// ("chat.tools.autoApprove"), but a file may write a setting either as that flat
// key or as nested objects ({"chat": {"tools": {"autoApprove": true}}}), and VS
// Code applies both (#640). Lookups therefore go through a value tree built the
// way VS Code builds it, not through Raw.
type VSCodeSettings struct {
	// Raw is the file's top-level key→value map, as written.
	Raw map[string]json.RawMessage

	// order is the top-level keys in file order. VS Code applies them in that
	// order, so it decides which spelling wins when both set the same setting.
	// Nil when the struct was built from Raw alone; sorted order is used then.
	order []string
	tree  *settingsNode
}

// settingsNode is one node of the value tree: an object (kids non-nil) or a
// leaf value.
type settingsNode struct {
	raw  json.RawMessage
	kids map[string]*settingsNode
}

func newSettingsNode(raw json.RawMessage) *settingsNode {
	var obj map[string]json.RawMessage
	if len(raw) > 0 && raw[0] == '{' && json.Unmarshal(raw, &obj) == nil {
		n := &settingsNode{kids: make(map[string]*settingsNode, len(obj))}
		for k, v := range obj {
			n.kids[k] = newSettingsNode(v)
		}
		return n
	}
	return &settingsNode{raw: raw}
}

// marshal renders a node back to JSON. An object node is rebuilt from its
// children, because a later dotted key may have written into it.
func (n *settingsNode) marshal() json.RawMessage {
	if n.kids == nil {
		return n.raw
	}
	m := make(map[string]json.RawMessage, len(n.kids))
	for k, c := range n.kids {
		m[k] = c.marshal()
	}
	out, _ := json.Marshal(m)
	return out
}

// buildTree mirrors toValuesTree/addToValueTree in VS Code's
// src/vs/platform/configuration/common/configuration.ts: each top-level key, in
// file order, is split on "." and its value assigned at that path, replacing
// whatever was there. A segment that already holds a non-object value makes VS
// Code drop the key ("Ignoring <key> as <segment> is ..."), and so does this.
// Keys inside a nested object are not split, so {"chat": {"tools.autoApprove":
// true}} does not set chat.tools.autoApprove, matching getConfigurationValue.
func (s *VSCodeSettings) buildTree() *settingsNode {
	keys := s.order
	if keys == nil {
		keys = make([]string, 0, len(s.Raw))
		for k := range s.Raw {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	root := &settingsNode{kids: map[string]*settingsNode{}}
	for _, key := range keys {
		segs := strings.Split(key, ".")
		curr := root
		ok := true
		for _, seg := range segs[:len(segs)-1] {
			next, exists := curr.kids[seg]
			if !exists {
				next = &settingsNode{kids: map[string]*settingsNode{}}
				curr.kids[seg] = next
			} else if next.kids == nil {
				ok = false
				break
			}
			curr = next
		}
		if ok {
			curr.kids[segs[len(segs)-1]] = newSettingsNode(s.Raw[key])
		}
	}
	return root
}

// lookup returns the effective value of a setting and whether it is set.
func (s *VSCodeSettings) lookup(key string) (json.RawMessage, bool) {
	if s == nil {
		return nil, false
	}
	if s.tree == nil {
		s.tree = s.buildTree()
	}
	n := s.tree
	for _, seg := range strings.Split(key, ".") {
		if n.kids == nil {
			return nil, false
		}
		next, ok := n.kids[seg]
		if !ok {
			return nil, false
		}
		n = next
	}
	return n.marshal(), true
}

// Nested reports whether a setting takes its effective value from the nested
// object form rather than from its own flat key. Up to VS Code 1.136.1 the
// nested form skipped the workspace scope and Restricted Mode filters
// (CVE-2026-70334, CVE-2026-81376; fixed in 1.136.2 by 0684cb5), so a rule that
// leans on those filters needs to know which spelling it is reading.
func (s *VSCodeSettings) Nested(key string) bool {
	val, ok := s.lookup(key)
	if !ok {
		return false
	}
	flat, isFlat := s.Raw[key]
	if !isFlat {
		return true
	}
	return !jsonEqual(flat, val)
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y interface{}
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// BoolField returns the value of a boolean setting and whether it was present as
// a JSON boolean. A missing key or a non-boolean value yields (false, false), so
// callers can distinguish "explicitly true" from "absent / wrong type".
func (s *VSCodeSettings) BoolField(key string) (val, present bool) {
	raw, ok := s.lookup(key)
	if !ok {
		return false, false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, false
	}
	return b, true
}

// StringField returns the value of a string setting and whether it was present as
// a JSON string. A missing key or a non-string value yields ("", false).
func (s *VSCodeSettings) StringField(key string) (val string, present bool) {
	raw, ok := s.lookup(key)
	if !ok {
		return "", false
	}
	var str string
	if err := json.Unmarshal(raw, &str); err != nil {
		return "", false
	}
	return str, true
}

// ObjectField returns the entries of an object-valued setting and whether the key
// was present as a JSON object. Entry values stay raw because callers differ: the
// auto-approve edits map is pattern→bool, while the URL map allows either a bool
// or an object of per-direction flags.
func (s *VSCodeSettings) ObjectField(key string) (map[string]json.RawMessage, bool) {
	raw, ok := s.lookup(key)
	if !ok {
		return nil, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	return m, true
}

// ParseVSCodeSettings reads and decodes a .vscode/settings.json file. Like
// tasks.json it is JSONC, so comments and trailing commas are stripped first.
func ParseVSCodeSettings(path string) (*VSCodeSettings, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseVSCodeSettingsBytes(data, path)
}

// ParseVSCodeSettingsBytes decodes settings.json content; path only labels errors.
func ParseVSCodeSettingsBytes(data []byte, path string) (*VSCodeSettings, error) {
	clean := stripJSONC(data)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(clean, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &VSCodeSettings{Raw: raw, order: topLevelKeyOrder(clean)}, nil
}

// topLevelKeyOrder returns the top-level keys of a JSON object in the order they
// first appear. A repeated key keeps its first position and, through
// json.Unmarshal, its last value, which is how JSON.parse treats it too.
func topLevelKeyOrder(data []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}
	var keys []string
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, _ := tok.(string)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil
		}
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	return keys
}

// stripJSONC removes // line comments, /* */ block comments, and trailing commas
// from JSON-with-comments (the format VS Code uses for tasks.json / settings.json)
// so the result decodes with encoding/json. String literals are left untouched.
func stripJSONC(b []byte) []byte {
	// A UTF-8 BOM is not part of the document and json.Unmarshal rejects it. A
	// real committed .claude-plugin/marketplace.json carries one, and decoding it
	// strictly turned that file into a scan error rather than an audit (found by
	// the 504-repo pre-release run).
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	out := make([]byte, 0, len(b))
	inString, escaped := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n') // preserve the line break
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && (b[i] != '*' || b[i+1] != '/') {
				i++
			}
			i++ // skip past the closing '*'; the loop's i++ skips the '/'
		case c == '}' || c == ']':
			out = dropTrailingComma(out)
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// dropTrailingComma removes a comma immediately preceding a closing } or ]
// (ignoring intervening whitespace) from the already-emitted output.
func dropTrailingComma(out []byte) []byte {
	j := len(out)
	for j > 0 {
		switch out[j-1] {
		case ' ', '\t', '\n', '\r':
			j--
			continue
		}
		break
	}
	if j > 0 && out[j-1] == ',' {
		return out[:j-1]
	}
	return out
}
