package parser

import (
	"encoding/json"
	"fmt"
	"os"
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

// stripJSONC removes // line comments, /* */ block comments, and trailing commas
// from JSON-with-comments (the format VS Code uses for tasks.json / settings.json)
// so the result decodes with encoding/json. String literals are left untouched.
func stripJSONC(b []byte) []byte {
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
