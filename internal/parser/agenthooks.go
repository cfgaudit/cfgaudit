package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// AgentHook is one hook entry in Cursor's .cursor/hooks.json or Copilot's
// .github/hooks/*.json. The two formats overlap but are not identical, so every
// command spelling both use is decoded and Command() picks whichever is set.
//
// Cursor uses `command`. Copilot uses `bash` and `powershell`, with `command` as
// a cross-platform fallback — a matcher written for one of them would silently
// miss the other, so all three live here.
type AgentHook struct {
	Type    string `json:"type,omitempty"` // "command" (default), "prompt", or Copilot's "http"
	Command string `json:"command,omitempty"`
	Bash    string `json:"bash,omitempty"`
	Shell   string `json:"powershell,omitempty"`
	Matcher any    `json:"matcher,omitempty"`

	// URL, Headers and AllowedEnvVars belong to Copilot's http hook type, which
	// POSTs to an arbitrary endpoint. AllowedEnvVars names the environment
	// variables forwarded with that request.
	URL            string            `json:"url,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	AllowedEnvVars []string          `json:"allowedEnvVars,omitempty"`
}

// ShellCommand returns the shell command this hook runs, preferring the explicit
// per-platform spellings over the cross-platform fallback. Empty for a prompt or
// http hook, which run no command.
func (h AgentHook) ShellCommand() string {
	for _, c := range []string{h.Bash, h.Shell, h.Command} {
		if c != "" {
			return c
		}
	}
	return ""
}

// AgentHooks is the shared shape of both files: a version marker and a map from
// event name to the hooks that fire on it. Copilot additionally supports
// disableAllHooks, which turns the whole file off.
type AgentHooks struct {
	Version         int                    `json:"version,omitempty"`
	DisableAllHooks bool                   `json:"disableAllHooks,omitempty"`
	Hooks           map[string][]AgentHook `json:"hooks,omitempty"`
}

// ParseAgentHooks reads a Cursor or Copilot hooks file. Both are plain JSON with
// the same top-level shape. A malformed file is an error, so a hooks file that is
// silently not being scanned is reported rather than treated as absent.
func ParseAgentHooks(path string) (*AgentHooks, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var h AgentHooks
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &h, nil
}
