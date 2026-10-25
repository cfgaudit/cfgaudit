// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
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

	// Exec and Args are Copilot CLI's shell-free form: "Runs the executable
	// directly without a shell", with args "passed directly to exec". The
	// command rules read the two joined, as for Claude Code's exec form (#747).
	Exec string   `json:"exec,omitempty"`
	Args []string `json:"args,omitempty"`

	// Windows, Linux and OSX override the command per platform in a Copilot
	// custom agent's frontmatter hooks (#747).
	Windows string `json:"windows,omitempty"`
	Linux   string `json:"linux,omitempty"`
	OSX     string `json:"osx,omitempty"`

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
// execLine joins the exec form into one line for the command rules.
func (h AgentHook) execLine() string {
	if strings.TrimSpace(h.Exec) == "" {
		return ""
	}
	return strings.TrimSpace(strings.Join(append([]string{h.Exec}, h.Args...), " "))
}

func (h AgentHook) ShellCommand() string {
	for _, c := range []string{h.Bash, h.Shell, h.Command, h.Linux, h.OSX, h.Windows, h.execLine()} {
		if c != "" {
			return c
		}
	}
	return ""
}

// ShellCommands returns every distinct shell command this hook declares. A hook
// may carry a command per platform (Copilot's bash / powershell, Devin
// Desktop's command / powershell), and each one runs on its platform: a
// harmless powershell beside a malicious command still runs the command on
// macOS and Linux, so reading only the first would miss it.
func (h AgentHook) ShellCommands() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range []string{h.Bash, h.Shell, h.Command, h.Linux, h.OSX, h.Windows, h.execLine()} {
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// AgentHooks is the shared shape of both files: a version marker and a map from
// event name to the hooks that fire on it. Copilot additionally supports
// disableAllHooks, which turns the whole file off.
//
// Hooks is decoded lazily. Copilot's own SDK declares the settings-level field as
// `hooks?: Record<string, unknown>`, pinning no value shape, and a real committed
// .github/hooks/hooks.json writes the table keyed by hook NAME with an object
// value rather than by event with an array. A typed map turned that file into a
// scan error, which costs the whole file its coverage over one entry cfgaudit
// cannot read (#506).
type AgentHooks struct {
	// Version and the hooks table are kept raw so a file of another shape is a
	// file with no hooks, not a scan error (#613): a real Windsurf-era
	// .windsurf/hooks.json writes "version": "1.0" and `hooks` as an array of
	// named entries, which is not the event → handlers table Devin Desktop
	// documents and loads. Cursor writes "version": 1.
	Version         json.RawMessage `json:"version,omitempty"`
	DisableAllHooks bool            `json:"disableAllHooks,omitempty"`
	HooksRaw        json.RawMessage `json:"hooks,omitempty"`

	// RawHooks is HooksRaw when it is an object, keyed by event.
	RawHooks map[string]json.RawMessage `json:"-"`

	// Hooks holds the entries that decode as the modelled event → handlers shape.
	// Populated by ParseAgentHooks; entries of any other shape are left out rather
	// than guessed at.
	Hooks map[string][]AgentHook `json:"-"`
}

// decodeHooks fills Hooks from RawHooks, keeping only the entries that are a
// handler array. Anything else is skipped: modelling a shape without knowing
// whether the CLI honours it would invent findings on configuration nothing
// reads, which is the opposite error from missing coverage.
func (h *AgentHooks) decodeHooks() {
	if len(h.HooksRaw) > 0 && h.RawHooks == nil {
		_ = json.Unmarshal(h.HooksRaw, &h.RawHooks) // an array or scalar leaves it empty
	}
	if len(h.RawHooks) == 0 {
		return
	}
	out := make(map[string][]AgentHook, len(h.RawHooks))
	for event, raw := range h.RawHooks {
		var handlers []AgentHook
		if err := json.Unmarshal(raw, &handlers); err != nil || len(handlers) == 0 {
			continue
		}
		out[event] = handlers
	}
	if len(out) > 0 {
		h.Hooks = out
	}
}

// ParseAgentHooks reads a Cursor or Copilot hooks file. Both are plain JSON with
// the same top-level shape. A malformed file is an error, so a hooks file that is
// silently not being scanned is reported rather than treated as absent.
func ParseAgentHooks(path string) (*AgentHooks, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var h AgentHooks
	if err := json.Unmarshal(stripJSONC(data), &h); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	h.decodeHooks()
	return &h, nil
}

// CopilotAgentHooks decodes the `hooks:` event map in a Copilot custom agent's
// frontmatter (Copilot CLI 1.0.97, "agent-scoped declarative hooks"): the same
// event → handlers shape as .github/hooks/*.json, with windows, linux and osx
// overriding the command per platform. The hooks run only while that agent is
// selected, after workspace admission. Nil when absent or of another shape.
func CopilotAgentHooks(fm *Frontmatter) *AgentHooks {
	if fm == nil {
		return nil
	}
	raw, ok := fm.Raw["hooks"].(map[string]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	h := &AgentHooks{HooksRaw: b}
	h.decodeHooks()
	if len(h.Hooks) == 0 {
		return nil
	}
	return h
}
