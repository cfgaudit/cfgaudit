// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// executablePathKeys are settings whose value is a program the editor starts
// (#995): the git binary, the PHP validator, the Python interpreter. A value
// inside the repository is a binary the repository ships, which runs when
// the folder is opened (CVE-2025-54130, CVE-2025-53536); a system path is the
// normal use and is not reported.
var executablePathKeys = []string{"git.path", "php.validate.executablePath", "python.defaultInterpreterPath", "python.pythonPath"}

// terminalProfileKeys hold terminal profiles, each with a path to the shell.
var terminalProfileKeys = []string{"terminal.integrated.profiles.linux", "terminal.integrated.profiles.osx", "terminal.integrated.profiles.windows"}

// copilotDebugURLKeys send Copilot's traffic to another endpoint, the VS Code
// counterpart of CFG005 (CVE-2026-47282).
var copilotDebugURLKeys = []string{
	"github.copilot.advanced.debug.overrideProxyUrl",
	"github.copilot.advanced.debug.overrideCapiUrl",
	"github.copilot.advanced.debug.testOverrideProxyUrl",
	"github.copilot.chat.advanced.debug.overrideProxyUrl",
	"github.copilot.chat.advanced.debug.overrideCapiUrl",
}

// agentLocationsKey registers folders custom agents are loaded from, like
// chat.hookFilesLocations for hooks (CVE-2026-102232).
const agentLocationsKey = "chat.agentFilesLocations"

// defaultAgentFilePaths are the agent folders VS Code reads anyway.
var defaultAgentFilePaths = map[string]bool{".github/agents": true, ".claude/agents": true, "~/.copilot/agents": true, "~/.claude/agents": true}

// checkEditorSurfaces reports the settings of #995: executable paths inside
// the repository, terminal auto-replies, Copilot debug endpoint overrides and
// extra agent folders.
func (r *cfg048) checkEditorSurfaces(t *Target) []finding.Finding {
	s := t.VSCodeSettings
	var out []finding.Finding
	add := func(sev finding.Severity, key, msg string) {
		out = append(out, finding.Finding{RuleID: "CFG048", Severity: sev, Scope: t.Scope, File: t.VSCodeSettingsFile, Key: key, Message: msg + nestedNote(t, key)})
	}
	for _, key := range executablePathKeys {
		for _, v := range stringOrList(s, key) {
			if repoPath(v) {
				add(finding.Error, key, key+" is \""+v+"\", a program inside the repository — the editor starts it when the folder is opened, so the repository chooses what runs (CVE-2025-54130). VS Code reads the key only after the workspace is trusted, forks without workspace trust apply it on open. Remove it, or point it at an installed program")
			}
		}
	}
	for _, key := range terminalProfileKeys {
		profiles, ok := s.ObjectField(key)
		if !ok {
			continue
		}
		for _, name := range sortedRawKeys(profiles) {
			var p struct {
				Path json.RawMessage `json:"path"`
			}
			if json.Unmarshal(profiles[name], &p) != nil {
				continue
			}
			for _, v := range rawStringOrList(p.Path) {
				if repoPath(v) {
					add(finding.Error, key, key+"."+name+".path is \""+v+"\", a program inside the repository — opening a terminal with this profile runs it (CVE-2025-53536). Point the profile at an installed shell")
				}
			}
		}
	}
	out = append(out, terminalEnvFindings(t)...)
	if replies, ok := s.ObjectField("terminal.integrated.autoReplies"); ok && len(replies) > 0 {
		sev := finding.Warn
		if onlyVSCodeDocumentedAutoReply(replies) {
			sev = finding.Info
		}
		add(sev, "terminal.integrated.autoReplies", "terminal.integrated.autoReplies types text into the terminal when a pattern appears ("+quoteList(sortedRawKeys(replies))+") — committed, it answers prompts in the user's terminal on the repository's behalf (CVE-2026-21523). Remove it")
	}
	for _, key := range copilotDebugURLKeys {
		if v := copilotAdvancedString(t, key); v != "" {
			add(finding.Warn, key, key+" is \""+v+"\" — Copilot sends its requests, with the user's token, to an endpoint the repository chose (CVE-2026-47282). Remove it")
		}
	}
	if entries, ok := s.ObjectField(agentLocationsKey); ok {
		var added []string
		for _, p := range sortedRawKeys(entries) {
			var on bool
			if json.Unmarshal(entries[p], &on) == nil && on && !defaultAgentFilePaths[strings.TrimSuffix(filepath.ToSlash(p), "/")] {
				added = append(added, p)
			}
		}
		if len(added) > 0 {
			add(finding.Warn, agentLocationsKey, agentLocationsKey+" registers the agent folder "+quoteList(added)+" — VS Code loads custom agent definitions from it, outside the folders a reviewer expects (CVE-2026-102232); cfgaudit does not follow a registered folder. Remove it, or keep agents in .github/agents")
		}
	}
	return out
}

// copilotAdvancedString reads a Copilot debug key in its flat form or inside
// the "github.copilot.advanced" object, whose own keys contain a dot
// ("debug.overrideProxyUrl") or nest it ({"debug": {"overrideProxyUrl": ...}}).
func copilotAdvancedString(t *Target, key string) string {
	s := t.VSCodeSettings
	if v, ok := s.StringField(key); ok {
		return strings.TrimSpace(v)
	}
	for _, obj := range []string{"github.copilot.chat.advanced", "github.copilot.advanced"} {
		inner, ok := strings.CutPrefix(key, obj+".")
		if !ok {
			continue
		}
		fields, ok := s.ObjectField(obj)
		if !ok {
			return ""
		}
		var v string
		if raw, ok := fields[inner]; ok && json.Unmarshal(raw, &v) == nil {
			return strings.TrimSpace(v)
		}
		head, rest, _ := strings.Cut(inner, ".")
		var nested map[string]json.RawMessage
		if raw, ok := fields[head]; ok && json.Unmarshal(raw, &nested) == nil && json.Unmarshal(nested[rest], &v) == nil {
			return strings.TrimSpace(v)
		}
		return ""
	}
	return ""
}

// stringOrList returns a setting that is a string or a list of strings.
func stringOrList(s interface {
	RawValue(string) (json.RawMessage, bool)
}, key string) []string {
	raw, ok := s.RawValue(key)
	if !ok {
		return nil
	}
	return rawStringOrList(raw)
}

func rawStringOrList(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

// localEnvDirs are directories a developer creates in the workspace and does
// not commit: virtual environments and tool installs. An interpreter there
// ("${workspaceFolder}/.venv/bin/python") was every corpus hit of the
// executable-path check before it was excluded.
var localEnvDirs = map[string]bool{
	".venv": true, "venv": true, "env": true, ".env": true, ".pixi": true, ".conda": true,
	".tox": true, ".direnv": true, "node_modules": true, "mise-tools": true, ".mise": true,
}

// repoPath reports whether an executable setting names a file inside the
// workspace: ${workspaceFolder}, or a relative path with a directory part,
// unless the path runs through a local environment directory. A bare name
// ("bash", "git") is looked up on PATH.
func repoPath(v string) bool {
	v = strings.TrimSpace(v)
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }) {
		if localEnvDirs[part] {
			return false
		}
	}
	if strings.Contains(v, "${workspaceFolder") || strings.Contains(v, "${workspaceRoot}") {
		return true
	}
	if v == "" || filepath.IsAbs(v) || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "%") || strings.HasPrefix(v, "/") || (len(v) > 1 && v[1] == ':') {
		return false
	}
	return strings.ContainsAny(v, `/\`)
}

// popularExtensions are often-installed VS Code extension IDs a squatted
// lookalike imitates (#995). The list is short and kept by hand; there is no
// marketplace lookup in an offline scan.
var popularExtensions = []string{
	"ms-python.python", "ms-python.vscode-pylance", "ms-vscode.cpptools", "esbenp.prettier-vscode",
	"dbaeumer.vscode-eslint", "github.copilot", "github.copilot-chat", "ms-azuretools.vscode-docker",
	"golang.go", "rust-lang.rust-analyzer", "redhat.java", "redhat.vscode-yaml", "ms-toolsai.jupyter",
	"eamodio.gitlens", "ms-vscode-remote.remote-containers", "ms-vscode-remote.remote-ssh",
	"bradlc.vscode-tailwindcss", "ms-dotnettools.csharp", "anthropic.claude-code", "vscodevim.vim",
	"ritwickdey.liveserver", "christian-kohler.path-intellisense", "streetsidesoftware.code-spell-checker",
}

// extensionLookalike returns the popular ID a recommended one imitates, or "".
func extensionLookalike(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	pub, name, ok := strings.Cut(id, ".")
	if !ok {
		return ""
	}
	for _, p := range popularExtensions {
		if id == p {
			return ""
		}
	}
	for _, p := range popularExtensions {
		ppub, pname, _ := strings.Cut(p, ".")
		if levenshtein(id, p) <= 2 || (name == pname && pub != ppub && levenshtein(pub, ppub) <= 2) {
			return p
		}
	}
	return ""
}

// checkExtensionRecommendations reports recommended extension IDs that are a
// near miss of a popular one: users install a recommendation from the
// prompt VS Code shows on open (CVE-2026-69370, CVE-2026-58650).
func checkExtensionRecommendations(t *Target) []finding.Finding {
	var out []finding.Finding
	ids := append([]string(nil), t.VSCodeExtensions...)
	sort.Strings(ids)
	for _, id := range ids {
		if p := extensionLookalike(id); p != "" {
			out = append(out, finding.Finding{RuleID: "CFG048", Severity: finding.Warn, Scope: t.Scope, File: t.VSCodeExtensionsFile, Key: "recommendations",
				Message: "recommendations lists the extension \"" + id + "\", a near miss of \"" + p + "\" — VS Code offers to install a recommendation when the folder is opened, and a lookalike ID is how squatted extensions get installed (CVE-2026-69370). Check the publisher on the marketplace, or recommend \"" + p + "\""})
		}
	}
	return out
}

// vscodeHomeRe matches the VS Code variables that expand to the user's home
// directory, so a path under them counts as home-relative, not as a path in
// the repository; ${workspaceFolder} stays repository-relative.
var vscodeHomeRe = regexp.MustCompile(`\$\{(?:userHome|env:HOME|env:USERPROFILE)\}`)

// terminalEnvKeys set the environment of every integrated-terminal shell
// (#1399). VS Code 1.145.2 marks all three `restricted: true`
// (terminalConfiguration.ts), so it reads them only in a trusted workspace.
var terminalEnvKeys = []string{"terminal.integrated.env.linux", "terminal.integrated.env.osx", "terminal.integrated.env.windows"}

// interactiveShellEnvVars run code in an interactive shell only, which is what
// an integrated terminal is and a hook or MCP server is not, so they extend
// the shared code-execution list for this surface alone. ENV names a file in
// the same way as BASH_ENV, and the shell expands it first, so it gets the
// startup-file treatment.
var interactiveShellEnvVars = map[string]string{
	"PROMPT_COMMAND": "bash runs this command before every prompt",
	"ENV":            "an interactive sh, dash or ksh sources this file at startup",
}

// terminalEnvFindings reports a terminal.integrated.env.* variable that loads
// or runs code in each terminal, with CFG110's classification and severities:
// the shared code-execution list, and a startup file that names a path
// outside the repository at info. The value is not quoted. A user's own
// settings are not reported: a terminal environment there is their choice.
func terminalEnvFindings(t *Target) []finding.Finding {
	if t.Scope == finding.ScopeUser {
		return nil
	}
	var out []finding.Finding
	for _, key := range terminalEnvKeys {
		raw, ok := t.VSCodeSettings.ObjectField(key)
		if !ok {
			continue
		}
		env := map[string]string{}
		for k, v := range raw {
			var s string
			if json.Unmarshal(v, &s) == nil {
				env[k] = s
			}
		}
		type hit struct{ name, mechanism string }
		var hits []hit
		for _, h := range codeExecEnvHits(env, true) {
			hits = append(hits, hit{h.Key, h.Mechanism})
		}
		for _, name := range sortedKeys(env) {
			if m, ok := interactiveShellEnvVars[strings.ToUpper(name)]; ok && strings.TrimSpace(env[name]) != "" {
				hits = append(hits, hit{name, m})
			}
		}
		for _, h := range hits {
			upper := strings.ToUpper(h.name)
			sev := finding.Error
			tail := ", so the repository chooses code that runs in every integrated terminal, including the ones the agent runs its commands in"
			if (startupFileVars[upper] || upper == "ENV") && !hasRepoRelativeEntry(vscodeHomeRe.ReplaceAllString(env[h.name], "$$HOME")) {
				sev = finding.Info
				tail = ". The path is absolute or home-relative, so it names a file on the machine rather than one in the repository; on any other machine it is that machine's file or nothing"
			}
			out = append(out, finding.Finding{
				RuleID:   "CFG048",
				Severity: sev,
				Scope:    t.Scope,
				File:     t.VSCodeSettingsFile,
				Key:      key,
				Message: key + " sets " + h.name + ": " + h.mechanism + tail +
					". VS Code reads the key only after the workspace is trusted, forks without workspace trust apply it on open. Remove it" + nestedNote(t, key),
			})
		}
	}
	return out
}

// vscodeDocumentedAutoReplyPrompt is the pattern in VS Code's own
// terminal.integrated.autoReplies example, which answers cmd's Ctrl+C prompt
// (#1679).
const vscodeDocumentedAutoReplyPrompt = "Terminate batch job (Y/N)"

// onlyVSCodeDocumentedAutoReply reports whether autoReplies is exactly that
// documented pair. Any other prompt stays a warning.
func onlyVSCodeDocumentedAutoReply(replies map[string]json.RawMessage) bool {
	if len(replies) != 1 {
		return false
	}
	raw, ok := replies[vscodeDocumentedAutoReplyPrompt]
	if !ok {
		return false
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return v == "Y\r"
}
