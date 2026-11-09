// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg127 struct{}

var CFG127 = &cfg127{}

func init() { All = append(All, CFG127) }

func (r *cfg127) ID() string { return "CFG127" }

// Check reports MCP servers that start an interpreter on a script kept in a
// hidden home, cache, or temporary directory. SANDWORM_MODE used this shape to
// persist a generated server outside the configuration directory. The published
// correlation, MCP_SERVER_NAME naming the hidden directory, is reported in every
// scope; the location alone only in user scope.
func (r *cfg127) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if !mcpScriptRuntimeRe.MatchString(runtimeName(ref.Server.Command)) {
			continue
		}
		script := suspiciousMCPServerScript(ref.Server.Args)
		if script == "" {
			continue
		}
		dirName := hiddenHomeDir(normalizedMCPPath(script))
		serverName := strings.TrimSpace(ref.Server.Env["MCP_SERVER_NAME"])
		correlated := dirName != "" && strings.EqualFold(serverName, dirName)
		if t.Scope != finding.ScopeUser && !correlated {
			continue
		}

		severity := finding.Info
		message := "mcpServers." + ref.Name + " starts " + ref.Server.Command +
			" on a script in an unusual hidden-home, cache, or temporary directory (" + script +
			"); review the file and move a legitimate server to a documented installation path"
		if correlated {
			severity = finding.Error
			message = "mcpServers." + ref.Name + " starts a hidden-home MCP script (" + script +
				") and MCP_SERVER_NAME matches its directory name \"" + dirName +
				"\": this is the published SANDWORM_MODE persistence pattern. Remove the server entry and investigate the script and package installation"
		}
		out = append(out, finding.Finding{
			RuleID:   "CFG127",
			Severity: severity,
			File:     ref.File,
			Key:      "mcpServers." + ref.Name,
			Message:  message,
		})
	}
	return out
}

// mcpScriptRuntimeRe matches a language runtime, with a version on Python such
// as python3.12.
var mcpScriptRuntimeRe = regexp.MustCompile(`^(?:node|nodejs|bun|deno|ruby|py|pypy3?|python[0-9.]*)$`)

func runtimeName(command string) string {
	base := path.Base(normalizedMCPPath(command))
	return strings.TrimSuffix(base, ".exe")
}

// normalizedMCPPath returns a config path in lower case with forward slashes,
// so one check covers Linux, macOS and Windows.
func normalizedMCPPath(p string) string {
	p = strings.ToLower(strings.ReplaceAll(strings.Trim(strings.TrimSpace(p), `"'`), `\`, "/"))
	return strings.TrimPrefix(p, "file://")
}

func suspiciousMCPServerScript(args []string) string {
	for _, arg := range args {
		p := normalizedMCPPath(arg)
		if scriptExtension(p) && !reviewedMCPInstallPath(p) && (hiddenHomeDir(p) != "" || temporaryMCPPath(p)) {
			return strings.Trim(strings.TrimSpace(arg), `"'`)
		}
	}
	return ""
}

func scriptExtension(p string) bool {
	switch path.Ext(p) {
	case ".js", ".cjs", ".mjs", ".ts", ".py", ".rb":
		return true
	}
	return false
}

// homeRelative returns p below a home directory, and whether p is below one.
func homeRelative(p string) (string, bool) {
	for _, home := range []string{"~/", "$home/", "${home}/", "%userprofile%/", "/root/"} {
		if rest, ok := strings.CutPrefix(p, home); ok {
			return rest, true
		}
	}
	p = strings.TrimPrefix(p[strings.Index(p, ":")+1:], "/")
	for _, home := range []string{"home/", "users/"} {
		if rest, ok := strings.CutPrefix(p, home); ok {
			if _, below, ok := strings.Cut(rest, "/"); ok {
				return below, true
			}
		}
	}
	return "", false
}

// hiddenHomeDir returns the name of the hidden directory directly under a home
// directory that holds p, without its leading dot, or "".
func hiddenHomeDir(p string) string {
	rest, ok := homeRelative(p)
	if !ok {
		return ""
	}
	dir, _, nested := strings.Cut(rest, "/")
	if !nested || !strings.HasPrefix(dir, ".") {
		return ""
	}
	return strings.TrimPrefix(dir, ".")
}

// temporaryMCPPath reports an operating-system temporary or cache location. A
// project folder that happens to be called tmp or .cache does not count, so a
// relative path never does.
func temporaryMCPPath(p string) bool {
	for _, root := range []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/var/folders/", "/dev/shm/"} {
		if strings.HasPrefix(p, root) {
			return true
		}
	}
	rest, ok := homeRelative(p)
	return ok && (strings.HasPrefix(rest, ".cache/") || strings.HasPrefix(rest, "library/caches/") ||
		strings.HasPrefix(rest, "appdata/local/temp/"))
}

func reviewedMCPInstallPath(p string) bool {
	p = "/" + strings.TrimPrefix(p, "/")
	for _, part := range []string{
		"/node_modules/", "/.npm/", "/.nvm/", "/.bun/install/", "/.deno/", "/.volta/", "/.fnm/",
		"/.asdf/", "/.pyenv/", "/.rbenv/", "/.local/", "/.config/", "/.cache/pip/", "/.cache/uv/", "/.cache/pnpm/",
		"/.claude/", "/.codex/", "/.gemini/", "/.cursor/", "/.continue/", "/.windsurf/", "/.codeium/",
		"/.vscode/", "/.vscode-server/",
	} {
		if strings.Contains(p, part) {
			return true
		}
	}
	return false
}
