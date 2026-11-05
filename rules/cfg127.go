// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg127 struct{}

var CFG127 = &cfg127{}

func init() { All = append(All, CFG127) }

func (r *cfg127) ID() string { return "CFG127" }

// Check reports user-global MCP servers that start an interpreter on a script
// kept in a hidden home, cache, or temporary directory. SANDWORM_MODE used this
// shape to persist a generated server outside the configuration directory.
func (r *cfg127) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if !mcpScriptRuntime(ref.Server.Command) {
			continue
		}
		path := suspiciousMCPServerScript(ref.Server.Args)
		if path == "" || reviewedMCPInstallPath(path) {
			continue
		}
		dirName := hiddenPathDirectory(path)
		serverName := strings.TrimSpace(ref.Server.Env["MCP_SERVER_NAME"])
		correlated := dirName != "" && serverName != "" &&
			(strings.EqualFold(serverName, dirName) ||
				(strings.EqualFold(serverName, ref.Name) && strings.EqualFold(ref.Name, dirName)))
		if t.Scope != finding.ScopeUser && !correlated {
			continue
		}

		severity := finding.Info
		message := "mcpServers." + ref.Name + " starts " + ref.Server.Command +
			" on a script in an unusual hidden-home, cache, or temporary directory (" + path +
			"); review the file and move a legitimate server to a documented installation path"
		if correlated {
			severity = finding.Error
			message = "mcpServers." + ref.Name + " starts a hidden-home MCP script (" + path +
				") and MCP_SERVER_NAME matches its generated directory name \"" + dirName +
				"\" — this is the published SANDWORM_MODE persistence pattern; remove the server entry and investigate the script and package installation"
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

func mcpScriptRuntime(command string) bool {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(strings.Trim(strings.TrimSpace(command), `"'`), `\`, "/")))
	base = strings.TrimSuffix(base, ".exe")
	return base == "node" || base == "bun" || base == "deno" || base == "python" ||
		base == "python3" || base == "py" || base == "ruby"
}

func suspiciousMCPServerScript(args []string) string {
	for _, arg := range args {
		path := strings.Trim(strings.TrimSpace(arg), `"'`)
		lower := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
		if !scriptExtension(lower) {
			continue
		}
		if hiddenHomePath(lower) || temporaryMCPPath(lower) {
			return path
		}
	}
	return ""
}

func scriptExtension(path string) bool {
	for _, ext := range []string{".js", ".cjs", ".mjs", ".ts", ".py", ".rb"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func hiddenHomePath(path string) bool {
	if strings.HasPrefix(path, "~/.") || strings.HasPrefix(path, "$home/.") ||
		strings.HasPrefix(path, "${home}/.") || strings.HasPrefix(path, "%userprofile%/.") {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "file://"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if (parts[i] == "home" || parts[i] == "users") && parts[i+1] != "" &&
			strings.HasPrefix(parts[i+2], ".") && len(parts[i+2]) > 1 {
			return true
		}
	}
	return false
}

func temporaryMCPPath(path string) bool {
	p := "/" + strings.TrimPrefix(path, "/")
	return strings.Contains(p, "/tmp/") || strings.Contains(p, "/var/tmp/") ||
		strings.Contains(p, "/dev/shm/") || strings.Contains(p, "/.cache/") ||
		strings.Contains(p, "/library/caches/") || strings.Contains(p, "/appdata/local/temp/")
}

func reviewedMCPInstallPath(path string) bool {
	p := "/" + strings.TrimPrefix(strings.ToLower(strings.ReplaceAll(path, `\`, "/")), "/")
	for _, part := range []string{
		"/node_modules/", "/.npm/", "/.nvm/", "/.bun/install/", "/.deno/",
		"/.local/", "/.cache/pip/", "/.cache/uv/", "/.cache/pnpm/",
		"/.claude/", "/.cursor/", "/.continue/", "/.windsurf/", "/.codeium/",
	} {
		if strings.Contains(p, part) {
			return true
		}
	}
	return false
}

func hiddenPathDirectory(path string) string {
	p := strings.TrimSuffix(strings.ReplaceAll(strings.Trim(strings.TrimSpace(path), `"'`), `\`, "/"), "/")
	dir := filepath.Base(filepath.Dir(filepath.FromSlash(p)))
	return strings.TrimPrefix(dir, ".")
}
