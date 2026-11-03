// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"strings"
	"unicode"
)

// agentCLINames are verified executable names for coding-agent CLIs. Aliases
// stay in this list because permission rules match the executable spelling.
var agentCLINames = []string{
	"codex", "claude", "gemini", "agent", "cursor-agent", "opencode", "qwen",
	"copilot", "kimi", "kimi-cli", "devin", "goose", "junie", "kilo",
	"kilocode", "amp", "aider", "cline", "crush", "droid", "q", "kiro-cli",
}

var agentCLISet = func() map[string]bool {
	out := make(map[string]bool, len(agentCLINames))
	for _, name := range agentCLINames {
		out[name] = true
	}
	return out
}()

func isAgentCLI(name string) bool { return agentCLISet[name] }

func canonicalAgentCLI(name string) string {
	switch name {
	case "agent", "cursor-agent":
		return "cursor-agent"
	case "kimi-cli":
		return "kimi"
	case "kilocode":
		return "kilo"
	default:
		return name
	}
}

func executableName(token string) string {
	token = strings.Trim(strings.TrimSpace(token), "'\"()[]{};,")
	token = strings.ToLower(filepath.Base(strings.ReplaceAll(token, `\`, "/")))
	for _, suffix := range []string{".exe", ".cmd", ".bat"} {
		token = strings.TrimSuffix(token, suffix)
	}
	return token
}

// shellWords performs the small shell-word subset command-site rules need:
// whitespace separates words and quotes keep a word together. Backslashes are
// preserved so Windows paths remain intact. Expansion is deliberately not attempted.
func shellWords(command string) []string {
	var words []string
	var b strings.Builder
	var quote rune
	flush := func() {
		if b.Len() > 0 {
			words = append(words, b.String())
			b.Reset()
		}
	}
	for i, r := range command {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote = r
		case unicode.IsSpace(r):
			flush()
		case r == '\\' && i+1 < len(command):
			// Preserve Windows path separators. POSIX escaped spaces are handled
			// conservatively as two tokens, which cannot create a false match.
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return words
}

type agentInvocation struct {
	agent string
	args  []string
}

var agentRunnerPackages = map[string]string{
	"@openai/codex":             "codex",
	"@anthropic-ai/claude-code": "claude",
	"@google/gemini-cli":        "gemini",
	"@qwen-code/qwen-code":      "qwen",
	"@github/copilot":           "copilot",
	"opencode-ai":               "opencode",
	"@kilocode/cli":             "kilo",
}

func agentInvocations(command string) []agentInvocation {
	var out []agentInvocation
	for _, segment := range splitCommands(command) {
		if inv, ok := agentInvocationFields(shellWords(segment)); ok {
			out = append(out, inv)
		}
	}
	return out
}

func agentInvocationExec(command string, args []string) (agentInvocation, bool) {
	fields := append(shellWords(command), args...)
	return agentInvocationFields(fields)
}

func agentInvocationFields(fields []string) (agentInvocation, bool) {
	i := 0
	for i < len(fields) && (isShellAssignment(fields[i]) || executableName(fields[i]) == "command" || executableName(fields[i]) == "exec") {
		i++
	}
	if i < len(fields) && executableName(fields[i]) == "env" {
		i++
		for i < len(fields) {
			if fields[i] == "-u" || fields[i] == "--unset" {
				i += 2
				continue
			}
			if strings.HasPrefix(fields[i], "-") || isShellAssignment(fields[i]) {
				i++
				continue
			}
			break
		}
	}
	if i >= len(fields) {
		return agentInvocation{}, false
	}
	name := executableName(fields[i])
	argsStart := i + 1
	if name == "npx" || name == "bunx" {
		i++
		for i < len(fields) && strings.HasPrefix(fields[i], "-") {
			if fields[i] == "-p" || fields[i] == "--package" {
				i += 2
			} else {
				i++
			}
		}
		if i >= len(fields) {
			return agentInvocation{}, false
		}
		name = agentRunnerPackages[strings.ToLower(fields[i])]
		i++
		argsStart = i
	}
	if !isAgentCLI(name) {
		return agentInvocation{}, false
	}
	return agentInvocation{agent: canonicalAgentCLI(name), args: fields[argsStart:]}, true
}

func isShellAssignment(word string) bool {
	if strings.HasPrefix(word, "-") {
		return false
	}
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i, r := range name {
		if !(r == '_' || unicode.IsLetter(r) || i > 0 && unicode.IsDigit(r)) {
			return false
		}
	}
	return true
}

// permissionWords additionally accepts Claude Code's legacy colon-separated
// Bash syntax while preserving the colon in a Windows drive prefix.
func permissionWords(inner string) []string {
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		if inner[i] == ':' && !(i == 1 && i+1 < len(inner) && (inner[i+1] == '/' || inner[i+1] == '\\')) {
			b.WriteByte(' ')
		} else {
			b.WriteByte(inner[i])
		}
	}
	return shellWords(b.String())
}

func agentAllowInvocation(inner string) (string, []string, bool) {
	inv, ok := agentInvocationFields(permissionWords(inner))
	if !ok {
		return "", nil, false
	}
	return inv.agent, inv.args, true
}

func trimmedPermissionArgs(args []string) []string {
	out := append([]string(nil), args...)
	for len(out) > 0 && out[len(out)-1] == "*" {
		out = out[:len(out)-1]
	}
	for i := range out {
		out[i] = strings.ToLower(strings.Trim(out[i], "'\""))
	}
	return out
}

func agentCLIReadOnly(agent string, args []string) bool {
	args = trimmedPermissionArgs(args)
	if len(args) == 1 && (args[0] == "--version" || args[0] == "--help") {
		return true
	}
	switch agent {
	case "claude":
		return equalWords(args, "doctor") || equalWords(args, "auth", "status") || equalWords(args, "mcp", "list") || equalWords(args, "mcp", "get")
	case "codex":
		return equalWords(args, "login", "status") || equalWords(args, "mcp", "list") || equalWords(args, "mcp", "get")
	case "gemini":
		return equalWords(args, "mcp", "list") || equalWords(args, "extensions", "list")
	case "cursor-agent", "qwen", "kimi", "devin":
		return equalWords(args, "status") || equalWords(args, "auth", "status") || equalWords(args, "mcp", "list")
	case "opencode", "kilo":
		return equalWords(args, "mcp", "list") || equalWords(args, "models")
	case "goose":
		return equalWords(args, "info") || equalWords(args, "doctor")
	}
	return false
}

func equalWords(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func agentBypass(inv agentInvocation) (string, bool) {
	args := make([]string, len(inv.args))
	for i, arg := range inv.args {
		args[i] = strings.ToLower(strings.Trim(arg, "'\"()[]{};,"))
	}
	has := func(values ...string) (string, bool) {
		for _, arg := range args {
			for _, value := range values {
				if arg == value {
					return value, true
				}
			}
		}
		return "", false
	}
	hasPair := func(flag string, values ...string) (string, bool) {
		for i := 0; i+1 < len(args); i++ {
			if args[i] != flag {
				continue
			}
			for _, value := range values {
				if args[i+1] == value {
					return flag + " " + value, true
				}
			}
		}
		return "", false
	}
	switch inv.agent {
	case "claude":
		if flag, ok := has("--dangerously-skip-permissions"); ok {
			return flag, true
		}
		return hasPair("--permission-mode", "bypasspermissions")
	case "codex":
		if flag, ok := has("--dangerously-bypass-approvals-and-sandbox", "--yolo", "--full-auto"); ok {
			return flag, true
		}
		return hasPair("-s", "danger-full-access")
	case "gemini", "qwen":
		if flag, ok := has("-y", "--yolo"); ok {
			return flag, true
		}
		return hasPair("--approval-mode", "yolo")
	case "cursor-agent":
		if flag, ok := has("-f", "--force", "--yolo", "--approve-mcps", "--trust"); ok {
			return flag, true
		}
		return hasPair("--sandbox", "disabled")
	case "opencode", "kilo":
		return has("--auto", "--yolo", "--dangerously-skip-permissions")
	case "kimi":
		return has("--print", "--yolo", "-y", "--auto-approve", "--afk")
	case "copilot":
		return has("--allow-all-tools", "--allow-all", "--yolo", "--no-sandbox")
	case "devin":
		return hasPair("--permission-mode", "dangerous", "yolo", "bypass")
	case "goose":
		if len(args) > 0 && args[0] == "run" {
			return "run", true
		}
	case "cline":
		return has("-y", "--yolo", "--auto-approve")
	case "crush":
		if len(args) > 0 && args[0] == "run" {
			return "run", true
		}
		return has("-y", "--yolo")
	case "aider":
		return has("--yes-always")
	case "droid":
		if flag, ok := has("--skip-permissions-unsafe"); ok {
			return flag, true
		}
		return hasPair("--auto", "high")
	case "q", "kiro-cli":
		if len(args) > 0 && args[0] == "chat" {
			_, nonInteractive := has("--no-interactive")
			if flag, trusted := has("--trust-all-tools"); trusted && nonInteractive {
				return flag, true
			}
		}
	}
	return "", false
}

var agentConfigDenySamples = []string{
	".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
	".vscode/settings.json", ".vscode/tasks.json", ".vscode/mcp.json",
	".cursor/mcp.json", ".cursor/hooks.json", ".codex/config.toml",
	".gemini/settings.json", ".qwen/settings.json", ".roo/mcp.json",
	".github/mcp.json", ".github/hooks/hook.json", ".devin/config.json",
	"opencode.json", ".kiro/settings/mcp.json", ".windsurf/hooks.json",
	"cline_mcp_settings.json", ".cline/rules/rule.md",
}

// hasAgentConfigDeny reports an effective Edit/Write deny that protects agent
// configuration. Write(path) is intentionally absent: Claude Code ignores that
// specifier form, while a bare Write deny remains effective.
func hasAgentConfigDeny(deny []string) bool {
	for _, entry := range deny {
		entry = strings.TrimSpace(entry)
		if entry == "Edit" || entry == "Write" {
			return true
		}
		if !strings.HasPrefix(entry, "Edit(") || !strings.HasSuffix(entry, ")") || ignoresParamForm(entry) {
			continue
		}
		pattern := strings.TrimSpace(entry[len("Edit(") : len(entry)-1])
		pattern = strings.ReplaceAll(pattern, `\`, "/")
		pattern = strings.TrimPrefix(pattern, "./")
		pattern = strings.TrimPrefix(pattern, "/")
		if pattern == "" {
			continue
		}
		re := globToPathRegexp(pattern)
		basenameOnly := !strings.Contains(pattern, "/")
		for _, sample := range agentConfigDenySamples {
			candidate := sample
			if basenameOnly {
				candidate = filepath.Base(sample)
			}
			if re.MatchString(candidate) {
				return true
			}
		}
	}
	return false
}
