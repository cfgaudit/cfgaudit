// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg139 struct{}

// CFG139 reports a Kimi Code .kimi-code/local.toml that removes approval
// prompts with a project allow rule, or adds a folder outside the repository
// to the workspace (#1638).
var CFG139 = &cfg139{}

func init() { All = append(All, CFG139) }

func (r *cfg139) ID() string { return "CFG139" }

// kimiGuardedTools are the tools whose calls Kimi Code's sensitive-file and
// git-control-path guards ask about. In Kimi Code 2.6.0 a user or project
// allow rule is evaluated before both guards, so an allow that covers every
// call of one of these tools skips those prompts.
var kimiGuardedTools = map[string]bool{"Read": true, "Write": true, "Edit": true, "Bash": true, "*": true}

// kimiWildcardArgRe matches an argument pattern that constrains nothing.
var kimiWildcardArgRe = regexp.MustCompile(`^(?:\*{1,2}|/\*{1,2}|~/\*{1,2}|\*{1,2}/\*{1,2}|\./\*{1,2})$`)

// kimiSensitiveArgRe matches an argument pattern that names a file Kimi's
// sensitive-file guard asks about (tool/path-access.ts in 2.6.0: .env and its
// variants, SSH keys, credentials) or a git control path.
var kimiSensitiveArgRe = regexp.MustCompile(`(?i)(?:^|[/*])(?:\.env(?:\.[\w*-]+)?|id_(?:rsa|ed25519|ecdsa)[\w*]*|credentials[\w.*-]*|\.ssh|\.aws|\.git)(?:/|$|\*)`)

// kimiEnvTemplateRe matches the .env templates Kimi's guard exempts.
var kimiEnvTemplateRe = regexp.MustCompile(`(?i)(?:^|/)\.env\.(?:example|sample|template)$`)

// kimiPrivilegedCommands are the commands whose Bash allow auto-approves a
// privilege change, an irreversible write, the container daemon or a network
// transfer.
var kimiPrivilegedCommands = map[string]string{
	"sudo":   "runs commands as another user",
	"su":     "runs commands as another user",
	"doas":   "runs commands as another user",
	"rm":     "deletes files with no confirmation and no undo",
	"chmod":  "changes file permissions",
	"chown":  "changes file ownership",
	"docker": "reaches the container daemon, a root-equivalent interface on most setups",
	"curl":   "sends data to and fetches code from any host",
	"wget":   "fetches files from any host",
	"ssh":    "runs commands on other machines",
	"scp":    "copies files to and from other machines",
	"nc":     "opens raw network connections",
	"ncat":   "opens raw network connections",
}

const kimiAllowNote = ". Kimi Code loads .kimi-code/local.toml permission rules once the workspace is trusted, and its trust prompt defaults to trusting the folder; deny rules and the dangerous-command guard still run first"

// Check reports the weakening allow rules and the outside folders.
func (r *cfg139) Check(t *Target) []finding.Finding {
	if t == nil || t.KimiLocal == nil {
		return nil
	}
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG139", Severity: sev, Scope: t.Scope, File: t.KimiLocalFile, Message: msg})
	}
	for _, rule := range t.KimiLocal.Permission.Rules {
		if strings.TrimSpace(rule.Decision) != "allow" {
			continue
		}
		pattern := strings.TrimSpace(rule.Pattern)
		tool, arg := kimiSplitPattern(pattern)
		switch {
		case kimiGuardedTools[tool] && (arg == "" || kimiWildcardArgRe.MatchString(arg)):
			add(finding.Error, "permission.rules allows "+pattern+" with no constraint, so every "+kimiToolLabel(tool)+" call is approved without a prompt, including reads of .env, SSH keys and credentials and writes to .git, which Kimi Code otherwise asks about"+kimiAllowNote)
		case kimiGuardedTools[tool] && kimiSensitiveArgRe.MatchString(arg) && !kimiEnvTemplateRe.MatchString(arg):
			add(finding.Error, "permission.rules allows "+pattern+", which names a file Kimi Code's sensitive-file or git-control-path guard asks about, so that access is approved without a prompt"+kimiAllowNote)
		case tool == "Bash":
			if why, ok := kimiPrivilegedCommands[kimiFirstWord(arg)]; ok {
				add(finding.Warn, "permission.rules allows "+pattern+", which auto-approves "+kimiFirstWord(arg)+" with any arguments: it "+why+kimiAllowNote)
			}
		}
	}
	for _, dir := range t.KimiLocal.Workspace.AdditionalDir {
		if d := strings.TrimSpace(dir); kimiOutsideRepo(d) {
			add(finding.Info, "workspace.additional_dir adds "+d+", a folder outside the repository, to the workspace: once the folder is trusted, the agent can work there and Kimi Code loads the skills it holds. cfgaudit does not scan that folder")
		}
	}
	return findings
}

// kimiSplitPattern splits "Tool(arg)" into the tool name and the argument.
func kimiSplitPattern(p string) (tool, arg string) {
	i := strings.IndexByte(p, '(')
	if i < 0 || !strings.HasSuffix(p, ")") {
		return p, ""
	}
	return strings.TrimSpace(p[:i]), strings.TrimSpace(p[i+1 : len(p)-1])
}

func kimiToolLabel(tool string) string {
	if tool == "*" {
		return "tool"
	}
	return tool
}

// kimiFirstWord returns the command an argument pattern starts with.
func kimiFirstWord(arg string) string {
	f := strings.Fields(strings.TrimRight(arg, "*"))
	if len(f) == 0 {
		return ""
	}
	return path.Base(f[0])
}

// kimiOutsideRepo reports an additional_dir entry that leaves the
// repository: an absolute path, a home path, or a relative path above the
// root. Kimi resolves a relative entry against the project root.
func kimiOutsideRepo(d string) bool {
	if d == "" {
		return false
	}
	s := strings.ReplaceAll(d, `\`, "/")
	if strings.HasPrefix(s, "/") || s == "~" || strings.HasPrefix(s, "~/") || (len(s) > 1 && s[1] == ':') {
		return true
	}
	c := path.Clean(s)
	return c == ".." || strings.HasPrefix(c, "../")
}
