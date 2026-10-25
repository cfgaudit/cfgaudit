// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg007 struct{}

var CFG007 = &cfg007{}

func init() { All = append(All, CFG007) }

func (r *cfg007) ID() string { return "CFG007" }

// secretValuePatterns matches values that look like vendor-issued credentials.
// Each pattern is anchored at the start and tight enough to avoid common false matches.
var secretValuePatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`^sk-ant-[A-Za-z0-9_\-]{10,}`), "Anthropic API key"},
	{regexp.MustCompile(`^sk-proj-[A-Za-z0-9_\-]{10,}`), "OpenAI project key"},
	{regexp.MustCompile(`^sk-[A-Za-z0-9]{32,}`), "OpenAI API key"},
	{regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{20,}`), "GitHub token"},
	{regexp.MustCompile(`^glpat-[A-Za-z0-9_\-]{20,}`), "GitLab personal access token"},
	{regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`), "AWS access key ID"},
	{regexp.MustCompile(`^xox[abprs]-[A-Za-z0-9\-]{10,}`), "Slack token"},
	{regexp.MustCompile(`^AIza[0-9A-Za-z_\-]{35}$`), "Google API key"},
}

// secretSuffixes are key-name endings that imply the value is meant to be a secret.
var secretSuffixes = []string{
	"_TOKEN", "_SECRET", "_PASSWORD", "_PASSWD",
	"_API_KEY", "_PRIVATE_KEY", "_ACCESS_KEY", "_AUTH_KEY",
	"_CREDENTIAL", "_CREDENTIALS",
}

// shellRefRe matches a value that is a single shell-variable reference (e.g. "$FOO" or "${FOO}").
//
// The default forms "${FOO:-}", "${FOO-}" and "${FOO:-${BAR}}" count too:
// Claude Code expands ${VAR:-default} in .mcp.json and plugin MCP configs, and
// an empty or referenced default commits no value. A literal default
// ("${TOKEN:-sk-live-...}") is a committed secret and does not match (#852).
var shellRefRe = regexp.MustCompile(`^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*(?::?-(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)?)?\})$`)

// pathValueRe matches a value that is a filesystem path: absolute, home- or
// dot-relative, or a Windows drive path, with no whitespace.
var pathValueRe = regexp.MustCompile(`^(?:/|~/|\./|\.\./|[A-Za-z]:[\\/]|%[A-Za-z_]+%[\\/]|\$HOME/|\$\{HOME\}/)\S*$`)

// literalUnderSecretName reports whether the literal value v of a key with a
// secret-like name is the secret itself. A file path is not:
// GOOGLE_APPLICATION_CREDENTIALS and its kind hold the path of a key file by
// convention, and the file is not in the config (#852). Nor is a relative
// path with a directory and a file extension (".codex/credentials/dev.json"),
// or a boolean switch ("BRIDGE_PERSISTENT_SECRET": "true") (#891).
func literalUnderSecretName(k, v string) bool {
	v = strings.TrimSpace(v)
	return hasSecretSuffix(k) && !pathValueRe.MatchString(v) && !relativeFileValueRe.MatchString(v) && !booleanValueRe.MatchString(v)
}

// relativeFileValueRe matches a relative file path with at least one directory
// and an extension that starts with a letter: ".codex/credentials/dev.json".
var relativeFileValueRe = regexp.MustCompile(`^[\w.\-]+(?:/[\w.\-]+)*/[\w.\-]*\.[A-Za-z][A-Za-z0-9]{0,4}$`)

// booleanValueRe matches a boolean switch value.
var booleanValueRe = regexp.MustCompile(`^(?i:true|false|yes|no|on|off)$`)

// templateRefRe matches a value that is entirely a single template/interpolation
// placeholder ({{X}}, ${{X}}, %{X}, <% X %>, __X__) — resolved to a value at
// runtime, not a committed literal secret. Bare ${X} is covered by shellRefRe.
//
// The ${{...}} form is the GitHub Actions / CI expression syntax and is the most
// common header value in real configs: 7 of the 15 request headers in a 108-file
// Continue sample are ${{ secrets.NAME }}. shellRefRe rejects it because of the
// second brace, so without this branch every one of them reads as a committed
// literal.
//
// {env:NAME} and {file:path} are OpenCode's config substitutions (#612):
// packages/opencode/src/config/variable.ts applies both to the whole config text
// before parsing ("Apply {env:VAR} and {file:path} substitutions to config
// text"). In a 673-repository OpenCode sample, almost every credential under an
// mcp entry's environment or headers was written this way, and reading it as a
// literal reported a hardcoded secret in each.
//
// ${input:id} is VS Code's prompted input in mcp.json: the editor asks for the
// value and stores it, so the committed text names a prompt, not a secret. The
// same sample carried it in an OpenCode file copied from a VS Code config.
//
// ${env:NAME} is how Cursor and VS Code read an environment variable in
// mcp.json ("command, args, env, url, and headers", Cursor's MCP docs), and
// ${user_config.KEY} is a Claude Code plugin's user option, which Claude Code
// substitutes in the plugin's MCP server config (plugins reference). Both were
// reported as hardcoded credentials in real repositories (#821).
var templateRefRe = regexp.MustCompile(`^(?:\$?\{\{.+?\}\}|%\{[^}]+\}|<%.+?%>|__[A-Z][A-Z0-9_]+__|\{env:[^}]+\}|\{file:[^}]+\}|\$\{input:[^}]+\}|\$\{env:[A-Za-z_][A-Za-z0-9_]*\}|\$\{user_config\.[A-Za-z_][A-Za-z0-9_]*\})$`)

// screamingPlaceholderRe matches an all-caps token that names a credential rather
// than being one: TU_API_KEY_AQUI, MY_TOKEN_HERE, API_KEY. A real key has mixed
// case or digits somewhere; a value that is nothing but capitals, underscores and
// a credential word is a template someone forgot to fill in.
//
// Deliberately narrow. It requires the credential word, so an all-caps value that
// is not obviously a placeholder is still reported.
var screamingPlaceholderRe = regexp.MustCompile(`^[A-Z][A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PASS)[A-Z_]*$`)

// isSecretReference reports whether v is a reference/placeholder that resolves to
// a secret at runtime — a shell variable or a template placeholder — rather than
// a committed literal, so the hardcoded-secret rules (CFG007/050/054) skip it.
func isSecretReference(v string) bool {
	v = strings.TrimSpace(v)
	return shellRefRe.MatchString(v) || templateRefRe.MatchString(v)
}

func (r *cfg007) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Env == nil {
		return nil
	}
	keys := make([]string, 0, len(t.Settings.Env))
	for k := range t.Settings.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var findings []finding.Finding
	for _, k := range keys {
		v := t.Settings.Env[k]
		if v == "" || isSecretReference(v) {
			continue
		}
		if label, ok := matchSecretPattern(v); ok {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG007",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message:  "env." + k + " contains a hardcoded " + label + " — do not commit secrets to settings.json; reference a shell variable instead" + userScopeNote(t),
			})
			continue
		}
		if literalUnderSecretName(k, v) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG007",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message:  "env." + k + " has a secret-like name with a literal value — do not commit secrets to settings.json; reference a shell variable instead (e.g. \"$" + k + "\")" + userScopeNote(t),
			})
		}
	}
	return findings
}

func matchSecretPattern(v string) (string, bool) {
	for _, p := range secretValuePatterns {
		if p.re.MatchString(v) {
			return p.label, true
		}
	}
	return "", false
}

func hasSecretSuffix(key string) bool {
	upper := strings.ToUpper(key)
	for _, suffix := range secretSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}
