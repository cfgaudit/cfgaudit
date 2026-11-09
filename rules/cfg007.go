// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg007 struct{}

var CFG007 = &cfg007{}

func init() { All = append(All, CFG007) }

func (r *cfg007) ID() string { return "CFG007" }

// secretValuePatterns matches values that look like vendor-issued credentials.
// Each pattern is anchored at the start and tight enough to avoid common false
// matches: a vendor prefix plus the length and alphabet the vendor issues.
// Order matters where prefixes overlap (OpenRouter's sk-or-v1- before the
// generic OpenAI sk-).
var secretValuePatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`^sk-ant-[A-Za-z0-9_\-]{10,}`), "Anthropic API key"},
	{regexp.MustCompile(`^sk-or-v1-[0-9a-f]{64}$`), "OpenRouter API key"},
	{regexp.MustCompile(`^sk-proj-[A-Za-z0-9_\-]{10,}`), "OpenAI project key"},
	{regexp.MustCompile(`^sk-[A-Za-z0-9]{32,}`), "OpenAI API key"},
	{regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{20,}`), "GitHub token"},
	{regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{80,}$`), "GitHub fine-grained token"},
	{regexp.MustCompile(`^glpat-[A-Za-z0-9_\-]{20,}`), "GitLab personal access token"},
	{regexp.MustCompile(`^glrt-[A-Za-z0-9_\-]{20,}`), "GitLab runner token"},
	{regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`), "AWS access key ID"},
	{regexp.MustCompile(`^ASIA[0-9A-Z]{16}$`), "AWS temporary access key ID"},
	{regexp.MustCompile(`^ABSK[A-Za-z0-9+/]{40,}={0,2}$`), "Amazon Bedrock API key"},
	{regexp.MustCompile(`^xox[abprs]-[A-Za-z0-9\-]{10,}`), "Slack token"},
	{regexp.MustCompile(`^AIza[0-9A-Za-z_\-]{35}$`), "Google API key"},
	{regexp.MustCompile(`^[sr]k_live_[A-Za-z0-9]{24,}$`), "Stripe secret key"},
	{regexp.MustCompile(`^hf_[A-Za-z]{34}$`), "Hugging Face token"},
	{regexp.MustCompile(`^npm_[A-Za-z0-9]{36}$`), "npm token"},
	{regexp.MustCompile(`^pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}$`), "PyPI token"},
	{regexp.MustCompile(`^SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}$`), "SendGrid API key"},
	{regexp.MustCompile(`^SK[0-9a-f]{32}$`), "Twilio API key"},
	{regexp.MustCompile(`^dapi[0-9a-f]{32}(?:-[0-9]+)?$`), "Databricks token"},
	{regexp.MustCompile(`^hv[sb]\.[A-Za-z0-9_\-]{90,}$`), "HashiCorp Vault token"},
	{regexp.MustCompile(`^lin_api_[A-Za-z0-9]{40}$`), "Linear API key"},
	{regexp.MustCompile(`^ntn_[0-9]{11}[A-Za-z0-9]{35}$`), "Notion token"},
	{regexp.MustCompile(`^gsk_[A-Za-z0-9]{52}$`), "Groq API key"},
	{regexp.MustCompile(`^xai-[A-Za-z0-9]{80}$`), "xAI API key"},
	{regexp.MustCompile(`^pplx-[A-Za-z0-9]{48}$`), "Perplexity API key"},
	{regexp.MustCompile(`^r8_[A-Za-z0-9]{37}$`), "Replicate token"},
	{regexp.MustCompile(`^glsa_[A-Za-z0-9]{32}_[0-9a-f]{8}$`), "Grafana service account token"},
	{regexp.MustCompile(`^dckr_pat_[A-Za-z0-9_\-]{27}$`), "Docker Hub token"},
	{regexp.MustCompile(`^shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}$`), "Shopify token"},
	{regexp.MustCompile(`^dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}$`), "Doppler token"},
	{regexp.MustCompile(`^AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}$`), "age secret key"},
	{regexp.MustCompile(`^lsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}$`), "LangSmith API key"},
	{regexp.MustCompile(`^pcsk_[A-Za-z0-9]{4,}_[A-Za-z0-9]{40,}$`), "Pinecone API key"},
	{regexp.MustCompile(`^tskey-[a-z]+-[A-Za-z0-9]{8,}-[A-Za-z0-9]{20,}$`), "Tailscale key"},
	{regexp.MustCompile(`^ATATT3[A-Za-z0-9_\-=]{150,}$`), "Atlassian API token"},
	{regexp.MustCompile(`^PMAK-[0-9a-f]{24}-[0-9a-f]{34}$`), "Postman API key"},
	{regexp.MustCompile(`^figd_[A-Za-z0-9_\-]{40}$`), "Figma token"},
	{regexp.MustCompile(`^sntry[su]_[A-Za-z0-9_=+/\-]{40,}$`), "Sentry token"},
	{regexp.MustCompile(`^[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}$`), "Telegram bot token"},
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
	return secretKeyName(k) && !pathValueRe.MatchString(v) && !relativeFileValueRe.MatchString(v) && !booleanValueRe.MatchString(v) && !literalPlaceholder(v)
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
	if t.Settings == nil {
		return nil
	}
	findings := envSecrets(t)
	return append(findings, permissionSecrets(t)...)
}

// permissionTokenSplitRe splits a permission entry into the words a key can
// be: a shell word, a quoted string, a header value.
var permissionTokenSplitRe = regexp.MustCompile("[\\s\"'=:(),;|&<>`]+")

// permissionAssignRe matches a NAME=value assignment in a permission entry,
// quoted or bare.
var permissionAssignRe = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^\s"';&|)]+))`)

// permissionSecrets reports a credential in a permissions.allow, ask or deny
// entry (#1168). Claude Code writes an approved command into the allow list
// as it was typed, so a token exported or sent in a session ends up there,
// and a committed settings file publishes it.
func permissionSecrets(t *Target) []finding.Finding {
	p := t.Settings.Permissions
	if p == nil {
		return nil
	}
	var findings []finding.Finding
	for _, list := range []struct {
		name    string
		entries []string
	}{{"allow", p.Allow}, {"ask", p.Ask}, {"deny", p.Deny}} {
		for i, entry := range list.entries {
			what := ""
			for _, tok := range permissionTokenSplitRe.Split(entry, -1) {
				if label, ok := matchSecretPattern(tok); ok {
					what = "a hardcoded " + label
					break
				}
			}
			if what == "" {
				for _, m := range permissionAssignRe.FindAllStringSubmatch(entry, -1) {
					v := m[2] + m[3] + m[4]
					if v != "" && !isSecretReference(v) && literalUnderSecretName(m[1], v) {
						what = "a literal value for " + m[1]
						break
					}
				}
			}
			if what == "" {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG007",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message: "permissions." + list.name + "[" + strconv.Itoa(i) + "] contains " + what +
					" — the entry was probably recorded when a command that used the key was approved. Rotate the key: deleting the entry is not enough, since it stays in git history" + userScopeNote(t),
			})
		}
	}
	return findings
}

// envSecrets reports a credential in the env block.
func envSecrets(t *Target) []finding.Finding {
	if t.Settings.Env == nil {
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
		// A header list: each header is checked like an MCP server's headers (#1053).
		if headers, ok := envHeaders(k, v); ok {
			for _, name := range sortedKeys(headers) {
				if what, ok := headerCredential(name, headers[name]); ok {
					findings = append(findings, finding.Finding{
						RuleID:   "CFG007",
						Severity: finding.Error,
						File:     t.SettingsFile,
						Message:  "env." + k + " header " + name + " contains " + what + " — do not commit secrets to settings.json; set the variable in your shell instead" + userScopeNote(t),
					})
				}
			}
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
	return matchSecretShape(v)
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
