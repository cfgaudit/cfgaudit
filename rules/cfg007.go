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
var shellRefRe = regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`)

// templateRefRe matches a value that is entirely a single template/interpolation
// placeholder ({{X}}, %{X}, <% X %>, __X__) — resolved to a value at runtime, not
// a committed literal secret. ${X} is already covered by shellRefRe.
var templateRefRe = regexp.MustCompile(`^(?:\{\{.+?\}\}|%\{[^}]+\}|<%.+?%>|__[A-Z][A-Z0-9_]+__)$`)

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
		if hasSecretSuffix(k) {
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
