package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg050 struct{}

var CFG050 = &cfg050{}

func init() { All = append(All, CFG050) }

func (r *cfg050) ID() string { return "CFG050" }

// authHeaderNames are request-header names whose value is a credential. They
// don't match the CFG007 *_TOKEN/_SECRET key-name heuristic, so they are matched
// explicitly (case-insensitively).
var authHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"api-key":             true,
	"apikey":              true,
	"x-auth-token":        true,
	"x-auth":              true,
	"x-access-token":      true,
	"authentication":      true,
}

// authSchemeRe strips a leading auth scheme word (Bearer/Basic/Token) so the
// remaining credential can be checked for placeholder/shell-ref exemption.
var authSchemeRe = regexp.MustCompile(`^(?i:bearer|basic|token)\s+`)

// placeholderRe matches obvious non-secret placeholder values that should not be
// flagged (e.g. "<your-token>", "changeme", "xxxxx", "TODO").
var placeholderRe = regexp.MustCompile(`(?i)^(<.*>|x{3,}|changeme|your[-_ ].*|todo|placeholder|example|\.\.\.)$`)

// Check flags hardcoded secrets in an MCP server's env or headers block — the
// MCP analogue of CFG007 (which only covers settings.json env). Covers every MCP
// source in scope. Shares CFG007's secret detector for values and key names.
func (r *cfg050) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		base := "mcpServers." + ref.Name

		for _, k := range sortedKeys(ref.Server.Env) {
			v := strings.TrimSpace(ref.Server.Env[k])
			if v == "" || shellRefRe.MatchString(v) {
				continue
			}
			if label, ok := matchSecretPattern(v); ok {
				findings = append(findings, secretFinding(base+".env."+k, "a hardcoded "+label, ref.File, t))
			} else if hasSecretSuffix(k) {
				findings = append(findings, secretFinding(base+".env."+k, "a secret-like name with a literal value", ref.File, t))
			}
		}

		for _, k := range sortedKeys(ref.Server.Headers) {
			v := strings.TrimSpace(ref.Server.Headers[k])
			if v == "" || shellRefRe.MatchString(v) {
				continue
			}
			if label, ok := matchSecretPattern(v); ok {
				findings = append(findings, secretFinding(base+".headers."+k, "a hardcoded "+label, ref.File, t))
				continue
			}
			// An auth header carrying a literal (non-placeholder) credential.
			if authHeaderNames[strings.ToLower(k)] {
				cred := strings.TrimSpace(authSchemeRe.ReplaceAllString(v, ""))
				if cred == "" || shellRefRe.MatchString(cred) || placeholderRe.MatchString(cred) {
					continue
				}
				what := "a hardcoded credential"
				if label, ok := matchSecretPattern(cred); ok {
					what = "a hardcoded " + label
				}
				findings = append(findings, secretFinding(base+".headers."+k, what, ref.File, t))
			}
		}
	}
	return findings
}

func secretFinding(loc, what, file string, t *Target) finding.Finding {
	return finding.Finding{
		RuleID:   "CFG050",
		Severity: finding.Error,
		File:     file,
		Message:  loc + " contains " + what + " — do not commit secrets to an MCP config; reference an environment variable (e.g. \"${TOKEN}\") instead" + userScopeNote(t),
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
