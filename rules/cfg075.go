package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg075 struct{}

var CFG075 = &cfg075{}

func init() { All = append(All, CFG075) }

func (r *cfg075) ID() string { return "CFG075" }

// tlsVerifyOff describes an env var whose value turns off TLS certificate
// verification for the MCP server process. danger reports whether a given value
// is the disabling one; what names the effect for the finding message.
type tlsVerifyOff struct {
	danger func(string) bool
	what   string
}

var (
	// tlsCABundleOff matches a CA-bundle env value that effectively disables
	// verification: empty or pointed at /dev/null.
	tlsCABundleOff = func(v string) bool {
		t := strings.TrimSpace(v)
		return t == "" || t == "/dev/null"
	}

	// tlsEnvKillSwitches maps an upper-cased env key to the value condition that
	// disables certificate verification. Disjoint from CFG020 (code-exec env keys)
	// and CFG021 (proxy routing) — no key overlaps, so no double report.
	tlsEnvKillSwitches = map[string]tlsVerifyOff{
		"NODE_TLS_REJECT_UNAUTHORIZED": {isFalsy, "disables TLS certificate verification for every Node.js TLS connection"},
		"PYTHONHTTPSVERIFY":            {isFalsy, "disables HTTPS certificate verification for Python"},
		"GIT_SSL_NO_VERIFY":            {isTruthy, "disables TLS certificate verification for git"},
		"SSL_VERIFY":                   {isFalsy, "disables TLS certificate verification"},
		"NPM_CONFIG_STRICT_SSL":        {isFalsy, "disables TLS certificate verification for npm"},
		"PGSSLMODE":                    {func(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "disable") }, "runs the PostgreSQL connection without TLS"},
		"REQUESTS_CA_BUNDLE":           {tlsCABundleOff, "empties the CA bundle, disabling certificate verification for Python requests"},
		"CURL_CA_BUNDLE":               {tlsCABundleOff, "empties the CA bundle, disabling certificate verification for curl"},
	}

	// tlsVerifyKeyRe catches generic verify-toggle env keys (VERIFY_SSL,
	// HTTPX_SSL_VERIFY, FOO_TLS_VERIFY, …) so the explicit map need not list
	// every framework's spelling; a falsy value disables verification.
	tlsVerifyKeyRe = regexp.MustCompile(`(?i)^(.*_)?(ssl|tls)_?verify$|^verify_?(ssl|tls)$`)

	// sslmodeDisableRe matches sslmode=disable inside a DB/connection-string env
	// value (e.g. DATABASE_URL=postgres://…?sslmode=disable).
	sslmodeDisableRe = regexp.MustCompile(`(?i)sslmode\s*=\s*disable`)

	// connURLHostRe / connDSNHostRe extract the host from a connection string —
	// the URL authority (scheme://user:pass@HOST:port/…) or a libpq host=… DSN
	// field — so a loopback DB connection (where sslmode=disable is conventional
	// and has no network path to MITM) is not flagged.
	connURLHostRe = regexp.MustCompile(`(?i)://(?:[^@/\s]*@)?(\[[^\]]+\]|[^:/?\s"']+)`)
	connDSNHostRe = regexp.MustCompile(`(?i)(?:^|[\s;])host\s*=\s*([^\s;"']+)`)

	// tlsArgExact maps an unambiguous TLS-off arg token to its effect.
	tlsArgExact = map[string]string{
		"--insecure":             "disables TLS certificate verification",
		"--no-check-certificate": "disables TLS certificate verification (wget)",
	}

	// curlWgetCmdRe gates the ambiguous short flag -k to a curl/wget command,
	// where it means "insecure"; elsewhere -k has unrelated meanings.
	curlWgetCmdRe = regexp.MustCompile(`(?i)(^|/)(curl|wget)$`)
)

const tlsMITMTail = " — an on-path attacker can then MITM the server's TLS connections, reading and rewriting the agent's context and any forwarded credentials (a remote or cleartext endpoint per CFG049 is interceptable regardless of scheme); remove it"

// Check flags MCP servers whose env or args disables TLS certificate
// verification, turning an https:// endpoint into a MITM-able channel. Covers
// settings.json mcpServers and the project .mcp.json across every agent (via
// mcpServerRefs). Templated/$VAR values are runtime-resolved and skipped.
func (r *cfg075) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	add := func(file, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG075",
			Severity: finding.Error,
			File:     file,
			Message:  msg + userScopeNote(t),
		})
	}

	for _, ref := range t.mcpServerRefs() {
		loc := "mcpServers." + ref.Name

		for _, k := range sortedKeys(ref.Server.Env) {
			v := ref.Server.Env[k]
			if isSecretReference(v) {
				continue // ${VAR}/$(...) — resolved at runtime, can't judge
			}
			switch spec, ok := tlsEnvKillSwitches[strings.ToUpper(k)]; {
			case ok && spec.danger(v):
				add(ref.File, loc+".env sets "+k+"="+tlsDisplay(v)+" — "+spec.what+tlsMITMTail)
			case tlsVerifyKeyRe.MatchString(k) && isFalsy(v):
				add(ref.File, loc+".env sets "+k+"="+tlsDisplay(v)+" — disables TLS certificate verification"+tlsMITMTail)
			case sslmodeDisableRe.MatchString(v):
				if h := connStringHost(v); h != "" && isLoopbackHost(h) {
					break // loopback DB connection — sslmode=disable is conventional, no MITM path
				}
				// Do not echo the value — a connection string often carries a password.
				add(ref.File, loc+".env sets "+k+" with sslmode=disable, so the connection runs without TLS"+tlsMITMTail)
			}
		}

		cmdIsCurlWget := curlWgetCmdRe.MatchString(ref.Server.Command) ||
			(len(ref.Server.Args) > 0 && curlWgetCmdRe.MatchString(ref.Server.Args[0]))
		for _, a := range ref.Server.Args {
			tok := strings.TrimSpace(a)
			if what, ok := tlsArgExact[tok]; ok {
				add(ref.File, loc+".args passes "+tok+" — "+what+tlsMITMTail)
			} else if tok == "-k" && cmdIsCurlWget {
				add(ref.File, loc+".args passes -k — disables TLS certificate verification (curl)"+tlsMITMTail)
			}
		}
	}
	return findings
}

// tlsDisplay renders an env value for a message, showing an empty value as "".
func tlsDisplay(v string) string {
	if strings.TrimSpace(v) == "" {
		return `""`
	}
	return v
}

// connStringHost extracts the host from a DB connection string — the URL
// authority (scheme://user:pass@HOST:port/…) or a libpq host=… DSN field.
// Returns "" when no host is present (e.g. a Unix-socket DSN).
func connStringHost(v string) string {
	if m := connURLHostRe.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	if m := connDSNHostRe.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return ""
}

// isLoopbackHost reports whether a host names the local machine — there is no
// network path to MITM, so sslmode=disable against it is conventional local-dev
// configuration, not a finding.
func isLoopbackHost(h string) bool {
	h = strings.Trim(strings.ToLower(strings.TrimSpace(h)), "[]")
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return strings.HasPrefix(h, "127.")
}
