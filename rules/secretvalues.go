// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// Secret shapes that are not a single prefixed token: a PEM private key, a
// webhook URL whose path is the credential, a connection string with a literal
// password, and a JSON Web Token (#1053). matchSecretPattern consults them after
// the prefixed vendor formats, so CFG007, CFG050 and CFG054 all see them.

// pemPrivateKeyRe matches the header of a PEM private key anywhere in a value:
// "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
// "-----BEGIN OPENSSH PRIVATE KEY-----" and the like. A public key or a
// certificate has a different header and does not match.
var pemPrivateKeyRe = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)

// webhookPatterns are URLs that are their own credential: anyone who has the
// URL can post to the channel.
var webhookPatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`^https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_\-]{20,}`), "Slack webhook URL"},
	{regexp.MustCompile(`^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]{60,}`), "Discord webhook URL"},
}

// connStringRe matches a URL with a user and a literal password:
// postgres://user:password@host/db, mongodb+srv://user:password@cluster/...
var connStringRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*://([^\s/:@]+):([^\s/@]+)@([^\s/:?#]+)`)

// accountKeyRe matches an Azure storage or Service Bus connection string's key
// part: "AccountKey=<base64>" or "SharedAccessKey=<base64>".
var accountKeyRe = regexp.MustCompile(`(?:^|;)\s*(?:AccountKey|SharedAccessKey)=([A-Za-z0-9+/]{20,}={0,2})`)

// defaultPasswords are the passwords of local development databases and
// examples. A connection string that carries one is not a leaked credential.
var defaultPasswords = map[string]bool{
	"password": true, "pass": true, "passwd": true, "secret": true, "postgres": true,
	"root": true, "admin": true, "example": true, "changeme": true, "test": true,
	"mysql": true, "guest": true, "user": true,
}

// loopbackHosts are hosts a committed connection string can only reach on the
// developer's own machine or in a local container.
var loopbackHosts = map[string]bool{
	"localhost": true, "127.0.0.1": true, "0.0.0.0": true, "::1": true, "[::1]": true,
	"host.docker.internal": true, "db": true, "postgres": true, "mysql": true, "redis": true, "mongo": true,
}

// exampleHostRe matches the host names reserved for documentation and tests
// (RFC 2606, RFC 6761): example.com/.net/.org and the .example, .test,
// .invalid and .localhost top-level domains.
var exampleHostRe = regexp.MustCompile(`(?:^|\.)(?:example\.(?:com|net|org)|example|test|invalid|localhost)$`)

// fakeWordRe matches a password that says it is not real ("fake-password",
// "FAKEpw", "examplepass", "dummy123"), or is a well-known joke password
// ("hunter2", "s3cr3t") used in examples and test fixtures.
var fakeWordRe = regexp.MustCompile(`(?i)fake|example|dummy|sample|placeholder|redacted|changeme|hunter2|s3cr3t`)

// upperPlaceholderRe matches a value made only of capital letters and
// underscores, such as REDACTED, REPLACE_ME or SET_YOUR_TOKEN: a real token has
// digits or lower case somewhere.
var upperPlaceholderRe = regexp.MustCompile(`^[A-Z][A-Z_\-]{3,}$`)

// literalPlaceholder reports whether a literal value is an unfilled placeholder
// rather than a credential: "<your-token>", "changeme", "xxxx-yyyy",
// "REDACTED", "TU_API_KEY_AQUI".
func literalPlaceholder(v string) bool {
	return placeholderRe.MatchString(v) || screamingPlaceholderRe.MatchString(v) ||
		upperPlaceholderRe.MatchString(v) || strings.Contains(strings.ToLower(v), "xxx")
}

// secretHeaderNameRe matches header names that say their value is a credential,
// beyond the fixed authHeaderNames: dd-api-key, X-Billing-Token, x-secret.
// A bare *-key is not enough: SONARQUBE_PROJECT_KEY names a project.
var secretHeaderNameRe = regexp.MustCompile(`(?i)(?:^|[-_])(?:api[-_]?key|secret[-_]?key|access[-_]?key|token|secret|password|auth)$`)

// connectionStringSecret reports whether v is a connection string that commits
// a real password: a literal, not a reference or placeholder, not a local
// development default, and not pointing at the developer's own machine.
func connectionStringSecret(v string) bool {
	if m := connStringRe.FindStringSubmatch(v); m != nil {
		user, pass, host := m[1], m[2], strings.ToLower(m[3])
		if p, err := url.PathUnescape(pass); err == nil {
			pass = p
		}
		switch {
		case isSecretReference(pass), strings.ContainsAny(pass, "${}<>%*"), literalPlaceholder(pass), fakeWordRe.MatchString(pass):
			return false
		case defaultPasswords[strings.ToLower(pass)], strings.EqualFold(pass, user):
			return false
		case loopbackHosts[host], exampleHostRe.MatchString(host):
			return false
		}
		return true
	}
	return accountKeyRe.MatchString(v)
}

// jwtRe matches a JSON Web Token: three base64url parts, the first two JSON
// objects ("eyJ" is the encoding of `{"`).
var jwtRe = regexp.MustCompile(`^eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}$`)

// jwtSecret reports whether v is a JWT that grants access. A Supabase anon key
// is a JWT with "role": "anon", which Supabase issues for use in public
// clients, so it is not reported, like the publishable keys in CFG050.
func jwtSecret(v string) bool {
	if !jwtRe.MatchString(v) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(v, ".")[1])
	if err != nil {
		return true
	}
	var claims struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(payload, &claims) == nil && claims.Role == "anon" {
		return false
	}
	return true
}

// matchSecretShape is the second half of matchSecretPattern: the shapes above.
func matchSecretShape(v string) (string, bool) {
	if pemPrivateKeyRe.MatchString(v) {
		return "private key", true
	}
	for _, p := range webhookPatterns {
		if p.re.MatchString(v) {
			return p.label, true
		}
	}
	if connectionStringSecret(v) {
		return "connection string with a password", true
	}
	if jwtSecret(v) {
		return "JSON Web Token", true
	}
	return "", false
}

// knownSecretEnvNames hold a credential without ending in one of
// secretSuffixes. Taken from the Claude Code settings schema's env
// descriptions: "Bearer token for Bedrock API authentication" and "Passphrase
// for encrypted client private key".
var knownSecretEnvNames = map[string]bool{
	"AWS_BEARER_TOKEN_BEDROCK":          true,
	"CLAUDE_CODE_CLIENT_KEY_PASSPHRASE": true,
}

// secretKeyName reports whether a key name implies its value is a secret.
func secretKeyName(key string) bool {
	return hasSecretSuffix(key) || knownSecretEnvNames[strings.ToUpper(key)]
}

// headerEnvNames are Claude Code env variables whose value is a list of request
// headers rather than one value, and how to split them. ANTHROPIC_CUSTOM_HEADERS
// is newline-separated "Name: Value" pairs; the OTLP exporter variables are the
// OpenTelemetry format, comma-separated name=value pairs with URL-encoded
// values ("Authorization=Bearer%20...").
func envHeaders(key, value string) (map[string]string, bool) {
	switch k := strings.ToUpper(key); {
	case k == "ANTHROPIC_CUSTOM_HEADERS":
		return splitHeaders(value, "\n", ":", false), true
	case k == "OTEL_EXPORTER_OTLP_HEADERS",
		strings.HasPrefix(k, "OTEL_EXPORTER_OTLP_") && strings.HasSuffix(k, "_HEADERS"):
		return splitHeaders(value, ",", "=", true), true
	}
	return nil, false
}

func splitHeaders(value, sep, kv string, urlEncoded bool) map[string]string {
	headers := map[string]string{}
	for _, part := range strings.Split(value, sep) {
		name, val, ok := strings.Cut(part, kv)
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		val = strings.TrimSpace(val)
		if urlEncoded {
			if d, err := url.QueryUnescape(val); err == nil {
				val = d
			}
		}
		headers[name] = val
	}
	return headers
}

// headerCredential reports whether a request header carries a committed
// credential, and what kind: a recognised token shape anywhere in the value, or
// a literal, non-placeholder credential in an auth header or after a Bearer or
// Basic scheme in any header.
func headerCredential(name, value string) (string, bool) {
	v := unquoteValue(strings.TrimSpace(value))
	if v == "" || isSecretReference(v) || placeholderDefaultRef(v) {
		return "", false
	}
	if label, ok := matchSecretPattern(v); ok {
		return "a hardcoded " + label, true
	}
	scheme := authSchemeRe.FindString(v)
	authValue := authHeaderNames[strings.ToLower(name)] || secretHeaderNameRe.MatchString(name) ||
		(scheme != "" && !strings.EqualFold(strings.TrimSpace(scheme), "token"))
	if !authValue {
		return "", false
	}
	cred := strings.TrimSpace(authSchemeRe.ReplaceAllString(v, ""))
	switch {
	case cred == "", isSecretReference(cred), placeholderDefaultRef(cred), literalPlaceholder(cred):
		return "", false
	case len(cred) < minCredentialLen && !strings.ContainsAny(cred, "$%{"):
		return "", false // "Bearer X": too short to be any real token (#852)
	case publishableKey(cred):
		return "", false
	}
	if label, ok := matchSecretPattern(cred); ok {
		return "a hardcoded " + label, true
	}
	return "a hardcoded credential", true
}

// defaultRefRe matches a whole value that is a ${...} substitution: a variable
// with a default (${CONTEXT7_API_KEY:-YOUR_API_KEY}) or a dotted form some
// clients use (${env.API_KEY}).
var defaultRefRe = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_.]*)(?::?-([^{}]*))?\}$`)

// placeholderDefaultRef reports whether v is a substitution whose default, if
// any, is a placeholder rather than a credential. A literal default such as
// ${TOKEN:-sk-live-...} still commits the value (#852) and does not match.
func placeholderDefaultRef(v string) bool {
	m := defaultRefRe.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	return m[2] == "" || literalPlaceholder(m[2])
}
