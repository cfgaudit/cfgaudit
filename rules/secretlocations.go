// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Credentials outside a server's env and headers (#1046): in the server URL,
// in the arguments of a stdio server, and in a command the agent runs. Each
// helper returns what it found, never the value, so a message cannot leak it
// (#1045).

// secretQueryParams are query parameter names whose value is a credential.
var secretQueryParams = map[string]bool{
	"token": true, "key": true, "api_key": true, "apikey": true, "api-key": true,
	"access_token": true, "auth_token": true, "secret": true, "client_secret": true,
	"password": true, "sig": true, "signature": true,
}

// urlSecrets reports the credentials committed in a URL: a password in its
// userinfo, a known token format in a query value, and a literal value of a
// query parameter whose name says it is a credential.
func urlSecrets(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || isSecretReference(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if exampleHostRe.MatchString(host) || loopbackHosts[host] {
		return nil // documentation hosts and the developer's own machine
	}
	var found []string
	if pass, ok := u.User.Password(); ok && literalCredential(pass) &&
		!defaultPasswords[strings.ToLower(pass)] && !strings.EqualFold(pass, u.User.Username()) && !fakeWordRe.MatchString(pass) {
		found = append(found, "a password in the URL")
	}
	q := u.Query()
	for _, name := range sortedQueryNames(q) {
		for _, v := range q[name] {
			if label, ok := matchSecretPattern(v); ok {
				found = append(found, "a hardcoded "+label+" in the query parameter "+name)
			} else if secretQueryParams[strings.ToLower(name)] && literalCredential(v) {
				found = append(found, "a credential in the query parameter "+name)
			}
		}
	}
	return found
}

func sortedQueryNames(q url.Values) []string {
	m := make(map[string]string, len(q))
	for k := range q {
		m[k] = ""
	}
	return sortedKeys(m)
}

// literalCredential reports whether v is a committed credential rather than a
// reference, a placeholder or a value too short to be one.
func literalCredential(v string) bool {
	v = unquoteValue(strings.TrimSpace(v))
	switch {
	case v == "", isSecretReference(v), placeholderDefaultRef(v), literalPlaceholder(v):
		return false
	case strings.ContainsAny(v, "${}<>"):
		return false // part of a template such as "tok-${ID}" or "<token>"
	}
	return len(v) >= minCredentialLen
}

// secretFlagRe matches a command-line flag that takes a credential as its
// value: --token, --api-key, --apikey, --password, --secret, --access-token,
// --auth-token, --client-secret.
var secretFlagRe = regexp.MustCompile(`^--?(?i:token|api[-_]?key|password|passwd|secret|access[-_]token|auth[-_]token|client[-_]secret|bearer[-_]token)$`)

// envAssignRe matches the NAME of a NAME=value argument.
var envAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// argSecret is one credential in an argument list: the index of the argument
// holding the value, and what it is.
type argSecret struct {
	index int
	what  string
}

// argSecrets reports credentials in an MCP server's args: a known token format
// as an argument or as the value of --flag=value, and a literal value after a
// flag that takes a credential (--token VALUE, --api-key=VALUE).
func argSecrets(args []string) []argSecret {
	var found []argSecret
	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		flag, val, hasEq := strings.Cut(a, "=")
		switch {
		case hasEq && strings.HasPrefix(flag, "-"):
			if label, ok := matchSecretPattern(val); ok {
				found = append(found, argSecret{i, "a hardcoded " + label})
			} else if secretFlagRe.MatchString(flag) && literalCredential(val) {
				found = append(found, argSecret{i, "a credential after " + flag})
			}
		case hasEq && envAssignRe.MatchString(flag):
			// NAME=value, as passed by docker run -e or env: an env entry.
			if label, ok := matchSecretPattern(val); ok {
				found = append(found, argSecret{i, "a hardcoded " + label + " in " + flag})
			} else if literalUnderSecretName(flag, val) && literalCredential(val) {
				found = append(found, argSecret{i, "a literal value for " + flag})
			}
		case secretFlagRe.MatchString(a) && i+1 < len(args):
			v := args[i+1]
			if label, ok := matchSecretPattern(strings.TrimSpace(v)); ok {
				found = append(found, argSecret{i + 1, "a hardcoded " + label})
				i++
			} else if !strings.HasPrefix(strings.TrimSpace(v), "-") && literalCredential(v) {
				found = append(found, argSecret{i + 1, "a credential after " + a})
				i++
			}
		default:
			if label, ok := matchSecretPattern(a); ok {
				found = append(found, argSecret{i, "a hardcoded " + label})
			} else if strings.Contains(a, "://") {
				for _, what := range urlSecrets(a) {
					found = append(found, argSecret{i, what})
				}
			}
		}
	}
	return found
}

// commandWordRe splits a shell command into words for the token check:
// whitespace, quotes and the shell's separators end a word.
var commandWordRe = regexp.MustCompile(`[^\s'"` + "`" + `;|&()<>]+`)

// commandAuthHeaderRe finds an auth header passed on a command line, such as
// curl -H 'Authorization: Bearer ...' or --header "X-Api-Key: ...".
var commandAuthHeaderRe = regexp.MustCompile(`(?i)(authorization|proxy-authorization|x-api-key|api-key|x-auth-token)\s*:\s*((?:bearer|basic|token)\s+)?([^\s'"]+)`)

// commandSecrets reports credentials in a command the agent runs: known token
// formats as words, credentials in URLs, a literal auth header passed with -H,
// and a literal value after a flag that takes a credential.
func commandSecrets(cmd string) []string {
	var found []string
	seen := map[string]bool{}
	add := func(what string) {
		if !seen[what] {
			seen[what] = true
			found = append(found, what)
		}
	}
	inHeader := map[string]bool{}
	for _, m := range commandAuthHeaderRe.FindAllStringSubmatch(cmd, -1) {
		if what, ok := headerCredential(m[1], m[2]+m[3]); ok {
			add(what + " in the " + m[1] + " header")
			inHeader[m[3]] = true
		}
	}
	var words []string
	for _, w := range commandWordRe.FindAllString(cmd, -1) {
		if !inHeader[w] {
			words = append(words, w)
		}
	}
	for _, what := range argSecrets(words) {
		add(what.what)
	}
	return found
}

// argLabel is the key path of one MCP argument.
func argLabel(base string, i int) string {
	return base + ".args[" + strconv.Itoa(i) + "]"
}
