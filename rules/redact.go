// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
)

// messageURLRe matches a URL quoted in a finding message: a scheme, ://, and
// everything up to whitespace, a quote, a backtick or a bracket that closes
// the quoted value (a permission entry such as Bash(curl https://x/?t=v)).
var messageURLRe = regexp.MustCompile("[A-Za-z][A-Za-z0-9+.-]*://[^\\s\"'`<>()\\[\\]{}]+")

// redactPlaceholderRe matches a value that names a variable instead of holding one,
// such as ${API_KEY} or $TOKEN. It is no secret and tells the reader where the
// value comes from, so it stays.
var redactPlaceholderRe = regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`)

// RedactURLs rewrites every URL in s for display (#1045): a password in the
// userinfo becomes ***, and a user name with no password does too, since a
// token is often written as the user name (https://<token>@host). Every value
// in the query, and in a fragment written as key=value pairs, becomes ***;
// the keys stay so the message still explains itself. Findings go to SARIF,
// CI artifacts and logs that reach more people than the repository, so a
// message must not repeat the secret it warns about.
func RedactURLs(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return messageURLRe.ReplaceAllStringFunc(s, redactURL)
}

func redactURL(u string) string {
	// The :* that ends a Claude Code permission prefix is not part of the URL.
	if base, ok := strings.CutSuffix(u, ":*"); ok {
		return redactURL(base) + ":*"
	}
	scheme, rest, _ := strings.Cut(u, "://")
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		user, pass, hasPass := strings.Cut(authority[:at], ":")
		switch {
		case hasPass && !redactPlaceholderRe.MatchString(pass):
			authority = user + ":***" + authority[at:]
		case !hasPass && !redactPlaceholderRe.MatchString(user):
			authority = "***" + authority[at:]
		}
	}
	path, query, hasQuery := strings.Cut(tail, "?")
	fragment, hasFragment := "", false
	if hasQuery {
		query, fragment, hasFragment = strings.Cut(query, "#")
		query = redactPairs(query)
	} else {
		path, fragment, hasFragment = strings.Cut(path, "#")
	}
	out := scheme + "://" + authority + path
	if hasQuery {
		out += "?" + query
	}
	if hasFragment {
		if strings.Contains(fragment, "=") {
			fragment = redactPairs(fragment)
		}
		out += "#" + fragment
	}
	return out
}

// redactPairs replaces the value of each key=value pair in an & or ;
// separated list. A part with no = is a bare value and is replaced whole.
func redactPairs(s string) string {
	var b strings.Builder
	for s != "" {
		i := strings.IndexAny(s, "&;")
		part, sep := s, ""
		if i >= 0 {
			part, sep, s = s[:i], s[i:i+1], s[i+1:]
		} else {
			s = ""
		}
		key, val, ok := strings.Cut(part, "=")
		switch {
		case part == "":
		case !ok:
			b.WriteString("***")
		case val == "" || redactPlaceholderRe.MatchString(val):
			b.WriteString(part)
		default:
			b.WriteString(key + "=***")
		}
		b.WriteString(sep)
	}
	return b.String()
}
