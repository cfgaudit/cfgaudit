package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg072 struct{}

var CFG072 = &cfg072{}

func init() { All = append(All, CFG072) }

func (r *cfg072) ID() string { return "CFG072" }

// cmdSubstPat matches a single shell command substitution — `$(...)` (no nested
// parens, which exfil one-liners never use) or a backtick pair. Shared by the two
// host-context matchers below.
const cmdSubstPat = `(?:\$\([^()]*\)|` + "`" + `[^` + "`" + `]*` + "`" + `)`

var (
	// dnsQueryToolRe matches a DNS-resolution binary. These speak UDP/53 to a
	// resolver, so anything encoded into the queried name leaves the host without
	// any TCP connection an HTTP-watching firewall or CFG038 would observe.
	dnsQueryToolRe = regexp.MustCompile(`(?i)\b(?:nslookup|dig|host|drill|kdig|resolvectl|systemd-resolve)\b`)

	// dnsNetworkToolRe matches the HTTP/transfer tools that resolve a hostname via
	// DNS before connecting — so a secret spliced into the *host* segment of their
	// URL is still exfiltrated over DNS even if the connection never lands. (Note:
	// httpie's binaries are `http`/`https`, deliberately omitted because those
	// collide with the URL scheme and would match every `http://` line.)
	dnsNetworkToolRe = regexp.MustCompile(`(?i)\b(?:curl|wget|fetch|httpie)\b`)

	// substDomainRe matches a command substitution immediately followed by a dotted
	// domain suffix — `$(cat ~/.ssh/id_rsa | base64).attacker.com` — i.e. the
	// substitution output becomes a DNS label under an attacker domain.
	substDomainRe = regexp.MustCompile(cmdSubstPat + `\.[A-Za-z0-9.-]*[A-Za-z]`)

	// substURLHostRe matches a command substitution sitting in the host segment of
	// a URL — `http://data$(env).evil.com` — between `://` and the first path,
	// query, or fragment delimiter. Host-label characters (no `/?#` or space) may
	// prefix the substitution; the substitution itself may contain spaces/slashes.
	substURLHostRe = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[A-Za-z0-9._~%-]*` + cmdSubstPat)
)

// Check flags a command site that smuggles data out through a DNS query name. A
// command substitution whose output is spliced into a hostname — the argument to
// a DNS-resolution tool (`dig`/`nslookup`/`host`/…) or the host segment of a URL
// passed to `curl`/`wget`/… — resolves over UDP/53 to a recursive resolver,
// carrying the encoded secret off-host without any visible TCP endpoint. This is
// the DNS channel CFG038 (env → HTTP/TCP) does not cover; the substitution-feeds-a-
// hostname shape makes it virtually never a legitimate hook.
func (r *cfg072) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t) {
		cmd := site.Command

		dnsTool := dnsQueryToolRe.MatchString(cmd) && substDomainRe.MatchString(cmd)
		urlHost := dnsNetworkToolRe.MatchString(cmd) && substURLHostRe.MatchString(cmd)
		if !dnsTool && !urlHost {
			continue
		}

		var via string
		switch {
		case dnsTool:
			via = "the queried name of a DNS-resolution tool (dig/nslookup/host/…)"
		default:
			via = "the host segment of a URL passed to a network tool (curl/wget/…)"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG072",
			Severity: finding.Error,
			File:     site.File,
			Message: site.Label + " encodes a command substitution into " + via +
				" — the result becomes a DNS label resolved over UDP/53 to a recursive resolver, exfiltrating the data off-host with no TCP connection an HTTP firewall would see. Remove it" + userScopeNote(t),
		})
	}
	return findings
}
