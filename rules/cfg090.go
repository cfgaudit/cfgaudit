package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg090 struct{}

var CFG090 = &cfg090{}

func init() { All = append(All, CFG090) }

func (r *cfg090) ID() string { return "CFG090" }

// networkReconRe matches an instruction directing the agent to scan or enumerate
// an internal network — turning a trusted host into a reconnaissance tool
// (AVE-2026-00032).
//
// It requires a recon **verb** applied to a **network-scoped, internal** target.
// A pre-release FP analysis over 422 real instruction files that mention this
// vocabulary showed the earlier design fired almost entirely on false positives:
// bare tool names (nmap/masscan/port scan) matched security-tooling repos
// describing their own capabilities, capability inventories, forensic
// data-source lists ("port scan artifacts"), and even non-computer meanings
// ("map existing network for warm intros"). So:
//
//   - Bare tool names and bare "port scan" are NOT matched — a mention of a
//     scanner is not a directive to the agent.
//   - The target must be explicitly internal/private: an internal/corporate/
//     private network, a subnet, a LAN/VLAN, a private IPv4 range, or hosts/
//     ports/services *on* such a network. A bare "network" (business networking,
//     a Docker network, a neural network) does not qualify.
//
// This keeps AVE-00032's canonical directives ("enumerate services on the
// subnet", "find all open ports on the internal network") while dropping the
// intent-ambiguous vocabulary that a static linter cannot tell apart from
// legitimate security tooling.
// internalNetworkTarget matches a network-scoped, *internal* object: only these
// qualify a recon phrase as a finding, which is what keeps a bare "network"
// (business networking, a Docker/neural network) or a bare tool mention out.
const internalNetworkTarget = `(?:` +
	// an internal/private/corporate network|subnet|LAN|VLAN
	`(?:the\s+|an?\s+|our\s+|your\s+|its\s+|target\s+)?(?:internal|local|corporate|private|company|adjacent)\s+(?:network|subnet|lan\b|vlan|infrastructure|range|hosts?)` +
	// a bare subnet / LAN / VLAN (network-recon-specific on their own)
	`|(?:the\s+|a\s+)?(?:subnet|lan\b|vlan)\b` +
	// a private IPv4 range
	`|\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d` +
	// hosts/ports/services ON an (internal) network/subnet/LAN
	`|(?:open\s+|listening\s+|running\s+|live\s+|exposed\s+)?(?:hosts?|ports?|services?|machines?)\s+on\s+(?:the\s+)?(?:internal\s+|local\s+|corporate\s+|private\s+)?(?:network|subnet|lan\b|vlan|host|machine)` +
	`)`

var networkReconRe = regexp.MustCompile(`(?i)(?:` +
	// (a) recon verb + internal target
	`\b(?:scan|enumerate|probe|sweep|fingerprint|discover|map|list|find)\s+(?:\w+\s+){0,4}?` + internalNetworkTarget +
	`|` +
	// (b) a recon noun / tool name, but ONLY when an internal target follows within
	// a few words — so "port scan artifacts" or "wraps nmap" (no target) stay
	// silent while "host discovery across the subnet" / "nmap the internal net" fire
	`\b(?:port[- ]?scan(?:ning|s)?|host\s+discovery|network\s+scan(?:ning|s)?|network\s+reconnaissance|service\s+enumeration|ping\s+sweep|nmap|masscan|zmap)\b\s+(?:\w+\s+){0,4}?` + internalNetworkTarget +
	`)`)

// Check scans each instruction source for a network-reconnaissance directive.
// An agent with shell or network access is a reconnaissance tool once a committed
// instruction tells it to map internal infrastructure — the intelligence-gathering
// stage of an intrusion, executed from a trusted host (AVE-2026-00032). The
// command's own content is judged separately by the command-content rules; this
// keys on the instruction. Reports the line and the matched phrase. Matches
// inside fenced code blocks are treated as documentation and skipped.
func (r *cfg090) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		inFence := false
		for i, line := range strings.Split(src.Content, "\n") {
			if isFenceDelimiter(line) {
				inFence = !inFence
				continue
			}
			if inFence {
				continue
			}
			loc := networkReconRe.FindStringIndex(line)
			if loc == nil {
				continue
			}
			lineNo := i + 1
			findings = append(findings, finding.Finding{
				RuleID:   "CFG090",
				Severity: finding.Warn,
				File:     src.File,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message: src.Name + " line " + strconv.Itoa(lineNo) + ` directs the agent to scan or enumerate a network ("` + collapseWS(line[loc[0]:loc[1]]) +
					`") — a committed instruction that turns a trusted internal host into a reconnaissance tool, mapping infrastructure for a follow-on attack. Remove it, or scope the agent so it cannot reach the internal network` + userScopeNote(t),
			})
		}
	}
	return findings
}
