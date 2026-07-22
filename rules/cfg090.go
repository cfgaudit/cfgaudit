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
// a network — turning a trusted internal host into a reconnaissance tool
// (AVE-2026-00032). Two alternations:
//
//   - A: unambiguous recon terminology (port scan, host discovery, nmap, …) that
//     needs no further qualifier.
//   - B: a recon verb whose object is a network-specific noun. The object is
//     deliberately narrow — "network", "subnet", "open ports", "running services
//     on", "live hosts" — so that "scan the codebase", "enumerate the files" or
//     "map the dependencies" (all legitimate agent work) do not match. A bare
//     verb without a network object is not a finding.
var networkReconRe = regexp.MustCompile(`(?i)(?:` +
	// A: explicit recon terms
	`\b(?:port[- ]?scan(?:ning|s)?|host\s+discovery|network\s+scan(?:ning|s)?|network\s+reconnaissance|service\s+enumeration|ping\s+sweep|nmap|masscan|zmap)\b` +
	`|` +
	// B: recon verb + network object
	`\b(?:scan|enumerate|probe|sweep|fingerprint|discover|map|list|find)\s+(?:\w+\s+){0,4}?` +
	`(?:` +
	`(?:the\s+|an?\s+|any\s+|all\s+|every\s+|our\s+|your\s+|its\s+)?(?:internal\s+|local\s+|corporate\s+|adjacent\s+|target\s+)?(?:network|subnet|lan\b|vlan)` +
	`|(?:all\s+|the\s+)?open\s+ports?` +
	`|(?:running|listening|live|exposed)\s+(?:services?|ports?|hosts?)(?:\s+on)?` +
	`|(?:services?|ports?|hosts?)\s+on\s+(?:the\s+)?(?:internal\s+|local\s+)?(?:network|subnet|lan\b)` +
	`)` +
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
