package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg091 struct{}

var CFG091 = &cfg091{}

func init() { All = append(All, CFG091) }

func (r *cfg091) ID() string { return "CFG091" }

// lateralMovementRe matches an instruction directing the agent to use its
// current access as a pivot into adjacent systems (AVE-2026-00036). The match is
// anchored to the movement sense so the bare word "pivot" (pivot table, "let's
// pivot the strategy") does not fire:
//
//   - A: the explicit term "lateral movement" / "move laterally".
//   - B: a pivot/hop/spread verb whose target is a system-class noun (system,
//     server, host, machine, network, agent, node, account) qualified as other /
//     adjacent / connected / neighbouring — not "pivot to another approach".
//   - C: reuse of a foothold ("use this access/credentials/token/foothold … to
//     reach/compromise/move"), the defining phrasing of lateral movement.
var lateralMovementRe = regexp.MustCompile(`(?i)(?:` +
	// A: explicit term
	`\blateral\s+movement\b|\bmove\s+laterally\b` +
	`|` +
	// B: pivot/spread/hop verb + qualified system object
	`\b(?:pivot|spread|hop|jump|propagate|move|migrate|reach)\s+(?:\w+\s+){0,3}?` +
	`(?:to|into|onto|toward|across)\s+(?:\w+\s+){0,2}?` +
	`(?:other|another|adjacent|neighbou?ring|connected|nearby|internal|different|remaining|the\s+rest\s+of\s+the)\s+` +
	`(?:system|server|host|machine|network|agent|node|box|account|endpoint|workstation|device)s?\b` +
	`|` +
	// C: foothold / credential reuse to move
	`\b(?:use|reuse|leverage|abuse|exploit|take\s+advantage\s+of)\s+(?:(?:this|the|your|our|its|current|existing|agent'?s)\s+){1,3}` +
	`(?:foothold|access|credential|credentials|token|tokens|session|position|privilege|privileges|permission|permissions)\s+(?:\w+\s+){0,5}?` +
	`to\s+(?:reach|access|move|pivot|spread|compromise|get\s+into|hop\s+to|break\s+into|log\s+into|connect\s+to)` +
	`)`)

// Check scans each instruction source for a lateral-movement directive. Once one
// skill or pipeline stage is compromised, an instruction that tells the agent to
// reuse its existing credentials and network access to reach adjacent systems
// expands the compromise to hosts the attacker could not reach from outside
// (AVE-2026-00036) — the post-reconnaissance stage of an intrusion, and the
// sibling of CFG090. Reports the line and the matched phrase. Matches inside
// fenced code blocks are treated as documentation and skipped.
func (r *cfg091) Check(t *Target) []finding.Finding {
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
			loc := lateralMovementRe.FindStringIndex(line)
			if loc == nil {
				continue
			}
			lineNo := i + 1
			findings = append(findings, finding.Finding{
				RuleID:   "CFG091",
				Severity: finding.Warn,
				File:     src.File,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message: src.Name + " line " + strconv.Itoa(lineNo) + ` directs the agent to pivot to other systems using its current access ("` + collapseWS(line[loc[0]:loc[1]]) +
					`") — a committed instruction for lateral movement, reusing the agent's credentials and network reach to expand a compromise to adjacent hosts. Remove it, or scope the agent's credentials and network access` + userScopeNote(t),
			})
		}
	}
	return findings
}
