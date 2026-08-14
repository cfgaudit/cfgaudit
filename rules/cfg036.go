package rules

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg036 struct{}

var CFG036 = &cfg036{}

func init() { All = append(All, CFG036) }

func (r *cfg036) ID() string { return "CFG036" }

var (
	// Pattern A: command substitution ($(…) or backticks) reading a sensitive
	// CREDENTIAL/SECRET path. The \s requirement means a command must precede the
	// path inside the delimiter (e.g. `cat ~/.ssh/id_rsa`), so a bare Markdown
	// inline-code path is not flagged. Config/dir references (.claude/,
	// settings.json) and the bare word "credentials" are deliberately NOT listed:
	// skills legitimately run their own .claude/ scripts and mention "credentials"
	// in prose — only real secret files belong here (credentials.json is anchored).
	cmdSubstSensitiveRe = regexp.MustCompile("(?i)(?:\\$\\(|`)[^)`]*\\s[^)`]*(?:~/\\.ssh|~/\\.aws|~/\\.gcp|~/\\.config/gcloud|/etc/passwd|/etc/shadow|\\.env\\b|id_rsa|id_ed25519|credentials\\.json)")
	// Auto-execution directive (Patterns B and C; Part C narrows it further, see
	// partCDirective).
	autoExecRe = regexp.MustCompile(`(?i)(?:before\s+(?:each|every|any)\s+(?:task|session|request|command|run|step)|always\s+(?:run|execute|do)|at\s+(?:startup|session\s+start|the\s+start)|automatically\s+(?:run|execute))`)
	// Network exfiltration command (Pattern B).
	netExfilRe = regexp.MustCompile(`(?i)\b(?:curl|wget|nc|ncat|netcat|python[23]?\s+-c.*urllib|bash\s+-i)\b.*\bhttps?://`)

	// Part C only: which "at …" phrases are an order to the agent rather than
	// prose about something else starting. Measured over 390 real CLAUDE.md files
	// sampled from GitHub (#508): all 26 "at startup" matches described the
	// *program's* startup ("config is read at startup", "modules are discovered at
	// startup") and none ordered the agent to run anything, so the phrase carries no
	// Part C warning on its own. "at the start" turns on what starts: the matches
	// naming a session or conversation were directives ("At the start of every
	// session, run:"), while the five naming a cycle, a drag, an analysis or a
	// reconciliation were descriptions. Part B is unaffected: paired with a network
	// command on a nearby line, every one of these phrases still reports at error.
	atStartupPhraseRe  = regexp.MustCompile(`(?i)^at\s+startup$`)
	atTheStartPhraseRe = regexp.MustCompile(`(?i)^at\s+the\s+start$`)
	// The noun that follows "at the start", within the same sentence.
	sessionScopeRe = regexp.MustCompile(`(?i)^[^.;]{0,40}?\b(?:session|conversation|chat)\b`)
)

// partCDirective reports whether a directive match warrants a Part C warning on
// its own. loc is autoExecRe's match on line.
func partCDirective(line string, loc []int) bool {
	switch phrase := line[loc[0]:loc[1]]; {
	case atStartupPhraseRe.MatchString(phrase):
		return false
	case atTheStartPhraseRe.MatchString(phrase):
		return sessionScopeRe.MatchString(line[loc[1]:])
	}
	return true
}

// Check flags CLAUDE.md text that makes Claude run shell commands on the
// attacker's behalf. A: command substitution reading a credential path (error,
// independent). B: an auto-execution directive co-occurring with a network
// exfiltration command within 3 lines (error). C: an auto-execution directive
// alone (warn). Matches inside fenced code blocks are still reported.
func (r *cfg036) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		lines := strings.Split(src.Content, "\n")
		n := len(lines)

		directive := make([][]int, n)
		network := make([]bool, n)

		var srcFindings []finding.Finding
		add := func(line, col int, sev finding.Severity, msg string) {
			srcFindings = append(srcFindings, finding.Finding{
				RuleID: "CFG036", Severity: sev, File: src.File,
				Line: line + 1, Col: col + 1,
				Message: src.Name + " line " + strconv.Itoa(line+1) + " " + msg,
			})
		}

		for i, line := range lines {
			directive[i] = autoExecRe.FindStringIndex(line)
			network[i] = netExfilRe.MatchString(line)
			if loc := cmdSubstSensitiveRe.FindStringIndex(line); loc != nil {
				add(i, loc[0], finding.Error, "uses command substitution reading a sensitive path (Part A) — \""+strings.TrimSpace(line[loc[0]:loc[1]])+"…\"; reading credential files in a substitution has no legitimate use in documentation. Remove it")
			}
		}

		// A directive applies to the command that follows it, up to the next blank
		// line (end of its command block) and at most 3 lines ahead. Looking only
		// forward avoids associating a directive with an unrelated earlier command.
		covered := make(map[int]bool)
		for i := range lines {
			if directive[i] == nil {
				continue
			}
			for j := i; j <= min(n-1, i+3); j++ {
				if j > i && strings.TrimSpace(lines[j]) == "" {
					break
				}
				if network[j] {
					add(i, directive[i][0], finding.Error, "combines an auto-execution directive with a network-exfiltration command (Part B) — instructs the agent to run a command that sends data to a remote host. Remove it")
					covered[i] = true
					break
				}
			}
		}

		for i := range lines {
			if directive[i] == nil || covered[i] {
				continue
			}
			loc := directive[i]
			if !partCDirective(lines[i], loc) {
				continue
			}
			if strings.Contains(lines[i][loc[0]:], ":") {
				add(i, loc[0], finding.Warn, "contains an auto-execution directive (Part C) — \""+strings.TrimSpace(lines[i][loc[0]:loc[1]])+"\"; instruction files should describe tasks, not command the agent to auto-run things. Review it")
			}
		}
		sort.SliceStable(srcFindings, func(i, j int) bool {
			if srcFindings[i].Line != srcFindings[j].Line {
				return srcFindings[i].Line < srcFindings[j].Line
			}
			return srcFindings[i].Col < srcFindings[j].Col
		})
		findings = append(findings, srcFindings...)
	}
	return findings
}
