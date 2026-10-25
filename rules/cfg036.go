// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
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
	cmdSubstSensitiveRe = mustFiltered("(?i)(?:\\$\\(|`)[^)`]*\\s[^)`]*(?:~/\\.ssh|~/\\.aws|~/\\.gcp|~/\\.config/gcloud|/etc/passwd|/etc/shadow|\\.env\\b|id_rsa|id_ed25519|credentials\\.json)")
	// Auto-execution directive (Patterns B and C; Part C narrows it further, see
	// partCDirective).
	autoExecRe = mustFiltered(`(?i)(?:before\s+(?:each|every|any)\s+(?:task|session|request|command|run|step)|always\s+(?:run|execute|do)|at\s+(?:startup|session\s+start|the\s+start)|automatically\s+(?:run|execute))`)
	// A directive tied to a condition the agent meets in normal work (#791):
	// "Whenever you review a pull request, first run …", "When you start
	// working on this repository, run: …". It counts for Part B only, with
	// conditionalRunRe in the rest of the line or on the next one: on its own,
	// "When you change code, run the tests" is ordinary guidance, and of 21
	// such lines in 1,727 instruction files none had a network command nearby.
	conditionalRe    = mustFiltered(`(?i)\b(?:whenever|each\s+time|every\s+time)\s+you\b|\bwhen\s+you\s+(?:start|open|begin|review|clone|enter|first|check\s+out|work\s+on)\b|\bafter\s+(?:every|each)\s+\w+`)
	conditionalRunRe = regexp.MustCompile(`(?i)\b(?:run|execute)\b`)
	// A download piped into a shell or run through one (Part D, #791):
	// curl … https://… | sh, bash <(curl …), sh -c "$(curl …)", and the same
	// into python reading its script from stdin (no arguments, or "-"; not
	// python3 -m json.tool). The URL is required, so prose like "no
	// curl|bash installers" is not one.
	pipeShellRe = mustFiltered(`(?i)\b(?:curl|wget)\b[^|\n]*\bhttps?://[^|\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh(?:\s|$|[;&)` + "`" + `"'])|python[23]?(?:\s+-(?:\s|$)|\s*(?:$|[;&|)` + "`" + `"'])))|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b|\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b`)
	// A literal base64 string decoded straight into a shell (Part E, #906):
	// "echo '<base64>' | base64 -D | bash". A reader cannot see what it runs.
	// A variable or placeholder ($b64, <BASE64>) is not a literal and does
	// not match.
	decodeShellRe = mustFiltered(`(?i)\becho\s+(?:-n\s+)?['"]?[A-Za-z0-9+/]{16,}={0,2}['"]?\s*\|\s*base64\s+(?:-d|--decode)\b\s*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b`)
	// Network exfiltration command (Pattern B).
	netExfilRe = mustFiltered(`(?i)\b(?:curl|wget|nc|ncat|netcat|python[23]?\s+-c.*urllib|bash\s+-i)\b.*\bhttps?://`)

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
		return sessionScopeRe.MatchString(line[loc[1]:]) && !authorDirectedRe.MatchString(line[loc[1]:])
	case atSessionStartPhraseRe.MatchString(phrase):
		return !authorDirectedRe.MatchString(line[loc[1]:])
	}
	return true
}

// atSessionStartPhraseRe is the "at session start" form of the directive.
var atSessionStartPhraseRe = regexp.MustCompile(`(?i)^at\s+session\s+start$`)

// authorDirectedRe matches a start-of-session line addressed to the person
// writing the prompt rather than to the agent: "At session start, provide
// everything the agent needs in a structured block" (#623). Reading and
// loading stay Part C, as measured for #508: "At the start of each session,
// read:" is an order to the agent.
var authorDirectedRe = regexp.MustCompile(`(?i)^[^.;]{0,20}?\b(?:provide|give|share|paste|hand)\b`)

// substTemplateRe matches what looks like a secret path in a substitution but
// is not a read of one (#623): an env-file template (.env.example and its
// kin), an identifier ending in .env (process.env, import.meta.env), and the
// destination of a copy or move (cp .env.example .env, Copy-Item ...), a
// permission change (chmod 600 .../.env), and a public key (id_ed25519.pub).
// A ${Name.method(...)} span is a JavaScript template literal, not a shell
// expansion: `Bearer ${Deno.env.get("OPENAI_API_KEY")}` (#885).
var substTemplateRe = regexp.MustCompile(`(?i)\.env\.(?:example|sample|template|dist|defaults?)\b|\$\{[A-Za-z_$][\w$]*(?:\.[\w$]+)+\([^}]*\)\}|\b(?:process|import\.meta|os|Deno|globalThis|self)\.env\b|\b(?:cp|mv|copy|copy-item)\s+\S+\s+\S*\.env\b|\bchmod\s+\S+\s+\S*\.env\b|\S*id_(?:rsa|ed25519|ecdsa|dsa)\.pub\b`)

// inlineCodeSpanRe matches a Markdown inline-code span: a pair of backticks
// around text with no backtick in it.
var inlineCodeSpanRe = regexp.MustCompile("`[^`\n]+`")

// readOutCommands are the programs that print, copy or send a file's content.
var readOutCommands = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "bat": true,
	"strings": true, "xxd": true, "od": true, "hexdump": true, "base64": true,
	"scp": true, "rsync": true, "curl": true, "wget": true, "nc": true, "ncat": true,
	"netcat": true, "gpg": true, "tar": true, "zip": true, "openssl": true,
	"python": true, "python3": true, "node": true, "ruby": true, "perl": true,
	"type": true, "Get-Content": true, "gc": true,
}

// readsOut reports whether one of the commands in span runs a program from
// readOutCommands. Leading VAR=value assignments and sudo/env are skipped.
func readsOut(span string) bool {
	for _, cmd := range splitCommands(span) {
		// "node --env-file=.env scripts/x.mjs" loads the file into the
		// process (#868).
		if strings.Contains(cmd, "--env-file") {
			continue
		}
		for _, w := range strings.Fields(cmd) {
			if strings.Contains(w, "=") && !strings.HasPrefix(w, "-") && !strings.Contains(w, "`") {
				continue
			}
			if w == "sudo" || w == "env" {
				continue
			}
			w = strings.TrimLeft(w, "`(\"'")
			if readOutCommands[w] || readOutCommands[filepath.Base(w)] {
				return true
			}
			break
		}
	}
	return false
}

// splitCommands splits a command line at ;, | and & outside quotes, so the
// alternatives of a quoted search pattern ("a|b|@scope/node") stay one word.
func splitCommands(s string) []string {
	var out []string
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ';' || c == '|' || c == '&':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// envKeyLookupRe is a substitution that looks up one named key in an env file
// or lists env files: $(grep '^ADMIN_API_KEY=' .env | cut -d= -f2-),
// $(grep -E '^STATE_DIR=' docker/.env 2>/dev/null | cut -d= -f2- | tr -d '"'),
// $(ls apps/web/.env.local apps/web/.env 2>/dev/null | head -1).
var envKeyLookupRe = regexp.MustCompile(`^\$\(\s*(?:grep\s+(?:-\w+\s+)*["']?(?:\^[A-Za-z_<][\w<>]*|[A-Z_<][A-Z0-9_<>]*)=?["']?\s+[\w./\-]*\.env[\w.\-]*|ls\s+[^|)]*)\s*(?:2>\s*/dev/null\s*)?(?:\|\s*(?:cut|tr|sed|head|tail|xargs|awk)\b[^|)]*)*\)$`)

// substAssignedRe is a shell variable assignment right before a substitution:
// NAME=$( or NAME="$(.
var substAssignedRe = regexp.MustCompile(`(?:^|[\s;(])(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*="?$`)

// envKeyLookup reports whether the substitution at loc stores one key of an env
// file in a shell variable, or lists env files (#868). That is how a skill
// hands a project's own setting or token to the next command (PINATA_JWT=$(grep
// "^PINATA_API_JWT=" .env | cut -d'=' -f2-)); the value stays in the shell. A
// substitution used as an argument, which is where a payload sends a secret
// ("curl -H \"X: $(grep '^TOKEN=' .env)\" ..."), a whole-file read and an open
// search ("grep token .env") are still Part A.
func envKeyLookup(line string, loc []int) bool {
	sub := line[loc[0]:loc[1]]
	if !singleKeyLookup(line, loc) {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(sub[2:]), "ls") || substAssignedRe.MatchString(line[:loc[0]])
}

// pyKeyLookupRe is a Python one-liner that loads a TOML or JSON file and
// prints one key: $(python3 -c 'import tomllib,os;print(tomllib.load(open(
// os.path.expanduser("~/workspace/.env.toml"),"rb"))["gitlab"]["token"])')
// (#885). It is matched from the start of the substitution on the whole line,
// since the substitution itself ends at the first ")".
var pyKeyLookupRe = regexp.MustCompile(`^\$\(\s*python[23]?\s+-c\s+'[^']*\b(?:tomllib|json)\.loads?\([^']*\)(?:\[\\?"[\w.\-]+\\?"\])+\)\s*'\s*\)`)

// singleKeyLookup reports whether the substitution at loc looks up one named
// key in an env or config file, or lists env files: the grep form of
// envKeyLookupRe or the Python form of pyKeyLookupRe.
func singleKeyLookup(line string, loc []int) bool {
	return envKeyLookupRe.MatchString(line[loc[0]:loc[1]]) || pyKeyLookupRe.MatchString(line[loc[0]:])
}

// countOnlyGrepRe is a grep whose flags make it print a count, file names or
// nothing: -c, -l, -L, -q, alone or in a group (-qE, -cF).
var countOnlyGrepRe = regexp.MustCompile(`^grep\s+(?:-\w+\s+)*-[A-Za-z]*[clLq][A-Za-z]*\s`)

// countsOnly reports whether every command in the substitution sub is such a
// grep, or a fallback that prints nothing (|| true, :). "$(grep -c
// '^ACCOUNT_KEY_' .env 2>/dev/null || true)" counts keys and prints no value
// (#885).
func countsOnly(sub string) bool {
	inner := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(sub), "$("), ")")
	inner = strings.ReplaceAll(inner, "2>&1", "")
	greps := 0
	for _, cmd := range splitCommands(inner) {
		cmd = strings.TrimSpace(cmd)
		switch {
		case cmd == "" || cmd == "true" || cmd == ":":
		case countOnlyGrepRe.MatchString(cmd + " "):
			greps++
		default:
			return false
		}
	}
	return greps > 0
}

// dollarSubstRe is a $( ) substitution, to its closing parenthesis or the end
// of the line.
var dollarSubstRe = regexp.MustCompile(`\$\([^)]*\)?`)

// sensitiveSubstitution returns the location of a command substitution that
// reads a secret path: $( ... ) or a backtick span with a command and a path.
// Backtick spans are taken as pairs. Matching from any backtick read the text
// between a closing backtick and the next opening one as a substitution, which
// turned ".env file `chmod 600`" and "`npm run test` (locally, .env loaded)"
// into findings (#623).
//
// Outside a fenced code block a backtick span is Markdown code formatting: it
// names a command. Such a span counts only when one of its commands reads the
// file out or sends it ("`scp ~/.claude/.credentials.json host:`", "`cat
// ~/.ssh/id_rsa`"), not when it loads the file into a process ("`dotenvx run -f
// .env.test -- vitest`", "`tsx watch --env-file=../../.env`", "`set -a; .
// ./.env`"), searches for a pattern, or is a log line or a code expression. In
// a fence, where the text is a shell example, every span keeps its shell
// meaning (#849).
//
// The severity is Warn for a lookup of one named key that is neither stored
// in a variable nor part of a command that sends data out: redis-cli -a
// "$(grep '^REDIS_PASSWORD=' .env | cut -d= -f2-)" passes a project's own
// setting to a local tool (#885).
func sensitiveSubstitution(line string, inFence bool) ([]int, finding.Severity) {
	check := func(span string) bool {
		cleaned := substTemplateRe.ReplaceAllString(span, "")
		// A tool's own key read from that tool's home directory is reported by
		// CFG031 as a mention (#866).
		cleaned = homeToolPathRe.ReplaceAllStringFunc(cleaned, func(p string) string {
			if toolOwnPath(p) {
				return ""
			}
			return p
		})
		return cmdSubstSensitiveRe.MatchString(cleaned)
	}
	for _, loc := range dollarSubstRe.FindAllStringIndex(line, -1) {
		if envKeyLookup(line, loc) || countsOnly(line[loc[0]:loc[1]]) {
			continue
		}
		if check(line[loc[0]:loc[1]]) {
			if singleKeyLookup(line, loc) && !netExfilRe.MatchString(line) {
				return loc, finding.Warn
			}
			return loc, finding.Error
		}
	}
	// In a fence, a # line is a shell comment, where backticks run nothing:
	// "# Put these PATH exports + `set -a; source .env; set +a` in env.sh" (#868).
	if inFence && strings.HasPrefix(strings.TrimSpace(line), "#") {
		return nil, ""
	}
	for _, loc := range inlineCodeSpanRe.FindAllStringIndex(line, -1) {
		if !inFence && !readsOut(line[loc[0]+1:loc[1]-1]) {
			continue
		}
		if check(line[loc[0]:loc[1]]) {
			return loc, finding.Error
		}
	}
	return nil, ""
}

// guardHeadRe matches the head of a list item that names what a guard
// refuses or holds back: "**Blocks** catastrophic operations outright:",
// "**Asks** for confirmation on risky-but-legitimate ones:".
var guardHeadRe = regexp.MustCompile(`(?i)\b(?:block\w*|den(?:y|ied|ies)|refus\w*|forbid\w*|prohibit\w*|asks?\W*\s+(?:for\s+)?(?:confirmation|approval)|requires?\W*\s+(?:confirmation|approval))\b`)

// listedAsRefused reports whether the Part A span at loc on line i names a
// read the text refuses rather than orders: CFG031's checks (a negation or a
// refusing list, #869), or a list item, possibly wrapped over several lines,
// whose head says a guard blocks or asks about what follows: "credential
// reads (`cat ~/.ssh/…`), etc." under "- **Asks** for confirmation on
// risky-but-legitimate ones:" (#885).
func listedAsRefused(lines []string, i int, loc []int) bool {
	if notARead(lines, i, loc, lines[i][loc[0]:loc[1]]) {
		return true
	}
	for j := i; j >= 0 && i-j <= 20; j-- {
		l := lines[j]
		if strings.TrimSpace(l) == "" {
			return false
		}
		if m := listItemRe.FindStringSubmatch(l); m != nil {
			head := l
			if k := strings.Index(head, ":"); k >= 0 {
				head = head[:k]
			}
			return guardHeadRe.MatchString(head) || prohibitionRe.MatchString(head)
		}
		// Only an indented line continues the item above it.
		if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
			return false
		}
	}
	return false
}

// partBReach is how far, in bytes, a directive reaches to a network command
// on its own line, and how close to the end of its line it must sit to reach
// the lines below it.
const partBReach = 300

// netCommandStart returns where the first network command at or after from
// starts on line, or -1.
func netCommandStart(line string, from int) int {
	best := -1
	for _, re := range []filteredRegexp{netExfilRe, pipeShellRe} {
		if loc := re.FindStringIndex(line[from:]); loc != nil && (best < 0 || from+loc[0] < best) {
			best = from + loc[0]
		}
	}
	return best
}

// directiveReaches reports whether the directive at loc on line i applies to
// the network command on line j (#885). On the same line the command must
// start within partBReach of the directive, before or after it; a later line
// counts when the directive ends its own line and the command opens the later
// one. On a long prose paragraph "before any run" and a curl install note
// 13,000 characters away are unrelated.
func directiveReaches(lines []string, i int, loc []int, j int) bool {
	if j == i {
		start := netCommandStart(lines[i], max(0, loc[0]-partBReach))
		return start >= 0 && start <= loc[1]+partBReach
	}
	if len(lines[i])-loc[1] > partBReach {
		return false
	}
	start := netCommandStart(lines[j], 0)
	return start >= 0 && start <= partBReach
}

// Check flags CLAUDE.md text that makes Claude run shell commands on the
// attacker's behalf. A: command substitution reading a credential path (error,
// independent). B: an auto-execution or conditional directive co-occurring with
// a network command within 3 lines (error). C: an auto-execution directive
// alone (warn). D: a download piped into a shell, without a directive (warn).
// Matches inside fenced code blocks are still reported.
func (r *cfg036) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		lines := strings.Split(src.Content, "\n")
		fenced := fencedLines(src.Content)
		n := len(lines)

		directive := make([][]int, n)
		conditional := make([][]int, n)
		network := make([]bool, n)
		pipeShell := make([]bool, n)

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
			if loc := conditionalRe.FindStringIndex(line); loc != nil {
				next := ""
				if i+1 < n {
					next = lines[i+1]
				}
				if conditionalRunRe.MatchString(line[loc[1]:] + "\n" + next) {
					conditional[i] = loc
				}
			}
			pipeShell[i] = pipeShellRe.MatchString(line)
			network[i] = netExfilRe.MatchString(line) || pipeShell[i]
			if loc, sev := sensitiveSubstitution(line, fenced[i+1]); loc != nil {
				// A read the text refuses is downgraded, not dropped, as
				// CFG031 does (#869): a refusing heading must not hide a
				// payload.
				if listedAsRefused(lines, i, loc) {
					sev = finding.Warn
				}
				add(i, loc[0], sev, "uses command substitution reading a sensitive path (Part A) — \""+strings.TrimSpace(line[loc[0]:loc[1]])+"…\"; reading credential files in a substitution has no legitimate use in documentation. Remove it")
			}
		}

		// A directive applies to the command that follows it, up to the next blank
		// line (end of its command block) and at most 3 lines ahead. Looking only
		// forward avoids associating a directive with an unrelated earlier command.
		covered := make(map[int]bool)
		pipeCovered := make(map[int]bool)
		for i := range lines {
			loc := directive[i]
			if loc == nil {
				loc = conditional[i]
			}
			if loc == nil {
				continue
			}
			for j := i; j <= min(n-1, i+3); j++ {
				if j > i && strings.TrimSpace(lines[j]) == "" {
					break
				}
				if network[j] && directiveReaches(lines, i, loc, j) {
					add(i, loc[0], finding.Error, "combines an auto-execution directive with a network-exfiltration command (Part B) — instructs the agent to run a command that sends data to a remote host. Remove it")
					covered[i] = true
					pipeCovered[j] = true
					break
				}
			}
		}

		for i, line := range lines {
			if loc := decodeShellRe.FindStringIndex(line); loc != nil {
				add(i, loc[0], finding.Error, "decodes a literal base64 string into a shell (Part E) — nobody reading the file can see the command it runs; documentation has no reason to hide one this way. Write the command out")
			}
		}

		for i := range lines {
			if pipeShell[i] && !pipeCovered[i] {
				loc := pipeShellRe.FindStringIndex(lines[i])
				add(i, loc[0], finding.Warn, "pipes a download into a shell (Part D) — the agent runs whatever the server returns at that moment. If this is install documentation, point to a pinned, checksummed download or to the tool's own install docs instead")
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
