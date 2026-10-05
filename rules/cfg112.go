package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg112 struct{}

// CFG112 reports an MCP server that sends a local file as its bearer token.
var CFG112 = &cfg112{}

func init() { All = append(All, CFG112) }

func (r *cfg112) ID() string { return "CFG112" }

// tokenFileCredentialRe matches credential files that belong to other tools.
// It extends CFG031's sensitivePathRe with the single-line token stores a
// bearer header can carry whole: git's credential store, the GitHub CLI's
// hosts file, and the Codex and Claude Code auth files.
var tokenFileCredentialRe = regexp.MustCompile(`(?i)(\.git-credentials\b|\.config/gh/hosts\.ya?ml\b|\.codex/auth\.json\b|\.claude/\.credentials\.json\b)`)

// Check reports bearer_token_file on an MCP server (#616).
//
// xAI Grok reads the named file on every request and sends
// "Authorization: Bearer <contents>" to the server's url
// (xai-grok-mcp/src/bearer_token_file.rs), and its docs say the path "must be
// absolute or start with ~/". So the file is never the repository's own: a
// committed .grok/config.toml chooses a file on the reader's machine and the
// URL its contents go to.
//
// The documented use is a token file another process keeps fresh, in Grok's
// own example "~/.config/internal-tools/token" for an internal server; that is
// reported as info, naming where the file goes. A path that is another tool's
// credential store (SSH, cloud, git, the GitHub CLI, another agent's auth) is
// the exfiltration shape and is an error: those files are not tokens for this
// server, and a single-line one such as ~/.git-credentials passes Grok's header
// check intact.
//
// Project servers load only once the folder is trusted, the same gate as any
// project MCP server.
func (r *cfg112) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		path := strings.TrimSpace(ref.Server.BearerTokenFile)
		if path == "" {
			continue
		}
		dest := strings.TrimSpace(ref.Server.URL)
		if dest == "" {
			dest = "the server"
		}
		base := "mcpServers." + ref.Name + ".bearer_token_file"
		f := finding.Finding{
			RuleID:   "CFG112",
			Severity: finding.Info,
			Scope:    t.Scope,
			File:     ref.File,
			Message: base + " sends the contents of " + quoteValue(path) + " as a bearer token to " + dest +
				" on every request. The file is on the reader's machine, so make sure both the path and the URL are ones you control" + userScopeNote(t),
		}
		if sensitivePathRe.MatchString(path) || tokenFileCredentialRe.MatchString(path) {
			f.Severity = finding.Error
			f.Message = base + " sends " + quoteValue(path) + ", another tool's credential file, as a bearer token to " + dest +
				": a committed config makes the agent read that file on the reader's machine and send it to a URL the same file chooses. Remove the key, or point it at a token file issued for this server" + userScopeNote(t)
		}
		findings = append(findings, f)
	}
	return findings
}
