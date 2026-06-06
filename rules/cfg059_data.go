package rules

// Known-good MCP identifiers CFG059 compares config entries against to detect
// typosquats. This is the extensible allowlist referenced by the rule — add
// entries as the ecosystem standardises. Entries are matched case-insensitively;
// an exact match is always treated as legitimate (never flagged).

// knownMCPPackages are official / widely-used npm MCP server packages. A config
// package within one homoglyph substitution or one edit of one of these (but not
// an exact match) is reported as a likely typosquat.
var knownMCPPackages = []string{
	"@modelcontextprotocol/server-filesystem",
	"@modelcontextprotocol/server-memory",
	"@modelcontextprotocol/server-everything",
	"@modelcontextprotocol/server-sequential-thinking",
	"@modelcontextprotocol/server-fetch",
	"@modelcontextprotocol/server-git",
	"@modelcontextprotocol/server-time",
	"@modelcontextprotocol/server-github",
	"@modelcontextprotocol/server-gitlab",
	"@modelcontextprotocol/server-google-maps",
	"@modelcontextprotocol/server-slack",
	"@modelcontextprotocol/server-postgres",
	"@modelcontextprotocol/server-sqlite",
	"@modelcontextprotocol/server-puppeteer",
	"@modelcontextprotocol/server-brave-search",
	"@modelcontextprotocol/server-redis",
	"@modelcontextprotocol/server-aws-kb-retrieval",
	"@modelcontextprotocol/server-everart",
	"@modelcontextprotocol/inspector",
	"@modelcontextprotocol/sdk",
}

// knownMCPHosts are reference hostnames for well-known AI / MCP infrastructure.
// A remote MCP server whose host is a lookalike of one of these is flagged. These
// are anchors for lookalike detection, not an exhaustive list of valid endpoints.
var knownMCPHosts = []string{
	"api.anthropic.com",
	"mcp.anthropic.com",
	"api.openai.com",
	"mcp.deepwiki.com",
	"api.githubcopilot.com",
}
