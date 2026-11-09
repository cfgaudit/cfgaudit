// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net/url"
	"strings"
)

// mcpVendor is a remote MCP endpoint a vendor documents for its own service.
// CFG049 reports such a server at info instead of warn (#1202): it still gets
// the context and headers the agent sends, but the host is the vendor's, not
// an unknown one. Each entry links the page that names the endpoint; keep an
// entry only while that page does.
type mcpVendor struct {
	host   string
	path   string // required path prefix, for a host that serves more than MCP
	vendor string
	doc    string
}

var mcpVendors = []mcpVendor{
	{"api.githubcopilot.com", "/mcp", "GitHub", "https://github.com/github/github-mcp-server"},
	{"mcp.sentry.dev", "", "Sentry", "https://docs.sentry.io/product/sentry-mcp/"},
	{"mcp.atlassian.com", "", "Atlassian", "https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/"},
	{"mcp.context7.com", "", "Upstash Context7", "https://github.com/upstash/context7"},
	{"learn.microsoft.com", "/api/mcp", "Microsoft Learn", "https://github.com/MicrosoftDocs/mcp"},
	{"mcp.linear.app", "", "Linear", "https://linear.app/docs/mcp"},
	{"mcp.svelte.dev", "", "Svelte", "https://svelte.dev/docs/mcp/remote-setup"},
	{"mcp.posthog.com", "", "PostHog", "https://posthog.com/docs/model-context-protocol"},
	{"mcp.deepwiki.com", "", "DeepWiki", "https://docs.devin.ai/work-with-devin/deepwiki-mcp"},
	{"mcp.supabase.com", "", "Supabase", "https://supabase.com/docs/guides/getting-started/mcp"},
	{"mcp.neon.tech", "", "Neon", "https://neon.com/docs/ai/neon-mcp-server"},
	{"mcp.figma.com", "", "Figma", "https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/"},
	{"mcp.cloudflare.com", "", "Cloudflare", "https://github.com/cloudflare/mcp-server-cloudflare"},
	{"mcp.vercel.com", "", "Vercel", "https://vercel.com/docs/mcp/vercel-mcp"},
	{"huggingface.co", "/mcp", "Hugging Face", "https://huggingface.co/docs/hub/hf-mcp-server"},
	{"mcp.exa.ai", "", "Exa", "https://docs.exa.ai/reference/exa-mcp"},
	{"mcp.expo.dev", "", "Expo", "https://docs.expo.dev/eas/ai/mcp/"},
	{"mcp.docs.astro.build", "", "Astro", "https://docs.astro.build/en/guides/build-with-ai/"},
	{"mcp.slack.com", "", "Slack", "https://docs.slack.dev/ai/mcp-server"},
	{"mcp.stripe.com", "", "Stripe", "https://docs.stripe.com/mcp"},
	{"mcp.excalidraw.com", "", "Excalidraw", "https://github.com/excalidraw/excalidraw-mcp"},
	{"mcp.clickup.com", "", "ClickUp", "https://developer.clickup.com/docs/connect-an-ai-assistant-to-clickups-mcp-server"},
}

// knownMCPVendor returns the vendor whose documented endpoint raw points at:
// an https or wss URL, without userinfo, whose host is the vendor host exactly
// and whose path starts with the vendor's prefix. A lookalike such as
// api.githubcopilot.com.example.com, or a vendor name in the userinfo or the
// path, does not match.
func knownMCPVendor(raw string) (mcpVendor, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || (u.Scheme != "https" && u.Scheme != "wss") {
		return mcpVendor{}, false
	}
	host := strings.ToLower(u.Hostname())
	for _, v := range mcpVendors {
		if host != v.host {
			continue
		}
		if v.path == "" || u.Path == v.path || strings.HasPrefix(u.Path, v.path+"/") {
			return v, true
		}
	}
	return mcpVendor{}, false
}
