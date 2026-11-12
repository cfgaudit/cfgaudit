// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func cfg138One(t *testing.T, server string) []finding.Finding {
	t.Helper()
	return CFG138.Check(mcpTarget(t, `{"b":`+server+`}`))
}

// The fixture from #1634: both servers attach to a running browser, and the
// second also starts with the user's Chrome profile.
func TestCFG138_IssueFixture(t *testing.T) {
	f := CFG138.Check(mcpTarget(t, `{
	  "pw":{"command":"npx","args":["-y","@playwright/mcp@0.0.41","--cdp-endpoint","http://127.0.0.1:9222"]},
	  "cd":{"command":"npx","args":["-y","chrome-devtools-mcp@0.9.0","--browserUrl","http://127.0.0.1:9222","--user-data-dir","/home/me/.config/google-chrome"]}}`))
	var warn, info int
	for _, x := range f {
		switch x.Severity {
		case finding.Warn:
			warn++
			if !strings.Contains(x.Message, "mcpServers.cd") || !strings.Contains(x.Message, "own browser profile") {
				t.Errorf("warn should name the profile: %s", x.Message)
			}
		case finding.Info:
			info++
		}
	}
	if warn != 1 || info != 2 {
		t.Fatalf("want 1 warn and 2 info, got %+v", f)
	}
}

func TestCFG138_Warn(t *testing.T) {
	for _, s := range []string{
		`{"command":"npx","args":["@playwright/mcp@latest","--extension"]}`,
		`{"command":"npx","args":["-y","chrome-devtools-mcp@latest","--autoConnect"]}`,
		`{"command":"npx","args":["-y","chrome-devtools-mcp@latest","--auto-connect=true"]}`,
		`{"command":"npx","args":["@playwright/mcp","--user-data-dir=~/Library/Application Support/Google/Chrome"]}`,
		`{"command":"npx","args":["@playwright/mcp","--user-data-dir","C:\\Users\\me\\AppData\\Local\\Google\\Chrome\\User Data"]}`,
		`{"command":"npx","args":["@playwright/mcp","--user-data-dir=%LOCALAPPDATA%\\Microsoft\\Edge\\User Data"]}`,
		`{"command":"npx","args":["chrome-devtools-mcp","--chrome-arg=--user-data-dir=/home/me/.config/chromium"]}`,
		`{"command":"npx","args":["@playwright/mcp","--user-data-dir","/home/me/.mozilla/firefox/abc.default"]}`,
		`{"command":"npx","args":["@playwright/mcp","--cdp-endpoint=http://10.0.0.5:9222"]}`,
		`{"command":"npx","args":["chrome-devtools-mcp","--wsEndpoint","ws://browser.internal:9222/devtools/browser/x"]}`,
		`{"command":"npx","args":["@playwright/mcp"],"env":{"PLAYWRIGHT_MCP_EXTENSION":"true"}}`,
		`{"command":"npx","args":["@playwright/mcp"],"env":{"PLAYWRIGHT_MCP_USER_DATA_DIR":"/home/me/.config/google-chrome"}}`,
		`{"command":"playwright-mcp.cmd","args":["--extension"]}`,
	} {
		f := cfg138One(t, s)
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("%s: want one warn, got %+v", s, f)
		}
	}
}

func TestCFG138_Info(t *testing.T) {
	for _, s := range []string{
		`{"command":"npx","args":["@playwright/mcp@latest","--cdp-endpoint","http://localhost:9222"]}`,
		`{"command":"npx","args":["@playwright/mcp","--cdp-endpoint=http://127.0.0.1:8944"]}`,
		`{"command":"npx","args":["-y","chrome-devtools-mcp@latest","--browser-url=http://[::1]:9226"]}`,
		`{"command":"npx","args":["chrome-devtools-mcp","--browserUrl","127.0.0.1:9222"]}`,
		`{"command":"npx","args":["chrome-devtools-mcp","--browserUrl","${CDP_URL}"]}`,
		`{"command":"cmd","args":["/c","pnpm","dlx","firefox-devtools-mcp@latest","--connect-existing","--marionette-port","2828"]}`,
		`{"command":"npx","args":["@playwright/mcp"],"env":{"PLAYWRIGHT_MCP_CDP_ENDPOINT":"http://localhost:9222"}}`,
	} {
		f := cfg138One(t, s)
		if len(f) != 1 || f[0].Severity != finding.Info {
			t.Errorf("%s: want one info, got %+v", s, f)
		}
	}
}

func TestCFG138_NotReported(t *testing.T) {
	for _, s := range []string{
		// A project folder as the profile, the sandbox switch, a plain launch.
		`{"command":"npx","args":["@playwright/mcp@latest","--user-data-dir=./misc/browser-storage"]}`,
		`{"command":"npx","args":["@playwright/mcp@latest","--no-sandbox","--headless"]}`,
		`{"command":"npx","args":["-y","chrome-devtools-mcp@latest","--isolated"]}`,
		`{"command":"npx","args":["@playwright/mcp","--extension=false"]}`,
		`{"command":"npx","args":["@playwright/mcp"],"env":{"DEBUG":"pw:*","PLAYWRIGHT_MCP_EXTENSION":"false"}}`,
		`{"command":"npx","args":["@playwright/mcp"],"env":{"PLAYWRIGHT_MCP_EXTENSION":""}}`,
		`{"command":"npx","args":["@playwright/mcp","--cdp-endpoint"]}`,
		// The same switch names on a server that is not a browser server.
		`{"command":"node","args":["build/index.js","--extension","--extension-port","3334"]}`,
		`{"command":"npx","args":["some-mcp","--cdp-endpoint","http://10.0.0.5:9222"]}`,
	} {
		if f := cfg138One(t, s); len(f) != 0 {
			t.Errorf("%s: want no finding, got %+v", s, f)
		}
	}
}

func TestCFG138_Helpers(t *testing.T) {
	if CFG138.ID() != "CFG138" || CFG138.Check(nil) != nil {
		t.Fatal("ID or nil target")
	}
	if browserEndpointHost("http://%zz") != "" {
		t.Error("unparsable endpoint should give no host")
	}
	for h, want := range map[string]bool{"localhost": true, "app.localhost": true, "127.0.0.2": true, "0.0.0.0": true, "::1": true, "10.0.0.5": false, "example.com": false} {
		if loopbackHost(h) != want {
			t.Errorf("loopbackHost(%q) != %v", h, want)
		}
	}
}
