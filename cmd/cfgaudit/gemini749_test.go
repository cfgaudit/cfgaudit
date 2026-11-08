// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// #749: .gemini/.env answers settings placeholders and sets telemetry.
func TestGeminiDotEnvTelemetry(t *testing.T) {
	type res struct{ rule, file, sev string }
	scan := func(files map[string]string) []res {
		root := runFixture(t, files)
		var out []res
		for _, f := range scanFindings(t, "--only", "CFG046,CFG049,CFG110", root) {
			r, _ := filepath.Rel(root, f.File)
			out = append(out, res{f.RuleID, filepath.ToSlash(r), string(f.Severity)})
		}
		return out
	}
	// A placeholder answered by .gemini/.env.
	got := scan(map[string]string{
		".gemini/settings.json": `{"telemetry": {"enabled": true, "otlpEndpoint": "$X"}}`,
		".gemini/.env":          "X=https://collector.example\n",
	})
	if len(got) != 1 || got[0] != (res{"CFG046", ".gemini/settings.json", "warn"}) {
		t.Errorf("placeholder: %v", got)
	}
	// A placeholder .gemini/.env does not answer stays silent.
	if got := scan(map[string]string{
		".gemini/settings.json": `{"telemetry": {"enabled": true, "otlpEndpoint": "$X"}}`,
		".gemini/.env":          "OTHER=1\n",
	}); len(got) != 0 {
		t.Errorf("unanswered placeholder: %v", got)
	}
	// The endpoint in .gemini/.env, with no settings file.
	got = scan(map[string]string{".gemini/.env": "GEMINI_TELEMETRY_ENABLED=true\nGEMINI_TELEMETRY_LOG_PROMPTS=false\nOTEL_EXPORTER_OTLP_ENDPOINT=http://203.0.113.9:4318\n"})
	if len(got) != 1 || got[0] != (res{"CFG046", ".gemini/.env", "error"}) {
		t.Errorf("env endpoint: %v", got)
	}
	// The .env endpoint replaces the settings one, which is not reported.
	got = scan(map[string]string{
		".gemini/settings.json": `{"telemetry": {"otlpEndpoint": "https://settings.example"}}`,
		".gemini/.env":          "GEMINI_TELEMETRY_OTLP_ENDPOINT=https://env.example\n",
	})
	if len(got) != 1 || got[0] != (res{"CFG046", ".gemini/.env", "info"}) {
		t.Errorf("override: %v", got)
	}
	// A .env that only switches telemetry on raises the settings endpoint.
	got = scan(map[string]string{
		".gemini/settings.json": `{"telemetry": {"otlpEndpoint": "https://settings.example"}}`,
		".gemini/.env":          "GEMINI_TELEMETRY_ENABLED=1\n",
	})
	if len(got) != 1 || got[0] != (res{"CFG046", ".gemini/settings.json", "warn"}) {
		t.Errorf("enabled from env: %v", got)
	}
	// MCP url placeholders resolve too.
	got = scan(map[string]string{
		".gemini/settings.json": `{"mcpServers": {"s": {"url": "${H}/mcp"}}}`,
		".gemini/.env":          "H=http://203.0.113.7\n",
	})
	if len(got) != 1 || got[0].rule != "CFG049" {
		t.Errorf("mcp: %v", got)
	}
}

func TestGeminiCLIHome(t *testing.T) {
	for v, sev := range map[string]string{"./home": "error", "~/other": "info", "/opt/h": "info"} {
		root := runFixture(t, map[string]string{".gemini/.env": "GEMINI_CLI_HOME=" + v + "\n"})
		f := scanFindings(t, "--only", "CFG110", root)
		if len(f) != 1 || string(f[0].Severity) != sev || !strings.Contains(f[0].Message, "GEMINI_CLI_HOME") {
			t.Errorf("%s: %+v", v, f)
		}
	}
}

// A .gemini/.env that cannot be read to the end (a line past the scanner's
// limit) is CFG109's, and its placeholders are not used.
func TestGeminiDotEnvUnreadable(t *testing.T) {
	root := runFixture(t, map[string]string{".gemini/.env": "X=" + strings.Repeat("a", 70000) + "\n", "AGENTS.md": "# a\n"})
	f := scanFindings(t, "--only", "CFG109", root)
	if len(f) != 1 || filepath.Base(f[0].File) != ".env" {
		t.Fatalf("got %+v", f)
	}
}
