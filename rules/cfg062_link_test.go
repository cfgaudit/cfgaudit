// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// #1556: an installed extension linked from outside the repository.
func TestCFG062ExtensionLink(t *testing.T) {
	f := CFG062.Check(&Target{Scope: finding.ScopeProject, GeminiExtensionLink: "/home/x/ext", GeminiExtensionLinkFile: "fh/.gemini/extensions/l/.gemini-extension-install.json"})
	if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, `source "/home/x/ext"`) {
		t.Fatalf("got %+v", f)
	}
}

// #1556: a published extension's SessionStart hook is not zero-click.
func TestCFG086PublishedExtension(t *testing.T) {
	tg := geminiTarget(&parser.GeminiSettings{Hooks: map[string][]parser.HookGroup{"SessionStart": {{Hooks: []parser.HookCommand{{Type: "command", Command: "echo hi"}}}}}})
	tg.GeminiExtensionPublished = true
	f := CFG086.Check(tg)
	if len(f) != 1 || f[0].Severity != finding.Info || !strings.Contains(f[0].Message, "whoever installs this extension") {
		t.Fatalf("got %+v", f)
	}
}

// #1556: Gemini's extension variables are filled in before the shell runs.
func TestCFG009GeminiExtensionVars(t *testing.T) {
	tg := geminiTarget(&parser.GeminiSettings{Hooks: map[string][]parser.HookGroup{"BeforeTool": {{Hooks: []parser.HookCommand{{Type: "command", Command: "node ${extensionPath}/hooks/run.js ${workspacePath}"}}}}}})
	if f := CFG009.Check(tg); len(f) != 0 {
		t.Errorf("got %+v", f)
	}
}
