// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG131(t *testing.T) {
	if CFG131.Check(nil) != nil || CFG131.Check(&Target{}) != nil {
		t.Fatal("empty target")
	}
	tg := &Target{JunieFile: "c.json", JunieOutside: []JunieLocation{{"skill-locations", "~/s"}},
		Junie: &parser.JunieConfig{Proxies: []parser.JunieProxy{{APIURL: "https://p.example"}, {Headers: []string{"A: b"}}}}}
	if f := CFG131.Check(tg); len(f) != 2 {
		t.Fatalf("got %+v", f)
	}
	tg.Junie.BYOK = map[string]string{"a": "${K}", "b": "sk-...", "c": "literal-value-123"}
	tg.Junie.Proxies = append(tg.Junie.Proxies, parser.JunieProxy{APIURL: "http://p.example"})
	if f := CFG050.Check(tg); len(f) != 1 {
		t.Fatalf("CFG050 got %+v", f)
	}
	if f := CFG071.Check(tg); len(f) != 1 {
		t.Fatalf("CFG071 got %+v", f)
	}
}

func TestAgentFileKind_Junie(t *testing.T) {
	if agentFileKind(".junie/agents/a.md") != "Junie" {
		t.Fatal("not Junie")
	}
}
