package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG012_UnknownTopLevelKey(t *testing.T) {
	f := CFG012.Check(settingsTarget(t, `{"thisIsNotARealKey":"whatever"}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unknown key, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "thisIsNotARealKey") {
		t.Errorf("expected message to name the unknown key, got: %s", f[0].Message)
	}
}

func TestCFG012_TopLevelTypeMismatch(t *testing.T) {
	// apiKeyHelper is "string" in the schema and is not strict-parsed by the
	// internal Settings struct, so a wrong type still reaches CFG012 via Raw.
	// For keys the strict parser models (permissions, env, hooks, mcpServers)
	// the parser itself rejects the file before any rule runs — see
	// internal/parser/settings.go.
	f := CFG012.Check(settingsTarget(t, `{"apiKeyHelper":["should be a string"]}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for type mismatch, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "array") || !strings.Contains(f[0].Message, "string") {
		t.Errorf("expected message to name both actual and expected types, got: %s", f[0].Message)
	}
}

func TestCFG012_KnownKey_NoFinding(t *testing.T) {
	f := CFG012.Check(settingsTarget(t, `{"permissions":{"allow":[],"deny":["Bash(rm *)"]},"env":{"NODE_ENV":"production"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for schema-known keys, got %d: %+v", len(f), f)
	}
}

func TestCFG012_AllowlistedMcpServers_NoFinding(t *testing.T) {
	// mcpServers is widely used in the wild but absent from the bundled
	// schema — it must not produce a warning.
	f := CFG012.Check(settingsTarget(t, `{"mcpServers":{"x":{"command":"y"}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for allowlisted mcpServers, got %d: %+v", len(f), f)
	}
}

func TestCFG012_AllowlistedDefaultMode_NoFinding(t *testing.T) {
	f := CFG012.Check(settingsTarget(t, `{"defaultMode":"plan"}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for allowlisted defaultMode, got %d: %+v", len(f), f)
	}
}

func TestCFG012_SchemaMetaKey_NoFinding(t *testing.T) {
	f := CFG012.Check(settingsTarget(t, `{"$schema":"https://json.schemastore.org/claude-code-settings.json"}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for $schema meta key, got %d: %+v", len(f), f)
	}
}

func TestCFG012_IntegerForNumberSchema_NoFinding(t *testing.T) {
	// cleanupPeriodDays is typed "integer" in the schema; an integer JSON
	// literal must satisfy that ("integer" normalizes to "number" internally).
	f := CFG012.Check(settingsTarget(t, `{"cleanupPeriodDays":30}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for integer matching integer schema, got %d: %+v", len(f), f)
	}
}

func TestCFG012_MultipleProblems_SortedOutput(t *testing.T) {
	f := CFG012.Check(settingsTarget(t, `{"zUnknown":1,"aUnknown":2}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "aUnknown") || !strings.Contains(f[1].Message, "zUnknown") {
		t.Errorf("expected sorted output, got: %s / %s", f[0].Message, f[1].Message)
	}
}

func TestCFG012_NoSettings_NoFinding(t *testing.T) {
	f := CFG012.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}
