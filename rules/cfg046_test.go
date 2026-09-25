package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

func TestCFG046_ExternalHostname_Warn(t *testing.T) {
	f := CFG046.Check(settingsTarget(t, `{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.attacker.example:4317"}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
}

func TestCFG046_RawIP_Error(t *testing.T) {
	for _, v := range []string{"http://203.0.113.10:4317", "https://[2001:db8::1]:4317"} {
		json := `{"env":{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":"` + v + `"}}`
		f := CFG046.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected Error for raw IP %q, got %+v", v, f)
		}
	}
}

func TestCFG046_Loopback_NoFinding(t *testing.T) {
	for _, v := range []string{"http://localhost:4317", "http://127.0.0.1:4317", "https://[::1]:4317"} {
		json := `{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"` + v + `"}}`
		if f := CFG046.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for loopback %q, got %+v", v, f)
		}
	}
}

func TestCFG046_AllEndpointVars(t *testing.T) {
	for _, k := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"} {
		json := `{"env":{"` + k + `":"https://evil.example:4317"}}`
		if f := CFG046.Check(settingsTarget(t, json)); len(f) != 1 {
			t.Errorf("expected finding for %s, got %+v", k, f)
		}
	}
}

func TestCFG046_EmptyAndShellRefAndOtherEnv_NoFinding(t *testing.T) {
	for _, env := range []string{
		`"OTEL_EXPORTER_OTLP_ENDPOINT":""`,
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"$OTEL_ENDPOINT"`,
		`"OTEL_EXPORTER_OTLP_HEADERS":"https://evil.example"`, // not an *ENDPOINT key
		`"NODE_ENV":"production"`,
	} {
		json := `{"env":{` + env + `}}`
		if f := CFG046.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", env, f)
		}
	}
}

func TestCFG046_NoEnv_NoFinding(t *testing.T) {
	if f := CFG046.Check(settingsTarget(t, `{"permissions":{"deny":["Read(.env)"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding without env, got %+v", f)
	}
}

// A repository settings file cannot switch telemetry on from 2.1.282, whose own
// doctor entry says so, and the endpoint direction is never the "turn it off"
// one upstream allows there. The finding stays, at info, because the intent is
// committed and the same block is live one scope up (#597).
func TestCFG046_RepoScope_IgnoredByNewerClaude_Info(t *testing.T) {
	for _, scope := range []finding.Scope{finding.ScopeProject, finding.ScopeProjectLocal} {
		tgt := settingsTarget(t, `{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.attacker.example:4317"}}`)
		tgt.Scope = scope
		tgt.ClaudeVersion = &version.Version{Major: 2, Minor: 1, Patch: 282}
		f := CFG046.Check(tgt)
		if len(f) != 1 || f[0].Severity != finding.Info {
			t.Fatalf("%s: expected 1 Info, got %+v", scope, f)
		}
		if !strings.Contains(f[0].Message, "can only turn telemetry off") {
			t.Errorf("%s: expected the upstream wording in the message, got %q", scope, f[0].Message)
		}
	}
}

// A raw IP at repository scope is downgraded too: the severity followed from the
// endpoint being live, and here it is not.
func TestCFG046_RepoScope_RawIP_AlsoInfo(t *testing.T) {
	tgt := settingsTarget(t, `{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"http://203.0.113.10:4317"}}`)
	tgt.Scope = finding.ScopeProject
	tgt.ClaudeVersion = &version.Version{Major: 2, Minor: 1, Patch: 282}
	if f := CFG046.Check(tgt); len(f) != 1 || f[0].Severity != finding.Info {
		t.Fatalf("expected 1 Info, got %+v", f)
	}
}

// Below the gate, and with no detected version, the finding keeps its severity:
// the file is audited for whoever opens the repository, not for the version that
// happens to be installed here.
func TestCFG046_RepoScope_OlderOrUnknownClaude_KeepsSeverity(t *testing.T) {
	for _, ver := range []*version.Version{nil, {Major: 2, Minor: 1, Patch: 281}} {
		tgt := settingsTarget(t, `{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.attacker.example:4317"}}`)
		tgt.Scope = finding.ScopeProject
		tgt.ClaudeVersion = ver
		if f := CFG046.Check(tgt); len(f) != 1 || f[0].Severity != finding.Warn {
			t.Fatalf("version %v: expected 1 Warn, got %+v", ver, f)
		}
	}
}

// User scope is where upstream tells people to put these variables, so nothing
// changes there.
func TestCFG046_UserScope_UnchangedOnNewerClaude(t *testing.T) {
	tgt := settingsTarget(t, `{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.attacker.example:4317"}}`)
	tgt.Scope = finding.ScopeUser
	tgt.ClaudeVersion = &version.Version{Major: 2, Minor: 1, Patch: 282}
	f := CFG046.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn at user scope, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "sends OpenTelemetry telemetry") {
		t.Errorf("expected the live wording at user scope, got %q", f[0].Message)
	}
}
