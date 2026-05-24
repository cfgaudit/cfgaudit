package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
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
