// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// geminiEnvVarRe is the pattern of resolveEnvVarsInString
// (packages/cli/src/utils/envVarResolver.ts): $VAR, ${VAR} and
// ${VAR:-DEFAULT}.
var geminiEnvVarRe = regexp.MustCompile(`\$(?:(\w+)|\{([^}]+?)(?::-([^}]*))?\})`)

// ResolveGeminiEnvVars expands the placeholders of one settings string the way
// Gemini CLI does, with env standing for the variables cfgaudit knows: those of
// the committed .gemini/.env (#749). A variable env does not hold falls back to
// its ${VAR:-DEFAULT} default, which the repository wrote too; without one the
// placeholder stays, since its value is then the user's own.
func ResolveGeminiEnvVars(s string, env map[string]string) string {
	return geminiEnvVarRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := geminiEnvVarRe.FindStringSubmatch(m)
		name := sub[1]
		if name == "" {
			name = sub[2]
		}
		if v, ok := env[name]; ok {
			return v
		}
		if sub[2] != "" && strings.HasPrefix(m, "${"+sub[2]+":-") {
			return sub[3]
		}
		return m
	})
}

// ParseGeminiSettingsEnv parses a Gemini settings.json after expanding its
// placeholders with env. Since Gemini CLI 0.66.0 (google-gemini/gemini-cli
// #29750) the settings are resolved again once the .env file is loaded: "Final
// pass: variables from `.env` files are now part of `process.env`, so resolve
// the settings again" (packages/cli/src/config/settings.ts). Workspace settings
// are resolved only in a trusted folder, the same condition under which
// .gemini/.env loads. Every string value is expanded, as resolveEnvVarsInObject
// does; keys are not.
func ParseGeminiSettingsEnv(path string, env map[string]string) (*GeminiSettings, error) {
	if len(env) == 0 {
		return ParseGeminiSettings(path)
	}
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(stripJSONC(data)))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// A decoded JSON value always encodes again.
	resolved, _ := json.Marshal(resolveGeminiValue(raw, env))
	var s GeminiSettings
	if err := json.Unmarshal(resolved, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}

func resolveGeminiValue(v any, env map[string]string) any {
	switch x := v.(type) {
	case string:
		return ResolveGeminiEnvVars(x, env)
	case []any:
		for i := range x {
			x[i] = resolveGeminiValue(x[i], env)
		}
	case map[string]any:
		for k := range x {
			x[k] = resolveGeminiValue(x[k], env)
		}
	}
	return v
}

// GeminiEnvTelemetry returns the telemetry values a .gemini/.env sets, from the
// variables Gemini CLI reads ahead of the settings (resolveTelemetrySettings in
// packages/core/src/telemetry/config.ts: argv, then the environment, then
// settings), or nil when it sets none. GEMINI_TELEMETRY_OTLP_ENDPOINT wins over
// OTEL_EXPORTER_OTLP_ENDPOINT. EndpointKey names the variable that set the
// endpoint.
func GeminiEnvTelemetry(env map[string]string) (tel *AgentTelemetry, endpointKey string) {
	flag := func(key string) *bool {
		v, ok := env[key]
		if !ok {
			return nil
		}
		// parseBooleanEnvFlag: any value but "true" or "1" is false.
		b := v == "true" || v == "1"
		return &b
	}
	out := &AgentTelemetry{Enabled: flag("GEMINI_TELEMETRY_ENABLED"), LogPrompts: flag("GEMINI_TELEMETRY_LOG_PROMPTS")}
	for _, k := range []string{"GEMINI_TELEMETRY_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		if v := strings.TrimSpace(env[k]); v != "" {
			out.OtlpEndpoint, endpointKey = v, k
			break
		}
	}
	if out.Enabled == nil && out.LogPrompts == nil && out.OtlpEndpoint == "" {
		return nil, ""
	}
	return out, endpointKey
}
