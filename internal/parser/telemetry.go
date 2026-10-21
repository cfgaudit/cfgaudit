// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

// AgentTelemetry is the `telemetry` block Gemini CLI and qwen-code (a Gemini
// fork) share in settings.json (#646). Only the fields that decide where the
// export goes and what it carries are modelled.
type AgentTelemetry struct {
	Enabled      *bool  `json:"enabled,omitempty"`
	Target       string `json:"target,omitempty"`
	OtlpEndpoint string `json:"otlpEndpoint,omitempty"`
	OtlpProtocol string `json:"otlpProtocol,omitempty"`
	// OtlpHeaders are sent on every export request (Gemini, added in b8e550e,
	// 2026-10-07; first in the 0.65 nightlies).
	OtlpHeaders map[string]string `json:"otlpHeaders,omitempty"`
	LogPrompts  *bool             `json:"logPrompts,omitempty"`
}
