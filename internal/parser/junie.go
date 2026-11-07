// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"fmt"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// JunieConfig is the part of a Junie project config, .junie/config.json, that
// cfgaudit reads (#1413), per https://junie.jetbrains.com/docs/junie-cli-configuration.html.
// hooks is left out: "hooks from the default project configuration file are
// ignored".
type JunieConfig struct {
	// Locations are the *-locations folders and guidelines-location, keyed by
	// the config key, as written.
	Locations map[string][]string
	// BYOK maps a provider to its API key.
	BYOK map[string]string
	// Proxies are the custom endpoints for LLM traffic.
	Proxies []JunieProxy
}

// JunieProxy is one entry of proxies.
type JunieProxy struct {
	Name, Kind, APIURL string
	// Headers are "Name: value" strings, as Junie writes them.
	Headers []string
}

// JunieLocationKeys are the keys whose values name folders (or, for
// guidelines-location, a file) Junie reads.
var JunieLocationKeys = []string{"mcp-locations", "skill-locations", "command-locations", "agent-locations", "guidelines-location"}

// ParseJunieConfig reads a Junie config. A value of the wrong type is skipped,
// so the rest of the file is still read.
func ParseJunieConfig(path string) (*JunieConfig, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c := &JunieConfig{Locations: map[string][]string{}, BYOK: map[string]string{}}
	for _, k := range JunieLocationKeys {
		switch v := raw[k].(type) {
		case string:
			if v != "" {
				c.Locations[k] = []string{v}
			}
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok && s != "" {
					c.Locations[k] = append(c.Locations[k], s)
				}
			}
		}
	}
	byok, _ := raw["byok"].(map[string]any)
	for k, v := range byok {
		if s, ok := v.(string); ok {
			c.BYOK[k] = s
		}
	}
	proxies, _ := raw["proxies"].([]any)
	for _, p := range proxies {
		m, _ := p.(map[string]any)
		var px JunieProxy
		px.Name, _ = m["name"].(string)
		px.Kind, _ = m["kind"].(string)
		px.APIURL, _ = m["api-url"].(string)
		hs, _ := m["headers"].([]any)
		for _, h := range hs {
			if s, ok := h.(string); ok {
				px.Headers = append(px.Headers, s)
			}
		}
		if px.APIURL != "" || len(px.Headers) > 0 {
			c.Proxies = append(c.Proxies, px)
		}
	}
	return c, nil
}
