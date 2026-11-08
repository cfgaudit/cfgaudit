// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"sort"
)

// OpenCodeProviderURL is one base URL a committed OpenCode config sends a
// provider's requests, and with them its API key, to (#779).
type OpenCodeProviderURL struct {
	// Where names the key, e.g. `provider.anthropic.options.baseURL`.
	Where string
	URL   string
}

// openCodeProviderURLs returns the provider and model base URLs of a config,
// as OpenCode 2.2.6 resolves them:
//
//   - the v1 spelling `provider.<id>`, which normalize.ts migrates
//     (v1/config/migrate.ts): `api` replaces `options.baseURL`, and per model
//     `models.<m>.provider.api` replaces `models.<m>.options.baseURL`. OpenCode
//     1.x reads the same keys;
//   - the native v2 spelling `providers.<id>.settings.baseURL` and
//     `providers.<id>.models.<m>.settings.baseURL`. Since 2.1 a provider
//     baseURL replaces the catalog endpoint of every model of that provider,
//     not only the configured ones (config/plugin/provider.ts).
//
// The result is sorted by Where.
func openCodeProviderURLs(top map[string]json.RawMessage) []OpenCodeProviderURL {
	var out []OpenCodeProviderURL
	add := func(where, url string) {
		if url != "" {
			out = append(out, OpenCodeProviderURL{Where: where, URL: url})
		}
	}
	type v1Options struct {
		BaseURL string `json:"baseURL"`
	}
	var v1 map[string]struct {
		API     string    `json:"api"`
		Options v1Options `json:"options"`
		Models  map[string]struct {
			Provider struct {
				API string `json:"api"`
			} `json:"provider"`
			Options v1Options `json:"options"`
		} `json:"models"`
	}
	if raw, ok := top["provider"]; ok && json.Unmarshal(raw, &v1) == nil {
		for id, p := range v1 {
			base := "provider." + id
			if p.API != "" {
				add(base+".api", p.API)
			} else {
				add(base+".options.baseURL", p.Options.BaseURL)
			}
			for m, model := range p.Models {
				if model.Provider.API != "" {
					add(base+".models."+m+".provider.api", model.Provider.API)
				} else {
					add(base+".models."+m+".options.baseURL", model.Options.BaseURL)
				}
			}
		}
	}
	type v2Settings struct {
		BaseURL string `json:"baseURL"`
	}
	var v2 map[string]struct {
		Settings v2Settings `json:"settings"`
		Models   map[string]struct {
			Settings v2Settings `json:"settings"`
		} `json:"models"`
	}
	if raw, ok := top["providers"]; ok && json.Unmarshal(raw, &v2) == nil {
		for id, p := range v2 {
			base := "providers." + id
			add(base+".settings.baseURL", p.Settings.BaseURL)
			for m, model := range p.Models {
				add(base+".models."+m+".settings.baseURL", model.Settings.BaseURL)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Where < out[j].Where })
	return out
}
