// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// QwenModelProvider is one entry of a qwen settings file's modelProviders
// block (#1565): an auth type maps to a list of models, each with the
// endpoint (baseUrl) and the environment variable whose value qwen sends as
// its API key (envKey). modelConfigResolver.ts at v0.27.0 reads the key from
// env[modelProvider.envKey] and the endpoint from modelProvider.baseUrl.
type QwenModelProvider struct {
	AuthType, ID, BaseURL, EnvKey string
	// Selected is whether the same file picks this model: model.name is its
	// id, and security.auth.selectedType, when set, is its auth type.
	Selected bool
}

// ModelProviderEntries returns the modelProviders entries, sorted by auth type
// and id. A block of another shape gives none.
func (s *QwenSettings) ModelProviderEntries() []QwenModelProvider {
	if s == nil {
		return nil
	}
	var block map[string][]struct {
		ID      string `json:"id"`
		BaseURL string `json:"baseUrl"`
		EnvKey  string `json:"envKey"`
	}
	if json.Unmarshal(s.ModelProviders, &block) != nil {
		return nil
	}
	var model struct {
		Name string `json:"name"`
	}
	var security struct {
		Auth struct {
			SelectedType string `json:"selectedType"`
		} `json:"auth"`
	}
	_ = json.Unmarshal(s.Model, &model)
	_ = json.Unmarshal(s.Security, &security)
	var out []QwenModelProvider
	for auth, entries := range block {
		for _, e := range entries {
			out = append(out, QwenModelProvider{
				AuthType: auth, ID: e.ID, BaseURL: strings.TrimSpace(e.BaseURL), EnvKey: strings.TrimSpace(e.EnvKey),
				Selected: e.ID != "" && e.ID == model.Name && (security.Auth.SelectedType == "" || security.Auth.SelectedType == auth),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].AuthType+"\x00"+out[i].ID < out[j].AuthType+"\x00"+out[j].ID
	})
	return out
}

// Host returns the lower-cased host of the entry's baseUrl, or "".
func (p QwenModelProvider) Host() string {
	u, err := url.Parse(p.BaseURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
