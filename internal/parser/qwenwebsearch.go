// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

// QwenWebSearch is tools.webSearch of a qwen settings file (#974). The fields
// stay raw, so that a shape qwen rejects does not fail the whole file.
type QwenWebSearch struct {
	Enabled      json.RawMessage `json:"enabled,omitempty"`
	Model        json.RawMessage `json:"model,omitempty"`
	AllowedHosts json.RawMessage `json:"allowedHosts,omitempty"`
}

// qwenSearchBuiltinHosts are the host suffixes qwen's web search accepts
// without allowedHosts (classifyDashScopeBaseUrl in tools/web-search.ts,
// v0.27.0): DASHSCOPE_REGIONAL_HOSTS, QWENCLOUD_MAAS_HOSTS and three Alibaba
// suffixes.
var qwenSearchBuiltinHosts = []string{
	"dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com", "dashscope-us.aliyuncs.com",
	"maas.qianwenaiapi.com", "maas.qwencloudapi.com",
	"maas.aliyuncs.com", "alibaba-inc.com", "aliyun-inc.com",
}

// QwenWebSearchLeak is a search backend a repository names whose host only
// the repository's own allowedHosts admits, so the reader's API key goes to a
// host the repository picked.
type QwenWebSearchLeak struct {
	// File and Key say where the backend URL is set.
	File, Key string
	URL, Host string
	// KeyEnv is the environment variable whose value is sent as the bearer
	// token.
	KeyEnv string
	// AllowedBy names where the admitting host suffix comes from.
	AllowedBy string
	// Selected is whether the repository also picks the search model, without
	// which qwen does not use the backend.
	Selected bool
}

// QwenWebSearchInputs is what a repository commits for qwen's web search: the
// project settings file, and the variables of the project .env files in the
// order qwen reads them (.qwen/.env, then .env; the first file that sets a
// key wins).
type QwenWebSearchInputs struct {
	Settings     *QwenSettings
	SettingsFile string
	Env          map[string]string
	EnvFile      map[string]string
}

// QwenWebSearchLeaks resolves qwen's web search configuration the way
// resolveWebSearchSettings (cli/src/config/config.ts) and evaluateWebSearchGate
// (core/src/tools/web-search.ts) do at v0.27.0 and returns the backend whose
// host the repository admitted itself. Since v0.26.2, tools.webSearch.allowedHosts
// and WEB_SEARCH_ALLOWED_HOSTS add host suffixes, and the schema says "The
// configured host receives the API key". Neither is on qwen's workspace
// restriction lists, and WEB_SEARCH_* is not excluded from a project .env.
//
// The variables of the reader's own environment win over a .env, and cannot
// be seen here; the result assumes the reader sets none of them.
func QwenWebSearchLeaks(in QwenWebSearchInputs) []QwenWebSearchLeak {
	var ws *QwenWebSearch
	if in.Settings != nil && in.Settings.Tools != nil {
		ws = in.Settings.Tools.WebSearch
	}
	env := in.Env
	// ENABLE_WEB_SEARCH wins over tools.webSearch.enabled.
	if v, ok := env["ENABLE_WEB_SEARCH"]; ok && strings.TrimSpace(v) != "" {
		if !qwenTruthy(v) {
			return nil
		}
	} else if ws != nil && strings.TrimSpace(string(ws.Enabled)) == "false" {
		return nil
	}
	hosts, allowedBy := qwenEnvHosts(env["WEB_SEARCH_ALLOWED_HOSTS"]), "WEB_SEARCH_ALLOWED_HOSTS in "+qwenShortName(in.EnvFile["WEB_SEARCH_ALLOWED_HOSTS"])
	if len(hosts) == 0 && ws != nil {
		var list []any
		if json.Unmarshal(ws.AllowedHosts, &list) == nil {
			for _, e := range list {
				if s, ok := e.(string); ok {
					hosts = append(hosts, s)
				}
			}
		}
		allowedBy = "tools.webSearch.allowedHosts in " + qwenShortName(in.SettingsFile)
	}
	hosts = normalizeQwenHosts(hosts)
	if len(hosts) == 0 {
		return nil
	}
	selector := strings.TrimSpace(env["WEB_SEARCH_MODEL"])
	if selector == "" && ws != nil {
		var s string
		if json.Unmarshal(ws.Model, &s) == nil {
			selector = strings.TrimSpace(s)
		}
	}

	// The env backend: WEB_SEARCH_BASE_URL, keyed by WEB_SEARCH_API_KEY or,
	// without it, DASHSCOPE_API_KEY. A key the repository sets itself is its
	// own, not the reader's.
	if base := strings.TrimSpace(env["WEB_SEARCH_BASE_URL"]); base != "" {
		if strings.TrimSpace(env["WEB_SEARCH_API_KEY"]) != "" {
			return nil
		}
		host, ok := qwenAdmittedHost(base, hosts)
		if !ok {
			return nil
		}
		return []QwenWebSearchLeak{{
			File: in.EnvFile["WEB_SEARCH_BASE_URL"], Key: "WEB_SEARCH_BASE_URL", URL: base, Host: host,
			KeyEnv: "WEB_SEARCH_API_KEY or DASHSCOPE_API_KEY", AllowedBy: allowedBy, Selected: selector != "",
		}}
	}

	// The modelProviders backend: the selector names a model, and the entry's
	// own baseUrl and envKey are used. Only a selector the repository commits
	// is followed.
	if selector == "" || in.Settings == nil {
		return nil
	}
	authType, modelID := "", selector
	if i := strings.Index(selector, ":"); i > 0 {
		authType, modelID = selector[:i], selector[i+1:]
	}
	var providers map[string][]struct {
		ID      string `json:"id"`
		BaseURL string `json:"baseUrl"`
		EnvKey  string `json:"envKey"`
	}
	if json.Unmarshal(in.Settings.ModelProviders, &providers) != nil {
		return nil
	}
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []QwenWebSearchLeak
	for _, name := range names {
		if authType != "" && name != authType {
			continue
		}
		for _, e := range providers[name] {
			if e.ID != modelID {
				continue
			}
			if qwenBuiltinHost(e.BaseURL) {
				// qwen prefers an entry it can use, and a built-in host is one.
				return nil
			}
			if e.EnvKey == "" {
				continue
			}
			if host, ok := qwenAdmittedHost(e.BaseURL, hosts); ok {
				out = append(out, QwenWebSearchLeak{
					File: in.SettingsFile, Key: "modelProviders." + name + "[" + e.ID + "].baseUrl", URL: e.BaseURL, Host: host,
					KeyEnv: e.EnvKey, AllowedBy: allowedBy, Selected: true,
				})
			}
		}
	}
	return out
}

// qwenAdmittedHost reports the host of an https URL that only the extra
// suffixes admit.
func qwenAdmittedHost(raw string, extra []string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if hostUnder(host, qwenSearchBuiltinHosts) || !hostUnder(host, extra) {
		return "", false
	}
	return host, true
}

func qwenBuiltinHost(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Scheme == "https" && hostUnder(strings.ToLower(u.Hostname()), qwenSearchBuiltinHosts)
}

func hostUnder(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// qwenEnvHosts splits WEB_SEARCH_ALLOWED_HOSTS on commas.
func qwenEnvHosts(v string) []string {
	var out []string
	for _, e := range strings.Split(v, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// normalizeQwenHosts is normalizeWebSearchAllowedHosts: trim, lower-case,
// drop entries without a dot.
func normalizeQwenHosts(in []string) []string {
	var out []string
	for _, h := range in {
		if h = strings.ToLower(strings.TrimSpace(h)); strings.Contains(h, ".") {
			out = append(out, h)
		}
	}
	return out
}

// qwenTruthy is isTruthy (core/src/utils/bareMode.ts).
func qwenTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// qwenShortName names a project file for a message: .qwen/<name> for one in
// the .qwen folder, else the base name.
func qwenShortName(path string) string {
	if filepath.Base(filepath.Dir(path)) == ".qwen" {
		return ".qwen/" + filepath.Base(path)
	}
	return filepath.Base(path)
}
