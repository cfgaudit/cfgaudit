// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// originURLRe finds the url of [remote "origin"] in a git config.
var originURLRe = regexp.MustCompile(`(?ms)^\[remote "origin"\]\s*$(.*?)^\[`)
var configURLRe = regexp.MustCompile(`(?m)^\s*url\s*=\s*(\S+)`)

// githubOwnerRe takes the owner from a GitHub remote URL: https, ssh or scp
// form.
var githubOwnerRe = regexp.MustCompile(`(?i)^(?:https?://(?:[^@/]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)([A-Za-z0-9][A-Za-z0-9-]*)/`)

var repoOwnerCache sync.Map // dir -> owner ("" when none)

// repoGitHubOwner returns the GitHub owner of the repository that holds file,
// read from the origin remote in the nearest .git/config above it, or "" when
// there is none, the remote is not on GitHub, or .git is not a directory.
func repoGitHubOwner(file string) string {
	dir, err := filepath.Abs(filepath.Dir(file))
	if err != nil {
		return ""
	}
	for i := 0; i < 12; i++ {
		if v, ok := repoOwnerCache.Load(dir); ok {
			return v.(string)
		}
		if data, err := scanroot.ReadFile(filepath.Join(dir, ".git", "config")); err == nil {
			owner := githubOwnerFromConfig(string(data))
			repoOwnerCache.Store(dir, owner)
			return owner
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func githubOwnerFromConfig(cfg string) string {
	m := originURLRe.FindStringSubmatch(cfg + "\n[")
	if m == nil {
		return ""
	}
	u := configURLRe.FindStringSubmatch(m[1])
	if u == nil {
		return ""
	}
	if o := githubOwnerRe.FindStringSubmatch(u[1]); o != nil {
		return strings.ToLower(o[1])
	}
	return ""
}

// githubURLOwnerRe takes the owner from a GitHub URL in an instruction:
// github.com/OWNER/..., raw.githubusercontent.com/OWNER/...,
// api.github.com/repos/OWNER/..., OWNER.github.io.
var githubURLOwnerRe = regexp.MustCompile(`(?i)^https?://(?:(?:www\.)?github\.com/|raw\.githubusercontent\.com/|api\.github\.com/repos/|gist\.githubusercontent\.com/)([A-Za-z0-9][A-Za-z0-9-]*)(?:/|$)|^https?://([A-Za-z0-9][A-Za-z0-9-]*)\.github\.io(?:/|$)`)

// githubURLOwner returns the lower-cased GitHub owner a URL points at, or "".
func githubURLOwner(url string) string {
	m := githubURLOwnerRe.FindStringSubmatch(url)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return strings.ToLower(m[1])
	}
	return strings.ToLower(m[2])
}
