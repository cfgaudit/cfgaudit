// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg132 struct{}

// CFG132 reports an OpenCode config that loads instructions or skills from
// outside the repository (#748).
var CFG132 = &cfg132{}

func init() { All = append(All, CFG132) }

func (r *cfg132) ID() string { return "CFG132" }

// credentialPathRe matches a path or glob that reaches where credentials
// usually are. Normalised to slashes and matched anywhere in the entry.
var credentialPathRe = regexp.MustCompile(`(?i)(?:^|/)(?:\.ssh|\.aws|\.gnupg|\.azure|\.kube|\.docker|\.config/gcloud|\.npmrc|\.netrc|\.git-credentials|\.pypirc|\.env(?:\.[^/]*)?|credentials(?:\.json)?|id_(?:rsa|ed25519|ecdsa)[^/]*)(?:/|$)`)

// OpenCodeOutside classifies one instructions or skills entry: "url" for a
// remote source, "home" or "absolute" for a path on the reader's machine,
// "parent" for a relative path that climbs out, "" when it stays in the
// repository. OpenCode expands ~/ to the home directory and keeps an absolute
// path as it is (config/plugin/{instruction,skill}.ts, v2.2.6).
func OpenCodeOutside(entry string) string {
	e := strings.ReplaceAll(strings.TrimSpace(entry), `\`, "/")
	low := strings.ToLower(e)
	switch {
	case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"):
		return "url"
	case strings.HasPrefix(e, "~"):
		return "home"
	case strings.HasPrefix(e, "/"), len(e) >= 2 && e[1] == ':':
		return "absolute"
	case path.Clean(e) == ".." || strings.HasPrefix(path.Clean(e), "../"):
		return "parent"
	}
	return ""
}

// Check reports each instructions and skills entry of a committed OpenCode
// config that reaches outside the repository.
func (r *cfg132) Check(t *Target) []finding.Finding {
	if t == nil || t.OpenCode == nil {
		return nil
	}
	// A relative entry resolves against the working directory, not the
	// folder of the file, so "../x" in .opencode/opencode.json leaves the
	// repository even when it was meant from .opencode/.
	inDotDir := strings.Contains(strings.ReplaceAll(t.OpenCodeFile, `\`, "/"), ".opencode/")
	hint := func(kind string) string {
		if kind == "parent" && inDotDir {
			return " (relative entries resolve against the working directory, not the folder of this file, so drop the leading ../)"
		}
		return ""
	}
	var out []finding.Finding
	add := func(sev finding.Severity, msg string) {
		out = append(out, finding.Finding{RuleID: "CFG132", Severity: sev, Scope: t.Scope, File: t.OpenCodeFile, Message: msg})
	}
	for _, e := range t.OpenCode.Instructions {
		switch kind := OpenCodeOutside(e); {
		case kind == "url":
			add(finding.Warn, "OpenCode instructions names \""+e+"\", a URL: OpenCode fetches it whenever the config loads and adds the text to every request, so instructions the agent follows change on that server without a commit here. Copy the text into the repository instead")
		case kind != "" && credentialPathRe.MatchString(strings.ReplaceAll(e, `\`, "/")):
			add(finding.Error, "OpenCode instructions names \""+e+"\", which reaches a credentials location on the reader's machine: OpenCode reads every matching file into the instructions it sends to the model provider with each request, so the secrets leave the machine. Remove the entry")
		case kind != "":
			add(finding.Warn, "OpenCode instructions names \""+e+"\", outside the repository"+hint(kind)+": OpenCode reads the matching files on the reader's machine into every request, so files no review of this repository covers become instructions and go to the model provider. cfgaudit does not read them. Keep instructions in the repository, or in the user's own config")
		}
	}
	for _, e := range t.OpenCode.SkillSources() {
		switch kind := OpenCodeOutside(e); kind {
		case "":
		case "url":
			add(finding.Warn, "OpenCode skills names \""+e+"\", a URL: OpenCode downloads the skills it lists, so skill text the agent follows comes from that server and can change without a commit here. cfgaudit does not read it. Commit the skills instead")
		default:
			add(finding.Warn, "OpenCode skills names \""+e+"\", outside the repository"+hint(kind)+": OpenCode loads the skills in that folder on the reader's machine, which no review of this repository covers. cfgaudit does not read them. Keep shared skills in the repository")
		}
	}
	return out
}
