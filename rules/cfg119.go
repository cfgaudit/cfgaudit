// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg119 struct{}

// CFG119 reports a repository script that an auto-run hook, task or MCP launch
// starts and that carries the markers of a malicious payload in combination
// (#1218): obfuscation, a download that is then run, a hunt for credentials
// or a dump of the environment. The pre-release corpus run for v1.20.0 found
// such an implant, started by a Claude Code SessionStart hook and a VS Code
// folder-open task at once, that the other rules reported only as a generic
// task and hook.
var CFG119 = &cfg119{}

func init() { All = append(All, CFG119) }

func (r *cfg119) ID() string { return "CFG119" }

var (
	// payloadObfIdentRe matches the hex identifiers an obfuscator gives
	// every variable (_0x4d2cd2). A hand-written or minified file has few.
	payloadObfIdentRe = regexp.MustCompile(`\b_0x[0-9a-f]{4,}\b`)
	// payloadDownloadRe matches a download of a release asset, an archive or a
	// binary, or a runtime installer script.
	payloadDownloadRe = regexp.MustCompile(`https?://[^\s"'` + "`" + `]*(?:/releases/download/|\.zip\b|\.tar\.gz\b|\.tgz\b|\.exe\b|\.bin\b|/install\.sh\b|bun\.sh/install|deno\.land/install)`)
	// payloadRunRe matches code that starts a process or makes a file executable.
	payloadRunRe = regexp.MustCompile(`\b(?:execFileSync|execSync|spawnSync|spawn|execFile|subprocess|os\.system|Start-Process|chmodSync|chmod)\b|\|\s*(?:ba|z)?sh\b`)
	// payloadTokenRe matches the prefixes of access tokens a stealer looks for.
	payloadTokenRe = regexp.MustCompile(`\b(?:ghp_|ghs_|gho_|ghu_|github_pat_|npm_[A-Za-z0-9]|AKIA[0-9A-Z]|xox[abprs]-)`)
	// payloadCredFileRe matches the files that hold developer credentials.
	payloadCredFileRe = regexp.MustCompile(`\.npmrc\b|\.aws/credentials|\.docker/config\.json|\.git-credentials|\.ssh/id_|\.config/gh/hosts`)
	// payloadEnvDumpRe matches code that reads the whole environment at once.
	payloadEnvDumpRe = regexp.MustCompile(`JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.items\(\)`)
	payloadEnvReadRe = regexp.MustCompile(`\bprocess\.env\b`)
	// payloadNetworkRe matches code that sends data out.
	payloadNetworkRe = regexp.MustCompile(`https?://|\bfetch\(|https?\.request\(|XMLHttpRequest|\bcurl\b|requests\.post|urllib\.request`)
)

// payloadMarkers are what CFG119 found in one script.
type payloadMarkers struct {
	obfuscated, fetchRun, credentials, envDump bool
	idents, envReads                           int
}

func scanPayload(content string) payloadMarkers {
	var m payloadMarkers
	m.idents = len(payloadObfIdentRe.FindAllStringIndex(content, -1))
	m.obfuscated = m.idents >= 30
	m.fetchRun = payloadDownloadRe.MatchString(content) && payloadRunRe.MatchString(content)
	network := payloadNetworkRe.MatchString(content)
	m.credentials = network && (payloadTokenRe.MatchString(content) || payloadCredFileRe.MatchString(content))
	m.envReads = len(payloadEnvReadRe.FindAllStringIndex(content, -1))
	m.envDump = network && (payloadEnvDumpRe.MatchString(content) || m.envReads >= 50)
	return m
}

func (m payloadMarkers) describe() string {
	var parts []string
	if m.obfuscated {
		parts = append(parts, "it is obfuscated ("+strconv.Itoa(m.idents)+" _0x identifiers)")
	}
	if m.fetchRun {
		parts = append(parts, "it downloads a release asset, archive, binary or runtime and runs code")
	}
	if m.credentials {
		parts = append(parts, "it looks for access tokens or credential files and talks to the network")
	}
	if m.envDump {
		parts = append(parts, "it reads the whole environment and talks to the network")
	}
	return strings.Join(parts, "; ")
}

// toolsOf counts the different tools among the launcher files: the config
// directory, or the file name for a root-level file (.mcp.json).
func toolsOf(launchers []string) int {
	seen := map[string]bool{}
	for _, l := range launchers {
		d := filepath.ToSlash(filepath.Dir(l))
		if d == "." {
			d = filepath.Base(l)
		}
		seen[strings.SplitN(d, "/", 2)[0]] = true
	}
	return len(seen)
}

// Check reports at error a script with obfuscation and any other marker, or
// with a download-and-run step and a credential hunt; at warn a script with
// one marker that several tools start, since starting the same script from a
// VS Code task and an agent hook is rare in a legitimate repository and the
// usual way an implant makes sure it runs.
func (r *cfg119) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, s := range t.LaunchedScripts {
		m := scanPayload(s.Content)
		other := m.fetchRun || m.credentials || m.envDump
		var sev finding.Severity
		switch {
		case m.obfuscated && other, m.fetchRun && m.credentials:
			sev = finding.Error
		case (m.obfuscated || other) && toolsOf(s.Launchers) >= 2:
			sev = finding.Warn
		default:
			continue
		}
		msg := s.Label + " carries the markers of a malicious payload: " + m.describe()
		if n := toolsOf(s.Launchers); n >= 2 {
			msg += "; it is started from " + strconv.Itoa(n) + " tools' configuration (" + strings.Join(s.Launchers, ", ") + ")"
		}
		msg += ". A committed script that runs when the repository is opened must not hide what it does; read it before you open the repository with an agent or editor, and if nobody in the project added it, treat the repository as compromised"
		findings = append(findings, finding.Finding{RuleID: "CFG119", Severity: sev, File: s.File, Message: msg})
	}
	return findings
}
