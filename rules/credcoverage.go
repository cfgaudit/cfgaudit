// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// secretDenyRe matches a deny entry that guards secret files: the bare Read,
// Edit or Write tool, a wildcard, or a rule on a credential-like path.
var secretDenyRe = regexp.MustCompile(`(?i)^(?:Read|Edit|Write|Grep|Glob)(?:\(\s*(?:\*\*?|/?/?\*\*(?:/\*)?)\s*\)|\([^)]*(?:\.env|\.pem|\.key\b|\.p12|\.pfx|\.jks|\.ssh|id_(?:rsa|ed25519|ecdsa|dsa)|\.aws|gcloud|\.azure|credential|secret|token|\.npmrc|\.netrc|\.kube|\.gnupg|\.docker)[^)]*\))?$`)

// guardsSecrets reports whether any deny entry guards secret files.
func guardsSecrets(deny []string) bool {
	for _, d := range deny {
		if secretDenyRe.MatchString(strings.TrimSpace(d)) {
			return true
		}
	}
	return false
}

// credentialCoverage grades a credential-coverage gap of CFG041 to CFG044
// (#1172) and returns the severity and a clause for the message. The gap is
// an error for a deny list that guards secrets and misses this class whole,
// and in auto or bypass mode, where nothing else stops a read. It is a
// warning when the deny list guards no secret file at all, because it was
// written for something else (a git push, a generated directory): in the
// pre-release corpus run for v1.20.0, 65 of 110 files were of that kind and
// got three or four errors for adding one unrelated deny, where no deny list
// at all gets one CFG006 warning. It is also a warning when the class is
// partly covered.
func credentialCoverage(t *Target, deny []string, partial bool) (finding.Severity, string) {
	mode := ""
	if t.Settings != nil && t.Settings.Permissions != nil {
		mode = t.Settings.Permissions.DefaultMode
	}
	switch {
	case mode == "bypassPermissions" || mode == "auto":
		return finding.Error, ""
	case !guardsSecrets(deny):
		return finding.Warn, " (the deny list guards no secret file yet; it holds other rules)"
	case partial:
		return finding.Warn, " (the rest of this class is already denied)"
	}
	return finding.Error, ""
}
