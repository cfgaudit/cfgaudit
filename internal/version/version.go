// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package version handles detection and comparison of Claude Code releases.
// The CLI uses Detect to ask the installed `claude` binary for its version
// and rules use Version.AtLeast to gate themselves on a minimum release.
package version

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// Version is a three-component MAJOR.MINOR.PATCH release identifier.
// Pre-release tags and build metadata are not modelled — Claude Code's
// public versions have not used them in observed releases.
type Version struct {
	Major, Minor, Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// AtLeast reports whether v is greater than or equal to min.
func (v Version) AtLeast(min Version) bool {
	if v.Major != min.Major {
		return v.Major > min.Major
	}
	if v.Minor != min.Minor {
		return v.Minor > min.Minor
	}
	return v.Patch >= min.Patch
}

var versionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// Parse extracts the first semver-like token from s.
// Tolerates surrounding text such as the `claude --version` banner.
func Parse(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("no semver pattern in %q", s)
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return Version{Major: maj, Minor: min, Patch: patch}, nil
}

// detectTimeout bounds `claude --version`, so a hanging binary on PATH falls
// back to "version unknown" instead of hanging the scan (#1062).
var detectTimeout = 5 * time.Second

// Detect runs `claude --version` and parses the output.
// The second return value is false when the `claude` binary is not on PATH —
// callers should treat that as "no version info" rather than an error.
func Detect() (Version, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), detectTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "claude", "--version")
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return Version{}, false, fmt.Errorf("claude --version did not finish within %s", detectTimeout)
	}
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			return Version{}, false, nil
		}
		return Version{}, false, err
	}
	v, err := Parse(string(out))
	if err != nil {
		return Version{}, false, err
	}
	return v, true, nil
}
