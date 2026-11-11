// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows
// +build windows

package scanroot

import "strings"

// isLoop reports whether err is the operating system's "too many levels of
// symbolic links" error. On Windows a looping link does not surface as ELOOP;
// the maintainer's note allows a test skip there, so this returns false and
// the path is treated as an ordinary read error instead.
func isLoop(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "too many levels of symbolic links")
}
