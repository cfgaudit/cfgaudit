// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows
// +build windows

package scanroot

import "strings"

// isLoop reports whether err is the operating system's "too many levels of
// symbolic links" error. Windows surfaces a looping link as an error whose
// message contains that phrase, so this checks the message text; tests that
// need symlinks skip on Windows where the privilege is unavailable.
func isLoop(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "too many levels of symbolic links")
}
