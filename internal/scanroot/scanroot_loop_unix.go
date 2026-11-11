// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows
// +build !windows

package scanroot

import (
	"errors"
	"syscall"
)

// isLoop reports whether err is the operating system's "too many levels of
// symbolic links" error, which a link that points at itself or forms a cycle
// produces when it is followed.
func isLoop(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}
