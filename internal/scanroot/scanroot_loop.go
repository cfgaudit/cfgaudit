// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package scanroot

import (
	"errors"
	"syscall"
)

// isLoop reports a symbolic link that points at itself or forms a cycle:
// ELOOP on Unix, ERROR_CANT_RESOLVE_FILENAME (1921) on Windows.
func isLoop(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.Errno(1921))
}
