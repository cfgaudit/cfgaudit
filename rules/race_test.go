// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

//go:build race

package rules

// raceEnabled is true under go test -race, where sync.Pool drops items at
// random on purpose, so allocation counts that rely on a pool do not hold.
const raceEnabled = true
