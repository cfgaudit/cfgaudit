// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package safeyaml decodes YAML from files cfgaudit did not write.
//
// gopkg.in/yaml.v3 panics on some malformed documents instead of returning an
// error: a mapping with a sequence as a key next to a `<<` merge key, decoded
// into a map or a struct, hashes the sequence ("hash of unhashable type
// []interface {}"). A repository could commit such a document to abort the
// scan and lose every other finding (#846). Every decode of scanned content into
// a map or a struct goes through Unmarshal here, which turns the panic into an
// error, so the file is handled like any other that fails to parse.
package safeyaml

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Unmarshal is yaml.Unmarshal that returns a decoder panic as an error.
func Unmarshal(data []byte, v any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("yaml: cannot decode document: %v", r)
		}
	}()
	return yaml.Unmarshal(data, v)
}
