// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bufio"
	"fmt"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"os"
	"strings"
)

// IgnoreLine is a single non-blank, non-comment line from a .claudeignore file.
type IgnoreLine struct {
	Pattern string
	Line    int
}

// ParseIgnore reads a .claudeignore file and returns its effective pattern lines.
// Returns an empty slice (not an error) when the file does not exist.
func ParseIgnore(path string) ([]IgnoreLine, error) {
	f, err := scanroot.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var lines []IgnoreLine
	scanner := bufio.NewScanner(f)
	n := 0
	for scanner.Scan() {
		n++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, IgnoreLine{Pattern: line, Line: n})
	}
	return lines, scanner.Err()
}
