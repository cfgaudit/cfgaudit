package parser

import (
	"bufio"
	"fmt"
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
	f, err := os.Open(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
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

// HasPattern reports whether any of the ignore lines matches the given glob-style
// substring (case-insensitive prefix/suffix match is sufficient for our checks).
func HasPattern(lines []IgnoreLine, pattern string) bool {
	pattern = strings.ToLower(pattern)
	for _, l := range lines {
		if strings.ToLower(l.Pattern) == pattern ||
			strings.ToLower(l.Pattern) == "/"+pattern ||
			strings.HasSuffix(strings.ToLower(l.Pattern), "/"+pattern) {
			return true
		}
	}
	return false
}
