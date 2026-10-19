package parser

import (
	"bufio"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"strings"
)

// ParseDotEnv reads a .env file the way the dotenv package Gemini CLI uses does
// for the cases that matter here: KEY=VALUE per line, an optional `export `
// prefix, `#` comments, and single, double or backtick quotes around the value.
// A later key wins, as in dotenv.parse. Multi-line quoted values are not
// modelled; their first line is kept.
func ParseDotEnv(path string) (map[string]string, error) {
	f, err := scanroot.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		if n := len(val); n >= 2 && strings.ContainsRune("'\"`", rune(val[0])) && val[n-1] == val[0] {
			val = val[1 : n-1]
		} else if j := strings.Index(val, " #"); j >= 0 {
			val = strings.TrimSpace(val[:j])
		}
		out[key] = val
	}
	return out, sc.Err()
}
