// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package maliciousioc

import (
	"strings"
	"testing"
)

func TestEmbeddedDataset(t *testing.T) {
	d, err := Parse(npmData)
	if err != nil {
		t.Fatal(err)
	}
	if d.LastReviewed != "2026-11-06" || d.ReviewAfter != "2027-02-04" || len(d.Entries) != 20 {
		t.Fatalf("unexpected freshness/count: %+v", d)
	}
	if d.Owner != "cfgaudit maintainers" {
		t.Fatalf("dataset lost owner metadata: %+v", d)
	}
	if ioc, ok := MatchNPM("postmark-mcp", "1.0.16"); !ok || ioc.Campaign == "" {
		t.Fatalf("postmark IOC missing: %+v, %v", ioc, ok)
	}
	for _, pair := range [][2]string{{"postmark-mcp", "1.0.15"}, {"postmark-mcp-safe", "1.0.16"}, {"Postmark-MCP", "1.0.16"}, {"ethres", "1.0.0"}} {
		if _, ok := MatchNPM(pair[0], pair[1]); ok {
			t.Errorf("unexpected match for %s@%s", pair[0], pair[1])
		}
	}
}

func TestParseRejectsInvalidDatasets(t *testing.T) {
	valid := string(npmData)
	for name, data := range map[string]string{
		"json":         `{`,
		"schema":       strings.Replace(valid, `"schema_version": 1`, `"schema_version": 2`, 1),
		"review order": strings.Replace(valid, `"review_after": "2027-02-04"`, `"review_after": "2026-01-01"`, 1),
		"source":       strings.Replace(valid, `https://postmarkapp.com/`, `http://postmarkapp.com/`, 1),
		"uppercase":    strings.Replace(valid, `"package":"postmark-mcp"`, `"package":"Postmark-mcp"`, 1),
		"empty reason": strings.Replace(valid,
			`"reason":"Postmark confirmed this exact version added a backdoor that secretly copied sent email to an external recipient"`,
			`"reason":""`, 1),
		"duplicate IOC":  strings.Replace(valid, `"versions":["1.0.16"]`, `"versions":["1.0.16","1.0.16"]`, 1),
		"version range":  strings.Replace(valid, `"versions":["1.0.16"]`, `"versions":["^1.0.16"]`, 1),
		"bad date":       strings.Replace(valid, `"first_reviewed":"2026-11-06"`, `"first_reviewed":"yesterday"`, 1),
		"dataset date":   strings.Replace(valid, `"last_reviewed": "2026-11-06"`, `"last_reviewed": "yesterday"`, 1),
		"review date":    strings.Replace(valid, `"review_after": "2027-02-04"`, `"review_after": "later"`, 1),
		"entry last":     strings.Replace(valid, `"last_reviewed":"2026-11-06"`, `"last_reviewed":"yesterday"`, 1),
		"entry order":    strings.Replace(valid, `"last_reviewed":"2026-11-06"`, `"last_reviewed":"2025-11-06"`, 1),
		"versions order": strings.Replace(valid, `"versions":["1.0.16"]`, `"versions":["2.0.0","1.0.0"]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMustDatasetPanicsOnInvalidEmbeddedData(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustDataset did not panic")
		}
	}()
	_ = mustDataset([]byte(`{`))
}
