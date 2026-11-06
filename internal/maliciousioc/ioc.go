// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package maliciousioc owns the reviewed, offline indicators for package
// artifacts confirmed malicious by primary or vendor threat research.
package maliciousioc

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed npm.json
var npmData []byte

type Dataset struct {
	SchemaVersion int      `json:"schema_version"`
	Owner         string   `json:"owner"`
	LastReviewed  string   `json:"last_reviewed"`
	ReviewAfter   string   `json:"review_after"`
	Entries       []NPMIOC `json:"entries"`
}

type NPMIOC struct {
	Ecosystem     string   `json:"ecosystem"`
	Package       string   `json:"package"`
	Versions      []string `json:"versions"`
	Campaign      string   `json:"campaign"`
	Source        string   `json:"source"`
	FirstReviewed string   `json:"first_reviewed"`
	LastReviewed  string   `json:"last_reviewed"`
	Type          string   `json:"type"`
	Reason        string   `json:"reason"`
	RemovalPolicy string   `json:"removal_policy"`
}

var reviewed = mustDataset(npmData)

var exactVersionRe = regexp.MustCompile(`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$`)

func mustDataset(data []byte) Dataset {
	d, err := Parse(data)
	if err != nil {
		panic("invalid embedded malicious IOC data: " + err.Error())
	}
	return d
}

// Parse validates a serialized IOC data set. Validation is deliberately strict
// so a data-only update cannot silently broaden exact matching.
func Parse(data []byte) (Dataset, error) {
	var d Dataset
	if err := json.Unmarshal(data, &d); err != nil {
		return Dataset{}, err
	}
	if d.SchemaVersion != 1 || d.Owner == "" {
		return Dataset{}, errors.New("schema_version must be 1 and owner must be set")
	}
	last, err := parseDate("last_reviewed", d.LastReviewed)
	if err != nil {
		return Dataset{}, err
	}
	review, err := parseDate("review_after", d.ReviewAfter)
	if err != nil {
		return Dataset{}, err
	}
	if !review.After(last) {
		return Dataset{}, errors.New("review_after must be after last_reviewed")
	}
	seen := map[string]bool{}
	previous := ""
	for i, entry := range d.Entries {
		if entry.Ecosystem != "npm" || entry.Package == "" || entry.Campaign == "" || entry.Type != "malicious-version" ||
			entry.Reason == "" || entry.RemovalPolicy == "" || len(entry.Versions) == 0 {
			return Dataset{}, fmt.Errorf("entries[%d] lacks required exact-package IOC metadata", i)
		}
		if entry.Package != strings.ToLower(entry.Package) || (previous != "" && entry.Package < previous) {
			return Dataset{}, fmt.Errorf("entries[%d] package %q is not lowercase sorted", i, entry.Package)
		}
		previous = entry.Package
		u, err := url.Parse(entry.Source)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return Dataset{}, fmt.Errorf("entries[%d] source must be an https URL", i)
		}
		first, err := parseDate("first_reviewed", entry.FirstReviewed)
		if err != nil {
			return Dataset{}, fmt.Errorf("entries[%d]: %w", i, err)
		}
		entryLast, err := parseDate("last_reviewed", entry.LastReviewed)
		if err != nil {
			return Dataset{}, fmt.Errorf("entries[%d]: %w", i, err)
		}
		if entryLast.Before(first) || entryLast.After(last) {
			return Dataset{}, fmt.Errorf("entries[%d] review dates are outside the dataset review window", i)
		}
		if !sort.StringsAreSorted(entry.Versions) {
			return Dataset{}, fmt.Errorf("entries[%d] versions are not sorted", i)
		}
		for _, version := range entry.Versions {
			key := entry.Package + "@" + version
			if !exactVersionRe.MatchString(version) || seen[key] {
				return Dataset{}, fmt.Errorf("IOC %q has a non-exact version or is duplicated", key)
			}
			seen[key] = true
		}
	}
	return d, nil
}

func parseDate(field, value string) (time.Time, error) {
	d, err := time.Parse(time.DateOnly, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be YYYY-MM-DD: %w", field, err)
	}
	return d, nil
}

// MatchNPM returns the metadata for an exact package/version pair.
func MatchNPM(name, version string) (NPMIOC, bool) {
	for _, entry := range reviewed.Entries {
		if name != entry.Package {
			continue
		}
		for _, affected := range entry.Versions {
			if version == affected {
				return entry, true
			}
		}
	}
	return NPMIOC{}, false
}
