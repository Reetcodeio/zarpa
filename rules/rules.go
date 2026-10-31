// Package rules loads and compiles Zarpa's versioned detection rules.
//
// The default rule set is embedded from rules.json so the binary works
// offline. A custom file can be loaded with LoadFile for testing new rules.
package rules

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

//go:embed rules.json
var embedded []byte

// Severity levels, from most to least urgent.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Rank orders severities: a higher number is more urgent.
func Rank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// Rule is one detection rule.
type Rule struct {
	ID          string   `json:"id"`
	Provider    string   `json:"provider"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Regex       string   `json:"regex"`
	SecretGroup int      `json:"secretGroup"`
	Keywords    []string `json:"keywords"`
	// CaseInsensitiveKeywords makes the keyword prefilter ignore case.
	CaseInsensitiveKeywords bool `json:"caseInsensitiveKeywords"`
	// PrefixLen is how many leading characters are safe to print
	// (the provider's fixed prefix, never random key material).
	PrefixLen  int     `json:"prefixLen"`
	Priority   int     `json:"priority"`
	EntropyMin float64 `json:"entropyMin"`
	Validate   string  `json:"validate"`
	Generic    bool    `json:"generic"`
	// Multiline rules run on the whole buffer; others only on keyword lines.
	Multiline bool `json:"multiline"`
	// SkipInTests turns the rule off in test files and fixtures, where
	// generated vectors and throwaway keys are normal.
	SkipInTests bool   `json:"skipInTests"`
	Description string `json:"description"`

	re           *regexp.Regexp
	lowerKeyword [][]byte
	keyword      [][]byte
}

// Re returns the compiled regular expression.
func (r *Rule) Re() *regexp.Regexp { return r.re }

// SearchKeywords returns the prefilter keywords: lowercase when the rule is
// case-insensitive (to search the lowercased buffer).
func (r *Rule) SearchKeywords() (kws [][]byte, lower bool) {
	if r.CaseInsensitiveKeywords {
		return r.lowerKeyword, true
	}
	return r.keyword, false
}

// KeywordHit reports whether content (and its lowercase copy) contains any
// of the rule's keywords. Rules without keywords always pass.
func (r *Rule) KeywordHit(content, lower []byte) bool {
	if len(r.keyword) == 0 {
		return true
	}
	if r.CaseInsensitiveKeywords {
		for _, k := range r.lowerKeyword {
			if containsBytes(lower, k) {
				return true
			}
		}
		return false
	}
	for _, k := range r.keyword {
		if containsBytes(content, k) {
			return true
		}
	}
	return false
}

// Allowlist holds values and markers that are never reported.
type Allowlist struct {
	ValueSubstrings []string `json:"valueSubstrings"`
	ValueRegexes    []string `json:"valueRegexes"`
	LineMarkers     []string `json:"lineMarkers"`

	lowerSubstrings []string
	res             []*regexp.Regexp
}

// AllowsValue reports whether a candidate secret is a known dummy value.
func (a *Allowlist) AllowsValue(v string) bool {
	lv := strings.ToLower(v)
	for _, s := range a.lowerSubstrings {
		if strings.Contains(lv, s) {
			return true
		}
	}
	for _, re := range a.res {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// AllowsLine reports whether a line carries an inline allow marker.
func (a *Allowlist) AllowsLine(line string) bool {
	for _, m := range a.LineMarkers {
		if strings.Contains(line, m) {
			return true
		}
	}
	return false
}

// Set is a compiled rule set.
type Set struct {
	Version   string    `json:"version"`
	Rules     []*Rule   `json:"rules"`
	Allowlist Allowlist `json:"allowlist"`

	byID map[string]*Rule
}

// ByID returns the rule with the given id, or nil.
func (s *Set) ByID(id string) *Rule { return s.byID[id] }

// Load returns the embedded default rule set.
func Load() (*Set, error) { return Parse(embedded) }

// LoadFile loads a rule set from a JSON file on disk.
func LoadFile(path string) (*Set, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and compiles a rule set.
func Parse(b []byte) (*Set, error) {
	var s Set
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	s.byID = make(map[string]*Rule, len(s.Rules))
	for _, r := range s.Rules {
		if r.ID == "" || r.Regex == "" {
			return nil, fmt.Errorf("rules: rule missing id or regex")
		}
		if _, dup := s.byID[r.ID]; dup {
			return nil, fmt.Errorf("rules: duplicate id %q", r.ID)
		}
		if Rank(r.Severity) == 0 {
			return nil, fmt.Errorf("rules: %s: unknown severity %q", r.ID, r.Severity)
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("rules: %s: %w", r.ID, err)
		}
		if r.SecretGroup > re.NumSubexp() {
			return nil, fmt.Errorf("rules: %s: secretGroup %d but regex has %d groups", r.ID, r.SecretGroup, re.NumSubexp())
		}
		if r.Validate != "" && !knownValidator(r.Validate) {
			return nil, fmt.Errorf("rules: %s: unknown validator %q", r.ID, r.Validate)
		}
		r.re = re
		for _, k := range r.Keywords {
			r.keyword = append(r.keyword, []byte(k))
			r.lowerKeyword = append(r.lowerKeyword, []byte(strings.ToLower(k)))
		}
		s.byID[r.ID] = r
	}
	// Higher priority first, so overlapping matches go to the most specific rule.
	sort.SliceStable(s.Rules, func(i, j int) bool { return s.Rules[i].Priority > s.Rules[j].Priority })

	for _, v := range s.Allowlist.ValueSubstrings {
		s.Allowlist.lowerSubstrings = append(s.Allowlist.lowerSubstrings, strings.ToLower(v))
	}
	for _, v := range s.Allowlist.ValueRegexes {
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, fmt.Errorf("rules: allowlist regex %q: %w", v, err)
		}
		s.Allowlist.res = append(s.Allowlist.res, re)
	}
	return &s, nil
}

func knownValidator(name string) bool {
	switch name {
	case "jwt-service-role":
		return true
	}
	return false
}

func containsBytes(haystack, needle []byte) bool {
	return bytes.Contains(haystack, needle)
}
