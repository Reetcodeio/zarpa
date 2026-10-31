// Package detect finds candidate secrets in a byte buffer.
//
// The pipeline per buffer is:
//  1. keyword prefilter per rule (cheap substring test),
//  2. provider regexes, most specific rule first,
//  3. the generic entropy-plus-context rule, only where no provider rule matched,
//  4. validators (for example, JWT role checks) and the allowlist.
package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/Reetcodeio/zarpa/rules"
)

// Match is one secret found in a buffer.
type Match struct {
	Rule      *rules.Rule
	Secret    string
	Start     int // byte offset of the secret in the buffer
	End       int
	Line      int // 1-based line number within the buffer
	Column    int // 1-based byte column
	VarName   string
	PublicVar bool // VarName uses a prefix that frameworks ship to the browser
}

// Options tune one Scan call.
type Options struct {
	// SkipGeneric disables the entropy rule (used for lockfiles and similar).
	SkipGeneric bool
	// TestPath turns off rules marked skipInTests (see IsTestPath).
	TestPath bool
}

// Engine runs a compiled rule set over buffers. It is safe for concurrent use.
type Engine struct {
	set *rules.Set
}

// New returns an engine for the given rule set.
func New(set *rules.Set) *Engine { return &Engine{set: set} }

// Rules returns the engine's rule set.
func (e *Engine) Rules() *rules.Set { return e.set }

// PublicPrefixes are env var prefixes that common frameworks inline into
// client-side bundles. A secret behind one of these will ship to the browser.
var PublicPrefixes = []string{
	"VITE_", "NEXT_PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_",
	"PUBLIC_", "GATSBY_", "VUE_APP_", "STORYBOOK_",
}

var varBeforeRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*(?::=|=>|=|:)\s*["'` + "`" + `]?$`)

type span struct{ s, e int }

// Scan returns every non-allowlisted match in content, ordered by position.
func (e *Engine) Scan(content []byte, opt Options) []Match {
	if len(content) == 0 {
		return nil
	}
	lower := asciiLower(content)
	var (
		out   []Match
		taken []span
		lines []int // lazily computed line start offsets
	)
	overlaps := func(s, en int) bool {
		for _, t := range taken {
			if s < t.e && t.s < en {
				return true
			}
		}
		return false
	}
	lineOf := func(off int) (line, lineStart, lineEnd int) {
		if lines == nil {
			lines = append(lines, 0)
			for i, b := range content {
				if b == '\n' {
					lines = append(lines, i+1)
				}
			}
		}
		idx := sort.Search(len(lines), func(i int) bool { return lines[i] > off }) - 1
		lineStart = lines[idx]
		lineEnd = len(content)
		if idx+1 < len(lines) {
			lineEnd = lines[idx+1] - 1
		}
		return idx + 1, lineStart, lineEnd
	}

	for _, r := range e.set.Rules {
		if r.Generic && opt.SkipGeneric {
			continue
		}
		if r.SkipInTests && opt.TestPath {
			continue
		}
		var found [][]int
		if r.Multiline {
			if !r.KeywordHit(content, lower) {
				continue
			}
			found = r.Re().FindAllSubmatchIndex(content, -1)
		} else {
			// The window search doubles as the keyword prefilter.
			found = findInWindows(r, content, lower)
		}
		for _, m := range found {
			g := r.SecretGroup
			s, en := m[2*g], m[2*g+1]
			if s < 0 || en <= s {
				continue
			}
			if r.Generic {
				// Trim punctuation a sentence or a config line may glue on.
				for en > s && strings.ContainsRune(".,;", rune(content[en-1])) {
					en--
				}
			}
			if overlaps(s, en) {
				continue
			}
			secret := string(content[s:en])
			if !validate(r, secret) {
				continue
			}
			if e.set.Allowlist.AllowsValue(secret) {
				continue
			}
			if r.EntropyMin > 0 && !looksRandom(secret, r.EntropyMin) {
				continue
			}
			line, ls, le := lineOf(s)
			if r.Generic && le-ls > maxGenericLine {
				continue // minified code and data blobs: entropy is meaningless there
			}
			lineText := string(content[ls:le])
			if e.set.Allowlist.AllowsLine(lineText) {
				continue
			}
			var varName string
			if r.Generic && len(m) > 3 && m[2] >= 0 {
				varName = string(content[m[2]:m[3]])
			} else if sm := varBeforeRe.FindStringSubmatch(string(content[ls:s])); sm != nil {
				varName = sm[1]
			}
			taken = append(taken, span{s, en})
			out = append(out, Match{
				Rule:      r,
				Secret:    secret,
				Start:     s,
				End:       en,
				Line:      line,
				Column:    s - ls + 1,
				VarName:   varName,
				PublicVar: IsPublicVar(varName),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// maxGenericLine is the longest line the entropy rule trusts.
const maxGenericLine = 1000

// asciiLower lowercases A-Z only. Unlike bytes.ToLower it never changes the
// length (bytes.ToLower rewrites invalid UTF-8 and some runes with different
// byte counts), so offsets found in the copy are valid in the original.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// Window bounds for keyword lines. Very long lines (minified code) are cut
// to a window around the keyword so a 2 MB line costs a few KB of regex.
const (
	windowBefore = 512
	windowAfter  = 4096
)

// findInWindows runs a line rule only on the lines that contain one of its
// keywords. Returned indices are absolute offsets into content.
func findInWindows(r *rules.Rule, content, lower []byte) [][]int {
	kws, useLower := r.SearchKeywords()
	hay := content
	if useLower {
		hay = lower
	}
	type win struct{ s, e int }
	var wins []win
	for _, kw := range kws {
		for off := 0; off < len(hay); {
			i := bytes.Index(hay[off:], kw)
			if i < 0 {
				break
			}
			hit := off + i
			ls := bytes.LastIndexByte(content[:hit], '\n') + 1
			le := bytes.IndexByte(content[hit:], '\n')
			if le < 0 {
				le = len(content)
			} else {
				le += hit
			}
			if hit-ls > windowBefore {
				ls = hit - windowBefore
			}
			if le-hit > windowAfter {
				le = hit + windowAfter
			}
			if ls < 0 || le > len(content) || ls > le {
				break // cannot happen with asciiLower; never index out of range
			}
			wins = append(wins, win{ls, le})
			off = le
			if off <= hit {
				off = hit + len(kw)
			}
		}
	}
	if len(wins) == 0 {
		return nil
	}
	sort.Slice(wins, func(i, j int) bool { return wins[i].s < wins[j].s })
	// Merge overlapping windows (several keywords on one line).
	merged := wins[:1]
	for _, w := range wins[1:] {
		last := &merged[len(merged)-1]
		if w.s <= last.e {
			if w.e > last.e {
				last.e = w.e
			}
			continue
		}
		merged = append(merged, w)
	}
	var out [][]int
	re := r.Re()
	for _, w := range merged {
		for _, m := range re.FindAllSubmatchIndex(content[w.s:w.e], -1) {
			for k := range m {
				if m[k] >= 0 {
					m[k] += w.s
				}
			}
			out = append(out, m)
		}
	}
	return out
}

// IsTestPath reports paths that hold tests, fixtures, docs or examples.
// Provider keys are still reported there (a real key in a README is a real
// leak); only rules marked skipInTests (entropy, PEM) are turned off.
func IsTestPath(p string) bool {
	l := "/" + strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	for _, d := range []string{"/test/", "/tests/", "/testdata/", "/__tests__/", "/fixtures/",
		"/__fixtures__/", "/mocks/", "/__mocks__/", "/spec/", "/testing/", "/test-data/", "/testfixtures/",
		"/docs/", "/doc/", "/examples/", "/example/", "/samples/", "/sample/"} {
		if strings.Contains(l, d) {
			return true
		}
	}
	base := l[strings.LastIndexByte(l, '/')+1:]
	for _, suf := range []string{"_test.go", "_test.py", "_spec.rb", "_test.rb", "test.java", "tests.cs", "test.kt", "_test.dart"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	if strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") || base == "conftest.py" {
		return true
	}
	for _, mid := range []string{".test.", ".spec.", ".stories.", ".fixture.", "example", "sample", "template", "swagger", "openapi"} {
		if strings.Contains(base, mid) {
			return true
		}
	}
	for _, ext := range []string{".md", ".mdx", ".rst", ".adoc", ".d.ts", ".html"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// IsPublicVar reports whether an env var name uses a browser-bound prefix.
func IsPublicVar(name string) bool {
	if name == "" {
		return false
	}
	// Handle "import.meta.env.VITE_X" and "process.env.NEXT_PUBLIC_X".
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	up := strings.ToUpper(name)
	for _, p := range PublicPrefixes {
		if strings.HasPrefix(up, p) {
			return true
		}
	}
	return false
}

// Entropy returns the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, 64)
	n := 0
	for _, c := range s {
		freq[c]++
		n++
	}
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

var dottedIdentRe = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:[.\-][A-Za-z_$][A-Za-z0-9_$]*)+$`)

// looksRandom applies the checks that keep the generic rule quiet on code:
// enough entropy, a mix of letters and digits, and not an identifier path.
func looksRandom(s string, minEntropy float64) bool {
	if Entropy(s) < minEntropy {
		return false
	}
	var letters, digits int
	for _, c := range s {
		switch {
		case unicode.IsDigit(c):
			digits++
		case unicode.IsLetter(c):
			letters++
		}
	}
	if letters == 0 || digits == 0 {
		return false
	}
	if dottedIdentRe.MatchString(s) {
		return false
	}
	// Eight lowercase letters in a row read as a word ("parameters"), which
	// random key material almost never contains (about 3% of 32-char base62).
	if lowerRunRe.MatchString(s) || uuidRe.MatchString(s) {
		return false // a word, or an id rather than a secret
	}
	if identRe.MatchString(s) {
		// A plain identifier that spells a code word ("testRSA2048PrivateKey",
		// "defaultClientToken1") is a variable name, not key material.
		l := strings.ToLower(s)
		for _, w := range codeWords {
			if strings.Contains(l, w) {
				return false
			}
		}
	}
	return true
}

var (
	identRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	lowerRunRe = regexp.MustCompile(`[a-z]{8}`)
	uuidRe     = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

var codeWords = []string{"key", "token", "secret", "passw", "test", "private", "public", "config",
	"cert", "example", "value", "default", "client", "server", "handler", "string", "auth", "access"}

func validate(r *rules.Rule, secret string) bool {
	switch r.Validate {
	case "":
		return true
	case "jwt-service-role":
		return jwtRole(secret) == "service_role"
	}
	return false
}

func jwtRole(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Role
}
