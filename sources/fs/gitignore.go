package fs

import (
	"bufio"
	"os"
	"path"
	"regexp"
	"strings"
)

// ignoreRule is one compiled .gitignore line.
type ignoreRule struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

// ignoreFile holds the rules of one .gitignore, relative to its directory.
type ignoreFile struct {
	base  string // slash path of the directory, relative to the repo root ("" = root)
	rules []ignoreRule
}

// parseIgnore compiles gitignore text. base is the file's directory relative
// to the repo root, with forward slashes.
func parseIgnore(base, text string) *ignoreFile {
	f := &ignoreFile{base: base}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if r, ok := compileIgnoreLine(sc.Text()); ok {
			f.rules = append(f.rules, r)
		}
	}
	return f
}

func loadIgnoreFile(osPath, base string) *ignoreFile {
	b, err := os.ReadFile(osPath)
	if err != nil {
		return nil
	}
	f := parseIgnore(base, string(b))
	if len(f.rules) == 0 {
		return nil
	}
	return f
}

func compileIgnoreLine(line string) (ignoreRule, bool) {
	line = strings.TrimRight(line, "\r")
	// Trailing spaces are ignored unless escaped.
	for strings.HasSuffix(line, " ") && !strings.HasSuffix(line, `\ `) {
		line = line[:len(line)-1]
	}
	if line == "" || strings.HasPrefix(line, "#") {
		return ignoreRule{}, false
	}
	var r ignoreRule
	if strings.HasPrefix(line, "!") {
		r.negate = true
		line = line[1:]
	} else if strings.HasPrefix(line, `\!`) || strings.HasPrefix(line, `\#`) {
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly = true
		line = strings.TrimRight(line, "/")
	}
	if line == "" {
		return ignoreRule{}, false
	}
	anchored := strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")

	var b strings.Builder
	if anchored {
		b.WriteString("^")
	} else {
		b.WriteString("(?:^|/)")
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '*':
			if i+1 < len(line) && line[i+1] == '*' {
				// "**/" = zero or more directories; trailing "/**" = everything inside.
				atStart := i == 0 || line[i-1] == '/'
				if atStart && i+2 < len(line) && line[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
					continue
				}
				if atStart && i+2 == len(line) {
					b.WriteString(".*")
					i++
					continue
				}
				b.WriteString("[^/]*")
				i++
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '[':
			j := i + 1
			if j < len(line) && (line[j] == '!' || line[j] == '^') {
				j++
			}
			if j < len(line) && line[j] == ']' {
				j++
			}
			for j < len(line) && line[j] != ']' {
				j++
			}
			if j >= len(line) {
				b.WriteString(`\[`)
				continue
			}
			class := line[i+1 : j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i = j
		case '\\':
			if i+1 < len(line) {
				i++
				b.WriteString(regexp.QuoteMeta(string(line[i])))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return ignoreRule{}, false
	}
	r.re = re
	return r, true
}

// ignoreStack evaluates .gitignore files from the repo root down.
type ignoreStack []*ignoreFile

// ignored reports whether rel (slash path relative to the repo root) is ignored.
// Later files and later lines win, as in git.
func (st ignoreStack) ignored(rel string, isDir bool) bool {
	ignored := false
	for _, f := range st {
		sub := rel
		if f.base != "" {
			if !strings.HasPrefix(rel, f.base+"/") {
				continue
			}
			sub = rel[len(f.base)+1:]
		}
		for _, r := range f.rules {
			if r.dirOnly && !isDir {
				continue
			}
			if r.re.MatchString(sub) {
				ignored = !r.negate
			}
		}
	}
	return ignored
}

// alwaysFlag reports files Zarpa scans even when git ignores them,
// because ignored env files are where forgotten keys live.
func alwaysFlag(name string) bool {
	n := strings.ToLower(name)
	switch {
	case n == ".env", strings.HasPrefix(n, ".env."), strings.HasSuffix(n, ".env"),
		n == ".envrc", n == ".dev.vars", n == ".npmrc", n == ".pypirc", n == ".netrc":
		return true
	}
	return isMCPConfigName(n)
}

// isMCPConfigName recognises project-level MCP and editor config files.
func isMCPConfigName(lowerName string) bool {
	switch lowerName {
	case ".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json":
		return true
	}
	return false
}

func slashJoin(a, b string) string {
	if a == "" {
		return b
	}
	return path.Join(a, b)
}
