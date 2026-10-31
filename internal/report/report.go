// Package report prints scan results as text, JSON or SARIF.
// No output format ever contains a raw key.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Reetcodeio/zarpa/internal/item"
	"github.com/Reetcodeio/zarpa/internal/scan"
	"github.com/Reetcodeio/zarpa/internal/version"
	"github.com/Reetcodeio/zarpa/rules"
)

// TextOptions tune the human report.
type TextOptions struct {
	Color   bool
	Verbose bool // list every location
	// Compact drops the scan header and the -v hint (pre-commit hook, CI).
	Compact bool
	Now     time.Time
}

type palette struct{ bold, dim, red, yellow, cyan, reset string }

func colors(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{bold: "\x1b[1m", dim: "\x1b[2m", red: "\x1b[31m", yellow: "\x1b[33m", cyan: "\x1b[36m", reset: "\x1b[0m"}
}

// Text writes the human-readable report: leaks first, then keys that sit in
// a tool's own credential file, then keys only in other people's commits.
func Text(w io.Writer, res *scan.Result, opt TextOptions) {
	var leaks, stored, others []*scan.Finding
	for _, f := range res.Findings {
		switch f.Category {
		case scan.CategoryStored:
			stored = append(stored, f)
		case scan.CategoryOthers:
			others = append(others, f)
		default:
			leaks = append(leaks, f)
		}
	}
	view := *res
	view.Findings = leaks
	textMain(w, &view, opt, len(stored), len(others))
	c := colors(opt.Color)
	section(w, c, stored, opt, "Kept by tools in their own credential files",
		"Expected places. Rotate them if this Mac or a backup of it was exposed.")
	section(w, c, others, opt, "Only in commits by other people (repos you cloned)",
		"Not your keys, unless you shared them. Report them to the repo owner if they still work.")
	if !opt.Verbose && !opt.Compact && len(res.Findings) > 0 {
		fmt.Fprintf(w, "\n%sRun with -v for every location, or --json for machine-readable output.%s\n", c.dim, c.reset)
	}
}

func section(w io.Writer, c palette, fs []*scan.Finding, opt TextOptions, title, note string) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s%s (%d)%s · %s\n", c.bold, title, len(fs), c.reset, note)
	wp, wk := 0, 0
	for _, f := range fs {
		wp, wk = maxLen(wp, f.Provider), maxLen(wk, f.Display)
	}
	for _, f := range fs {
		where := f.Locations[0].Ref
		if n := len(f.Locations) - 1; n > 0 && !opt.Verbose {
			where += fmt.Sprintf("  +%d more", n)
		}
		st := ""
		if f.Liveness != "" {
			st = statusWord(f.Liveness) + "  "
		}
		fmt.Fprintf(w, "  %s  %s  %s%s\n", pad(f.Provider, wp), pad(f.Display, wk), st, where)
		if opt.Verbose {
			for _, l := range f.Locations[1:] {
				fmt.Fprintf(w, "  %s  %s%s%s\n", strings.Repeat(" ", wp+wk+2), c.dim, l.Ref, c.reset)
			}
		}
	}
}

func textMain(w io.Writer, res *scan.Result, opt TextOptions, nStored, nOthers int) {
	c := colors(opt.Color)
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	s := res.Stats
	dur := s.Duration.Round(time.Millisecond)
	if s.Duration >= 10*time.Second {
		dur = s.Duration.Round(100 * time.Millisecond)
	}
	if opt.Compact {
		fmt.Fprintf(w, "%sZarpa%s · checked %s %s\n", c.bold, c.reset, comma(int(s.Files)), plural(int(s.Files), "file", "files"))
	} else {
		fmt.Fprintf(w, "%sZarpa %s%s · scanned %s %s (%s, %d from AI tools, shell and dotfiles) · %d %s, %s %s · %s\n",
			c.bold, version.Version, c.reset,
			comma(int(s.Files)), plural(int(s.Files), "file", "files"), humanBytes(s.Bytes), s.MachineFiles,
			s.Repos, plural(s.Repos, "repo", "repos"), comma(s.Commits), plural(s.Commits, "commit", "commits"), dur)
	}
	for _, wmsg := range res.Warnings {
		fmt.Fprintf(w, "%s! %s%s\n", c.yellow, wmsg, c.reset)
	}
	if s.CloudOnly > 0 {
		fmt.Fprintf(w, "%s! skipped %d iCloud %s not downloaded to this Mac (scanning them would download them)%s\n",
			c.yellow, s.CloudOnly, plural(int(s.CloudOnly), "item", "items"), c.reset)
	}
	fmt.Fprintln(w)

	if len(res.Findings) == 0 {
		if nStored+nOthers > 0 {
			fmt.Fprintf(w, "No leaked keys found.\n")
		} else {
			fmt.Fprintf(w, "No keys found.\n")
		}
		return
	}

	var historyOnly, public, critical, inTranscripts, ignoredKeys int
	ignoredSeen := map[string]bool{}
	var ignoredNames []string
	for _, f := range res.Findings {
		if f.HistoryOnly {
			historyOnly++
		}
		if f.PublicExposure {
			public++
		}
		if f.Severity == rules.SeverityCritical {
			critical++
		}
		transcript, ignored := false, false
		for _, l := range f.Locations {
			if l.Kind == item.KindTranscript || l.Kind == item.KindShell {
				transcript = true
			}
			if l.GitIgnored && l.Kind != item.KindGit {
				ignored = true
				if name := refFile(l.Ref); !ignoredSeen[name] {
					ignoredSeen[name] = true
					ignoredNames = append(ignoredNames, name)
				}
			}
		}
		if transcript {
			inTranscripts++
		}
		if ignored {
			ignoredKeys++
		}
	}

	parts := []string{fmt.Sprintf("%s%d leaked %s found%s", c.bold, len(res.Findings), plural(len(res.Findings), "key", "keys"), c.reset)}
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("%s%d critical%s", c.red, critical, c.reset))
	}
	if historyOnly > 0 {
		parts = append(parts, fmt.Sprintf("%d only in git history", historyOnly))
	}
	if public > 0 {
		parts = append(parts, fmt.Sprintf("%s%d will ship to the browser%s", c.red, public, c.reset))
	}
	if n := countLive(res.Findings); n > 0 {
		parts = append(parts, fmt.Sprintf("%s%d still %s%s", c.red, n, plural(n, "works", "work"), c.reset))
	}
	if nStored+nOthers > 0 {
		parts = append(parts, fmt.Sprintf("%s+%d listed separately below%s", c.dim, nStored+nOthers, c.reset))
	}
	fmt.Fprintln(w, strings.Join(parts, " · "))
	fmt.Fprintln(w)

	// Table.
	hasStatus := false
	for _, f := range res.Findings {
		if f.Liveness != "" {
			hasStatus = true
		}
	}
	type row struct{ sev, prov, key, status, age, where string }
	rows := []row{{"SEVERITY", "PROVIDER", "KEY", "STATUS", "AGE", "WHERE"}}
	for _, f := range res.Findings {
		where := f.Locations[0].Ref
		if n := len(f.Locations) - 1; n > 0 && !opt.Verbose {
			where += fmt.Sprintf("  +%d more", n)
		}
		rows = append(rows, row{f.Severity, f.Provider, f.Display, statusWord(f.Liveness), age(f.FirstSeen, opt.Now), where})
	}
	wSev, wProv, wKey, wAge, wStat := 0, 0, 0, 0, 0
	for _, r := range rows {
		wSev, wProv = maxLen(wSev, r.sev), maxLen(wProv, r.prov)
		wKey, wAge = maxLen(wKey, r.key), maxLen(wAge, r.age)
		wStat = maxLen(wStat, r.status)
	}
	statusCol := func(r row, i int) string {
		if !hasStatus {
			return ""
		}
		cell := pad(r.status, wStat) + "  "
		if i > 0 && r.status == statusWord("live") {
			return c.red + cell + c.reset
		}
		return cell
	}
	extra := 0
	if hasStatus {
		extra = wStat + 2
	}
	indent := strings.Repeat(" ", wSev+wProv+wKey+wAge+10+extra)
	for i, r := range rows {
		sevColor, end := "", ""
		switch {
		case i == 0:
			sevColor, end = c.dim, c.reset
		case r.sev == rules.SeverityCritical:
			sevColor, end = c.red, c.reset
		case r.sev == rules.SeverityHigh:
			sevColor, end = c.yellow, c.reset
		}
		fmt.Fprintf(w, "  %s%s%s  %s  %s  %s%s  %s\n",
			sevColor, pad(r.sev, wSev), end, pad(r.prov, wProv), pad(r.key, wKey), statusCol(r, i), pad(r.age, wAge), r.where)
		if opt.Verbose && i > 0 {
			for _, l := range res.Findings[i-1].Locations[1:] {
				fmt.Fprintf(w, "%s%s%s%s\n", indent, c.dim, l.Ref, c.reset)
			}
		}
	}
	fmt.Fprintln(w)

	// Why a check came out as it did, when the provider told us.
	if hasStatus {
		var notes []row
		for _, f := range res.Findings {
			if f.LiveDetail != "" && f.Liveness != "unsupported" && f.Liveness != "not_checked" {
				notes = append(notes, row{prov: f.Provider, key: f.Display, status: statusWord(f.Liveness), where: f.LiveDetail})
			}
		}
		if len(notes) > 0 {
			fmt.Fprintf(w, "%sCheck details%s\n", c.dim, c.reset)
			for _, n := range notes {
				fmt.Fprintf(w, "  %s  %s  %s  %s\n", pad(n.prov, wProv), pad(n.key, wKey), pad(n.status, wStat), n.where)
			}
			fmt.Fprintln(w)
		}
	}

	// Callouts, most urgent first.
	for _, f := range res.Findings {
		if !f.PublicExposure {
			continue
		}
		for _, l := range f.Locations {
			if l.PublicExposure {
				fmt.Fprintf(w, "%s⚠ %s will ship to the browser:%s %s is a public env var (%s)\n",
					c.red, f.Display, c.reset, l.VarName, l.Ref)
				break
			}
		}
	}
	if historyOnly > 0 {
		fmt.Fprintf(w, "%s•%s %d %s only in git history. Deleting the file did not remove %s; revoke and rotate.\n",
			c.cyan, c.reset, historyOnly, plural(historyOnly, "key exists", "keys exist"), plural(historyOnly, "it", "them"))
	}
	if ignoredKeys > 0 {
		sort.Strings(ignoredNames)
		if len(ignoredNames) > 3 {
			ignoredNames = append(ignoredNames[:3], fmt.Sprintf("%d more", len(ignoredNames)-3))
		}
		fmt.Fprintf(w, "%s•%s %d %s in git-ignored files (%s). Ignored files still get copied, synced and backed up.\n",
			c.cyan, c.reset, ignoredKeys, plural(ignoredKeys, "key sits", "keys sit"), strings.Join(ignoredNames, ", "))
	}
	if inTranscripts > 0 {
		fmt.Fprintf(w, "%s•%s %d %s in AI tool transcripts or shell history, in plain text.\n",
			c.cyan, c.reset, inTranscripts, plural(inTranscripts, "key appears", "keys appear"))
	}
}

// JSON writes the full result as indented JSON.
func JSON(w io.Writer, res *scan.Result) error {
	out := struct {
		Tool    string `json:"tool"`
		Version string `json:"version"`
		*scan.Result
	}{"zarpa", version.Version, res}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// SARIF writes a SARIF 2.1.0 log, suitable for code-scanning dashboards.
// baseDir makes file URIs relative where possible.
func SARIF(w io.Writer, res *scan.Result, set *rules.Set, baseDir string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type region struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn,omitempty"`
	}
	type artifact struct {
		URI string `json:"uri"`
	}
	type physical struct {
		ArtifactLocation artifact `json:"artifactLocation"`
		Region           *region  `json:"region,omitempty"`
	}
	type location struct {
		Physical physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties,omitempty"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		Properties       map[string]any `json:"properties"`
	}

	used := map[string]bool{}
	results := []result{}
	for _, f := range res.Findings {
		used[f.RuleID] = true
		for _, l := range f.Locations {
			uri := sarifURI(l, baseDir)
			if uri == "" {
				continue
			}
			props := map[string]any{"kind": l.Kind, "ref": l.Ref}
			if l.Commit != "" {
				props["commit"] = l.Commit
			}
			results = append(results, result{
				RuleID:              f.RuleID,
				Level:               sarifLevel(f.Severity),
				Message:             msg{fmt.Sprintf("%s %s found (%s)", f.Name, f.Display, l.Kind)},
				Locations:           []location{{physical{artifact{uri}, &region{StartLine: max1(l.Line), StartColumn: l.Column}}}},
				PartialFingerprints: map[string]string{"zarpa/v1": f.Fingerprint},
				Properties:          props,
			})
		}
	}
	rs := []rule{}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := set.ByID(id)
		if r == nil {
			continue
		}
		rs = append(rs, rule{ID: r.ID, Name: r.Name, ShortDescription: msg{r.Name},
			Properties: map[string]any{"provider": r.Provider, "severity": r.Severity, "tags": []string{"security", "secret"}}})
	}
	log := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "zarpa", "version": version.Version, "rules": rs,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifURI(l scan.Location, baseDir string) string {
	if l.Kind == item.KindGit {
		return filepath.ToSlash(l.Path)
	}
	p := l.OSPath()
	if p == "" {
		return ""
	}
	if baseDir != "" {
		if r, err := filepath.Rel(baseDir, p); err == nil && !strings.HasPrefix(r, "..") {
			return filepath.ToSlash(r)
		}
	}
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows: file:///C:/Users/...
	}
	return "file://" + p
}

func sarifLevel(sev string) string {
	switch sev {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	}
	return "note"
}

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func age(t, now time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < 24*time.Hour:
		return "today"
	case d < 60*24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d < 730*24*time.Hour:
		return fmt.Sprintf("%dmo", int(d.Hours()/24/30))
	}
	return fmt.Sprintf("%dy", int(d.Hours()/24/365))
}

// statusWord is the STATUS column text for a liveness result.
func statusWord(l string) string {
	switch l {
	case "live":
		return "WORKS"
	case "revoked":
		return "dead"
	case "unknown":
		return "?"
	case "":
		return ""
	}
	return "-" // unsupported or not checked
}

func countLive(fs []*scan.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Liveness == "live" {
			n++
		}
	}
	return n
}

// refFile strips the kind prefix and line from a ref:
// "repo:web:.env:2" -> "web/.env", "file:~/x/.env:3" -> "~/x/.env".
func refFile(ref string) string {
	parts := strings.Split(ref, ":")
	if len(parts) < 3 {
		return ref
	}
	parts = parts[:len(parts)-1]
	if parts[0] == "repo" {
		return parts[1] + "/" + strings.Join(parts[2:], ":")
	}
	return strings.Join(parts[1:], ":")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

func pad(s string, w int) string {
	n := len([]rune(s))
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

func maxLen(cur int, s string) int {
	if n := len([]rune(s)); n > cur {
		return n
	}
	return cur
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
