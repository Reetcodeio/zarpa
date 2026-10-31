// Package scan wires sources, the detection engine and fingerprinting
// together and merges every sighting of the same key into one finding.
package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Reetcodeio/zarpa/internal/detect"
	"github.com/Reetcodeio/zarpa/internal/fingerprint"
	"github.com/Reetcodeio/zarpa/internal/item"
	"github.com/Reetcodeio/zarpa/rules"
	kfs "github.com/Reetcodeio/zarpa/sources/fs"
	"github.com/Reetcodeio/zarpa/sources/gitsrc"
	"github.com/Reetcodeio/zarpa/sources/machine"
)

// Progress is updated while a scan runs so a caller can show it live.
type Progress struct {
	Files   atomic.Int64
	Commits atomic.Int64

	mu        sync.Mutex
	stage     string
	current   string
	currentAt time.Time
}

func (p *Progress) setStage(s string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stage = s
	p.current, p.currentAt = "", time.Time{}
	p.mu.Unlock()
}

func (p *Progress) setCurrent(f string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.current, p.currentAt = f, time.Now()
	p.mu.Unlock()
}

// Snapshot returns the current stage, the file most recently started and
// how long ago it started.
func (p *Progress) Snapshot() (stage, current string, since time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.currentAt.IsZero() {
		since = time.Since(p.currentAt)
	}
	return p.stage, p.current, since
}

// Config controls one scan.
type Config struct {
	Paths       []string // folders or files to walk
	Home        string
	GOOS        string
	AppData     string
	Git         bool // scan git history of repos found under Paths
	Machine     bool // scan MCP configs, AI transcripts, shell history, dotfiles
	Workers     int
	MaxFileSize int64
	MaxCommits  int
	MinSeverity string
	Rules       *rules.Set
	Hasher      *fingerprint.Hasher
	Progress    *Progress // optional
	// Bundle treats Paths as built frontend output (see fs.Options.Bundle).
	Bundle bool
	// Staged scans only what is staged in the repos containing Paths.
	Staged bool
	// KeepSecrets keeps raw keys in memory (never serialised) for liveness checks.
	KeepSecrets bool
}

// Location is one place a key was seen.
type Location struct {
	Kind           string     `json:"kind"`
	Ref            string     `json:"ref"`
	Line           int        `json:"line,omitempty"`
	Column         int        `json:"column,omitempty"`
	Path           string     `json:"path,omitempty"`
	Repo           string     `json:"repo,omitempty"`
	Tool           string     `json:"tool,omitempty"`
	Commit         string     `json:"commit,omitempty"`
	CommittedAt    *time.Time `json:"committed_at,omitempty"`
	Commits        int        `json:"commits,omitempty"`
	VarName        string     `json:"var,omitempty"`
	GitIgnored     bool       `json:"git_ignored,omitempty"`
	PublicExposure bool       `json:"public_exposure,omitempty"`
	// Expected marks a tool's own credential store (~/.ssh, CLI login files).
	Expected bool `json:"expected_store,omitempty"`
	// ByOther marks git history written by someone else (cloned repos).
	ByOther bool `json:"by_other,omitempty"`

	osPath string // absolute path for files; never serialised
}

// OSPath returns the absolute file path for file-backed locations.
func (l *Location) OSPath() string { return l.osPath }

// Finding is one unique key (by fingerprint) and everywhere it appears.
type Finding struct {
	Fingerprint    string `json:"fingerprint"`
	Provider       string `json:"provider"`
	RuleID         string `json:"rule"`
	Name           string `json:"name"`
	Severity       string `json:"severity"`
	Display        string `json:"display"`
	Last4          string `json:"last4"`
	PublicExposure bool   `json:"public_exposure"`
	HistoryOnly    bool   `json:"history_only"`
	// Category: "leak" (act on it), "stored" (only in a tool's own credential
	// store), or "others" (only in commits by other people, in cloned repos).
	Category string `json:"category"`
	// Liveness is set by "zarpa check": live, revoked, unknown, unsupported, not_checked.
	Liveness   string     `json:"liveness,omitempty"`
	LiveDetail string     `json:"liveness_detail,omitempty"`
	FirstSeen  time.Time  `json:"first_seen"`
	Locations  []Location `json:"locations"`

	secret string         // raw key, only with Config.KeepSecrets; never serialised
	gitIdx map[string]int // repo|path -> index into Locations
	locIdx map[string]bool
}

// Stats summarise a scan.
type Stats struct {
	Files        int64         `json:"files"`
	Bytes        int64         `json:"bytes"`
	Skipped      int64         `json:"skipped"`
	Ignored      int64         `json:"git_ignored_skipped"`
	CloudOnly    int64         `json:"cloud_only_skipped"`
	Repos        int           `json:"repos"`
	Commits      int           `json:"commits"`
	MachineFiles int           `json:"machine_files"`
	Duration     time.Duration `json:"duration_ns"`
}

// Result is the outcome of a scan.
type Result struct {
	Findings     []*Finding `json:"findings"`
	Stats        Stats      `json:"stats"`
	Warnings     []string   `json:"warnings,omitempty"`
	RulesVersion string     `json:"rules_version"`
	SaltStore    string     `json:"salt_store"`
	StartedAt    time.Time  `json:"started_at"`
}

// Secret returns the raw key when the scan ran with KeepSecrets, else "".
func (f *Finding) Secret() string { return f.secret }

// ForgetSecret drops the raw key from memory.
func (f *Finding) ForgetSecret() { f.secret = "" }

type collector struct {
	keepSecrets bool
	home        string
	mu          sync.Mutex
	hasher      *fingerprint.Hasher
	byFP        map[string]*Finding
	warnings    []string
}

// Run performs the scan.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Rules == nil || cfg.Hasher == nil {
		return nil, errors.New("scan: rules and hasher are required")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.GOOS == "" {
		cfg.GOOS = runtime.GOOS
	}
	// Resolve symlinks once (on macOS /var -> /private/var, and some homes
	// live on symlinked volumes) so every source sees the same path for a file.
	if cfg.Home != "" {
		if r, err := filepath.EvalSymlinks(cfg.Home); err == nil {
			cfg.Home = r
		}
	}
	start := time.Now()
	eng := detect.New(cfg.Rules)
	col := &collector{keepSecrets: cfg.KeepSecrets, home: cfg.Home, hasher: cfg.Hasher, byFP: map[string]*Finding{}}
	var st Stats
	var files, bytesRead, skipped, machineFiles, cloudOnly atomic.Int64

	jobs := make(chan item.Job, 256)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if j.File != "" {
					cfg.Progress.setCurrent(j.File)
				}
				n, err := col.process(eng, j)
				if cfg.Progress != nil {
					cfg.Progress.Files.Add(1)
				}
				if errors.Is(err, item.ErrCloudOnly) {
					cloudOnly.Add(1)
				}
				switch {
				case err == nil:
					files.Add(1)
					bytesRead.Add(n)
					if j.Template.Machine {
						machineFiles.Add(1)
					}
				default:
					// Binary, too large, unreadable, or a recovered panic (already warned).
					skipped.Add(1)
				}
			}
		}()
	}

	// Producer: machine sources first (so the walk can skip what they cover),
	// then the folder walk, then git history of every repo the walk found.
	claimedFiles := map[string]bool{}
	var claimedDirs []string
	exclude := func(p string, isDir bool) bool {
		if claimedFiles[p] {
			return true
		}
		for _, d := range claimedDirs {
			if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	emit := func(j item.Job) {
		select {
		case jobs <- j:
		case <-ctx.Done():
		}
	}

	if cfg.Staged {
		// Pre-commit mode: only the staged diff of each repo, nothing else.
		cfg.Machine, cfg.Git = false, false
	}
	if cfg.Machine && cfg.Home != "" {
		cfg.Progress.setStage("AI tools, shell history, dotfiles")
		env := machine.Env{GOOS: cfg.GOOS, Home: cfg.Home, AppData: cfg.AppData}
		machine.Collect(env, machine.Targets(env), emit, func(p string, isDir bool) {
			paths := []string{p}
			if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
				paths = append(paths, r)
			}
			for _, q := range paths {
				if isDir {
					claimedDirs = append(claimedDirs, q)
				} else {
					claimedFiles[q] = true
				}
			}
		})
	}

	var repos []string
	seenRepo := map[string]bool{}
	for _, p := range cfg.Paths {
		if ctx.Err() != nil {
			break
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			col.warn(fmt.Sprintf("%s: %v", p, err))
			continue
		}
		if cfg.Staged {
			root, err := gitsrc.RepoRoot(abs)
			if err != nil {
				col.warn(fmt.Sprintf("%s: not inside a git repository", p))
				continue
			}
			if !seenRepo[root] {
				seenRepo[root] = true
				if _, err := gitsrc.Scan(ctx, root, gitsrc.Options{Staged: true}, emit); err != nil {
					col.warn(err.Error())
				}
			}
			continue
		}
		cfg.Progress.setStage("folders: " + kfs.Tildify(abs, cfg.Home))
		ws, err := kfs.Walk(kfs.Options{Root: abs, Home: cfg.Home, MaxFileSize: cfg.MaxFileSize, Exclude: exclude, Bundle: cfg.Bundle},
			emit, func(root string) {
				if !seenRepo[root] {
					seenRepo[root] = true
					repos = append(repos, root)
				}
			})
		if err != nil {
			col.warn(fmt.Sprintf("%s: %v", p, err))
		}
		st.Ignored += int64(ws.Ignored)
		st.CloudOnly += int64(ws.CloudOnly)
	}
	st.Repos = len(repos)

	if cfg.Git && len(repos) > 0 {
		if !gitsrc.Available() {
			col.warn("git is not installed, so git history was not scanned")
		} else {
			for _, r := range repos {
				if ctx.Err() != nil {
					break
				}
				cfg.Progress.setStage("git history: " + kfs.Tildify(r, cfg.Home))
				// A repo counts as someone else's only if you never committed to it:
				// keys you pushed under an old or work email stay in the main list.
				self := gitsrc.UserEmail(r)
				if self != "" && gitsrc.HasAuthor(r, self) {
					self = ""
				}
				gopt := gitsrc.Options{MaxFileBytes: int(maxInt64(cfg.MaxFileSize, item.DefaultMaxFile)),
					MaxCommits: cfg.MaxCommits, SelfEmail: self}
				if cfg.Progress != nil {
					gopt.OnCommit = func() { cfg.Progress.Commits.Add(1) }
				}
				n, err := gitsrc.Scan(ctx, r, gopt, emit)
				st.Commits += n
				if err != nil && ctx.Err() == nil {
					col.warn(err.Error())
				}
			}
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	st.Files = files.Load()
	st.Bytes = bytesRead.Load()
	st.Skipped = skipped.Load()
	st.MachineFiles = int(machineFiles.Load())
	st.CloudOnly += cloudOnly.Load()
	st.Duration = time.Since(start)

	res := &Result{Stats: st, Warnings: col.warnings, RulesVersion: cfg.Rules.Version,
		SaltStore: cfg.Hasher.Where, StartedAt: start.UTC()}
	min := rules.Rank(cfg.MinSeverity)
	for _, f := range col.byFP {
		if rules.Rank(f.Severity) < min {
			continue
		}
		finalize(f)
		res.Findings = append(res.Findings, f)
	}
	sortFindings(res.Findings)
	return res, nil
}

// process scans one job. A panic in detection is recovered and reported as a
// warning for that file, so one bad input never stops the whole scan.
func (c *collector) process(eng *detect.Engine, j item.Job) (n int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			name := j.File
			if name == "" {
				name = j.Template.Ref
			}
			c.warn(fmt.Sprintf("internal error while scanning %s (skipped): %v", name, r))
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	if j.File == "" {
		it := j.Template
		c.add(eng, &it)
		return int64(len(it.Content)), nil
	}
	return item.ReadFile(j.File, j.Read, func(content []byte, lineOffset int) {
		it := j.Template
		it.Content = content
		it.LineOffset = lineOffset
		c.add(eng, &it)
	})
}

func (c *collector) warn(s string) {
	c.mu.Lock()
	c.warnings = append(c.warnings, s)
	c.mu.Unlock()
}

func (c *collector) add(eng *detect.Engine, it *item.Item) {
	matches := eng.Scan(it.Content, detect.Options{SkipGeneric: it.SkipGeneric, TestPath: it.TestPath})
	if len(matches) == 0 {
		return
	}
	for _, m := range matches {
		fp := c.hasher.Of(m.Secret)
		line := it.RealLine(m.Line)
		loc := Location{
			Kind:           it.Kind,
			Ref:            fmt.Sprintf("%s:%d", it.Ref, line),
			Line:           line,
			Column:         m.Column,
			Repo:           it.Repo,
			Tool:           it.Tool,
			VarName:        m.VarName,
			GitIgnored:     it.GitIgnored,
			PublicExposure: m.PublicVar || it.Public,
			ByOther:        it.ByOther,
		}
		if it.Kind == item.KindGit {
			loc.Path = it.Path
			loc.Commit = it.Commit
			t := it.CommitTime
			loc.CommittedAt = &t
			loc.Commits = 1
		} else {
			loc.osPath = it.Path
			loc.Expected = isExpectedStore(it.Path, c.home)
		}
		seen := it.ModTime
		if it.Kind == item.KindGit {
			seen = it.CommitTime
		}

		c.mu.Lock()
		f := c.byFP[fp]
		if f == nil {
			f = &Finding{
				Fingerprint: fp,
				Provider:    m.Rule.Provider,
				RuleID:      m.Rule.ID,
				Name:        m.Rule.Name,
				Severity:    m.Rule.Severity,
				Display:     Redact(m.Secret, m.Rule.PrefixLen),
				Last4:       Last4(m.Secret),
				gitIdx:      map[string]int{},
				locIdx:      map[string]bool{},
			}
			c.byFP[fp] = f
		} else if rules.Rank(m.Rule.Severity) > rules.Rank(f.Severity) ||
			(f.Provider == "generic" && m.Rule.Provider != "generic") {
			// A more specific rule names the same key elsewhere.
			f.Provider, f.RuleID, f.Name, f.Severity = m.Rule.Provider, m.Rule.ID, m.Rule.Name, m.Rule.Severity
			f.Display = Redact(m.Secret, m.Rule.PrefixLen)
		}
		if c.keepSecrets && f.secret == "" {
			f.secret = m.Secret
		}
		if !seen.IsZero() && (f.FirstSeen.IsZero() || seen.Before(f.FirstSeen)) {
			f.FirstSeen = seen.UTC()
		}
		if it.Kind == item.KindGit {
			// One location per repo+file: the commit that introduced the key.
			key := it.Repo + "|" + it.Path
			if i, ok := f.gitIdx[key]; ok {
				cur := &f.Locations[i]
				cur.Commits++
				byOther := cur.ByOther && loc.ByOther
				if it.CommitTime.Before(*cur.CommittedAt) {
					commits := cur.Commits
					*cur = loc
					cur.Commits = commits
				}
				cur.ByOther = byOther
				cur.PublicExposure = cur.PublicExposure || loc.PublicExposure
			} else {
				f.gitIdx[key] = len(f.Locations)
				f.Locations = append(f.Locations, loc)
			}
		} else if !f.locIdx[loc.Ref] {
			f.locIdx[loc.Ref] = true
			f.Locations = append(f.Locations, loc)
		}
		c.mu.Unlock()
	}
}

func finalize(f *Finding) {
	f.HistoryOnly = true
	allStored, allOthers := true, true
	for _, l := range f.Locations {
		if l.Kind != item.KindGit {
			f.HistoryOnly = false
			allOthers = false
		} else if !l.ByOther {
			allOthers = false
		}
		if !l.Expected {
			allStored = false
		}
		if l.PublicExposure {
			f.PublicExposure = true
		}
	}
	switch {
	case allStored:
		f.Category = CategoryStored
	case allOthers:
		f.Category = CategoryOthers
	default:
		f.Category = CategoryLeak
	}
	sort.SliceStable(f.Locations, func(i, j int) bool {
		a, b := f.Locations[i], f.Locations[j]
		if (a.Kind == item.KindGit) != (b.Kind == item.KindGit) {
			return b.Kind == item.KindGit // working copies first
		}
		return a.Ref < b.Ref
	})
}

// Finding categories.
const (
	CategoryLeak   = "leak"
	CategoryStored = "stored"
	CategoryOthers = "others"
)

// expectedStores are files and folders (relative to home) where a tool is
// meant to keep its own credential. A key there is reported, but apart
// from leaks: the fix is rotation hygiene, not cleanup.
var expectedStores = []string{
	".ssh/", ".gnupg/", ".anydesk/", ".openclaw/identity/", ".config/gcloud/", ".kube/config",
	".codex/auth.json", ".gemini/oauth_creds.json", ".claude/.credentials.json",
	"Library/Application Support/com.vercel.cli/auth.json", ".config/gh/hosts.yml",
	".aws/credentials", ".aws/config", ".docker/config.json", ".netrc", ".git-credentials",
	".npmrc", ".pypirc", ".huggingface/token", ".cache/huggingface/token", ".kaggle/kaggle.json",
	".config/stripe/config.toml", ".supabase/access-token", ".terraformrc",
}

func isExpectedStore(p, home string) bool {
	if home == "" || !strings.HasPrefix(p, home+string(filepath.Separator)) {
		return false
	}
	rel := filepath.ToSlash(p[len(home)+1:])
	for _, s := range expectedStores {
		if rel == s || strings.HasSuffix(s, "/") && strings.HasPrefix(rel, s) {
			return true
		}
	}
	return false
}

func sortFindings(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := rules.Rank(a.Severity), rules.Rank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.PublicExposure != b.PublicExposure {
			return a.PublicExposure
		}
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		return a.Display < b.Display
	})
}

// Last4 returns the last four characters of key material. For PEM blocks it
// uses the base64 body only, ignoring armour, quotes, spaces and literal "\\n"
// escapes (PEM keys pasted into code or JSON strings).
func Last4(secret string) string {
	s := secret
	if strings.HasPrefix(s, "-----BEGIN") {
		if i := strings.Index(s, "-----END"); i > 0 {
			s = s[:i]
		}
		s = strings.ReplaceAll(s, `\n`, "")
		var b strings.Builder
		for _, c := range s {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
				b.WriteRune(c)
			}
		}
		s = b.String()
	} else {
		s = strings.TrimRight(s, "\r\n\t =-")
	}
	if len(s) <= 4 {
		return ""
	}
	return s[len(s)-4:]
}

// Redact shows the provider's fixed prefix and the last four characters.
// At least 12 characters always stay hidden.
func Redact(secret string, prefixLen int) string {
	if strings.HasPrefix(secret, "-----BEGIN") {
		return "PEM private key …" + Last4(secret)
	}
	if prefixLen > len(secret)-12 {
		prefixLen = len(secret) - 12
	}
	if prefixLen < 0 {
		prefixLen = 0
	}
	l4 := Last4(secret)
	if len(secret) < 16 {
		l4 = ""
	}
	return secret[:prefixLen] + "…" + l4
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// HomeDir returns the user's home directory or "".
func HomeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}
