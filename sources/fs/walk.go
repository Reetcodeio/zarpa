// Package fs walks a directory tree and produces scan jobs.
//
// Inside git repositories it honours .gitignore (and .git/info/exclude),
// but still scans ignored env and MCP config files and marks them, because
// an ignored .env is exactly where forgotten keys live.
package fs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Reetcodeio/zarpa/internal/detect"
	"github.com/Reetcodeio/zarpa/internal/item"
)

// Options configure a walk.
type Options struct {
	Root        string // absolute path to walk
	Home        string // used to print "~/..." instead of the home path
	MaxFileSize int64
	// Exclude skips absolute paths another source already covers.
	Exclude func(absPath string, isDir bool) bool
	// Bundle scans a built frontend (dist/, build/, .next/static): .gitignore
	// is not applied, and everything found is marked as shipping to browsers.
	Bundle bool
}

// Stats summarise a walk.
type Stats struct {
	Files   int
	Skipped int
	Ignored int // files skipped because git ignores them
	// CloudOnly counts iCloud folders not on this Mac (skipped).
	CloudOnly int
	Repos     int
}

// skipDirNames are never descended into: dependency caches, VCS internals,
// build caches. Built bundles are covered by `scan --bundle`.
var skipDirNames = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "bower_components": true,
	"__pycache__": true, ".venv": true, "venv": true, ".tox": true, ".mypy_cache": true,
	".pytest_cache": true, ".ruff_cache": true, ".pnpm-store": true, ".npm": true, ".yarn": true,
	".gradle": true, ".m2": true, "Pods": true, "DerivedData": true, ".Trash": true,
	".terraform": true, ".turbo": true, ".parcel-cache": true, ".angular": true,
	".cargo": true, ".rustup": true, ".bundle": true, "site-packages": true, "dist-packages": true,
}

// skipHomeDirs are skipped only directly under the home directory.
var skipHomeDirs = map[string]bool{
	"Library": true, "Applications": true, "Movies": true, "Music": true, "Pictures": true,
	"Photos Library.photoslibrary": true, ".cache": true, "go": true,
	"snap": true, ".nvm": true, ".pyenv": true, ".rbenv": true, ".sdkman": true,
	".vscode": true, ".cursor": true, ".windsurf": true, ".android": true, ".gem": true,
	"OneDrive": true, "AppData": true,
}

var skipExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".icns": true,
	".bmp": true, ".tiff": true, ".psd": true, ".svgz": true, ".heic": true,
	".mp3": true, ".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".wav": true, ".flac": true, ".m4a": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".zip": true, ".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true, ".dmg": true, ".iso": true,
	".pdf": true, ".exe": true, ".dll": true, ".so": true, ".dylib": true, ".a": true, ".o": true,
	".class": true, ".jar": true, ".pyc": true, ".wasm": true, ".node": true, ".bin": true,
	".sqlite": true, ".db": true, ".parquet": true, ".npy": true, ".pt": true, ".safetensors": true, ".onnx": true,
}

// lockfiles get provider rules only: their hashes trip the entropy rule.
var lockfiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "go.sum": true,
	"cargo.lock": true, "poetry.lock": true, "composer.lock": true, "gemfile.lock": true,
	"pipfile.lock": true, "uv.lock": true, "flake.lock": true, "podfile.lock": true, "mix.lock": true,
}

type dirCtx struct {
	repoRoot string // "" when not in a repo
	repoName string
	stack    ignoreStack
}

// Walk walks opt.Root, sends file jobs to emit, and reports every git
// repository root it meets to onRepo.
func Walk(opt Options, emit func(item.Job), onRepo func(root string)) (Stats, error) {
	var st Stats
	root := filepath.Clean(opt.Root)
	// A symlinked root (common: /usr/local/go, ~/code -> /Volumes/...) is followed;
	// symlinks below the root are not.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	opt.Root = root
	if opt.Bundle && filepath.Base(root) == ".next" {
		// Only .next/static is served to browsers; .next/server stays on the server.
		if fi, err := os.Stat(filepath.Join(root, "static")); err == nil && fi.IsDir() {
			root = filepath.Join(root, "static")
			opt.Root = root
		}
	}
	if opt.MaxFileSize <= 0 {
		opt.MaxFileSize = item.DefaultMaxFile
	}
	info, err := os.Stat(root)
	if err != nil {
		return st, err
	}
	if !info.IsDir() {
		st.Files++
		emit(fileJob(opt, root, filepath.Dir(root), nil, false))
		return st, nil
	}

	kwIgnore := loadIgnoreFile(filepath.Join(root, ".zarpaignore"), "")
	ctxs := map[string]*dirCtx{}
	ctxs[root] = enclosingRepo(root)
	if ctxs[root].repoRoot != "" && onRepo != nil {
		st.Repos++
		onRepo(ctxs[root].repoRoot)
	}

	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if d != nil && d.IsDir() && p != root {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		name := d.Name()
		parent := filepath.Dir(p)

		if d.IsDir() {
			if p == root {
				enterDir(ctxs, ctxs[root], p, &st, onRepo, true)
				return nil
			}
			if skipDirNames[name] || skipDirByContext(name, filepath.Base(parent)) || IsBrowserProfile(p, name) {
				return fs.SkipDir
			}
			if opt.Home != "" && parent == opt.Home && skipHomeDirs[name] {
				return fs.SkipDir
			}
			if opt.Exclude != nil && opt.Exclude(p, true) {
				return fs.SkipDir
			}
			if info, err := d.Info(); err == nil && item.IsCloudOnly(info) {
				st.CloudOnly++
				return fs.SkipDir // listing it would make macOS download it
			}
			pc := ctxs[parent]
			if kwIgnore != nil && kwIgnore.ignoredRel(rel(root, p), true) {
				return fs.SkipDir
			}
			if !opt.Bundle && pc != nil && pc.repoRoot != "" && !isRepoRoot(p) && pc.stack.ignored(rel(pc.repoRoot, p), true) {
				return fs.SkipDir
			}
			enterDir(ctxs, pc, p, &st, onRepo, false)
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}
		if skipExt[strings.ToLower(filepath.Ext(name))] || name == ".DS_Store" || browserFiles[name] {
			st.Skipped++
			return nil
		}
		if opt.Exclude != nil && opt.Exclude(p, false) {
			return nil
		}
		if kwIgnore != nil && kwIgnore.ignoredRel(rel(root, p), false) {
			return nil
		}
		dc := ctxs[parent]
		gitIgnored := false
		if !opt.Bundle && dc != nil && dc.repoRoot != "" && dc.stack.ignored(rel(dc.repoRoot, p), false) {
			if !alwaysFlag(name) {
				st.Ignored++
				return nil
			}
			gitIgnored = true
		}
		st.Files++
		emit(fileJob(opt, p, parent, dc, gitIgnored))
		return nil
	})
	return st, err
}

func (f *ignoreFile) ignoredRel(relPath string, isDir bool) bool {
	return ignoreStack{f}.ignored(relPath, isDir)
}

func enterDir(ctxs map[string]*dirCtx, parent *dirCtx, dir string, st *Stats, onRepo func(string), isRoot bool) {
	var c *dirCtx
	switch {
	case !isRoot && isRepoRoot(dir):
		c = &dirCtx{repoRoot: dir, repoName: filepath.Base(dir)}
		if f := loadIgnoreFile(filepath.Join(dir, ".git", "info", "exclude"), ""); f != nil {
			c.stack = append(c.stack, f)
		}
		st.Repos++
		if onRepo != nil {
			onRepo(dir)
		}
	case parent != nil:
		cp := *parent
		cp.stack = append(ignoreStack(nil), parent.stack...)
		c = &cp
	default:
		c = &dirCtx{}
	}
	if c.repoRoot != "" && !isRoot {
		// The walk root's ignore files were already loaded by enclosingRepo.
		if f := loadIgnoreFile(filepath.Join(dir, ".gitignore"), rel(c.repoRoot, dir)); f != nil {
			c.stack = append(c.stack, f)
		}
	}
	ctxs[dir] = c
}

// enclosingRepo finds the repo containing dir (if any) and loads the ignore
// files from the repo root down to, but not including, dir.
func enclosingRepo(dir string) *dirCtx {
	for cur := dir; ; {
		if isRepoRoot(cur) {
			c := &dirCtx{repoRoot: cur, repoName: filepath.Base(cur)}
			if f := loadIgnoreFile(filepath.Join(cur, ".git", "info", "exclude"), ""); f != nil {
				c.stack = append(c.stack, f)
			}
			if cur != dir {
				// Load .gitignore files on the path cur .. parent(dir).
				relDir := rel(cur, dir)
				parts := strings.Split(relDir, "/")
				p := cur
				base := ""
				for i := 0; i < len(parts); i++ {
					if f := loadIgnoreFile(filepath.Join(p, ".gitignore"), base); f != nil {
						c.stack = append(c.stack, f)
					}
					p = filepath.Join(p, parts[i])
					base = slashJoin(base, parts[i])
				}
				if f := loadIgnoreFile(filepath.Join(dir, ".gitignore"), relDir); f != nil {
					c.stack = append(c.stack, f)
				}
			} else if f := loadIgnoreFile(filepath.Join(cur, ".gitignore"), ""); f != nil {
				c.stack = append(c.stack, f)
			}
			return c
		}
		next := filepath.Dir(cur)
		if next == cur {
			return &dirCtx{}
		}
		cur = next
	}
}

func isRepoRoot(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil
}

func rel(base, p string) string {
	r, err := filepath.Rel(base, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	if r == "." {
		return ""
	}
	return filepath.ToSlash(r)
}

func fileJob(opt Options, p, parent string, dc *dirCtx, gitIgnored bool) item.Job {
	name := filepath.Base(p)
	lname := strings.ToLower(name)
	t := item.Item{Kind: item.KindFile, Path: p, GitIgnored: gitIgnored}
	if fi, err := os.Stat(p); err == nil {
		t.ModTime = fi.ModTime()
	}
	t.SkipGeneric = SkipGenericFor(lname)
	if tool := mcpTool(lname, filepath.Base(parent)); tool != "" {
		t.Kind = item.KindMCP
		t.Tool = tool
	}
	if dc != nil && dc.repoRoot != "" {
		t.TestPath = detect.IsTestPath(rel(dc.repoRoot, p))
	} else {
		t.TestPath = detect.IsTestPath(rel(opt.Root, p))
	}
	if dc != nil && dc.repoRoot != "" {
		t.Repo = dc.repoName
		t.Ref = "repo:" + dc.repoName + ":" + rel(dc.repoRoot, p)
	} else {
		t.Ref = "file:" + Tildify(p, opt.Home)
	}
	if t.Kind == item.KindMCP {
		t.Ref = "mcp:" + t.Tool + ":" + strings.SplitN(t.Ref, ":", 2)[1]
	}
	if opt.Bundle {
		// Everything in a built bundle is downloadable by any visitor.
		t.Kind, t.Public, t.SkipGeneric, t.TestPath = item.KindBundle, true, true, false
		t.Ref = "bundle:" + Tildify(p, opt.Home)
	}
	return item.Job{Template: t, File: p, Read: item.ReadOptions{MaxWhole: opt.MaxFileSize}}
}

// mcpTool names the tool a project-level MCP config belongs to.
func mcpTool(lowerName, parentDir string) string {
	switch {
	case lowerName == ".mcp.json":
		return "claude-code"
	case parentDir == ".cursor" && lowerName == "mcp.json":
		return "cursor"
	case parentDir == ".vscode" && (lowerName == "mcp.json" || lowerName == "settings.json"):
		return "vscode"
	case parentDir == ".claude" && strings.HasPrefix(lowerName, "settings"):
		return "claude-code"
	case lowerName == "mcp_config.json":
		return "windsurf"
	case lowerName == "claude_desktop_config.json":
		return "claude-desktop"
	}
	return ""
}

// Tildify prints p relative to home as "~/...".
func Tildify(p, home string) string {
	if home != "" {
		if p == home {
			return "~"
		}
		if strings.HasPrefix(p, home+string(filepath.Separator)) {
			return "~/" + filepath.ToSlash(p[len(home)+1:])
		}
	}
	return filepath.ToSlash(p)
}

// browserFiles are Chromium profile files full of random ids.
var browserFiles = map[string]bool{
	"Preferences": true, "Secure Preferences": true, "Local State": true, "ChromeFeatureState": true,
	"Cookies": true, "Web Data": true, "Login Data": true, "History": true, "TransportSecurity": true,
}

// skipDirByContext skips folders by name and parent: editor extension
// stores (~/.vscode/extensions, ~/.antigravity/extensions, ...) and the
// "Page_files" folders browsers create when saving a web page.
func skipDirByContext(name, parent string) bool {
	if name == "extensions" && strings.HasPrefix(parent, ".") {
		return true
	}
	return strings.HasSuffix(name, "_files")
}

// IsBrowserProfile reports Chromium profile folders (including ones AI tools
// and test runners create): "*browser-profile*" names, or a folder holding
// a "Local State" file.
func IsBrowserProfile(dir, name string) bool {
	l := strings.ToLower(name)
	if strings.Contains(l, "browser-profile") || strings.Contains(l, "browser_profile") || l == "chrome-profile" {
		return true
	}
	_, err := os.Stat(filepath.Join(dir, "Local State"))
	return err == nil
}

// SkipPath applies the folder and file skip rules to a repo-relative slash
// path (used for git history, where there is no folder walk).
func SkipPath(slashPath string) bool {
	parts := strings.Split(slashPath, "/")
	for i, seg := range parts[:len(parts)-1] {
		parent := ""
		if i > 0 {
			parent = parts[i-1]
		}
		l := strings.ToLower(seg)
		if skipDirNames[seg] || skipDirByContext(seg, parent) || strings.Contains(l, "browser-profile") || l == "profile" && i+1 < len(parts) && parts[i+1] == "Default" {
			return true
		}
	}
	base := parts[len(parts)-1]
	return browserFiles[base] || strings.HasPrefix(base, ".com.google.Chrome.")
}

// SkipDirName reports dependency, cache and VCS folders never worth walking.
func SkipDirName(name string) bool { return skipDirNames[name] }

// SkipGenericFor reports files that get provider rules only (lockfiles,
// minified code, source maps).
func SkipGenericFor(name string) bool {
	l := strings.ToLower(name)
	return lockfiles[l] || strings.HasSuffix(l, ".min.js") || strings.HasSuffix(l, ".map")
}

// SkipExt reports files never worth reading (media, archives, binaries).
func SkipExt(name string) bool {
	return skipExt[strings.ToLower(filepath.Ext(name))]
}
