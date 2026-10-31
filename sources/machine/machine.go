// Package machine lists the per-user places where keys pile up outside
// project folders: MCP and editor configs, AI tool session logs and
// transcripts, shell history, and credential dotfiles.
package machine

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Reetcodeio/zarpa/internal/detect"
	"github.com/Reetcodeio/zarpa/internal/item"
	kfs "github.com/Reetcodeio/zarpa/sources/fs"
)

// Target is one file or tool directory to scan.
type Target struct {
	Path string
	Kind string // item.Kind*
	Tool string
	Dir  bool // scan recursively (tool directories)
}

// Env carries the per-OS base folders. Tests set these to a temp tree.
type Env struct {
	GOOS    string
	Home    string
	AppData string // Windows %APPDATA%
}

// Targets returns every location to check for the given OS.
func Targets(env Env) []Target {
	h := func(p ...string) string { return filepath.Join(append([]string{env.Home}, p...)...) }
	var t []Target
	add := func(kind, tool, p string) { t = append(t, Target{Path: p, Kind: kind, Tool: tool}) }
	dir := func(tool, p string) { t = append(t, Target{Path: p, Kind: item.KindTranscript, Tool: tool, Dir: true}) }

	// Per-user AI tool folders: configs inside are tagged MCP, the rest
	// (sessions, history, logs, shell snapshots) are transcripts.
	dir("claude-code", h(".claude"))
	dir("codex", h(".codex"))
	dir("gemini", h(".gemini"))
	dir("continue", h(".continue"))
	dir("cursor", h(".cursor"))
	dir("windsurf", h(".codeium"))
	dir("aider", h(".aider"))
	t = append(t, Target{Path: h(".zsh_sessions"), Kind: item.KindShell, Tool: "zsh", Dir: true})
	add(item.KindMCP, "claude-code", h(".claude.json"))

	// Editor and desktop-app configs, which live in OS-specific folders.
	var appConf string
	switch env.GOOS {
	case "darwin":
		appConf = h("Library", "Application Support")
		dir("claude-desktop", h("Library", "Logs", "Claude"))
	case "windows":
		appConf = env.AppData
		if appConf == "" {
			appConf = h("AppData", "Roaming")
		}
		add(item.KindShell, "powershell", filepath.Join(appConf, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
	default:
		appConf = h(".config")
	}
	add(item.KindMCP, "claude-desktop", filepath.Join(appConf, "Claude", "claude_desktop_config.json"))
	add(item.KindMCP, "cursor", filepath.Join(appConf, "Cursor", "User", "settings.json"))
	add(item.KindMCP, "cursor", filepath.Join(appConf, "Cursor", "User", "mcp.json"))
	add(item.KindMCP, "vscode", filepath.Join(appConf, "Code", "User", "settings.json"))
	add(item.KindMCP, "vscode", filepath.Join(appConf, "Code", "User", "mcp.json"))
	add(item.KindMCP, "windsurf", filepath.Join(appConf, "Windsurf", "User", "settings.json"))
	add(item.KindMCP, "zed", h(".config", "zed", "settings.json"))
	add(item.KindDotfile, "vercel", filepath.Join(appConf, "com.vercel.cli", "auth.json"))

	for _, f := range []string{".zsh_history", ".bash_history", ".sh_history", ".python_history",
		".node_repl_history", ".psql_history", ".mysql_history", ".sqlite_history", ".irb_history",
		".rediscli_history"} {
		add(item.KindShell, strings.TrimPrefix(strings.TrimSuffix(f, "_history"), "."), h(f))
	}
	add(item.KindShell, "fish", h(".local", "share", "fish", "fish_history"))

	for _, f := range [][]string{
		{".zshrc"}, {".zprofile"}, {".zshenv"}, {".zlogin"}, {".bashrc"}, {".bash_profile"}, {".profile"},
		{".config", "fish", "config.fish"}, {".env"}, {".envrc"}, {".netrc"}, {".npmrc"}, {".yarnrc"},
		{".yarnrc.yml"}, {".pypirc"}, {".gitconfig"}, {".git-credentials"}, {".aws", "credentials"},
		{".aws", "config"}, {".docker", "config.json"}, {".config", "gh", "hosts.yml"},
		{".huggingface", "token"}, {".cache", "huggingface", "token"}, {".kaggle", "kaggle.json"},
		{".config", "stripe", "config.toml"}, {".supabase", "access-token"}, {".terraformrc"},
		{".config", "openai"}, {".config", "anthropic"},
	} {
		add(item.KindDotfile, "", h(f...))
	}
	return t
}

// skipInToolDir are bulky subfolders of AI tool directories with no secrets
// of their own. Dependency folders (node_modules, venv, site-packages, ...)
// are skipped too, via fs.SkipDirName.
var skipInToolDir = map[string]bool{
	"extensions": true, "cache": true, "Cache": true, "CachedData": true, "GPUCache": true,
	"Code Cache": true, "statsig": true, "Crashpad": true, "ShaderCache": true, "GrShaderCache": true,
	"Service Worker": true, "IndexedDB": true, "Local Storage": true, "Session Storage": true,
	"blob_storage": true, "WebStorage": true, "component_crx_cache": true,
}

// transcriptExt are file types that hold logs, sessions and histories.
var transcriptExt = map[string]bool{".jsonl": true, ".json": true, ".log": true, ".txt": true, "": true, ".ndjson": true}

// Collect emits jobs for every target that exists and calls claim for each
// file and directory covered, so the folder walk can skip them.
func Collect(env Env, targets []Target, emit func(item.Job), claim func(path string, isDir bool)) int {
	n := 0
	seen := map[string]bool{}
	for _, tg := range targets {
		if tg.Dir {
			fi, err := os.Stat(tg.Path)
			if err != nil || !fi.IsDir() {
				continue
			}
			claim(tg.Path, true)
			_ = filepath.WalkDir(tg.Path, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					if d != nil && d.IsDir() && p != tg.Path {
						return fs.SkipDir
					}
					return nil
				}
				if d.IsDir() {
					if p != tg.Path && (skipInToolDir[d.Name()] || kfs.SkipDirName(d.Name()) || kfs.IsBrowserProfile(p, d.Name())) {
						return fs.SkipDir
					}
					return nil
				}
				if !d.Type().IsRegular() || kfs.SkipExt(d.Name()) || seen[p] {
					return nil
				}
				seen[p] = true
				kind := tg.Kind
				switch {
				case isCredentialName(d.Name()):
					// A tool's own login file, not a transcript.
					kind = item.KindDotfile
				case isConfigName(d.Name()):
					kind = item.KindMCP
				case tg.Kind == item.KindTranscript && !transcriptExt[strings.ToLower(filepath.Ext(d.Name()))]:
					// Code and docs that tools keep around (plugins, scratch projects).
					kind = item.KindFile
				}
				n++
				j := job(env, kind, tg.Tool, p)
				if r, err := filepath.Rel(tg.Path, p); err == nil {
					j.Template.TestPath = detect.IsTestPath(filepath.ToSlash(r))
					j.Template.SkipGeneric = kfs.SkipGenericFor(d.Name())
				}
				emit(j)
				return nil
			})
			continue
		}
		fi, err := os.Stat(tg.Path)
		if err != nil || !fi.Mode().IsRegular() || seen[tg.Path] {
			continue
		}
		seen[tg.Path] = true
		claim(tg.Path, false)
		n++
		emit(job(env, tg.Kind, tg.Tool, tg.Path))
	}
	return n
}

// isCredentialName matches the files AI tools keep their sign-in in
// (~/.codex/auth.json, ~/.gemini/oauth_creds.json, ~/.claude/.credentials.json).
func isCredentialName(name string) bool {
	switch strings.ToLower(name) {
	case "auth.json", "oauth_creds.json", ".credentials.json", "credentials.json", "google_accounts.json":
		return true
	}
	return false
}

func isConfigName(name string) bool {
	l := strings.ToLower(name)
	switch {
	case strings.HasPrefix(l, "settings") && strings.HasSuffix(l, ".json"),
		l == "mcp.json", l == "mcp_config.json", l == "config.toml", l == "config.json", l == "config.yaml":
		return true
	}
	return false
}

func job(env Env, kind, tool, p string) item.Job {
	disp := kfs.Tildify(p, env.Home)
	ref := kind + ":" + disp
	if tool != "" {
		ref = kind + ":" + tool + ":" + disp
	}
	t := item.Item{Kind: kind, Tool: tool, Path: p, Ref: ref, Machine: true}
	if fi, err := os.Stat(p); err == nil {
		t.ModTime = fi.ModTime()
	}
	ro := item.ReadOptions{MaxWhole: item.DefaultMaxFile}
	if kind == item.KindTranscript || kind == item.KindShell || kind == item.KindMCP {
		// Transcripts and histories grow large; stream them.
		ro = item.ReadOptions{MaxWhole: item.DefaultMaxFile, Chunked: true,
			ChunkSize: item.TranscriptChunk, MaxTotal: item.TranscriptMax}
	}
	return item.Job{Template: t, File: p, Read: ro}
}
