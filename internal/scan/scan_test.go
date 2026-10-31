package scan_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Reetcodeio/zarpa/internal/fingerprint"
	"github.com/Reetcodeio/zarpa/internal/item"
	"github.com/Reetcodeio/zarpa/internal/report"
	"github.com/Reetcodeio/zarpa/internal/scan"
	"github.com/Reetcodeio/zarpa/internal/testkeys"
	"github.com/Reetcodeio/zarpa/rules"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

type fixture struct {
	home string
	keys map[string]string // label -> raw key
}

// buildFixture lays out a fake home folder with one project repo and the
// machine files an AI-heavy developer accumulates.
func buildFixture(t *testing.T) fixture {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	g := testkeys.New(42)
	k := g.Keys()
	keys := map[string]string{
		"A_history_openai":      k["openai-project-key"],
		"B_env_anthropic":       k["anthropic-api-key"],
		"C_vite_stripe":         k["stripe-live-secret-key"],
		"D_dist_only":           k["sendgrid-api-key"],
		"E_tracked_google":      k["google-api-key"],
		"F_mcp_github":          k["github-pat-classic"],
		"G_zsh_groq":            k["groq-api-key"],
		"H_desktop_huggingface": k["huggingface-token"],
	}
	// The home folder is reached through a symlink, as macOS temp dirs are
	// (/var -> /private/var). Every source must still agree on each path.
	realHome := t.TempDir()
	home := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(realHome, home); err != nil {
		// Windows only allows symlinks with Developer Mode or admin rights.
		t.Logf("no symlink (%v); using the folder directly", err)
		home = realHome
	}
	repo := filepath.Join(home, "projects", "web")
	git(t, home, "init", "-q", repo)
	git(t, repo, "config", "user.email", "t@t") // commits below are "yours"

	write(t, filepath.Join(repo, "config.js"), "export const openai = '"+keys["A_history_openai"]+"';\n")
	write(t, filepath.Join(repo, "src", "app.ts"), "// app\nconst maps = \""+keys["E_tracked_google"]+"\";\n")
	write(t, filepath.Join(repo, ".gitignore"), ".env*\ndist/\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "first")
	git(t, repo, "rm", "-q", "config.js")
	git(t, repo, "commit", "-q", "-m", "remove key")

	write(t, filepath.Join(repo, ".env.local"), "ANTHROPIC_API_KEY="+keys["B_env_anthropic"]+"\n")
	write(t, filepath.Join(repo, ".env"), "PORT=3000\nVITE_STRIPE_KEY="+keys["C_vite_stripe"]+"\n")
	write(t, filepath.Join(repo, "dist", "assets", "index.js"), "var k=\""+keys["D_dist_only"]+"\";")
	write(t, filepath.Join(repo, ".mcp.json"), `{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"`+keys["F_mcp_github"]+`"}}}}`)

	write(t, filepath.Join(home, ".claude", "projects", "web", "s1.jsonl"),
		`{"type":"tool_result","content":"ANTHROPIC_API_KEY=`+keys["B_env_anthropic"]+`"}`+"\n")
	write(t, filepath.Join(home, ".zsh_history"), ": 1700000000:0;export GROQ_API_KEY="+keys["G_zsh_groq"]+"\n")
	write(t, filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		`{"mcpServers":{"hf":{"env":{"HF_TOKEN":"`+keys["H_desktop_huggingface"]+`"}}}}`)

	// Noise that must stay quiet: a venv and a browser profile inside an AI
	// tool folder, and plugin docs with example tokens.
	write(t, filepath.Join(home, ".gemini", "antigravity", "scratch", "bot", "venv", "lib", "site-packages", "x", "test_k.py"),
		k["private-key-block"])
	write(t, filepath.Join(home, ".gemini", "antigravity-browser-profile", "Default", "Preferences"),
		`{"device_token":"`+g.Alnum(40)+`9"}`)
	write(t, filepath.Join(home, ".codex", ".tmp", "plugins", "zoom", "docs", "auth.md"),
		"client_secret: "+g.Alnum(30)+"7\n")
	// Editor extension bundles ship sample PEM keys: vendor code, skipped.
	write(t, filepath.Join(home, ".antigravity", "extensions", "php-1.0", "out", "extension.js"),
		"var k = `"+k["private-key-block"]+"`;")

	// A tool's own credential file: reported, but as "stored", not a leak.
	keys["I_ssh_key"] = testkeys.New(43).Keys()["private-key-block"]
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), keys["I_ssh_key"]+"\n")

	// A cloned third-party repo: a key committed by someone else.
	keys["J_others_aws"] = k["aws-access-key-id"]
	other := filepath.Join(home, "src", "upstream-lib")
	git(t, home, "init", "-q", other)
	git(t, other, "config", "user.email", "me@example.org")
	write(t, filepath.Join(other, "config.json"), `{"aws_key":"`+keys["J_others_aws"]+`"}`)
	git(t, other, "add", "-A")
	git(t, other, "commit", "-q", "-m", "upstream")
	git(t, other, "rm", "-q", "config.json")
	git(t, other, "commit", "-q", "-m", "remove")
	return fixture{home: home, keys: keys}
}

func runScan(t *testing.T, fx fixture) (*scan.Result, *fingerprint.Hasher) {
	t.Helper()
	set, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	h := fingerprint.NewWithSalt(bytes.Repeat([]byte{7}, 32), "test")
	res, err := scan.Run(context.Background(), scan.Config{
		Paths: []string{fx.home}, Home: fx.home, GOOS: "darwin",
		Git: true, Machine: true, Workers: 4, MinSeverity: "low",
		Rules: set, Hasher: h,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res, h
}

func TestEndToEnd(t *testing.T) {
	fx := buildFixture(t)
	res, h := runScan(t, fx)

	byFP := map[string]*scan.Finding{}
	for _, f := range res.Findings {
		byFP[f.Fingerprint] = f
	}
	get := func(label string) *scan.Finding {
		f := byFP[h.Of(fx.keys[label])]
		if f == nil && label != "D_dist_only" {
			t.Fatalf("%s not found; findings: %d", label, len(res.Findings))
		}
		return f
	}
	kinds := func(f *scan.Finding) string {
		var ks []string
		for _, l := range f.Locations {
			ks = append(ks, l.Kind)
		}
		return strings.Join(ks, ",")
	}

	if len(res.Findings) != 9 {
		for _, f := range res.Findings {
			t.Logf("%s %s %s", f.RuleID, f.Display, kinds(f))
		}
		t.Fatalf("want 9 findings, got %d", len(res.Findings))
	}

	a := get("A_history_openai")
	if !a.HistoryOnly || kinds(a) != "git" || a.Locations[0].Commit == "" || a.Locations[0].Line != 1 {
		t.Errorf("A: history_only=%v kinds=%s loc=%+v", a.HistoryOnly, kinds(a), a.Locations[0])
	}

	b := get("B_env_anthropic")
	if kinds(b) != "file,transcript" || !b.Locations[0].GitIgnored {
		t.Errorf("B: kinds=%s ignored=%v refs=%v", kinds(b), b.Locations[0].GitIgnored, refs(b))
	}

	c := get("C_vite_stripe")
	if !c.PublicExposure || c.Severity != "critical" || c.Locations[0].Line != 2 {
		t.Errorf("C: public=%v sev=%s loc=%+v", c.PublicExposure, c.Severity, c.Locations[0])
	}

	if get("D_dist_only") != nil {
		t.Error("D: keys in git-ignored dist/ belong to scan --bundle, not the tree walk")
	}

	e := get("E_tracked_google")
	if e.HistoryOnly || kinds(e) != "file,git" || e.Locations[0].Ref != "repo:web:src/app.ts:2" {
		t.Errorf("E: kinds=%s refs=%v", kinds(e), refs(e))
	}

	f := get("F_mcp_github")
	if kinds(f) != item.KindMCP || f.Locations[0].Tool != "claude-code" {
		t.Errorf("F: kinds=%s tool=%s", kinds(f), f.Locations[0].Tool)
	}

	g := get("G_zsh_groq")
	if kinds(g) != item.KindShell || g.Locations[0].Ref != "shell:zsh:~/.zsh_history:1" {
		t.Errorf("G: %v", refs(g))
	}

	hf := get("H_desktop_huggingface")
	if kinds(hf) != item.KindMCP || hf.Locations[0].Tool != "claude-desktop" {
		t.Errorf("H: kinds=%s tool=%s refs=%v", kinds(hf), hf.Locations[0].Tool, refs(hf))
	}

	if ssh := get("I_ssh_key"); ssh.Category != scan.CategoryStored {
		t.Errorf("I: ~/.ssh key category %q, want stored", ssh.Category)
	}
	if o := get("J_others_aws"); o.Category != scan.CategoryOthers {
		t.Errorf("J: third-party commit category %q, want others", o.Category)
	}
	if a.Category != scan.CategoryLeak || b.Category != scan.CategoryLeak {
		t.Errorf("own keys must be leaks: A=%s B=%s", a.Category, b.Category)
	}
	if res.Stats.Repos != 2 || res.Stats.Commits != 4 {
		t.Errorf("stats: repos=%d commits=%d", res.Stats.Repos, res.Stats.Commits)
	}
}

func TestReportsNeverContainRawKeys(t *testing.T) {
	fx := buildFixture(t)
	res, _ := runScan(t, fx)
	set, _ := rules.Load()

	var text, js, sarif bytes.Buffer
	report.Text(&text, res, report.TextOptions{Verbose: true})
	if err := report.JSON(&js, res); err != nil {
		t.Fatal(err)
	}
	if err := report.SARIF(&sarif, res, set, fx.home); err != nil {
		t.Fatal(err)
	}
	for label, key := range fx.keys {
		for name, out := range map[string]string{"text": text.String(), "json": js.String(), "sarif": sarif.String()} {
			if strings.Contains(out, key) || strings.Contains(out, key[:len(key)-4]) {
				t.Errorf("%s report leaks %s", name, label)
			}
		}
	}
	if !strings.Contains(text.String(), "7 leaked keys found") || !strings.Contains(text.String(), "Kept by tools") ||
		!strings.Contains(text.String(), "commits by other people") {
		t.Errorf("summary line missing:\n%s", text.String())
	}
}

func TestLast4OfPEMInCodeString(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ\\n-----END RSA PRIVATE KEY-----"
	if got := scan.Last4(pem); got != "EAAQ" {
		t.Fatalf("Last4 = %q, want EAAQ", got)
	}
}

func TestRedact(t *testing.T) {
	key := testkeys.New(9).Keys()["anthropic-api-key"]
	got := scan.Redact(key, 13)
	if !strings.HasPrefix(got, "sk-ant-api03-…") || !strings.HasSuffix(got, key[len(key)-4:]) {
		t.Errorf("Redact = %q", got)
	}
	// Short secrets keep at least 12 characters hidden.
	if got := scan.Redact("abcdefghijklmnop", 10); got != "abcd…mnop" {
		t.Errorf("short Redact = %q", got)
	}
}

func refs(f *scan.Finding) []string {
	var out []string
	for _, l := range f.Locations {
		out = append(out, l.Ref)
	}
	return out
}
