package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Reetcodeio/zarpa/internal/live"
	"github.com/Reetcodeio/zarpa/internal/testkeys"
	"github.com/Reetcodeio/zarpa/internal/vault"
)

// TestMain lets the test binary stand in for a child program of zarpa run,
// so the run tests need no shell (Windows has none by default).
func TestMain(m *testing.M) {
	switch os.Getenv("ZARPA_TEST_CHILD") {
	case "print":
		fmt.Print(os.Getenv("KW_RUN_TEST"))
		os.Exit(0)
	case "exit7":
		os.Exit(7)
	}
	os.Exit(m.Run())
}

func gitIn(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type jsonResult struct {
	Findings []struct {
		Rule           string `json:"rule"`
		PublicExposure bool   `json:"public_exposure"`
		Liveness       string `json:"liveness"`
		Locations      []struct {
			Kind string `json:"kind"`
		} `json:"locations"`
	} `json:"findings"`
}

func scanJSON(t *testing.T, args ...string) (jsonResult, int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	args = append(args, "--json", "-q", "--salt-file", filepath.Join(t.TempDir(), "s"), "--home", t.TempDir())
	code := run(args, &out, &errb)
	var r jsonResult
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("bad json: %v\n%s", err, out.String())
		}
	}
	return r, code, errb.String()
}

func TestBundleFlagsEverythingAsPublic(t *testing.T) {
	dir := t.TempDir()
	if _, err := gitIn(t, dir, "init", "-q"); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("dist/\n"), 0o644))
	key := testkeys.New(21).Keys()["stripe-live-secret-key"]
	must(t, os.MkdirAll(filepath.Join(dir, "dist", "assets"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "dist", "assets", "index-abc.js"), []byte(`var s="`+key+`";`), 0o644))

	r, code, stderr := scanJSON(t, "scan", "--bundle", filepath.Join(dir, "dist"))
	if code != exitFindings || len(r.Findings) != 1 {
		t.Fatalf("code %d, %d findings, %s", code, len(r.Findings), stderr)
	}
	f := r.Findings[0]
	if !f.PublicExposure || f.Locations[0].Kind != "bundle" {
		t.Fatalf("finding: %+v", f)
	}
}

func TestStagedOnlySeesStagedLines(t *testing.T) {
	dir := t.TempDir()
	if _, err := gitIn(t, dir, "init", "-q"); err != nil {
		t.Fatal(err)
	}
	k := testkeys.New(22).Keys()
	must(t, os.WriteFile(filepath.Join(dir, "staged.py"), []byte("KEY='"+k["openai-project-key"]+"'\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "unstaged.py"), []byte("KEY='"+k["anthropic-api-key"]+"'\n"), 0o644))
	if _, err := gitIn(t, dir, "add", "staged.py"); err != nil {
		t.Fatal(err)
	}

	r, code, stderr := scanJSON(t, "scan", "--staged", dir)
	if code != exitFindings || len(r.Findings) != 1 || r.Findings[0].Rule != "openai-project-key" {
		t.Fatalf("code %d findings %+v %s", code, r.Findings, stderr)
	}
	if _, err := gitIn(t, dir, "reset", "-q"); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := scanJSON(t, "scan", "--staged", dir); code != exitClean {
		t.Fatalf("nothing staged should be clean, got %d", code)
	}
}

func TestHookBlocksCommitsWithKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "zarpa")
	if runtime.GOOS == "windows" {
		bin += ".exe" // Windows only starts programs with a known extension
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	repo := t.TempDir()
	if _, err := gitIn(t, repo, "init", "-q"); err != nil {
		t.Fatal(err)
	}
	// An existing hook must keep working after install --force.
	hooks := filepath.Join(repo, ".git", "hooks")
	must(t, os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte("#!/bin/sh\ntouch \"$(git rev-parse --git-dir)/old-hook-ran\"\n"), 0o755))

	cmd := exec.Command(bin, "hook", "install")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("install over a foreign hook must ask for --force:\n%s", out)
	}
	cmd = exec.Command(bin, "hook", "install", "--force")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install --force: %v\n%s", err, out)
	}

	key := testkeys.New(23).Keys()["github-pat-classic"]
	must(t, os.WriteFile(filepath.Join(repo, "config.js"), []byte("const t = '"+key+"';\n"), 0o644))
	if _, err := gitIn(t, repo, "add", "config.js"); err != nil {
		t.Fatal(err)
	}
	out, err := gitIn(t, repo, "commit", "-m", "add token")
	if err == nil || !strings.Contains(out, "commit blocked") {
		t.Fatalf("commit with a key must be blocked:\n%s", out)
	}
	if strings.Contains(out, key) {
		t.Fatal("hook output contains the raw key")
	}

	must(t, os.WriteFile(filepath.Join(repo, "config.js"), []byte("const t = process.env.GITHUB_TOKEN;\n"), 0o644))
	if _, err := gitIn(t, repo, "add", "config.js"); err != nil {
		t.Fatal(err)
	}
	if out, err := gitIn(t, repo, "commit", "-q", "-m", "clean"); err != nil {
		t.Fatalf("clean commit blocked:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "old-hook-ran")); err != nil {
		t.Fatal("the previous pre-commit hook did not run")
	}

	cmd = exec.Command(bin, "hook", "uninstall")
	cmd.Dir = repo
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(hooks, "pre-commit"))
	if strings.Contains(string(b), hookMarker) || !strings.Contains(string(b), "old-hook-ran") {
		t.Fatal("uninstall must restore the previous hook")
	}
}

func TestVaultImportAndRun(t *testing.T) {
	mem := vault.Memory()
	openVault = func() (*vault.Vault, error) { return mem, nil }
	defer func() { openVault = vault.Open }()

	env := filepath.Join(t.TempDir(), ".env")
	must(t, os.WriteFile(env, []byte("# app\nexport KW_RUN_TEST=\"hello-from-vault\"\nPORT=3000 # comment\nlower=skip\n"), 0o600))
	var out, errb bytes.Buffer
	if code := cmdVault([]string{"import", env}, nil, &out, &errb); code != 0 {
		t.Fatalf("import: %s", errb.String())
	}
	if !strings.Contains(out.String(), "Stored 2 keys") || !strings.Contains(out.String(), "lower") {
		t.Fatalf("import output: %s", out.String())
	}

	self, err := os.Executable()
	must(t, err)
	out.Reset()
	t.Setenv("ZARPA_TEST_CHILD", "print")
	if code := cmdRun([]string{"--only", "KW_RUN_TEST", "--", self}, &out, &errb); code != 0 {
		t.Fatalf("run: %s", errb.String())
	}
	if out.String() != "hello-from-vault" {
		t.Fatalf("child saw %q", out.String())
	}
	t.Setenv("ZARPA_TEST_CHILD", "exit7")
	if code := cmdRun([]string{"--", self}, &out, &errb); code != 7 {
		t.Fatalf("exit code not passed through: %d", code)
	}
	t.Setenv("ZARPA_TEST_CHILD", "")

	out.Reset()
	cmdVault([]string{"get", "KW_RUN_TEST"}, nil, &out, &errb) // not a terminal: raw value
	if out.String() != "hello-from-vault" {
		t.Fatalf("get into a pipe = %q", out.String())
	}
	out.Reset()
	cmdVault([]string{"ls"}, nil, &out, &errb)
	if strings.Contains(out.String(), "hello-from-vault") || !strings.Contains(out.String(), "PORT") {
		t.Fatalf("ls must redact: %s", out.String())
	}
}

func TestCheckMarksLiveAndDeadKeys(t *testing.T) {
	g := testkeys.New(24).Keys()
	liveKey, deadKey := g["openai-project-key"], g["anthropic-api-key"]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+liveKey {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()
	savedO, savedA := live.Hosts["openai"], live.Hosts["anthropic"]
	live.Hosts["openai"], live.Hosts["anthropic"] = srv.URL, srv.URL
	defer func() { live.Hosts["openai"], live.Hosts["anthropic"] = savedO, savedA }()

	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "a.env"), []byte("OPENAI_API_KEY="+liveKey+"\nANTHROPIC_API_KEY="+deadKey+"\n"), 0o644))
	r, code, stderr := scanJSON(t, "check", dir, "--yes", "--no-machine")
	if code != exitFindings {
		t.Fatalf("code %d: %s", code, stderr)
	}
	got := map[string]string{}
	for _, f := range r.Findings {
		got[f.Rule] = f.Liveness
	}
	if got["openai-project-key"] != "live" || got["anthropic-api-key"] != "revoked" {
		t.Fatalf("liveness %v", got)
	}
	if !strings.Contains(stderr, "will test 2 keys") {
		t.Fatalf("no confirmation summary: %s", stderr)
	}
}
