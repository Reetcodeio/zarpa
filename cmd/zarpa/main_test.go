package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Reetcodeio/zarpa/internal/testkeys"
)

func TestScanExitCodesAndFlagsAfterPath(t *testing.T) {
	dir := t.TempDir()
	salt := filepath.Join(t.TempDir(), "salt")
	home := t.TempDir()

	var out, errb bytes.Buffer
	code := run([]string{"scan", dir, "--no-git", "--home", home, "--salt-file", salt}, &out, &errb)
	if code != exitClean || !strings.Contains(out.String(), "No keys found") {
		t.Fatalf("empty dir: code %d\n%s%s", code, out.String(), errb.String())
	}

	key := testkeys.New(3).Keys()["anthropic-api-key"]
	must(t, os.WriteFile(filepath.Join(dir, "config.py"), []byte("KEY = '"+key+"'\n"), 0o644))
	out.Reset()
	code = run([]string{"scan", dir, "--json", "--home", home, "--salt-file", salt}, &out, &errb)
	if code != exitFindings {
		t.Fatalf("want exit %d, got %d: %s", exitFindings, code, errb.String())
	}
	var res struct {
		Findings []struct {
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || len(res.Findings) != 1 || res.Findings[0].Rule != "anthropic-api-key" {
		t.Fatalf("json: %v %s", err, out.String())
	}
	if strings.Contains(out.String(), key) {
		t.Fatal("JSON output contains the raw key")
	}
	if code := run([]string{"scan", dir, "--exit-zero", "--home", home, "--salt-file", salt}, &out, &errb); code != exitClean {
		t.Fatalf("--exit-zero: %d", code)
	}
	if code := run([]string{"scan", "--format", "xml"}, &out, &errb); code != exitError {
		t.Fatalf("bad format: %d", code)
	}
}

func TestMissingPathIsAnError(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"scan", filepath.Join(t.TempDir(), "nope"), "--salt-file", filepath.Join(t.TempDir(), "s")}, &out, &errb)
	if code != exitError || !strings.Contains(errb.String(), "no such file or folder") {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
}

func TestHomeFlagKeepsAppDataInsideHome(t *testing.T) {
	t.Setenv("APPDATA", filepath.Join(t.TempDir(), "real-appdata"))
	if got := appDataFor("/some/other/home"); got != "" {
		t.Fatalf("--home must not read the real APPDATA, got %q", got)
	}
	if got := appDataFor(""); got != os.Getenv("APPDATA") {
		t.Fatalf("no --home: want the real APPDATA, got %q", got)
	}
}
