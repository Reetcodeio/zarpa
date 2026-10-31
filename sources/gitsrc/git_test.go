package gitsrc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Reetcodeio/zarpa/internal/item"
)

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestAddedLinesAndLineNumbers(t *testing.T) {
	if !Available() {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	must(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\ntwo\n"), 0o644))
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-qm", "1")
	// "++ looks like a header" must be treated as content, not a file header.
	must(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n++ looks like a header\ntwo\nthree\n"), 0o644))
	run(t, dir, "commit", "-qam", "2")

	var jobs []item.Job
	n, err := Scan(context.Background(), dir, Options{}, func(j item.Job) { jobs = append(jobs, j) })
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("commits = %d, want 2", n)
	}
	// Newest commit first: lines 2 and 4 were added.
	j := jobs[0].Template
	if j.Path != "a.txt" || string(j.Content) != "++ looks like a header\nthree\n" {
		t.Fatalf("got path %q content %q", j.Path, j.Content)
	}
	if len(j.LineMap) != 2 || j.LineMap[0] != 2 || j.LineMap[1] != 4 {
		t.Fatalf("line map %v, want [2 4]", j.LineMap)
	}
	if !strings.HasPrefix(j.Ref, "git:"+filepath.Base(dir)+"@") {
		t.Fatalf("ref %q", j.Ref)
	}
}

func TestEmptyRepo(t *testing.T) {
	if !Available() {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	if n, err := Scan(context.Background(), dir, Options{}, func(item.Job) {}); err != nil || n != 0 {
		t.Fatalf("empty repo: n=%d err=%v", n, err)
	}
}
