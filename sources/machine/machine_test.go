package machine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Reetcodeio/zarpa/internal/item"
)

func TestToolLoginFilesAreNotTranscripts(t *testing.T) {
	home := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".codex/auth.json")
	write(".gemini/oauth_creds.json")
	write(".codex/sessions/2026/a.jsonl")

	kinds := map[string]string{}
	Collect(Env{GOOS: "darwin", Home: home}, Targets(Env{GOOS: "darwin", Home: home}),
		func(j item.Job) { kinds[filepath.ToSlash(j.File[len(home)+1:])] = j.Template.Kind },
		func(string, bool) {})

	want := map[string]string{
		".codex/auth.json":             item.KindDotfile,
		".gemini/oauth_creds.json":     item.KindDotfile,
		".codex/sessions/2026/a.jsonl": item.KindTranscript,
	}
	for f, k := range want {
		if kinds[f] != k {
			t.Errorf("%s: kind %q, want %q", f, kinds[f], k)
		}
	}
}
