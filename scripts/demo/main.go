// Command demo builds a throwaway "machine" full of fake keys under the folder
// it is given, so `make demo` can show a realistic report without touching
// anything real. Every key is generated at run time (internal/testkeys), so the
// repository itself never contains a key-shaped string.
//
//	go run ./scripts/demo /tmp/zarpa-demo
//	HOME=/tmp/zarpa-demo/home zarpa scan /tmp/zarpa-demo/home/code --salt-file /tmp/zarpa-demo/salt
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Reetcodeio/zarpa/internal/testkeys"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: demo <empty folder>")
		os.Exit(2)
	}
	if err := build(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func build(root string) error {
	k := testkeys.New(2026).Keys()
	home := filepath.Join(root, "home")
	now := time.Now()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	day := 24 * time.Hour

	// A web shop: a live Stripe key in .env, an OpenAI key in a public Vite
	// variable (ships to every visitor), and a key deleted from the code but
	// still in git history.
	shop := filepath.Join(home, "code", "shop")
	files := []struct {
		path, body string
		mod        time.Time
	}{
		{filepath.Join(shop, ".gitignore"), "node_modules/\n.env\n", ago(120 * day)},
		{filepath.Join(shop, "src", "main.js"), "import './app.css'\nconsole.log('shop')\n", ago(2 * day)},
		{filepath.Join(shop, ".env"), "PORT=3000\nSTRIPE_SECRET_KEY=" + k["stripe-live-secret-key"] + "\nVITE_OPENAI_API_KEY=" + k["openai-project-key"] + "\n", ago(95 * day)},

		// Claude Code's MCP config with a GitHub token for the GitHub server.
		{filepath.Join(home, ".claude.json"), `{"mcpServers":{"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"],"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"` + k["github-pat-classic"] + `"}}}}` + "\n", ago(21 * day)},

		// An Anthropic admin key pasted into an AI chat, saved in the transcript.
		{filepath.Join(home, ".claude", "projects", "-home-me-code-shop", "0b7c.jsonl"), `{"type":"user","message":{"role":"user","content":"usage is weird, here is my admin key ` + k["anthropic-admin-key"] + ` can you check the billing API?"}}` + "\n", ago(9 * day)},

		// Shell history: a key exported by hand months ago.
		{filepath.Join(home, ".zsh_history"), ": 1700000000:0;cd code/shop\n: 1700000100:0;export ANTHROPIC_API_KEY=" + k["anthropic-api-key"] + "\n: 1700000200:0;npm run dev\n", ago(200 * day)},

		// A CLI login file: a key that is stored on purpose (lower priority).
		{filepath.Join(home, ".codex", "auth.json"), `{"OPENAI_API_KEY":"` + k["openai-service-account-key"] + `"}` + "\n", ago(40 * day)},

		// Cursor MCP config with a Supabase service_role key.
		{filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{"supabase":{"command":"npx","args":["-y","@supabase/mcp-server-supabase"],"env":{"SUPABASE_SERVICE_ROLE_KEY":"` + k["supabase-service-role-jwt"] + `"}}}}` + "\n", ago(33 * day)},
	}
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(f.path, []byte(f.body), 0o600); err != nil {
			return err
		}
	}

	// Git history: config.js with a key, committed a year ago, deleted later.
	git := func(when time.Time, args ...string) error {
		cmd := exec.Command("git", append([]string{"-c", "user.name=Me", "-c", "user.email=me@example.com", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
		cmd.Dir = shop
		stamp := when.Format(time.RFC3339)
		cmd.Env = append(os.Environ(), "HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_DATE="+stamp, "GIT_COMMITTER_DATE="+stamp)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	cfg := filepath.Join(shop, "config.js")
	steps := []func() error{
		func() error { return git(ago(400*day), "init", "-q") },
		func() error {
			return os.WriteFile(cfg, []byte("export const openai = '"+k["openai-legacy-key"]+"'\n"), 0o600)
		},
		func() error { return git(ago(400*day), "add", "config.js", ".gitignore", "src") },
		func() error { return git(ago(400*day), "commit", "-q", "-m", "first version") },
		func() error { return os.Remove(cfg) },
		func() error { return git(ago(300*day), "commit", "-q", "-am", "remove hardcoded key") },
	}
	for _, s := range steps {
		if err := s(); err != nil {
			return err
		}
	}
	for _, f := range files {
		if err := os.Chtimes(f.path, f.mod, f.mod); err != nil {
			return err
		}
	}
	return nil
}
