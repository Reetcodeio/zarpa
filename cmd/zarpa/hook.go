package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const hookMarker = "# zarpa pre-commit hook"

const hookUsage = `Usage:
  zarpa hook install [--force]   Block commits that add an API key (this repo)
  zarpa hook uninstall           Remove the hook (restores any hook it replaced)
  zarpa hook status              Show whether the hook is installed

For built frontends, add a check after your build step, e.g. in package.json:
  "postbuild": "zarpa scan --bundle dist"
`

// hookScript runs `zarpa scan --staged`. It prefers zarpa on PATH and
// falls back to the binary that installed the hook. A hook that existed
// before (saved as pre-commit.zarpa-backup) still runs afterwards.
func hookScript(selfPath string) string {
	return `#!/bin/sh
` + hookMarker + ` (installed by "zarpa hook install")
# Blocks commits that add an API key. Bypass once with: git commit --no-verify
KW="$(command -v zarpa 2>/dev/null)"
[ -z "$KW" ] && KW='` + strings.ReplaceAll(selfPath, "'", `'\''`) + `'
if [ -x "$KW" ]; then
  "$KW" scan --staged -q --no-color . || {
    echo "" >&2
    echo "zarpa: commit blocked because it adds the key(s) above." >&2
    echo "  Remove the key and keep it in the vault: zarpa vault add NAME" >&2
    echo "  Not a real key? Add  zarpa:allow  as a comment on that line." >&2
    echo "  Bypass once: git commit --no-verify" >&2
    exit 1
  }
else
  echo "zarpa: not found, skipping the secret check" >&2
fi
BACKUP="$(dirname "$0")/pre-commit.zarpa-backup"
[ -x "$BACKUP" ] && exec "$BACKUP" "$@"
exit 0
`
}

func cmdHook(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, hookUsage)
		return exitError
	}
	force := len(args) > 1 && args[1] == "--force"
	dir, err := hooksDir(".")
	if err != nil {
		fmt.Fprintln(stderr, "zarpa hook: not inside a git repository")
		return exitError
	}
	hook := filepath.Join(dir, "pre-commit")
	backup := hook + ".zarpa-backup"
	current, readErr := os.ReadFile(hook)
	ours := readErr == nil && strings.Contains(string(current), hookMarker)

	switch args[0] {
	case "install":
		if readErr == nil && !ours {
			if !force {
				fmt.Fprintf(stderr, "zarpa hook: %s already exists and is not Zarpa's.\n"+
					"Run again with --force to keep it (it will still run, after Zarpa's check).\n", hook)
				return exitError
			}
			if err := os.Rename(hook, backup); err != nil {
				fmt.Fprintln(stderr, "zarpa hook:", err)
				return exitError
			}
		}
		self, _ := os.Executable()
		// Git runs hooks with sh, also on Windows, where C:/x/zarpa.exe is
		// safer in a shell script than C:\x\zarpa.exe.
		self = filepath.ToSlash(self)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintln(stderr, "zarpa hook:", err)
			return exitError
		}
		if err := os.WriteFile(hook, []byte(hookScript(self)), 0o755); err != nil {
			fmt.Fprintln(stderr, "zarpa hook:", err)
			return exitError
		}
		fmt.Fprintf(stdout, "Installed %s. Commits that add an API key are now blocked.\n", hook)
	case "uninstall":
		if !ours {
			fmt.Fprintln(stdout, "No Zarpa hook installed here.")
			return exitClean
		}
		if err := os.Remove(hook); err != nil {
			fmt.Fprintln(stderr, "zarpa hook:", err)
			return exitError
		}
		if _, err := os.Stat(backup); err == nil {
			_ = os.Rename(backup, hook)
			fmt.Fprintln(stdout, "Removed the Zarpa hook and restored your previous pre-commit hook.")
		} else {
			fmt.Fprintln(stdout, "Removed the Zarpa hook.")
		}
	case "status":
		if ours {
			fmt.Fprintf(stdout, "Installed: %s\n", hook)
		} else {
			fmt.Fprintln(stdout, "Not installed. Run: zarpa hook install")
		}
	default:
		fmt.Fprint(stderr, hookUsage)
		return exitError
	}
	return exitClean
}

// hooksDir honours core.hooksPath and worktrees (git rev-parse --git-path).
// The answer is relative to dir when not absolute.
func hooksDir(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(string(out))
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	return filepath.Abs(p)
}
