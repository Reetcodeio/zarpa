package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"

	"github.com/Reetcodeio/zarpa/internal/report"
	"github.com/Reetcodeio/zarpa/internal/scan"
	"github.com/Reetcodeio/zarpa/internal/vault"
)

const vaultUsage = `Usage:
  zarpa vault add NAME          Store a key (paste it, or pipe it: pbpaste | zarpa vault add NAME)
  zarpa vault import FILE       Store every KEY=value line of a .env file
  zarpa vault ls                List stored names
  zarpa vault get NAME          Print a key (only into a pipe, or with --reveal)
  zarpa vault rm NAME           Delete a key

Names are env var names, like OPENAI_API_KEY. Keys live in your OS keychain.
`

// openVault is a variable so tests can swap in an in-memory vault.
var openVault = vault.Open

func cmdVault(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, vaultUsage)
		return exitError
	}
	v, err := openVault()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa vault:", err)
		return exitError
	}
	sub, rest := args[0], args[1:]
	need := func(n int) bool {
		if len(rest) != n {
			fmt.Fprint(stderr, vaultUsage)
			return false
		}
		return true
	}
	switch sub {
	case "add", "set":
		if !need(1) {
			return exitError
		}
		value, err := readSecret(stdin, stderr, "Paste the key for "+rest[0]+" (hidden), then press Enter: ")
		if err != nil {
			fmt.Fprintln(stderr, "zarpa vault:", err)
			return exitError
		}
		if err := v.Set(rest[0], value); err != nil {
			fmt.Fprintln(stderr, "zarpa vault:", err)
			return exitError
		}
		fmt.Fprintf(stdout, "Stored %s (%s).\n", rest[0], scan.Redact(strings.TrimSpace(value), 4))
	case "import":
		if !need(1) {
			return exitError
		}
		n, skipped, err := importEnvFile(v, rest[0])
		if err != nil {
			fmt.Fprintln(stderr, "zarpa vault:", err)
			return exitError
		}
		fmt.Fprintf(stdout, "Stored %d keys from %s.", n, rest[0])
		if len(skipped) > 0 {
			fmt.Fprintf(stdout, " Skipped (not valid names): %s.", strings.Join(skipped, ", "))
		}
		fmt.Fprintf(stdout, "\nRun your app with: zarpa run -- <command>\nThen delete %s so the keys stop living in plain text.\n", rest[0])
	case "ls", "list":
		names, err := v.List()
		if err != nil {
			fmt.Fprintln(stderr, "zarpa vault:", err)
			return exitError
		}
		if len(names) == 0 {
			fmt.Fprintln(stdout, "The vault is empty. Add a key with: zarpa vault add NAME")
			return exitClean
		}
		for _, n := range names {
			val, err := v.Get(n)
			disp := "(unreadable)"
			if err == nil {
				disp = scan.Redact(val, 4)
			}
			fmt.Fprintf(stdout, "%-32s %s\n", n, disp)
		}
	case "get":
		reveal := len(rest) == 2 && rest[1] == "--reveal"
		if len(rest) == 2 && rest[0] == "--reveal" {
			reveal, rest = true, rest[1:]
		}
		if len(rest) < 1 {
			fmt.Fprint(stderr, vaultUsage)
			return exitError
		}
		val, err := v.Get(rest[0])
		if err != nil {
			fmt.Fprintf(stderr, "zarpa vault: %s: %v\n", rest[0], err)
			return exitError
		}
		// Raw values go only into pipes or on explicit request, so a key does
		// not end up in a terminal scrollback or an AI tool's transcript.
		if f, ok := stdout.(*os.File); ok && report.IsTerminal(f) && !reveal {
			fmt.Fprintf(stdout, "%s = %s\n(use --reveal to print it, or pipe it: zarpa vault get %s | pbcopy)\n",
				rest[0], scan.Redact(val, 4), rest[0])
			return exitClean
		}
		fmt.Fprint(stdout, val)
	case "rm", "delete":
		if !need(1) {
			return exitError
		}
		if err := v.Delete(rest[0]); err != nil {
			fmt.Fprintf(stderr, "zarpa vault: %s: %v\n", rest[0], err)
			return exitError
		}
		fmt.Fprintf(stdout, "Deleted %s.\n", rest[0])
	default:
		fmt.Fprint(stderr, vaultUsage)
		return exitError
	}
	return exitClean
}

// readSecret reads one line. On a terminal it turns echo off so the key is
// not shown on screen.
func readSecret(stdin io.Reader, stderr io.Writer, prompt string) (string, error) {
	if f, ok := stdin.(*os.File); ok && report.IsTerminal(f) {
		fmt.Fprint(stderr, prompt)
		if err := stty(f, "-echo"); err == nil {
			defer func() { _ = stty(f, "echo"); fmt.Fprintln(stderr) }()
		}
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", errors.New("no key given")
	}
	return line, nil
}

func stty(tty *os.File, arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = tty
	return cmd.Run()
}

// importEnvFile stores KEY=value lines. It understands `export KEY=...`,
// quotes and comments.
func importEnvFile(v *vault.Vault, path string) (int, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	n := 0
	var skipped []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' || val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		} else if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		if val == "" {
			continue
		}
		if !vault.ValidName(k) {
			skipped = append(skipped, k)
			continue
		}
		if err := v.Set(k, val); err != nil {
			return n, skipped, fmt.Errorf("%s: %w", k, err)
		}
		n++
	}
	return n, skipped, sc.Err()
}

const runUsage = `Usage: zarpa run [--only NAME,NAME] -- command [args...]

Starts the command with your vault keys as environment variables, so the
app reads OPENAI_API_KEY etc. without a .env file on disk.
`

func cmdRun(args []string, stdout, stderr io.Writer) int {
	var only []string
	i := 0
	for i < len(args) && args[i] != "--" {
		switch {
		case args[i] == "--only" && i+1 < len(args):
			only = strings.Split(args[i+1], ",")
			i += 2
		case strings.HasPrefix(args[i], "--only="):
			only = strings.Split(strings.TrimPrefix(args[i], "--only="), ",")
			i++
		default:
			fmt.Fprint(stderr, runUsage)
			return exitError
		}
	}
	if i >= len(args)-1 {
		fmt.Fprint(stderr, runUsage)
		return exitError
	}
	command := args[i+1:]
	v, err := openVault()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa run:", err)
		return exitError
	}
	env, names, err := v.Env(only)
	if err != nil {
		fmt.Fprintln(stderr, "zarpa run:", err)
		return exitError
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	fmt.Fprintf(stderr, "zarpa: starting %s with %d %s from the vault\n", command[0], len(names), pluralize(len(names), "key", "keys"))
	// Ctrl+C reaches the child directly (same process group); just don't die first.
	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintln(stderr, "zarpa run:", err)
		return 127
	}
	return 0
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
