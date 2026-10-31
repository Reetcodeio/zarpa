// Command zarpa finds API keys on a machine and (in later releases)
// watches and freezes them.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Reetcodeio/zarpa/internal/fingerprint"
	"github.com/Reetcodeio/zarpa/internal/report"
	"github.com/Reetcodeio/zarpa/internal/scan"
	"github.com/Reetcodeio/zarpa/internal/version"
	"github.com/Reetcodeio/zarpa/rules"
)

// Exit codes.
const (
	exitClean    = 0 // nothing found
	exitFindings = 1 // keys found
	exitError    = 2
)

const usage = `Zarpa finds every API key on your machine and shows where it lives.

Usage:
  zarpa scan [path ...] [flags]   Find keys in folders, git history, MCP configs,
                                  AI tool transcripts, shell history and dotfiles
  zarpa scan --bundle ./dist      Find secret keys in a built frontend (ships to browsers)
  zarpa check [path ...]          Scan, then test which found keys still work
  zarpa vault add|ls|get|rm|import  Keep keys in your OS keychain
  zarpa run -- <command>          Start a command with vault keys as env vars
  zarpa hook install              Block commits that add a key (this repo)
  zarpa login --api URL           Link this machine to your Zarpa account (paid stage)
  zarpa sync [path ...]           Upload fingerprints and locations (never keys) to it
  zarpa panic --tool T | --all    Freeze every matching key at once, then get a checklist
  zarpa logout                    Remove this machine's CLI token
  zarpa rules                     List the detection rules
  zarpa version                   Print the version

Run "zarpa scan -h" for scan flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "check":
		return cmdScan(append([]string{"--check"}, args[1:]...), stdout, stderr)
	case "vault":
		return cmdVault(args[1:], os.Stdin, stdout, stderr)
	case "run":
		return cmdRun(args[1:], stdout, stderr)
	case "hook":
		return cmdHook(args[1:], stdout, stderr)
	case "rules":
		return cmdRules(stdout, stderr)
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "zarpa %s (%s, %s) %s/%s\n", version.Version, version.Commit, version.Date, runtime.GOOS, runtime.GOARCH)
		return exitClean
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitClean
	case "login":
		return cmdLogin(args[1:], os.Stdin, stdout, stderr)
	case "logout":
		return cmdLogout(stdout, stderr)
	case "sync":
		return cmdSync(args[1:], os.Stdin, stdout, stderr)
	case "panic":
		return cmdPanic(args[1:], os.Stdin, stdout, stderr)
	}
	fmt.Fprintf(stderr, "zarpa: unknown command %q\n\n%s", args[0], usage)
	return exitError
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var (
		format     = fl.String("format", "text", "output format: text, json or sarif")
		asJSON     = fl.Bool("json", false, "shorthand for --format json")
		asSARIF    = fl.Bool("sarif", false, "shorthand for --format sarif")
		outFile    = fl.String("o", "", "write the report to this file instead of stdout")
		verbose    = fl.Bool("v", false, "list every location of every key")
		noGit      = fl.Bool("no-git", false, "skip git history")
		noMachine  = fl.Bool("no-machine", false, "skip MCP configs, AI transcripts, shell history and dotfiles")
		minSev     = fl.String("min-severity", "low", "hide findings below: critical, high, medium, low")
		maxFileMB  = fl.Int("max-file-mb", 5, "largest regular file to read, in MB")
		maxCommits = fl.Int("max-commits", 0, "newest commits to read per repo (0 = all)")
		workers    = fl.Int("workers", runtime.NumCPU(), "parallel scanners")
		exitZero   = fl.Bool("exit-zero", false, "exit 0 even when keys are found")
		noColor    = fl.Bool("no-color", false, "disable colors")
		saltFile   = fl.String("salt-file", "", "keep the fingerprint salt in this file instead of the keychain")
		rulesFile  = fl.String("rules", "", "load detection rules from this JSON file")
		home       = fl.String("home", "", "home directory to scan for machine sources (default: yours)")
		quiet      = fl.Bool("q", false, "no progress line")
		bundle     = fl.Bool("bundle", false, "paths are built frontend output (dist/, build/, .next): flag every key in them")
		staged     = fl.Bool("staged", false, "scan only changes staged for commit (used by the pre-commit hook)")
		check      = fl.Bool("check", false, "after scanning, test which keys still work (one read-only call per key to its provider)")
		yes        = fl.Bool("yes", false, "with --check: do not ask for confirmation")
	)
	fl.Usage = func() {
		fmt.Fprintln(stderr, "Usage: zarpa scan [path ...] [flags]\n\nWith no path, scans the current folder. Machine sources (MCP configs,\nAI transcripts, shell history, dotfiles) are always included unless --no-machine.\n\nFlags:")
		fl.PrintDefaults()
	}
	paths, err := parseInterleaved(fl, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitClean
		}
		return exitError
	}
	if *asJSON {
		*format = "json"
	}
	if *asSARIF {
		*format = "sarif"
	}
	switch *format {
	case "text", "json", "sarif":
	default:
		fmt.Fprintf(stderr, "zarpa: unknown format %q\n", *format)
		return exitError
	}
	if rules.Rank(*minSev) == 0 {
		fmt.Fprintf(stderr, "zarpa: unknown severity %q\n", *minSev)
		return exitError
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(stderr, "zarpa: %s: no such file or folder\n", p)
			return exitError
		}
	}

	set, err := loadRules(*rulesFile)
	if err != nil {
		fmt.Fprintln(stderr, "zarpa:", err)
		return exitError
	}
	hasher, err := fingerprint.Open(*saltFile)
	if err != nil {
		fmt.Fprintln(stderr, "zarpa:", err)
		return exitError
	}
	if *bundle || *staged {
		*noGit, *noMachine = true, true
	}
	h := *home
	if h == "" {
		h = scan.HomeDir()
	}
	if abs, err := filepath.Abs(h); err == nil && h != "" {
		h = abs
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var prog *scan.Progress
	stopProgress := func() {}
	if !*quiet && stderr == io.Writer(os.Stderr) && report.IsTerminal(os.Stderr) {
		prog = &scan.Progress{}
		stopProgress = showProgress(os.Stderr, prog, h)
	}
	res, err := scan.Run(ctx, scan.Config{
		Progress:    prog,
		Paths:       paths,
		Home:        h,
		AppData:     appDataFor(*home),
		Git:         !*noGit,
		Machine:     !*noMachine,
		Workers:     *workers,
		MaxFileSize: int64(*maxFileMB) << 20,
		MaxCommits:  *maxCommits,
		MinSeverity: *minSev,
		Rules:       set,
		Hasher:      hasher,
		Bundle:      *bundle,
		Staged:      *staged,
		KeepSecrets: *check,
	})
	stopProgress()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa:", err)
		return exitError
	}
	if *check {
		if code := runChecks(ctx, res, *yes, stderr); code != exitClean {
			return code
		}
	}

	out := stdout
	color := !*noColor && os.Getenv("NO_COLOR") == "" && stdout == io.Writer(os.Stdout) && report.IsTerminal(os.Stdout)
	if *outFile != "" {
		f, err := os.OpenFile(*outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "zarpa:", err)
			return exitError
		}
		defer f.Close()
		out, color = f, false
	}
	switch *format {
	case "json":
		err = report.JSON(out, res)
	case "sarif":
		base, _ := filepath.Abs(paths[0])
		err = report.SARIF(out, res, set, base)
	default:
		report.Text(out, res, report.TextOptions{Color: color, Verbose: *verbose, Compact: *staged})
	}
	if err != nil {
		fmt.Fprintln(stderr, "zarpa:", err)
		return exitError
	}
	if len(res.Findings) > 0 && !*exitZero {
		return exitFindings
	}
	return exitClean
}

// showProgress redraws one status line on w until the returned func is called.
// It names the stage and, when a file takes long, which one, so a slow
// network or iCloud file is visible instead of looking like a hang.
func showProgress(w io.Writer, p *scan.Progress, home string) func() {
	done := make(chan struct{})
	finished := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(finished)
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				fmt.Fprint(w, "\r\x1b[2K")
				return
			case <-t.C:
				stage, cur, since := p.Snapshot()
				line := fmt.Sprintf("Scanning %s · %d files · %d commits · %s",
					stage, p.Files.Load(), p.Commits.Load(), time.Since(start).Round(time.Second))
				if since > 5*time.Second && cur != "" {
					line += fmt.Sprintf(" · slow: %s (%s)", tildify(cur, home), since.Round(time.Second))
				}
				// Never wider than the window: a wrapped line cannot be redrawn in place.
				if max := termWidth(os.Stderr) - 1; max > 10 {
					if r := []rune(line); len(r) > max {
						line = string(r[:max-1]) + "…"
					}
				}
				fmt.Fprint(w, "\r\x1b[2K"+line)
			}
		}
	}()
	return func() {
		select {
		case <-done:
		default:
			close(done)
			<-finished
		}
	}
}

func tildify(p, home string) string {
	if home != "" && strings.HasPrefix(p, home+string(filepath.Separator)) {
		return "~" + p[len(home):]
	}
	return p
}

func cmdRules(stdout, stderr io.Writer) int {
	set, err := rules.Load()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "Rules version %s · %d rules\n\n", set.Version, len(set.Rules))
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPROVIDER\tSEVERITY\tNAME")
	for _, r := range set.Rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Provider, r.Severity, r.Name)
	}
	tw.Flush()
	return exitClean
}

func loadRules(path string) (*rules.Set, error) {
	if path == "" {
		return rules.Load()
	}
	return rules.LoadFile(path)
}

// parseInterleaved lets flags appear before, between or after paths.
func parseInterleaved(fl *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fl.Parse(args); err != nil {
			return nil, err
		}
		rest := fl.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
		if strings.HasPrefix(rest[0], "-") && rest[0] != "-" {
			return nil, fmt.Errorf("bad argument %q", rest[0])
		}
	}
}

// appDataFor returns Windows' %APPDATA% when scanning the real home folder.
// With --home, the scan stays inside that folder (<home>\AppData\Roaming).
func appDataFor(homeFlag string) string {
	if homeFlag != "" {
		return ""
	}
	return os.Getenv("APPDATA")
}
