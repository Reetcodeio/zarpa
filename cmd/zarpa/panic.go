package main

// zarpa panic: freeze every key in a scope at once through the cloud, then
// print a checklist for what can't be automated.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const panicUsage = `Usage:
  zarpa panic --all | --provider P | --tool T | --tag T [flags]
  zarpa panic status [RUN_ID]      the latest run (or RUN_ID) and its checklist
  zarpa panic done N               mark checklist step N of the latest run as done

Freezes every matching key on your connected provider accounts (Anthropic,
Google), then lists what you still need to do: rotate keys Zarpa can't
freeze (OpenAI, Stripe, keys on accounts you haven't connected) and replace
the frozen ones. Freezing can be undone; nothing is deleted.

  --tool T   keys found where tool T keeps its files, e.g. --tool opencode
             (matches the places zarpa sync uploaded)

Flags:
`

var (
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	panicCtxTO = 5 * time.Minute
)

type panicItem struct {
	ID     string `json:"id"`
	KeyID  string `json:"key_id"`
	Step   string `json:"step"`
	Status string `json:"status"`
	Title  string `json:"title"`
	Note   string `json:"note"`
}

type panicReply struct {
	RunID   string `json:"run_id"`
	Summary struct {
		ToFreeze int `json:"to_freeze"`
		Frozen   int `json:"frozen"`
		Failed   int `json:"failed"`
		Skipped  int `json:"skipped"`
		Manual   int `json:"manual"`
		Todo     int `json:"todo"`
	} `json:"summary"`
	Items []panicItem `json:"items"`
}

func cmdPanic(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return panicStatus(args[1:], stdout, stderr)
		case "done":
			return panicDone(args[1:], stdout, stderr)
		}
	}
	fl := flag.NewFlagSet("panic", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var (
		all       = fl.Bool("all", false, "every key on the account")
		provider  = fl.String("provider", "", "only keys of this provider (anthropic, google, openai, ...)")
		tool      = fl.String("tool", "", "only keys found in this tool's files")
		tag       = fl.String("tag", "", "only keys with this tag")
		protected = fl.Bool("include-protected", false, "also freeze keys marked never-auto-kill")
		dryRun    = fl.Bool("dry-run", false, "show what would happen, change nothing")
		yes       = fl.Bool("yes", false, "do not ask for confirmation")
	)
	fl.Usage = func() { fmt.Fprint(stderr, panicUsage); fl.PrintDefaults() }
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitClean
		}
		return exitError
	}
	if fl.NArg() > 0 {
		fmt.Fprintf(stderr, "zarpa panic: unexpected %q\n", fl.Arg(0))
		return exitError
	}
	scope := map[string]any{}
	if *all {
		scope["all"] = true
	}
	for k, v := range map[string]string{"provider": *provider, "tool": *tool, "tag": *tag} {
		if v != "" {
			scope[k] = strings.TrimSpace(v)
		}
	}
	if len(scope) == 0 {
		fmt.Fprintln(stderr, "zarpa panic: say what to freeze: --all, --provider, --tool or --tag")
		return exitError
	}
	if *all && len(scope) > 1 {
		fmt.Fprintln(stderr, "zarpa panic: --all can't be combined with other filters")
		return exitError
	}
	if *protected {
		scope["include_protected"] = true
	}

	api, token, ok := cloudLogin("panic", stderr)
	if !ok {
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), panicCtxTO)
	defer cancel()

	// Always look first: the plan says how many keys a freeze would touch.
	plan, code := panicPost(ctx, api, token, scope, true, stderr)
	if code != exitClean {
		return code
	}
	s := plan.Summary
	if s.ToFreeze+s.Frozen+s.Failed+s.Skipped+s.Manual == 0 {
		fmt.Fprintln(stdout, "No keys match. Upload scan results first with: zarpa sync ~")
		return exitClean
	}
	fmt.Fprintf(stdout, "%d %s to freeze", s.ToFreeze, pluralize(s.ToFreeze, "key", "keys"))
	if s.Frozen > 0 {
		fmt.Fprintf(stdout, ", %d already frozen", s.Frozen)
	}
	if s.Skipped > 0 {
		fmt.Fprintf(stdout, ", %d protected (left running)", s.Skipped)
	}
	fmt.Fprintf(stdout, ". %d %s for you afterwards.\n", s.Manual, pluralize(s.Manual, "step", "steps"))
	if *dryRun {
		printPanicItems(stdout, plan.Items)
		return exitClean
	}
	if s.ToFreeze > 0 && !*yes {
		if !isTerminalIn() {
			fmt.Fprintln(stderr, "zarpa panic: not a terminal; add --yes to confirm")
			return exitError
		}
		fmt.Fprintf(stderr, "Freeze %d %s now? Type freeze to go on: ", s.ToFreeze, pluralize(s.ToFreeze, "key", "keys"))
		ans, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(ans)) != "freeze" {
			fmt.Fprintln(stderr, "Nothing frozen.")
			return exitClean
		}
	}
	res, code := panicPost(ctx, api, token, scope, false, stderr)
	if code != exitClean {
		return code
	}
	fmt.Fprintf(stdout, "\nFrozen %d, failed %d, protected %d. Run %s\n", res.Summary.Frozen, res.Summary.Failed, res.Summary.Skipped, res.RunID)
	printPanicItems(stdout, res.Items)
	if res.Summary.Todo > 0 {
		fmt.Fprintln(stdout, "\nMark a step done with: zarpa panic done N   (see it again: zarpa panic status)")
	}
	if res.Summary.Failed > 0 {
		return exitFindings
	}
	return exitClean
}

func panicPost(ctx context.Context, api, token string, scope map[string]any, dry bool, stderr io.Writer) (panicReply, int) {
	body := map[string]any{"dry_run": dry}
	for k, v := range scope {
		body[k] = v
	}
	var r panicReply
	status, out, err := apiCall(ctx, "POST", api, "/v1/panic", token, body)
	if err != nil {
		fmt.Fprintf(stderr, "zarpa panic: can't reach %s: %v\n", api, err)
		return r, exitError
	}
	if status != http.StatusOK && status != http.StatusCreated {
		msg := apiErrorMessage(status, out)
		if status == http.StatusUnauthorized {
			msg += ". Log in again: zarpa login"
		}
		fmt.Fprintln(stderr, "zarpa panic:", msg)
		return r, exitError
	}
	if err := json.Unmarshal(out, &r); err != nil {
		fmt.Fprintln(stderr, "zarpa panic: unexpected reply from the API")
		return r, exitError
	}
	return r, exitClean
}

// printPanicItems prints freezes as a result list and people's steps as a
// numbered checklist (numbers are what "zarpa panic done N" takes).
func printPanicItems(w io.Writer, items []panicItem) {
	n := 0
	header := false
	for _, it := range items {
		if it.Step == "freeze" {
			mark := map[string]string{"done": "✓", "failed": "✗", "skipped": "–", "todo": "·"}[it.Status]
			fmt.Fprintf(w, "  %s %s%s\n", mark, oneLine(it.Title), noteSuffix(it.Note))
			continue
		}
		if !header {
			fmt.Fprintln(w, "\nChecklist:")
			header = true
		}
		n++
		box := "[ ]"
		if it.Status == "done" {
			box = "[x]"
		} else if it.Status == "skipped" {
			box = "[-]"
		}
		fmt.Fprintf(w, "  %d. %s %s\n", n, box, oneLine(it.Title))
		if it.Note != "" {
			fmt.Fprintf(w, "        %s\n", oneLine(it.Note))
		}
	}
}

func noteSuffix(n string) string {
	if n == "" {
		return ""
	}
	return ": " + oneLine(n)
}

// oneLine keeps API text to one printable line (it ends up in a terminal).
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func latestRun(ctx context.Context, api, token string) (string, error) {
	status, out, err := apiCall(ctx, "GET", api, "/v1/panic", token, nil)
	if err != nil {
		return "", fmt.Errorf("can't reach %s: %v", api, err)
	}
	if status != http.StatusOK {
		return "", errors.New(apiErrorMessage(status, out))
	}
	var r struct {
		Runs []struct {
			ID string `json:"id"`
		} `json:"runs"`
	}
	_ = json.Unmarshal(out, &r)
	if len(r.Runs) == 0 || !uuidRe.MatchString(r.Runs[0].ID) {
		return "", errors.New("no panic runs yet")
	}
	return r.Runs[0].ID, nil
}

func getRun(ctx context.Context, api, token, id string) ([]panicItem, string, error) {
	status, out, err := apiCall(ctx, "GET", api, "/v1/panic/"+id, token, nil)
	if err != nil {
		return nil, "", fmt.Errorf("can't reach %s: %v", api, err)
	}
	if status != http.StatusOK {
		return nil, "", errors.New(apiErrorMessage(status, out))
	}
	var r struct {
		CreatedAt  string      `json:"created_at"`
		FinishedAt *string     `json:"finished_at"`
		Items      []panicItem `json:"items"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, "", errors.New("unexpected reply from the API")
	}
	state := "started " + r.CreatedAt
	if r.FinishedAt != nil {
		state += ", every step done " + *r.FinishedAt
	}
	return r.Items, state, nil
}

func panicStatus(args []string, stdout, stderr io.Writer) int {
	api, token, ok := cloudLogin("panic", stderr)
	if !ok {
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := ""
	if len(args) > 0 {
		id = args[0]
		if !uuidRe.MatchString(id) {
			fmt.Fprintln(stderr, "zarpa panic status: RUN_ID must be a run id")
			return exitError
		}
	} else {
		var err error
		if id, err = latestRun(ctx, api, token); err != nil {
			fmt.Fprintln(stderr, "zarpa panic status:", err)
			return exitError
		}
	}
	items, state, err := getRun(ctx, api, token, id)
	if err != nil {
		fmt.Fprintln(stderr, "zarpa panic status:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "Panic run %s (%s)\n", id, state)
	printPanicItems(stdout, items)
	return exitClean
}

func panicDone(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "Usage: zarpa panic done N   (N from zarpa panic status)")
		return exitError
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 {
		fmt.Fprintln(stderr, "zarpa panic done: N must be a step number from zarpa panic status")
		return exitError
	}
	api, token, ok := cloudLogin("panic", stderr)
	if !ok {
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id, err := latestRun(ctx, api, token)
	if err == nil {
		var items []panicItem
		if items, _, err = getRun(ctx, api, token, id); err == nil {
			var steps []panicItem
			for _, it := range items {
				if it.Step == "manual" {
					steps = append(steps, it)
				}
			}
			if n > len(steps) {
				err = fmt.Errorf("the latest run has %d %s", len(steps), pluralize(len(steps), "step", "steps"))
			} else if !uuidRe.MatchString(steps[n-1].ID) {
				err = errors.New("unexpected reply from the API")
			} else {
				var status int
				var out []byte
				status, out, err = apiCall(ctx, "PATCH", api, "/v1/panic/"+id+"/items/"+steps[n-1].ID, token, map[string]string{"status": "done"})
				if err == nil && status != http.StatusOK {
					err = errors.New(apiErrorMessage(status, out))
				}
				if err == nil {
					var r struct {
						RunFinished bool `json:"run_finished"`
					}
					_ = json.Unmarshal(out, &r)
					fmt.Fprintf(stdout, "Done: %s\n", oneLine(steps[n-1].Title))
					if r.RunFinished {
						fmt.Fprintln(stdout, "Every step of this panic run is done.")
					}
					return exitClean
				}
			}
		}
	}
	fmt.Fprintln(stderr, "zarpa panic done:", err)
	return exitError
}
