package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Reetcodeio/zarpa/internal/live"
	"github.com/Reetcodeio/zarpa/internal/report"
	"github.com/Reetcodeio/zarpa/internal/scan"
)

// runChecks tests found keys against their providers, after the user agrees.
// Keys found only in other people's commits are never tested: using
// someone else's credential, even read-only, is not ours to do.
func runChecks(ctx context.Context, res *scan.Result, yes bool, stderr io.Writer) int {
	defer func() {
		for _, f := range res.Findings {
			f.ForgetSecret()
		}
	}()
	var jobs []live.Job
	byID := map[string]*scan.Finding{}
	perProvider := map[string]int{}
	for _, f := range res.Findings {
		switch {
		case f.Category == scan.CategoryOthers:
			f.Liveness, f.LiveDetail = "not_checked", "someone else's key"
		case !live.Supported(f.RuleID):
			f.Liveness = string(live.Unsupported)
		case f.Secret() == "":
			f.Liveness = string(live.Unknown)
		default:
			jobs = append(jobs, live.Job{ID: f.Fingerprint, RuleID: f.RuleID, Key: f.Secret()})
			byID[f.Fingerprint] = f
			perProvider[f.Provider]++
		}
	}
	if len(jobs) == 0 {
		return exitClean
	}
	var parts []string
	for p, n := range perProvider {
		parts = append(parts, fmt.Sprintf("%s %d", p, n))
	}
	sort.Strings(parts)
	fmt.Fprintf(stderr, "zarpa check will test %d %s with one read-only call each, sent only to the provider that issued it (%s).\n",
		len(jobs), pluralize(len(jobs), "key", "keys"), strings.Join(parts, ", "))
	if !yes {
		if !report.IsTerminal(os.Stdin) {
			fmt.Fprintln(stderr, "zarpa: not a terminal; add --yes to confirm")
			return exitError
		}
		fmt.Fprint(stderr, "Continue? [y/N] ")
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			fmt.Fprintln(stderr, "Skipped the checks.")
			return exitClean
		}
	}
	for id, r := range live.CheckAll(ctx, jobs, live.Options{}) {
		if f := byID[id]; f != nil {
			f.Liveness, f.LiveDetail = string(r.Status), r.Detail
		}
	}
	return exitClean
}
