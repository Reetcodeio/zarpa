package main

// zarpa login / logout / sync: the link to the paid cloud.
//
// sync uploads this and nothing more (docs/SECURITY.md lists it): for each
// key, its salted fingerprint (HMAC, not reversible), provider, last 4
// characters, where it was found, and whether it ships to browsers. Raw keys
// never leave the machine, and keys found only in other people's commits are
// not sent at all.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Reetcodeio/zarpa/internal/fingerprint"
	"github.com/Reetcodeio/zarpa/internal/report"
	"github.com/Reetcodeio/zarpa/internal/scan"
	"github.com/Reetcodeio/zarpa/internal/vault"
	"github.com/Reetcodeio/zarpa/internal/version"
)

const tokenAccount = "cli-token"

var cliTokenRe = regexp.MustCompile(`^zarpa_[A-Za-z0-9_-]{43}$`)

// Swapped in tests.
var (
	openSecrets = vault.OpenSecrets
	configDir   = func() (string, error) {
		d, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(d, "zarpa"), nil
	}
	isTerminalIn = func() bool { return report.IsTerminal(os.Stdin) }
)

type cloudConfig struct {
	APIURL   string `json:"api_url"`
	DeviceID string `json:"device_id"`
}

func loadCloudConfig() (cloudConfig, string, error) {
	dir, err := configDir()
	if err != nil {
		return cloudConfig{}, "", err
	}
	path := filepath.Join(dir, "cloud.json")
	var c cloudConfig
	b, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(b, &c)
	} else if !errors.Is(err, os.ErrNotExist) {
		return c, path, err
	}
	if c.DeviceID == "" {
		var r [12]byte
		_, _ = rand.Read(r[:])
		c.DeviceID = runtime.GOOS + "-" + hex.EncodeToString(r[:])
	}
	return c, path, nil
}

func saveCloudConfig(c cloudConfig, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// checkAPIURL allows https anywhere and plain http only to this machine (local development).
func checkAPIURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q is not a valid API URL", raw)
	}
	host := u.Hostname()
	local := host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return "", errors.New("the API URL must use https:// (http:// is allowed only for localhost)")
	}
	return u.String(), nil
}

func apiClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		// A redirect could carry the token somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") },
	}
}

func apiCall(ctx context.Context, method, base, path, token string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "zarpa-cli/"+version.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := apiClient().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, out, nil
}

func apiErrorMessage(status int, body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	return fmt.Sprintf("HTTP %d", status)
}

const loginUsage = `Usage: zarpa login [--api URL]

Links this machine to your Zarpa account. Create a CLI token in the
dashboard (Settings, CLI tokens), then paste it here. The token is kept in
your OS keychain. CLI tokens can upload scan results and read; changes to
your account need the dashboard.
`

func cmdLogin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("login", flag.ContinueOnError)
	fl.SetOutput(stderr)
	apiFlag := fl.String("api", "", "Zarpa API URL (or set ZARPA_API_URL)")
	fl.Usage = func() { fmt.Fprint(stderr, loginUsage); fl.PrintDefaults() }
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitClean
		}
		return exitError
	}
	cfg, path, err := loadCloudConfig()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa login:", err)
		return exitError
	}
	raw := firstNonEmpty(*apiFlag, os.Getenv("ZARPA_API_URL"), cfg.APIURL)
	if raw == "" {
		fmt.Fprintln(stderr, "zarpa login: give the API URL with --api https://… (it is remembered afterwards)")
		return exitError
	}
	api, err := checkAPIURL(raw)
	if err != nil {
		fmt.Fprintln(stderr, "zarpa login:", err)
		return exitError
	}
	token, err := readSecret(stdin, stderr, "Paste your CLI token (hidden), then press Enter: ")
	if err != nil {
		fmt.Fprintln(stderr, "zarpa login:", err)
		return exitError
	}
	if !cliTokenRe.MatchString(token) {
		fmt.Fprintln(stderr, "zarpa login: that is not a Zarpa CLI token (they start with zarpa_)")
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, body, err := apiCall(ctx, "GET", api, "/v1/me", token, nil)
	if err != nil {
		fmt.Fprintf(stderr, "zarpa login: can't reach %s: %v\n", api, err)
		return exitError
	}
	if status != http.StatusOK {
		fmt.Fprintln(stderr, "zarpa login:", apiErrorMessage(status, body))
		return exitError
	}
	var me struct {
		Account struct {
			Name string `json:"name"`
		} `json:"account"`
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.Unmarshal(body, &me)
	secrets, err := openSecrets()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa login:", err)
		return exitError
	}
	if err := secrets.Set(tokenAccount, token); err != nil {
		fmt.Fprintln(stderr, "zarpa login:", err)
		return exitError
	}
	cfg.APIURL = api
	if err := saveCloudConfig(cfg, path); err != nil {
		fmt.Fprintln(stderr, "zarpa login:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "Logged in as %s (%s). Upload scan results with: zarpa sync ~\n", firstNonEmpty(me.User.Email, "you"), api)
	return exitClean
}

func cmdLogout(stdout, stderr io.Writer) int {
	secrets, err := openSecrets()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa logout:", err)
		return exitError
	}
	if err := secrets.Delete(tokenAccount); err != nil {
		fmt.Fprintln(stderr, "zarpa logout:", err)
		return exitError
	}
	fmt.Fprintln(stdout, "Logged out on this machine. To stop the token working everywhere, revoke it in the dashboard (Settings, CLI tokens).")
	return exitClean
}

// syncKey is one entry of POST /v1/sync (connectors/core ScannedKey).
type syncKey struct {
	Fingerprint string `json:"fingerprint"`
	// The same key's fingerprint under this machine's own salt (older CLIs sent that one).
	PreviousFingerprint string   `json:"previous_fingerprint,omitempty"`
	Provider            string   `json:"provider"`
	Last4               string   `json:"last4"`
	Locations           []string `json:"locations"`
	PublicExposure      bool     `json:"public_exposure"`
	FirstSeen           string   `json:"first_seen"`
}

const (
	syncBatch        = 2000
	syncMaxLocations = 200
)

func cmdSync(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("sync", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var (
		noGit     = fl.Bool("no-git", false, "skip git history")
		noMachine = fl.Bool("no-machine", false, "skip MCP configs, AI transcripts, shell history and dotfiles")
		yes       = fl.Bool("yes", false, "do not ask for confirmation")
		dryRun    = fl.Bool("dry-run", false, "print what would be uploaded, upload nothing")
		quiet     = fl.Bool("q", false, "no progress line")
		saltFile  = fl.String("salt-file", "", "this machine's fingerprint salt file instead of the keychain (uploads use your account's salt)")
		home      = fl.String("home", "", "home directory for machine sources (default: yours)")
	)
	fl.Usage = func() {
		fmt.Fprintln(stderr, "Usage: zarpa sync [path ...] [flags]\n\nScans like `zarpa scan`, then uploads fingerprints and locations (never the keys)\nto your Zarpa account, so the cloud can tie each key to where it lives.\n\nFlags:")
		fl.PrintDefaults()
	}
	paths, err := parseInterleaved(fl, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitClean
		}
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
	cfg, _, err := loadCloudConfig()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa sync:", err)
		return exitError
	}
	var api, token string
	loggedIn := false
	if *dryRun {
		// A dry run needs no login, but shows the real fingerprints when there is one.
		api, token, loggedIn = cloudLogin("sync", io.Discard)
	} else {
		if api, token, loggedIn = cloudLogin("sync", stderr); !loggedIn {
			return exitError
		}
	}

	set, err := loadRules("")
	if err != nil {
		fmt.Fprintln(stderr, "zarpa:", err)
		return exitError
	}
	hasher, err := fingerprint.Open(*saltFile)
	if err != nil {
		fmt.Fprintln(stderr, "zarpa:", err)
		return exitError
	}
	// Uploads use the account's salt, so the same key on two machines gets one
	// fingerprint. Each key's old per-machine fingerprint goes along once, so
	// the cloud can re-key what earlier syncs sent.
	var account *fingerprint.Hasher
	if loggedIn {
		actx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		account, err = accountHasher(actx, api, token)
		cancel()
		if err != nil && !*dryRun {
			fmt.Fprintln(stderr, "zarpa sync:", err)
			return exitError
		}
		if account == nil {
			fmt.Fprintln(stderr, "zarpa sync: no shared fingerprint salt from the API; using this machine's.")
		}
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
		Progress: prog, Paths: paths, Home: h, AppData: appDataFor(*home),
		Git: !*noGit, Machine: !*noMachine, Workers: runtime.NumCPU(), MaxFileSize: 5 << 20,
		MinSeverity: "low", Rules: set, Hasher: hasher, KeepSecrets: account != nil,
	})
	stopProgress()
	if err != nil {
		fmt.Fprintln(stderr, "zarpa:", err)
		return exitError
	}

	keys, skipped := syncPayload(res, time.Now(), account)
	if len(keys) == 0 {
		fmt.Fprintln(stdout, "No keys to upload.")
		return exitClean
	}
	if *dryRun {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(keys)
		return exitClean
	}
	fmt.Fprintf(stderr, "zarpa sync will upload %d %s to %s: fingerprints, providers, last 4 characters and locations. Raw keys stay on this machine.",
		len(keys), pluralize(len(keys), "key", "keys"), api)
	if skipped > 0 {
		fmt.Fprintf(stderr, " (%d found only in other people's commits are not sent.)", skipped)
	}
	fmt.Fprintln(stderr)
	if !*yes {
		if !isTerminalIn() {
			fmt.Fprintln(stderr, "zarpa: not a terminal; add --yes to confirm")
			return exitError
		}
		fmt.Fprint(stderr, "Continue? [y/N] ")
		ans, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			fmt.Fprintln(stderr, "Nothing uploaded.")
			return exitClean
		}
	}

	var received, matched, created int
	for i := 0; i < len(keys); i += syncBatch {
		end := min(i+syncBatch, len(keys))
		body := map[string]any{
			"cli_version": version.Version, "rules_version": set.Version, "device_id": cfg.DeviceID, "keys": keys[i:end],
		}
		status, out, err := apiCall(ctx, "POST", api, "/v1/sync", token, body)
		if err != nil {
			fmt.Fprintf(stderr, "zarpa sync: can't reach %s: %v\n", api, err)
			return exitError
		}
		if status != http.StatusOK {
			msg := apiErrorMessage(status, out)
			if status == http.StatusUnauthorized {
				msg += ". Log in again: zarpa login"
			}
			fmt.Fprintln(stderr, "zarpa sync:", msg)
			return exitError
		}
		var r struct{ Received, Matched, Created int }
		_ = json.Unmarshal(out, &r)
		received, matched, created = received+r.Received, matched+r.Matched, created+r.Created
	}
	fmt.Fprintf(stdout, "Uploaded %d %s. %d matched keys on your connected provider accounts, %d new to Zarpa.\n",
		received, pluralize(received, "key", "keys"), matched, created)
	return exitClean
}

// syncPayload turns scan findings into upload entries. Keys found only in
// other people's commits are left out (not ours to report). With an account
// hasher (and a scan that kept secrets), fingerprints use the account salt
// and the machine one goes along as previous_fingerprint; the raw keys are
// dropped from memory here. Returns the entries and how many were left out.
func syncPayload(res *scan.Result, now time.Time, account *fingerprint.Hasher) ([]syncKey, int) {
	var keys []syncKey
	skipped := 0
	for _, f := range res.Findings {
		fp, prev := f.Fingerprint, ""
		if account != nil && f.Secret() != "" {
			fp, prev = account.Of(f.Secret()), f.Fingerprint
			if prev == fp {
				prev = ""
			}
		}
		f.ForgetSecret()
		if f.Category == scan.CategoryOthers {
			skipped++
			continue
		}
		locs := make([]string, 0, min(len(f.Locations), syncMaxLocations))
		for _, l := range f.Locations {
			if len(locs) == syncMaxLocations {
				break
			}
			if len(l.Ref) <= 1024 {
				locs = append(locs, l.Ref)
			}
		}
		first := f.FirstSeen
		if first.IsZero() {
			first = now
		}
		last4 := f.Last4
		if len(last4) > 4 {
			last4 = last4[len(last4)-4:]
		}
		keys = append(keys, syncKey{
			Fingerprint: fp, PreviousFingerprint: prev, Provider: f.Provider, Last4: last4, Locations: locs,
			PublicExposure: f.PublicExposure, FirstSeen: first.UTC().Format(time.RFC3339),
		})
	}
	return keys, skipped
}

// cloudLogin returns the API and token saved by zarpa login. The token goes
// only to the API it was created for: an environment variable can't redirect it.
func cloudLogin(cmd string, stderr io.Writer) (api, token string, ok bool) {
	cfg, _, err := loadCloudConfig()
	if err != nil {
		fmt.Fprintf(stderr, "zarpa %s: %v\n", cmd, err)
		return "", "", false
	}
	api = cfg.APIURL
	if env := os.Getenv("ZARPA_API_URL"); env != "" {
		if e, err := checkAPIURL(env); err != nil || e != api {
			fmt.Fprintf(stderr, "zarpa %s: ZARPA_API_URL differs from the API you logged in to. Run: zarpa login --api %s\n", cmd, env)
			return "", "", false
		}
	}
	if api == "" {
		fmt.Fprintf(stderr, "zarpa %s: not logged in. Run: zarpa login --api https://…\n", cmd)
		return "", "", false
	}
	if api, err = checkAPIURL(api); err != nil {
		fmt.Fprintf(stderr, "zarpa %s: %v\n", cmd, err)
		return "", "", false
	}
	secrets, err := openSecrets()
	if err == nil {
		token, err = secrets.Get(tokenAccount)
	}
	if err != nil || token == "" {
		fmt.Fprintf(stderr, "zarpa %s: not logged in. Run: zarpa login\n", cmd)
		return "", "", false
	}
	return api, token, true
}

// accountHasher fetches the account's fingerprint salt. It is kept in memory
// for this run only. Returns nil, nil when the API predates shared salts.
func accountHasher(ctx context.Context, api, token string) (*fingerprint.Hasher, error) {
	status, body, err := apiCall(ctx, "GET", api, "/v1/fingerprint-salt", token, nil)
	if err != nil {
		return nil, fmt.Errorf("can't reach %s: %v", api, err)
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		msg := apiErrorMessage(status, body)
		if status == http.StatusUnauthorized {
			msg += ". Log in again: zarpa login"
		}
		return nil, errors.New(msg)
	}
	var r struct {
		Salt string `json:"salt"`
	}
	_ = json.Unmarshal(body, &r)
	salt, err := hex.DecodeString(r.Salt)
	if err != nil || len(salt) != 32 {
		return nil, errors.New("the API sent a fingerprint salt in an unknown format")
	}
	return fingerprint.NewWithSalt(salt, "your Zarpa account"), nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
