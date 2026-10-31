package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Reetcodeio/zarpa/internal/testkeys"
	"github.com/Reetcodeio/zarpa/internal/vault"
)

const goodToken = "zarpa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// fakeSalt is the account salt the fake API hands out.
var fakeSalt = strings.Repeat("ab", 32)

// fakeCloud stands in for the Zarpa API. It records sync and panic bodies.
func fakeCloud(t *testing.T) (*httptest.Server, *[][]byte) {
	t.Helper()
	var bodies [][]byte
	panicked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+goodToken {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"invalid or revoked CLI token"}}`))
			return
		}
		switch r.URL.Path {
		case "/v1/me":
			_, _ = w.Write([]byte(`{"account":{"name":"a"},"user":{"email":"dev@example.com"},"via":"cli"}`))
		case "/v1/sync":
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, b)
			var p struct{ Keys []json.RawMessage }
			_ = json.Unmarshal(b, &p)
			_ = json.NewEncoder(w).Encode(map[string]int{"received": len(p.Keys), "matched": 1, "created": len(p.Keys) - 1, "known": 0})
		case "/v1/redirect":
			http.Redirect(w, r, "https://evil.example/", http.StatusFound)
		case "/v1/fingerprint-salt":
			_, _ = w.Write([]byte(`{"salt":"` + fakeSalt + `","algorithm":"hmac-sha256"}`))
		case "/v1/panic":
			if r.Method == "GET" {
				_, _ = w.Write([]byte(`{"runs":[{"id":"11111111-2222-4333-8444-555555555555"}]}`))
				return
			}
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, b)
			var p map[string]any
			_ = json.Unmarshal(b, &p)
			items := `[{"id":"aaaaaaaa-0000-4000-8000-000000000001","step":"freeze","status":"todo","title":"Freeze Anthropic \"prod\" …Pr0d"},` +
				`{"id":"aaaaaaaa-0000-4000-8000-000000000002","step":"manual","status":"todo","title":"Rotate OpenAI key …uRkA","note":"OpenAI keys can't be paused.\u001b[31m"}]`
			if p["dry_run"] == true {
				_, _ = w.Write([]byte(`{"dry_run":true,"summary":{"to_freeze":1,"frozen":0,"failed":0,"skipped":0,"manual":1,"todo":1},"items":` + items + `}`))
				return
			}
			panicked = true
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"run_id":"11111111-2222-4333-8444-555555555555","summary":{"to_freeze":0,"frozen":1,"failed":0,"skipped":0,"manual":1,"todo":1},"items":` +
				strings.Replace(items, `"status":"todo","title":"Freeze`, `"status":"done","title":"Freeze`, 1) + `}`))
		case "/v1/panic/11111111-2222-4333-8444-555555555555":
			if !panicked {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(`{"created_at":"2026-10-30T12:00:00Z","finished_at":null,"items":[{"id":"aaaaaaaa-0000-4000-8000-000000000001","step":"freeze","status":"done","title":"Freeze"},{"id":"aaaaaaaa-0000-4000-8000-000000000002","step":"manual","status":"todo","title":"Rotate OpenAI key …uRkA"}]}`))
		case "/v1/panic/11111111-2222-4333-8444-555555555555/items/aaaaaaaa-0000-4000-8000-000000000002":
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, b)
			_, _ = w.Write([]byte(`{"id":"aaaaaaaa-0000-4000-8000-000000000002","status":"done","run_finished":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

// isolate points config and keychain at temp/in-memory stores.
func isolate(t *testing.T) *vault.Secrets {
	t.Helper()
	dir := t.TempDir()
	mem := vault.MemorySecrets()
	oldS, oldC, oldT := openSecrets, configDir, isTerminalIn
	openSecrets = func() (*vault.Secrets, error) { return mem, nil }
	configDir = func() (string, error) { return dir, nil }
	isTerminalIn = func() bool { return false }
	t.Setenv("ZARPA_API_URL", "")
	t.Cleanup(func() { openSecrets, configDir, isTerminalIn = oldS, oldC, oldT })
	return mem
}

func TestCheckAPIURL(t *testing.T) {
	for _, ok := range []string{"https://api.zarpa.dev", "https://api.zarpa.dev/", "http://127.0.0.1:8080", "http://localhost:8080"} {
		if _, err := checkAPIURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://api.zarpa.dev", "ftp://x", "https://user:pw@api.zarpa.dev", "https://api.zarpa.dev?x=1", "api.zarpa.dev"} {
		if _, err := checkAPIURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestLoginStoresTokenInKeychain(t *testing.T) {
	mem := isolate(t)
	srv, _ := fakeCloud(t)
	var out, errb bytes.Buffer
	if code := cmdLogin([]string{"--api", srv.URL}, strings.NewReader("not-a-token\n"), &out, &errb); code != exitError {
		t.Fatalf("bad token accepted: %d", code)
	}
	wrong := "zarpa_" + strings.Repeat("B", 43)
	if code := cmdLogin([]string{"--api", srv.URL}, strings.NewReader(wrong+"\n"), &out, &errb); code != exitError || !strings.Contains(errb.String(), "revoked") {
		t.Fatalf("wrong token: %d %s", code, errb.String())
	}
	errb.Reset()
	if code := cmdLogin([]string{"--api", srv.URL}, strings.NewReader(goodToken+"\n"), &out, &errb); code != exitClean {
		t.Fatalf("login: %d %s", code, errb.String())
	}
	if got, _ := mem.Get(tokenAccount); got != goodToken {
		t.Fatal("token not stored")
	}
	if strings.Contains(out.String()+errb.String(), goodToken) {
		t.Fatal("token printed")
	}
	cfg, _, _ := loadCloudConfig()
	if cfg.APIURL != srv.URL || cfg.DeviceID == "" {
		t.Fatalf("config: %+v", cfg)
	}
	// The token file is not written anywhere on disk.
	dir, _ := configDir()
	b, _ := os.ReadFile(filepath.Join(dir, "cloud.json"))
	if strings.Contains(string(b), "zarpa_") {
		t.Fatal("token in config file")
	}
	if code := cmdLogout(&out, &errb); code != exitClean {
		t.Fatal("logout")
	}
	if _, err := mem.Get(tokenAccount); err == nil {
		t.Fatal("token still stored")
	}
}

func TestSyncUploadsFingerprintsNotKeys(t *testing.T) {
	mem := isolate(t)
	srv, bodies := fakeCloud(t)
	must(t, mem.Set(tokenAccount, goodToken))
	cfg, path, _ := loadCloudConfig()
	cfg.APIURL = srv.URL
	must(t, saveCloudConfig(cfg, path))

	dir := t.TempDir()
	keys := testkeys.New(7).Keys()
	ant, oai := keys["anthropic-api-key"], keys["openai-project-key"]
	must(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("ANTHROPIC_API_KEY="+ant+"\nOPENAI_API_KEY="+oai+"\n"), 0o600))
	salt := filepath.Join(t.TempDir(), "salt")
	args := []string{dir, "--no-git", "--no-machine", "-q", "--salt-file", salt, "--home", t.TempDir()}

	var out, errb bytes.Buffer
	if code := cmdSync(args, strings.NewReader(""), &out, &errb); code != exitError || !strings.Contains(errb.String(), "--yes") {
		t.Fatalf("non-terminal without --yes must refuse: %d %s", code, errb.String())
	}
	if len(*bodies) != 0 {
		t.Fatal("uploaded without confirmation")
	}
	out.Reset()
	errb.Reset()
	if code := cmdSync(append(args, "--yes"), strings.NewReader(""), &out, &errb); code != exitClean {
		t.Fatalf("sync: %d %s", code, errb.String())
	}
	if len(*bodies) != 1 {
		t.Fatalf("bodies: %d", len(*bodies))
	}
	body := string((*bodies)[0])
	if strings.Contains(body, ant) || strings.Contains(body, oai) || strings.Contains(body, ant[10:30]) {
		t.Fatal("raw key in upload")
	}
	var p struct {
		DeviceID string    `json:"device_id"`
		Keys     []syncKey `json:"keys"`
	}
	must(t, json.Unmarshal((*bodies)[0], &p))
	if len(p.Keys) != 2 || p.DeviceID == "" {
		t.Fatalf("payload: %s", body)
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, k := range p.Keys {
		if !hex64.MatchString(k.Fingerprint) || len(k.Last4) != 4 || len(k.Locations) == 0 {
			t.Fatalf("bad entry: %+v", k)
		}
	}
	if !strings.Contains(out.String(), "Uploaded 2 keys. 1 matched") {
		t.Fatalf("output: %s", out.String())
	}

	// --dry-run shows the same payload and sends nothing.
	out.Reset()
	if code := cmdSync(append(args, "--dry-run"), strings.NewReader(""), &out, &errb); code != exitClean || len(*bodies) != 1 {
		t.Fatalf("dry run: %d", code)
	}
	if strings.Contains(out.String(), ant) || !strings.Contains(out.String(), p.Keys[0].Fingerprint) {
		t.Fatal("dry run output")
	}
}

func TestSyncNeedsLoginAndDoesNotFollowRedirects(t *testing.T) {
	isolate(t)
	var out, errb bytes.Buffer
	if code := cmdSync([]string{t.TempDir(), "--yes", "-q"}, strings.NewReader(""), &out, &errb); code != exitError || !strings.Contains(errb.String(), "not logged in") {
		t.Fatalf("%d %s", code, errb.String())
	}
	srv, _ := fakeCloud(t)
	// A different URL in the environment must not receive the saved token.
	mem, _ := openSecrets()
	must(t, mem.Set(tokenAccount, goodToken))
	cfg, path, _ := loadCloudConfig()
	cfg.APIURL = srv.URL
	must(t, saveCloudConfig(cfg, path))
	t.Setenv("ZARPA_API_URL", "https://elsewhere.example")
	errb.Reset()
	if code := cmdSync([]string{t.TempDir(), "--yes", "-q", "--no-git", "--no-machine"}, strings.NewReader(""), &out, &errb); code != exitError || !strings.Contains(errb.String(), "differs") {
		t.Fatalf("env override accepted: %d %s", code, errb.String())
	}
	if _, _, err := apiCall(context.Background(), "GET", srv.URL, "/v1/redirect", goodToken, nil); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect followed: %v", err)
	}
}

func TestSyncUsesTheAccountSaltAndSendsTheOldFingerprint(t *testing.T) {
	mem := isolate(t)
	srv, bodies := fakeCloud(t)
	must(t, mem.Set(tokenAccount, goodToken))
	cfg, path, _ := loadCloudConfig()
	cfg.APIURL = srv.URL
	must(t, saveCloudConfig(cfg, path))
	dir := t.TempDir()
	ant := testkeys.New(9).Keys()["anthropic-api-key"]
	must(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("ANTHROPIC_API_KEY="+ant+"\n"), 0o600))

	// Two machines with different local salts upload the same fingerprint.
	var got []syncKey
	for _, machine := range []string{"mac", "laptop"} {
		salt := filepath.Join(t.TempDir(), machine)
		var out, errb bytes.Buffer
		args := []string{dir, "--no-git", "--no-machine", "-q", "--yes", "--salt-file", salt, "--home", t.TempDir()}
		if code := cmdSync(args, strings.NewReader(""), &out, &errb); code != exitClean {
			t.Fatalf("%s: %d %s", machine, code, errb.String())
		}
		var p struct{ Keys []syncKey }
		must(t, json.Unmarshal((*bodies)[len(*bodies)-1], &p))
		if len(p.Keys) != 1 {
			t.Fatalf("%s: %d keys", machine, len(p.Keys))
		}
		got = append(got, p.Keys[0])
		if strings.Contains(string((*bodies)[len(*bodies)-1]), ant) {
			t.Fatal("raw key uploaded")
		}
	}
	if got[0].Fingerprint != got[1].Fingerprint {
		t.Fatal("same key, two fingerprints: the account salt was not used")
	}
	if got[0].PreviousFingerprint == "" || got[0].PreviousFingerprint == got[1].PreviousFingerprint {
		t.Fatalf("previous fingerprints should be the per-machine ones: %+v", got)
	}
}

func TestPanicPlansConfirmsFreezesAndTicksOff(t *testing.T) {
	mem := isolate(t)
	srv, bodies := fakeCloud(t)
	must(t, mem.Set(tokenAccount, goodToken))
	cfg, path, _ := loadCloudConfig()
	cfg.APIURL = srv.URL
	must(t, saveCloudConfig(cfg, path))

	var out, errb bytes.Buffer
	if code := cmdPanic(nil, strings.NewReader(""), &out, &errb); code != exitError || !strings.Contains(errb.String(), "say what to freeze") {
		t.Fatalf("no scope: %d %s", code, errb.String())
	}
	errb.Reset()
	if code := cmdPanic([]string{"--all", "--tool", "x"}, strings.NewReader(""), &out, &errb); code != exitError {
		t.Fatal("--all with a filter accepted")
	}
	// Not a terminal and no --yes: plan only, nothing frozen.
	errb.Reset()
	if code := cmdPanic([]string{"--tool", "opencode"}, strings.NewReader(""), &out, &errb); code != exitError || !strings.Contains(errb.String(), "--yes") {
		t.Fatalf("froze without confirmation: %d %s", code, errb.String())
	}
	if len(*bodies) != 1 || !strings.Contains(string((*bodies)[0]), `"dry_run":true`) || !strings.Contains(string((*bodies)[0]), `"tool":"opencode"`) {
		t.Fatalf("plan request: %s", *bodies)
	}
	out.Reset()
	if code := cmdPanic([]string{"--tool", "opencode", "--yes"}, strings.NewReader(""), &out, &errb); code != exitClean {
		t.Fatalf("panic: %d %s", code, errb.String())
	}
	text := out.String()
	for _, want := range []string{"1 key to freeze", "Frozen 1, failed 0", "✓ Freeze Anthropic", "1. [ ] Rotate OpenAI key", "zarpa panic done N"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b") {
		t.Fatal("control characters from the API reached the terminal")
	}
	out.Reset()
	if code := cmdPanic([]string{"status"}, nil, &out, &errb); code != exitClean || !strings.Contains(out.String(), "1. [ ] Rotate") {
		t.Fatalf("status: %d %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := cmdPanic([]string{"done", "2"}, nil, &out, &errb); code != exitError {
		t.Fatal("step 2 doesn't exist")
	}
	if code := cmdPanic([]string{"done", "1"}, nil, &out, &errb); code != exitClean || !strings.Contains(out.String(), "Every step of this panic run is done") {
		t.Fatalf("done: %d %s %s", code, out.String(), errb.String())
	}
	if last := string((*bodies)[len(*bodies)-1]); last != `{"status":"done"}` {
		t.Fatalf("patch body: %s", last)
	}
}
