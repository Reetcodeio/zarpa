// Package live tests whether found keys still work, with one cheap,
// read-only call per key to the provider that issued it.
//
// Rules for every checker:
//   - the key is sent only to its own provider's API host, over HTTPS;
//   - the call reads metadata (list models, whoami, balance) and changes nothing;
//   - the key is never logged, printed or kept after the call.
package live

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Status of a key after a check.
type Status string

const (
	Live        Status = "live"        // the provider accepted the key
	Revoked     Status = "revoked"     // the provider rejected it (deleted, disabled, expired)
	Unknown     Status = "unknown"     // network error, rate limit or unexpected answer
	Unsupported Status = "unsupported" // no safe single-key check exists (AWS, Twilio need a pair)
)

// Result of checking one key.
type Result struct {
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"` // e.g. "HTTP 403: key valid but restricted"
}

// Hosts maps a logical provider host to its base URL. Tests point these at
// a local server; nothing else should change them.
var Hosts = map[string]string{
	"openai":      "https://api.openai.com",
	"anthropic":   "https://api.anthropic.com",
	"google":      "https://generativelanguage.googleapis.com",
	"stripe":      "https://api.stripe.com",
	"github":      "https://api.github.com",
	"huggingface": "https://huggingface.co",
	"groq":        "https://api.groq.com",
	"xai":         "https://api.x.ai",
	"openrouter":  "https://openrouter.ai",
	"slack":       "https://slack.com",
	"sendgrid":    "https://api.sendgrid.com",
	"supabase":    "https://%s.supabase.co", // %s = project ref from the JWT
}

type checker func(ctx context.Context, c *http.Client, key string) Result

// bearer builds a GET check with "Authorization: Bearer <key>".
func bearer(host, path string) checker {
	return func(ctx context.Context, c *http.Client, key string) Result {
		return get(ctx, c, Hosts[host]+path, map[string]string{"Authorization": "Bearer " + key})
	}
}

// checkers maps rule ids to their check.
var checkers = map[string]checker{
	"openai-project-key":         bearer("openai", "/v1/models"),
	"openai-service-account-key": bearer("openai", "/v1/models"),
	"openai-legacy-key":          bearer("openai", "/v1/models"),
	"openai-admin-key":           bearer("openai", "/v1/organization/projects?limit=1"),
	"anthropic-api-key": func(ctx context.Context, c *http.Client, k string) Result {
		return get(ctx, c, Hosts["anthropic"]+"/v1/models?limit=1",
			map[string]string{"x-api-key": k, "anthropic-version": "2023-06-01"})
	},
	"anthropic-key": func(ctx context.Context, c *http.Client, k string) Result {
		return get(ctx, c, Hosts["anthropic"]+"/v1/models?limit=1",
			map[string]string{"x-api-key": k, "anthropic-version": "2023-06-01"})
	},
	"anthropic-admin-key": func(ctx context.Context, c *http.Client, k string) Result {
		return get(ctx, c, Hosts["anthropic"]+"/v1/organizations/api_keys?limit=1",
			map[string]string{"x-api-key": k, "anthropic-version": "2023-06-01"})
	},
	"google-api-key":             googleKey,
	"google-auth-key":            googleKey,
	"stripe-live-secret-key":     bearer("stripe", "/v1/balance"),
	"stripe-live-restricted-key": bearer("stripe", "/v1/balance"),
	"stripe-test-secret-key":     bearer("stripe", "/v1/balance"),
	"github-pat-classic":         bearer("github", "/user"),
	"github-pat-fine-grained":    bearer("github", "/user"),
	"github-app-token":           bearer("github", "/user"),
	"huggingface-token":          bearer("huggingface", "/api/whoami-v2"),
	"groq-api-key":               bearer("groq", "/openai/v1/models"),
	"xai-api-key":                bearer("xai", "/v1/api-key"),
	"openrouter-key":             bearer("openrouter", "/api/v1/key"),
	"sendgrid-api-key":           bearer("sendgrid", "/v3/scopes"),
	"slack-token":                slackAuthTest,
	"supabase-service-role-jwt":  supabaseJWT,
}

// Supported reports whether a rule has a liveness check.
func Supported(ruleID string) bool { _, ok := checkers[ruleID]; return ok }

// Job is one key to check.
type Job struct {
	ID     string // caller's id (the fingerprint)
	RuleID string
	Key    string
}

// Options tune a batch of checks.
type Options struct {
	Concurrency int
	Timeout     time.Duration
	Client      *http.Client
}

// CheckAll runs the jobs in parallel and returns results by job ID.
func CheckAll(ctx context.Context, jobs []Job, opt Options) map[string]Result {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 4
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	client := opt.Client
	if client == nil {
		client = &http.Client{
			Timeout: opt.Timeout,
			// Never follow a redirect: it could carry the key's header elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	out := make(map[string]Result, len(jobs))
	var mu sync.Mutex
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	for _, j := range jobs {
		j := j
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := Check(ctx, client, j.RuleID, j.Key)
			mu.Lock()
			out[j.ID] = r
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// Check tests one key.
func Check(ctx context.Context, c *http.Client, ruleID, key string) Result {
	ch, ok := checkers[ruleID]
	if !ok {
		return Result{Status: Unsupported}
	}
	return ch(ctx, c, key)
}

func get(ctx context.Context, c *http.Client, url string, headers map[string]string) Result {
	code, _, err := fetch(ctx, c, url, headers)
	if err != nil {
		return Result{Status: Unknown, Detail: netDetail(err)}
	}
	return classify(code)
}

// fetch sends one GET and returns the status and up to 64 KB of the body.
// The body is only parsed for the provider's error code; it is never shown.
func fetch(ctx context.Context, c *http.Client, url string, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, errors.New("bad request")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "zarpa-check")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, body, nil
}

// netDetail turns a transport error into a short reason. It never includes
// the URL, which for Supabase holds the project ref.
func netDetail(err error) string {
	var dns *net.DNSError
	var cert x509.UnknownAuthorityError
	var tlsErr tls.RecordHeaderError
	var ne net.Error
	switch {
	case errors.As(err, &dns) && dns.IsNotFound:
		return "host not found"
	case errors.As(err, &dns):
		return "DNS lookup failed (offline?)"
	case errors.As(err, &cert):
		return "TLS certificate not trusted (proxy or VPN in the way?)"
	case errors.As(err, &tlsErr):
		return "TLS handshake failed"
	case errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case err.Error() == "bad request":
		return "bad request"
	}
	return "network error"
}

// classify maps an HTTP status to a key status. 403 means the provider
// recognised the key but it lacks permission for this endpoint: still live.
func classify(code int) Result {
	switch {
	case code >= 200 && code < 300:
		return Result{Status: Live}
	case code == 403:
		return Result{Status: Live, Detail: "HTTP 403: key valid but restricted"}
	case code == 401:
		return Result{Status: Revoked}
	case code == 429:
		return Result{Status: Unknown, Detail: "rate limited, try again later"}
	}
	return Result{Status: Unknown, Detail: fmt.Sprintf("HTTP %d", code)}
}

func slackAuthTest(ctx context.Context, c *http.Client, key string) Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Hosts["slack"]+"/api/auth.test", nil)
	if err != nil {
		return Result{Status: Unknown}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := c.Do(req)
	if err != nil {
		return Result{Status: Unknown, Detail: netDetail(err)}
	}
	defer resp.Body.Close()
	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body) != nil {
		return Result{Status: Unknown, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	switch {
	case body.OK:
		return Result{Status: Live}
	case body.Error == "invalid_auth" || body.Error == "token_revoked" || body.Error == "account_inactive" || body.Error == "token_expired":
		return Result{Status: Revoked, Detail: body.Error}
	}
	return Result{Status: Unknown, Detail: body.Error}
}

// googleKey checks a Google API key against the Gemini API. Google answers
// 400 API_KEY_INVALID for a deleted or expired key (not 401), and 403 with a
// reason when the key exists but is restricted.
func googleKey(ctx context.Context, c *http.Client, key string) Result {
	// Header, not ?key=, so the key never lands in a URL or proxy log.
	code, body, err := fetch(ctx, c, Hosts["google"]+"/v1beta/models?pageSize=1", map[string]string{"x-goog-api-key": key})
	if err != nil {
		return Result{Status: Unknown, Detail: netDetail(err)}
	}
	reason, msg := googleError(body)
	switch {
	case code >= 200 && code < 300:
		return Result{Status: Live}
	case reason == "ACCESS_TOKEN_TYPE_UNSUPPORTED":
		// Reported for valid AQ. keys too (Gemini forum, 2026), so it proves nothing.
		return Result{Status: Unknown, Detail: "Google did not accept this key type for the test call; check it in Google AI Studio"}
	case reason == "API_KEY_INVALID" || reason == "API_KEY_EXPIRED" || code == 401:
		d := "key deleted or not valid"
		if strings.Contains(strings.ToLower(msg), "expired") || reason == "API_KEY_EXPIRED" {
			d = "key expired"
		}
		return Result{Status: Revoked, Detail: d}
	case code == 403 || reason != "" && strings.HasPrefix(reason, "API_KEY_"):
		switch reason {
		case "SERVICE_DISABLED", "API_KEY_SERVICE_BLOCKED":
			return Result{Status: Live, Detail: "key exists; the Gemini API is not enabled for it, other Google APIs may still work"}
		case "API_KEY_HTTP_REFERRER_BLOCKED":
			return Result{Status: Live, Detail: "key exists; limited to certain websites"}
		case "API_KEY_IP_ADDRESS_BLOCKED":
			return Result{Status: Live, Detail: "key exists; limited to certain IP addresses"}
		case "API_KEY_ANDROID_APP_BLOCKED", "API_KEY_IOS_APP_BLOCKED":
			return Result{Status: Live, Detail: "key exists; limited to a mobile app"}
		}
		return Result{Status: Live, Detail: "key exists but is restricted"}
	case code == 400 && strings.Contains(strings.ToLower(msg), "location is not supported"):
		return Result{Status: Unknown, Detail: "Gemini API not available in your region, so the key could not be tested"}
	}
	return classify(code)
}

// googleError pulls error.details[].reason and error.message from a Google
// API error body.
func googleError(body []byte) (reason, msg string) {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return "", ""
	}
	for _, d := range e.Error.Details {
		if d.Reason != "" {
			return d.Reason, e.Error.Message
		}
	}
	return "", e.Error.Message
}

// supabaseJWT checks a service_role key against its own project, whose ref
// is inside the token.
func supabaseJWT(ctx context.Context, c *http.Client, key string) Result {
	ref := jwtClaim(key, "ref")
	if ref == "" || strings.ContainsAny(ref, "./:@?#") {
		return Result{Status: Unsupported, Detail: "no project ref in the token"}
	}
	base := fmt.Sprintf(Hosts["supabase"], ref)
	code, body, err := fetch(ctx, c, base+"/rest/v1/", map[string]string{"apikey": key, "Authorization": "Bearer " + key})
	if err != nil {
		var dns *net.DNSError
		if errors.As(err, &dns) && dns.IsNotFound {
			// supabase.co itself resolves; only this project's name is gone.
			return Result{Status: Revoked, Detail: "the project no longer exists"}
		}
		return Result{Status: Unknown, Detail: netDetail(err)}
	}
	low := strings.ToLower(string(body))
	switch {
	case code == 540 || strings.Contains(low, "project paused") || strings.Contains(low, "project is paused"):
		return Result{Status: Unknown, Detail: "project is paused; the key works again if the project is restored"}
	case code == 401 && strings.Contains(low, "legacy api keys are disabled"):
		return Result{Status: Revoked, Detail: "legacy keys turned off for this project"}
	case code == 404 && strings.Contains(low, "project not found"):
		return Result{Status: Revoked, Detail: "the project no longer exists"}
	}
	return classify(code)
}

func jwtClaim(token, claim string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	s, _ := m[claim].(string)
	return s
}
