package live

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const good, bad = "good-key", "bad-key"

// fakeProviders answers like the real APIs: 200 for the good key, 401 for
// anything else, 403 for the "restricted" key.
func fakeProviders(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("x-api-key") + r.Header.Get("x-goog-api-key") + r.Header.Get("apikey")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if strings.HasSuffix(key, "."+good) { // Supabase JWT signed "good"
			key = good
		}
		if strings.Contains(r.URL.RawQuery, "key=") {
			t.Errorf("key sent in a URL: %s", r.URL)
		}
		if r.URL.Path == "/api/auth.test" { // Slack always answers 200 with ok:true/false
			if key == good {
				_, _ = w.Write([]byte(`{"ok":true}`))
			} else {
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
			}
			return
		}
		switch key {
		case good:
			w.WriteHeader(200)
		case "restricted":
			w.WriteHeader(403)
		default:
			w.WriteHeader(401)
		}
	}))
	t.Cleanup(srv.Close)
	saved := map[string]string{}
	for k, v := range Hosts {
		saved[k] = v
		Hosts[k] = srv.URL
	}
	Hosts["supabase"] = srv.URL + "/%s"
	t.Cleanup(func() {
		for k, v := range saved {
			Hosts[k] = v
		}
	})
}

func TestEveryCheckerClassifiesGoodAndBad(t *testing.T) {
	fakeProviders(t)
	for id := range checkers {
		t.Run(id, func(t *testing.T) {
			g, b := good, bad
			if id == "supabase-service-role-jwt" {
				g, b = jwtWithRef(good), jwtWithRef(bad)
			}
			if r := Check(context.Background(), http.DefaultClient, id, g); r.Status != Live {
				t.Errorf("good key: %+v", r)
			}
			if r := Check(context.Background(), http.DefaultClient, id, b); r.Status != Revoked {
				t.Errorf("bad key: %+v", r)
			}
		})
	}
}

func TestRestrictedKeyIsStillLive(t *testing.T) {
	fakeProviders(t)
	r := Check(context.Background(), http.DefaultClient, "stripe-live-restricted-key", "restricted")
	if r.Status != Live || r.Detail == "" {
		t.Fatalf("%+v", r)
	}
}

func TestUnsupportedAndCheckAll(t *testing.T) {
	fakeProviders(t)
	res := CheckAll(context.Background(), []Job{
		{ID: "a", RuleID: "openai-project-key", Key: good},
		{ID: "b", RuleID: "aws-access-key-id", Key: good},
		{ID: "c", RuleID: "anthropic-api-key", Key: bad},
	}, Options{Concurrency: 2})
	if res["a"].Status != Live || res["b"].Status != Unsupported || res["c"].Status != Revoked {
		t.Fatalf("%+v", res)
	}
}

func TestNetworkErrorIsUnknown(t *testing.T) {
	saved := Hosts["openai"]
	Hosts["openai"] = "http://127.0.0.1:1" // nothing listens here
	defer func() { Hosts["openai"] = saved }()
	if r := Check(context.Background(), http.DefaultClient, "openai-project-key", good); r.Status != Unknown {
		t.Fatalf("%+v", r)
	}
}

func jwtWithRef(sig string) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." +
		enc.EncodeToString([]byte(`{"ref":"abcdefgh","role":"service_role"}`)) + "." + sig
}

// replyWith points every host at a server that gives one fixed answer.
func replyWith(t *testing.T, code int, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	saved := map[string]string{}
	for k, v := range Hosts {
		saved[k] = v
		Hosts[k] = srv.URL
	}
	Hosts["supabase"] = srv.URL + "/%s"
	t.Cleanup(func() {
		for k, v := range saved {
			Hosts[k] = v
		}
	})
}

func googleBody(code int, status, reason, msg string) string {
	return `{"error":{"code":` + strconv.Itoa(code) + `,"message":"` + msg + `","status":"` + status +
		`","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"` + reason + `","domain":"googleapis.com"}]}}`
}

func TestGoogleErrorReasons(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		body   string
		status Status
		detail string
	}{
		{"invalid", 400, googleBody(400, "INVALID_ARGUMENT", "API_KEY_INVALID", "API key not valid. Please pass a valid API key."), Revoked, "not valid"},
		{"expired", 400, googleBody(400, "INVALID_ARGUMENT", "API_KEY_INVALID", "API key expired. Please renew the API key."), Revoked, "expired"},
		{"service off", 403, googleBody(403, "PERMISSION_DENIED", "SERVICE_DISABLED", "Generative Language API has not been used"), Live, "not enabled"},
		{"blocked api", 403, googleBody(403, "PERMISSION_DENIED", "API_KEY_SERVICE_BLOCKED", "Requests to this API are blocked."), Live, "not enabled"},
		{"referrer", 403, googleBody(403, "PERMISSION_DENIED", "API_KEY_HTTP_REFERRER_BLOCKED", "Requests from referer <empty> are blocked."), Live, "websites"},
		{"region", 400, `{"error":{"code":400,"message":"User location is not supported for the API use.","status":"FAILED_PRECONDITION"}}`, Unknown, "region"},
		// Seen with valid AQ. keys: not proof the key is dead.
		{"aq key type", 401, googleBody(401, "UNAUTHENTICATED", "ACCESS_TOKEN_TYPE_UNSUPPORTED", "Request had invalid authentication credentials."), Unknown, "key type"},
		{"plain 401", 401, `{"error":{"code":401,"message":"Request had invalid authentication credentials.","status":"UNAUTHENTICATED"}}`, Revoked, "not valid"},
		{"ok", 200, `{"models":[]}`, Live, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			replyWith(t, tc.code, tc.body)
			r := Check(context.Background(), http.DefaultClient, "google-api-key", "AIzaFAKE")
			if r.Status != tc.status || !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("got %+v, want %s containing %q", r, tc.status, tc.detail)
			}
		})
	}
}

func TestSupabaseProjectStates(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		body   string
		status Status
	}{
		{"paused", 540, `{"message":"Project paused"}`, Unknown},
		{"legacy off", 401, `{"message":"Legacy API keys are disabled"}`, Revoked},
		{"wrong secret", 401, `{"message":"Invalid API key"}`, Revoked},
		{"ok", 200, `{}`, Live},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			replyWith(t, tc.code, tc.body)
			r := Check(context.Background(), http.DefaultClient, "supabase-service-role-jwt", jwtWithRef("x"))
			if r.Status != tc.status {
				t.Errorf("got %+v, want %s", r, tc.status)
			}
		})
	}
}

func TestSupabaseDeletedProjectIsDead(t *testing.T) {
	// A deleted project's hostname stops resolving.
	c := &http.Client{Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
		},
	}}
	r := Check(context.Background(), c, "supabase-service-role-jwt", jwtWithRef("x"))
	if r.Status != Revoked || !strings.Contains(r.Detail, "no longer exists") {
		t.Errorf("got %+v", r)
	}
	// Any other network failure stays unknown.
	c.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: addr, IsTemporary: true}
	}
	if r := Check(context.Background(), c, "supabase-service-role-jwt", jwtWithRef("x")); r.Status != Unknown {
		t.Errorf("temporary DNS failure: got %+v", r)
	}
}
