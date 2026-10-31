package detect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Reetcodeio/zarpa/internal/testkeys"
	"github.com/Reetcodeio/zarpa/rules"
)

func engine(t *testing.T) *Engine {
	t.Helper()
	set, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	return New(set)
}

func TestEveryProviderRuleFindsItsKey(t *testing.T) {
	e := engine(t)
	keys := testkeys.New(1).Keys()
	for _, r := range e.Rules().Rules {
		if r.Generic || r.ID == "anthropic-key" || r.ID == "aws-secret-access-key" {
			continue // covered elsewhere
		}
		key, ok := keys[r.ID]
		if !ok {
			t.Errorf("no fake key for rule %s", r.ID)
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			content := []byte("config:\n  value: \"" + key + "\"\n")
			ms := e.Scan(content, Options{})
			if len(ms) != 1 {
				t.Fatalf("want 1 match, got %d: %+v", len(ms), ruleIDs(ms))
			}
			if ms[0].Rule.ID != r.ID {
				t.Fatalf("matched by %s, want %s", ms[0].Rule.ID, r.ID)
			}
			if ms[0].Secret != key {
				t.Fatalf("secret span wrong:\n got %q\nwant %q", ms[0].Secret, key)
			}
			if ms[0].Line != 2 {
				t.Fatalf("line = %d, want 2", ms[0].Line)
			}
		})
	}
}

func TestAWSSecretNeedsContext(t *testing.T) {
	e := engine(t)
	g := testkeys.New(2)
	secret := g.AWSSecret()
	ms := e.Scan([]byte("[default]\naws_secret_access_key = "+secret+"\n"), Options{})
	if len(ms) != 1 || ms[0].Rule.ID != "aws-secret-access-key" || ms[0].Secret != secret {
		t.Fatalf("got %+v", ruleIDs(ms))
	}
}

func TestGenericEntropyRule(t *testing.T) {
	e := engine(t)
	g := testkeys.New(3)
	cases := []struct {
		line string
		want bool
	}{
		{"MISTRAL_API_KEY=" + g.Alnum(32), true},
		{`"client_secret": "` + g.Alnum(24) + "9" + `"`, true},
		{"db_password: " + g.Alnum(20) + "7", true},
		{"API_KEY=process.env.OPENAI_API_KEY_FALLBACK", false}, // identifier path
		{"token = this.configService.getToken", false},
		{"SECRET_KEY=your_secret_key_goes_here_123", false}, // placeholder
		{"api_key = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx'", false},
		{"password=short1", false},                         // too short
		{"token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", false}, // low entropy
		{"apiKey: " + g.Alnum(30) + "  // zarpa:allow", false},
		{"name: " + g.Alnum(32), false}, // no key-like name
	}
	for i, c := range cases {
		ms := e.Scan([]byte(c.line), Options{})
		got := len(ms) == 1 && ms[0].Rule.ID == "generic-secret"
		if got != c.want {
			t.Errorf("case %d %q: got match=%v (%v), want %v", i, c.line, got, ruleIDs(ms), c.want)
		}
	}
	// Lockfiles and similar turn the generic rule off.
	if ms := e.Scan([]byte("MISTRAL_API_KEY="+g.Alnum(32)), Options{SkipGeneric: true}); len(ms) != 0 {
		t.Errorf("SkipGeneric ignored: %v", ruleIDs(ms))
	}
}

func TestProviderBeatsGeneric(t *testing.T) {
	e := engine(t)
	key := testkeys.New(4).Keys()["anthropic-api-key"]
	ms := e.Scan([]byte("ANTHROPIC_API_KEY="+key), Options{})
	if len(ms) != 1 || ms[0].Rule.ID != "anthropic-api-key" {
		t.Fatalf("got %v", ruleIDs(ms))
	}
	if ms[0].VarName != "ANTHROPIC_API_KEY" {
		t.Fatalf("var = %q", ms[0].VarName)
	}
}

func TestSupabaseAnonKeyIsNotReported(t *testing.T) {
	e := engine(t)
	g := testkeys.New(5)
	if ms := e.Scan([]byte("SUPABASE_ANON_KEY="+g.JWT("anon")), Options{}); len(ms) != 0 {
		t.Fatalf("anon JWT reported: %v", ruleIDs(ms))
	}
	ms := e.Scan([]byte("SUPABASE_SERVICE_ROLE_KEY="+g.JWT("service_role")), Options{})
	if len(ms) != 1 || ms[0].Rule.ID != "supabase-service-role-jwt" {
		t.Fatalf("service_role JWT: %v", ruleIDs(ms))
	}
}

func TestPublicVarDetection(t *testing.T) {
	e := engine(t)
	key := testkeys.New(6).Keys()["stripe-live-secret-key"]
	for _, line := range []string{
		"VITE_STRIPE_KEY=" + key,
		"NEXT_PUBLIC_STRIPE=" + key,
		"export EXPO_PUBLIC_STRIPE=\"" + key + "\"",
		"const k = { REACT_APP_STRIPE: '" + key + "' }",
	} {
		ms := e.Scan([]byte(line), Options{})
		if len(ms) != 1 || !ms[0].PublicVar {
			t.Errorf("%q: public=%v vars=%v", line, len(ms) == 1 && ms[0].PublicVar, varNames(ms))
		}
	}
	ms := e.Scan([]byte("STRIPE_SECRET_KEY="+key), Options{})
	if len(ms) != 1 || ms[0].PublicVar {
		t.Errorf("server var flagged as public")
	}
	if !IsPublicVar("import.meta.env.VITE_X") || IsPublicVar("MY_VITE_X") {
		t.Error("IsPublicVar prefix handling")
	}
}

func TestManyKeysOnePass(t *testing.T) {
	e := engine(t)
	keys := testkeys.New(7).Keys()
	var b strings.Builder
	n := 0
	for id, k := range keys {
		fmt.Fprintf(&b, "# %s\nX%d=%s\n\n", id, n, k)
		n++
	}
	ms := e.Scan([]byte(b.String()), Options{})
	if len(ms) != n {
		t.Fatalf("found %d of %d keys: %v", len(ms), n, ruleIDs(ms))
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaa") != 0 {
		t.Error("constant string should have 0 entropy")
	}
	if e := Entropy("abcd"); e < 1.99 || e > 2.01 {
		t.Errorf("Entropy(abcd) = %v, want 2", e)
	}
}

func ruleIDs(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Rule.ID)
	}
	return out
}

func varNames(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.VarName)
	}
	return out
}

func TestIsTestPath(t *testing.T) {
	yes := []string{"pkg/foo_test.go", "src/__tests__/a.ts", "testdata/x.json", "web/app.spec.tsx",
		"tests/conftest.py", "test_api.py", "docs/setup.md", "README.md", "aws/apis/s3.examples.json",
		"types/index.d.ts", ".env.example"}
	no := []string{"src/app.ts", "config/prod.json", ".env", "cmd/main.go", "latest/config.yaml"}
	for _, p := range yes {
		if !IsTestPath(p) {
			t.Errorf("%s should be a test/doc path", p)
		}
	}
	for _, p := range no {
		if IsTestPath(p) {
			t.Errorf("%s is not a test/doc path", p)
		}
	}
}

func TestProviderKeysStillReportedInTests(t *testing.T) {
	e := engine(t)
	key := testkeys.New(11).Keys()["openai-project-key"]
	ms := e.Scan([]byte("OPENAI_API_KEY="+key), Options{TestPath: true})
	if len(ms) != 1 {
		t.Fatalf("provider key in a test file must be reported, got %v", ruleIDs(ms))
	}
}

// Regression: bytes.ToLower changes length on invalid UTF-8 and some runes,
// which made keyword offsets point past the line end and panicked.
func TestNonASCIIInputKeepsOffsets(t *testing.T) {
	e := engine(t)
	key := testkeys.New(12).Keys()["openai-project-key"]
	junk := strings.Repeat("\xff\xfe İ ẞ 😀 ", 400)
	content := []byte(junk + "\n" + junk + " OPENAI_API_KEY=" + key + " " + junk + "\nnext token=" + junk)
	ms := e.Scan(content, Options{})
	if len(ms) != 1 || ms[0].Secret != key || ms[0].Line != 2 {
		t.Fatalf("got %v", ruleIDs(ms))
	}
}
