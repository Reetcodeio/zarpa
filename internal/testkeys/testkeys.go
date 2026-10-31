// Package testkeys builds realistic-looking fake keys at test time, so the
// repository never contains literal key-shaped strings that would trip
// secret scanners (including this one) or push protection.
package testkeys

import (
	"encoding/base64"
	"math/rand"
	"strings"
)

const (
	alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	urlB  = alnum + "_-"
	hexc  = "0123456789abcdef"
	upnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// Gen produces deterministic random strings.
type Gen struct{ r *rand.Rand }

// New returns a generator with a fixed seed.
func New(seed int64) *Gen { return &Gen{r: rand.New(rand.NewSource(seed))} }

func (g *Gen) pick(set string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(set[g.r.Intn(len(set))])
	}
	return b.String()
}

// Alnum returns n random letters and digits.
func (g *Gen) Alnum(n int) string { return g.pick(alnum, n) }

// URLSafe returns n random base64url characters.
func (g *Gen) URLSafe(n int) string { return g.pick(urlB, n) }

// Hex returns n random lowercase hex characters.
func (g *Gen) Hex(n int) string { return g.pick(hexc, n) }

// UpperNum returns n random uppercase letters and digits.
func (g *Gen) UpperNum(n int) string { return g.pick(upnum, n) }

// P joins prefix parts; it exists so prefixes are never one literal token.
func P(parts ...string) string { return strings.Join(parts, "") }

// JWT returns an unsigned-looking JWT whose payload carries the given role.
func (g *Gen) JWT(role string) string {
	enc := base64.RawURLEncoding
	h := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p := enc.EncodeToString([]byte(`{"iss":"supabase","ref":"` + g.Alnum(20) + `","role":"` + role + `","iat":1700000000,"exp":2000000000}`))
	return h + "." + p + "." + g.URLSafe(43)
}

// Keys returns one fake key per rule id, for rules with a fixed format.
func (g *Gen) Keys() map[string]string {
	return map[string]string{
		"anthropic-admin-key":        P("sk-ant-", "admin01-") + g.URLSafe(93) + "AA",
		"anthropic-api-key":          P("sk-ant-", "api03-") + g.URLSafe(93) + "AA",
		"openai-admin-key":           P("sk-", "admin-") + g.URLSafe(60),
		"openai-project-key":         P("sk-", "proj-") + g.URLSafe(120),
		"openai-service-account-key": P("sk-", "svcacct-") + g.URLSafe(120),
		"openai-legacy-key":          P("sk-") + g.Alnum(20) + P("T3Blbk", "FJ") + g.Alnum(20),
		"openrouter-key":             P("sk-", "or-v1-") + g.Hex(64),
		"google-api-key":             P("AI", "za") + g.URLSafe(35),
		"google-auth-key":            P("AQ", ".Ab") + g.URLSafe(60),
		"stripe-live-secret-key":     P("sk_", "live_") + g.Alnum(99),
		"stripe-live-restricted-key": P("rk_", "live_") + g.Alnum(99),
		"stripe-test-secret-key":     P("sk_", "test_") + g.Alnum(99),
		"stripe-webhook-secret":      P("wh", "sec_") + g.Alnum(32),
		"supabase-secret-key":        P("sb_", "secret_") + g.URLSafe(32),
		"supabase-service-role-jwt":  g.JWT("service_role"),
		"aws-access-key-id":          P("AK", "IA") + g.UpperNum(16),
		"github-pat-classic":         P("gh", "p_") + g.Alnum(36),
		"github-pat-fine-grained":    P("github", "_pat_") + g.pick(alnum+"_", 82),
		"github-app-token":           P("gh", "s_") + g.Alnum(36),
		"slack-token":                P("xo", "xb-") + g.pick("0123456789", 12) + "-" + g.pick("0123456789", 13) + "-" + g.Alnum(24),
		"slack-webhook-url":          P("https://hooks.", "slack.com/services/T") + g.UpperNum(10) + "/B" + g.UpperNum(10) + "/" + g.Alnum(24),
		"twilio-api-key":             P("S", "K") + g.Hex(32),
		"sendgrid-api-key":           P("S", "G.") + g.URLSafe(22) + "." + g.URLSafe(43),
		"huggingface-token":          P("h", "f_") + g.Alnum(34),
		"groq-api-key":               P("gs", "k_") + g.Alnum(52),
		"xai-api-key":                P("xa", "i-") + g.Alnum(80),
		"private-key-block":          P("-----BEGIN ", "OPENSSH PRIVATE KEY-----\n") + g.pick(alnum+"+/", 70) + "\n" + g.pick(alnum+"+/", 70) + "\n" + P("-----END ", "OPENSSH PRIVATE KEY-----"),
	}
}

// AWSSecret returns a 40-character AWS-style secret access key.
func (g *Gen) AWSSecret() string { return g.pick(alnum+"/+", 40) }
