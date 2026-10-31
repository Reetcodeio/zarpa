# Detection rules

Rules live in `rules/rules.json`, versioned by date (`"version"`), and are
embedded in the binary. Run `zarpa rules` to list them, or test a draft with
`zarpa scan --rules my-rules.json`.

## Rule fields

| Field | Meaning |
|---|---|
| `id` | Stable id, used in reports and SARIF |
| `provider` | `anthropic`, `openai`, … or `generic` |
| `severity` | `critical` (can manage other keys, or moves money), `high`, `medium`, `low` (test keys) |
| `regex` | RE2 syntax (no look-arounds) |
| `secretGroup` | Capture group holding the secret; 0 = whole match |
| `keywords` | Substrings that must appear on the line. They are the prefilter: the regex runs only on lines that contain one |
| `caseInsensitiveKeywords` | Match keywords ignoring case |
| `prefixLen` | Leading characters safe to print (the fixed prefix, never random material) |
| `priority` | Higher wins when two rules match the same characters |
| `entropyMin` | Minimum Shannon entropy (bits per char) for the value |
| `validate` | Extra check in code, e.g. `jwt-service-role` |
| `multiline` | Run on the whole buffer (PEM blocks) instead of keyword lines |
| `skipInTests` | Off in tests, fixtures, docs and examples |
| `generic` | The entropy-plus-context rule; off in lockfiles too |

## Adding a provider

1. Add the rule with a fixed prefix and the right `prefixLen`.
2. Add a fake-key generator line in `internal/testkeys/testkeys.go`. Build the prefix from pieces (`P("sk-", "proj-")`) so the repo never holds a literal key shape.
3. `make test`. `TestEveryProviderRuleFindsItsKey` fails until the fake key matches.
4. Bump `"version"` in `rules.json`.

## Formats to confirm before the public launch

These prefixes are well known, but exact lengths change. Each must be checked
against a real key (redacted) or the provider docs:

- Anthropic admin (`sk-ant-admin01-`) and API (`sk-ant-api03-`) key lengths
- OpenAI `sk-admin-` and `sk-svcacct-` formats
- Supabase `sb_secret_` length
- Google auth keys (`AQ.Ab…`, the default for new Gemini keys since 2026-05-28): only the prefix is
  public. The rule assumes 30–300 URL-safe characters after `AQ.Ab`; confirm against a real key.
- Groq, xAI and Hugging Face minimum lengths
- Twilio API key SIDs (`SK` + 32 hex) — medium severity because the SID alone is not the secret
