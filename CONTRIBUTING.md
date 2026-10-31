# Contributing

Thanks for helping. Bug reports, false positives, false negatives and new
provider rules are all welcome.

## Build and test

Go 1.23 or newer and git.

```sh
make build     # bin/zarpa
make test      # all tests
make race      # with the race detector
make lint      # gofmt + go vet (+ golangci-lint when installed)
make demo      # scan a fake machine full of fake keys
```

The CLI uses only the Go standard library. Please keep it that way: every
dependency is code that runs next to people's keys.

## Rules

Detection rules live in `rules/rules.json`. `docs/RULES.md` explains the
fields and how to add a provider. A new rule needs a positive and a negative
test.

## Never commit a key-shaped string

Not even a fake one. Secret scanners (including this one, which runs on every
CI build) would flag it, and so would GitHub push protection. Build fake keys
at test time with `internal/testkeys`, joining the prefix from pieces:
`P("sk-", "proj-") + g.URLSafe(120)`.

## Reporting a false positive

Open an issue with the rule id from the report and the **redacted** value
(prefix and last 4, exactly as Zarpa prints it). Never paste a real key into
an issue. If it is a placeholder or test value in your own code, a `zarpa:allow`
comment on that line silences it.

## Security issues

Please report them privately instead of opening an issue: the **Security** tab →
**Report a vulnerability**, or security@zarpa.dev (see `docs/SECURITY.md`).
