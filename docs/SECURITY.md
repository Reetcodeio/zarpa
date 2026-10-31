# Security

Zarpa handles the thing attackers want most: API keys. This page says what
the CLI does with them, so you can check every claim against the code.

## Reporting a vulnerability

Please don't open a public issue for a vulnerability. Report it privately,
either on GitHub (this repository's **Security** tab → **Report a vulnerability**)
or by email to **security@zarpa.dev**.

## What the CLI does

| Question | Answer | Where in the code |
|---|---|---|
| Does it make network calls? | Only `zarpa check` (after you confirm) and the optional cloud commands `login`, `sync` and `panic`. `check` sends one read-only request per key to that key's own provider, over HTTPS, redirects never followed, key in a header (never a URL). Keys in other people's commits are never sent. | `internal/live`, `cmd/zarpa/cloud.go` |
| Does it collect telemetry? | No. | — |
| Does it print raw keys? | No. Prefix + last 4 only, at least 12 characters hidden. | `internal/scan.Redact` |
| Does it write raw keys to disk? | No. Reports (`-o`) hold redacted values and fingerprints; files are created `0600`. | `internal/report`, `cmd/zarpa` |
| Where does `vault` keep keys? | macOS Keychain (service `zarpa-vault`) or Linux Secret Service. Values go through stdin, never command-line arguments. No plaintext fallback. | `internal/vault` |
| Can `vault get` leak a key to the screen? | Only with `--reveal`; otherwise raw values go to pipes only. | `cmd/zarpa/vault.go` |
| What is a fingerprint? | `hex(HMAC-SHA256(salt, key))`. Not reversible without the salt. | `internal/fingerprint` |
| Where is the salt? | macOS Keychain (service `zarpa`, account `fingerprint-salt`); Linux Secret Service when available; otherwise a `0600` file in the user config dir. `--salt-file` puts it elsewhere. | `internal/fingerprint` |
| Which programs does it run? | `git` (read-only: `log`, `diff --cached`, `config`, `rev-parse`), `/usr/bin/security` on macOS, `stty` to hide pasted keys, and the command you give `zarpa run`. | `sources/gitsrc`, `internal/fingerprint`, `internal/vault`, `cmd/zarpa` |
| Third-party dependencies? | None. Go standard library only. | `go.mod` |

Known limitation: on macOS the fingerprint salt is passed to
`security add-generic-password` as an argument once, when it is created. The
salt is not a credential; real keys (`zarpa vault`) always go through stdin.

## What leaves the machine with Zarpa Cloud (optional, paid)

Nothing, unless you run `zarpa login` and then `zarpa sync`. `sync` first shows
exactly what it will send (`--dry-run` sends nothing) and asks. Per key, it
uploads only:

```json
{ "fingerprint": "…", "provider": "openai", "last4": "x9Qa",
  "locations": ["repo:web:.env.local:3"], "public_exposure": false,
  "first_seen": "2026-10-29T17:00:00Z" }
```

- Location refs use `~` instead of your home path.
- Keys found only in other people's commits are not sent at all.
- Uploaded fingerprints use your Zarpa account's salt instead of the
  machine's, so one key on two machines is one key. The cloud keeps that salt
  encrypted with a key-management service and audits every read; the CLI
  fetches it on each sync and keeps it in memory only. Someone holding both
  Zarpa's database and your account's salt could confirm whether a key *they
  already have* is in your account; nobody can recover a key from a
  fingerprint.
- The CLI token is stored in the keychain (service `zarpa-cloud`), is sent only
  to the API it logged in to, and follows no redirects.
- `zarpa panic` can only **freeze** keys (reversible, audited), never delete
  them, so a stolen CLI token can pause keys but not destroy them. Revoke
  tokens in the dashboard.
