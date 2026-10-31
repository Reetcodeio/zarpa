# Releasing

Releases are built by GoReleaser from a git tag, in CI (`.github/workflows/release.yml`).

## One-time setup

| What | Why | Where it goes |
|---|---|---|
| Public `homebrew-tap` and `scoop-bucket` repos under the same account (`Reetcodeio/homebrew-tap`, `Reetcodeio/scoop-bucket`) | `brew install reetcodeio/tap/zarpa` / `scoop install zarpa` | Created by you, with a README (GoReleaser can't add the first file to an empty repo) |
| `HOMEBREW_TAP_TOKEN` secret | Lets the release push the Homebrew formula and the Scoop manifest to those repos | Repo secret (a fine-grained token with write access to those two repos only) |
| *Optional, later:* Apple Developer ID certificate as base64 `.p12` → `MACOS_SIGN_P12`, plus `MACOS_SIGN_PASSWORD` | Signs the macOS binary | Repo secrets |
| *Optional, later:* App Store Connect API key → `MACOS_NOTARY_ISSUER_ID`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_KEY` | Notarizes it so Gatekeeper accepts it when it is downloaded in a browser | Repo secrets |
| Azure Artifact Signing (Basic) | Signs the Windows `.exe` | Not wired yet: add a Windows job that signs `zarpa.exe` before archiving |

Without the Apple secrets the release still works; the macOS binary is unsigned
(only the ad-hoc signature Apple Silicon requires). That is fine for the three ways the README installs it: the Homebrew **formula**,
`install.sh` (curl) and `go install` don't set macOS's quarantine flag, and Gatekeeper only checks
quarantined files. It is *not* fine for a cask (Homebrew quarantines cask downloads) or for an
archive downloaded in a browser; the README says how to handle the latter. Add the Apple secrets
when the $99/year is worth it: the release workflow notarizes on its own once they exist.

Homebrew 6 asks users to trust third-party taps. Installing with the full name
(`brew install reetcodeio/tap/zarpa`) trusts just that formula, so no extra step is needed.

## Each release

1. `make test` passes and CI is green.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
3. The workflow builds 5 targets (one universal macOS binary), archives, `checksums.txt`, SBOMs, and a keyless cosign signature of the checksums.
4. The GitHub release is created as a **draft**: read the notes, then publish.

## Try it locally (nothing is published)

```sh
goreleaser release --snapshot --clean --skip=sign,sbom,publish,notarize
ls dist/
```

## How users verify a download

```sh
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/Reetcodeio/zarpa/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing
```

`install.sh` does both automatically when cosign is installed.
