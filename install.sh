#!/bin/sh
# Zarpa installer: downloads a release, checks its SHA-256 against the
# signed checksum file, and (if cosign is installed) verifies that file's
# signature before installing. Read it before you run it.
#
#   curl -fsSL https://raw.githubusercontent.com/Reetcodeio/zarpa/main/install.sh | sh
#   ZARPA_VERSION=0.2.0 sh install.sh        # a specific version
#   ZARPA_BIN_DIR=~/.local/bin sh install.sh # somewhere other than /usr/local/bin
set -eu

REPO="${ZARPA_REPO:-Reetcodeio/zarpa}"
VERSION="${ZARPA_VERSION:-}"
BIN_DIR="${ZARPA_BIN_DIR:-/usr/local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) echo "unsupported CPU: $arch" >&2; exit 1 ;; esac
case "$os" in darwin) arch=all ;; linux) ;; *) echo "unsupported OS: $os (use the .zip from the releases page)" >&2; exit 1 ;; esac

if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)"
fi
[ -n "$VERSION" ] || { echo "could not find the latest version" >&2; exit 1; }

base="https://github.com/$REPO/releases/download/v$VERSION"
file="zarpa_${VERSION}_${os}_${arch}.tar.gz"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

echo "Downloading $file"
curl -fsSL -o "$tmp/$file" "$base/$file"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"

if command -v cosign >/dev/null 2>&1; then
  curl -fsSL -o "$tmp/checksums.txt.sig" "$base/checksums.txt.sig"
  curl -fsSL -o "$tmp/checksums.txt.pem" "$base/checksums.txt.pem"
  cosign verify-blob \
    --certificate "$tmp/checksums.txt.pem" --signature "$tmp/checksums.txt.sig" \
    --certificate-identity-regexp "^https://github.com/$REPO/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$tmp/checksums.txt" >/dev/null
  echo "Signature OK (cosign)"
else
  echo "cosign not installed: checking the SHA-256 only (brew install cosign for the full check)"
fi

expected="$(grep " $file\$" "$tmp/checksums.txt" | cut -d' ' -f1)"
if command -v sha256sum >/dev/null 2>&1; then actual="$(sha256sum "$tmp/$file" | cut -d' ' -f1)"
else actual="$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)"; fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "checksum mismatch, not installing" >&2; exit 1; }
echo "Checksum OK"

tar -xzf "$tmp/$file" -C "$tmp" zarpa
if [ -w "$BIN_DIR" ]; then install -m 0755 "$tmp/zarpa" "$BIN_DIR/zarpa"
else sudo install -m 0755 "$tmp/zarpa" "$BIN_DIR/zarpa"; fi
echo "Installed $BIN_DIR/zarpa ($("$BIN_DIR/zarpa" version))"
