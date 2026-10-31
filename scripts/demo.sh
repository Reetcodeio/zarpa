#!/bin/sh
# Scans a throwaway fake machine full of fake keys, so you can see a real
# report without exposing anything of yours. Your own files, keychain and
# history are never read: HOME points at the fake machine and the salt goes
# to a temporary file.
#
#   make demo            (or: ./scripts/demo.sh after make build)
set -eu
cd "$(dirname "$0")/.."
[ -x bin/zarpa ] || { echo "run make build first" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
go run ./scripts/demo "$tmp"

echo "\$ zarpa scan ~/code"
HOME="$tmp/home" ./bin/zarpa scan "$tmp/home/code" --salt-file "$tmp/salt" --exit-zero "$@"
