#!/usr/bin/env bash
# Sign the nix-built sinete binary with Secure Enclave entitlements and run it.
#
# The Secure Enclave rejects key operations from an unsigned/unentitled binary
# (errSecMissingEntitlement / CFError -34018), and `nix build` produces only an
# ad-hoc-signed binary. This copies the build output to a writable path, signs it
# with an Apple Development identity + sinete.entitlements, then runs it.
#
# Usage:   scripts/sign-and-run.sh [args passed to sinete, e.g. -keep]
# Override identity:  SINETE_SIGN_IDENTITY="Apple Development: ... (TEAMID)" scripts/sign-and-run.sh
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
identity="${SINETE_SIGN_IDENTITY:-Apple Development: Paulo Duarte (P6K8K4X996)}"
bin="$repo/result/bin/sinete"
out="$repo/sinete"
ent="$repo/sinete.entitlements"

[ -x "$bin" ] || { echo "no build output at $bin — run 'nix build' first" >&2; exit 1; }

cp -f "$bin" "$out"
chmod u+w "$out"
codesign --force --sign "$identity" --entitlements "$ent" "$out"

echo "--- signature ---"
codesign -dv --entitlements - "$out" 2>&1 | grep -iE "Authority=Apple Development|TeamIdentifier|application-identifier|keychain-access" || true

echo "--- running spike (expect a Touch ID prompt) ---"
exec "$out" "$@"
