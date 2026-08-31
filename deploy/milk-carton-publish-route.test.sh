#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly RUNNER=$SCRIPT_DIR/milk-carton-publish-route.sh
readonly TEST_DIR=$(mktemp -d)
readonly REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
readonly IN_REPO_KEY=$(mktemp "$REPO_ROOT/.milk-carton-route-key.XXXXXX")
readonly IN_REPO_GATEWAY=$(mktemp "$REPO_ROOT/.milk-carton-route-gateway.XXXXXX")
readonly IN_REPO_OPENSSL=$(mktemp "$REPO_ROOT/.milk-carton-route-openssl.XXXXXX")
trap 'rm -rf -- "$TEST_DIR"; rm -f -- "$IN_REPO_KEY" "$IN_REPO_GATEWAY" "$IN_REPO_OPENSSL"' EXIT

fail() {
  printf 'milk-carton-publish-route.test: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

cat >"$TEST_DIR/gateway" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_LOG"
if [[ $* == *"publish-route"* && $* == *"--signature"* ]]; then
  signature=
  manifest=
  while (($#)); do
    case $1 in
      --manifest) manifest=$2; shift 2 ;;
      --signature) signature=$2; shift 2 ;;
      *) shift ;;
    esac
  done
  "$FAKE_OPENSSL" pkeyutl -verify -rawin -pubin -inkey "$FAKE_PUBLIC_KEY" -in "$manifest" -sigfile "$signature" >/dev/null
  printf '{"schema_version":"milk.route-publication-receipt.v3","candidate_api_key_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active"}\n'
elif [[ $* == *"publish-route"* && $* == *"--check-only"* && ${MUTATE_MANIFEST:-0} == 1 ]]; then
  chmod 0600 "$FAKE_MANIFEST"
  printf 'x' >>"$FAKE_MANIFEST"
fi
SH
chmod 0500 "$TEST_DIR/gateway"
cp "$(command -v openssl)" "$TEST_DIR/openssl"
chmod 0500 "$TEST_DIR/openssl"
printf '{}\n' >"$TEST_DIR/config.json"
printf '{"exact":"route-bytes"}\n' >"$TEST_DIR/route.json"
chmod 0400 "$TEST_DIR/route.json"
"$TEST_DIR/openssl" genpkey -algorithm ED25519 -out "$TEST_DIR/signing.pem" >/dev/null 2>&1
"$TEST_DIR/openssl" pkey -in "$TEST_DIR/signing.pem" -pubout -out "$TEST_DIR/public.pem" >/dev/null 2>&1
chmod 0600 "$TEST_DIR/signing.pem"
export FAKE_LOG=$TEST_DIR/calls.log
export FAKE_PUBLIC_KEY=$TEST_DIR/public.pem
export FAKE_MANIFEST=$TEST_DIR/route.json
export FAKE_OPENSSL=$TEST_DIR/openssl
mkdir "$TEST_DIR/poison"
cat >"$TEST_DIR/poison/stat" <<'SH'
#!/bin/sh
touch "$POISON_MARKER"
exit 1
SH
chmod 0700 "$TEST_DIR/poison/stat"
export POISON_MARKER=$TEST_DIR/poison-used
export PATH=$TEST_DIR/poison:$PATH

receipt=$(
  "$RUNNER" \
    "$TEST_DIR/gateway" \
    "$TEST_DIR/openssl" \
    "$TEST_DIR/config.json" \
    "$TEST_DIR/route.json" \
    "$TEST_DIR/route.sig" \
    "$TEST_DIR/signing.pem"
)
[[ ! -e $POISON_MARKER ]] || fail "route signer used an operator-controlled PATH tool"
[[ $receipt == '{"schema_version":"milk.route-publication-receipt.v3","candidate_api_key_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active"}' ]] || fail "publication receipt changed"
[[ $(wc -c <"$TEST_DIR/route.sig" | tr -d ' ') == 64 ]] || fail "signature is not 64 raw bytes"
"$TEST_DIR/openssl" pkeyutl -verify -rawin -pubin -inkey "$TEST_DIR/public.pem" -in "$TEST_DIR/route.json" -sigfile "$TEST_DIR/route.sig" >/dev/null || fail "signature does not cover exact manifest bytes"
[[ $(wc -l <"$FAKE_LOG" | tr -d ' ') == 2 ]] || fail "unexpected Rust command count"
expected_calls="--config $TEST_DIR/config.json publish-route --manifest $TEST_DIR/route.json --check-only
--config $TEST_DIR/config.json publish-route --manifest $TEST_DIR/route.json --signature $TEST_DIR/.milk-carton-route-signature.TOKEN"
actual_calls=$(sed -E '2s#(\.milk-carton-route-signature\.)[^ ]+#\1TOKEN#' "$FAKE_LOG")
[[ $actual_calls == "$expected_calls" ]] || fail "publisher passed fields outside the signed manifest"
expect_failure "$RUNNER" "$TEST_DIR/gateway" "$TEST_DIR/openssl" "$TEST_DIR/config.json" "$TEST_DIR/route.json" "$TEST_DIR/extra.sig" "$TEST_DIR/signing.pem" extra

printf '{"mutable":true}\n' >"$TEST_DIR/mutable.json"
expect_failure "$RUNNER" "$TEST_DIR/gateway" "$TEST_DIR/openssl" "$TEST_DIR/config.json" "$TEST_DIR/mutable.json" "$TEST_DIR/mutable.sig" "$TEST_DIR/signing.pem"

"$TEST_DIR/openssl" genpkey -algorithm ED25519 -out "$IN_REPO_KEY" >/dev/null 2>&1
chmod 0600 "$IN_REPO_KEY"
expect_failure "$RUNNER" "$TEST_DIR/gateway" "$TEST_DIR/openssl" "$TEST_DIR/config.json" "$TEST_DIR/route.json" "$TEST_DIR/repo-key.sig" "$IN_REPO_KEY"

cp "$TEST_DIR/gateway" "$IN_REPO_GATEWAY"
chmod 0500 "$IN_REPO_GATEWAY"
expect_failure "$RUNNER" "$IN_REPO_GATEWAY" "$TEST_DIR/openssl" "$TEST_DIR/config.json" "$TEST_DIR/route.json" "$TEST_DIR/repo-gateway.sig" "$TEST_DIR/signing.pem"
cp "$TEST_DIR/gateway" "$TEST_DIR/writable-gateway"
chmod 0700 "$TEST_DIR/writable-gateway"
expect_failure "$RUNNER" "$TEST_DIR/writable-gateway" "$TEST_DIR/openssl" "$TEST_DIR/config.json" "$TEST_DIR/route.json" "$TEST_DIR/writable-gateway.sig" "$TEST_DIR/signing.pem"
cp "$TEST_DIR/openssl" "$TEST_DIR/writable-openssl"
chmod 0700 "$TEST_DIR/writable-openssl"
expect_failure "$RUNNER" "$TEST_DIR/gateway" "$TEST_DIR/writable-openssl" "$TEST_DIR/config.json" "$TEST_DIR/route.json" "$TEST_DIR/writable-openssl.sig" "$TEST_DIR/signing.pem"
ln "$TEST_DIR/signing.pem" "$TEST_DIR/signing-link.pem"
expect_failure "$RUNNER" "$TEST_DIR/gateway" "$TEST_DIR/openssl" "$TEST_DIR/config.json" "$TEST_DIR/route.json" "$TEST_DIR/linked-key.sig" "$TEST_DIR/signing.pem"
rm "$TEST_DIR/signing-link.pem"

cp "$TEST_DIR/openssl" "$IN_REPO_OPENSSL"
chmod 0500 "$IN_REPO_OPENSSL"
expect_failure "$RUNNER" "$TEST_DIR/gateway" "$IN_REPO_OPENSSL" "$TEST_DIR/config.json" "$TEST_DIR/route.json" "$TEST_DIR/repo-openssl.sig" "$TEST_DIR/signing.pem"

printf '{"exact":"mutated-during-preflight"}\n' >"$TEST_DIR/mutated.json"
chmod 0400 "$TEST_DIR/mutated.json"
export MUTATE_MANIFEST=1
export FAKE_MANIFEST=$TEST_DIR/mutated.json
expect_failure "$RUNNER" "$TEST_DIR/gateway" "$TEST_DIR/openssl" "$TEST_DIR/config.json" "$TEST_DIR/mutated.json" "$TEST_DIR/mutated.sig" "$TEST_DIR/signing.pem"
[[ ! -e $TEST_DIR/mutated.sig ]] || fail "mutation produced a signature"
unset MUTATE_MANIFEST

printf 'milk-carton-publish-route.test: ok\n'
