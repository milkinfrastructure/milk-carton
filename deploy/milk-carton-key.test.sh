#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly RUNNER=$SCRIPT_DIR/milk-carton-key.sh
readonly TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT

fail() {
  printf 'milk-carton-key.test: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

readonly OPENSSL=/usr/bin/openssl
readonly UUIDGEN=/usr/bin/uuidgen
[[ -x $OPENSSL && -x $UUIDGEN ]] || fail "root-owned system OpenSSL and uuidgen are required"

mkdir -m 0700 "$TEST_DIR/private"
metadata=$("$RUNNER" "$OPENSSL" "$UUIDGEN" "$TEST_DIR/private/traffic.token")
readonly METADATA_RE='^\{"key_id":"([0-9a-f-]{36})","api_key_sha256":"([0-9a-f]{64})"\}$'
[[ $metadata =~ $METADATA_RE ]] || fail "metadata output changed"
expected_id=${BASH_REMATCH[1]}
expected_sha=${BASH_REMATCH[2]}
token=$(<"$TEST_DIR/private/traffic.token")
[[ $token =~ ^milk_live_[0-9a-f-]{36}_[0-9a-f]{64}$ ]] || fail "token format is invalid"
[[ ${token:10:36} == "$expected_id" ]] || fail "metadata key ID differs from token"
[[ $metadata != *"$token"* ]] || fail "raw token leaked to stdout"
actual_sha=$(printf '%s' "$token" | "$OPENSSL" dgst -sha256 -r)
actual_sha=${actual_sha%% *}
[[ $actual_sha == "$expected_sha" ]] || fail "token verifier does not cover exact token bytes"
mode=$(stat -c '%a' -- "$TEST_DIR/private/traffic.token" 2>/dev/null || stat -f '%Lp' "$TEST_DIR/private/traffic.token")
[[ $mode == 400 ]] || fail "token file mode is not 0400"

expect_failure "$RUNNER" "$OPENSSL" "$UUIDGEN" "$TEST_DIR/private/traffic.token"
mkdir -m 0755 "$TEST_DIR/public"
expect_failure "$RUNNER" "$OPENSSL" "$UUIDGEN" "$TEST_DIR/public/token"
cp "$OPENSSL" "$TEST_DIR/private/operator-openssl"
chmod 0500 "$TEST_DIR/private/operator-openssl"
expect_failure "$RUNNER" "$TEST_DIR/private/operator-openssl" "$UUIDGEN" "$TEST_DIR/private/other.token"

mkdir "$TEST_DIR/poison"
cat >"$TEST_DIR/poison/openssl" <<'SH'
#!/bin/sh
printf 'stolen\n' >"$POISON_MARKER"
exit 1
SH
chmod 0700 "$TEST_DIR/poison/openssl"
export POISON_MARKER=$TEST_DIR/poison-used
PATH=$TEST_DIR/poison:$PATH "$RUNNER" "$OPENSSL" "$UUIDGEN" "$TEST_DIR/private/outcome.token" >/dev/null
[[ ! -e $POISON_MARKER ]] || fail "generator used an operator-controlled PATH tool"

printf 'milk-carton-key.test: ok\n'
