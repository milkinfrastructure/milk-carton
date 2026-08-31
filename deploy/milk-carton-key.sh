#!/bin/bash
set -euo pipefail

readonly PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

die() {
  printf 'milk-carton-key: %s\n' "$*" >&2
  exit 64
}

file_mode() {
  stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"
}

file_owner() {
  stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' -- "$1"
}

file_links() {
  stat -c '%h' -- "$1" 2>/dev/null || stat -f '%l' -- "$1"
}

trusted_tool() {
  local path=$1 label=$2 mode
  [[ $path == /* && -f $path && ! -L $path && -x $path ]] || die "$label must be an absolute executable regular file"
  [[ $(file_owner "$path") == 0 ]] || die "$label must be owned by root"
  [[ $(file_links "$path") == 1 ]] || die "$label must be a single-link file"
  mode=$(file_mode "$path")
  [[ $mode =~ ^[0-7]{3,4}$ ]] || die "could not determine $label mode"
  (( (8#$mode & 8#022) == 0 )) || die "$label cannot be group or world writable"
}

main() {
  [[ $# -eq 3 ]] || die "usage: $0 OPENSSL_ABS UUIDGEN_ABS TOKEN_OUT_ABS"
  local openssl=$1 uuidgen=$2 token_out=$3 token_parent key_id secret token sha256 digest_tail created=0
  [[ $(id -u) != 0 ]] || die "run as an unprivileged operator"
  trusted_tool "$openssl" "OpenSSL"
  trusted_tool "$uuidgen" "uuidgen"
  [[ $token_out == /* && ! -e $token_out && ! -L $token_out ]] || die "token output must be a new absolute path"
  token_parent=$(cd "$(dirname "$token_out")" && pwd -P) || die "token output parent is unavailable"
  [[ ! -L $(dirname "$token_out") && $(file_owner "$token_parent") == "$(id -u)" ]] || die "token output parent must be a real operator-owned directory"
  local parent_mode
  parent_mode=$(file_mode "$token_parent")
  [[ $parent_mode =~ ^[0-7]{3,4}$ ]] || die "could not determine token output parent mode"
  (( (8#$parent_mode & 8#077) == 0 )) || die "token output parent cannot be accessible by group or other users"
  token_out=$token_parent/$(basename "$token_out")

  key_id=$("$uuidgen" | tr '[:upper:]' '[:lower:]')
  [[ $key_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || die "uuidgen returned an invalid UUID"
  secret=$("$openssl" rand -hex 32)
  [[ $secret =~ ^[0-9a-f]{64}$ ]] || die "OpenSSL returned an invalid secret"
  token="milk_live_${key_id}_${secret}"
  read -r sha256 digest_tail < <(printf '%s' "$token" | "$openssl" dgst -sha256 -r)
  [[ $sha256 =~ ^[0-9a-f]{64}$ && $digest_tail == '*stdin' ]] || die "OpenSSL returned an invalid SHA-256 digest"

  umask 077
  set -C
  printf '%s\n' "$token" >"$token_out" || die "token output was created concurrently"
  set +C
  created=1
  trap 'if ((created)); then rm -f -- "$token_out"; fi' EXIT
  chmod 0400 "$token_out"
  [[ -f $token_out && ! -L $token_out && $(file_links "$token_out") == 1 && $(file_mode "$token_out") == 400 ]] || die "token output is not an owner-read-only regular file"

  created=0
  trap - EXIT
  printf '{"key_id":"%s","api_key_sha256":"%s"}\n' "$key_id" "$sha256"
}

main "$@"
