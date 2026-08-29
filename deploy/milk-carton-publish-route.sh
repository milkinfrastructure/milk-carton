#!/bin/bash
set -euo pipefail

readonly PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

die() {
  printf 'milk-carton-publish-route: %s\n' "$*" >&2
  exit 64
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{print $1}'
  else
    shasum -a 256 -- "$1" | awk '{print $1}'
  fi
}

file_mode() {
  stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"
}

file_owner() {
  stat -c '%u' -- "$1" 2>/dev/null || stat -f '%u' -- "$1"
}

file_size() {
  stat -c '%s' -- "$1" 2>/dev/null || stat -f '%z' -- "$1"
}

file_links() {
  stat -c '%h' -- "$1" 2>/dev/null || stat -f '%l' -- "$1"
}

canonical_file() {
  local directory name
  directory=$(cd "$(dirname "$1")" && pwd -P) || return
  name=$(basename "$1")
  printf '%s/%s\n' "$directory" "$name"
}

owned_regular_file() {
  [[ -f $1 && ! -L $1 ]] || die "$2 must be a regular non-symlink file"
  [[ $(file_owner "$1") == "$(id -u)" ]] || die "$2 must be owned by the operator"
}

main() {
  [[ $# -eq 6 ]] || die "usage: $0 GATEWAY_ABS OPENSSL_ABS CONFIG_ABS MANIFEST_ABS SIGNATURE_OUT_ABS SIGNING_KEY_ABS"
  local gateway=$1 openssl=$2 config=$3 manifest=$4 signature_out=$5 signing_key=$6
  [[ $gateway == /* && $openssl == /* && $config == /* && $manifest == /* && $signature_out == /* && $signing_key == /* ]] || die "all file paths must be absolute"
  [[ -x $gateway ]] || die "gateway must be executable"
  [[ -x $openssl ]] || die "OpenSSL must be executable"
  owned_regular_file "$gateway" "gateway"
  owned_regular_file "$openssl" "OpenSSL"
  owned_regular_file "$config" "config"
  owned_regular_file "$manifest" "route manifest"
  owned_regular_file "$signing_key" "signing key"
  [[ $(file_links "$gateway") == 1 && $(file_links "$openssl") == 1 && $(file_links "$signing_key") == 1 ]] || die "gateway, OpenSSL, and signing key must be single-link files"
  [[ ! -e $signature_out && ! -L $signature_out ]] || die "signature output already exists"
  [[ -d $(dirname "$signature_out") && ! -L $(dirname "$signature_out") ]] || die "signature output parent must be a real directory"

  local gateway_mode openssl_mode manifest_mode key_mode repo_root canonical_gateway canonical_openssl canonical_key
  gateway_mode=$(file_mode "$gateway")
  openssl_mode=$(file_mode "$openssl")
  manifest_mode=$(file_mode "$manifest")
  key_mode=$(file_mode "$signing_key")
  [[ $gateway_mode =~ ^[0-7]{3,4}$ && $openssl_mode =~ ^[0-7]{3,4}$ && $manifest_mode =~ ^[0-7]{3,4}$ && $key_mode =~ ^[0-7]{3,4}$ ]] || die "could not determine secure file modes"
  (( (8#$gateway_mode & 8#222) == 0 )) || die "gateway must not be writable"
  (( (8#$openssl_mode & 8#222) == 0 )) || die "OpenSSL must not be writable"
  (( (8#$manifest_mode & 8#222) == 0 )) || die "route manifest must be immutable to owner and group"
  (( (8#$key_mode & 8#077) == 0 )) || die "signing key cannot be accessible by group or other users"
  repo_root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel) || die "repository root is unavailable"
  canonical_gateway=$(canonical_file "$gateway") || die "gateway path is unavailable"
  canonical_openssl=$(canonical_file "$openssl") || die "OpenSSL path is unavailable"
  canonical_key=$(canonical_file "$signing_key") || die "signing key path is unavailable"
  [[ $canonical_gateway != "$repo_root" && $canonical_gateway != "$repo_root/"* ]] || die "gateway must be installed outside the repository"
  [[ $canonical_openssl != "$repo_root" && $canonical_openssl != "$repo_root/"* ]] || die "OpenSSL must be installed outside the repository"
  [[ $canonical_key != "$repo_root" && $canonical_key != "$repo_root/"* ]] || die "signing key must remain outside the repository"
  gateway=$canonical_gateway
  openssl=$canonical_openssl
  signing_key=$canonical_key
  "$openssl" pkey -in "$signing_key" -check -noout >/dev/null 2>&1 || die "signing key is not a readable private key"

  local manifest_sha signature_tmp signature_sha receipt
  manifest_sha=$(sha256_file "$manifest")
  "$gateway" --config "$config" publish-route --manifest "$manifest" --check-only >/dev/null
  [[ $(sha256_file "$manifest") == "$manifest_sha" ]] || die "route manifest changed after publication preflight"

  umask 077
  signature_tmp=$(mktemp "$(dirname "$signature_out")/.milk-carton-route-signature.XXXXXX") || die "could not create signature temporary file"
  trap 'rm -f -- "$signature_tmp"' EXIT
  "$openssl" pkeyutl -sign -rawin -inkey "$signing_key" -in "$manifest" -out "$signature_tmp" || die "route signing failed"
  [[ $(file_size "$signature_tmp") == 64 ]] || die "Ed25519 signature must contain exactly 64 raw bytes"
  chmod 0400 "$signature_tmp"
  signature_sha=$(sha256_file "$signature_tmp")
  [[ $(sha256_file "$manifest") == "$manifest_sha" ]] || die "route manifest changed during signing"

  receipt=$("$gateway" --config "$config" publish-route --manifest "$manifest" --signature "$signature_tmp")
  [[ $(sha256_file "$manifest") == "$manifest_sha" ]] || die "route manifest changed during publication"
  [[ $(sha256_file "$signature_tmp") == "$signature_sha" ]] || die "route signature changed during publication"
  ln "$signature_tmp" "$signature_out" || die "signature output was created concurrently"
  rm -f -- "$signature_tmp"
  trap - EXIT
  printf '%s\n' "$receipt"
}

main "$@"
