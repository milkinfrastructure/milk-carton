#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: bundle-rust.sh OUTPUT" >&2
  exit 2
fi

output=$1
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

LC_ALL=C "${CARGO:-cargo}" tree --locked --package milk-carton \
  --target x86_64-unknown-linux-gnu --edges normal,build \
  --prefix none --format '{p}' > "$temporary/tree"
sed -E 's/ \(\*\)$//; s/ \(proc-macro\)$//' \
  < "$temporary/tree" > "$temporary/normalized"
LC_ALL=C sort -u < "$temporary/normalized" > "$temporary/packages"
package_count=$(wc -l < "$temporary/packages")
if [ "$package_count" -le 1 ]; then
  echo "cargo tree returned no registry dependencies" >&2
  exit 1
fi

cat > "$output" <<'EOF'
Milk Carton Rust dependency licenses and notices

This deterministic bundle contains the legal files shipped in every registry
crate linked into the x86_64 Linux gateway. When a crate ships no separate
legal file, its registry Cargo.toml is preserved instead.
EOF

while IFS=' ' read -r name tagged_version _rest; do
  [ "$name" = "milk-carton" ] && continue
  case "$tagged_version" in
    v*) version=${tagged_version#v} ;;
    *) echo "invalid cargo tree package: $name $tagged_version" >&2; exit 1 ;;
  esac

  crate=
  matches=0
  for candidate in "${CARGO_HOME:-/usr/local/cargo}"/registry/src/*/"$name-$version"; do
    [ -d "$candidate" ] || continue
    crate=$candidate
    matches=$((matches + 1))
  done
  if [ "$matches" -ne 1 ]; then
    echo "expected one registry source for $name $version, found $matches" >&2
    exit 1
  fi

  find "$crate" -maxdepth 2 -type f \
    \( -iname 'license*' -o -iname 'licence*' -o -iname 'copying*' \
       -o -iname 'copyright*' -o -iname 'notice*' -o -iname 'authors*' \
       -o -iname 'unlicense' \) \
    | LC_ALL=C sort > "$temporary/legal"

  printf '\n===== %s %s =====\n' "$name" "$version" >> "$output"
  if [ -s "$temporary/legal" ]; then
    while IFS= read -r legal; do
      relative=${legal#"$crate"/}
      printf '\n----- %s -----\n' "$relative" >> "$output"
      cat "$legal" >> "$output"
      printf '\n' >> "$output"
    done < "$temporary/legal"
  else
    printf '\n----- Cargo.toml (no separate legal file shipped) -----\n' >> "$output"
    cat "$crate/Cargo.toml" >> "$output"
    printf '\n' >> "$output"
  fi
done < "$temporary/packages"

chmod 0444 "$output"
