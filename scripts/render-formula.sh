#!/usr/bin/env bash
# Renders the Homebrew formula for a release.
# usage: scripts/render-formula.sh vX.Y.Z DIR_WITH_SHA256_FILES   (or)
#        scripts/render-formula.sh vX.Y.Z --from-release   (downloads SHA256SUMS)
set -euo pipefail
tag="$1"; src="$2"; ver="${tag#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$src" = "--from-release" ]; then
  sums="$(curl -fsSL "https://github.com/0xRD/forensic-hunter/releases/download/${tag}/SHA256SUMS")"
else
  sums="$(cat "$src"/*.sha256)"
fi
out="$(cat "$root/packaging/homebrew/forhunt.rb.in")"
out="${out//@VERSION@/$ver}"
for t in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
  sha="$(printf '%s\n' "$sums" | awk -v f="forhunt-${ver}-${t}.tar.gz" '$2 == f || $2 == "*"f {print $1}')"
  [ -n "$sha" ] || { echo "missing checksum for $t" >&2; exit 1; }
  out="${out//@SHA_${t}@/$sha}"
done
printf '%s\n' "$out"
