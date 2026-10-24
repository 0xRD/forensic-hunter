#!/usr/bin/env bash
# Fallback when the release workflow cannot push to the tap (no
# TAP_DEPLOY_KEY): renders the formula from a published release and pushes
# it with your local `gh` login.
# usage: scripts/update-tap.sh v0.1.0 [owner/homebrew-tap]
set -euo pipefail
tag="${1:?usage: update-tap.sh vX.Y.Z [owner/homebrew-tap]}"
tap="${2:-0xRD/homebrew-tap}"
root="$(cd "$(dirname "$0")/.." && pwd)"
command -v gh >/dev/null || { echo "gh is required (https://cli.github.com)" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
"$root/scripts/render-formula.sh" "$tag" --from-release > "$work/forhunt.rb"
gh repo clone "$tap" "$work/tap"
mkdir -p "$work/tap/Formula"
cp "$work/forhunt.rb" "$work/tap/Formula/forhunt.rb"
cd "$work/tap"
git add Formula/forhunt.rb
if git commit -m "forhunt ${tag#v}"; then
  git push
  echo "pushed Formula/forhunt.rb to $tap"
else
  echo "formula already up to date"
fi
