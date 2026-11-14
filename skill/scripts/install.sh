#!/usr/bin/env bash
# Installs or updates forhunt and Hayabusa for the Forensic Hunter skill
# (Linux, macOS).
#
#   install.sh [--check] [--force] [--prefix DIR] [--forhunt-version vX.Y.Z]
#              [--hayabusa-version X.Y.Z] [--no-hayabusa | --no-forhunt]
#
# - --check installs nothing: it says which forhunt and Hayabusa would be
#   used, whether forhunt is recent enough for this skill, and how to update
#   it. Exit code 0 when both are ready, 1 otherwise.
# - Run again at any time to update: what is already at the wanted version is
#   left alone (--force installs it again), files are replaced atomically, and
#   older Hayabusa versions in the prefix are removed.
# - Detects OS and architecture.
# - Downloads release archives from GitHub over HTTPS and verifies SHA-256:
#   forhunt against the SHA256SUMS published with its release (or a pinned
#   checksums/forhunt-<version>.sha256 file next to this script when present),
#   Hayabusa against hayabusa.sha256 pinned in this skill.
# - Installs into --prefix, or $FORHUNT_PREFIX (default
#   ~/.local/share/forensic-hunter), with forhunt and a hayabusa wrapper in
#   <prefix>/bin. Nothing is embedded in the skill.
# - FORHUNT_BASE_URL: optional mirror holding the forhunt release assets.
#
# Hayabusa is GPL-3.0 software by Yamato Security, downloaded unmodified from
# https://github.com/Yamato-Security/hayabusa (source code available there).
set -euo pipefail

FORHUNT_REPO="0xRD/forensic-hunter"
# Oldest forhunt this skill's checklists and references work with (kept equal
# to MIN_FORHUNT in scripts/gen-checklist-index.py, checked in CI).
FORHUNT_MIN="0.6.0"
FORHUNT_VERSION="${FORHUNT_VERSION:-latest}"
HAYABUSA_VERSION="${HAYABUSA_VERSION:-4.2.0}"
PREFIX="${FORHUNT_PREFIX:-$HOME/.local/share/forensic-hunter}"
WITH_HAYABUSA=1
WITH_FORHUNT=1
CHECK=0
FORCE=0
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "install: $*" >&2; exit 1; }
value() { [ $# -ge 2 ] && [ -n "$2" ] || { echo "option $1 needs a value" >&2; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) value "$@"; PREFIX="$2"; shift 2 ;;
    --forhunt-version) value "$@"; FORHUNT_VERSION="$2"; shift 2 ;;
    --hayabusa-version) value "$@"; HAYABUSA_VERSION="$2"; shift 2 ;;
    --no-hayabusa) WITH_HAYABUSA=0; shift ;;
    --no-forhunt) WITH_FORHUNT=0; shift ;;
    --check) CHECK=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed -n 's/^# \{0,1\}//p'; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

# "forhunt 0.6.1" -> "0.6.1"; empty when the binary does not run.
version_of() { "$1" --version 2>/dev/null | awk 'NR == 1 && $1 == "forhunt" {print $2}' || true; }
# older A B: true when version A is lower than B (numeric x.y.z; a
# pre-release suffix is ignored).
older() {
  local a b i x y
  IFS=. read -r -a a <<< "${1%%[-+]*}"
  IFS=. read -r -a b <<< "${2%%[-+]*}"
  for i in 0 1 2; do
    x="${a[$i]:-0}"; y="${b[$i]:-0}"
    case "$x$y" in *[!0-9]*) return 1 ;; esac
    [ "$((10#$x))" -lt "$((10#$y))" ] && return 0
    [ "$((10#$x))" -gt "$((10#$y))" ] && return 1
  done
  return 1
}
# The file a command name or path really is (links followed), for messages.
real() {
  local p="$1" l
  while [ -L "$p" ]; do
    l="$(readlink "$p")"
    case "$l" in /*) p="$l" ;; *) p="$(dirname "$p")/$l" ;; esac
  done
  echo "$p"
}
update_hint() { # path of the forhunt found
  case "$(real "$1")" in
    */Cellar/forhunt/*|*/linuxbrew/*) echo "brew update && brew upgrade 0xrd/tap/forhunt" ;;
    *) echo "bash $HERE/install.sh" ;;
  esac
}

# --- check ---------------------------------------------------------------------
if [ "$CHECK" = 1 ]; then
  ok=1
  # What a shell with the documented PATH would run: the prefix first.
  fh=""
  if [ -x "$PREFIX/bin/forhunt" ]; then fh="$PREFIX/bin/forhunt"
  elif command -v forhunt >/dev/null 2>&1; then fh="$(command -v forhunt)"; fi
  if [ -z "$fh" ]; then
    echo "forhunt: not installed (install: bash $HERE/install.sh)"; ok=0
  else
    v="$(version_of "$fh")"
    if [ -z "$v" ]; then
      echo "forhunt: $fh does not run (reinstall: bash $HERE/install.sh --force)"; ok=0
    elif older "$v" "$FORHUNT_MIN"; then
      echo "forhunt: $v at $fh is too old, this skill needs $FORHUNT_MIN or later (update: $(update_hint "$fh"))"; ok=0
    else
      echo "forhunt: $v at $fh"
    fi
  fi
  hb=""
  if [ -x "$PREFIX/bin/hayabusa" ]; then hb="$PREFIX/bin/hayabusa"
  elif command -v hayabusa >/dev/null 2>&1; then hb="$(command -v hayabusa)"; fi
  if [ -n "$hb" ] && "$hb" help >/dev/null 2>&1; then
    echo "hayabusa: $hb"
  else
    echo "hayabusa: not installed (optional; install: bash $HERE/install.sh --no-forhunt)"; ok=0
  fi
  if [ "$ok" = 1 ]; then echo ready; exit 0; fi
  exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
need curl; need tar; need uname
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
verify() { # file expected
  local got; got="$(sha256 "$1")"
  [ "$got" = "$2" ] || die "checksum mismatch for $(basename "$1"): expected $2, got $got"
  echo "  sha256 ok  $(basename "$1")"
}

os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Linux)  ft_os="unknown-linux-musl"; hb_os="lin" ;;
  Darwin) ft_os="apple-darwin"; hb_os="mac"
    # A shell under Rosetta says x86_64 on Apple Silicon.
    if [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then arch=arm64; fi ;;
  *) die "unsupported OS $os (use install.ps1 on Windows)" ;;
esac
case "$arch" in
  x86_64|amd64) ft_arch="x86_64"; hb_arch="x64" ;;
  arm64|aarch64) ft_arch="aarch64"; hb_arch="aarch64" ;;
  *) die "unsupported architecture $arch" ;;
esac
target="${ft_arch}-${ft_os}"
# Intel Macs are not released (D-042); build from source there.
if [ "$WITH_FORHUNT" = 1 ] && [ "$target" = "x86_64-apple-darwin" ]; then
  die "no Intel macOS build; use: cargo install --git https://github.com/0xRD/forensic-hunter forhunt (Hayabusa alone: --no-forhunt)"
fi
case "$hb_os" in
  lin) hb_plat="lin-${hb_arch}-musl" ;;
  mac) hb_plat="mac-${hb_arch}" ;;
esac

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$PREFIX/bin"
# Absolute: the hayabusa wrapper changes directory.
PREFIX="$(cd "$PREFIX" && pwd)"
# Staging inside the prefix, so the final rename never crosses file systems.
stage="$PREFIX/.staging.$$"
trap 'rm -rf "$tmp" "$stage"' EXIT
rm -rf "$stage"; mkdir -p "$stage"

# --- forhunt -----------------------------------------------------------------
if [ "$WITH_FORHUNT" = 1 ]; then
if [ "$FORHUNT_VERSION" = "latest" ]; then
  # Resolve the tag through the redirect of /releases/latest (no API token needed).
  url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$FORHUNT_REPO/releases/latest")" \
    || die "cannot reach https://github.com/$FORHUNT_REPO/releases/latest"
  case "$url" in
    */tag/*) FORHUNT_VERSION="${url##*/tag/}" ;;
    *) die "no published forhunt release found; pass --forhunt-version vX.Y.Z" ;;
  esac
fi
ver="${FORHUNT_VERSION#v}"
case "$ver" in ""|*[!0-9A-Za-z.+-]*) die "not a version: $FORHUNT_VERSION" ;; esac
have="$(version_of "$PREFIX/bin/forhunt")"
if [ "$have" = "$ver" ] && [ "$FORCE" = 0 ]; then
  echo "forhunt v${ver} is already installed in $PREFIX/bin"
else
  archive="forhunt-${ver}-${target}.tar.gz"
  # FORHUNT_BASE_URL: optional mirror holding the release assets (offline labs).
  base="${FORHUNT_BASE_URL:-https://github.com/$FORHUNT_REPO/releases/download/v${ver}}"
  if [ -n "$have" ]; then echo "forhunt v${have} -> v${ver} (${target})"; else echo "forhunt v${ver} (${target})"; fi
  curl -fsSL -o "$tmp/$archive" "$base/$archive" || die "download failed: $base/$archive"
  if [ -f "$HERE/checksums/forhunt-${ver}.sha256" ]; then
    sums="$(cat "$HERE/checksums/forhunt-${ver}.sha256")"
  else
    sums="$(curl -fsSL "$base/SHA256SUMS")" || die "cannot download SHA256SUMS"
  fi
  expected="$(printf '%s\n' "$sums" | awk -v f="$archive" '$2 == f || $2 == "*"f {print $1}')"
  [ -n "$expected" ] || die "no checksum listed for $archive"
  verify "$tmp/$archive" "$expected"
  tar xzf "$tmp/$archive" -C "$tmp"
  # Checked before it replaces the installed one, then renamed into place:
  # a failed or interrupted update leaves the previous forhunt working.
  install -m 0755 "$tmp/forhunt-${ver}-${target}/forhunt" "$stage/forhunt"
  got="$(version_of "$stage/forhunt")"
  [ "$got" = "$ver" ] || die "the downloaded forhunt does not run or is not v${ver} (it says: ${got:-nothing}); nothing was changed"
  mv -f "$stage/forhunt" "$PREFIX/bin/forhunt"
  "$PREFIX/bin/forhunt" --version
fi
if older "$ver" "$FORHUNT_MIN"; then
  echo "  warning: this skill needs forhunt $FORHUNT_MIN or later; v${ver} will miss some checks" >&2
fi
# Another forhunt earlier in PATH would still be the one that runs.
other="$(command -v forhunt 2>/dev/null || true)"
if [ -n "$other" ] && [ "$(real "$other")" != "$(real "$PREFIX/bin/forhunt")" ]; then
  ov="$(version_of "$other")"
  if [ "$ov" != "$ver" ]; then
    echo "  note: PATH has another forhunt first: $other (v${ov:-?})."
    echo "        Put $PREFIX/bin first in PATH, or update that one: $(update_hint "$other")"
  fi
fi
fi

# --- Hayabusa ----------------------------------------------------------------
if [ "$WITH_HAYABUSA" = 1 ]; then
  case "$HAYABUSA_VERSION" in ""|*[!0-9A-Za-z.+-]*) die "not a version: $HAYABUSA_VERSION" ;; esac
  hb_zip="hayabusa-${HAYABUSA_VERSION}-${hb_plat}.zip"
  dest="$PREFIX/hayabusa-${HAYABUSA_VERSION}"
  hb_bin="hayabusa-${HAYABUSA_VERSION}-${hb_plat}"
  if [ -x "$dest/$hb_bin" ] && [ -x "$PREFIX/bin/hayabusa" ] && grep -qF "$dest" "$PREFIX/bin/hayabusa" && [ "$FORCE" = 0 ]; then
    echo "Hayabusa ${HAYABUSA_VERSION} is already installed in $dest"
  else
    need unzip
    expected="$(awk -v f="$hb_zip" '$2 == f {print $1}' "$HERE/hayabusa.sha256")"
    [ -n "$expected" ] || die "Hayabusa $HAYABUSA_VERSION ($hb_plat) is not pinned in hayabusa.sha256; refusing an unverified download"
    echo "Hayabusa ${HAYABUSA_VERSION} (${hb_plat})"
    curl -fsSL -o "$tmp/$hb_zip" "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${hb_zip}" \
      || die "Hayabusa download failed"
    verify "$tmp/$hb_zip" "$expected"
    mkdir -p "$stage/hayabusa"
    unzip -q "$tmp/$hb_zip" -d "$stage/hayabusa"
    [ -f "$stage/hayabusa/$hb_bin" ] || die "the Hayabusa archive does not hold $hb_bin; nothing was changed"
    chmod +x "$stage/hayabusa/$hb_bin"
    rm -rf "$dest"
    mv "$stage/hayabusa" "$dest"
    # Hayabusa finds rules/ and config/ next to its binary: wrap instead of copying.
    cat > "$stage/hayabusa.wrap" <<WRAP
#!/usr/bin/env bash
cd "$dest" && exec "./$hb_bin" "\$@"
WRAP
    chmod +x "$stage/hayabusa.wrap"
    mv -f "$stage/hayabusa.wrap" "$PREFIX/bin/hayabusa"
    echo "  installed in $dest (rules included; refresh with: hayabusa update-rules)"
  fi
  # Versions installed earlier by this script: the wrapper no longer uses them.
  for old in "$PREFIX"/hayabusa-[0-9]*; do
    [ -d "$old" ] && [ "$old" != "$dest" ] || continue
    rm -rf "$old"
    echo "  removed $(basename "$old")"
  done
  echo "  note: the wrapper runs from the Hayabusa directory; pass absolute paths to -d/-f/-o."
fi

echo
case ":$PATH:" in
  *":$PREFIX/bin:"*) echo "Done." ;;
  *) echo "Done. Add to PATH:  export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
