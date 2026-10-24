#!/usr/bin/env bash
# Installs forhunt and Hayabusa for the Forensic Hunter skill (Linux, macOS).
#
#   install.sh [--prefix DIR] [--forhunt-version vX.Y.Z] [--hayabusa-version X.Y.Z]
#              [--no-hayabusa | --no-forhunt]
#
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
FORHUNT_VERSION="${FORHUNT_VERSION:-latest}"
HAYABUSA_VERSION="${HAYABUSA_VERSION:-4.2.0}"
PREFIX="${FORHUNT_PREFIX:-$HOME/.local/share/forensic-hunter}"
WITH_HAYABUSA=1
WITH_FORHUNT=1
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --forhunt-version) FORHUNT_VERSION="$2"; shift 2 ;;
    --hayabusa-version) HAYABUSA_VERSION="$2"; shift 2 ;;
    --no-hayabusa) WITH_HAYABUSA=0; shift ;;
    --no-forhunt) WITH_FORHUNT=0; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed -n 's/^# \{0,1\}//p'; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

die() { echo "install: $*" >&2; exit 1; }
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
  Darwin) ft_os="apple-darwin"; hb_os="mac" ;;
  *) die "unsupported OS $os (use install.ps1 on Windows)" ;;
esac
case "$arch" in
  x86_64|amd64) ft_arch="x86_64"; hb_arch="x64" ;;
  arm64|aarch64) ft_arch="aarch64"; hb_arch="aarch64" ;;
  *) die "unsupported architecture $arch" ;;
esac
target="${ft_arch}-${ft_os}"
# Intel Macs are not released (D-042); build from source there.
[ "$target" = "x86_64-apple-darwin" ] && die "no Intel macOS build; use: cargo install --git https://github.com/0xRD/forensic-hunter forhunt"
case "$hb_os" in
  lin) hb_plat="lin-${hb_arch}-musl" ;;
  mac) hb_plat="mac-${hb_arch}" ;;
esac

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$PREFIX/bin"

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
archive="forhunt-${ver}-${target}.tar.gz"
# FORHUNT_BASE_URL: optional mirror holding the release assets (offline labs).
base="${FORHUNT_BASE_URL:-https://github.com/$FORHUNT_REPO/releases/download/v${ver}}"
echo "forhunt v${ver} (${target})"
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
install -m 0755 "$tmp/forhunt-${ver}-${target}/forhunt" "$PREFIX/bin/forhunt"
"$PREFIX/bin/forhunt" --version
fi

# --- Hayabusa ----------------------------------------------------------------
if [ "$WITH_HAYABUSA" = 1 ]; then
  need unzip
  hb_zip="hayabusa-${HAYABUSA_VERSION}-${hb_plat}.zip"
  expected="$(awk -v f="$hb_zip" '$2 == f {print $1}' "$HERE/hayabusa.sha256")"
  [ -n "$expected" ] || die "Hayabusa $HAYABUSA_VERSION ($hb_plat) is not pinned in hayabusa.sha256; refusing an unverified download"
  echo "Hayabusa ${HAYABUSA_VERSION} (${hb_plat})"
  curl -fsSL -o "$tmp/$hb_zip" "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${hb_zip}" \
    || die "Hayabusa download failed"
  verify "$tmp/$hb_zip" "$expected"
  dest="$PREFIX/hayabusa-${HAYABUSA_VERSION}"
  rm -rf "$dest"; mkdir -p "$dest"
  unzip -q "$tmp/$hb_zip" -d "$dest"
  chmod +x "$dest/hayabusa-${HAYABUSA_VERSION}-${hb_plat}"
  # Hayabusa finds rules/ and config/ next to its binary: wrap instead of copying.
  cat > "$PREFIX/bin/hayabusa" <<WRAP
#!/usr/bin/env bash
cd "$dest" && exec "./hayabusa-${HAYABUSA_VERSION}-${hb_plat}" "\$@"
WRAP
  chmod +x "$PREFIX/bin/hayabusa"
  echo "  installed in $dest (rules included; refresh with: hayabusa update-rules)"
  echo "  note: the wrapper runs from the Hayabusa directory; pass absolute paths to -d/-f/-o."
fi

echo
echo "Done. Add to PATH:  export PATH=\"$PREFIX/bin:\$PATH\""
