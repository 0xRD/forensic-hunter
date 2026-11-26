<#
.SYNOPSIS
  Installs forhunt and, if you say yes, its Sigma detection rules, for the
  Forensic Hunter skill (Windows).
.DESCRIPTION
  Downloads release archives from GitHub over HTTPS and verifies SHA-256:
  forhunt against the SHA256SUMS of its release (or a pinned
  checksums\forhunt-<version>.sha256 next to this script). Installs into
  $Prefix (default %LOCALAPPDATA%\forensic-hunter) and creates
  bin\forhunt.exe. forhunt runs the detection rules itself (forhunt sigma):
  nothing else is installed. -NoForhunt skips forhunt;
  $env:FORHUNT_BASE_URL points to a mirror of the forhunt release assets.

  Rules are never downloaded without asking: in an interactive session the
  script asks (default no); otherwise it downloads them only with -Rules (an
  answer given in advance: the skill asks you before passing it). -NoRules
  never downloads them. They are Yamato Security's hayabusa-rules (Sigma and
  Hayabusa rules, Detection Rule License 1.1, ~10 MB) at the commit pinned
  below, checked against a SHA-256 digest of their content, into
  $Prefix\rules\hayabusa-rules. -RulesLatest takes the newest rules instead
  (checked by HTTPS only). Your own rules go in $Prefix\rules\custom.

  -Check installs nothing: it says which forhunt and rules would be used and
  whether forhunt is recent enough for this skill (exit code 0 when both are
  ready, 1 otherwise). Run the script again at any time to update: what is
  already at the wanted version is left alone (-Force installs it again).

  The rules are by their authors (named in each rule and in forhunt's
  output), under https://github.com/SigmaHQ/Detection-Rule-License.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install.ps1
#>
[CmdletBinding()]
param(
  [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'forensic-hunter'),
  [string]$ForhuntVersion = 'latest',
  [switch]$Rules,
  [switch]$NoRules,
  [switch]$RulesLatest,
  [switch]$NoForhunt,
  [switch]$Check,
  [switch]$Force
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 redraws a progress bar for every chunk downloaded or
# extracted, which makes both many times slower.
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Repo = '0xRD/forensic-hunter'
# Oldest forhunt this skill's checklists and references work with (kept equal
# to MIN_FORHUNT in scripts/gen-checklist-index.py, checked in CI).
$FORHUNT_MIN = '0.6.0'
# Oldest forhunt with the built-in Sigma engine (`forhunt sigma`).
$FORHUNT_SIGMA_MIN = '0.8.0'
$RulesRepo = 'Yamato-Security/hayabusa-rules'
# Pinned rule set (same values as install.sh): commit, and SHA-256 of the
# `sha256sum` listing of every file ("<hash>  ./path", paths sorted
# bytewise), i.e. of the content, not of the archive bytes.
$RULES_COMMIT = 'fefb31c530e554116041ae106a5d40304fd9d251'
$RULES_DIGEST = 'ec441b7f5d631f05be2f3f50a88ca9f387b3d4b74d13843075403a4915945d91'

# SHA-256 of a tree's content, as `find . -type f -print0 | LC_ALL=C sort -z |
# xargs -0 sha256sum | sha256sum` computes it.
function Get-TreeDigest([string]$Root) {
  $root = (Resolve-Path $Root).Path.TrimEnd('\')
  $paths = [string[]](Get-ChildItem -Recurse -File -Force -LiteralPath $root | ForEach-Object {
    './' + $_.FullName.Substring($root.Length + 1).Replace('\', '/')
  })
  [Array]::Sort($paths, [StringComparer]::Ordinal)
  $sb = New-Object Text.StringBuilder
  foreach ($p in $paths) {
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root $p.Substring(2))).Hash.ToLowerInvariant()
    [void]$sb.Append("$h  $p`n")
  }
  $sha = [Security.Cryptography.SHA256]::Create()
  $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sb.ToString()))
  return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Verify-Sha256([string]$Path, [string]$Expected) {
  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
  if ($got -ne $Expected.ToLowerInvariant()) {
    throw "checksum mismatch for $(Split-Path -Leaf $Path): expected $Expected, got $got"
  }
  Write-Host "  sha256 ok  $(Split-Path -Leaf $Path)"
}

function Find-Sum([string[]]$Lines, [string]$Name) {
  foreach ($l in $Lines) {
    $p = $l.Trim() -split '\s+', 2
    if ($p.Count -eq 2 -and ($p[1] -eq $Name -or $p[1] -eq "*$Name")) { return $p[0] }
  }
  return $null
}

# "forhunt 0.6.1" -> "0.6.1"; $null when the binary is missing or does not run.
function Get-ForhuntVersion([string]$Exe) {
  if (-not $Exe -or -not (Test-Path $Exe)) { return $null }
  try {
    $line = (& $Exe --version 2>$null | Select-Object -First 1)
    if ($line -match '^forhunt\s+(\S+)') { return $Matches[1] }
  } catch { }
  return $null
}

# True when version $A is lower than $B (numeric x.y.z; a pre-release suffix is ignored).
function Test-Older([string]$A, [string]$B) {
  try { return ([version](($A -split '[-+]')[0])) -lt ([version](($B -split '[-+]')[0])) }
  catch { return $false }
}

$binDir = Join-Path $Prefix 'bin'
$fhExe = Join-Path $binDir 'forhunt.exe'

if ($Check) {
  $ok = $true
  $fh = $null
  if (Test-Path $fhExe) { $fh = $fhExe }
  else {
    $c = Get-Command forhunt -ErrorAction SilentlyContinue
    if ($c) { $fh = $c.Source }
  }
  $self = $MyInvocation.MyCommand.Path
  if (-not $fh) { Write-Host "forhunt: not installed (install: powershell -ExecutionPolicy Bypass -File `"$self`")"; $ok = $false }
  else {
    $v = Get-ForhuntVersion $fh
    if (-not $v) { Write-Host "forhunt: $fh does not run (reinstall with -Force)"; $ok = $false }
    elseif (Test-Older $v $FORHUNT_MIN) {
      Write-Host "forhunt: $v at $fh is too old, this skill needs $FORHUNT_MIN or later (update: powershell -ExecutionPolicy Bypass -File `"$self`")"
      $ok = $false
    }
    else { Write-Host "forhunt: $v at $fh" }
  }
  if ($fh -and $v -and (Test-Older $v $FORHUNT_SIGMA_MIN)) {
    Write-Host "forhunt sigma: needs forhunt $FORHUNT_SIGMA_MIN or later"; $ok = $false
  }
  $rinfo = Join-Path $Prefix 'rules\hayabusa-rules\.forhunt-rules'
  if (Test-Path $rinfo) {
    $commit = ((Get-Content $rinfo | Where-Object { $_ -like 'commit=*' }) -replace '^commit=', '')
    Write-Host "rules: $(Join-Path $Prefix 'rules\hayabusa-rules') ($($commit.Substring(0, [Math]::Min(12, $commit.Length))))"
  }
  # Optional (downloaded only on a yes): not a reason to say "not ready".
  else { Write-Host 'rules: not installed, optional (-NoForhunt asks before downloading them, ~10 MB)' }
  if ($ok) { Write-Host 'ready'; exit 0 }
  exit 1
}

$arch = $env:PROCESSOR_ARCHITECTURE
switch ($arch) {
  'AMD64' { $target = 'x86_64-pc-windows-msvc' }
  'ARM64' { $target = 'x86_64-pc-windows-msvc' } # x64 forhunt runs under emulation
  default { throw "unsupported architecture $arch" }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("fh-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp, (Join-Path $Prefix 'bin') | Out-Null
try {
  # --- forhunt ---
  if (-not $NoForhunt) {
  if ($ForhuntVersion -eq 'latest') {
    $req = [Net.WebRequest]::Create("https://github.com/$Repo/releases/latest")
    $req.AllowAutoRedirect = $true
    $resp = $req.GetResponse(); $ForhuntVersion = ($resp.ResponseUri.AbsoluteUri -split '/tag/')[1]; $resp.Close()
    if (-not $ForhuntVersion) { throw 'no published forhunt release found; pass -ForhuntVersion vX.Y.Z' }
  }
  $ver = $ForhuntVersion.TrimStart('v')
  if ($ver -notmatch '^[0-9A-Za-z.+-]+$') { throw "not a version: $ForhuntVersion" }
  $have = Get-ForhuntVersion $fhExe
  if ($have -eq $ver -and -not $Force) {
    Write-Host "forhunt v$ver is already installed in $binDir"
  }
  else {
  $zip = "forhunt-$ver-$target.zip"
  # FORHUNT_BASE_URL: optional mirror holding the release assets (offline labs).
  $base = if ($env:FORHUNT_BASE_URL) { $env:FORHUNT_BASE_URL } else { "https://github.com/$Repo/releases/download/v$ver" }
  if ($have) { Write-Host "forhunt v$have -> v$ver ($target)" } else { Write-Host "forhunt v$ver ($target)" }
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$zip" -OutFile (Join-Path $tmp $zip)
  $pinned = Join-Path $Here "checksums\forhunt-$ver.sha256"
  if (Test-Path $pinned) { $sums = Get-Content $pinned }
  else {
    # Windows PowerShell 5.1 returns octet-stream bodies as byte[].
    $c = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS").Content
    if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }
    $sums = $c -split "`n"
  }
  $expected = Find-Sum $sums $zip
  if (-not $expected) { throw "no checksum listed for $zip" }
  Verify-Sha256 (Join-Path $tmp $zip) $expected
  Expand-Archive -Force -Path (Join-Path $tmp $zip) -DestinationPath $tmp
  # Checked before it replaces the installed one: a failed update leaves the
  # previous forhunt working.
  $new = Join-Path $tmp "forhunt-$ver-$target\forhunt.exe"
  $got = Get-ForhuntVersion $new
  if ($got -ne $ver) { throw "the downloaded forhunt does not run or is not v$ver (it says: $got); nothing was changed" }
  # A running forhunt.exe cannot be overwritten on Windows, but it can be
  # renamed: move it aside, then put the new one in place.
  $old = "$fhExe.old"
  if (Test-Path $old) { Remove-Item -Force $old -ErrorAction SilentlyContinue }
  if (Test-Path $fhExe) { Move-Item -Force $fhExe $old }
  try { Copy-Item -Force $new $fhExe }
  catch {
    if (Test-Path $old) { Move-Item -Force $old $fhExe }
    throw
  }
  if (Test-Path $old) { Remove-Item -Force $old -ErrorAction SilentlyContinue }
  & $fhExe --version
  }
  if (Test-Older $ver $FORHUNT_MIN) {
    Write-Warning "this skill needs forhunt $FORHUNT_MIN or later; v$ver will miss some checks"
  }
  # Another forhunt earlier in PATH would still be the one that runs.
  $other = Get-Command forhunt -ErrorAction SilentlyContinue
  if ($other -and ($other.Source -ne $fhExe)) {
    $ov = Get-ForhuntVersion $other.Source
    if ($ov -ne $ver) { Write-Host "  note: PATH has another forhunt first: $($other.Source) (v$ov). Put $binDir first in PATH." }
  }
  }

  # --- Sigma rules ---
  $rulesDir = Join-Path $Prefix 'rules'
  $rdest = Join-Path $rulesDir 'hayabusa-rules'
  $rinfo = Join-Path $rdest '.forhunt-rules'
  $ref = if ($RulesLatest) { 'main' } else { $RULES_COMMIT }
  $current = (Test-Path $rinfo) -and ((Get-Content $rinfo) -contains "commit=$RULES_COMMIT") -and -not $RulesLatest -and -not $Force
  # Never downloaded without a yes: asked when interactive, else only -Rules.
  $want = $Rules -or ($current -and -not $NoRules)
  if (-not $Rules -and -not $NoRules -and -not $current) {
    if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
      $what = if (Test-Path $rinfo) { 'Update' } else { 'Download' }
      $answer = Read-Host "$what the Sigma detection rules (Yamato Security hayabusa-rules, ~10 MB, Detection Rule License 1.1)? [y/N]"
      $want = $answer -match '^(y|yes)$'
    }
    else { Write-Host 'Sigma rules: not downloaded (not interactive; run with -Rules to download them, ~10 MB)' }
  }
  if ($want) {
    if ($current) {
      Write-Host "Sigma rules (hayabusa-rules $($RULES_COMMIT.Substring(0, 12))) are already installed in $rdest"
    }
    else {
      Write-Host "Sigma rules: $RulesRepo @ $($ref.Substring(0, [Math]::Min(12, $ref.Length))) (Detection Rule License 1.1)"
      $tgz = Join-Path $tmp 'rules.tar.gz'
      Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$RulesRepo/archive/$ref.tar.gz" -OutFile $tgz
      $rstage = Join-Path $tmp 'rules'
      New-Item -ItemType Directory -Force -Path $rstage | Out-Null
      # tar.exe ships with Windows 10 1803 and later.
      & tar.exe -xzf $tgz -C $rstage
      if ($LASTEXITCODE -ne 0) { throw 'cannot extract the rules archive (tar.exe)' }
      $src = Get-ChildItem -Directory -Path $rstage | Select-Object -First 1
      if (-not $src -or -not (Test-Path (Join-Path $src.FullName 'config')) -or -not (Test-Path (Join-Path $src.FullName 'sigma'))) {
        throw 'the archive is not a hayabusa-rules tree; nothing was changed'
      }
      if (-not $RulesLatest) {
        $got = Get-TreeDigest $src.FullName
        if ($got -ne $RULES_DIGEST) { throw "rules content digest mismatch: expected $RULES_DIGEST, got $got; nothing was changed" }
        Write-Host "  sha256 ok  hayabusa-rules $($RULES_COMMIT.Substring(0, 12)) (content)"
      }
      else { Write-Host '  note: -RulesLatest is not pinned: only HTTPS vouches for it' }
      New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null
      # Copied next to the installed set (the temporary folder may be on
      # another drive), marked last, then swapped in: a failed copy leaves
      # the previous rules as they were.
      $rnew = "$rdest.new"; $rold = "$rdest.old"
      foreach ($d in $rnew, $rold) { if (Test-Path -LiteralPath $d) { Remove-Item -Recurse -Force -LiteralPath $d } }
      Copy-Item -Recurse -Force -LiteralPath $src.FullName -Destination $rnew
      Set-Content -Encoding ASCII -LiteralPath (Join-Path $rnew '.forhunt-rules') -Value @(
        "commit=$ref", "source=https://github.com/$RulesRepo",
        'license=Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License)',
        "installed=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
      if (Test-Path -LiteralPath $rdest) { Move-Item -LiteralPath $rdest -Destination $rold }
      try { Move-Item -LiteralPath $rnew -Destination $rdest }
      catch {
        if (Test-Path -LiteralPath $rold) { Move-Item -LiteralPath $rold -Destination $rdest }
        throw "cannot install the rules in ${rdest}; the previous rules were kept: $_"
      }
      if (Test-Path -LiteralPath $rold) { Remove-Item -Recurse -Force -LiteralPath $rold -ErrorAction SilentlyContinue }
      $n = (Get-ChildItem -Recurse -File -Filter '*.yml' -Path (Join-Path $rdest 'hayabusa'), (Join-Path $rdest 'sigma')).Count
      Write-Host "  installed in $rdest ($n rule files; run with: forhunt sigma <evidence>)"
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $rulesDir 'custom') | Out-Null
    Write-Host "  your own rules: $(Join-Path $rulesDir 'custom') (run with the others)"
  }

  Write-Host ""
  Write-Host "Done. Add $(Join-Path $Prefix 'bin') to PATH."
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
