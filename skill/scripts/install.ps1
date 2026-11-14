<#
.SYNOPSIS
  Installs forhunt and Hayabusa for the Forensic Hunter skill (Windows).
.DESCRIPTION
  Downloads release archives from GitHub over HTTPS and verifies SHA-256:
  forhunt against the SHA256SUMS of its release (or a pinned
  checksums\forhunt-<version>.sha256 next to this script), Hayabusa against
  hayabusa.sha256 pinned in this skill. Installs into $Prefix
  (default %LOCALAPPDATA%\forensic-hunter) and creates bin\forhunt.exe and
  bin\hayabusa.cmd. Nothing is embedded in the skill. -NoForhunt or
  -NoHayabusa install only the other tool; $env:FORHUNT_BASE_URL points to a
  mirror of the forhunt release assets.

  -Check installs nothing: it says which forhunt and Hayabusa would be used
  and whether forhunt is recent enough for this skill (exit code 0 when both
  are ready, 1 otherwise). Run the script again at any time to update: what
  is already at the wanted version is left alone (-Force installs it again),
  and older Hayabusa versions in the prefix are removed.

  Hayabusa is GPL-3.0 software by Yamato Security, downloaded unmodified from
  https://github.com/Yamato-Security/hayabusa (source code available there).
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install.ps1
#>
[CmdletBinding()]
param(
  [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'forensic-hunter'),
  [string]$ForhuntVersion = 'latest',
  [string]$HayabusaVersion = '4.2.0',
  [switch]$NoHayabusa,
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
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Verify-Sha256([string]$Path, [string]$Expected) {
  $got = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
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
$hbCmd = Join-Path $binDir 'hayabusa.cmd'

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
  $hb = $null
  if (Test-Path $hbCmd) { $hb = $hbCmd }
  else {
    $c = Get-Command hayabusa -ErrorAction SilentlyContinue
    if ($c) { $hb = $c.Source }
  }
  if ($hb) { Write-Host "hayabusa: $hb" }
  else { Write-Host 'hayabusa: not installed (optional; install with -NoForhunt)'; $ok = $false }
  if ($ok) { Write-Host 'ready'; exit 0 }
  exit 1
}

$arch = $env:PROCESSOR_ARCHITECTURE
switch ($arch) {
  'AMD64' { $target = 'x86_64-pc-windows-msvc'; $hbPlat = 'win-x64' }
  'ARM64' { $target = 'x86_64-pc-windows-msvc'; $hbPlat = 'win-aarch64' } # x64 forhunt runs under emulation
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

  # --- Hayabusa ---
  if (-not $NoHayabusa) {
    if ($HayabusaVersion -notmatch '^[0-9A-Za-z.+-]+$') { throw "not a version: $HayabusaVersion" }
    $hbZip = "hayabusa-$HayabusaVersion-$hbPlat.zip"
    $dest = Join-Path $Prefix "hayabusa-$HayabusaVersion"
    $exe = "hayabusa-$HayabusaVersion-$hbPlat.exe"
    $wrapped = (Test-Path $hbCmd) -and (Get-Content -Raw $hbCmd).Contains($dest)
    if ((Test-Path (Join-Path $dest $exe)) -and $wrapped -and -not $Force) {
      Write-Host "Hayabusa $HayabusaVersion is already installed in $dest"
    }
    else {
      $expected = Find-Sum (Get-Content (Join-Path $Here 'hayabusa.sha256') | Where-Object { $_ -notmatch '^#' }) $hbZip
      if (-not $expected) { throw "Hayabusa $HayabusaVersion ($hbPlat) is not pinned in hayabusa.sha256; refusing an unverified download" }
      Write-Host "Hayabusa $HayabusaVersion ($hbPlat)"
      Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/Yamato-Security/hayabusa/releases/download/v$HayabusaVersion/$hbZip" -OutFile (Join-Path $tmp $hbZip)
      Verify-Sha256 (Join-Path $tmp $hbZip) $expected
      $stage = Join-Path $tmp 'hayabusa'
      Expand-Archive -Force -Path (Join-Path $tmp $hbZip) -DestinationPath $stage
      if (-not (Test-Path (Join-Path $stage $exe))) { throw "the Hayabusa archive does not hold $exe; nothing was changed" }
      if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
      # Copy, not move: the temporary folder may be on another drive.
      Copy-Item -Recurse -Force $stage $dest
      Set-Content -Encoding ASCII -Path $hbCmd -Value "@echo off`r`npushd `"$dest`"`r`n`"$dest\$exe`" %*`r`nset FH_RC=%ERRORLEVEL%`r`npopd`r`nexit /b %FH_RC%"
      Write-Host "  installed in $dest (rules included; refresh with: hayabusa update-rules)"
    }
    # Versions installed earlier by this script: the wrapper no longer uses them.
    Get-ChildItem -Directory -Path $Prefix -Filter 'hayabusa-*' | Where-Object { $_.FullName -ne $dest -and $_.Name -match '^hayabusa-[0-9]' } | ForEach-Object {
      Remove-Item -Recurse -Force $_.FullName
      Write-Host "  removed $($_.Name)"
    }
    Write-Host "  note: the wrapper runs from the Hayabusa directory; pass absolute paths to -d/-f/-o."
  }
  Write-Host ""
  Write-Host "Done. Add $(Join-Path $Prefix 'bin') to PATH."
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
