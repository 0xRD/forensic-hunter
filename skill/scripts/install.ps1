<#
.SYNOPSIS
  Installs forhunt and Hayabusa for the Forensic Hunter skill (Windows).
.DESCRIPTION
  Downloads release archives from GitHub over HTTPS and verifies SHA-256:
  forhunt against the SHA256SUMS of its release (or a pinned
  checksums\forhunt-<version>.sha256 next to this script), Hayabusa against
  hayabusa.sha256 pinned in this skill. Installs into $Prefix
  (default %LOCALAPPDATA%\forensic-hunter) and creates bin\forhunt.exe and
  bin\hayabusa.cmd. Nothing is embedded in the skill.

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
  [switch]$NoHayabusa
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Repo = '0xRD/forensic-hunter'
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
  if ($ForhuntVersion -eq 'latest') {
    $req = [Net.WebRequest]::Create("https://github.com/$Repo/releases/latest")
    $req.AllowAutoRedirect = $true
    $resp = $req.GetResponse(); $ForhuntVersion = ($resp.ResponseUri.AbsoluteUri -split '/tag/')[1]; $resp.Close()
    if (-not $ForhuntVersion) { throw 'cannot resolve the latest forhunt release' }
  }
  $ver = $ForhuntVersion.TrimStart('v')
  $zip = "forhunt-$ver-$target.zip"
  $base = "https://github.com/$Repo/releases/download/v$ver"
  Write-Host "forhunt v$ver ($target)"
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$zip" -OutFile (Join-Path $tmp $zip)
  $pinned = Join-Path $Here "checksums\forhunt-$ver.sha256"
  if (Test-Path $pinned) { $sums = Get-Content $pinned }
  else { $sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS").Content -split "`n" }
  $expected = Find-Sum $sums $zip
  if (-not $expected) { throw "no checksum listed for $zip" }
  Verify-Sha256 (Join-Path $tmp $zip) $expected
  Expand-Archive -Force -Path (Join-Path $tmp $zip) -DestinationPath $tmp
  Copy-Item -Force (Join-Path $tmp "forhunt-$ver-$target\forhunt.exe") (Join-Path $Prefix 'bin\forhunt.exe')
  & (Join-Path $Prefix 'bin\forhunt.exe') --version

  # --- Hayabusa ---
  if (-not $NoHayabusa) {
    $hbZip = "hayabusa-$HayabusaVersion-$hbPlat.zip"
    $expected = Find-Sum (Get-Content (Join-Path $Here 'hayabusa.sha256') | Where-Object { $_ -notmatch '^#' }) $hbZip
    if (-not $expected) { throw "Hayabusa $HayabusaVersion ($hbPlat) is not pinned in hayabusa.sha256; refusing an unverified download" }
    Write-Host "Hayabusa $HayabusaVersion ($hbPlat)"
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/Yamato-Security/hayabusa/releases/download/v$HayabusaVersion/$hbZip" -OutFile (Join-Path $tmp $hbZip)
    Verify-Sha256 (Join-Path $tmp $hbZip) $expected
    $dest = Join-Path $Prefix "hayabusa-$HayabusaVersion"
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Expand-Archive -Force -Path (Join-Path $tmp $hbZip) -DestinationPath $dest
    $exe = "hayabusa-$HayabusaVersion-$hbPlat.exe"
    Set-Content -Encoding ASCII -Path (Join-Path $Prefix 'bin\hayabusa.cmd') -Value "@echo off`r`npushd `"$dest`"`r`n`"$dest\$exe`" %*`r`npopd"
    Write-Host "  installed in $dest (rules included; refresh with: hayabusa update-rules)"
    Write-Host "  note: the wrapper runs from the Hayabusa directory; pass absolute paths to -d/-f/-o."
  }
  Write-Host ""
  Write-Host "Done. Add $(Join-Path $Prefix 'bin') to PATH."
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
