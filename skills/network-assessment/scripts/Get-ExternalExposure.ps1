<#
.SYNOPSIS
  External (WAN) exposure view - what the internet sees of your public IP, without
  scanning it yourself (NAT makes a self-scan see the LAN, not the WAN edge).
.DESCRIPTION
  Resolves your public IP, then queries Shodan's free InternetDB (no API key) for the
  open ports, CPEs, CVEs, hostnames, and tags Shodan last observed on that IP. Read-only.

  Every visible port is checked against config/exposure-allowlist.yml (TheHub #60852).
  Exit codes, which the Concourse external-exposure job passes straight through:
    0  no public ports visible (or InternetDB 404), or every visible port is allowlisted
    1  at least one visible port is NOT on the allowlist - the alert
    2  the check could not run: no public IP, InternetDB query failed, or the allowlist
       is missing/unreadable. Unknown is not a pass.
.NOTES
  ASCII only: Windows PowerShell 5.1 (the Scheduled Task) reads a BOM-less file as ANSI,
  and the UTF-8 em dash it used to contain decodes to a closing curly quote that ends the
  string - the whole script failed to parse there.
  InternetDB reflects Shodan's LAST scan of the IP - it can be stale, and a 404 (IP not in
  Shodan) is a GOOD sign (nothing externally indexed). Residential IPs also rotate via DHCP.
.EXAMPLE
  .\Get-ExternalExposure.ps1 -OutDir .\netassess\2026-08-10
.EXAMPLE
  .\Get-ExternalExposure.ps1 -OutDir .\out -Allowlist .\my-allowlist.yml
#>
[CmdletBinding()]
param(
  [string]$OutDir = ".",
  [string]$Allowlist = (Join-Path $PSScriptRoot '../config/exposure-allowlist.yml')
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
function Log($m){ Add-Content (Join-Path $OutDir 'scan-log.md') ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $m) }
. (Join-Path $PSScriptRoot 'NetAssess.Verdicts.ps1')

Write-Host "== External exposure (WAN view via Shodan InternetDB) ==" -ForegroundColor Cyan

# The allowlist is read before any network call: a check that cannot judge what it
# finds should say so up front rather than after it has found something.
try { $allowed = Read-ExposureAllowlist -Path $Allowlist }
catch {
  Write-Host "UNKNOWN: exposure allowlist unreadable - $($_.Exception.Message). The WAN view cannot be judged; this is not a pass." -ForegroundColor Red
  exit 2
}
Write-Host ("Allowlist  : {0} ({1})" -f $(if($allowed.Count){ $allowed -join ', ' } else { 'empty - every visible port fails' }), $Allowlist)

$pub = $null
foreach($svc in "https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"){
  # One echo service failing is expected and the next is tried; all of them
  # failing is reported by the 'Could not determine public IP' line below.
  try { $pub = (Invoke-RestMethod -Uri $svc -TimeoutSec 10).ToString().Trim(); if($pub){ break } }
  catch { Write-Verbose "public-IP lookup via $svc failed: $($_.Exception.Message)" }
}
# The pipeline greps for this exact sentence; keep it.
if(-not $pub){ Write-Host "Could not determine public IP." -ForegroundColor Red; exit 2 }
Write-Host "Public IP: $pub" -ForegroundColor White
Log "external exposure check for public IP $pub (Shodan InternetDB)"

$db = $null
try {
  $db = Invoke-RestMethod "https://internetdb.shodan.io/$pub" -TimeoutSec 15
} catch {
  if($_.Exception.Response.StatusCode.value__ -eq 404){
    Write-Host "`n  OK: Not in Shodan InternetDB (HTTP 404) - nothing externally indexed on $pub. Good sign." -ForegroundColor Green
    Write-Host "`n  NOTE: reflects Shodan's last scan; not a live probe. For a live external port test, use an authorized outside vantage." -ForegroundColor DarkGray
    exit 0
  }
  # WAS: printed "Query failed" and fell through to exit 0 - a lookup that never
  # happened read as a clean edge.
  Write-Host "UNKNOWN: InternetDB query failed - $($_.Exception.Message). The WAN view was not taken; this is not a pass." -ForegroundColor Red
  exit 2
}

$verdict = Get-ExposureVerdict -Ports $db.ports -Allowed $allowed
$out = [PSCustomObject]@{
  ip=$pub; ports=$db.ports; cves=$db.vulns; cpes=$db.cpes; hostnames=$db.hostnames; tags=$db.tags
  unexpected_ports=$verdict.Unexpected; allowlisted_ports=$verdict.Allowlisted
}
$out | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutDir 'external-exposure.json')
Write-Host "`n-- What the internet sees on $pub --" -ForegroundColor Yellow
Write-Host ("  Open ports : {0}" -f (($db.ports | Sort-Object) -join ', ' | ForEach-Object { if($_){$_}else{'none'} }))
Write-Host ("  CVEs       : {0}" -f (($db.vulns) -join ', ' | ForEach-Object { if($_){$_}else{'none'} }))
Write-Host ("  Hostnames  : {0}" -f (($db.hostnames) -join ', ' | ForEach-Object { if($_){$_}else{'none'} }))
Write-Host ("  Tags       : {0}" -f (($db.tags) -join ', ' | ForEach-Object { if($_){$_}else{'none'} }))
Write-Host "`n  NOTE: reflects Shodan's last scan; not a live probe. For a live external port test, use an authorized outside vantage." -ForegroundColor DarkGray

if(-not $verdict.Pass){
  Write-Host ("`n  FAIL: port(s) {0} visible from the internet and not in {1}." -f ($verdict.Unexpected -join ', '), $Allowlist) -ForegroundColor Red
  Write-Host "  Close each one (port-forward / UPnP), or add it to the allowlist with a reason if it is intentional." -ForegroundColor Red
  exit 1
}
if($verdict.Allowlisted.Count){ Write-Host "`n  OK: Every visible port is allowlisted: $($verdict.Allowlisted -join ', ')." -ForegroundColor Green }
else { Write-Host "`n  OK: Shodan shows no open ports on your edge." -ForegroundColor Green }
exit 0
