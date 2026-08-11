<#
.SYNOPSIS
  External (WAN) exposure view — what the internet sees of your public IP, without
  scanning it yourself (NAT makes a self-scan see the LAN, not the WAN edge).
.DESCRIPTION
  Resolves your public IP, then queries Shodan's free InternetDB (no API key) for the
  open ports, CPEs, CVEs, hostnames, and tags Shodan last observed on that IP. Read-only.
.NOTES
  InternetDB reflects Shodan's LAST scan of the IP — it can be stale, and a 404 (IP not in
  Shodan) is a GOOD sign (nothing externally indexed). Residential IPs also rotate via DHCP.
.EXAMPLE
  .\Get-ExternalExposure.ps1 -OutDir .\netassess\2026-08-10
#>
[CmdletBinding()]
param([string]$OutDir = ".")
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
function Log($m){ Add-Content "$OutDir\scan-log.md" ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $m) }

Write-Host "== External exposure (WAN view via Shodan InternetDB) ==" -ForegroundColor Cyan
$pub = $null
foreach($svc in "https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"){
  try { $pub = (Invoke-RestMethod $svc -TimeoutSec 10).ToString().Trim(); if($pub){ break } } catch {}
}
if(-not $pub){ Write-Host "Could not determine public IP." -ForegroundColor Red; return }
Write-Host "Public IP: $pub" -ForegroundColor White
Log "external exposure check for public IP $pub (Shodan InternetDB)"

try {
  $db = Invoke-RestMethod "https://internetdb.shodan.io/$pub" -TimeoutSec 15
  $out = [PSCustomObject]@{
    ip=$pub; ports=$db.ports; cves=$db.vulns; cpes=$db.cpes; hostnames=$db.hostnames; tags=$db.tags
  }
  $out | ConvertTo-Json -Depth 5 | Set-Content "$OutDir\external-exposure.json"
  Write-Host "`n-- What the internet sees on $pub --" -ForegroundColor Yellow
  Write-Host ("  Open ports : {0}" -f (($db.ports | Sort-Object) -join ', ' | ForEach-Object { if($_){$_}else{'none'} }))
  Write-Host ("  CVEs       : {0}" -f (($db.vulns) -join ', ' | ForEach-Object { if($_){$_}else{'none'} }))
  Write-Host ("  Hostnames  : {0}" -f (($db.hostnames) -join ', ' | ForEach-Object { if($_){$_}else{'none'} }))
  Write-Host ("  Tags       : {0}" -f (($db.tags) -join ', ' | ForEach-Object { if($_){$_}else{'none'} }))
  if($db.ports){ Write-Host "`n  ⚠️ Ports are visible from the internet — confirm each is intentional (port-forward/UPnP). Close what you don't need." -ForegroundColor DarkYellow }
  else { Write-Host "`n  ✅ Shodan shows no open ports on your edge." -ForegroundColor Green }
} catch {
  if($_.Exception.Response.StatusCode.value__ -eq 404){
    Write-Host "`n  ✅ Not in Shodan InternetDB (HTTP 404) — nothing externally indexed on $pub. Good sign." -ForegroundColor Green
  } else { Write-Host "  Query failed: $($_.Exception.Message)" -ForegroundColor Red }
}
Write-Host "`n  NOTE: reflects Shodan's last scan; not a live probe. For a live external port test, use an authorized outside vantage." -ForegroundColor DarkGray
