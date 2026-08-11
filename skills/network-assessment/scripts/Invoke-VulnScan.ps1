<#
.SYNOPSIS
  Vulnerability scan — matches detected service versions to known CVEs via nmap's
  vulners script. Turns "port open" into "port open AND running software with known CVEs."
.DESCRIPTION
  Runs nmap -sV --script vulners (queries vulners.com; needs internet) against targets,
  filters by minimum CVSS, and summarizes CVEs per host/service. Non-elevated, read-only —
  it does NOT exploit anything; it reports what version detection + the CVE DB imply.
.NOTES
  Accuracy caveat: this is BANNER-BASED. A matched CVE means "the reported version is
  associated with this CVE," not "this host is confirmed exploitable." Back-port patches,
  wrong version banners, and non-applicable configs cause false positives. Verify before acting.
.EXAMPLE
  .\Invoke-VulnScan.ps1 -Targets 192.168.0.1,192.168.0.5 -MinCvss 6.0 -OutDir .\netassess\2026-08-10
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$Targets,
  [double]$MinCvss = 5.0,
  [string]$OutDir = ".",
  [string]$NmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir, "$OutDir\raw" | Out-Null
function Log($m){ Add-Content "$OutDir\scan-log.md" ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $m) }

Write-Host "== Vulnerability scan (CVE match, mincvss=$MinCvss) on: $($Targets -join ', ') ==" -ForegroundColor Cyan
Log "nmap -sV --script vulners mincvss=$MinCvss $($Targets -join ' ')   [CVE match — banner-based, read-only]"

$raw = "$OutDir\raw\vulnscan.txt"
& $NmapPath -sT -sV -Pn --script vulners --script-args "mincvss=$MinCvss" @Targets | Tee-Object $raw | Out-Null

# parse: group CVE lines under their host
$lines = Get-Content $raw
$curHost = $null; $rows = @()
foreach($l in $lines){
  if($l -match 'Nmap scan report for (\S+)'){ $curHost = $matches[1] }
  # vulners lines look like:  \tCVE-2021-1234\t7.5\thttps://vulners.com/...
  if($l -match '(CVE-\d{4}-\d+)\s+(\d+\.\d+)'){
    $rows += [PSCustomObject]@{ Host=$curHost; CVE=$matches[1]; CVSS=[double]$matches[2] }
  }
}

Write-Host "`n-- CVE summary (CVSS >= $MinCvss) --" -ForegroundColor Yellow
if(-not $rows){
  Write-Host "  No CVEs matched at this threshold (either patched, no version data, or vulners unreachable)." -ForegroundColor Green
} else {
  $rows | Group-Object Host | ForEach-Object {
    $crit = ($_.Group | Where-Object CVSS -ge 9.0).Count
    $high = ($_.Group | Where-Object { $_.CVSS -ge 7.0 -and $_.CVSS -lt 9.0 }).Count
    "  {0,-15} {1,3} CVEs   (crit>=9: {2}, high 7-9: {3}, top: {4})" -f `
      $_.Name, $_.Count, $crit, $high, (($_.Group | Sort-Object CVSS -Desc | Select-Object -First 1).CVE)
  }
  $rows | Sort-Object CVSS -Descending | Export-Csv "$OutDir\vulns.csv" -NoTypeInformation
  Write-Host "`n  Full list -> $OutDir\vulns.csv ; raw -> $raw" -ForegroundColor DarkGray
}
Write-Host "`n  NOTE: banner-based matches — confirm applicability (back-ports, config) before acting." -ForegroundColor DarkYellow
