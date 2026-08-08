<#
.SYNOPSIS
  Phase 2 — service & version fingerprinting. Non-elevated TCP-connect only.
  Deep full-port on infrastructure hosts; gentle top-ports on the rest.
.NOTES
  Read-only. No OS fingerprint (needs raw sockets/admin). No intrusive scripts.
  Reads $OutDir\inventory.csv from Invoke-NetDiscovery.ps1.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$OutDir,
  [string[]]$InfraHosts = @(),                  # router, NAS, unknowns -> full port scan
  [string]$NmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"
)
$ErrorActionPreference = "Stop"
function Log($msg){ Add-Content "$OutDir\scan-log.md" ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $msg) }
$inv = Import-Csv "$OutDir\inventory.csv"
$all = $inv.IP
$rest = $all | Where-Object { $InfraHosts -notcontains $_ }

if($InfraHosts.Count){
  Write-Host "== Phase 2a: full-port on infra: $($InfraHosts -join ', ') ==" -ForegroundColor Cyan
  Log "nmap -sT -sV -Pn -p- --version-intensity 4 $($InfraHosts -join ' ')   [infra full-port]"
  & $NmapPath -sT -sV -Pn --version-intensity 4 -p- --min-rate 1500 --host-timeout 12m @InfraHosts |
    Tee-Object "$OutDir\raw\services-infra.txt"
}

Write-Host "== Phase 2b: top-300 on $($rest.Count) hosts ==" -ForegroundColor Cyan
# batch to keep runs bounded / gentle on IoT
$i = 0
foreach($batch in ($rest | ForEach-Object { $_ } | Group-Object { [math]::Floor(($i++)/12) })){
  $hosts = $batch.Group
  Log "nmap -sT -sV -Pn --top-ports 300 $($hosts -join ' ')   [service scan]"
  & $NmapPath -sT -sV -Pn --version-intensity 2 --top-ports 300 --min-rate 1200 --host-timeout 4m @hosts |
    Tee-Object "$OutDir\raw\services-batch$($batch.Name).txt" -Append
}
Write-Host "`nRaw service output in $OutDir\raw\. Identify devices via references/device-fingerprints.md." -ForegroundColor Green
Write-Host "Next: Invoke-ShareEnum.ps1 for the NAS / file-sharing hosts." -ForegroundColor DarkGray
