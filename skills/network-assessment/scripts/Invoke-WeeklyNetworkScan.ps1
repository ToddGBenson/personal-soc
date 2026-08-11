<#
.SYNOPSIS
  Unattended weekly network scan for the local Scheduled Task. Collects inventory,
  mechanically checks the NAS + Wi-Fi, diffs hosts vs the previous run, and writes a
  network-status.md fragment for the weekly digest. Read-only. No Claude required.
#>
[CmdletBinding()]
param(
  [string]$Cidr,
  [string]$Root = (Join-Path $env:USERPROFILE 'netassess'),
  [string]$NmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"
)
$ErrorActionPreference = 'Continue'
$today = Get-Date -Format 'yyyy-MM-dd'
$out = Join-Path $Root $today
New-Item -ItemType Directory -Force -Path $out, "$out\raw" | Out-Null

# auto-detect LAN
$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
$ip  = $cfg.IPv4Address.IPAddress
if(-not $Cidr){ $Cidr = ($ip -replace '\.\d+$','.0') + '/24' }
$nasGuess = ($ip -replace '\.\d+$','.5')   # NAS default; adjust if moved

# discovery via the skill's inventory builder
& (Join-Path $PSScriptRoot 'Invoke-NetDiscovery.ps1') -Cidr $Cidr -LocalIp $ip -OutDir $out -NmapPath $NmapPath *> "$out\raw\discovery-run.txt"
$curCount = (Import-Csv "$out\inventory.csv").Count

# find previous engagement folder (most recent dated dir before today)
$prev = Get-ChildItem $Root -Directory | Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}' -and $_.Name -lt $today } |
        Sort-Object Name | Select-Object -Last 1
$hostDelta = "n/a (no prior run)"
if($prev -and (Test-Path "$($prev.FullName)\inventory.csv")){
  $bMac = (Import-Csv "$($prev.FullName)\inventory.csv").MAC.ForEach({$_.ToUpper()})
  $cMac = (Import-Csv "$out\inventory.csv").MAC.ForEach({$_.ToUpper()})
  $added = @($cMac | Where-Object { $bMac -notcontains $_ }).Count
  $removed = @($bMac | Where-Object { $cMac -notcontains $_ }).Count
  $hostDelta = "+$added / -$removed vs $($prev.Name)"
}

# mechanical NAS checks
$nfs = (& $NmapPath -sT -Pn -p111 --script nfs-showmount,rpcinfo $nasGuess 2>&1 | Out-String)
# /mnt export line = exposed; port 111 responded with no export = closed; nothing = scan failed
$nfsOpen = if($nfs -match '/mnt/'){'EXPORTS PRESENT'} elseif($nfs -match 'No NFS mounts available' -or $nfs -match '111/tcp\s+open'){'closed (no exports)'} else{'unknown (scan failed)'}
$smb = (& $NmapPath -sT -Pn '-p139,445' --script smb-protocols $nasGuess 2>$null | Out-String)
$smbv1 = if($smb -match 'NT LM 0\.12'){'SMBv1 ENABLED'} elseif($smb -match '2\.0\.2|3\.1\.1'){'SMB2/3 only'} else{'unknown'}
$anon = (net view "\\$nasGuess" 2>&1 | Select-String 'Disk').Count

# mechanical Wi-Fi checks
$wifi = netsh wlan show networks mode=bssid | Out-String
$openAP = if($wifi -match 'SmartLife-6A82'){'SmartLife-6A82 OPEN — broadcasting'} else {'no known open AP'}

# external (WAN) exposure — what the internet sees (needs the home public IP, so it runs locally)
& (Join-Path $PSScriptRoot 'Get-ExternalExposure.ps1') -OutDir $out *> "$out\raw\external-run.txt"
$extPorts = 'n/a'
if(Test-Path "$out\external-exposure.json"){
  try { $ext = Get-Content "$out\external-exposure.json" -Raw | ConvertFrom-Json
        $extPorts = if($ext.ports){ ($ext.ports -join ', ') } else { 'none visible' } } catch {}
}

@"
## Network status — $today (local scheduled scan)

- **Hosts:** $curCount live ($hostDelta)
- **NAS NFS exports:** $nfsOpen
- **NAS SMB:** $smbv1
- **NAS anonymous shares listed:** $anon
- **Open Wi-Fi AP:** $openAP
- **WAN (external) ports visible:** $extPorts

_Raw data + inventory.csv in $out. Full CIS findings + digest: run the network-assessment skill or fold into the weekly digest._
"@ | Set-Content "$out\network-status.md"

Write-Host "Wrote $out\network-status.md"
Get-Content "$out\network-status.md"
