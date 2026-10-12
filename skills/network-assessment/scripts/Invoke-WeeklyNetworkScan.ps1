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
. "$PSScriptRoot/NetAssess.Verdicts.ps1"
$nfs = (& $NmapPath -sT -Pn -p111 --script nfs-showmount,rpcinfo $nasGuess 2>&1 | Out-String)
# The ladder that reads this lives in NetAssess.Verdicts.ps1 with fixtures in
# tests/Test-NfsVerdict.ps1. It is out of here because the only way anybody has
# ever checked it is by scanning the live LAN -- #8 was validated that way, and
# #9 could not be, for a good reason.
#
# #9: two states that ARE definite answers were reported as unknown, so the
# gate stayed shut on questions that had been answered. Port 111 CLOSED was
# lumped in with "no output at all" as 'unknown (scan failed)', so a correctly
# hardened NAS could never pass. And rpcinfo already enumerates the registered
# programs -- if neither mountd nor nfs is among them, nothing serves exports.
#
# What stays unknown stays unknown: filtered, and "NFS registered but showmount
# returned no list", which is the case #9 says is worth knowing about quickly.
$nfsOpen = Get-NfsExportVerdict -NmapText $nfs

$smb = (& $NmapPath -sT -Pn '-p139,445' --script smb-protocols $nasGuess 2>$null | Out-String)
$smbv1 = if($smb -match 'NT LM 0\.12'){'SMBv1 ENABLED'} elseif($smb -match '2\.0\.2|3\.1\.1'){'SMB2/3 only'} else{'unknown'}
$anon = (net view "\\$nasGuess" 2>&1 | Select-String 'Disk').Count

# mechanical Wi-Fi checks
# WAS: `if($wifi -match 'SmartLife-6A82')`. It matched ONE SSID by NAME and
# never read the Authentication field, so it had two blind spots that both
# fail toward "all clear": it would still call that network OPEN after it was
# secured, and it reported "no known open AP" for every rogue or misconfigured
# AP it had not been told about. A control that can only find the problem it
# already knows is not a control.
#
# Then: ANY network whose authentication was Open failed the gate - including
# a neighbour's ISP hotspot through the wall, which nobody here can fix.
#
# Now: Get-OpenApVerdict (NetAssess.Verdicts.ps1, fixtures in
# tests/Test-OpenApVerdict.ps1) flags an open network when the gateway serves
# it OR it is strong enough to be inside the house, and names weak unrelated
# ones as neighbours without failing on them.
$gwIp  = $cfg.IPv4DefaultGateway.NextHop
$gwMac = (Get-NetNeighbor -IPAddress $gwIp -InterfaceIndex $cfg.InterfaceIndex -ErrorAction SilentlyContinue |
          Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |
          Select-Object -First 1).LinkLayerAddress
$wifiTxt = netsh wlan show networks mode=bssid 2>&1 | Out-String
$wifiTxt | Set-Content "$out\raw\wifi-airscan.txt"
$openAP = Get-OpenApVerdict -NetshText $wifiTxt -GatewayMac $gwMac

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
