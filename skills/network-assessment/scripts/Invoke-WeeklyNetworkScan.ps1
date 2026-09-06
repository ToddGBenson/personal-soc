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
# WAS: `if($nfs -match '/mnt/')`. Two faults. `/mnt/` is a Synology-shaped
# export path and this NAS is a Western Digital, so a real export under any
# other prefix could never match. And the fallback then reported a LISTENING
# service as "closed (no exports)" purely because port 111 answered -- a
# reachable NFS daemon described as closed.
#
# Now an export is any path nfs-showmount actually lists, and the two facts
# are reported separately because they have different remedies: "the service
# is reachable" is hardening, "shares are exported" is exposure.
$nfsExports = [regex]::Matches($nfs, '(?m)^\|[_ ]*\s*(/\S+)') | ForEach-Object { $_.Groups[1].Value }
$nfsPortOpen = $nfs -match '111/(tcp|udp)\s+open'
$nfsOpen =
  if($nfsExports.Count){ 'EXPORTS PRESENT (' + ($nfsExports -join ', ') + ')' }
  elseif($nfs -match 'No NFS mounts available'){ 'service reachable, no exports' }
  elseif($nfsPortOpen){ 'unknown (service reachable, exports not enumerable)' }
  else{ 'unknown (scan failed)' }
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
# Now: pair each `SSID n :` with the `Authentication :` that follows it and
# report ANY network whose authentication is literally Open, by name.
$wifiRaw = netsh wlan show networks mode=bssid 2>&1
$wifiTxt = $wifiRaw | Out-String
if($wifiTxt -match 'not running|is not enabled|no wireless interface|There is no wireless'){
  # A missing adapter or a stopped WLAN service must NOT read as an all-clear.
  # 'unknown' is deliberate: the pipeline treats it as "did not run", not a pass.
  $openAP = 'unknown (no usable wireless interface)'
} else {
  $ssid = $null; $openList = @()
  foreach($line in $wifiRaw){
    if($line -match '^\s*SSID\s+\d+\s*:\s*(.*)$'){ $ssid = $Matches[1].Trim() }
    elseif($line -match '^\s*Authentication\s*:\s*(.*)$'){
      if($Matches[1].Trim() -eq 'Open'){ $openList += $(if($ssid){$ssid}else{'<hidden SSID>'}) }
      $ssid = $null
    }
  }
  $openAP = if($openList.Count){ ($openList -join ', ') + ' OPEN — broadcasting' } else { 'no open AP' }
}

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
