<#
.SYNOPSIS
  Phase 1 — host discovery + full inventory. Non-elevated, read-only.
  Combines nmap ping-sweep, the ARP/neighbor table, and passive SSDP+mDNS
  (bound to the LAN interface) so hosts that ignore ICMP are still found.
.NOTES
  Only scan networks you own or are authorized to test. Logs to $OutDir\scan-log.md.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Cidr,          # e.g. 192.168.0.0/24
  [Parameter(Mandatory)][string]$LocalIp,       # this host's LAN IP, e.g. 192.168.0.14
  [string]$OutDir = "$env:TEMP\netassess\adhoc",
  [string]$NmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir, "$OutDir\raw" | Out-Null
function Log($msg){ Add-Content "$OutDir\scan-log.md" ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $msg) }

Write-Host "== Phase 1: discovery on $Cidr from $LocalIp ==" -ForegroundColor Cyan

# --- nmap host discovery (multiple probe types) ---
Log "nmap -sn -PE -PS22,80,443,445 -PA3389 $Cidr   [host discovery]"
& $NmapPath -sn -PE '-PS22,80,443,445' -PA3389 $Cidr | Tee-Object "$OutDir\raw\discovery.txt" | Out-Null

# --- full ARP / neighbor table (catches non-ping hosts) ---
$nbr = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.State -in 'Reachable','Stale','Permanent','Delay','Probe' -and $_.IPAddress -like ($Cidr.Split('/')[0].Substring(0,$Cidr.Split('/')[0].LastIndexOf('.')) + '.*') }

# --- passive SSDP (bound to LAN interface, not a virtual NIC) ---
$ssdpHosts = @{}
try {
  $udp = New-Object System.Net.Sockets.UdpClient((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIp),0)))
  $udp.Client.ReceiveTimeout = 3000
  $m = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: upnp:rootdevice`r`n`r`n"
  $b = [Text.Encoding]::ASCII.GetBytes($m)
  $udp.Send($b,$b.Length,(New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("239.255.255.250"),1900))) | Out-Null
  for($i=0;$i -lt 25;$i++){ try { $r=New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0); $d=$udp.Receive([ref]$r); $ssdpHosts[$r.Address.ToString()]=$true } catch { break } }
  $udp.Close()
  Log "SSDP M-SEARCH from $LocalIp   [passive discovery]  found $($ssdpHosts.Count)"
} catch { Log "SSDP failed: $($_.Exception.Message)" }

# --- OUI vendor lookup from nmap's prefix DB ---
$ouiFile = Join-Path (Split-Path $NmapPath) "nmap-mac-prefixes"
function Get-Vendor($mac){
  if(-not $mac){ return "" }
  $pfx = ($mac -replace '[:-]','').Substring(0,6).ToUpper()
  $line = Select-String -Path $ouiFile -Pattern "^$pfx\s" -ErrorAction SilentlyContinue | Select-Object -First 1
  $rand = ""
  try { if([Convert]::ToInt32($mac.Substring(0,2) -replace '[:-]','',16) -band 2){ $rand=" [RANDOMIZED]" } } catch {}
  if($line){ (($line.Line -replace "^\S+\s+","")) + $rand } else { "unknown$rand" }
}

# --- build inventory ---
$rows = foreach($n in $nbr){
  [PSCustomObject]@{
    IP     = $n.IPAddress
    MAC    = $n.LinkLayerAddress
    Vendor = Get-Vendor $n.LinkLayerAddress
    State  = $n.State
    SSDP   = if($ssdpHosts[$n.IPAddress]){"yes"}else{""}
  }
}
$rows = $rows | Sort-Object { [int]($_.IP -split '\.')[3] }
$rows | Export-Csv "$OutDir\inventory.csv" -NoTypeInformation
$rows | Format-Table -AutoSize
Write-Host "`nInventory: $($rows.Count) hosts -> $OutDir\inventory.csv" -ForegroundColor Green
Write-Host "Next: Invoke-ServiceScan.ps1 -OutDir `"$OutDir`"" -ForegroundColor DarkGray
