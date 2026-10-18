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

# --- force ARP resolution for every address in scope ---
# Non-elevated nmap on Windows cannot send ARP or ICMP, so `-sn` falls back to
# TCP probes and the ARP table it leaves behind holds only the hosts that
# answered one - 3 of 14 on 2026-10-11, which is why weekly host counts fell
# from 54 to 15 with nothing on the network changing. An OS-level ping needs no
# elevation and makes Windows ARP for the address first; a device that drops
# ICMP still answers ARP and lands in the neighbour table. SendPingAsync rather
# than ForEach-Object -Parallel: the Scheduled Task runs Windows PowerShell 5.1.
function ConvertTo-IpNumber([string]$a) {
  $o = $a.Split('.') | ForEach-Object { [uint64]$_ }
  return $o[0] * 16777216 + $o[1] * 65536 + $o[2] * 256 + $o[3]
}
$net, $bits = $Cidr.Split('/')
$bits = [int]$bits
$size = [uint64][Math]::Pow(2, 32 - $bits)
$base = (ConvertTo-IpNumber $net) - ((ConvertTo-IpNumber $net) % $size)
if ($bits -lt 22) {
  Log "ARP sweep skipped: /$bits is wider than /22   [discovery relies on nmap + existing ARP only]"
} else {
  $targets = for ($i = 1; $i -lt $size - 1; $i++) {
    $v = $base + $i
    '{0}.{1}.{2}.{3}' -f ([Math]::Floor($v / 16777216) % 256), ([Math]::Floor($v / 65536) % 256), ([Math]::Floor($v / 256) % 256), ($v % 256)
  }
  Log "ICMP echo x2 (OS ping, forces ARP) $Cidr, 64 at a time   [ARP-forcing discovery]"
  foreach ($round in 1..2) {
    for ($i = 0; $i -lt $targets.Count; $i += 64) {
      $batch = $targets[$i..([Math]::Min($i + 63, $targets.Count - 1))]
      $pingers = @(); $tasks = @()
      foreach ($t in $batch) {
        $p = New-Object System.Net.NetworkInformation.Ping
        $pingers += $p; $tasks += $p.SendPingAsync($t, 1000)
      }
      # The sweep only exists to populate the ARP table; a ping that faults
      # (no route, host gone) is the same as one that timed out, and the
      # neighbour table read below is the result either way.
      try { [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$tasks) }
      catch { Write-Verbose "ping batch at offset ${i}: $($_.Exception.Message)" }
      $pingers | ForEach-Object { $_.Dispose() }
    }
  }
}

# --- ARP / neighbor table, LAN interface only ---
# Entries confirmed by this run only: Reachable/Delay/Probe. Stale and
# Permanent are left out - Stale is a host that did not answer the sweep just
# now, and Permanent is the subnet broadcast (FF-FF-FF-FF-FF-FF), which was
# being counted as a host.
$ifIndex = (Get-NetIPAddress -IPAddress $LocalIp -ErrorAction SilentlyContinue).InterfaceIndex
$nbr = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.State -in 'Reachable','Delay','Probe' -and
                 (ConvertTo-IpNumber $_.IPAddress) -ge $base -and (ConvertTo-IpNumber $_.IPAddress) -lt ($base + $size) -and
                 (-not $ifIndex -or $_.InterfaceIndex -eq $ifIndex) -and
                 $_.LinkLayerAddress -notmatch '^(FF-FF-FF-FF-FF-FF|00-00-00-00-00-00|01-00-5E)' }

# --- passive SSDP (bound to LAN interface, not a virtual NIC) ---
$ssdpHosts = @{}
try {
  $udp = New-Object System.Net.Sockets.UdpClient((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIp),0)))
  $udp.Client.ReceiveTimeout = 3000
  $m = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: upnp:rootdevice`r`n`r`n"
  $b = [Text.Encoding]::ASCII.GetBytes($m)
  $udp.Send($b,$b.Length,(New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("239.255.255.250"),1900))) | Out-Null
  for($i=0;$i -lt 25;$i++){ try { $r=New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0); $null=$udp.Receive([ref]$r); $ssdpHosts[$r.Address.ToString()]=$true } catch { break } }
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
  # A MAC whose first octet will not parse is reported without the flag rather than failing the inventory.
  try { if([Convert]::ToInt32($mac.Substring(0,2) -replace '[:-]','',16) -band 2){ $rand=" [RANDOMIZED]" } }
  catch { Write-Verbose "could not read the locally-administered bit of '$mac': $($_.Exception.Message)" }
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
