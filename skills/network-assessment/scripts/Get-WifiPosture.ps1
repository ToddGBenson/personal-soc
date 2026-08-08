<#
.SYNOPSIS
  Phase 4 — Wi-Fi posture audit. Passive, from the local wireless adapter.
  Saved-profile auth/cipher, over-the-air auth/cipher, and BSSID->gateway
  correlation to detect WPA3-transition mode and in-home Open SSIDs.
.NOTES
  Only reads local profiles you own and passively observes broadcasts.
  Never connects to or captures from networks you don't own.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$OutDir,
  [string]$GatewayMac = ""                       # e.g. 70:F2:20:67:07:F0 to correlate the AP
)
$ErrorActionPreference = "Continue"
function Log($msg){ Add-Content "$OutDir\scan-log.md" ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $msg) }
New-Item -ItemType Directory -Force -Path "$OutDir\raw" | Out-Null
Log "netsh wlan show profiles/networks/interfaces   [Wi-Fi passive audit]"

Write-Host "== Phase 4: Wi-Fi posture ==" -ForegroundColor Cyan

# --- saved profiles: negotiated auth/cipher ---
$profiles = (netsh wlan show profiles) | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
Write-Host "`n-- Saved profiles (what THIS client negotiated) --"
$saved = foreach($n in $profiles){
  $o = netsh wlan show profile name="$n" key=clear | Out-String
  [PSCustomObject]@{
    SSID   = $n
    Auth   = if($o -match "Authentication\s*:\s*(.+)"){$matches[1].Trim()}else{"?"}
    Cipher = if($o -match "Cipher\s*:\s*(.+)"){$matches[1].Trim()}else{"?"}
    KeyLen = if($o -match "Key Content\s*:\s*(.+)"){$matches[1].Trim().Length}else{0}
  }
}
$saved | Format-Table -AutoSize
$saved | Export-Csv "$OutDir\raw\wifi-saved.csv" -NoTypeInformation

# --- over-the-air: advertised auth/cipher + BSSIDs ---
$o = netsh wlan show networks mode=bssid | Out-String
$o | Set-Content "$OutDir\raw\wifi-airscan.txt"
Write-Host "`n-- Over-the-air (what the AP ADVERTISES) --"
$airRows = @()
foreach($b in ($o -split "(?=SSID \d+ :)")){
  if($b -notmatch "SSID (\d+) : (.*)"){ continue }
  $ssid = $matches[2].Trim(); if($ssid -eq ""){ $ssid = "<hidden>" }
  $auth = if($b -match "Authentication\s*:\s*(.+)"){$matches[1].Trim()}else{"?"}
  $enc  = if($b -match "Encryption\s*:\s*(.+)"){$matches[1].Trim()}else{"?"}
  $bssids = [regex]::Matches($b,"BSSID \d+\s*:\s*(\S+)") | ForEach-Object { $_.Groups[1].Value }
  $airRows += [PSCustomObject]@{ SSID=$ssid; Auth=$auth; Enc=$enc; APs=$bssids.Count; BSSIDs=($bssids -join ',') }
}
$airRows | Format-Table SSID,Auth,Enc,APs -AutoSize

# --- analysis ---
Write-Host "`n-- Findings --" -ForegroundColor Yellow
foreach($a in $airRows){
  if($a.Auth -match "Open"){ Write-Host ("  OPEN SSID broadcasting: {0}  -> Critical/High (CIS 04)" -f $a.SSID) -ForegroundColor Red }
  $s = $saved | Where-Object { $_.SSID -eq $a.SSID }
  if($s -and $s.Auth -match "WPA3" -and $a.Auth -match "WPA2"){
    Write-Host ("  WPA3-transition on {0}: client=WPA3 / air=WPA2 -> downgrade risk (CIS 04)" -f $a.SSID) -ForegroundColor Yellow
  }
  if($GatewayMac){
    $gp = ($GatewayMac -replace '[:-]','').Substring(0,8)
    if($a.BSSIDs -replace '[:-]','' -match $gp){ Write-Host ("  {0} is served BY the gateway (BSSID ~ {1})" -f $a.SSID,$GatewayMac) -ForegroundColor DarkYellow }
  }
}
Write-Host "`nRaw Wi-Fi data in $OutDir\raw\." -ForegroundColor Green
