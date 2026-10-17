<#
.SYNOPSIS
    Get-OpenApVerdict against netsh text. No network.

.DESCRIPTION
    The weekly gate failed on 2026-10-11 for an open ISP hotspot in a
    neighbouring house. These fixtures pin the rule that replaced "any open
    network fails": flag it when the gateway serves it or it is strong enough
    to be inside the house; name weak unrelated ones as neighbours without the
    word the pipeline gates on ('broadcasting').

    ALL FIXTURES ARE CONSTRUCTED. The repository is public and a real BSSID can
    be geolocated, so no captured air scan is committed. Names and MACs below
    are invented; the layout follows `netsh wlan show networks mode=bssid` on
    Windows 11 as observed on the scan host.

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-OpenApVerdict.ps1
    Also runs under Windows PowerShell 5.1, which is what the Scheduled Task uses.
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../scripts/NetAssess.Verdicts.ps1"

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    if (& $Test) { Write-Host ("  [ok]   {0,-50} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-50} got '{1}'" -f $Name, $Shown); $script:fail++ }
}

function Net([string]$Ssid, [string]$Auth, [string[]]$Bssids) {
    # One SSID block. Each BSSID is 'mac@signalPercent' - a flat string,
    # because @(@(mac, n)) with one element unrolls to @(mac, n).
    $s = "SSID 1 : $Ssid`r`n    Network type            : Infrastructure`r`n"
    $s += "    Authentication          : $Auth`r`n"
    $s += "    Encryption              : $(if ($Auth -eq 'Open') { 'None' } else { 'CCMP ' })`r`n"
    $n = 1
    foreach ($b in $Bssids) {
        $s += "    BSSID $n                 : $(($b -split '@')[0])`r`n         Signal             : $(($b -split '@')[1])%  `r`n         Radio type         : 802.11ac`r`n"
        $n++
    }
    return $s
}
$header = "`r`nInterface name : Wi-Fi 2 `r`nThere are N networks currently visible. `r`n`r`n"

# The household gateway, as Get-NetNeighbor prints it.
$gw = '02-1A-2B-3C-4D-10'

$ours      = Net -Ssid 'HomeNet'        -Auth 'WPA2-Personal' -Bssids @('02:1a:2b:3c:4d:13@100', '02:1a:2b:3c:4d:14@100')
$oursGuest = Net -Ssid 'HomeNet-Guest'  -Auth 'Open'          -Bssids @('8a:1a:2b:3c:4d:15@41')
$neighbour = Net -Ssid 'ISPHotspot'     -Auth 'Open'          -Bssids @('06:77:88:99:aa:bc@30')
$nbrSecure = Net -Ssid 'NeighbourHome'  -Auth 'WPA2-Personal' -Bssids @('06:77:88:99:aa:ba@27')
$gadget    = Net -Ssid 'SmartPlug-9F01' -Auth 'Open'          -Bssids @('0a:55:66:77:88:01@84')
$hidden    = Net -Ssid ''               -Auth 'Open'          -Bssids @('0e:12:34:56:78:9a@72')
$nearNbr   = Net -Ssid 'CafeFree'       -Auth 'Open'          -Bssids @('06:77:88:99:aa:01@63')

Write-Host ""
Write-Host "open networks that are not ours"

$v = Get-OpenApVerdict -NetshText ($header + $ours + $neighbour + $nbrSecure) -GatewayMac $gw
Check -Name "weak unrelated open AP does not fail the gate" -Test { $v -notmatch 'broadcasting' } -Shown $v
Check -Name "...and is still named, as a neighbour"         -Test { $v -match 'neighbouring, not ours: ISPHotspot 30%' } -Shown $v

$v = Get-OpenApVerdict -NetshText ($header + $ours + $nearNbr) -GatewayMac $gw
Check -Name "unrelated open AP above threshold still fails" -Test { $v -match 'CafeFree \(63% signal\) OPEN - broadcasting' } -Shown $v

Write-Host ""
Write-Host "open networks that are ours"

# August's real Critical: a device in setup mode, its own MAC, strong signal.
$v = Get-OpenApVerdict -NetshText ($header + $ours + $gadget + $neighbour) -GatewayMac $gw
Check -Name "in-home gadget (own MAC, 84%) fails the gate"   -Test { $v -match 'SmartPlug-9F01 \(84% signal\)' -and $v -match 'broadcasting' } -Shown $v
Check -Name "...and the neighbour is listed separately"      -Test { $v -match '; neighbouring, not ours: ISPHotspot 30%' } -Shown $v

# Locally-administered first octet, last octet +5: the gateway's own guest SSID.
$v = Get-OpenApVerdict -NetshText ($header + $ours + $oursGuest) -GatewayMac $gw
Check -Name "gateway-served open guest SSID fails (41%)"     -Test { $v -match 'HomeNet-Guest \(served by the gateway\) OPEN - broadcasting' } -Shown $v

$v = Get-OpenApVerdict -NetshText ($header + $hidden) -GatewayMac $gw
Check -Name "strong hidden open SSID is named, and fails"    -Test { $v -match '<hidden SSID> \(72% signal\)' -and $v -match 'broadcasting' } -Shown $v

Write-Host ""
Write-Host "states that must not read as an all-clear"

$v = Get-OpenApVerdict -NetshText ($header + $neighbour) -GatewayMac ''
Check -Name "gateway MAC unknown: every open AP fails"       -Test { $v -match 'ISPHotspot \(gateway MAC unknown\) OPEN - broadcasting' } -Shown $v

$v = Get-OpenApVerdict -NetshText "The Wireless AutoConfig Service (wlansvc) is not running." -GatewayMac $gw
Check -Name "no wireless service is unknown, not a pass"     -Test { $v -like 'unknown*' } -Shown $v

$v = Get-OpenApVerdict -NetshText ($header + $ours + $nbrSecure) -GatewayMac $gw
Check -Name "nothing open is a pass"                         -Test { $v -eq 'no open AP' } -Shown $v

Write-Host ""
Write-Host "BSSID-to-gateway matching"

$cases = @(
    @('02:1a:2b:3c:4d:10', $true,  'identical'),
    @('8a:1a:2b:3c:4d:20', $true,  'first octet ignored, last +16'),
    @('02:1a:2b:3c:4d:21', $false, 'last +17 is too far'),
    @('02:1a:2b:3c:4e:10', $false, 'a middle octet differs'),
    @('02:1a:2b:3c',       $false, 'malformed')
)
foreach ($c in $cases) {
    $got = Test-GatewayServedBssid -Bssid $c[0] -GatewayMac $gw
    Check -Name ("{0} ({1})" -f $c[0], $c[2]) -Test { $got -eq $c[1] } -Shown "$got"
}

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
