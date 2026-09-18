<#
.SYNOPSIS
    Get-NfsExportVerdict against recorded nmap output. No network.

.DESCRIPTION
    #8 was validated by scanning the live LAN. #9 could not be, and said so:
    answering "is the NAS exporting NFS?" by scanning the NAS ad hoc from an
    agent session is the wrong way to ask about somebody's own storage. So the
    classifier is tested against text instead.

    Two of the fixtures below are REAL nmap 7.98 output, captured on
    2026-09-18 against 127.0.0.1 (loopback, nothing left the host) and
    192.0.2.1 (RFC 5737 documentation range, unroutable). Those two are the
    states the old code got wrong, so they are the two that had to be real.

    The rest are CONSTRUCTED from nmap's documented NSE output format and are
    labelled as such. A constructed fixture proves the classifier does what it
    says about that text; it does not prove nmap emits that text. Where the
    distinction matters -- the 'no NFS registered' pass -- the classifier
    refuses to conclude anything unless rpcinfo actually produced a listing.

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-NfsVerdict.ps1
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../scripts/NetAssess.Verdicts.ps1"

$pass = 0; $fail = 0
function Check([string]$Name, [string]$Expected, [string]$Text) {
    $got = Get-NfsExportVerdict -NmapText $Text
    if ($got -like $Expected) {
        Write-Host ("  [ok]   {0,-44} {1}" -f $Name, $got)
        $script:pass++
    } else {
        Write-Host ("  [FAIL] {0,-44} expected '{1}', got '{2}'" -f $Name, $Expected, $got)
        $script:fail++
    }
}

# ---- REAL captures, nmap 7.98, 2026-09-18 ---------------------------------

# nmap -sT -Pn -p111 --script nfs-showmount,rpcinfo 127.0.0.1
$realClosed = @'
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-18 01:55 -0700
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00s latency).

PORT    STATE  SERVICE
111/tcp closed rpcbind

Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds
'@

# nmap -sT -Pn -p111 --host-timeout 25s --script nfs-showmount,rpcinfo 192.0.2.1
$realFiltered = @'
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-18 01:55 -0700
Nmap scan report for 192.0.2.1
Host is up.

PORT    STATE    SERVICE
111/tcp filtered rpcbind

Nmap done: 1 IP address (1 host up) scanned in 2.63 seconds
'@

Write-Host ""
Write-Host "the two states the old code called 'unknown (scan failed)'"
# THE REGRESSION. A NAS with rpcbind closed is hardened, and the old code
# reported it as a failed scan, so the gate could never open.
Check "port 111 closed is an ANSWER"        'no NFS service (port 111 closed)'   $realClosed
# And this one must stay unknown: filtered means nothing was learned.
Check "port 111 filtered stays unknown"     'unknown (port 111 filtered*'        $realFiltered

# ---- CONSTRUCTED from nmap's NSE output format ----------------------------

$exportsPresent = @'
PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount:
|_  /volume1/backup 192.168.0.0/24
Nmap done: 1 IP address (1 host up) scanned in 1.10 seconds
'@

$noMounts = @'
PORT    STATE SERVICE
111/tcp open  rpcbind
|_nfs-showmount: No NFS mounts available
Nmap done: 1 IP address (1 host up) scanned in 1.10 seconds
'@

$rpcbindNoNfs = @'
PORT    STATE SERVICE
111/tcp open  rpcbind
| rpcinfo:
|   program version    port/proto  service
|_  100000  2,3,4      111/tcp     rpcbind
Nmap done: 1 IP address (1 host up) scanned in 1.10 seconds
'@

$nfsRegisteredNoList = @'
PORT    STATE SERVICE
111/tcp open  rpcbind
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4      111/tcp     rpcbind
|   100005  1,2,3      892/tcp     mountd
|_  100003  3,4        2049/tcp    nfs
Nmap done: 1 IP address (1 host up) scanned in 1.10 seconds
'@

$openNoScriptOutput = @'
PORT    STATE SERVICE
111/tcp open  rpcbind
Nmap done: 1 IP address (1 host up) scanned in 1.10 seconds
'@

Write-Host ""
Write-Host "constructed from nmap's documented NSE output"
Check "an export under ANY prefix is found"  'EXPORTS PRESENT (/volume1/backup)'     $exportsPresent
Check "no mounts available"                  'service reachable, no exports'         $noMounts
Check "rpcbind up, nothing NFS registered"   'rpcbind reachable, no NFS service*'    $rpcbindNoNfs
Check "NFS registered but no list -> unknown" 'unknown (NFS registered*'             $nfsRegisteredNoList
Check "open, rpcinfo silent -> unknown"      'unknown (service reachable, rpcinfo*'  $openNoScriptOutput

Write-Host ""
Write-Host "nothing may read as a pass by accident"
Check "empty output"                         'unknown (nmap did not complete)'       ''
Check "nmap missing / killed mid-scan"       'unknown (nmap did not complete)'       "PORT    STATE SERVICE`n111/tcp closed rpcbind"
Check "completed, no line for 111"           'unknown (nmap completed but reported*' "Nmap done: 1 IP address (1 host up) scanned in 0.2 seconds"

Write-Host ""
if ($fail -eq 0) {
    Write-Host "  $pass passed, 0 failed"
    exit 0
} else {
    Write-Host "  $pass passed, $fail FAILED"
    exit 1
}
