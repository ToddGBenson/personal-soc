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
Check -Name "port 111 closed is an ANSWER"        -Expected 'no NFS service (port 111 closed)'   -Text $realClosed
# And this one must stay unknown: filtered means nothing was learned.
Check -Name "port 111 filtered stays unknown"     -Expected 'unknown (port 111 filtered*'        -Text $realFiltered

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
Check -Name "an export under ANY prefix is found"  -Expected 'EXPORTS PRESENT (/volume1/backup)'     -Text $exportsPresent
Check -Name "no mounts available"                  -Expected 'service reachable, no exports'         -Text $noMounts
Check -Name "rpcbind up, nothing NFS registered"   -Expected 'rpcbind reachable, no NFS service*'    -Text $rpcbindNoNfs
Check -Name "NFS registered but no list -> unknown" -Expected 'unknown (NFS registered*'             -Text $nfsRegisteredNoList
Check -Name "open, rpcinfo silent -> unknown"      -Expected 'unknown (service reachable, rpcinfo*'  -Text $openNoScriptOutput

Write-Host ""
Write-Host "nothing may read as a pass by accident"
Check -Name "empty output"                         -Expected 'unknown (nmap did not complete)'       -Text ''
Check -Name "nmap missing / killed mid-scan"       -Expected 'unknown (nmap did not complete)'       -Text "PORT    STATE SERVICE`n111/tcp closed rpcbind"
Check -Name "completed, no line for 111"           -Expected 'unknown (nmap completed but reported*' -Text "Nmap done: 1 IP address (1 host up) scanned in 0.2 seconds"

# ---- REAL captures, nmap 7.98, 2026-10-17, the NAS itself ----------------
#
# nmap -sT -Pn -p111 --script nfs-showmount,rpcinfo 192.168.0.5, run three
# times in a row against the operator's own WD NAS (read-only; the same
# command the weekly scan runs). All three answered. nmap does not order NSE
# output, so the second came back with nfs-showmount AFTER rpcinfo; both
# orders are kept because the classifier must not depend on it.

$realNasShowmountFirst = @'
Starting Nmap 7.98 ( https://nmap.org ) at 2026-10-17 07:26 -0700
Nmap scan report for 192.168.0.5
Host is up (0.00s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
|_nfs-showmount: No NFS mounts available
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/tcp   nfs
|   100003  3           2049/udp   nfs
|   100005  1,2,3      41669/tcp   mountd
|   100005  1,2,3      43639/udp   mountd
|   100021  1,3,4      35501/udp   nlockmgr
|   100021  1,3,4      46415/tcp   nlockmgr
|   100024  1          41661/tcp   status
|   100024  1          59033/udp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl

Nmap done: 1 IP address (1 host up) scanned in 1.52 seconds
'@

$realNasShowmountLast = @'
Starting Nmap 7.98 ( https://nmap.org ) at 2026-10-17 07:26 -0700
Nmap scan report for 192.168.0.5
Host is up (0.00s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/tcp   nfs
|   100003  3           2049/udp   nfs
|   100005  1,2,3      41669/tcp   mountd
|   100005  1,2,3      43639/udp   mountd
|   100021  1,3,4      35501/udp   nlockmgr
|   100021  1,3,4      46415/tcp   nlockmgr
|   100024  1          41661/tcp   status
|   100024  1          59033/udp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
|_nfs-showmount: No NFS mounts available

Nmap done: 1 IP address (1 host up) scanned in 0.66 seconds
'@

Write-Host ""
Write-Host "the NAS as it answers today (real, 2026-10-17)"
Check "NFS running, export list empty"       'service reachable, no exports'         $realNasShowmountFirst
Check "same, NSE output in the other order"  'service reachable, no exports'         $realNasShowmountLast

# ---- Get-NfsExportVerdictWithRetry ----------------------------------------
#
# #9: 09-07 and 09-14 were unknown while every run either side got the answer
# above. Retry must (a) recover a definite answer after a non-answer, (b)
# never turn all-unknown into a pass, (c) not probe again once answered.

function CheckRetry([string]$Name, [string]$Expected, [int]$ExpectedAttempts, [string[]]$Replies) {
    $script:replyQueue = [System.Collections.Queue]::new([object[]]$Replies)
    $r = Get-NfsExportVerdictWithRetry -Attempts 3 -Probe { $script:replyQueue.Dequeue() }
    if ($r.Verdict -like $Expected -and $r.Attempts -eq $ExpectedAttempts -and $r.Texts.Count -eq $ExpectedAttempts) {
        Write-Host ("  [ok]   {0,-44} {1}" -f $Name, $r.Verdict)
        $script:pass++
    } else {
        Write-Host ("  [FAIL] {0,-44} expected '{1}' in {2}, got '{3}' in {4}" -f $Name, $Expected, $ExpectedAttempts, $r.Verdict, $r.Attempts)
        $script:fail++
    }
}

Write-Host ""
Write-Host "retry: a non-answer is asked again, never promoted"
CheckRetry "answered first time, probed once"     'service reachable, no exports'                1 @($realNasShowmountFirst)
CheckRetry "unknown, then answered"               'service reachable, no exports (answered on attempt 2 of 3)' 2 @($nfsRegisteredNoList, $realNasShowmountLast)
CheckRetry "unknown x3 stays unknown"             'unknown (NFS registered*(all 3 attempts)'     3 @($nfsRegisteredNoList, $nfsRegisteredNoList, $nfsRegisteredNoList)
CheckRetry "killed, then exports found"           'EXPORTS PRESENT (/volume1/backup) (answered on attempt 2 of 3)' 2 @('', $exportsPresent)

Write-Host ""
if ($fail -eq 0) {
    Write-Host "  $pass passed, 0 failed"
    exit 0
} else {
    Write-Host "  $pass passed, $fail FAILED"
    exit 1
}
