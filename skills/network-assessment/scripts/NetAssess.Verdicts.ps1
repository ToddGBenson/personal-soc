<#
.SYNOPSIS
    Classifiers for the weekly network scan, separated so they can be tested
    without a network.

.DESCRIPTION
    These were inline in Invoke-WeeklyNetworkScan.ps1. They are here because
    the only way anybody has ever checked them is by scanning the live LAN --
    #8 was validated that way, and #9 could not be, because answering "is the
    NAS exporting NFS?" by scanning the NAS ad hoc from an agent session is
    the wrong way to answer a question about somebody's own storage.

    A classifier that takes text and returns a verdict can be tested against
    recorded output instead. tests/Test-NfsVerdict.ps1 does that.

.NOTES
    ASCII only.
#>

function Get-NfsExportVerdict {
    <#
    .SYNOPSIS
        What the NFS scan actually established, from nmap's output text.

    .DESCRIPTION
        Everything that is not a definite answer returns a string beginning
        'unknown', and the pipeline treats 'unknown' as "did not run, so not a
        pass". That is the right default and it is preserved: the unrecognised
        case below is unknown, not a pass.

        The defect this fixes is the opposite one. Two states that ARE definite
        answers were being reported as unknown, so the gate stayed shut on a
        question that had in fact been answered:

          1. Port 111 CLOSED. nmap ran, connected, and was refused. There is no
             rpcbind, so there is no NFS export service. The old code called
             this 'unknown (scan failed)' -- it had lumped closed in with "no
             output at all" -- so a correctly-hardened NAS could never pass.

          2. Port 111 open, rpcinfo enumerated the registered programs, and
             neither mountd nor nfs is among them. rpcbind is listening for
             something else. Nothing serves exports, which is a definite pass.

        Genuinely-unknown states stay unknown, and they are the ones worth
        seeing named separately rather than as one word:

          - FILTERED. Something dropped the packet. Nothing was learned.
          - Open, NFS registered, and showmount returned no list. This is the
            case #9 says is worth knowing about quickly -- it is either good
            posture (enumeration restricted to known clients) or exports that
            something incidental is hiding, and the two are not separable from
            here.
          - nmap did not run at all.

    .PARAMETER NmapText
        Combined stdout/stderr of
        `nmap -sT -Pn -p111 --script nfs-showmount,rpcinfo <target>`.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$NmapText)

    $text = if ($null -eq $NmapText) { '' } else { $NmapText }

    # An export is any path nfs-showmount actually lists, under any prefix.
    # (#8: the previous version matched '/mnt/', a Synology shape, against a
    # Western Digital NAS.)
    $exports = [regex]::Matches($text, '(?m)^\|[_ ]*\s*(/\S+)') |
        ForEach-Object { $_.Groups[1].Value }

    if ($exports.Count) {
        return 'EXPORTS PRESENT (' + ($exports -join ', ') + ')'
    }
    if ($text -match 'No NFS mounts available') {
        return 'service reachable, no exports'
    }

    # `Nmap done:` is nmap's own statement that it completed. Without it the
    # binary was missing, killed, or died -- and no port state below can be
    # trusted, including a missing one.
    if ($text -notmatch '(?m)^Nmap done:') {
        return 'unknown (nmap did not complete)'
    }

    if ($text -match '(?m)^111/(tcp|udp)\s+closed') {
        return 'no NFS service (port 111 closed)'
    }
    if ($text -match '(?m)^111/(tcp|udp)\s+filtered') {
        return 'unknown (port 111 filtered - nothing was learned)'
    }

    if ($text -match '(?m)^111/(tcp|udp)\s+open') {
        # rpcinfo's NSE output is a table of the programs registered with
        # rpcbind. Its presence is required before drawing a NEGATIVE
        # conclusion from it: "rpcinfo listed no mountd" only means anything
        # if rpcinfo produced a listing at all.
        $rpcinfoRan = $text -match '(?m)^\|[_ ]?\s*rpcinfo:'
        $nfsRegistered = $text -match '(?im)^\|.*\b(mountd|nfs(_acl)?)\b'

        if ($rpcinfoRan -and -not $nfsRegistered) {
            return 'rpcbind reachable, no NFS service registered'
        }
        if ($nfsRegistered) {
            return 'unknown (NFS registered, exports not enumerable)'
        }
        return 'unknown (service reachable, rpcinfo produced no listing)'
    }

    # nmap completed and said nothing about port 111. Not a pass.
    return 'unknown (nmap completed but reported no state for port 111)'
}

function Get-NfsExportVerdictWithRetry {
    <#
    .SYNOPSIS
        Run the NFS probe up to -Attempts times and keep the first definite
        answer, with every raw output kept as evidence.

    .DESCRIPTION
        #9: the scheduled scans of 2026-09-07 and 2026-09-14 reported
        'unknown (service reachable, exports not enumerable)', which shut the
        weekly gate for two weeks. The runs either side of them (09-05, and
        every run from 09-21 on) got a definite 'No NFS mounts available' from
        the same NAS with the same command, and three probes on 2026-10-17
        answered identically. The non-answer was not the NAS's state; it was
        one probe that did not get a reply. A single attempt let it stand for
        a week, and because the nmap text was never written to disk nobody
        could see why.

        So: ask again, and stop at the first verdict that does not begin
        'unknown'. This cannot turn a non-answer into a pass -- only a probe
        that actually returned a definite answer ends the loop, and if every
        attempt is unknown the result is still unknown. Every attempt's raw
        text is returned so the caller can keep it.

    .PARAMETER Probe
        Scriptblock returning the nmap text for one attempt.
    .PARAMETER Attempts
        Maximum number of probes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Probe,
        [ValidateRange(1, 10)][int]$Attempts = 3
    )

    $texts = @()
    $verdict = 'unknown (no probe ran)'
    for ($i = 1; $i -le $Attempts; $i++) {
        $text = (& $Probe | Out-String)
        $texts += $text
        $verdict = Get-NfsExportVerdict -NmapText $text
        if ($verdict -notlike 'unknown*') { break }
    }
    $n = $texts.Count
    if ($n -gt 1) {
        if ($verdict -like 'unknown*') {
            $verdict += " (all $n attempts)"
        } else {
            $verdict += " (answered on attempt $n of $Attempts)"
        }
    }
    [pscustomobject]@{ Verdict = $verdict; Attempts = $n; Texts = $texts }
}

function Test-GatewayServedBssid {
    <#
    .SYNOPSIS
        True when a BSSID is one the home gateway's own radio derives from its
        LAN MAC.

    .DESCRIPTION
        Consumer gateways number their BSSIDs off the LAN MAC: octets 2-5 are
        kept, the last octet moves a few steps, and the first octet often gets
        the locally-administered bit set for the extra SSIDs (a guest network
        on 70:..:f0's gateway shows up as 8a:..:f5 or 92:..:f0). So the first
        octet is ignored, octets 2-5 must match exactly, and the last may
        differ by up to 16.
    #>
    [CmdletBinding()]
    param([string]$Bssid, [string]$GatewayMac)

    $b = @($Bssid -split '[:-]' | Where-Object { $_ })
    $g = @($GatewayMac -split '[:-]' | Where-Object { $_ })
    if ($b.Count -ne 6 -or $g.Count -ne 6) { return $false }
    for ($i = 1; $i -le 4; $i++) {
        if ($b[$i].ToLower() -ne $g[$i].ToLower()) { return $false }
    }
    $delta = [Convert]::ToInt32($b[5], 16) - [Convert]::ToInt32($g[5], 16)
    return ([Math]::Abs($delta) -le 16)
}

function Get-OpenApVerdict {
    <#
    .SYNOPSIS
        Which open Wi-Fi networks are this household's problem, from
        `netsh wlan show networks mode=bssid` text.

    .DESCRIPTION
        The previous check reported ANY open network in the air. That made the
        weekly gate fail on a neighbour's ISP hotspot (an open "CoxWiFi" from
        the next house, 30% signal) - a result nobody here can act on, and a
        red gate that is red for good is one people learn to ignore.

        The obvious fix - only count networks the home gateway serves - is
        wrong the other way. August's real Critical was a smart plug stuck in
        setup mode broadcasting its own open SSID from its own MAC; the
        gateway had nothing to do with it. So an open network is treated as
        in-home when EITHER:

          - one of its BSSIDs is derived from the gateway's MAC, or
          - its strongest BSSID is at or above -InHomeSignal percent, which is
            what a device inside the house looks like.

        Only weak open networks unrelated to the gateway are set aside as
        neighbours, and they are still named, without the word the pipeline
        gates on. If the gateway MAC is unknown, everything open is in-home:
        not being able to tell must fail toward the alert.

        A neighbour's open AP close enough to cross the threshold will still
        be flagged. That is the safe direction to be wrong in.

    .PARAMETER NetshText
        Output of `netsh wlan show networks mode=bssid`.
    .PARAMETER GatewayMac
        The default gateway's MAC from the neighbour table. Empty if unknown.
    .PARAMETER InHomeSignal
        Signal percent at or above which an open AP counts as in-home.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$NetshText,
        [string]$GatewayMac = '',
        [int]$InHomeSignal = 60
    )

    $text = if ($null -eq $NetshText) { '' } else { $NetshText }
    if ($text -match 'not running|is not enabled|no wireless interface|There is no wireless') {
        # A missing adapter or a stopped WLAN service must NOT read as an
        # all-clear. The pipeline treats 'unknown' as "did not run".
        return 'unknown (no usable wireless interface)'
    }

    $nets = @()
    $cur = $null
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*SSID\s+\d+\s*:\s*(.*)$') {
            $name = $Matches[1].Trim()
            $cur = [pscustomobject]@{
                Name = $(if ($name) { $name } else { '<hidden SSID>' })
                Auth = ''; Bssids = @(); MaxSignal = 0
            }
            $nets += $cur
        } elseif ($cur -and $line -match '^\s*Authentication\s*:\s*(.*)$') {
            $cur.Auth = $Matches[1].Trim()
        } elseif ($cur -and $line -match '^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:-]{17})') {
            $cur.Bssids += $Matches[1]
        } elseif ($cur -and $line -match '^\s*Signal\s*:\s*(\d+)%') {
            $cur.MaxSignal = [Math]::Max($cur.MaxSignal, [int]$Matches[1])
        }
    }

    $inHome = @()
    $neighbours = @()
    foreach ($n in ($nets | Where-Object { $_.Auth -eq 'Open' })) {
        $served = $false
        if ($GatewayMac) {
            foreach ($b in $n.Bssids) {
                if (Test-GatewayServedBssid -Bssid $b -GatewayMac $GatewayMac) { $served = $true }
            }
        }
        if (-not $GatewayMac) {
            $inHome += "$($n.Name) (gateway MAC unknown)"
        } elseif ($served) {
            $inHome += "$($n.Name) (served by the gateway)"
        } elseif ($n.MaxSignal -ge $InHomeSignal) {
            $inHome += "$($n.Name) ($($n.MaxSignal)% signal)"
        } else {
            $neighbours += "$($n.Name) $($n.MaxSignal)%"
        }
    }

    $aside = if ($neighbours.Count) { "neighbouring, not ours: " + ($neighbours -join ', ') } else { '' }
    if ($inHome.Count) {
        $v = ($inHome -join ', ') + ' OPEN - broadcasting'
        if ($aside) { $v += "; $aside" }
        return $v
    }
    if ($aside) { return "no open AP of ours ($aside)" }
    return 'no open AP'
}
