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
