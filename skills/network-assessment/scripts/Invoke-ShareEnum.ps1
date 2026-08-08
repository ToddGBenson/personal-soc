<#
.SYNOPSIS
  Phase 3 — file-sharing enumeration, READ-ONLY, listing depth only.
  SMB protocols/security + share listing; NFS showmount + directory listing.
.NOTES
  SAFETY: pinned safe nmap scripts only. Stops at listing — never opens file
  contents, never writes, never authenticates. This is the model used to confirm
  an unauthenticated NFS export without touching data.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Target,        # host to enumerate, e.g. 192.168.0.5
  [Parameter(Mandatory)][string]$OutDir,
  [string]$NmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"
)
$ErrorActionPreference = "Continue"
function Log($msg){ Add-Content "$OutDir\scan-log.md" ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $msg) }
New-Item -ItemType Directory -Force -Path "$OutDir\raw" | Out-Null

Write-Host "== Phase 3: read-only share enum on $Target ==" -ForegroundColor Cyan

# --- SMB: dialects + signing posture + anonymous share listing ---
Log "nmap --script smb-protocols,smb2-security-mode,smb-security-mode $Target   [SMB read-only]"
& $NmapPath -sT -Pn '-p139,445' --script 'smb-protocols,smb2-security-mode,smb-security-mode' $Target |
  Tee-Object "$OutDir\raw\smb-$Target.txt"
Log "net view \\$Target   [anonymous share listing]"
net view "\\$Target" 2>&1 | Tee-Object "$OutDir\raw\smb-shares-$Target.txt"

# --- NFS: exports + listing depth (proves unauth read/write WITHOUT reading files) ---
Log "nmap --script nfs-showmount,rpcinfo $Target   [NFS exports]"
& $NmapPath -sT -Pn -p111 --script 'nfs-showmount,rpcinfo' $Target |
  Tee-Object "$OutDir\raw\nfs-$Target.txt"
Log "nmap --script nfs-ls maxfiles=12 $Target   [NFS listing depth ONLY]"
& $NmapPath -sT -Pn -p111 --script nfs-ls --script-args nfs-ls.maxfiles=12 $Target |
  Tee-Object "$OutDir\raw\nfs-ls-$Target.txt"

Write-Host "`nDONE (listing depth). Flags to look for:" -ForegroundColor Green
Write-Host "  - SMB dialect 'NT LM 0.12 (SMBv1)'      -> Critical/High (CIS 04)"
Write-Host "  - message_signing 'not required'         -> High"
Write-Host "  - NFS export to '*' with Modify/Delete   -> Critical (CIS 03/11)"
Write-Host "  - anonymous share names returned         -> High (CIS 05)"
Write-Host "SAFETY: do not go deeper than these listings." -ForegroundColor Yellow
