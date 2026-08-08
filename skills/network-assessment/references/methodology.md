# Methodology — the phased playbook

Six phases. Each lists the commands, the script that encapsulates them, and the stop conditions. All commands here are Tier 0–1 (passive / light-active, read-only). Log every active command to `scan-log.md`.

Paths assume the skill's `scripts/` dir. On this machine nmap is at `C:\Program Files (x86)\Nmap\nmap.exe`. PowerShell scripts target Windows; the underlying nmap commands are portable.

---

## Phase 0 — Scope & authorization

1. Apply the **RoE gate** (`rules-of-engagement.md`). Confirm authorization + scope with the user.
2. Read the local network config to derive the default scope and record the vantage point:
   ```powershell
   Get-NetIPConfiguration | ? {$_.NetAdapter.Status -eq "Up"}
   Get-NetRoute -DestinationPrefix "0.0.0.0/0"     # default gateway
   Get-DnsClientServerAddress -AddressFamily IPv4
   ```
3. Create the engagement folder and write the confirmed scope + authorization statement as the first entry in `scan-log.md`.

**Stop:** no active probing until scope is confirmed in writing in the log.

---

## Phase 1 — Discovery & inventory

Goal: a complete host list. ICMP alone misses devices — combine sweep + ARP + mDNS/SSDP. Run **`Invoke-NetDiscovery.ps1`**, which does all three, or manually:

```
nmap -sn -PE -PS22,80,443,445 -PA3389 <CIDR>      # host discovery (multiple probes)
```
```powershell
Get-NetNeighbor -AddressFamily IPv4 | ? {$_.State -in 'Reachable','Stale'}   # full ARP table
```
Passive service discovery (catches hosts that ignore ping) — SSDP `M-SEARCH` to `239.255.255.250:1900` and an mDNS PTR query for `_services._dns-sd._udp.local` to `224.0.0.251:5353`, **bound to the LAN interface IP** (not the WSL/virtual adapter — that was the gotcha; multicast went out the wrong NIC until bound explicitly).

Cross-reference every MAC against the OUI table in `device-fingerprints.md`. Flag locally-administered (randomized) MACs — bit 0x02 of the first octet.

**Output:** `inventory.csv` (host, MAC, vendor, state). Expect the count to exceed the ping-sweep count; mDNS/ARP routinely surface 20–30% more.

**Stop:** discovery only — no port scanning of out-of-scope hosts.

---

## Phase 2 — Service & version fingerprinting

Non-elevated TCP-connect scans (no admin, no OS fingerprint). Deep on infrastructure, broad on the rest. Run **`Invoke-ServiceScan.ps1`** or:

```
# Infrastructure (router, NAS, unknowns): full-port
nmap -sT -sV -Pn --version-intensity 4 -p- --min-rate 1500 --host-timeout 12m <infra hosts>

# Everything else: top ports, gentle
nmap -sT -sV -Pn --version-intensity 2 --top-ports 300 --min-rate 1200 --host-timeout 4m <hosts>
```

Batch the host list to keep runs bounded. Identify each host by correlating open ports + banners + OUI against `device-fingerprints.md` (e.g. `9999`→Kasa, WD `GstpServer` banner→My Cloud, `8008/8009`→Chromecast).

**Stop:** version detection only. `-sV` sends benign probes; do not add intrusive `--script` categories here.

---

## Phase 3 — Targeted enumeration (read-only)

For each service of interest, enumerate **to listing depth only**. Run **`Invoke-ShareEnum.ps1`** for the file-sharing checks, plus the UPnP/SSDP steps.

- **SMB** (pinned safe scripts only):
  ```
  nmap -sT -Pn -p139,445 --script smb-protocols,smb2-security-mode,smb-security-mode <host>
  net view \\<host>          # anonymous share listing
  ```
  Flag: SMBv1 (`NT LM 0.12`) enabled; signing "enabled but not required"; anonymous share enumeration.
- **NFS** (listing depth — this is where the critical finding lives):
  ```
  nmap -sT -Pn -p111 --script nfs-showmount,rpcinfo <host>
  nmap -sT -Pn -p111 --script nfs-ls --script-args nfs-ls.maxfiles=12 <host>
  ```
  `nfs-ls` at listing depth proves unauthenticated read/write **without touching file contents**. Exports to `*` with `Modify/Extend/Delete` in the access line = Critical. **Do not go deeper.**
- **UPnP / SSDP:** fetch the IGD device description, enumerate the WAN service, and attempt to read (never add/delete) port mappings:
  ```
  GetExternalIPAddress / GetGenericPortMappingEntry via the WANIP/PPPConnection control URL
  ```
  Some gateways accept the connection but never answer — record as **inconclusive, not clean**. Never call `AddPortMapping`/`DeletePortMapping`.
- **SNMP** (read-only community check only, no guessing): `nmap -sU -p161 --script snmp-info` — closed is good; if open with `public`, flag but don't enumerate deeply.

**Stop:** listing only. No writes, no auth, no config calls.

---

## Phase 4 — Wi-Fi posture audit

Passive, from the local wireless adapter. Run **`Get-WifiPosture.ps1`** or:

```
netsh wlan show interfaces
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear      # saved auth/cipher (local profiles you own)
netsh wlan show networks mode=bssid                  # over-the-air auth/cipher + BSSIDs
```

Key checks:
- **Encryption:** WPA3 vs WPA2 vs Open. A saved profile showing WPA3 while the over-the-air scan shows WPA2 for the same SSID = **WPA3 transition mode** (downgrade-attackable).
- **Open SSIDs broadcasting in-home** — correlate strong-signal Open networks to a device (e.g. a Tuya/SmartLife gadget in setup mode).
- **BSSID→gateway correlation:** if the SSID BSSIDs match the router's LAN MAC ±a few (e.g. `70:f2:20:67:07:f0` → `...f3/f4/f5`), the Wi-Fi is served by the gateway itself — relevant when the gateway is EOL.

**Stop:** never attempt to connect to or capture handshakes from networks you don't own.

---

## Phase 5 — Analysis → CIS Controls v8 gap mapping

Load `cis-controls-v8.md`. Walk all 18 controls; for each, cite the **observed evidence** from Phases 1–4 and assign a status (Pass / Partial / Gap / High / Critical) per the rubric there. Then draft findings using `remediation-library.md` so remediation wording is consistent and correct.

Produce `findings.json`: `{id, title, severity, cis_control, evidence, impact, remediation}`.

Severity anchors (see report-outline): unauthenticated access to data/backups = Critical; missing structure (segmentation, monitoring, managed infra) = High; hardening gaps = Medium.

---

## Phase 6 — Report

Load `report-outline.md` for the required structure and diagram set. Design the page fresh with the `artifact-design` and `artifact-diagramming` skills — do not clone a previous report's visuals. Publish as a private artifact and hand the user the link with a confidentiality reminder.

---

## What non-elevation costs you (disclose in the report)

TCP-connect scans can't do SYN stealth, OS fingerprinting, or raw-socket UDP nuance. State this in the method/caveats. Also flag what you **couldn't** reach: WAN-side exposure (needs an external vantage), router/NAS credential strength (needs the login), and guest-network isolation (needs joining it). Default/reused admin credentials would undercut multiple controls — always call this out.
