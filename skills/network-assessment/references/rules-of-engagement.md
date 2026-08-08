# Rules of Engagement & Security Controls

This is the control layer for the network-assessment skill. It applies the same discipline a professional engagement uses, scaled to a self-owned network. Follow it on every run.

## 1. Authorization model

Only assess a network under one of these conditions:

- The user **owns** it (their home / their lab), **or**
- The user has **explicit written authorization** to test it (an engagement, a CTF/lab range they were granted).

Signals that require you to stop and confirm before proceeding:
- A target **outside the local machine's own subnet**.
- A **public / routable** IP as a scan target.
- Any hostname/SSID/range that could belong to a **neighbor, employer, or third party**.
- The user is on a **work-managed device** (corporate MDM, domain-joined) — their employer's network is not theirs to scan without authorization.

If authorization is ambiguous, do not scan. Ask one direct question and wait.

## 2. Scope definition

- **In scope:** the confirmed CIDR(s), captured verbatim in `scan-log.md` at Phase 0.
- **Default:** the local interface's own subnet, discovered from `Get-NetIPConfiguration` / `ip addr`.
- **Out of scope:** everything else, including the WAN side, the ISP, and any cloud services the devices talk to. Assess the *local* posture; do not probe upstream providers.
- Never pivot beyond the agreed scope even if a device offers a route to another segment.

## 3. Technique tiers

| Tier | Techniques | Rule |
|------|-----------|------|
| **0 — Passive** | Read local config; listen for ARP, mDNS/`5353`, SSDP/`1900`; read `netsh wlan` profiles | Always allowed within scope |
| **1 — Light active** | Host discovery (`nmap -sn`); TCP-connect service/version scan (`-sT -sV`); read-only enumeration — SMB dialect/share **listing**, `nfs-showmount`, UPnP device description fetch, mDNS query | Allowed within confirmed scope |
| **2 — Intrusive** | Authentication attempts, default-credential checks, write/delete tests, SNMP community guessing, deauth, active exploitation | **Requires explicit, specific, per-engagement authorization.** Default is NO. Prefer to *report the exposure* rather than prove it. |
| **✕ — Never** | Credential brute force, exploitation for access, DoS/stress, config modification, data exfiltration, persistence, scanning out-of-scope hosts | Prohibited in a defensive assessment. Do not perform even if asked casually — confirm intent and authorization, and decline if it isn't legitimate authorized testing |

Default posture is **Tier 0–1 only**. To prove a finding (e.g., that an NFS export is actually writable), stop at the least-intrusive demonstration — a directory *listing* proves unauthenticated read; do not write a test file, do not open documents. For example, a WD My Cloud exporting NFS to `*` can be confirmed at listing depth with `nfs-ls` and taken no further; that is the model.

## 4. Hard stop conditions

- **Stop at listing.** Enumerate share/export/directory *names* only. Never open, read, download, or copy file contents.
- **No writes.** Never create/modify/delete files or device configuration during an assessment.
- **No credentials.** No login attempts, no password guessing, no default-cred testing, without Tier-2 authorization.
- **Non-elevated first.** Use TCP-connect scans that don't need admin. If elevation would materially change findings (SYN scan, OS fingerprint, raw sockets), *note what it would add* and let the user decide — don't silently escalate privilege.
- **Rate & stability.** Keep scan rates modest; fragile IoT devices can crash under aggressive probing. Avoid `--min-rate` spikes and full `-p-` sweeps against unknown embedded devices unless needed.

## 5. Least privilege (how the process itself is scoped)

- Run recon at the lowest privilege that produces the evidence.
- The helper scripts are non-elevated by design.
- Don't request or use admin/root, MCP tokens, or cloud credentials for a LAN assessment — they aren't needed and expand blast radius.

## 6. Evidence handling & confidentiality

- All output goes to the dated engagement folder; nothing leaves it automatically.
- Scan results are a **live map of exposures** — treat as confidential. Do not paste raw findings into external tools, chats, or issue trackers without the user's say-so.
- When the user publishes the report, remind them it exposes real weaknesses and to share it deliberately (private by default).
- Retain evidence only as long as useful; offer to purge the engagement folder when done.

## 7. Audit trail (required)

Maintain `scan-log.md` in the engagement folder. For every active command, record: timestamp, the exact command, the target(s), and a one-line purpose. This makes the assessment reconstructable and is itself the CIS-18 discipline you're recommending to others. Example row:

```
2026-08-07 18:27  nmap -sn -PE 192.168.0.0/24        scope 0.0/24   host discovery
2026-08-07 18:45  nmap --script smb-protocols 0.5     NAS            SMB dialect check (read-only)
```

## 8. Recommended Claude Code permission allowlist

To make recurring recon low-friction *without* loosening safety, allowlist the read-only commands and keep everything else prompting. Apply via the `update-config` or `fewer-permission-prompts` skill (don't hand-edit settings.json with guessed matcher syntax). Suggested allow entries:

- `nmap` invocations for discovery and TCP-connect service scans
- `netsh wlan show` (profiles/networks/interfaces)
- `Get-NetIPConfiguration`, `Get-NetNeighbor`, `Get-NetRoute`, `Get-NetFirewallProfile` (read-only PowerShell)

Do **not** allowlist anything that writes, authenticates, or modifies config — those should always prompt. Note: nmap default-script categories can include intrusive scripts; pin scripts explicitly (as the methodology does) rather than allowlisting `--script` broadly.

## 9. Legal & ethical note

Unauthorized network scanning may violate computer-misuse law (e.g., CFAA in the US) and ISP/employer terms. This skill is for defending networks you own or are authorized to test. If a request doesn't fit that, decline the scan and offer the defensive alternative (config review, guidance) instead.
