---
name: network-assessment
description: Repeatable, safety-gated security assessment of a network you own or are explicitly authorized to test. Covers host discovery, service fingerprinting, SMB/NFS/UPnP/mDNS enumeration, Wi-Fi posture audit, CIS Controls v8 gap mapping, and a structured report with network diagrams. Use for "assess/scan/audit my network", home / lab / small-business network reviews, standing up a recurring internal scan cadence, or any request to inventory and evaluate the security of a LAN. Do NOT use for scanning networks the user does not control.
---

# Network Assessment

A controlled, evidence-driven process for assessing the security of a LAN and producing a report mapped to CIS Controls v8. This skill encodes a methodology that is **read-only and non-destructive by default** and gated behind an authorization check.

## STOP — Rules of Engagement gate (do this first, every time)

Before running **any** active probe (anything beyond reading the local machine's own config), confirm two things with the user:

1. **Authorization** — the user owns the target network or has explicit permission to test it.
2. **Scope** — the exact CIDR/subnet(s) in bounds, and anything explicitly out of bounds.

Derive the default scope from the local machine (its own subnet, e.g. `192.168.0.0/24`). If a requested target is **outside** the local subnet, or looks like it could be a third party (a neighbor's SSID, a public IP, a corporate range on a work device), do not scan it without an explicit, unambiguous confirmation of ownership/authorization. When in doubt, ask.

Read `references/rules-of-engagement.md` and follow it. It defines the technique tiers, the hard stop conditions, evidence handling, and the audit-log requirement. **The stop conditions are not optional** — most important: enumeration stops at *listing* (shares, exports, directory names). Never open, read, copy, or exfiltrate file contents; never attempt credential guessing/brute force; never modify a device's configuration; never run exploits or denial-of-service techniques as part of an assessment.

## Workflow

Run the phases in `references/methodology.md`. In short:

| Phase | What | Tier |
|-------|------|------|
| 0 | Scope & authorization (RoE gate) + local config | passive |
| 1 | Host discovery + full inventory (nmap `-sn`, ARP, mDNS, SSDP) | passive / light |
| 2 | Service & version fingerprinting (TCP-connect, non-elevated) | light active |
| 3 | Targeted enumeration — SMB/NFS/UPnP, read-only | light active |
| 4 | Wi-Fi posture audit (`netsh`) | passive |
| 5 | Analysis → CIS Controls v8 gap mapping | offline |
| 6 | Report with diagrams | offline |

Prefer the scripts in `scripts/` — they encapsulate exactly the commands this process uses and write structured evidence to the engagement folder. They are non-elevated (TCP-connect) by design; note in the report what elevation would additionally reveal rather than silently requiring it.

## Knowledgebase index (load on demand — this is the RAG)

Pull the relevant reference into context only when the phase needs it:

- `references/rules-of-engagement.md` — **always, at Phase 0.** Authorization, scope, technique tiers, stop conditions, evidence handling, audit log, recommended permission allowlist.
- `references/methodology.md` — the phased playbook with exact commands and per-phase stop conditions.
- `references/device-fingerprints.md` — Phase 1–3. Port/service signatures and vendor-OUI hints → device type (Kasa, Echo, WD My Cloud, casting, thermostats, etc.).
- `references/cis-controls-v8.md` — Phase 5. All 18 controls, what to verify on a home/SMB network, how to gather evidence, and the status rubric.
- `references/remediation-library.md` — Phase 5–6. Reusable finding→remediation blocks so recommendations stay consistent and correct across engagements.
- `references/report-outline.md` — Phase 6. Required report sections, the diagram set, and the severity model. Design each report fresh via the `artifact-design` + `artifact-diagramming` skills — the outline fixes *structure*, not visuals.
- `references/vulnerability-scanning.md` — CVE matching (`scripts/Invoke-VulnScan.ps1`). Turns "port open" into "known-CVE finding" via version→CVE lookup. **Banner-based — verify before acting.**
- `references/external-exposure.md` — WAN view (`scripts/Get-ExternalExposure.ps1`). What the internet sees of your public IP (Shodan InternetDB) — the perspective a NAT'd internal scan can't reach.

## Output & data handling

Create a dated engagement folder and keep all evidence there (default under the session scratchpad, or a path the user designates):

```
netassess/<YYYY-MM-DD>-<scope-label>/
  scan-log.md        # every command run, with timestamps and target — the audit trail
  raw/               # raw nmap / netsh / enumeration output
  inventory.csv      # host, MAC, vendor, open ports, identified device
  findings.json      # structured findings: id, title, severity, cis, evidence, remediation
  report.html        # the published artifact source
```

Assessment output is **confidential** — it is a map of someone's exposures. Keep it in the engagement folder, never send it to an external service, and when the user shares the report, remind them it reveals live weaknesses. Redact or caveat before any external distribution.

## Repeatability, change detection & scoring

To make this a recurring monitoring capability (ported from a production SOC's security automation), see `references/change-detection.md`:

- Each run writes `findings.json` (`{id,title,severity,cis,status}`) + `inventory.csv` to `netassess/<date>/`.
- **`scripts/Compare-Assessment.ps1 -Baseline <prev> -Current <this>`** diffs the two: resolved / new / severity-changed findings, host add/remove (MAC-level), and a **0–100 posture score with delta**.
- Emit a **combined security digest** (network + OSINT + threat + score + changes) as the deliverable — severity-gated so only high/critical changes page.
- Drive on a cadence with `/schedule` or `/loop`; lead with the delta, not a full re-dump. A new host or a newly opened critical is the signal worth alerting on.
