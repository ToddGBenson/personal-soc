# CIS Controls v8 — home / small-network mapping

The knowledgebase for Phase 5. For each of the 18 controls: what to verify on a home/SMB LAN, how to gather the evidence (from the earlier phases), and the status rubric. Scope to Implementation Groups 1–2 — IG1 is the "essential cyber hygiene" floor, IG2 adds structure. Don't grade against IG3 (enterprise) for a home network.

## Status rubric

| Status | Meaning |
|--------|---------|
| **Pass** | Control substantially met |
| **Partial** | Some coverage, material gaps |
| **Gap** | Control largely absent, moderate risk |
| **High** | Absent and creating real exposure |
| **Critical** | Absent/broken and directly exposing data, credentials, or recovery capability |
| **N/A** | Not applicable at this scale |

Severity should reflect *this* network's evidence, not the control's generic importance.

---

## The 18 controls

**01 — Enterprise Asset Inventory.** Verify: is there a maintained device list? Evidence: compare your discovered inventory (Phase 1) to any list the user keeps; note hosts found only via ARP/mDNS. Typical home gap: none maintained; DHCP on ISP gateway with no visibility → **Gap**.

**02 — Software Asset Inventory.** Verify: known/allowed software & firmware across PC, NAS, IoT. Evidence: service/version banners (Phase 2); unmanaged IoT firmware. Typical: none → **Gap** (low priority at home).

**03 — Data Protection.** Verify: who can reach the data, is it classified, encrypted at rest. Evidence: SMB/NFS enumeration (Phase 3). Unauthenticated read/write to personal or backup shares → **Critical**. This is usually the headline finding on a home NAS.

**04 — Secure Configuration.** Verify: hardening of devices/services. Evidence: SMBv1, signing-not-required, UPnP, WPA3-transition, Open SSID, plaintext admin, vendor defaults. Multiple present → **Critical/High**.

**05 — Account & Credential Management.** Verify: unique accounts, no anonymous access, MFA on admin planes, credential strength. Evidence: anonymous SMB/NFS (Phase 3); admin-plane exposure. Note credential strength is usually **untested** (needs login) — say so. Anonymous data access → **High**.

**06 — Access Control Management.** Verify: least privilege between zones. Evidence: is the network flat (Phase 1)? Flat /24 with IoT + servers + workstation together → **High**. This is the segmentation control.

**07 — Continuous Vulnerability Management.** Verify: recurring scanning, patch cadence, EOL gear. Evidence: first-ever scan? EOL kernel on the gateway (unpatchable)? → **High**.

**08 — Audit Log Management.** Verify: central logging + retention. Evidence: any logging anywhere? Usually none at home → **High**. Incident reconstruction impossible without it.

**09 — Email & Web Browser Protections.** Usually out of primary LAN scope; if personal mail is on a major provider, note provider defenses → often **N/A / Partial**.

**10 — Malware Defenses.** Verify: endpoint protection. Evidence: Windows Defender on the PC (firewall state as a proxy); NAS/IoT typically undefended → **Partial**.

**11 — Data Recovery.** Verify: 3-2-1, offline/immutable copy, tested restores. Evidence: are "backups" on a network-writable share (Phase 3)? A single network-reachable, writable copy → **Critical** (ransomware destroys data + backup together). Distinct from control 03 — grade both.

**12 — Network Infrastructure Management.** Verify: supported gear, managed firewall, config backup/versioning. Evidence: EOL ISP gateway as sole router/firewall/DNS/AP → **High**.

**13 — Network Monitoring & Defense.** Verify: IDS/IPS/NSM, netflow, egress/DNS monitoring. Evidence: none present → **High**. This is the "do I need Security Onion" control — answer per remediation-library.

**14 — Security Awareness.** Single household → **N/A**. For a family/small-biz, brief guidance may apply.

**15 — Service Provider Management.** Verify: third-party/ISP access. Evidence: ISP remote-management agent on the gateway (e.g. a listener on a high port); cloud dependencies of IoT → **Gap**. Provider access you don't control/monitor.

**16 — Application Software Security.** Applies when the user *develops* software. Verify: environment separation, secure SDLC, where source/artifacts live. Evidence: source on an unsecured NAS; no dev/CI/staging/prod separation; no SAST/dependency/secret scanning → **High**. Ties the assessment to their build pipeline.

**17 — Incident Response Management.** Verify: a plan, roles, and the logging to support it. Evidence: none + no logs (control 08) → **Gap**.

**18 — Penetration Testing.** Verify: regular internal/external testing. Evidence: this assessment is the baseline; no external-perspective test; recommend turning their own tooling inward on a cadence → **Partial**.

---

## Scorecard pattern

Home NAS + flat network engagements typically land: Criticals cluster in **03 / 04 / 11** (all on the NAS, usually configuration not patching), Highs cluster in the **absence of structure** — **06 (segmentation), 12 (managed infra), 13 (monitoring)**. Lead the report with that shape; it tells the user *what kind* of problem they have (config + missing architecture), not just a list.
