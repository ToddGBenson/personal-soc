# Multi-domain risk (beyond cyber)

Extends Check B from "cyber threats/scams" to a broader personal-risk picture. Each domain: what to assess, where to look, how it ties to the profile, and how it feeds the weekly digest. **Not professional financial/medical/legal advice** — risk *awareness* with concrete actions.

Weight by the subject's `profile.md`: age band, household composition (partner / children / any dependent elderly relative), locale + ZIPs, mobile carrier, and confirmed/likely breach exposure.

---

## 1. Identity theft  (HIGH when SSN/DL are breach-exposed)
Assess: new-account fraud, tax-refund fraud, medical identity theft, SSN misuse.
Sources/actions:
- **Credit freeze** (3 bureaus) — the #1 control; already flagged.
- **IRS Identity Protection PIN** — get one at irs.gov/ippin (blocks fraudulent tax filing in your name). Proactive, free.
- **SSA account** — create/lock `my Social Security` at ssa.gov so no one else registers it.
- **FTC** identitytheft.gov — recovery plan template; monitor for signs.
- **Medical** — review insurer EOBs for services you didn't get (medical ID theft).
Digest signal: any breach adding SSN/financial identifiers, tax-season timing (Jan–Apr), new-account alerts.

## 2. Physical / home security  (weight the elderly parent + package theft)
Assess: residential crime trends for your ZIPs, package/mail theft, physical mail as an ID-theft vector, smart-home physical security (locks/cameras/garage — cross-refs the network scan).
Sources:
- **Local crime data** — the subject's city/county police crime maps; SpotCrime / community alerts for their ZIPs.
- **Mail theft** — USPS Informed Delivery (enroll so you know what *should* arrive; blocks a thief enrolling as you); package-theft seasonality.
- Cross-reference: cameras/locks found on the network scan — are they patched, and is footage stored securely?
Digest signal: a crime-trend spike in your ZIPs, active porch-piracy/mail-theft waves (esp. holidays), a smart-lock/camera CVE from the vuln scan.

## 3. Personal / travel safety
Assess: destination safety + health, and "empty house" signaling.
Sources:
- **State Dept advisories** — travel.state.gov (levels 1–4) for any destination.
- **CDC Travelers' Health** — health notices for destinations.
- **OPSEC:** real-time social posts ("at the airport!") advertise an empty home — a physical-risk leak from the OSINT side. Recommend delayed posting.
Digest signal: only when travel is planned (ask/observe); otherwise the OPSEC reminder.

## 4. Financial risk / exposure  (awareness, not advice)
Assess: fraud impact + resilience (not investment advice — profile reports no notable investments).
Sources/actions:
- **Account-takeover** monitoring on primary financial + email accounts (already covered by cyber).
- **Free credit reports** — annualcreditreport.com (weekly free) to catch new-account fraud early.
- **Bank/card alerts** — enable transaction alerts.
- **Elderly parent financial exploitation** — the top elder-fraud vector; CFPB/AARP resources; watch for the parent-targeted scams in Check B.
Digest signal: a breach at a financial provider you use; elder-financial-exploitation campaigns active in AZ.

## 5. Reputational / doxxing
Assess: aggregated public info usable to target or impersonate you (large overlap with OSINT footprint).
Sources: the OSINT footprint (Check A) + broker removal worklist; monitor for new profiles/mentions.
Digest signal: a new high-visibility exposure, or your identifiers appearing in a paste/forum.

---

## How this changes the digest
The digest gains a **"cross-domain" section** below cyber/OSINT: only surface a domain when there's something *active and applicable* (a crime spike in your ZIP, tax season for IP-PIN, a planned trip, an elder-fraud wave). Keep it awareness-level and action-oriented; don't manufacture risk to fill space. Same severity gating (🔴/🟠/⚪).
