---
name: personal-threat-monitor
description: Two personal-security checks for the account owner about themselves. (1) OSINT self-assessment — what is publicly known about the user across web, data brokers, breach dumps, social media, usenet/forums, code repos, and public records, with a removal playbook. (2) Personalized threat intelligence — current threats, scams, and social-engineering/phishing campaigns relevant to the user's specific profile (age, location, job, health, family, finances) for a given week. Use for "what's known about me online", "check my digital footprint", "my personal threat brief", "am I being targeted", weekly personal-security digests, or automating either on a schedule. Self-directed only — this assesses the user's OWN exposure and risks.
---

# Personal Threat Monitor

Two related checks that keep the account owner informed about (A) their **public exposure** and (B) their **personal threat landscape**. Both are *self-directed*: they operate on the user's own identity and risk profile, using public sources plus — with consent — the user's own connected accounts.

## Guardrails (read first, every run)

This skill is **only** for a person assessing themselves (or a dependent they are responsible for, with a clear basis). It is not for researching, profiling, or investigating other people. Load `references/controls.md` and follow it:

- **Subject = the account owner.** If asked to run this against a third party, decline and explain it's a self-monitoring tool.
- **Public sources + owner's own accounts only.** No paying brokers, no logging into others' accounts, no scraping gated data, no impersonation, no pretexting, no purchasing personal data.
- **Consent for connected accounts.** Reading the user's Gmail/Calendar/etc. requires their go-ahead; minimize access (snippets/metadata before full bodies).
- **PII is confidential.** Findings are a live map of the user's vulnerabilities — keep them in the local engagement folder, never publish to a shareable artifact without explicit consent, never send externally.
- **Report only what sources return.** Never fabricate a "finding." Distinguish confirmed vs inferred vs ambiguous (common-name collisions are real — don't conflate other people's records into the user's profile).

## The profile & identifier ledger (personalization core)

Both checks are driven by two confidential files — read **both** at the start of every run:

- `references/profile.md` — the identity summary + risk-dimension weights.
- `references/identifiers.md` — the expanded **identifier ledger** (current + previous emails, phones, addresses, handles, employers, digital assets, voice/photo exposure, and a monitor-only set). This is what makes deep OSINT and attack-surface modeling possible.

Then read `references/identifier-usage.md` for how to consume the ledger — query fan-out across every historical identifier, the ≥2-fact disambiguation rule, and deriving SIM-swap / recovery-chain / KBA / voice-clone risk. **Respect the handling classes:** `[S]` search, `[D]` disambiguate only, `[M]` never search — monitor exposure only. If the ledger is empty or stale, prompt the user to populate it (see the collection guide inside `identifiers.md`). **Keep `profile.md` and `identifiers.md` out of any git repo or synced/shared location; strip them if the skill is ever exported.**

## Check A — OSINT self-assessment (digital footprint)

Goal: tell the user what is publicly discoverable about them, what changed since last run, and how to reduce it.

1. Load `references/profile.md` (identifiers) and `references/osint-sources.md` (where to look + query patterns).
2. Sweep the source categories: search engines, data brokers, breach/paste exposure, social media, usenet/forums, code repos (they're a developer — watch for leaked secrets/emails in commits), professional networks, images, public records.
3. With consent, check the user's own inbox for breach notifications, security alerts, standing OAuth grants, and linked/recovery identities (`references/osint-sources.md` has the Gmail query set).
4. Classify each finding: category, what's exposed, severity, and — per the user's preference — a **removal action** from `references/broker-optout.md`.
5. Diff against the previous run's `footprint.json`; surface *new* exposures prominently.

## Check B — Personalized threat intelligence (weekly brief)

Goal: a short, dated brief of threats that actually apply to *this* person this week.

1. Load `references/profile.md` (risk dimensions) and `references/threat-sources.md` (feeds + demographic-risk mapping).
2. Research current campaigns across the user's weighted dimensions (e.g. executive/whaling, financial/crypto, health/medical, family/eldercare) **plus their locale** (state/metro fraud alerts).
3. With consent, correlate against the user's inbox — is any of this *already* landing on them? Active phishing they've received is the strongest signal.
4. Produce the brief per `references/brief-template.md`: per-dimension threats with sources, an "act this week" list, and anything newly relevant since last week.

## Output & engagement folder

```
personal-monitor/<YYYY-MM-DD>/
  footprint.json     # Check A findings (structured, for diffing)
  threat-brief.md    # Check B brief
  run-log.md         # sources queried + accounts accessed (audit trail)
  report.md          # combined human-readable digest (local file, NOT auto-published)
```

Keep everything local and confidential. If the user wants a formatted artifact, build it as a **local file** and let them choose whether to publish (per `controls.md`).

## Accuracy & coverage add-ons

- **Verify before asserting** (`references/verification.md`) — common-name OSINT hits are *candidates* until confirmed; keep them off the profile/report and on a `verify-checklist.md` until the user rules on them.
- **Confirm breaches** (`scripts/Invoke-BreachCheck.ps1` + `references/breach-confirmation.md`) — HIBP/DeHashed turn "likely breached" into dated, confirmed exposure (needs a HIBP API key; never commit it).
- **Beyond cyber** (`references/risk-domains.md`) — identity-theft, physical/home, travel/personal-safety, and financial-risk domains, surfaced in the digest only when active and applicable.

## Automation

Both checks suit a weekly cadence. Use the `/schedule` skill to run a cloud agent (e.g. Monday mornings, aligned to the user's existing morning-brief routine), or `/loop` for a self-paced local run. Each scheduled run should: reload the profile, run A and B, diff against last week, and surface only what's **new or newly relevant** — a full re-dump every week trains the user to ignore it. Alert-worthy signals: a new broker listing, a new breach hit, a new device/OAuth grant, or a threat campaign that matches something in their inbox.

**Combined digest.** Deliver the output as a single severity-gated digest that folds these two checks together with the network assessment's posture score and change detection — the "morning briefing" format (🔴 page / 🟠 nudge / ⚪ log). See the network-assessment skill's `references/change-detection.md` and the worked example at `netassess/<date>/security-digest.md`. This is the shape to hand to a schedule or push to notifications.
