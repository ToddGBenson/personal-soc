# personal-soc

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![guard](https://github.com/ToddGBenson/personal-soc/actions/workflows/guard.yml/badge.svg)](.github/workflows/guard.yml)

A small suite of [Claude Code](https://claude.com/claude-code) **skills** that act as a security operations center scoped to one person and one home. Each skill is a repeatable, safety-gated process with an on-demand reference knowledgebase (the "RAG") and — where useful — helper scripts.

Built defensively: read-only and non-destructive by default, authorization-gated, and strict about keeping personal data out of version control.

## Skills

### `network-assessment`
Repeatable security assessment of a network you own or are authorized to test: host discovery, service fingerprinting, SMB/NFS/UPnP/mDNS enumeration, Wi-Fi posture audit, and a report mapped to **CIS Controls v8**.

- **Safety:** Rules-of-Engagement gate (authorization + scope) before any active probe; technique tiers; enumeration stops at listing (never opens file contents); non-elevated, read-only scripts; audit-logged.
- **Layout:** `SKILL.md` orchestrator · `references/` (methodology, CIS v8 mapping, device fingerprints, remediation library, report outline, rules-of-engagement) · `scripts/` (PowerShell, parse-verified).

### `personal-threat-monitor`
Two self-directed checks that keep the account owner informed about their own exposure and risks:

- **Check A — OSINT self-assessment:** what's publicly discoverable about you (web, data brokers, breach/paste, social, usenet, code repos, public records) + an inbox breach/OAuth review, with a data-broker **removal playbook**.
- **Check B — personalized threat intel:** a weekly brief of current scams, phishing, and social-engineering campaigns weighted to your own risk profile (executive/security-leader, financial/crypto, health, family/eldercare) plus your locale.

- **Safety:** self-directed only (won't profile third parties); public sources + your own consented accounts only; least-data access; findings kept local and never auto-published; a confidential **identifier ledger** with three handling classes — `[S]` search, `[D]` disambiguate-only, `[M]` monitor-only (sensitive IDs never stored in full).

## Personal data is not in this repo

The skills are shareable; **your data is not.** Two files hold personal information and are **gitignored**:

- `skills/personal-threat-monitor/references/profile.md`
- `skills/personal-threat-monitor/references/identifiers.md`

This repo ships only sanitized templates: `profile.example.md` and `identifiers.example.md`. To use the skill, copy each `.example.md` to its real name and fill it in locally. Engagement output (`personal-monitor/`, `netassess/`, scan logs, findings) is gitignored too.

The shared skill files also use **generic examples** (placeholder MACs, IPs, and profiles) — personalization lives only in your local, gitignored copies. A continuous check ([`.github/workflows/guard.yml`](.github/workflows/guard.yml)) fails the build if a filled `profile.md` or `identifiers.md` is ever committed.

> Tip: keep the filled `profile.md` / `identifiers.md` physically outside the repo and symlink them in, so an accidental `git add -A` can't scoop them up.

## Install

Copy (or symlink) a skill folder into your Claude Code skills directory:

```
~/.claude/skills/network-assessment
~/.claude/skills/personal-threat-monitor
```

Then invoke by asking for it — e.g. "assess my network", "check my digital footprint", or "give me my threat brief."

## Scope & ethics

For defending networks and identities **you own or are authorized to assess**. Not for scanning third-party networks or profiling other people. Each skill's `rules-of-engagement.md` / `controls.md` defines the boundaries; follow them.

## Repository

- **License:** [MIT](LICENSE).
- **Security policy:** report issues privately via [SECURITY.md](SECURITY.md) (GitHub private advisory); no public issues for security-sensitive reports.
- **Integrity:** `main` is branch-protected (no force-push, no deletion, linear history required); GitHub **secret scanning + push protection** are enabled; the [`guard`](.github/workflows/guard.yml) workflow blocks personal data from ever being committed.

---

_Last updated: 2026-08-08 — documented LICENSE, SECURITY policy, and the CI guard added during public release; noted that shared skill files use generic examples with personalization kept local._
