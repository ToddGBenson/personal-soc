# personal-soc

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
