# Controls — privacy, ethics, and data handling

The safety layer for both checks. This skill touches sensitive PII, so the controls are the point, not an afterthought.

## 1. Self-directed only

- The subject is the **account owner** (or a dependent they're clearly responsible for and acting for — e.g. a minor child, an elderly parent under their care). 
- **Refuse** to run this to profile, investigate, locate, or build a dossier on anyone else. If asked, say plainly it's a self-monitoring tool and stop. OSINT techniques pointed at a third party without cause are surveillance — not what this skill does.

## 2. Source boundaries

**Allowed:** public search engines, publicly readable broker listings, public social/forum/usenet posts, public code repos, public records, breach-notification services the user chooses to use, and the user's **own** connected accounts (with consent).

**Not allowed:** paying data brokers to unlock records, logging into accounts that aren't the user's, scraping behind auth walls, buying leaked datasets, running credential-stuffing/lookups against others, social-engineering or pretexting any human or support desk, or creating fake accounts to view someone's profile.

## 3. Consent & least data for connected accounts

- Get explicit consent before reading the user's Gmail/Calendar/Drive/etc. Record the grant in `run-log.md`.
- **Minimize:** query with metadata/snippets first; only open a full message body when a specific finding needs it, and note why.
- Read-only. Never send, draft, label, delete, or modify the user's mail/accounts as part of monitoring.
- Don't retain message contents in the report — record the *finding* (e.g. "OAuth grant to Fieldy, Feb 2026"), not the raw email.

## 4. Confidentiality of output

- Findings map the user's live vulnerabilities. Treat as **confidential**.
- Store only in the local `personal-monitor/<date>/` folder. Do **not** publish to a shareable/hosted artifact by default — build a local file and let the user decide (self-OSINT reports are exactly the "sensitive, let the user choose the URL" case).
- Never transmit findings to any external service, and never include another real person's PII (relatives surfaced in broker records) beyond what the user needs to act.

## 5. Accuracy discipline

- Report only what a source actually returned. **No invented findings**, no assumed breaches, no "you're probably on X."
- Label confidence: **confirmed** (direct hit), **inferred** (pattern match), **ambiguous** (possible common-name collision). Keep other people's records out of the user's profile.
- "Not found in public search" ≠ "not exposed" — recommend the authoritative check (e.g. HIBP/DeHashed for breaches) rather than asserting a clean bill.
- Cite sources for every threat-intel claim so the user can verify.

## 6. `profile.md` handling

- It contains the user's PII and risk attributes. Keep it in `~/.claude/skills/` only; **never** commit it to a repo, sync it, or include it in an artifact.
- If the skill is ever shared/exported, `profile.md` must be stripped.

## 7. Audit trail

Maintain `run-log.md` per run: timestamp, which source categories were queried, which of the user's accounts were accessed and why. Same discipline the network skill applies — the monitoring is itself logged.

## 8. Tone

Inform, don't alarm. Rank by real applicability to this user. Give concrete next actions, separate "confirmed exposure" from "general risk," and never use fear to push action. The goal is an informed owner, not an anxious one.
