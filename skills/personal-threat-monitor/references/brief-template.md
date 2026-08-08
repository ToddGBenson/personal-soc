# Output templates

## Check B — weekly threat brief (`threat-brief.md`)

Keep it short and scannable — one screen. Lead with what's new/actionable, not a wall of background.

```
# Personal Threat Brief — <Full Name> — week of <YYYY-MM-DD>

## Act this week
- <1–4 concrete items: a live campaign matching the user + what to do>

## By dimension
### Executive / security-leader
- <threat> — <one line why it applies to this user> [source]
### Financial / crypto
- <threat> [source]
### Health / medical
- <threat> [source]
### Family / eldercare  (+ Arizona locale)
- <threat> [source]

## In your inbox (if consented)
- <any researched campaign already reaching the user, or "nothing matched this week">

## New since last week
- <deltas vs the prior brief; omit if first run>

Sources: <list of URLs cited>
```

Rules: date it; cite every claim; rank by applicability to *this* user; separate "seen on you" from "general risk"; inform without alarm (see `controls.md` §8).

## Check A — footprint digest (`report.md` section)

```
# Digital Footprint — <Full Name> — <YYYY-MM-DD>

## New exposures since last run
- <lead with these>

## Standing exposure by category
| Category | What's exposed | Where | Confidence | Removal action |
|----------|----------------|-------|------------|----------------|
| Brokers  | age/phone/addr | Spokeo, ... | confirmed | opt-out link + steps |
| Breach   | ...            | ...   | ...        | ... |
| Account  | OAuth grant / device / linked acct | Gmail | confirmed | review/revoke |
| Social/code | ...         | ...   | ...        | ... |

## Removal worklist (prioritized)
1. <broker> — <link> — <status>

## Account hygiene
- <OAuth revokes, passkey/device checks, MFA, linked-account security>

## Not tested / recommend the user check
- <e.g. HIBP/DeHashed direct lookup, LinkedIn visibility settings>
```

Both are **local files**. Offer to render a formatted artifact only if the user asks — and even then, keep it private (self-OSINT is sensitive; never auto-publish). Update `footprint.json` so the next run can diff.
