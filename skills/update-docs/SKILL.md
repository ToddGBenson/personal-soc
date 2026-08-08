---
name: update-docs
description: Create or update documentation that stays true to the actual artifact. Every doc explains three things — its Purpose/Goal/Outcome (why it exists), how it's Constructed & Engineered (architecture, design decisions, how it's built), and how it's Used (setup, invocation, examples). Use for "update the docs", "write/refresh a README", "document this project/skill/module/API", "the docs are out of date", or after building or changing something that has documentation. Defaults to updating existing docs in place and verifying claims against ground truth.
---

# Update Docs

A repeatable process for writing and maintaining documentation that a cold reader can trust. The governing rule: **documentation describes what the artifact actually is and does — never what it was assumed, intended, or remembered to do.** Read the real thing first; write second.

## The content model (every doc answers these three)

Whatever you're documenting — a repo, a skill, a module, an API, a pipeline — the documentation must make three things clear. This is the required backbone; adapt depth and headings to the artifact.

1. **Purpose · Goal · Outcome** — *why it exists.* The problem it solves, what it's trying to achieve (and explicit non-goals/scope), and what a successful result looks like for the reader or system.
2. **Construction & Engineering** — *how it's built.* Architecture and components, how they relate and where data/control flows, the key design decisions and trade-offs (and why), dependencies and interfaces, and the engineering constraints (platform, performance, security).
3. **Usage** — *how to use it.* Prerequisites and setup, how to invoke/run/call it, real working examples and common workflows, configuration options, and troubleshooting/gotchas.

Details of what belongs in each are in `references/doc-structure.md`.

## Process (follow `references/process.md`)

1. **Identify** the subject and which doc(s) cover it; find where docs live.
2. **Gather ground truth** — read the actual code/config/tests/entry points. Do not trust existing docs or memory; they may have drifted.
3. **Detect drift** (for updates) — diff what the docs claim against what the artifact now does. The `scripts/Find-DocDrift.ps1` helper lists source files changed since a doc was last touched.
4. **Draft or update** — follow the content model and the right template (`references/templates.md`). **Update in place**, preserving the existing voice and intent; change only what's inaccurate or missing — don't rewrite wholesale unless asked.
5. **Verify** — confirm every command, path, and example is real and works; check code references resolve; strip any aspirational or unverifiable claim.
6. **Record the change** — update the "last updated" line and add a short changelog/"what changed" note.

## Non-negotiables

- **Accuracy over completeness.** A smaller doc that's correct beats a thorough one that lies. If you can't verify a claim, cut it or flag it.
- **Show, don't just tell.** Prefer runnable examples over prose descriptions of behavior.
- **Don't document what will rot.** Auto-derivable exhaustive lists (every function/flag) drift fast — link to the source instead of copying it.
- **Honor what's there.** Match the project's existing doc style, structure, and terminology (check `CLAUDE.md` / existing docs first). The user's conventions win over these defaults.
- **Diagram a mechanism when a picture beats prose** — use the `artifact-diagramming` approach for architecture/flow.
- **Match depth to the artifact.** A one-file script needs a paragraph; a system needs architecture. Don't over- or under-document.

## Output

Default: Markdown files living next to the code (`README.md`, `docs/`, a skill's `SKILL.md`, etc.), edited in place. Only build a rendered/hosted doc (artifact) when the audience needs it and the user asks — and load `artifact-design` if you do. See `references/style.md` for writing conventions.
