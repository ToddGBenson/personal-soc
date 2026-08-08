# Documentation content model

The three pillars every doc must cover, expanded. Use these as the checklist for *what to say*; use `templates.md` for *how to lay it out* per doc type. Not every artifact needs every sub-point — include what's true and useful, omit what isn't, and never pad.

## Front matter (top of every doc)
- **Title** + one-line summary (what it is, in a sentence a stranger understands).
- **Status** if relevant (draft / stable / deprecated).
- **Last updated** date + a short changelog or link to one, so drift is visible.
- **Audience** note when a doc serves both users and maintainers — split the sections rather than blending.

## Pillar 1 — Purpose · Goal · Outcome  (the *why*)
- **Purpose:** the problem this solves and why it exists. What was missing or painful without it.
- **Goal:** what it sets out to achieve; the scope. State **non-goals** explicitly — what it deliberately does *not* do is as clarifying as what it does.
- **Outcome:** what the reader/system actually gets. What "working" looks like; concrete results, guarantees, or metrics where they exist. Answer "how do I know it succeeded?"

## Pillar 2 — Construction & Engineering  (the *how it's built*)
- **Architecture / overview:** the components and how they fit together. A diagram earns its place when the structure or flow is hard to hold in prose (see `artifact-diagramming`).
- **Data & control flow:** how a request/input moves through the parts; what transforms it; where state lives.
- **Design decisions & trade-offs:** the choices that matter and *why* — what was chosen, what was rejected, and the constraint that forced it. This is what a future maintainer most needs and can't recover from the code alone.
- **Interfaces & contracts:** inputs/outputs, APIs, events, file formats, invariants callers rely on.
- **Dependencies:** external services, libraries, runtimes, and why each is needed.
- **Layout:** where things live (key files/dirs) — link to source; don't transcribe it.
- **Constraints:** platform, performance, security, and operational limits the design lives within.

## Pillar 3 — Usage  (the *how to use it*)
- **Prerequisites & setup:** what must exist first; install/config steps that actually work.
- **Invocation:** how to run/call/trigger it — the primary path, shown with a **real, runnable example**.
- **Workflows / recipes:** the common tasks, each as a concrete example (input → command → result).
- **Configuration:** options/flags/env vars, with defaults and effects — as a table when there are several.
- **Troubleshooting:** the failure modes people actually hit and how to resolve them; known gotchas.
- **Reference (if a library/API):** the interface surface — but link to generated/source-of-truth reference for exhaustive detail rather than duplicating it.

## Quality bar (a doc is done when…)
- A newcomer can state the purpose and decide if it's for them from Pillar 1 alone.
- A maintainer can understand *why it's shaped this way* from Pillar 2 without reading all the code.
- A user can go from zero to a working result by following Pillar 2's setup + Pillar 3's example.
- Every command, path, and code reference has been verified against the actual artifact.
