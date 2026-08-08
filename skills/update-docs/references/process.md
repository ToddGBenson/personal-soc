# Process — writing and updating docs

Six steps. The discipline that separates good docs from confident-but-wrong ones lives in steps 2 and 5: ground truth in, verification out.

## 1. Identify the subject and the docs
- Pin exactly what's being documented (a repo, a skill, a module, an endpoint) and its boundary.
- Find where docs already live: `README.md`, `docs/`, `SKILL.md`, header comments, a wiki. Prefer updating these over creating parallel files.
- If nothing exists, decide the right home and doc type (`templates.md`).

## 2. Gather ground truth (do not skip)
- **Read the actual artifact** — code, config, tests, entry points, `package.json`/manifests, git history. Tests and examples reveal real usage; the entry point reveals real flow.
- Treat existing docs and your own memory as **hints, not facts** — both drift. Confirm every claim against the current source.
- Note the real: purpose (from what it does, not what a stale intro says), structure, inputs/outputs, dependencies, and examples that actually run.

## 3. Detect drift (when updating)
- Compare what the docs claim to what the artifact now does. List: **wrong** (contradicts reality), **stale** (no longer true), **missing** (new behavior undocumented), **orphaned** (documents something removed).
- Use `scripts/Find-DocDrift.ps1 -Doc <doc> -Paths <src...>` to list source files changed since the doc was last committed — those are your update candidates.

## 4. Draft or update
- Follow the content model (`doc-structure.md`) and the matching template (`templates.md`).
- **Update in place.** Preserve the existing voice, structure, and intent; change only what's inaccurate, unclear, or missing. Don't rewrite a whole doc to fix a paragraph unless the user asks for a rework.
- Keep the reader's task in view — lead with what they need first (purpose, then quick start), detail later.
- Add a diagram only where it beats prose (architecture, data flow, state) — inline SVG per `artifact-diagramming`, or a mermaid block if the target renders it.

## 5. Verify (do not skip)
- **Run or trace every example.** Commands must execute; file paths must exist; code snippets must match current signatures. For a repo, actually run the quick-start, or at minimum confirm the referenced files/commands are real.
- Resolve every code reference (`file:line`, function names) against the tree.
- Remove anything you can't verify. No aspirational features, no "should work," no invented flags.
- Re-read Pillar 1–3 coverage: can a stranger get purpose, engineering rationale, and a working result?

## 6. Record the change
- Update the **Last updated** date.
- Add a one-line changelog entry (or update `CHANGELOG.md`): what changed and why, in the reader's terms.
- If docs and code are versioned together, note the version/commit the docs now reflect.

## Scope discipline
- Match effort to the artifact: a helper script gets a docstring + a paragraph; a system gets architecture + diagrams.
- Don't create documentation debt: avoid copying detail that will rot (exhaustive API dumps) — link to the source of truth.
- One change at a time: if asked to "update the docs" after a specific change, update what that change affected — don't silently re-document the whole project unless it's warranted and flagged.
