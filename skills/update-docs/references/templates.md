# Templates by doc type

Skeletons that lay out the three-pillar content model for common doc types. Fill with verified content; drop sections that don't apply. Headings can be renamed to match the project.

---

## Project README

```markdown
# <name>
<one-line: what it is and who it's for>

## Purpose
<the problem it solves; why it exists. Non-goals if useful.>  ← Pillar 1

## Quick start
<prerequisites → install → the single command that produces a result>  ← Pillar 3 (lead with this)

## How it works
<architecture overview + a diagram if the structure warrants; key design
decisions and why; data/control flow; dependencies>  ← Pillar 2

## Usage
<common workflows as real examples; configuration table; troubleshooting>  ← Pillar 3

## Project layout
<key dirs/files, linked to source>

## Contributing / Security / License
<links>

_Last updated: <date>_
```

---

## Component / skill / module doc

```markdown
# <component>
<one-line summary>

## Purpose & outcome
<what it's for; what success looks like>  ← Pillar 1

## Design
<how it's built: responsibilities, interfaces/contracts, key decisions,
dependencies, constraints>  ← Pillar 2

## Usage
<how to invoke; parameters/options table; examples; gotchas>  ← Pillar 3
```

---

## Architecture / design doc (decision-oriented, ADR-style)

```markdown
# <title>
**Status:** <proposed | accepted | superseded>  **Date:** <date>

## Context
<the forces and constraints; what problem/decision this addresses>  ← Pillar 1

## Decision
<what was chosen>

## Engineering
<how it's constructed to realize the decision: components, flow, interfaces,
trade-offs considered and rejected>  ← Pillar 2

## Consequences
<outcomes, benefits, costs, follow-ups; how to operate/use the result>  ← Pillars 1 & 3
```

---

## API / interface reference (entry point + link, don't transcribe everything)

```markdown
# <API name>
## Purpose
<what it lets a caller do>  ← Pillar 1
## Contract
<endpoints/functions: signature, inputs, outputs, errors, invariants>  ← Pillar 2
## Examples
<request → response for the common calls>  ← Pillar 3
## Full reference
<link to generated/source-of-truth docs>
```

---

## CHANGELOG entry

```markdown
## [<version or date>]
### Changed / Added / Fixed / Removed
- <reader-facing description of what changed and why>
```
