# Writing style

How the prose should read. These are defaults — a project's existing conventions (in `CLAUDE.md` or its current docs) override them.

## Voice
- **Audience-first.** Write from the reader's side. Name things as they know them, not by internal implementation ("notifications," not "webhook dispatcher").
- **Active voice, present tense, concrete.** "The scanner reads the config," not "the config will be read." Say exactly what happens.
- **Plain and direct.** Cut throat-clearing, marketing, and hedging. No "simply," "just," "easy" — they age badly and belittle stuck readers.

## Accuracy (the prime directive)
- Every claim is traceable to the artifact. If you didn't verify it, don't assert it.
- Prefer showing real output/examples over describing behavior in the abstract.
- When something is uncertain or unverified, mark it plainly (`> TODO: confirm…`) rather than stating it as fact.

## Structure & scannability
- Lead with the answer: purpose and quick start up top; depth below.
- Real headings that describe content; keep a consistent heading hierarchy.
- Short paragraphs. Lists for sequences and options. Tables for anything with parallel columns (flags, config, comparisons).
- Define a term once, then use it consistently — no synonyms for the same concept.

## Formatting conventions
- Fenced code blocks with a **language tag**; keep examples copy-pasteable and minimal.
- Use `inline code` for identifiers, paths, commands, and values.
- Link to source (`path/to/file`) instead of transcribing code that will drift.
- Keep line length reasonable; let Markdown reflow prose.

## What not to do
- Don't document intentions or roadmap as if implemented.
- Don't duplicate content that lives authoritatively elsewhere — link it.
- Don't bury the usage example under paragraphs of theory.
- Don't let tone drift into sales copy; a reader wants to understand and act, not be convinced.
