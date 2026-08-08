# Security Policy

## Scope & intent

`personal-soc` is **defensive** tooling: Claude Code skills for assessing and hardening
networks and identities **you own or are explicitly authorized to test**. The skills are
read-only and non-destructive by default and are gated behind authorization checks
(`rules-of-engagement.md`, `controls.md`). They are not intended for scanning third-party
networks or profiling other people.

## Reporting a vulnerability

If you find a security issue in these skills or scripts (for example, a code path that could
act destructively, leak data, or exceed the stated read-only boundaries), please report it
**privately**:

- Use GitHub's **"Report a vulnerability"** button under the repository's **Security** tab
  (private security advisory).

Please do not open a public issue for security-sensitive reports. As a solo project,
acknowledgement may take a little time — thanks for your patience.

## Handling personal data

This repository intentionally contains **no** personal data. The personalized files
(`references/profile.md`, `references/identifiers.md`) and all engagement output are
`.gitignore`d; only sanitized `*.example.md` templates are tracked. A CI check fails the
build if a real profile/ledger is ever committed. If you fork or reuse these skills, keep
your own filled copies out of version control.
