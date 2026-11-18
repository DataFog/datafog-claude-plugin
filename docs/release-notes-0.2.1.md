# DataFog for Claude Code 0.2.1 — candidate

Not released or submitted. Final commit, CI and live results must be attached before
using these notes for a release or directory review.

This candidate addresses the directory reviewer's exact-version requirement and fixes
two cases where readable tool content could escape tokenization. It pins the detector
and encrypted vault to version 1.7.0, scans MCP resource-link names/titles/descriptions,
and hides stranded email-domain tails in joined Unicode text. Joined addresses may
become one marker; restoration remains byte-exact.

The manifest now provides privacy, documentation and support links, accurate coverage
language and the official DataFog icon. MCP tools declare their effects. A separate
CI job validates both plugin and marketplace manifests with an exact Claude Code version.
Privacy and security reporting documentation explain local storage and remaining limits.

MCP edit permission and concurrent-file safety changes are under final verification;
their behavior and results must be included here after review.

## Validation to attach

- Exact candidate commit and version agreement.
- Full Python suite, lint, types, shell parsing and strict manifests.
- Linux/macOS CI matrix, including private Secret Service tests on Linux.
- Real Claude Code read, Bash and marker-aware edit examples.
- Interactive permission behavior, host modes and runner lifecycle evidence.
- Candidate cached install, version-changing upgrade and uninstall retention.

## Remaining product boundaries

Detection is selective; names, ordinary unlabelled addresses and several phone/secret
formats remain unsupported. Post-tool hard failures can expose raw output. Built-in
file-tool restoration can enter local Claude records. DataFog is not a sandbox against
a manipulated agent or same-user software. The README contains the full coverage limits.
