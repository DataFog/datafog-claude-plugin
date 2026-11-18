# DataFog for Claude Code 0.2.1 — candidate

Not released or submitted. Final commit, CI and live results must be attached before
using these notes for a release or directory review.

This candidate addresses the directory reviewer's exact-version requirement and fixes
two cases where readable tool content could escape tokenization. It pins the detector
and encrypted vault to version 1.7.0, scans MCP resource-link names/titles/descriptions,
and hides stranded email-domain tails in joined Unicode text. Startup and runtime
checks reject other installed versions, including after a failed upgrade; doctor
reports version failures accurately. Joined addresses may
become one marker; restoration remains byte-exact.

The manifest now provides privacy, documentation and support links, accurate coverage
language and the official DataFog icon. MCP tools declare their effects. A separate
CI job validates both plugin and marketplace manifests with an exact Claude Code version.
Privacy and security reporting documentation explain local storage and remaining limits.

Marker-aware MCP edits now enforce Read/Edit deny and ask rules, refuse uncheckable
settings, preserve internal symlink targets and reject intervening file/path changes.
Bounded reads, pinned directories and advisory locks protect the normal edit flow;
an unrelated writer can still race the final identity-check/rename boundary.

Independent review reproduced and verified fixes for an alias-retarget permission
race and repeated email-tail scanning. Cached 0.2.1 model sessions passed Read,
Bash, marker-aware edit and outside-project refusal, with installed production-file
hashes matching the candidate. The 0.2.0 → 0.2.1 upgrade retained marker identity.
Candidate evidence is recorded below; the final CI matrix remains open.

## Candidate validation

Candidate `fe1bd1c848880fc4c3c6015c136d5fd9ff28c1e0` retains the production files
from live-tested `aa99659a0f3218c443a6fcbc17dbeb9e43537574` unchanged.

- Main real-Claude suite: 187 PASS, 24 INFO, no failures or cap skips.
- Cached installed candidate: fresh startup, Read, Bash, marker-aware edit and
  outside-project refusal passed with installed production hashes verified.
- Fresh 0.2.0→0.2.1 upgrade preserved markers; uninstall retention was checked.
- Interactive permission, cancellation and macOS sandbox results are recorded in
  the host report, including host limitations and unverified environments.
- Six isolated Linux keyring tests passed, including locked-keyring refusal and
  recovery without rekeying or file-key fallback.
- Local lint, types and strict manifests passed. The actual `/bin/sh` fallback's
  27 cases passed after diagnosing an unrelated standalone Apple dash crash.
- The [final CI matrix](https://github.com/DataFog/datafog-claude-plugin/actions/runs/44368890375)
  is still running; this candidate is not yet declared ready to release.

See [candidate validation](verification/candidate-validation.md) for original
failed runs, corrections, evidence links and scope. These results do not imply
portal acceptance or publication.

## Remaining product boundaries

Detection is selective; names, ordinary unlabelled addresses and several phone/secret
formats remain unsupported. Post-tool hard failures can expose raw output. Built-in
file-tool restoration can enter local Claude records. DataFog is not a sandbox against
a manipulated agent or same-user software. The README contains the full coverage limits.
