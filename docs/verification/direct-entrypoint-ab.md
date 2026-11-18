# Direct executable entry-point A/B candidate

Prepared on 2026-11-18 against released baseline `964fe10`, without a version bump
or a new release. This is a narrow experiment for the portal's
`COMMAND_PATH_COMPUTED` finding; passing local tests does not prove that finding
is resolved. The report locates the blocker only at `.`.

The four hook commands now invoke the quoted
`${CLAUDE_PLUGIN_ROOT}/scripts/datafog-guard` executable directly. The MCP command
uses that same path with `args: ["mcp"]`. The existing launcher is unchanged,
tracked executable (`100755`), and starts with `#!/bin/sh`. Bootstrap, dependency
pins, runtime selection, vault behavior, hook failure policy and engine code are
unchanged. Manual commands using `sh` continue to work.

This names the actual bundled entry point directly rather than making `sh` the
declared executable. It does not conceal the launcher, move its code, or remove
any capability. Nested-script reviewer holds and organization verification remain
separate questions for the portal.

## Verification

- Relevant CLI/plugin, hook protocol, MCP and live-driver tests: **208 passed,
  4 skipped** in 24.89 seconds. A new regression executes actual declared
  SessionStart and MCP entries from a plugin directory containing spaces.
- Network-enabled cold bootstrap and full simulator tests: **2 passed** in
  18.50 seconds. The simulator now expands `${CLAUDE_PLUGIN_ROOT}` in the command
  field as the real host does, as well as in arguments.
- Ruff, `git diff --check`, and strict `claude plugin validate --profile directory`
  passed. The local directory profile has fewer checks than the portal.
- Real Claude Code **2.1.327** cached installation: fresh interactive trust/startup,
  Read, filtered Bash, marker-aware MCP edit and outside-project MCP refusal all
  passed. Every model run loaded the actual installed cache. The cache matched
  candidate production hashes. The unique installation/marketplace and generated
  fixture host records were removed afterwards.

[Structured cached-host results and candidate hashes](direct-entrypoint-ab-results.json)
preserve the tested state. The candidate retains version 0.2.1 for isolated A/B
validation only; do not present it as a replacement for the published tag.

## Required next evidence

Push the diagnostic branch and validate that exact SHA in the portal. Record
whether `COMMAND_PATH_COMPUTED` disappears, changes, or remains. A local pass is
not grounds to rewrite the launcher internals speculatively or to mark publisher
verification complete.
