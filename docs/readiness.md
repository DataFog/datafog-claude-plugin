# Public plugin directory readiness

Working inventory, 2026-11-18. Baseline: released v0.2.0, commit 3c41b49.
This is a live work list, not a claim that the release is ready. Submission and
publication require Sid's explicit go-ahead. Preparation and verification proceed now.

## Implementation and release gates

| ID | Gap / required outcome | Status and evidence |
| --- | --- | --- |
| I01 | Scan MCP resource-link human-readable metadata without corrupting identifiers. | Fixed locally; agent reports 139 hook tests, 12 MCP tests, lint and type checks passing. Final candidate validation remains open. |
| I02 | Resolve adjacent Unicode email domain leak. | Local mitigation covers the joined span using core-validated trailing domains. 99 core/vault/stream tests and 90 additional Unicode/domain combinations passed; final integrated validation pending. |
| I03 | Resolve or explicitly constrain phone coverage regressions. | Known-format fixtures pin the affected 1.7.0 behavior and README gap 19 discloses it. A general regex workaround is deferred: multiline streaming needs lookahead semantics and numeric-prefix cases need precision evaluation. No complete phone-detection claim is made. |
| I04 | Align all public claims with actual coverage. | Manifest/marketplace/README and GitHub About narrowed to detected values. Homepage update drafted for release; no directory availability announced. |
| I05 | Verify clean install, first start and MCP startup from distributed repository. | Cached candidate real-host startup, three examples and project boundary passed with source hashes. Fresh 0.2.0→0.2.1 upgrade preserved markers; uninstall retention checked. See verification reports. Public final-release URL check awaits release. |
| I06 | Validate final candidate across supported systems. | v0.2.0 release reports 2,476 passed, 42 skipped, one expected failure; four CI jobs passed. New candidate needs its own lint/types/tests, Linux key-store coverage and live evidence. |
| I07 | Package the reviewed candidate consistently. | Manifest/version/dependency agreement, strict plugin validation, release notes and exact tested revision must agree before submission. |
| I08 | Marker-aware MCP edit must respect denied paths. | Implemented shared Read/Edit matcher, ask/deny refusal and malformed-settings fail-closed behavior. Focused tests and independent retarget-race reproduction pass; final suite pending. |
| I09 | Characterize concurrent edits and symlink handling in MCP edit. | Implemented bounded descriptor reads, advisory lock, pinned target and identity/version checks. Independent review passes; final-check/rename race against noncooperating writers remains explicitly disclosed. |
| I10 | Enforce reviewed dependency versions at runtime, including failed upgrade. | Implemented metadata-before-import and module-version checks, truthful doctor, verified stamp reuse and failed-bootstrap refusal. Focused failure-path suite and independent review pass; full candidate suite running. |

## Runtime verification gates

| ID | Behavior requiring evidence | Status |
| --- | --- | --- |
| V01 | Runner preserves cwd; collects complete stdout/stderr; cancellation and timeout stop descendants. | L04 covers cwd. Real 2.1.327 collected 100 lines per stream; TaskStop and timeout with host background disabled prevented delayed effects. Default timeout auto-backgrounds; docs corrected. Repeat candidate cases after freeze. |
| V02 | Hook allow executes rewritten command without extra prompt in interactive and headless sessions. | Observed default-mode interactive allow on 2.1.299; headless fixture allows pass. |
| V03 | Hook ask displays markers; approve/deny works; persistent approval saves a safe rule; denied-call records retain marker command. | Real UI approve/deny passed; marker remained inside visible wrapper. Tested hook prompt has Yes/No only, no persistent approval. Four headless denial modes preserve marker and no raw value. |
| V04 | Plan, auto, dontAsk and bypassPermissions modes obey documented decisions. | Verify each separately; especially hook ask under bypassPermissions and auto classifier behavior. |
| V05 | Actual permission_mode hook values, including subagents. | Observer captured dontAsk/plan/bypassPermissions/auto; parent and subagent acceptEdits with child agent_id. See host report. |
| V06 | Claude rule matching agrees with plugin for Bash and Read/Edit paths; unknown cases remain conservative. | Unit coverage exists; live parity beyond documented examples remains open. |
| V07 | Trust location and CLAUDE_CONFIG_DIR behavior. | Verify against isolated configuration; do not alter real user trust/settings. |
| V08 | Managed settings from file versus server/MDM. | Cannot infer effective server policy from a file; document supported boundary and verify available cases. |
| V09 | macOS Keychain locked/denied, SSH, login, and interpreter rebuild/update access. | Happy-path creation/read/purge already reported passing; other states remain unverified. |
| V10 | Linux Secret Service: KWallet and locked session keyring. | Private GNOME Keyring CI exists; other providers/states remain unverified. |
| V11 | Built-in Edit result after marker restoration does not unexpectedly expose restored content to model. | Plain old_string plus marker new_string succeeded with no planted raw value in model-facing result. Marker old_string rejected before hook, as documented. |
| V12 | First-install MCP project directory and startup. | Passed in real cached-install 2.1.327 sessions: fresh bootstrap, marker edit and outside-project refusal, with actual cache path and hashes verified. |
| V13 | Blocked prompt and unscannable-file ask user experience. | Observed blocked prompt + sanitized resubmission and generic unscannable Read prompt. UI omission of unscannable warning documented. |
| V14 | Claude Bash sandbox compatibility with runner process sessions. | macOS sandbox enabled with failIfUnavailable and no fallback: outside write denied, tokenized read succeeded. Scope requires explicit temporary data/vault write allowances; Linux remains unverified. |
| V15 | Unsupported platforms fail with actionable messaging. | Windows, Intel Mac, ARM/musl/older-glibc Linux are unsupported; do not imply runtime support from mocked checks. |

## Product limits requiring accurate disclosure

These are not automatically bugs that can be fixed inside a hook. Closure means
evidence, accurate claims and appropriate defaults; unsupported protection is not promised.

1. Unknown values: names, ordinary unlabelled addresses, missing credential formats,
   and detector false negatives. A future local model needs accuracy and latency evaluation.
2. Encoded/transformed values, hashes, partial output and command-based inference.
3. PostToolUse crash/timeout window for output-only tools.
4. Deliberate same-user recovery, Linux `/proc` output bypass, indirect vault access.
5. Unscanned images/PDFs and unrecognised `@` mention syntax.
6. Claude telemetry and local prompt history outside the plugin's control.
7. Restored Write/Edit/NotebookEdit and Grep/Glob input in local transcripts;
   optional third-party MCP restoration also sends real values away.
8. Paths, filenames and resource URIs are identifiers, not scanned prose.
9. Binary output with invalid-byte splits; huge values/commands; vault capacity limits.
10. Writes by other tools may leave markers; unknown markers remain unchanged.
11. Restored Bash arguments may appear in process lists or be interpreted as options.
12. Vault encryption does not resist programs running as the logged-in user;
    explicit file-key mode exposes values if the whole directory is copied.
13. Permission rules unavailable to the plugin and indirect file access cannot be
    represented as complete enforcement of host policy.
14. Shell state/aliases/functions differ from ordinary Claude Bash sessions;
    multiline values can change shadow-file line counts.
15. Core ApplicationVault API/filesystem limitations tracked in core #275,
    including whole-vault cost and finite revision/value capacity.

## Submission gates

Detailed policy sources and reviewer copy belong in `directory-submission.md`.

The directory audit adds explicit gates D01–D13 there: old submission ownership,
privacy-policy URL, verified support/security contact, three runnable examples, MCP
annotations, accurate public claims, Code-only surface support, install/upgrade/uninstall,
dependency provenance, permission/sandbox review, portal validation, final release evidence,
and authorized submission/publication. These are part of this inventory, not optional
follow-up work. A local privacy notice and narrower manifests are now drafted; they are
not yet publicly published or portal-validated.

- Existing submission located in the authenticated portal: submitted July 2, marked
  **Needs changes** October 5. Reviewer rejected v0.1.0 (`7a154b2`) because package
  execution was not exactly pinned. Exact dependency pins are therefore a confirmed
  blocker, not just a reproducibility preference. The existing entry offers resubmission;
  no duplicate or migration is needed. See D01/D09 and the portal link in the submission doc.
- Portal auto-publish was enabled and all app surfaces were selected. Both are corrected:
  auto-publish is now OFF, support is Claude Code only; no resubmission occurred.
- GitHub private vulnerability reporting is enabled and verified. `SECURITY.md` and
  `PRIVACY.md` are local candidate documents awaiting release publication.
- Verify current portal eligibility, automated checks and manual-review requirements
  for shell hooks, local MCP, Python and first-start dependency installation.
- Supply accurate description, support/security contact, privacy information,
  reproducible reviewer examples, platform constraints and installation guidance.
- Resolve portal checks against the final repository revision and inspect rendered listing.
- Obtain explicit publication instruction, then submit and retain confirmation/status.
  Review acceptance is external; submission alone does not prove listing publication.

## Evidence discipline

Record command, revision, environment, result and limitations for every closed gate.
Do not count a synthetic unit test as proof of host UI behavior or a release's old
test results as proof of a changed candidate. Keep synthetic fixtures and temporary
vaults separate from real user data. Never commit login material or raw user transcripts.
