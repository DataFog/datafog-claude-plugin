# Public plugin directory readiness

Working inventory, 2026-11-18. Baseline: released v0.2.0, commit 3c41b49.
This is a live work list, not a claim that the release is ready. Submission and
publication require Sid's explicit go-ahead. Preparation and verification proceed now.

## Implementation and release gates

| ID | Gap / required outcome | Status and evidence |
| --- | --- | --- |
| I01 | Scan MCP resource-link human-readable metadata without corrupting identifiers. | Implemented and committed; focused hook/MCP tests passed. Final candidate CI remains open; see verification/candidate-validation.md. |
| I02 | Resolve adjacent Unicode email domain leak. | Local mitigation covers the joined span using core-validated trailing domains. 99 core/vault/stream tests and 90 additional Unicode/domain combinations passed; final integrated validation pending. |
| I03 | Resolve or explicitly constrain phone coverage regressions. | Known-format fixtures pin the affected 1.7.0 behavior and README gap 19 discloses it. A general regex workaround is deferred: multiline streaming needs lookahead semantics and numeric-prefix cases need precision evaluation. No complete phone-detection claim is made. |
| I04 | Align all public claims with actual coverage. | Manifest/marketplace/README and GitHub About narrowed to detected values. Homepage update drafted for release; no directory availability announced. |
| I05 | Verify clean install, first start and MCP startup from distributed repository. | Cached candidate real-host startup, three examples and project boundary passed with source hashes. Fresh 0.2.0→0.2.1 upgrade preserved markers; uninstall retention checked. See verification reports. Public final-release URL check awaits release. |
| I06 | Validate final candidate across supported systems. | Candidate lint/types/strict manifests pass; 187 real-Claude checks and six isolated Linux key-store tests pass. Final four-way CI for fe1bd1c remains active; prior release results are not substituted. |
| I07 | Package the reviewed candidate consistently. | Candidate manifests and pyproject agree on 0.2.1, runtime pins are 1.7.0, and strict manifests pass. Release notes identify tested production baseline and candidate; final CI and release/tag verification remain open. |
| I08 | Marker-aware MCP edit must respect denied paths. | Implemented shared Read/Edit matcher, ask/deny refusal and malformed-settings fail-closed behavior. Focused tests and independent retarget-race reproduction pass; final suite pending. |
| I09 | Characterize concurrent edits and symlink handling in MCP edit. | Implemented bounded descriptor reads, advisory lock, pinned target and identity/version checks. Independent review passes; final-check/rename race against noncooperating writers remains explicitly disclosed. |
| I10 | Enforce reviewed dependency versions at runtime, including failed upgrade. | Implemented metadata-before-import and module-version checks, truthful doctor, verified stamp reuse and failed-bootstrap refusal. Focused failure-path suite and independent review pass; full candidate suite running. |

## Runtime verification gates

| ID | Behavior requiring evidence | Status |
| --- | --- | --- |
| V01 | Runner preserves cwd and output; explicit cancellation/hard timeout stop descendants; default timeout behavior is accurately described. | **Verified scope:** candidate L04 passed cwd persistence; supplementary 2.1.327 probes collected 100 lines per stream and prevented delayed effects after TaskStop or timeout with `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1`. Default timeout auto-backgrounds, as now documented. Runner/wrapper code is unchanged between those probes and this candidate; no redundant repeat is required. Evidence: [candidate live](verification/candidate-validation.md), [host lifecycle](verification/2026-11-18-host-readiness.md). This does not prove unlimited output or every OS/termination signal. |
| V02 | Hook allow executes rewritten command without extra prompt in interactive and headless sessions. | **Verified scope:** default-mode interactive allow on 2.1.299; candidate 2.1.327 L02 and L19 confirm headless rule allow and late restoration; the cached installed Bash example also passed. Other interactive host versions are not certified. Evidence: [host](verification/2026-11-18-host-readiness.md), [candidate cases](verification/candidate-live-results.json), [installed](verification/2026-11-18-installed-candidate.md). |
| V03 | Hook ask retains markers, offered approve/deny choices work, and denial records retain marker commands. | **Verified scope:** real UI Yes/No worked and displayed the marker inside the rewritten wrapper. That hook prompt offers no persistent approval option, so a saved-rule test is inapplicable to this UI. Four headless denial modes preserve markers without raw values; candidate L18 also checks transcript/debug/denial records. Evidence: [interactive excerpts](verification/interactive-2026-11-18.txt), [host report](verification/2026-11-18-host-readiness.md), [candidate cases](verification/candidate-live-results.json). |
| V04 | Plan, auto, dontAsk and bypassPermissions modes obey documented decisions. | **Finite representative checks verified on 2.1.327:** four headless marker-ask denials; interactive bypass marker prompt/No; dontAsk exact-rule allow; interactive plan exact-rule command prompts/No; interactive auto nonmarker ask-rule prompts/No. For a deferred auto command, the guard recorded no decision plus rewritten input, and host permission metadata explicitly attributed acceptance to the classifier; interactive UI also showed `Allowed by auto mode`. This does not certify arbitrary classifier judgments or all mode/command combinations. [Mode evidence](verification/2026-11-18-host-readiness.md#finite-permission-mode-follow-up). |
| V05 | Actual permission_mode hook values, including subagents. | **Representative parent/child values verified:** default, acceptEdits, dontAsk, plan, bypassPermissions and auto arrived literally across probes. General-purpose child Read inherited acceptEdits, plan and dontAsk, with child agent IDs distinguishing it from the parent. Other child types/mode combinations are outside this finite check, not silently counted as covered. [Initial observer evidence](verification/host-readiness-results.json), [mode follow-up](verification/mode-supplement-results.json). |
| V06 | Documented Bash and Read/Edit path-rule cases match host behavior; unsupported cases remain conservative. | **Verified documented fixtures, not full matcher equivalence:** candidate live cases cover allow/ask/deny, untrusted shared allow rules and file/directory/quoted-glob Read restrictions. Broader host rule parity remains unverified; unknown patterns and invisible rules retain the documented conservative/unsupported boundary. Do not claim complete parity from unit tests. [Candidate cases](verification/candidate-live-results.json). |
| V07 | Trust location and CLAUDE_CONFIG_DIR behavior. | **Partial with an authentication boundary:** actual fixture trust was recorded under `~/.claude.json` at the canonical project path, including the installed candidate. A fresh CLAUDE_CONFIG_DIR created `<config-root>/.claude.json`, but required login before workspace trust; relocated trust-field behavior remains unverified. No credentials were copied, and generated fixture trust/session records were cleaned up. [Installed report](verification/2026-11-18-installed-candidate.md). |
| V08 | Managed settings from file versus server/MDM. | **Disclosed environment limit:** a managed file does not prove the effective server/MDM policy. No organization-managed host was exercised. The plugin cannot enforce policy it cannot read, and the README discloses that boundary; enterprise-policy equivalence remains unverified and must not be promised. |
| V09 | macOS Keychain locked/denied, SSH, login, and interpreter rebuild/update access. | **Happy path verified; environment-specific states remain open:** candidate optional L28 created/read/purged a separate real Keychain entry, preserved markers across processes and measured 15 hook processes. Locked/denied, SSH/login and interpreter-rebuild access were not exercised. These are disclosed state limitations, not covered by happy-path success. [Candidate Keychain evidence](verification/candidate-validation.md). |
| V10 | Linux Secret Service: locked collection, recovery and alternate providers. | **Focused GNOME state verification passed:** six isolated Ubuntu 24.04 tests proved a genuinely locked collection yields bounded refusal without rekey/file fallback, then restores the original marker after actual unlock. KWallet and other providers remain unverified. This focused result does not replace the final four-way platform matrix; fe1bd1c [CI run 44368890375](https://github.com/DataFog/datafog-claude-plugin/actions/runs/44368890375) remains pending in this inventory. [Private keyring evidence](verification/linux-keyring.md). |
| V11 | Built-in Edit result after marker restoration does not unexpectedly expose restored content to model. | **Verified scope on 2.1.327:** plain old_string plus marker new_string changed the real file, with no planted raw value in the model-facing result. Marker old_string was rejected before the hook, confirming the documented host limitation. Local transcripts can still contain restored input; this check does not remove that disclosure. [Host report](verification/2026-11-18-host-readiness.md). |
| V12 | First-install MCP project directory and startup. | **Verified cached candidate on 2.1.327:** real first-start bootstrap, marker-aware edit and outside-project refusal passed; initialization used the installed cache, with source/cache hashes checked. Production files match 276b2b3 and are unchanged at fe1bd1c. This closes local cached-install behavior; public final-release URL verification remains a separate release gate. [Installed report](verification/2026-11-18-installed-candidate.md). |
| V13 | Blocked prompt and unscannable-file ask user experience. | **Verified tested UI:** blocked synthetic prompt offered sanitized resubmission; unscannable Read offered a generic file approval and honored No. The screen-reader UI omitted DataFog's unscannable explanation; that limitation is documented rather than treated as a successful warning. Other renderers remain unverified. [Interactive excerpts](verification/interactive-2026-11-18.txt). |
| V14 | Claude Bash sandbox compatibility with runner process sessions. | **Verified configured macOS boundary:** sandbox enabled with failIfUnavailable and no unsandboxed fallback; a protected write inside the fixture was denied while the same runner returned tokenized content. Temporary plugin data/vault writes were explicitly allowed. Linux sandbox behavior and other sandbox/path configurations remain unverified environment limits. [Host report](verification/2026-11-18-host-readiness.md). |
| V15 | Unsupported platforms are clearly excluded and preflight gives actionable failure messaging. | **Support boundary disclosed; actual unsupported-host runs unverified:** Windows, Intel Mac, ARM/musl/older-glibc Linux remain unsupported. Platform-selection tests do not certify runtime behavior on those machines. No unsupported platform must pass as a supported target; preserve the explicit disable/uninstall guidance and do not market broader support. |

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
