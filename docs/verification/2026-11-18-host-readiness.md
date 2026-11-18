# Host verification, 18 November 2026

This records observed behavior, not a final-candidate certification. Tests ran on
macOS Apple Silicon against the working tree based on `3c41b49` while other
readiness fixes were being developed. Repeat the relevant probes against the
frozen candidate. Synthetic fixtures, temporary file-key vaults and fixture-only
Claude settings were used. Real user vaults and key-store entries were not used.

Claude Code updated itself during verification: the first interactive process
remained **2.1.299**; subsequent headless and bypass-mode interactive processes
reported **2.1.327**. Do not merge these into a single-version claim.

## Interactive observations

The real CLI ran in a PTY with `--ax-screen-reader --setting-sources project,local`
and `--plugin-dir` pointing at this checkout. See the redacted excerpts in
[interactive-2026-11-18.txt](interactive-2026-11-18.txt).

| Gate | Evidence | Scope / remaining work |
| --- | --- | --- |
| V02 | On 2.1.299, default-mode `pwd` matched a local allow rule and ran without a command approval prompt. | Workspace trust was separately accepted for the synthetic fixture. |
| V03 | A `grep -cxF` call containing the hostile synthetic value's marker prompted. Yes returned the exact-match count `1`; repeating the call prompted again; No interrupted it. | Prompt shows the rewritten shell wrapper, paths and restore ticket, with marker retained. It does not show the raw value. |
| V03 | Hook-generated Bash ask offered only Yes and No. | No persistent “don't ask again” option existed in this tested UI; do not claim a saved-rule flow was tested. |
| V04 | On 2.1.327, interactive `bypassPermissions` still prompted for the marker call. No interrupted it. | Only this marker-ask path was tested interactively in bypass mode. |
| V07 | Accepting fixture trust wrote `projects[canonical_fixture_path].hasTrustDialogAccepted=true` in `~/.claude.json`. | `CLAUDE_CONFIG_DIR` behavior remains unverified. No existing project trust was changed. |
| V13 | Submitting a synthetic email prompt showed “your prompt was not sent,” entity count and sanitized replacement text. | The raw text remained in the local input box, consistent with documented local-history limits. |
| V13 | Reading an unscannable synthetic image asked permission; No interrupted it. | The screen-reader UI showed a generic Read approval with the file path, **not** DataFog's unscannable warning. Do not imply the host always explains that approval reveals unscanned content. |

The original interactive log is retained locally under the printed temporary
fixture directory, rather than committed as a full host transcript.

A separate 2.1.327 PTY launched with a fresh `CLAUDE_CONFIG_DIR` created
`<config-root>/.claude.json`, then required login before showing workspace trust.
The probe stopped at login and copied no credentials. The relocated config-file
location is observed; the relocated project-trust field remains unverified.

## Additional real-host probes

Run `python3 tests/live/run_readiness.py` for the bounded supplementary suite, or
pass individual case names. It prints its temporary evidence directory and writes
`log/readiness.json` plus host stream-json transcripts. It uses the existing
Claude login and therefore consumes normal Claude usage. This complements
`tests/live/run-live.command`; simulator results do not prove host behavior.

Observed on **2.1.327**:

| Probe | Result |
| --- | --- |
| `reviewer-read` | PASS: Read result contained markers; no planted sentinel in model-facing tool results. |
| `reviewer-bash` | PASS: allowed `cat notes.txt` returned markers; no planted sentinel in tool results. |
| `reviewer-mcp-edit` | PASS: DataFog MCP edit ran; exact real email plus suffix was on disk; no marker on disk or sentinel in tool results. |
| `built-in-edit-marker-old-string` | Verified documented host limitation: marker-bearing old_string was rejected before plugin restoration; file unchanged. |
| `built-in-edit-marker-new-string` | PASS: plain old_string and marker-bearing new_string updated the real file; the model-facing Edit result contained no planted sentinel. |
| `runner-complete-output` | PASS: all 100 numbered stdout lines and all 100 stderr lines reached the tool result. This is a finite collection check, not unlimited-output coverage. |
| Default foreground timeout | **Finding:** timeout 1000 ms and `run_in_background=false` still moved the command into the background; its delayed side effect occurred. The timeout is a host background threshold by default. |
| `runner-timeout-no-background` | PASS with `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1`: host reported timeout and the delayed descendant side effect remained absent after six seconds. |
| `runner-cancel` | PASS: TaskStop stopped an auto-backgrounded command; its ten-second delayed side effect remained absent after a twelve-second observation. |
| `mode-marker-dontAsk`, `mode-marker-plan`, `mode-marker-bypassPermissions`, `mode-marker-auto` | PASS: actual Bash call attempted and denied, denial record retained a marker, no raw synthetic value in denial. These headless sessions explicitly had no approval surface. |
| Mode observation hooks | A read-only fixture hook recorded actual `permission_mode`: `dontAsk`, `plan`, `bypassPermissions`, `auto`, and `acceptEdits` matched the requested modes. It saved only tool name/id, mode and agent metadata. |
| `subagent-mode` | PASS: parent Agent and a general-purpose subagent's actual Read both received `acceptEdits`; child hook input included its own agent ID/type. Other subagent modes remain untested. |
| `sandbox-bash`, `sandbox-boundary` | PASS: macOS sandbox enabled with `failIfUnavailable=true`, `allowUnsandboxedCommands=false`, and explicit writes allowed to temp plugin data/vault. A protected fixture write was refused with an operation-not-permitted error and no file created, while the same runner returned tokenized notes. No tool requested a sandbox bypass. |

The first supplementary run intentionally exposed two failed expectations:
marker old_string Edit support and hard termination on default Bash timeout.
Neither was “fixed” by changing the product. Later probes separate the documented
Edit restriction, default host auto-background behavior, explicit TaskStop and
the host's disable-background setting. Keep these distinctions in release copy.

The underlying source logs are in the local temp directories named in
`host-readiness-results.json`; the checked-in summary preserves their case names,
version and assertions without full host transcripts. Initial logs were produced
before the supplement began recording provenance hashes, so they prove these
observations but do not certify the final source revision.

## Still unverified

- Arbitrary auto-classifier decisions and other command/permission combinations
  beyond the finite mode checks below; all subagent types/mode combinations.
- Additional Bash and Read/Edit rule parity beyond existing documented fixtures.
- Alternate configuration-root trust handling, server-managed policy and MDM.
- Locked/denied macOS Keychain, SSH/login/rebuilt-interpreter access; KWallet and
  locked Linux keyrings. Happy-path vault tests do not prove these states.
- Network-hosted marketplace startup and upgrade paths. A later
  [cached installed candidate run](2026-11-18-installed-candidate.md) separately
  verifies installed first start, all three examples and MCP project boundaries.
- Other sandbox configurations/providers, including a vault outside the sandbox's
  allowed write paths. The macOS probe explicitly allowed its temporary data/vault.
- Unsupported hardware/OS runtime behavior beyond mocked platform checks.
- Other terminal renderers/accessibility modes, other host versions, larger output
  and platform-specific cancellation semantics.

## Reviewer examples

Use a fresh synthetic fixture folder and file-key vault as created by the
supplementary driver. `notes.txt` starts with `Primary contact:` followed by the
synthetic email, and other synthetic test values. Marker suffixes vary per vault;
never hard-code them in a reviewer instruction.

1. **Read** — Prompt: `Use Read on notes.txt and report the Primary contact line.`
   Expected: the tool result and answer contain an `[[EMAIL_…]]` marker rather than
   the original address. Independently compare the on-disk fixture, which remains
   unchanged. Automated assertion: `reviewer-read`.
2. **Bash output** — Prompt: `Run exactly this Bash command: cat notes.txt. Report
   its output.` The fixture's local settings allow `Bash(cat *)`. Expected: a real
   Bash call succeeds and its output contains markers. Automated assertion:
   `reviewer-bash`.
3. **MCP marker edit** — Prompt: `Use Read on notes.txt. Append " (verified)" to
   the Primary contact line using only DataFog edit_with_markers, with the exact
   full line as old_string. Do not use built-in Edit.` Expected: the MCP tool runs,
   the disk line contains the original address plus the suffix, and no marker is
   left on disk. Tool results contain no planted raw value. Automated assertion:
   `reviewer-mcp-edit`.

These three examples passed on 2.1.327 and were subsequently repeated against the
[installed cached candidate](2026-11-18-installed-candidate.md), closing that
distribution-path check separately from the local plugin path.

## Harness validation

`ruff check tests/live/run_readiness.py tests/live/run_live.py` passed. Four
existing non-network live-driver tests passed, covering temp confinement, version
rejection and fixture-settings isolation. The new supplementary probes use the
real host directly; their successful observations are listed above rather than
inferred from simulator behavior. Sandbox options follow the official
[settings reference](https://code.claude.com/docs/en/settings-reference).

## Finite permission-mode follow-up

Five additional headless runs and two real PTY sessions on **2.1.327** closed the
remaining representative V04/V05 checks. They reused the existing live Driver
with synthetic fixtures and a file-key vault; no production code or tracked test
harness changed. Source revision was `fe1bd1c`. The observer saved only tool name,
tool-use ID, permission mode and agent metadata. See
[structured results](mode-supplement-results.json) and
[interactive excerpts](mode-supplement-interactive.txt).

| Probe | Actual behavior and evidence |
| --- | --- |
| `default` exact-rule allow | `pwd` ran; guard recorded step 7 `allow`; actual hook input was the literal `default`. |
| `dontAsk` exact-rule allow | `pwd` ran without a denial; guard recorded step 7 `allow` and input `dontAsk`. This complements the earlier dontAsk marker denial. |
| `auto` deferred wrapper | No fixture rule allowed `date -u +%Y`. Guard recorded step 8 with a null decision and supplied the rewritten runner command. Host debug recorded that updated input; matching `tool_result_meta.permission_decision` reported `decision=accept`, `source=config`, `reason_type=classifier`. The command returned `2026`. This is actual classifier-attributed acceptance, not an inference from a successful command alone. |
| Interactive `auto` deferred wrapper | The same date command ran with no approval prompt; the UI showed `Allowed by auto mode`. Observer/guard records confirmed `auto`, step 8, null hook decision. |
| Interactive `plan` exact-rule allow | `pwd` matched a fixture allow rule, but the hook returned ask with its plan-mode explanation. The UI prompted; selecting No interrupted the call. The hook did not silently approve a read-only command in plan mode. |
| Interactive `auto` explicit ask rule | `git push --dry-run` matched the fixture ask rule and prompted with its rule explanation; selecting No interrupted it. The folder had no Git repository or remote, and the command was not executed. This verifies a nonmarker ask independently of marker restoration. |
| General-purpose child under `plan` | Parent Agent and child Read both received literal `plan`; the child was identified by its own agent ID and completed the allowed read. |
| General-purpose child under `dontAsk` | Parent Agent and child Read both received literal `dontAsk`; the child was identified by its own agent ID and completed the allowed read. Together with the earlier acceptEdits case, these are representative inherited modes, not every possible subagent configuration. |

Both PTY sessions were exited. The host's own `claude purge <generated-project>
--yes` removed only these fixtures' local host records, trust and prompt history.
Synthetic raw evidence remains in their temporary log directories. No credentials
were copied, no real vault was opened, and no user-owned project was modified.
The classifier result characterizes this safe command on this host version; it
does not promise how the classifier will judge arbitrary commands or future hosts.
