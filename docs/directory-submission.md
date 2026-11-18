# Public directory submission preparation

Audit date: 2026-11-18. Candidate baseline: `3c41b49` / v0.2.0; subsequent workspace changes require fresh verification. No directory submission or publication was performed by this audit. Publish only after Sid gives the word.

## Route and old submission

Submit the repository root of `DataFog/datafog-claude-plugin` as a **Plugin bundle** at <https://claude.ai/directory/manage>. This plugin has a local stdio MCP server, not a remote connector.

The existing submission is already in the current portal: [DataFog review](https://claude.ai/directory/manage/plugins/b9ad3ff1-41bf-4162-9a1b-7feb8a4a6d36?tab=feedback), ID `b9ad3ff1-41bf-4162-9a1b-7feb8a4a6d36`. Read-only inspection on 2026-11-18 found submission date July 2, status **Needs changes**, and an October 5 reviewer rejection of v0.1.0 / `7a154b2`. The reviewer required exact dependency versions, explaining: “That code can change after review.” The page offers **Resubmit for review** and is no longer scanning commits. Resume this submission; migration or a duplicate submission is unnecessary.

The September 23 check also reported warnings for publisher-name similarity, missing icon, a README download-and-run command, and hook usage. These are historical findings against the old commit, not results for today's candidate.

Settings inspection found default-branch tracking, a populated private contact address, automatic publication enabled, and all three app surfaces selected. Authorized readiness changes were saved and verified: automatic publication **off**, **Claude Code only** (Cowork and Claude apps unchecked). No resubmission or publication occurred. The contact address matches the user's authenticated Gmail profile, confirming mailbox access; no portal verification badge or test delivery was observed. The collection/transmission switch remains off: its helper specifically addresses remote MCP servers/HTTP hooks; final form answers must distinguish local sensitive-data storage from publisher collection.
Keep auto-publish off. Select a release tag containing the reviewed commit, record its SHA, and run portal validation against that exact revision. Local CLI success is not portal approval. Submission, security scanning, reviewer approval and publication are separate states; passing checks does not itself publish a version. Record each result and the public listing URL after publication. [Submission lifecycle](https://claude.com/docs/plugins/submit).

## Repository evidence

- Repository is public (verified with `gh repo view`).
- Initial Claude Code 2.1.299 strict validation passed separately for `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`. Validating `.` initially reported only the marketplace manifest, so both explicit checks are retained. Final local CLI reported 2.1.327 and strict plugin validation additionally ran a directory subset with no findings; safety scan and policy review remain portal-only.
- Baseline tracked tree: 62 regular files, 802,853 bytes total; largest file 77,973 bytes. No tracked symlinks or submodules. README and Apache-2.0 LICENSE exist.
- Plugin files live at the repository root; hook/MCP entry points reference `${CLAUDE_PLUGIN_ROOT}`.
- Three slash commands, four hook events, two local MCP tools, Python engine, shell launcher and bootstrap are bundled.
- Exact-pin validation: 24 CLI/plugin tests passed with one network test skipped; that network bootstrap case then passed separately with `DATAFOG_TEST_NETWORK=1`. Ruff and `git diff --check` passed.
- Bootstrap now pins `datafog-core==1.7.0` and `datafog-fogvault==1.7.0`, matching engine constants, pyproject, CI and documented install commands. This directly addresses the prior reviewer request; final portal confirmation remains necessary.
- CI parses JSON and runs shell parsing, Ruff, mypy and pytest on macOS/Linux with Python 3.10/3.12. A new isolated strict-manifest job uses Claude Code 2.1.327; local execution and the final candidate CI manifest job passed; the four platform test jobs remain pending. See [verification and homepage plan](release-verification-plan.md).

## Directory-specific remaining gates

| ID | Remaining work | Completion evidence |
| --- | --- | --- |
| D01 | Existing submission found; resume it rather than migrate or duplicate. Reconfirm push access at resubmission. | Portal ID/status recorded above; no migration needed. |
| D02 | PRIVACY.md and manifest link added locally; publish with reviewed release. | Public policy URL must resolve after push and match final behavior. |
| D03 | Support URL added; SECURITY.md and private GitHub vulnerability reporting enabled. Portal contact matches authenticated Gmail profile. | Mailbox access confirmed; final public-doc URLs await merge. No test email was sent or portal badge claimed. |
| D04 | Provide three runnable synthetic reviewer examples. | All three passed in real cached candidate sessions with source hashes and disk-state assertions; see verification/2026-11-18-installed-candidate.md. |
| D05 | MCP annotations added by implementation workstream. | Focused MCP tests pass; final integrated suite still required. |
| D06 | Narrow all listing claims to detected values and disclosed limits. | Manifest, marketplace, README and GitHub About now describe detected values. Homepage release-copy update is drafted for publication; directory availability is not announced. |
| D07 | Portal now restricted to Claude Code; keep unsupported app claims out of listing. | Settings saved and verified Code on, Cowork/apps off. |
| D08 | Run a clean cached marketplace install, upgrade and uninstall scenario. | Cached candidate startup passed; fresh 0.2.0→0.2.1 upgrade preserved markers and uninstall retention passed. Final public release URL verification remains open; see verification/marketplace-install.md. |
| D09 | Establish dependency provenance/reproducibility and bootstrap failure coverage. | Exact resolved distributions, source/index behavior and network needs recorded; cold install succeeds on both supported platforms. |
| D10 | Assess permission/sandbox integration against directory policy. | Interactive verification report and reviewer explanation for wrapper behavior; no claim of sandbox compatibility without testing. |
| D11 | Portal validation of final pushed release; address every blocking result. | Saved finding report tied to SHA, including any reviewer holds and responses. |
| D12 | Refresh release version and final CI/live evidence after fixes. | Tag/SHA, green checks and release evidence all describe the same candidate. |
| D13 | Submit after readiness gates; track review; publish only on Sid's explicit authorization. | Recorded submission/review status and, finally, reachable public listing. |

D02–D05 reflect policy requirements for privacy, contact/support, sample use cases and MCP metadata. Review also needs to address the policy's restrictions on sensitive context access and interference with other tools: DataFog deliberately scans user-requested operations and blocks some calls as its advertised function. Explain that scope explicitly; do not represent local testing as a compliance ruling. No DataFog cloud account exists for this plugin, so provide synthetic fixtures and installation instructions instead of inventing test credentials. [Directory policy](https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy).

## Portal scanner preflight

Check the final archive for valid portable names, ordinary files, contained paths, supported readable file types, no OS junk or rewriting Git attributes, and size/count limits (50 MiB archive, 256 MiB unpacked, fewer than 10,000 entries; individual files under 5 MiB). Reviewer thresholds include 512 files and 256 KiB non-image/font files. Verify unique name, manifest, README, license, component schemas, front matter and absence of real credentials. Launchers require exact package pins; registry overrides and opaque execution can block or hold review. [Official checklist](https://claude.com/docs/plugins/pre-submission-checklist).

Local archive preflight for `fe1bd1c848880fc4c3c6015c136d5fd9ff28c1e0` used
`git archive --format=tar HEAD`: 1,075,200 archive bytes, 98 entries (84 files),
996,706 unpacked file bytes; largest file 77,973 bytes. No absolute/parent-traversal
or backslash paths, special entries, OS junk, or files at least 5 MiB were found.
This checks those packaging limits only; it does not certify credential absence,
policy compliance or the portal's scan. Repeat against the final release revision.

**Expected holds, not confirmed portal findings:** the MCP command uses `sh`; its launcher invokes another shell file and Python; bootstrap installs registry packages. The launcher derives its root using `dirname/..`, which could trigger a containment finding even though the computed root is inside the plugin. Do not redesign working bootstrapping merely to suppress an inferred hold: run the portal validator and resolve its actual result. Prepare a readable entry-point/dependency explanation for reviewers.

Hooks are ignored in chat; local MCP servers also do not run there. Cowork supports hooks/local servers in supported sessions, but DataFog's OS assumptions, environment variables and permission semantics have only been targeted at Claude Code. The portal derives supported surfaces from components. This creates a concrete listing/compatibility risk to resolve, not evidence that Cowork works. [App support matrix](https://claude.com/docs/plugins/platform-support).

## Brand asset

Bundled `assets/datafog-icon-512.png` is the 512×512 PNG linked by the official DataFog homepage, downloaded from `https://datafog.ai/datafog-icon-512.png` on 2026-11-18. The manifest now references it, addressing the old missing-icon warning. No new branding was invented.

## Draft listing

**Name:** DataFog (`datafog`).

**Short description:** Locally replaces detected personal data and selected credentials with reversible markers in Claude Code files and tool output. Uses an encrypted local vault. Requires a supported Mac or Linux machine; coverage and failure-mode limits apply.

**Source:** `https://github.com/DataFog/datafog-claude-plugin`; plugin path: repository root; branch/tag: final verified release tag, not selected yet.

**Documentation:** `https://github.com/DataFog/datafog-claude-plugin#readme`.

**Support:** `https://github.com/DataFog/datafog-claude-plugin/issues`; do not put personal data or credentials in public issues. Private security reports: `https://github.com/DataFog/datafog-claude-plugin/security/advisories/new` (enabled and verified by the root workstream). Portal contact matches the authenticated Gmail profile, confirming mailbox access; no portal verification badge or test delivery is claimed.

**Privacy policy:** `https://github.com/DataFog/datafog-claude-plugin/blob/main/PRIVACY.md` (authored locally; URL becomes live after push). **License:** Apache-2.0.

**Supported environment:** Claude Code 2.1.295+, macOS 11+ Apple Silicon, Linux x86_64 glibc 2.38+ with usable Secret Service or explicit weaker file-key mode. Reconfirm minimum version with final tests. Do not advertise protection in chat, Cowork, Windows, Intel macOS or unsupported Linux.

**Reviewer caveats:** selected structured entity detection only; no general name detector; ordinary unlabeled addresses and many secret formats are missed. Post-tool hard failures can expose raw results. Built-in file-tool restoration may enter local Claude records. This is accidental-exposure reduction, not a boundary against malicious agents or same-user programs.

## Draft data-handling answers

These describe repository behavior, not final legal acknowledgements.

- **Reads personal data:** yes. It scans prompts, requested text files and tool output locally to detect configured entity types; marker-aware writes restore saved values locally.
- **Stores personal data:** yes. Detected original values persist in the encrypted vault so markers can be restored. The default key is in macOS Keychain/Linux Secret Service. Explicit file-key mode stores the key beside the vault and weakens protection.
- **Retention:** the vault persists until explicit purge; the default retains it across uninstall. Configuring plugin-data storage changes uninstall behavior. Purge deletes the vault and its key; it cannot erase restored data in project files or Claude-managed records.
- **Other local records:** marker index, encrypted vault metadata, restore-ticket key, tokenized shadow files, diagnostic counts/logs and the private Python environment. Inventory and exact retention must be reconciled against the final privacy document.
- **Data sent elsewhere:** DataFog detection/storage has no hosted service. Bootstrap downloads dependencies; user-requested shell commands and tools may communicate externally. Third-party MCP restoration is disabled by default and can expose restored inputs when enabled. Claude itself processes the filtered context; do not claim that all user data can never leave the machine.
- **Under-18 audience:** intended for developers, not specifically designed for minors; final portal answer must reflect publisher intent rather than an invented age restriction.

## Reviewer examples to verify

Use only a throwaway project/vault and the committed synthetic fixtures.

1. Ask Claude to read `tests/live/fixtures/customers.csv` and report the rows without guessing marker values. Confirm recognized sensitive fields become markers while row structure remains usable.
2. Ask Claude to print `tests/live/fixtures/config.env` through Bash. Confirm supported detected credential formats are replaced in successful and failing output; record expected undetected formats rather than implying complete secret coverage.
3. Ask Claude to use `edit_with_markers` to change a non-sensitive field on a row identified by a marker. Confirm the real original value remains on disk and the tool result contains only line numbers/counts.

Release evidence should attach concrete prompts, observed outputs and assertions for these examples, plus interactive permission and cancellation results tracked by the verification workstream.

## Prepared response to the earlier review

Use only after the final candidate and public URLs are verified; this text has not
been sent or entered as a submission:

> Version 0.2.1 pins the two runtime distributions to datafog-core==1.7.0 and
> datafog-fogvault==1.7.0. No optional extras or transitive Python distributions are
> installed. Bootstrap verifies installed versions even when its stamp already exists;
> runtime loading and doctor also validate the reviewed versions. A failed upgrade
> cannot silently launch an older environment. The repository includes privacy and
> security-reporting documentation, an official icon, and three synthetic reviewer
> examples exercised from an installed plugin cache. Support is limited to Claude
> Code on the documented macOS/Linux platforms. Please review the final release
> revision and its attached validation evidence; the coverage limits are explicit.

Before sending, replace any version/revision references if the candidate changes,
attach the observed release URL and final CI/live report, and retain automatic
publication off. No reviewer acceptance is implied by this draft.
