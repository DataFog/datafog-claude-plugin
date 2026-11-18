# Directory validation after release 0.2.1

Observed 2026-11-18 in the authenticated Claude directory portal. Release
[v0.2.1](https://github.com/DataFog/datafog-claude-plugin/releases/tag/v0.2.1)
was validated at commit `964fe1004bfd5c1188f46990a08d4f15e748c6ca`.
Result: **4 blocking findings, 12 warnings, 21 policy holds; 5 of 7 checks passed**.
This is validation, not submission acceptance, security-scan approval, or publication.

## Existing entry and migration

The [existing entry](https://claude.ai/directory/manage/plugins/b9ad3ff1-41bf-4162-9a1b-7feb8a4a6d36?tab=feedback)
remains Needs changes, with the October 5 decision on version 0.1.0 / `7a154b2`.
Its tracked source was saved as tag `v0.2.1`; Code-only listing and auto-publish off
were verified. No contact address is recorded in this public evidence.

Clicking Resubmit for review failed: the entry lacks a validation report, and the
portal requires withdrawal, repository validation, then recreation from that
report. This supersedes the earlier inference that no migration was needed.
Before withdrawing, the release was validated in the new submission form. Because
that validation exposed hard blockers, the old entry was preserved intact.
Nothing was withdrawn, recreated, accepted for review, or published in the directory.

The report is visible in the same browser tab at
[Source](https://claude.ai/directory/manage/new/plugin?step=source).
The portal says the form is kept in that tab until it closes. No standalone report
ID, download, or permanent report URL was exposed. The report's GitHub links point
to the exact commit above. Browser accessibility observations recorded the findings;
no screenshot containing unrelated account sidebar data was added to this repository.

## Blocking findings

| Code | Report location | Meaning and next action |
| --- | --- | --- |
| `COMMAND_PATH_COMPUTED` | `.` | The validator cannot follow a loader command's path. Its examples include non-root variables, command substitution, glob/brace patterns and inline programs. Expanded detail provides no exact command, line, or narrower field. Ask for the offending source before changing launch behavior. |
| `LOCAL_CODE_HOOK_COMMAND` | `hooks/hooks.json` | Command hooks are refused for this unverified organization. Removing them would remove the plugin's automatic interception. |
| `LOCAL_CODE_MCP_SERVER` | `.mcp.json`, `mcpServers.guard` | Local command-based MCP servers are refused for this unverified organization. A remote server would change the product's local processing design. |
| `LOCAL_CODE_FILE_TYPE` | `engine/datafog_guard/__init__.py` | Executable/restricted file types are refused for this unverified organization. The first identified file is Python source, not an unexplained binary. |

The three local-code findings explicitly say:

> Anthropic chooses who is a Verified organization, and there’s no way to ask to become one yet.

The portal offers no self-service organization verification control in these pages.
GitHub ownership authentication is not evidence of this directory status.

## All policy holds

| Code | Count | Reported locations or trigger |
| --- | ---: | --- |
| `HOOK_GRANTS_PERMISSION` | 1 | `hooks/hooks.json`, PreToolUse: can approve a call or change its input. Review the actual bounded permission behavior. |
| `UNREAD_ASSET_REFERENCED` | 4 | Icon path mentioned in `docs/directory-submission.md`, `tests/test_bash_permissions.py`, manifest reached from `scripts/verify-manifests.sh`, and directory-submission document reached from the test. |
| `MCP_FORWARDS_CREDENTIAL_ENV` | 7 | README; readiness doc; host-readiness doc; bash-permissions test; keystore test; late-swap test; aggregate manifest finding combining README with CI Python. The heuristic combines credential-like text with URLs or opaque text; this is not proof of transmission. |
| `COMMAND_SCRIPT_NOT_FOLLOWED` | 1 | `scripts/datafog-guard`: script requires manual path/behavior review. |
| `MCP_SCRIPT_NOT_READ` | 1 | `.mcp.json`, `mcpServers.guard.args`: `sh` launcher requires manual review. |
| `NAME_CONFUSABLE` | 5 | `name` and `author.name` resemble Datadog brand/connector; name also resembles Datadog's plugin. |
| `PUBLISHER_CONFUSABLE` | 2 | GitHub owner DataFog resembles Datadog brand/connector. |

Credential heuristic details: README combines a Claude docs URL with a Claude config
path; readiness combines a GitHub URL with that path; host-readiness flags the phrase
“pass individual”; the keystore test combines the Secret Service specification URL
with its isolated `secret-tool search`. The two larger test files contain patterns
too complex for the validator. These need source-backed reviewer explanations,
not claims that the scanner has established a leak.

## All warnings and informational groups

The 12 warnings comprise:

- Three `UNKNOWN_KEY` findings: `documentationUrl`, `privacyPolicyUrl`, `supportUrl`.
  Each expanded finding says the directory reads it and no action is needed.
- One icon field warning: directory-only metadata, also no action needed.
- Eight `RUNTIME_FETCH_EXEC` findings: README; `bashwrap.py`, `ccperms.py`,
  `filtercmd.py`, `plain.py`; `tests/live/fake_claude.py`; bash-permissions and
  late-swap tests. The report supplies file locations but no exact matching lines.
  Pattern detection in safety checks/tests must be distinguished from execution.

Informational groups: local stdio MCP does not run on claude.ai; the PNG passed
image validation; interpreter/file-extension mismatches (group count four, with
an aggregate noting five findings and three examples shown); server environment
names outside the directory list (group count four, showing project directory,
data directory and vault directory examples); and existing submission ownership.
These are currently notes, not refusals. The extension examples include
PostToolUse, PreToolUse and SessionStart command strings; do not adopt a new hook
schema without checking released Claude Code compatibility.

## Support route and unresolved review path

The existing entry's More actions > Contact Anthropic is an email link to
`directory@anthropic.com`, confirmed using the browser's Copy Email Address action.
No portal reply field was exposed. After explicit user authorization, an email was
sent to this official address on 2026-11-18 asking for the supported migration/review
path and the precise command-path location. No response or approval is yet recorded.
The old entry and validation form remain available for follow-up.

The official [publishing overview](https://claude.com/docs/directory/publish)
says Anthropic decides Verified designation during review, with no separate
application. [Connector verification](https://claude.com/docs/connectors/verification)
describes automatic escalation for connectors; that is not a self-service mechanism
for this plugin's submitting organization. The actual plugin report blocks entry
before review for local code. Ask the directory team which review/migration path is
supported, and request the precise `COMMAND_PATH_COMPUTED` location.

The [plugin checklist](https://claude.com/docs/plugins/pre-submission-checklist)
distinguishes blocking direct-command path problems from scripts requiring review.
Local `claude plugin validate` checks manifest structure, not these publisher policy
gates. Neither successful local validation nor a published GitHub release resolves
the directory's organization requirements.

## Continuation criteria

Keep release 0.2.1 immutable and preserve local processing. Resume migration only
when a supported publisher/review path is established and blocking validation is
resolved. Then validate the intended immutable release, migrate the old entry as
instructed, complete accurate listing/data handling, submit, and observe approval
before publishing. Existing settings remain Code-only and auto-publish off.
