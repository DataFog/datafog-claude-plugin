# 0.2.1 candidate validation

Production code baseline: `aa99659a0f3218c443a6fcbc17dbeb9e43537574`.
The subsequent `276b2b3` change makes a startup-import test portable across Python
versions; production files are identical. This report is preparation evidence, not
a directory approval or release announcement.

## Main real-Claude suite

On 2026-11-18, `LIVE_KEYCHAIN=1 DISABLE_AUTOUPDATER=1 bash tests/live/run-live.command`
completed on macOS Apple Silicon with Claude Code 2.1.327:

- 29 headless runs, 30 cases, 394 seconds; no cases skipped by caps.
- **187 PASS, 24 INFO, zero FAIL/FINDING.**
- Coverage includes Read shadows, successful/failing Bash, cwd persistence, exit traps,
  terminal control sequences, marker approval/late restoration, hostile synthetic value
  handling, deny/ask rules, untrusted-project rules, file-path denials, Grep, writes,
  marker-aware editing, prompts, file mentions, subagents and unavailable/corrupt engines.
- Optional Keychain case created one separate throwaway vault and key entry, restored
  the same marker across processes, then verified purge removed both vault and key entry.
  Fifteen full hook processes measured p50 71 ms and maximum 79 ms. Initial key creation
  took 0.1 seconds. No real user vault was used.

[Candidate live check results](candidate-live-results.json) preserves each check and
its status. Full synthetic logs remain locally at `.live/results/`; the source-result
hash is recorded in the JSON. Production files were confirmed unchanged since the
run began. The supplementary interactive, sandbox, lifecycle and installed-cache
reports cover paths outside this main headless suite.

## Local and platform suites

The initial network-enabled local pytest run finished with **2,568 passed, 43 skipped,
one failed** in 738.89 seconds. The failed optional standalone-dash fuzz case was
investigated rather than retried into a passing release claim:

- The receiver got an empty value in one three-stage pipeline. The isolated full
  case passed, but four repeated context batches reproduced an empty result with
  `Segmentation fault: 11` on stderr.
- Two corresponding macOS crash reports identify Apple's `/bin/dash` (`dash-16`,
  `com.apple.dash`, macOS 26.6.2) with EXC_BAD_ACCESS/SIGSEGV. This binary is not
  selected by the plugin: it selects bash/zsh, then literal `/bin/sh` as fallback.
- Tests now exercise that actual `/bin/sh` fallback. On this Mac it is Apple bash
  3.2.57; on Linux CI it is dash. The full hostile randomized corpus passed with
  identical exact-byte, no-side-effect and exit-status assertions. No retries,
  expected failures or relaxed assertions were added. The complete fallback subset
  then passed: **27 passed, 1,128 deselected in 80.68 seconds**. The initial failed
  full run remains recorded as failed; this is scoped replacement evidence for the
  incorrectly selected shell, not a claim that the original run passed.

Linux 3.10 CI finished with **2,608 passed, 3 skipped, one failed**. Its only failure
was the new test's private keyring recovery: the unlock command returned without
unlocking the original private collection. The corrected fixture uses a private control socket and the GNOME existing-daemon
unlock protocol. All six private keyring tests passed in an isolated Ubuntu 24.04
container, including locked-state refusal, no rekey or file-key fallback, and recovery
of the original marker. See [Linux keyring evidence](linux-keyring.md).

The revised four-way platform matrix must pass before submission. Final fixture
and evidence commit `fe1bd1c` is being tested by
[run 44368890375](https://github.com/DataFog/datafog-claude-plugin/actions/runs/44368890375).
Its strict manifest job passed; platform tests remain pending. Local lint and mypy
pass on 21 engine modules. The previous run for `276b2b3` was cancelled after its
Linux fixture failure once the corrected candidate run started; it is not green evidence.

An earlier local full-suite attempt was intentionally interrupted when the failed
dependency-upgrade gap was found. It is not release evidence. The earlier GitHub
run for `aa99659` was cancelled after the cross-Python test correction; the new run
must supply platform evidence, including the added private locked-keyring case.

## Distribution and remaining scope

[Installed candidate verification](2026-11-18-installed-candidate.md) confirms real
cached startup and reviewer examples. [Upgrade checks](marketplace-install.md) confirm
marker preservation and retention, with cache hashes checked against the candidate.
Public release URLs, the portal's final scan/review, and directory publication remain
gated on the owner's instruction. Environment-specific limitations are retained in
the [readiness inventory](../readiness.md); green tests do not erase those limits.
