# Installed candidate verification

**Passed on macOS Apple Silicon, Claude Code 2.1.327, 18 November 2026.**
The production files tested match commit
`276b2b351389b48efe5b7a7a7f2c0a4977dc875f` byte for byte. See
[installed-readiness-results.json](installed-readiness-results.json) for production
file hashes, installation identity, exact case results and cleanup status.

The test used a unique temporary local-scope marketplace whose plugin source was
a Git URL pinned to a generated fixture commit. That Git repository contained an
unchanged snapshot of the candidate. The separate test catalog changed only the
marketplace name and source location. This exercises Claude's real clone/install
cache without publishing the candidate or modifying its public marketplace.

`python3 tests/live/run_installed_readiness.py` reproduces the workflow. It uses
the existing Claude login, loads only fixture project/local settings, and never
passes `--plugin-dir` or copies credentials. The file-key vault and plugin data
directory are temporary. A bounded PTY accepts only the generated workspace's
trust prompt, waits for DataFog's protected startup, then exits. No model request
is submitted in that PTY. The four model probes run afterwards.

## Observed results

- Installed version **0.2.1** into the real Claude plugin cache. Production engine,
  launcher, hook and MCP files in that cache matched the snapshot hashes.
- The plugin's private environment did not exist before first start. The actual
  installed SessionStart path bootstrapped it and reported `DataFog guard: on.`
- The host recorded trust for the exact generated canonical project path.
- Each model run's initialization record named the installed cache path; none
  loaded the source checkout or used the local-directory shortcut.
- **Read example:** returned markers for the synthetic fixture and no planted raw
  value in model-facing tool results.
- **Bash example:** allowed `cat notes.txt` ran through the cached runner and
  returned markers without planted raw values.
- **MCP edit example:** the installed MCP tool restored the exact synthetic email
  plus the requested suffix on disk, left no markers in the file, and returned no
  planted raw values to the model.
- **MCP project scope:** the actual installed tool was called on a synthetic
  sibling file outside the fixture project. It returned “Refused: the path is
  outside the project directory.” The sibling file stayed byte-for-byte unchanged.
- The unique local-scope install and marketplace were removed. A subsequent
  plugin inventory verified the test plugin ID was absent. Only the generated
  fixture's host transcript/trust record was purged; raw test logs remain in its
  temporary evidence directory.

## Why the source form matters

The initial local-folder installation passed the functional examples but did
**not** prove cached execution: Claude's installed metadata included
`readFromFolder`, and the MCP process loaded that folder. The harness caught this
by comparing the runtime initialization path with the installation cache path.
The final pinned Git URL run has no such override and passes that assertion.
This distinction is documented in the official
[marketplace guide](https://code.claude.com/docs/en/plugin-marketplaces#test-an-edit-to-a-plugin).

An intermediate test catalog used the unsupported source type `git` and was
rejected before plugin execution. The corrected documented source type is `url`.
That unique test catalog was also removed; this was a harness setup error, not a
candidate plugin failure.

## Boundaries

This closes cached installed startup, three runnable reviewer examples, and the
installed MCP project-boundary behavior for this host/platform. It does not prove
public directory acceptance, a network GitHub install from an unpublished
revision, Linux installed-host behavior, or first-start operating-system keychain
prompts. Those gates have separate evidence or remain explicit limitations.

The separate relocated-config probe observed that `CLAUDE_CONFIG_DIR` creates
`<config-root>/.claude.json`, but reached login before workspace trust. No
credentials were copied; relocated trust-field behavior remains unverified.
