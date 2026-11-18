# Release verification and public-page follow-through

Evidence checked 2026-11-18. This plan does not claim the current working tree has passed CI, and makes no website or directory publication.

## Strict manifest verification

Run `sh scripts/verify-manifests.sh`. It validates the plugin and marketplace manifests separately with `--strict`, in a temporary Claude configuration directory. It needs no model credentials and does not install the plugin or execute hooks. `CLAUDE_BIN` can select a particular Claude executable. Local run passed with Claude Code 2.1.327.

The added `manifests` CI job installs `@anthropic-ai/claude-code@2.1.327` through npm on Ubuntu 24.04 / Node 22, then runs the same script. The exact version exists in the publisher's npm registry; observed package integrity is `sha512-QToNtikIupqVMsxRUdDHUP0nS/uv3Wc43vcbT8YNRo7FtQOE9MvYLqPLQPoVhJ2DQQVPOFMB5PkaBNJbnNYeVg==`. This is development verification tooling, not a runtime plugin dependency. The publisher documents npm installation in its [Claude Code repository](https://github.com/anthropics/claude-code).

## Runtime dependency provenance

The rejected directory submission required exact package versions. Both runtime packages are now fixed to 1.7.0. Installed wheel metadata and the public PyPI release JSON agree:

- `datafog-fogvault==1.7.0` has no `Requires-Dist` dependencies.
- `datafog-core==1.7.0` has only dependencies conditional on the optional `gliner2` extra. The plugin requests no extras, so none of them resolve or install.
- Therefore the normal plugin runtime currently has two Python distributions and no transitive Python dependency tree to pin. This does not mean the compiled libraries contain no third-party Rust/native code; the pinned wheel captures that compiled artifact.
- Python, uv/pip, OS libraries and the system key store remain environmental dependencies. Pinning package versions alone is not a fully hermetic build.

Sources: [core release metadata](https://pypi.org/pypi/datafog-core/1.7.0/json), [vault release metadata](https://pypi.org/pypi/datafog-fogvault/1.7.0/json). Registry source overrides remain possible through the user's package-manager environment; this should be disclosed and evaluated separately from exact version selection.

Selected platform wheel SHA-256 values recorded for provenance (bootstrap does not yet enforce these hashes):

| Distribution | Supported platform wheel | SHA-256 |
| --- | --- | --- |
| core 1.7.0 | cp310-abi3 macosx_11_0_arm64 | `ba8c3fc0817fecc7cb153dea7b219dc4bcff10696195c063d88917621f31a8fc` |
| core 1.7.0 | cp310-abi3 manylinux_2_28_x86_64 | `bae450c6360f9e942d72fedfa6645a9be92deafae276a2ba3ab0aa84027caa15` |
| fogvault 1.7.0 | cp310-abi3 macosx_11_0_arm64 | `a945828c4875d4dafe61ede042df12dcbca2858788369e6238d01884929f3c91` |
| fogvault 1.7.0 | cp310-abi3 manylinux_2_38_x86_64 | `5daffe08633bbdc04de6a35a4a25acd702cbb8a9ed5afd3657d2b100fbdc8892` |

The directory checklist describes registry dependency execution as potentially requiring reviewer inspection; it does not make a lockfile proof of approval. The actual prior reviewer request and final portal result remain authoritative for this submission. See [submission preparation](directory-submission.md).

## Linux CI execution plan

Read-only GitHub checks confirmed repository admin/push permission for the current account, Actions enabled with all actions allowed, and no self-hosted runners. Repository secret listing returned no secrets. No credential values were read or uploaded. The existing four-way test matrix uses GitHub-hosted Linux/macOS runners and needs no Claude model credentials.

1. Finish and review the candidate, then commit the exact intended tree to `directory-readiness`.
2. Push that branch and create a PR; the existing `pull_request` trigger runs the four test jobs plus the new strict-manifest job. A branch push alone does not trigger this workflow, because its push filter only covers `main` and `rebuild/**`.
3. Verify the run's `headSha` matches the candidate; inspect every job, including Linux private Secret Service coverage and network bootstrap. Do not use the existing green run for `3c41b49` as evidence for new code.
4. Download or inspect logs on failure, fix and rerun only the changed candidate as appropriate. Record run URL and exact versions in release evidence.
5. An authenticated real Claude Linux session is a separate gate: there is no existing repo secret for it. Do not copy a developer's credential into CI. Use an explicitly authorized Linux Claude session or report that gate as unverified; pytest/manifest success does not prove live interactive Linux behavior.

`workflow_dispatch` was added for future deliberate reruns once the workflow is available on the default branch. No run was dispatched and no branch was pushed by this workstream.

## Public homepage audit and proposed copy

The live [DataFog homepage](https://datafog.ai/) was inspected on 2026-11-18. Its Claude Code card still says “In development · 0.2.0-dev” and redirects people seeking a released workflow to DataFog MCP. The repository already has v0.2.0 published. This is stale distribution copy; it does not imply that the public directory listing is live.

Draft card change, to apply only after the final release decision:

- Badge: **Claude Code plugin · v[final release version]**.
- Heading: **DataFog for Claude Code**.
- Body: **Replace detected personal data and selected credentials with reversible markers in files and tool output. Detection and the encrypted vault stay local. Supported on Apple Silicon macOS and selected Linux x86_64 systems; see coverage and platform limits.**
- Primary link: **Install from GitHub** → `https://github.com/DataFog/datafog-claude-plugin#install`.
- Secondary link: **Coverage and limitations** → `https://github.com/DataFog/datafog-claude-plugin#known-gaps`.
- After a verified public listing exists, add **Open in Claude directory** using its observed public URL. Do not invent the URL or announce directory availability early.

Keep the existing DataFog MCP card separate: it is a different product and release track. Do not imply that Claude chat or Cowork receives this plugin's protection. Also update any matching homepage structured metadata/release snapshot when changing the card. No homepage source file was edited or deployed here.
