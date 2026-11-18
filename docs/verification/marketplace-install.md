# Cached marketplace installation check

Observed 2026-11-18 on macOS Apple Silicon. This checks the currently published
**v0.2.0**, not the uncommitted directory-readiness candidate. Repeat against the final
release before closing D08. Claude Code auto-updated during the broader audit, so this
check must not be used to establish minimum-version compatibility.

An isolated `CLAUDE_CONFIG_DIR` and throwaway project were used. The vault override
pointed at a temporary directory and used explicit file-key mode. No real user vault,
plugin installation or key-store entry was used. Local raw evidence is under
`/var/folders/kt/xxfb4y954tbfw5mpmgm4ybq00000gn/T/datafog-install-audit-_n8jeu21`.

| Check | Result |
| --- | --- |
| `claude plugin install datafog --marketplace DataFog/datafog-claude-plugin --json` | Exit 0; installed `datafog@datafog` into isolated cache at version 0.2.0. Three unset options reported; defaults available. |
| Invoke cached launcher `session-start` with a SessionStart hook payload | Exit 0; private environment bootstrapped and status reported guard on, temporary file-key vault, Bash filtering, marker restoration ask. |
| Invoke cached launcher `mcp` over JSON-RPC | Initialize, tools/list and protection_status each returned a result; process exited 0. |
| `claude plugin update datafog@datafog --json` | Exit 0; correctly reported already at 0.2.0. This is not evidence of a version-changing upgrade. |
| `claude plugin uninstall datafog@datafog --json` | Exit 0; plugin data directory removed, separately configured temporary vault retained. |

Limitations: hook and MCP launch were exercised directly from the cached installation,
not through a model session. This verifies packaged paths and cold bootstrap but does
not prove host MCP environment interpolation or first-session startup ordering. The
retention result applies to an explicit external vault override; default OS-vault and
plugin-data-vault retention need separate checks. A version-changing upgrade and the
final candidate's cache remain open gates.

## Local candidate upgrade and retention

A subsequent isolated local Git marketplace used a baseline 0.2.0 snapshot and then
the 0.2.1 workspace snapshot. The CLI installed 0.2.0, refreshed the marketplace and
reported a successful **0.2.0 → 0.2.1** update. Cached SessionStart and Read hooks ran
after both versions. The same synthetic address retained exactly the same marker across
the upgrade, and the new private environment stamp contained both exact 1.7.0 pins.
Uninstall removed plugin data while preserving the explicitly external temporary vault.

A second candidate install configured `keep_vault_on_uninstall=false`. The cached
SessionStart hook received that option, created a file-key vault inside plugin data,
and CLI uninstall removed both data and vault. This does not test OS key-store cleanup:
the README correctly states that uninstall leaves a key-store entry unless purged first.

Both checks passed. Local evidence directory:
`/var/folders/kt/xxfb4y954tbfw5mpmgm4ybq00000gn/T/datafog-upgrade-audit-axnii59g`.
These remain direct cached-hook checks, not model sessions, and precede the later runtime
version-enforcement fix. Final-release host startup and updated-candidate certification
are still required.
