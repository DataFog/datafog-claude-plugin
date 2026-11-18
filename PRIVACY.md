# Privacy and local data handling

DataFog for Claude Code processes text locally to replace detected personal data and
selected credentials with reversible markers. This notice describes the plugin, not
Anthropic's services, your shell commands, or other installed tools.

## What the plugin processes and stores

The hooks examine supported file content, tool inputs/results and submitted prompts.
Detected values are stored in an encrypted local ApplicationVault so markers can be
restored. Processes temporarily hold decrypted values in memory. The encryption key is
stored in macOS Keychain or Linux Secret Service by default. Explicit `vault_key: file`
mode stores the key beside the vault and provides weaker protection.

The vault is shared across projects. By default it lives at
`~/Library/Application Support/DataFog/vaults/claude-code` on macOS or
`${XDG_DATA_HOME:-~/.local/share}/datafog/vaults/claude-code` on Linux. Configuration can
change this location. The marker index, vault metadata and Bash restore-ticket signing
key are not encrypted. They do not contain the original value mapping.

The plugin data directory also contains its Python environment, settings, tokenized
shadow copies and diagnostic logs. Configuration can contain user-entered allowlist
values in plaintext. Diagnostic event entries contain events, tool names,
entity types, counts and error codes, rather than prompt/file content or detected values.
The event log rotates after approximately 2 MB, keeping a previous log. The separate
bootstrap log appends installer output, which can include paths and error details;
it has no automatic rotation. Shadow copies retain
content that was not detected, so they must not be treated as fully anonymized files.
Session startup attempts to remove shadow copies not refreshed for a week; this is
best-effort cleanup, not a guaranteed deletion deadline.

## Network activity and other software

The plugin does not send scanned text or vault values to a DataFog service and has no
plugin analytics endpoint. Initial installation downloads dependencies through `uv`
or `pip`; package infrastructure receives ordinary download requests. GitHub supplies
the plugin source. Detection and vault operations run locally after installation.

Claude Code communicates with its model provider. Its own settings govern transcripts,
prompt history, telemetry and retention. DataFog cannot guarantee that all personal data
is removed: unknown formats, unscanned content and post-tool hook failures can expose it.
Built-in Write/Edit/NotebookEdit and Grep/Glob inputs can contain restored values in
Claude Code's local records. Commands can transmit data, and explicit
`restore_in_mcp_input: true` can pass restored values to third-party MCP tools.

## Retention and deletion

By default the vault and its key survive plugin uninstall so markers in your files remain
recoverable. `/datafog:purge` requests confirmation; a successful purge deletes the vault,
its key and shadow copies. Partial deletion failures are reported and may require manual
cleanup. Purging permanently removes marker recovery; it does not erase values
already written to your files, external services, Claude records or backups. Diagnostic
logs and configuration are separate from the vault. The README explains the alternative
plugin-data storage option and its uninstall consequences.

## Limits and support

Encryption at rest does not prevent software running as your logged-in account from
accessing values. DataFog reduces accidental exposure; it is not a sandbox or a complete
secret scanner. See the README's coverage table, known gaps and configuration defaults.

For non-sensitive questions, use the
[repository issue tracker](https://github.com/DataFog/datafog-claude-plugin/issues).
Do not include real credentials, personal data, vault files or unredacted transcripts.
For a vulnerability, follow [private security reporting](SECURITY.md).
