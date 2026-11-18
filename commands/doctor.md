---
description: Check that DataFog guard is installed and working, and say what to fix if not
---

Run exactly this command with the Bash tool, then show its output to the user unchanged, in a code block.

```
sh "${CLAUDE_PLUGIN_ROOT}/scripts/datafog-guard" --data-dir "${CLAUDE_PLUGIN_DATA}" doctor
```

If a line starts with `[FAIL]`, explain in one or two sentences what the user should do:

- "supported machine": the plugin cannot run on this computer (it needs macOS on Apple Silicon, or Linux on x86_64 with glibc 2.38 or later). The only remedy is to disable or uninstall the plugin.
- `keystore_unavailable`: the operating system's key store (macOS Keychain, or the Secret Service on Linux) is locked, not running or refused access. The user should unlock it or allow access. On a machine without a key store, the README describes the weaker `vault_key: file` setting.
- `vault_key_mismatch`, `vault_corrupt`, `vault_insecure`: say what the line says. Do not suggest deleting anything except through `/datafog:purge`, and say that purging makes existing markers unrestorable.
- "no unencrypted vault left over": an old development build left an unencrypted vault; `/datafog:purge` deletes it.

If the detector library or the vault library is missing, the fix is to run this in a terminal and then start a new session:

```
sh "${CLAUDE_PLUGIN_ROOT}/scripts/datafog-guard" --data-dir "${CLAUDE_PLUGIN_DATA}" bootstrap
```
