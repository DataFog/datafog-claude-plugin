---
description: Delete the DataFog vault after an explicit confirmation (markers can then never be restored)
disable-model-invocation: true
---

The user wants to delete the DataFog vault. This cannot be undone. Follow these steps in order and do not skip the confirmation.

1. Run this with the Bash tool and show its output to the user unchanged. It deletes nothing.

```
sh "${CLAUDE_PLUGIN_ROOT}/scripts/datafog-guard" --data-dir "${CLAUDE_PLUGIN_DATA}" purge
```

2. Tell the user plainly: the vault is the only thing that can turn markers such as `[[EMAIL_ABC123]]` back into real values. After deletion, any file, note or transcript that still contains markers can never be restored. Files that already contain the real values are not affected.

3. Ask the user to reply with the exact words `delete the vault`. Stop and wait for their reply. Anything else means cancel.

4. Only after the user replied with exactly those words, run:

```
sh "${CLAUDE_PLUGIN_ROOT}/scripts/datafog-guard" --data-dir "${CLAUDE_PLUGIN_DATA}" purge --confirm DELETE-VAULT
```

Show the output unchanged.
