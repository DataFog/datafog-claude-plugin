---
description: Check that DataFog guard is installed and working, and say what to fix if not
---

Run exactly this command with the Bash tool, then show its output to the user unchanged, in a code block.

```
sh "${CLAUDE_PLUGIN_ROOT}/scripts/datafog-guard" --data-dir "${CLAUDE_PLUGIN_DATA}" doctor
```

If a line starts with `[FAIL]`, explain in one or two sentences what the user should do. If the detector library is missing, the fix is to run this in a terminal and then start a new session:

```
sh "${CLAUDE_PLUGIN_ROOT}/scripts/datafog-guard" --data-dir "${CLAUDE_PLUGIN_DATA}" bootstrap
```
