"""Tool output shapes.

PostToolUse may replace a tool's output only with an object of exactly the
tool's own shape; anything else is silently ignored by Claude Code and the raw
output goes through. So a replacement is always built from the response that
arrived: same keys, same types, same order, with only content strings changed.

The shapes were recorded from Claude Code 2.1.299:

  Read      {type, file: {content, filePath, numLines, startLine, totalLines}}
  Grep      {content, filenames, mode, numFiles, numLines, totalLines}
  Glob      {filenames, numFiles, totalMatches, countIsComplete, truncated, durationMs}
  Bash      {stdout, stderr, interrupted, isImage, noOutputExpected}
  WebFetch  {result, url, code, codeText, bytes, durationMs}
  Write     {type, filePath, content, originalFile, structuredPatch, userModified}
  Agent     {content: [{type, text}], prompt, agentId, agentType, status, ...}
  MCP tool  [{type: "text", text}]

For each tool, KEEP lists the string fields that are identifiers, not content
(paths, modes, ids); they are passed through untouched. Every other string, at
any depth, is content. A tool that is not listed has every string treated as
content.
"""
from __future__ import annotations

WITHHELD = "[datafog: this output was withheld because it could not be checked for personal data]"

_IDENTITY = {"type"}
KEEP = {
    "Read": {"type", "filePath"},
    "Grep": {"mode", "filenames"},
    "Glob": {"filenames"},
    "Bash": set(),
    "WebFetch": {"url", "codeText"},
    "WebSearch": set(),
    "Write": {"type", "filePath"},
    "Edit": {"type", "filePath"},
    "NotebookEdit": {"type", "filePath", "notebook_path", "cell_id", "cell_type", "language", "edit_mode"},
    "Agent": {"type", "agentId", "agentType", "status", "resolvedModel", "harnessSectionHash", "service_tier",
              "speed", "inference_geo"},
}
KEEP["Task"] = KEEP["Agent"]
_BINARY_ITEM_TYPES = {"image", "audio"}


def _keep_for(tool: str) -> set:
    if tool.startswith("mcp__"):
        return _IDENTITY
    return KEEP.get(tool, set())


def _skip_whole(tool: str, response) -> bool:
    """Outputs that carry no text to check (binary payloads)."""
    if tool == "Read" and isinstance(response, dict) and response.get("type") not in (None, "text", "notebook"):
        return True
    return False


def _walk(node, keep: set, tool: str, leaves: list, key: str | None = None, parent=None):
    """Collect (container, key) for every content string, depth first."""
    if isinstance(node, dict):
        if node.get("type") in _BINARY_ITEM_TYPES and (tool.startswith("mcp__") or tool in ("Agent", "Task")):
            return
        if node.get("type") == "resource_link" and (tool.startswith("mcp__") or tool in ("Agent", "Task")):
            # A resource link has readable metadata, not a binary payload. Its URI is
            # an identifier (like a file path); names, titles and descriptions are content.
            for name, value in node.items():
                if name not in ("type", "uri", "mimeType"):
                    _walk(value, keep, tool, leaves, name, node)
            return
        if tool == "Bash" and node.get("isImage") is True:
            for name, value in node.items():
                if name != "stdout":
                    _walk(value, keep, tool, leaves, name, node)
            return
        for name, value in node.items():
            if name in keep:
                continue
            _walk(value, keep, tool, leaves, name, node)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, keep, tool, leaves, index, node)   # type: ignore[arg-type]
    elif isinstance(node, str) and parent is not None and node:
        leaves.append((parent, key))


def _copy(node):
    if isinstance(node, dict):
        return {name: _copy(value) for name, value in node.items()}
    if isinstance(node, list):
        return [_copy(value) for value in node]
    return node


def content_strings(tool: str, response):
    """Return (copy of response, leaves) where each leaf is (container, key) inside the copy."""
    if isinstance(response, str):
        holder = {"value": response}
        return holder, ([(holder, "value")] if response else []), True
    copy = _copy(response)
    leaves: list = []
    if not _skip_whole(tool, copy):
        _walk(copy, _keep_for(tool), tool, leaves)
    return copy, leaves, False


def transform(tool: str, response, tokenize_many):
    """Tokenize every content string. Returns (new response, counts, changed)."""
    copy, leaves, bare = content_strings(tool, response)
    if not leaves:
        return response, {}, False
    originals = [container[key] for container, key in leaves]
    replaced, counts = tokenize_many(originals)
    changed = False
    for (container, key), old, new in zip(leaves, originals, replaced):
        if new != old:
            container[key] = new
            changed = True
    return (copy["value"] if bare else copy), counts, changed


def withheld(tool: str, response):
    """The same shape with every content string replaced by a notice. Used when tokenizing failed."""
    copy, leaves, bare = content_strings(tool, response)
    for container, key in leaves:
        container[key] = WITHHELD
    return copy["value"] if bare else copy
