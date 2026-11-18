"""The plugin's MCP server (stdio, newline-delimited JSON-RPC 2.0, standard library only).

Tools:

edit_with_markers(file_path, old_string, new_string, replace_all=false)
    The built-in Edit tool cannot match a line that holds a marker, because the file on
    disk holds the real value. This tool restores the markers in both strings, applies
    the edit to the real file with Edit's uniqueness rule, and reports line numbers and
    counts only.

protection_status()
    Entity types and counts.

No tool returns file content, a real value, or the marker-to-value mapping. The server is
long-lived, so the vault is reopened whenever another process moved its head.
"""
from __future__ import annotations

import json
import os
import stat
import sys

from . import __version__, config, files, log
from .errors import GuardError, safe_code

TOOLS = [
    {
        "name": "edit_with_markers",
        "description": (
            "Edit a file when old_string or new_string contains DataFog markers such as [[EMAIL_ABC123]]. "
            "Works like the built-in Edit tool: old_string must match the file exactly once unless "
            "replace_all is true. Markers are swapped for the real values locally before matching and "
            "writing. Returns line numbers and counts only, never file content."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute path of the file to edit"},
                "old_string": {"type": "string", "description": "Text to replace; may contain markers"},
                "new_string": {"type": "string", "description": "Replacement text; may contain markers"},
                "replace_all": {"type": "boolean", "default": False,
                                "description": "Replace every occurrence instead of requiring exactly one"},
            },
            "required": ["file_path", "old_string", "new_string"],
        },
    },
    {
        "name": "protection_status",
        "description": "Show what DataFog guard protects in this session: entity types and counts only.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class ToolError(Exception):
    pass


class Server:
    def __init__(self):
        self._vault = None
        self._vault_key = None

    def session(self):
        from .engine import open_vault
        settings = config.load()
        key = (settings.vault_dir, settings.entities, settings.allowlist, settings.recall_required)
        if self._vault is None or key != self._vault_key:
            self._vault, _ = open_vault(settings)
            self._vault_key = key
        return self._vault, settings

    @staticmethod
    def project_dir() -> str:
        value = os.environ.get("CLAUDE_PROJECT_DIR", "")
        if not value or value.startswith("${"):
            value = os.getcwd()
        return value

    # -- tools -----------------------------------------------------------
    def edit_with_markers(self, arguments: dict) -> str:
        path = arguments.get("file_path")
        old = arguments.get("old_string")
        new = arguments.get("new_string")
        replace_all = arguments.get("replace_all", False) is True
        if not isinstance(path, str) or not isinstance(old, str) or not isinstance(new, str):
            raise ToolError("file_path, old_string and new_string must be strings.")
        vault, settings = self.session()
        path = files.original_of(settings.shadow_dir, path) or path
        if not os.path.isabs(path):
            path = os.path.join(self.project_dir(), path)
        if files.is_inside(path, settings.vault_dir) or files.is_inside(path, settings.data_dir):
            raise ToolError("Refused: the path is inside DataFog's own storage.")
        if not files.is_inside(path, self.project_dir()):
            raise ToolError("Refused: the path is outside the project directory.")
        if not old:
            raise ToolError("old_string is empty. Use the Write tool to create a file.")
        try:
            info = os.stat(path)
        except OSError:
            raise ToolError("The file does not exist.") from None
        if not stat.S_ISREG(info.st_mode):
            raise ToolError("The path is not a regular file.")
        if info.st_size > settings.max_scan_bytes:
            raise ToolError("The file is too large to edit with this tool.")

        vault.health()
        old_real = vault.restore(old)
        new_real = vault.restore(new)
        if old_real.text == new_real.text:
            raise ToolError("old_string and new_string are the same; nothing to change.")
        with open(path, "rb") as handle:
            raw = handle.read()
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ToolError("The file is not UTF-8 text.") from None
        count = content.count(old_real.text)
        if count == 0:
            hint = ""
            if old_real.unknown:
                hint = f" {old_real.unknown} marker(s) in old_string are not known to the vault."
            raise ToolError("old_string was not found in the file." + hint)
        if count > 1 and not replace_all:
            raise ToolError(f"old_string matches {count} places in the file. Add surrounding text to make it "
                            "unique, or set replace_all to true.")
        lines, position = [], 0
        for _ in range(count if replace_all else 1):
            position = content.index(old_real.text, position)
            lines.append(content.count("\n", 0, position) + 1)
            position += len(old_real.text)
        updated = content.replace(old_real.text, new_real.text) if replace_all \
            else content.replace(old_real.text, new_real.text, 1)
        self._write(path, updated.encode("utf-8"), info.st_mode)

        restored = old_real.restored + new_real.restored
        unknown = old_real.unknown + new_real.unknown
        log.write(settings.log_path, event="McpEdit", replacements=len(lines), restored=dict(restored),
                  unknown_markers=unknown)
        summary = (f"Edited {arguments.get('file_path')}: {len(lines)} replacement(s) at line(s) "
                   f"{', '.join(map(str, lines[:50]))}{' ...' if len(lines) > 50 else ''}. "
                   f"Markers swapped for real values: {log.describe_counts(restored)}.")
        if unknown:
            summary += f" {unknown} marker-like string(s) were not known to the vault and were used as written."
        return summary

    @staticmethod
    def _write(path: str, data: bytes, mode: int) -> None:
        """Replace the file in one step, keeping its permission bits."""
        directory = os.path.dirname(path)
        temp = os.path.join(directory, f".{os.path.basename(path)}.datafog-{os.getpid()}.tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IMODE(mode))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp, stat.S_IMODE(mode))
            os.replace(temp, path)
        except BaseException:
            try:
                os.unlink(temp)
            except OSError:
                pass
            raise

    def protection_status(self, arguments: dict) -> str:
        from .cli import status_report
        return status_report(for_model=True)

    # -- protocol --------------------------------------------------------
    def call_tool(self, params: dict) -> dict:
        name = params.get("name")
        raw = params.get("arguments")
        arguments: dict = raw if isinstance(raw, dict) else {}
        try:
            if name == "edit_with_markers":
                text = self.edit_with_markers(arguments)
            elif name == "protection_status":
                text = self.protection_status(arguments)
            else:
                raise ToolError("Unknown tool.")
            return {"content": [{"type": "text", "text": text}], "isError": False}
        except ToolError as error:
            return {"content": [{"type": "text", "text": str(error)}], "isError": True}
        except GuardError as error:
            text = f"DataFog guard could not do this ({error.code}: {error.user_message}). Nothing was changed."
            return {"content": [{"type": "text", "text": text}], "isError": True}
        except Exception as error:   # never echo a foreign exception message: it may quote file content
            text = f"DataFog guard failed ({safe_code(error)}). Nothing was reported about the file."
            return {"content": [{"type": "text", "text": text}], "isError": True}

    def handle(self, message: dict):
        method = message.get("method")
        raw = message.get("params")
        params: dict = raw if isinstance(raw, dict) else {}
        if method == "initialize":
            return {"protocolVersion": params.get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "datafog-guard", "version": __version__}}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            return self.call_tool(params)
        raise LookupError


def main() -> int:
    server = Server()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
            continue
        if not isinstance(message, dict) or "id" not in message:
            continue   # a notification: nothing to answer
        try:
            reply = {"jsonrpc": "2.0", "id": message["id"], "result": server.handle(message)}
        except LookupError:
            reply = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "method not found"}}
        except Exception:
            reply = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32603, "message": "internal error"}}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0
