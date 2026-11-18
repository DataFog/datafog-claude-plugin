"""Diagnostic log. Entries name events, tools, entity types, counts and error codes only.

Nothing passed to :func:`write` may be text taken from a tool, a file or a prompt.
"""
from __future__ import annotations

import json
import os
import time


def write(path: str, **fields) -> None:
    try:
        directory = os.path.dirname(path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            if os.path.getsize(path) > 2_000_000:
                os.replace(path, path + ".1")
        except OSError:
            pass
        fields["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(fields, sort_keys=True, default=str) + "\n")
    except Exception:
        pass   # logging must never break or delay a hook


def describe_counts(counts) -> str:
    """'2 EMAIL, 1 SSN' from a Counter; types and counts only."""
    return ", ".join(f"{number} {name}" for name, number in sorted(counts.items())) or "none"
