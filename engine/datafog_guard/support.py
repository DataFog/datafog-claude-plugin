"""Which machines the plugin runs on, and the one message shown everywhere else.

The vault is ``datafog-fogvault``, which ships compiled wheels for macOS on Apple Silicon,
Linux x86_64 with glibc 2.38 or later, and Windows x64 (the plugin itself does not support
Windows yet). There is no other storage and no fallback: on any other machine the plugin does
not protect, says so with this message, and blocks tool calls.
"""
from __future__ import annotations

# Also in scripts/bootstrap.sh (tests/test_cli_and_plugin.py checks that the two are the same).
UNSUPPORTED = (
    "DataFog does not support this machine. It needs macOS on Apple Silicon, or Linux on x86_64 with "
    "glibc 2.38 or later. Nothing is protected and tool calls are blocked; disable or uninstall the "
    "plugin to work without it."
)


def platform_problem() -> str | None:
    """None on a supported machine, else a short reason (no paths, no content)."""
    import platform
    import sys
    machine = platform.machine().lower()
    if sys.platform == "darwin":
        return None if machine in ("arm64", "aarch64") else "macOS on Intel"
    if sys.platform.startswith("linux"):
        if machine not in ("x86_64", "amd64"):
            return f"Linux on {machine or 'an unknown processor'}"
        name, version = platform.libc_ver()
        if name != "glibc":
            return "Linux without glibc"
        try:
            parts = tuple(int(part) for part in version.split(".")[:2])
        except ValueError:
            return "Linux with an unknown glibc"
        return None if parts >= (2, 38) else f"glibc {version}"
    return "this operating system"
