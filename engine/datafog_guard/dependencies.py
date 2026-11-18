"""Check reviewed dependency versions before calling detector or vault code.

This detects stale or accidentally upgraded environments; version labels are not a
cryptographic integrity check against another program running as the same user.
"""
from __future__ import annotations

from functools import lru_cache

from .errors import EngineUnavailable


@lru_cache(maxsize=2)
def reviewed_version(requirement: str) -> str:
    from importlib.metadata import PackageNotFoundError, version

    name, expected = requirement.split("==", 1)
    try:
        installed = version(name)
    except PackageNotFoundError:
        raise EngineUnavailable("reviewed dependency metadata is missing; run the bootstrap command "
                                "shown at session start", "dependency_version_unavailable") from None
    if installed != expected:
        raise EngineUnavailable(f"the installed dependency must match {requirement}; run the bootstrap "
                                "command shown at session start", "dependency_version_mismatch")
    return expected


def check_module(module, requirement: str) -> None:
    if getattr(module, "__version__", None) != reviewed_version(requirement):
        raise EngineUnavailable(f"the loaded dependency must match {requirement}; run the bootstrap "
                                "command shown at session start", "dependency_version_mismatch")
