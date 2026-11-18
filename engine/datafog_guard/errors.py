"""Errors raised by the engine.

Every error carries a short machine-readable ``code`` and a message written
for the user. Neither may ever contain a real value: messages name entity
types, counts and fixed text only.
"""
from __future__ import annotations


class GuardError(Exception):
    code = "internal_error"

    def __init__(self, message: str = "", code: str | None = None):
        super().__init__(message or self.code)
        if code:
            self.code = code
        self.user_message = message or self.code


class EngineUnavailable(GuardError):
    """The detector library is missing or does not work."""
    code = "engine_unavailable"


class ConfigError(GuardError):
    code = "config_error"


class VaultError(GuardError):
    code = "vault_error"


class VaultCorrupt(VaultError):
    code = "vault_corrupt"


class VaultLocked(VaultError):
    code = "vault_locked"


class VaultBusy(VaultError):
    """Too many concurrent writers: the bounded retry on a stale head ran out."""
    code = "vault_busy"


class VaultFull(VaultError):
    code = "vault_full"


class RecallUnavailable(VaultError):
    code = "recall_unavailable"


class TokenizeError(GuardError):
    code = "tokenize_error"


def safe_code(error: BaseException) -> str:
    """A description of an error that is safe to log or show: never the message of a foreign exception."""
    if isinstance(error, GuardError):
        return error.code
    return "unexpected_" + type(error).__name__
