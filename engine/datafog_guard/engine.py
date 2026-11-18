"""Builds the working parts (store, detector, vault) from the settings."""
from __future__ import annotations

import os

from . import config
from .errors import ConfigError
from .store import EncryptedStore
from .vault import Detector, Vault


def open_store(settings: config.Settings) -> EncryptedStore:
    try:
        lock_timeout = float(os.environ.get("DATAFOG_LOCK_TIMEOUT", "10"))
    except ValueError:
        lock_timeout = 10.0
    return EncryptedStore(settings.vault_dir, key_mode=settings.vault_key, lock_timeout=lock_timeout)


def open_vault(settings: config.Settings | None = None) -> tuple[Vault, config.Settings]:
    settings = settings or config.load()
    if settings.problems:
        raise ConfigError("configuration problem: " + "; ".join(settings.problems))
    return Vault(open_store(settings), Detector(settings.entities, settings.allowlist)), settings
