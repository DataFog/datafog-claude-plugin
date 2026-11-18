"""Builds the working parts (store, detector, vault) from the settings."""
from __future__ import annotations

import os

from . import config
from .errors import ConfigError
from .store import FileVaultStore
from .vault import Detector, Vault


def open_vault(settings: config.Settings | None = None) -> tuple[Vault, config.Settings]:
    settings = settings or config.load()
    if settings.problems:
        raise ConfigError("configuration problem: " + "; ".join(settings.problems))
    try:
        lock_timeout = float(os.environ.get("DATAFOG_LOCK_TIMEOUT", "10"))
    except ValueError:
        lock_timeout = 10.0
    store = FileVaultStore(settings.vault_dir, lock_timeout=lock_timeout)
    detector = Detector(settings.entities, settings.allowlist)
    return Vault(store, detector, recall_required=settings.recall_required), settings
