"""Only the reviewed detector/vault versions may process user data."""
from __future__ import annotations

import builtins
import importlib.metadata

import pytest
from datafog_guard import CORE_REQUIREMENT, VAULT_REQUIREMENT
from datafog_guard.dependencies import reviewed_version
from datafog_guard.errors import EngineUnavailable
from datafog_guard.store import _fogvault
from datafog_guard.vault import _core


@pytest.fixture(autouse=True)
def clear_version_cache():
    reviewed_version.cache_clear()
    yield
    reviewed_version.cache_clear()


@pytest.mark.parametrize("loader, requirement, module_name", [
    (_core, CORE_REQUIREMENT, "datafog_core"), (_fogvault, VAULT_REQUIREMENT, "datafog_fogvault"),
])
@pytest.mark.parametrize("missing", [False, True])
def test_unreviewed_distribution_is_rejected_before_import(monkeypatch, loader, requirement, module_name, missing):
    imported = False
    original_import = builtins.__import__

    def tracked_import(name, *args, **kwargs):
        nonlocal imported
        if name == module_name:
            imported = True
        return original_import(name, *args, **kwargs)

    def wrong_version(name):
        if missing:
            raise importlib.metadata.PackageNotFoundError(name)
        return "9.9.9"

    monkeypatch.setattr(builtins, "__import__", tracked_import)
    monkeypatch.setattr(importlib.metadata, "version", wrong_version)
    with pytest.raises(EngineUnavailable) as raised:
        loader()
    assert raised.value.code == ("dependency_version_unavailable" if missing else "dependency_version_mismatch")
    assert not imported


@pytest.mark.parametrize("loader", [_core, _fogvault])
def test_loaded_module_version_must_agree_with_reviewed_metadata(monkeypatch, loader):
    module = loader()
    monkeypatch.setattr(module, "__version__", "9.9.9")
    with pytest.raises(EngineUnavailable, match="loaded dependency"):
        loader()


def test_successful_metadata_checks_are_cached_without_repeated_import_scans(monkeypatch):
    original = importlib.metadata.version
    seen = []

    def counted(name):
        seen.append(name)
        return original(name)

    monkeypatch.setattr(importlib.metadata, "version", counted)
    for _ in range(20):
        _core()
        _fogvault()
    assert seen == ["datafog-core", "datafog-fogvault"]
