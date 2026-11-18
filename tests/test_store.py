"""File vault store: permissions, atomic compare-and-save, corruption handling, purge."""
from __future__ import annotations

import json
import os
import stat

import pytest
from conftest import EMAIL
from datafog_guard.errors import VaultCorrupt, VaultLocked
from datafog_guard.store import FileVaultStore, Head


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_empty_store(tmp_path):
    store = FileVaultStore(str(tmp_path / "v"))
    assert store.load() is None and store.peek_head() is None
    assert not (tmp_path / "v").exists(), "reading must not create anything"


def test_compare_and_save_is_the_only_write(tmp_path):
    store = FileVaultStore(str(tmp_path / "v"))
    first, second = Head(0, "aa"), Head(1, "bb")
    assert store.compare_and_save(None, first, b"bundle-0", {"entries": {}})
    assert not store.compare_and_save(None, first, b"other", {}), "creating twice must fail"
    assert not store.compare_and_save(second, Head(2, "cc"), b"x", {}), "stale head must fail"
    assert store.load().bundle == b"bundle-0"
    assert store.compare_and_save(first, second, b"bundle-1", {"entries": {"EMAIL": 1}})
    snapshot = store.load()
    assert snapshot.head == second and snapshot.bundle == b"bundle-1"
    assert snapshot.annotations == {"entries": {"EMAIL": 1}}


def test_permissions_and_layout(box):
    vault = box.open_vault()
    vault.tokenize(f"x {EMAIL}")
    assert mode(box.vault) == 0o700 and mode(box.vault / "snapshots") == 0o700
    for path in box.vault.rglob("*"):
        if path.is_file():
            assert mode(path) == 0o600, path.name
    meta = json.loads((box.vault / "meta.json").read_text())
    assert meta["app_id"] == "claude-code" and meta["contract_version"] == 1
    assert meta["encrypted_at_rest"] is False and len(meta["vault_id"]) == 32 and meta["created"]


def test_snapshot_bytes_are_cores_unmodified(box):
    import datafog_core
    vault = box.open_vault()
    vault.tokenize(f"x {EMAIL}")
    pointer = json.loads((box.vault / "HEAD").read_text())
    raw = (box.vault / "snapshots" / pointer["snapshot"]).read_bytes()
    workspace = datafog_core.Workspace.open_bundle(raw)
    assert workspace.export_bundle() == raw
    assert workspace.head().revision == pointer["revision"]


def test_loose_directory_permissions_are_tightened(tmp_path):
    directory = tmp_path / "v"
    directory.mkdir(mode=0o755)
    os.chmod(directory, 0o755)
    FileVaultStore(str(directory)).compare_and_save(None, Head(0, "aa"), b"b", {})
    assert mode(directory) == 0o700


def test_old_snapshots_are_removed(box):
    vault = box.open_vault()
    for number in range(6):
        vault.tokenize(f"user{number}.synthetic@example.com")
    assert len(list((box.vault / "snapshots").iterdir())) <= 2


@pytest.mark.parametrize("damage", ["pointer_garbage", "pointer_truncated", "snapshot_flipped", "snapshot_missing",
                                    "snapshot_truncated"])
def test_corruption_is_detected_not_ignored(box, damage):
    vault = box.open_vault()
    vault.tokenize(f"x {EMAIL}")
    pointer_path = box.vault / "HEAD"
    pointer = json.loads(pointer_path.read_text())
    snapshot = box.vault / "snapshots" / pointer["snapshot"]
    if damage == "pointer_garbage":
        pointer_path.write_text("not json")
    elif damage == "pointer_truncated":
        pointer_path.write_text(pointer_path.read_text()[:20])
    elif damage == "snapshot_flipped":
        raw = bytearray(snapshot.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        snapshot.write_bytes(bytes(raw))
    elif damage == "snapshot_missing":
        snapshot.unlink()
    else:
        snapshot.write_bytes(snapshot.read_bytes()[:-9])
    with pytest.raises(VaultCorrupt):
        box.open_vault().tokenize(f"y {EMAIL}")
    with pytest.raises(VaultCorrupt):
        box.open_vault().restore("[[EMAIL_ABC123]]")


def test_lock_times_out_instead_of_hanging(box):
    box.open_vault().tokenize(f"x {EMAIL}")
    holder = FileVaultStore(str(box.vault))
    with holder.lock():
        blocked = FileVaultStore(str(box.vault), lock_timeout=0.2)
        with pytest.raises(VaultLocked):
            blocked.compare_and_save(blocked.peek_head(), Head(99, "zz"), b"x", {})
    assert holder.load().head.revision == 1


def test_purge(box):
    vault = box.open_vault()
    out, _ = vault.tokenize(f"x {EMAIL}")
    store = FileVaultStore(str(box.vault))
    assert store.purge() is True
    assert store.load() is None and not list((box.vault / "snapshots").iterdir())
    result = box.open_vault().restore(out)
    assert result.text == out and result.unknown == 1, "markers from a purged vault can never be restored"
    assert store.purge() is False
