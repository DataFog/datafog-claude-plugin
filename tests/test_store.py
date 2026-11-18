"""The encrypted store: layout, permissions, ciphertext on disk, key modes, corruption, purge."""
from __future__ import annotations

import os
import stat

import pytest
from conftest import API_KEY, EMAIL, NOTES, SENTINELS, open_test_vault
from datafog_guard.errors import VaultCorrupt, VaultError, VaultLocked
from datafog_guard.store import EncryptedStore, FileLock, legacy_plain_store, read_envelope_header, vault_path

OURS = {"markers.index", "bash-restore.key"}
CORES = {"workspace.enc", "workspace.lock", "workspace.key"}


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_reading_creates_nothing(box):
    vault = box.open_vault()
    assert vault.restore("x [[EMAIL_ABC123]]").unknown == 1 and vault.tokenize("plain text")[0] == "plain text"
    assert vault.entry_counts() == {}
    assert not box.vault.exists(), "reading must not create a vault (or a key)"


def test_layout_and_permissions(box):
    box.open_vault().tokenize(NOTES)
    names = {path.name for path in box.vault.iterdir()}
    assert names == {"workspace.enc", "workspace.lock", "workspace.key", "markers.index"}
    assert mode(box.vault) == 0o700
    for path in box.vault.iterdir():
        assert path.is_file() and mode(path) == 0o600, path.name


def test_our_files_do_not_collide_with_cores(box):
    """The restore-ticket key and the marker index live beside core's files and do not disturb them."""
    from datafog_guard import bashwrap
    assert not OURS & CORES
    vault = box.open_vault()
    out, _ = vault.tokenize(NOTES)
    ticket = bashwrap.restore_ticket("echo x", str(box.vault))
    assert ticket and mode(box.vault / "bash-restore.key") == 0o600
    again = box.open_vault()
    again.health()
    assert again.restore(out).text == NOTES
    assert bashwrap.ticket_is_valid(ticket, "echo x", str(box.vault))


def test_nothing_on_disk_holds_a_value(box):
    """What is on disk is ciphertext: no planted value, whole or in a recognisable part."""
    vault = box.open_vault()
    hostile = "it's \"q\" $(touch x) `y`\nline two\\"
    vault.tokenize(NOTES + f"\nkey {API_KEY}\n")
    from conftest import seed_values
    seed_values(vault, [("ACCOUNT_NUMBER", hostile)])
    vault.restore(vault.tokenize(NOTES)[0])
    needles = [value.encode() for value in SENTINELS] + [b"ada.synthetic", b"4242", b"078-05", b"555-0134",
                                                         b"4eC39HqLyjWDarjtT1zdp7dc", b"touch x", b"line two"]
    for path in box.tmp.rglob("*"):
        if path.is_file() and box.vault in path.parents:
            raw = path.read_bytes()
            for needle in needles:
                assert needle not in raw, f"a value is readable in {path.name}"
    index = (box.vault / "markers.index").read_text()
    assert index.startswith("# datafog marker index v1 ") and "[[EMAIL_" in index


def test_the_envelope_names_the_app_and_the_key_mode_in_the_clear(box):
    box.open_vault().tokenize(EMAIL)
    header = read_envelope_header(str(box.vault))
    assert header["state"] == "ok" and header["app_id"] == "claude-code" and header["protection"] == "file_key"
    assert len(header["vault_id"]) == 32 and header["revision"] == 1


def test_a_directory_made_with_mkdir_is_made_private_before_the_vault_is_created(tmp_path):
    directory = tmp_path / "v"
    directory.mkdir(mode=0o755)
    os.chmod(directory, 0o755)
    open_test_vault(directory).tokenize(EMAIL)
    assert mode(directory) == 0o700


@pytest.mark.parametrize("target", ["directory", "workspace.enc", "workspace.key"])
def test_loose_permissions_on_an_existing_vault_are_refused_not_repaired(box, target):
    out, _ = box.open_vault().tokenize(EMAIL)
    path = box.vault if target == "directory" else box.vault / target
    os.chmod(path, 0o755 if target == "directory" else 0o644)
    for action in (lambda: box.open_vault().tokenize(f"y {EMAIL}"), lambda: box.open_vault().restore(out),
                   lambda: box.open_vault().health()):
        with pytest.raises(VaultError) as caught:
            action()
        assert caught.value.code == "vault_insecure" and EMAIL not in caught.value.user_message
    assert mode(path) == (0o755 if target == "directory" else 0o644), "nothing is repaired silently"


def test_a_vault_directory_that_is_a_symbolic_link_is_refused(box):
    out, _ = box.open_vault().tokenize(EMAIL)
    link = box.tmp / "link"
    link.symlink_to(box.vault)
    with pytest.raises(VaultError) as caught:
        open_test_vault(link).restore(out)
    assert caught.value.code == "vault_insecure"


def test_symbolic_links_above_the_vault_directory_are_followed(box):
    """/tmp and /var are links on macOS; only the vault directory itself must not be one."""
    real = box.tmp / "real"
    real.mkdir()
    (box.tmp / "alias").symlink_to(real)
    out, _ = open_test_vault(box.tmp / "alias" / "vault").tokenize(EMAIL)
    assert open_test_vault(real / "vault").restore(out).text == EMAIL
    assert vault_path(str(box.tmp / "alias" / "vault")) == str(real.resolve() / "vault")


@pytest.mark.parametrize("damage", ["flipped", "truncated", "garbage", "empty", "wrong_key", "short_key", "missing_key"])
def test_corruption_is_detected_not_ignored(box, damage):
    box.open_vault().tokenize(f"x {EMAIL}")
    envelope, key = box.vault / "workspace.enc", box.vault / "workspace.key"
    if damage == "flipped":
        raw = bytearray(envelope.read_bytes())
        raw[-20] ^= 0xFF
        envelope.write_bytes(bytes(raw))
    elif damage == "truncated":
        envelope.write_bytes(envelope.read_bytes()[:-9])
    elif damage == "garbage":
        envelope.write_bytes(b"not a vault at all " * 20)
    elif damage == "empty":
        envelope.write_bytes(b"")
    elif damage == "wrong_key":
        key.write_bytes(bytes(32))
    elif damage == "short_key":
        key.write_bytes(b"short")
    else:
        key.unlink()
    for action in (lambda: box.open_vault().tokenize(f"y {EMAIL}"), lambda: box.open_vault().restore("[[EMAIL_ABC123]]"),
                   lambda: box.open_vault().health()):
        with pytest.raises(VaultError) as caught:
            action()
        assert caught.value.code in ("vault_corrupt", "vault_unsupported", "vault_unreadable"), caught.value.code
        assert EMAIL not in str(caught.value) + caught.value.user_message
    if damage in ("flipped", "truncated", "wrong_key"):
        with pytest.raises(VaultCorrupt):
            box.open_vault().health()


def test_no_new_key_is_made_for_an_existing_vault(box):
    """A missing key must fail closed: core never replaces it, and neither does the plugin."""
    box.open_vault().tokenize(EMAIL)
    (box.vault / "workspace.key").unlink()
    with pytest.raises(VaultError):
        box.open_vault().health()
    assert not (box.vault / "workspace.key").exists()


def test_lock_times_out_instead_of_hanging(box):
    out, _ = box.open_vault().tokenize(f"x {EMAIL}")
    import time
    with FileLock(str(box.vault / "workspace.lock")):
        blocked = open_test_vault(box.vault)
        blocked.store.lock_timeout = 0.2
        started = time.monotonic()
        with pytest.raises(VaultLocked):
            blocked.restore(out)
        assert time.monotonic() - started < 15, "core waits five seconds for the lock; the plugin does not add much"
    assert box.open_vault().restore(out).text == f"x {EMAIL}"


@pytest.mark.skipif(os.name == "nt" or os.geteuid() != 0 or not __import__("shutil").which("setpriv"),
                    reason="needs root and setpriv to run as another user")
def test_core_limit_a_directory_above_the_vault_that_the_user_cannot_list(tmp_path):
    """LIMIT OF CORE 1.7.0, pinned so a change is noticed: ApplicationVault opens every directory
    above the vault (to flush it), so a parent the user may pass through but not list, such as a
    /home with mode 0711, makes the vault unusable. The plugin then fails closed."""
    import subprocess
    import sys

    from conftest import ENGINE, ROOT
    switch = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]
    if subprocess.run([*switch, sys.executable, "-I", "-c", "import datafog_fogvault"], capture_output=True).returncode:
        pytest.skip("this Python installation is not readable by the unprivileged test user")
    base = __import__("pathlib").Path(__import__("tempfile").mkdtemp(prefix="datafog-anc-", dir="/tmp"))
    try:
        home = base / "closed" / "home"
        home.mkdir(parents=True)
        subprocess.run(["chown", "65534:65534", str(home)], check=True)
        os.chmod(base, 0o755)
        code = ("import sys; sys.path[:0] = [%r, %r]\n"
                "from conftest import open_test_vault\n"
                "from datafog_guard.errors import GuardError\n"
                "try:\n    open_test_vault(sys.argv[1]).health(); print('ok')\n"
                "except GuardError as error:\n    print(error.code)\n" % (str(ENGINE), str(ROOT / "tests")))
        outcomes = []
        for mode_bits in (0o711, 0o755):
            os.chmod(base / "closed", mode_bits)
            result = subprocess.run([*switch, sys.executable, "-c", code, str(home / f"vault{mode_bits}")],
                                    capture_output=True, text=True, env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"})
            outcomes.append(result.stdout.strip() or result.stderr[-300:])
        assert outcomes == ["vault_unreadable", "ok"]
    finally:
        subprocess.run(["rm", "-rf", str(base)])


def test_two_vault_directories_do_not_share_a_key(box):
    first, second = box.tmp / "one", box.tmp / "two"
    a, _ = open_test_vault(first).tokenize(EMAIL)
    b, _ = open_test_vault(second).tokenize(EMAIL)
    assert (first / "workspace.key").read_bytes() != (second / "workspace.key").read_bytes()
    assert read_envelope_header(str(first))["vault_id"] != read_envelope_header(str(second))["vault_id"]
    assert open_test_vault(second).restore(a).unknown == (0 if a == b else 1)
    # one vault's key does not open the other
    (second / "workspace.key").write_bytes((first / "workspace.key").read_bytes())
    with pytest.raises(VaultCorrupt):
        open_test_vault(second).health()


def test_the_marker_index_of_another_vault_is_ignored_and_replaced(box):
    vault = box.open_vault()
    vault.tokenize(EMAIL)
    index = box.vault / "markers.index"
    index.write_text("# datafog marker index v1 " + "0" * 32 + "\n[[EMAIL_ZZZZZZ]]\n")
    fresh = box.open_vault()
    assert fresh.entry_counts() == {}
    out, _ = fresh.tokenize(f"again {EMAIL} and 415-555-0134")
    assert box.open_vault().entry_counts() == {"EMAIL": 1, "PHONE": 1}
    assert "[[EMAIL_ZZZZZZ]]" not in index.read_text()


def test_a_damaged_or_lost_marker_index_heals_and_never_blocks(box):
    vault = box.open_vault()
    first, _ = vault.tokenize(f"{EMAIL} 415-555-0134")
    index = box.vault / "markers.index"
    index.write_bytes(index.read_bytes()[:-5] + b"\xff\x00 junk")          # a torn last line
    assert box.open_vault().entry_counts() == {"EMAIL": 1}
    again, _ = box.open_vault().tokenize(f"{EMAIL} 415-555-0134")
    assert again == first, "the value gets the marker it always had"
    assert box.open_vault().entry_counts() == {"EMAIL": 1, "PHONE": 1}
    index.unlink()
    assert box.open_vault().restore(first).text == f"{EMAIL} 415-555-0134", "restoring never needs the index"
    assert box.open_vault().tokenize(f"{EMAIL} 415-555-0134")[0] == first
    index.write_text(index.read_text() + "[[EMAIL_ZZZZZZ]]\nnot a marker\n")   # entries the vault does not know
    assert box.open_vault().entry_counts() == {"EMAIL": 1, "PHONE": 1}


def test_a_fifo_marker_index_is_refused_without_waiting_for_a_writer(box):
    box.open_vault().tokenize(EMAIL)
    index = box.vault / "markers.index"
    index.unlink()
    os.mkfifo(index, mode=0o600)
    with pytest.raises(VaultError) as caught:
        box.open_vault().tokenize(EMAIL)
    assert caught.value.code == "vault_insecure"


def test_purge(box):
    from datafog_guard import bashwrap
    vault = box.open_vault()
    out, _ = vault.tokenize(f"x {EMAIL}")
    bashwrap.restore_ticket("echo", str(box.vault))
    store = EncryptedStore(str(box.vault), key_mode="file")
    result = store.purge()
    assert result["existed"] is True and result["keystore"] == "none"
    assert {path.name for path in box.vault.iterdir()} <= {"workspace.lock"}
    restored = box.open_vault().restore(out)
    assert restored.text == out and restored.unknown == 1, "markers from a purged vault can never be restored"
    assert store.purge()["existed"] is False
    box.open_vault().tokenize(EMAIL)
    assert box.open_vault().entry_counts() == {"EMAIL": 1}, "a new vault starts empty"


def test_purge_does_not_follow_a_symlinked_vault_directory(box):
    box.open_vault().tokenize(EMAIL)
    alias = box.tmp / "alias"
    alias.symlink_to(box.vault, target_is_directory=True)
    with pytest.raises(VaultError):
        EncryptedStore(str(alias), key_mode="file").purge()
    assert (box.vault / "workspace.enc").exists() and (box.vault / "workspace.key").exists()


def test_purge_unlinks_a_symlinked_legacy_directory_without_deleting_its_target(box):
    box.open_vault().tokenize(EMAIL)
    outside = box.tmp / "outside"
    outside.mkdir()
    document = outside / "important.txt"
    document.write_text("synthetic data outside the vault")
    (box.vault / "snapshots").symlink_to(outside, target_is_directory=True)
    result = EncryptedStore(str(box.vault), key_mode="file").purge()
    assert result["legacy"] is True
    assert document.read_text() == "synthetic data outside the vault"
    assert not (box.vault / "snapshots").is_symlink()


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_purge_refuses_a_linked_lock_file(box, link_kind):
    box.open_vault().tokenize(EMAIL)
    outside = box.tmp / "outside.txt"
    outside.write_text("synthetic outside data")
    lock = box.vault / "workspace.lock"
    lock.unlink()
    if link_kind == "symlink":
        lock.symlink_to(outside)
    else:
        os.link(outside, lock)
    with pytest.raises(VaultError):
        EncryptedStore(str(box.vault), key_mode="file").purge()
    assert outside.read_text() == "synthetic outside data"
    assert (box.vault / "workspace.enc").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root can unlink files in a read-only directory")
def test_purge_reports_a_deletion_failure_and_preserves_the_key(box):
    out, _ = box.open_vault().tokenize(EMAIL)
    box.vault.chmod(0o500)
    try:
        with pytest.raises(VaultError) as caught:
            EncryptedStore(str(box.vault), key_mode="file").purge()
        assert caught.value.code == "purge_failed"
        assert (box.vault / "workspace.enc").exists() and (box.vault / "workspace.key").exists()
    finally:
        box.vault.chmod(0o700)
    assert box.open_vault().restore(out).text == EMAIL


def test_purge_holds_the_vault_lock_until_key_removal_finishes(box, monkeypatch):
    from datafog_guard import store
    box.open_vault().tokenize(EMAIL)
    envelope = box.vault / "workspace.enc"
    raw = bytearray(envelope.read_bytes())
    raw[13 + raw[12] + 56] = 1      # a credential-store envelope; purge needs no working key
    envelope.write_bytes(raw)
    calls = []

    def remove_key(account):
        assert not envelope.exists()
        with pytest.raises(VaultLocked):
            with FileLock(str(box.vault / "workspace.lock"), timeout=0.01):
                pass
        calls.append(account)
        return True

    monkeypatch.setattr(store, "remove_keystore_entry", remove_key)
    result = EncryptedStore(str(box.vault), key_mode="file").purge()
    assert result["keystore"] == "removed" and calls == [result["account"]]


def test_purge_under_a_long_lived_process(box):
    """The MCP server keeps its vault object: after a purge by another process it sees the new vault."""
    server = box.open_vault()
    old, _ = server.tokenize(f"x {EMAIL}")
    EncryptedStore(str(box.vault), key_mode="file").purge()
    assert server.restore(old).unknown == 1 and server.entry_counts() == {}
    new, _ = box.open_vault().tokenize(f"x {EMAIL}")
    assert server.restore(new).text == f"x {EMAIL}" and server.entry_counts() == {"EMAIL": 1}
    assert server.restore(old).unknown == (0 if old == new else 1)


def test_an_unencrypted_vault_of_a_development_build_is_never_read_and_purge_removes_it(box):
    box.vault.mkdir(mode=0o700)
    (box.vault / "snapshots").mkdir()
    (box.vault / "snapshots" / "000000000001-aa.dfv").write_bytes(b"plain " + EMAIL.encode())
    (box.vault / "HEAD").write_text('{"revision": 1}')
    (box.vault / "meta.json").write_text("{}")
    assert legacy_plain_store(str(box.vault))
    vault = box.open_vault()
    assert vault.restore("[[EMAIL_ABC123]]").unknown == 1
    out, _ = vault.tokenize(EMAIL)                         # the encrypted vault works beside it
    assert box.open_vault().restore(out).text == EMAIL
    result = EncryptedStore(str(box.vault), key_mode="file").purge()
    assert result["legacy"] is True and not legacy_plain_store(str(box.vault))
    assert {path.name for path in box.vault.iterdir()} <= {"workspace.lock"}
