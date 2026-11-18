"""The default key mode: the vault key in the operating system's key store.

No test here touches the developer's real key store. On Linux, where the tools are installed, the
cases run against a PRIVATE Secret Service: a throwaway D-Bus session with its own GNOME Keyring
daemon and its own HOME and XDG directories, all inside the test's temp dir. On macOS these cases
are skipped (they would write to the real login Keychain); the Keychain is covered only by the
optional live case L28 (tests/live/run_live.py, LIVE_KEYCHAIN=1).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap

import pytest
from conftest import EMAIL, ENGINE

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not all(shutil.which(tool) for tool in ("dbus-run-session", "gnome-keyring-daemon",
                                                                        "secret-tool")),
    reason="needs Linux with dbus-run-session, gnome-keyring-daemon and secret-tool (a private Secret Service)")

SESSION = textwrap.dedent("""
    set -e
    printf 'synthetic-test-password\\n' | gnome-keyring-daemon --unlock --components=secrets \
        --control-directory="$GNOME_KEYRING_CONTROL" >/dev/null 2>&1
    sleep 0.3
    test -S "$GNOME_KEYRING_CONTROL/control"
    exec "$@"
""")
PRELUDE = textwrap.dedent("""
    import json, os, subprocess, sys
    from datafog_guard.config import DEFAULT_ENTITIES
    from datafog_guard.errors import GuardError
    from datafog_guard.store import KEYSTORE_SERVICE, EncryptedStore, read_envelope_header
    from datafog_guard.vault import Detector, Vault
    def vault(directory, mode="keystore"):
        return Vault(EncryptedStore(directory, key_mode=mode), Detector(DEFAULT_ENTITIES))
    def entries():
        found = subprocess.run(["secret-tool", "search", "--all", "service", KEYSTORE_SERVICE], capture_output=True)
        return sorted(line.split(b" = ")[1].decode() for line in found.stderr.splitlines()
                      if line.startswith(b"attribute.username"))
    def code_of(action):
        try:
            action()
            return "ok"
        except GuardError as error:
            return error.code
    EMAIL = "ada.synthetic@example.com"
    base = sys.argv[1]
""")


def in_private_key_store(tmp_path, script: str, timeout: int = 120) -> dict:
    """Run a Python script inside a throwaway D-Bus session with its own unlocked keyring."""
    root = tmp_path / "keystore-session"
    env = {"PATH": os.environ["PATH"], "PYTHONPATH": str(ENGINE), "PYTHONDONTWRITEBYTECODE": "1",
           "HOME": str(root / "home")}
    for name in ("data", "config", "cache", "run"):
        (root / name).mkdir(parents=True, exist_ok=True)
        env["XDG_RUNTIME_DIR" if name == "run" else f"XDG_{name.upper()}_HOME"] = str(root / name)
    (root / "home").mkdir(exist_ok=True)
    os.chmod(root / "run", 0o700)
    # gnome-keyring otherwise chooses a temporary control socket and prints its
    # location. Pin it explicitly so the recovery request reaches this same private daemon.
    control = root / "run" / "keyring"
    control.mkdir(mode=0o700)
    env["GNOME_KEYRING_CONTROL"] = str(control)
    result = subprocess.run(["dbus-run-session", "--", "sh", "-c", SESSION, "sh", sys.executable, "-c",
                             PRELUDE + textwrap.dedent(script), str(tmp_path)],
                            capture_output=True, text=True, env=env, timeout=timeout)
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_key_lives_in_the_key_store_and_other_processes_find_it(tmp_path):
    seen = in_private_key_store(tmp_path, """
        d = os.path.join(base, "vault")
        first = vault(d)
        health = first.health()
        out, _ = first.tokenize(f"mail {EMAIL}")
        code = "import sys\\n" + "from datafog_guard.config import DEFAULT_ENTITIES\\nfrom datafog_guard.store import EncryptedStore\\n" \\
               "from datafog_guard.vault import Detector, Vault\\n" \\
               "v = Vault(EncryptedStore(sys.argv[1]), Detector(DEFAULT_ENTITIES))\\nprint(v.restore(sys.argv[2]).text, v.health()['protection'])"
        other = subprocess.run([sys.executable, "-c", code, d, out], capture_output=True, text=True)
        header = read_envelope_header(d)
        raw = b"".join(open(os.path.join(d, name), "rb").read() for name in os.listdir(d))
        print(json.dumps({"protection": health["protection"], "files": sorted(os.listdir(d)), "other": other.stdout.strip(),
                          "entries": entries(), "account": header["app_id"] + "/" + header["vault_id"],
                          "value_on_disk": EMAIL.encode() in raw,
                          "file_mode": code_of(lambda: vault(d, "file").health())}))
    """)
    assert seen["protection"] == "credential_store"
    assert seen["files"] == ["markers.index", "workspace.enc", "workspace.lock"], "no key file beside the data"
    assert seen["other"] == f"mail {EMAIL} credential_store", "a second process gets the key from the key store"
    assert seen["entries"] == [seen["account"]] and seen["account"].startswith("claude-code/")
    assert seen["value_on_disk"] is False
    assert seen["file_mode"] == "vault_key_mismatch", "a key-store vault is never opened or re-keyed with a file key"


def test_two_vault_directories_have_two_keys_and_purge_removes_only_its_own(tmp_path):
    seen = in_private_key_store(tmp_path, """
        one, two = os.path.join(base, "one"), os.path.join(base, "two")
        a, _ = vault(one).tokenize(EMAIL)
        b, _ = vault(two).tokenize(EMAIL)
        before = entries()
        ids = [read_envelope_header(d)["vault_id"] for d in (one, two)]
        result = EncryptedStore(one).purge()
        print(json.dumps({"before": before, "ids": ids, "purge": result, "after": entries(),
                          "two_still_restores": vault(two).restore(b).text == EMAIL,
                          "one_is_gone": vault(one).restore(a).unknown}))
    """)
    assert len(seen["before"]) == 2 and seen["ids"][0] != seen["ids"][1]
    assert seen["purge"]["keystore"] == "removed" and seen["purge"]["account"] == "claude-code/" + seen["ids"][0]
    assert seen["after"] == ["claude-code/" + seen["ids"][1]], "the other vault's key is untouched"
    assert seen["two_still_restores"] is True and seen["one_is_gone"] == 1


def test_a_key_removed_from_the_key_store_fails_closed_and_is_never_replaced(tmp_path):
    seen = in_private_key_store(tmp_path, """
        d = os.path.join(base, "vault")
        out, _ = vault(d).tokenize(EMAIL)
        header = read_envelope_header(d)
        account = header["app_id"] + "/" + header["vault_id"]
        subprocess.run(["secret-tool", "clear", "service", KEYSTORE_SERVICE, "username", account], check=True)
        codes = [code_of(lambda: vault(d).health()), code_of(lambda: vault(d).restore(out)),
                 code_of(lambda: vault(d).tokenize("x " + EMAIL))]
        print(json.dumps({"codes": codes, "entries": entries(), "files": sorted(os.listdir(d))}))
    """)
    assert seen["codes"] == ["keystore_unavailable"] * 3
    assert seen["entries"] == [], "no replacement key is created for an existing vault"
    assert "workspace.key" not in seen["files"], "and no silent downgrade to a key file"


def test_a_wrong_key_in_the_key_store_fails_closed(tmp_path):
    seen = in_private_key_store(tmp_path, """
        d = os.path.join(base, "vault")
        out, _ = vault(d).tokenize(EMAIL)
        header = read_envelope_header(d)
        account = header["app_id"] + "/" + header["vault_id"]
        subprocess.run(["secret-tool", "store", "--label=x", "service", KEYSTORE_SERVICE, "username", account,
                        "application", "rust-keyring", "target", "default"], input=b"0" * 32, check=True)
        print(json.dumps({"codes": [code_of(lambda: vault(d).health()), code_of(lambda: vault(d).restore(out))]}))
    """)
    assert seen["codes"] == ["vault_corrupt"] * 2


def test_without_a_reachable_key_store_nothing_is_created_and_the_message_is_clear(box):
    """The default mode on a machine without a Secret Service (a server, a container, SSH)."""
    env = box.env(DATAFOG_VAULT_KEY="keystore", DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent/datafog-test",
                  XDG_RUNTIME_DIR=str(box.tmp / "no-runtime"))
    (box.data / "config.json").unlink()
    out, result = box.hook({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/x"},
                            "cwd": str(box.project)}, DATAFOG_VAULT_KEY="keystore",
                           DBUS_SESSION_BUS_ADDRESS=env["DBUS_SESSION_BUS_ADDRESS"], XDG_RUNTIME_DIR=env["XDG_RUNTIME_DIR"])
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "keystore_unavailable" in reason and "key store" in reason and "vault_key" in reason
    status = box.run("status", env=env).stdout.decode()
    doctor = box.run("doctor", env=env).stdout.decode()
    start = json.loads(box.run("hook", stdin=json.dumps({"hook_event_name": "SessionStart"}), env=env).stdout)
    for text in (status, doctor, start["systemMessage"]):
        assert "keystore_unavailable: the operating system's key store" in text
    assert "Protection: NOT WORKING" in status and "NOT PROTECTING" in start["systemMessage"]
    assert not (box.vault / "workspace.enc").exists() and not (box.vault / "workspace.key").exists()


@pytest.mark.skipif(not shutil.which("gdbus"), reason="needs gdbus to lock and inspect the private collection")
def test_locked_keyring_fails_closed_without_rekey_or_file_fallback(tmp_path):
    """Exercise a real Locked collection, not an absent bus or a cached open vault.

    Secret Service Lock/ReadAlias and Collection.Locked:
    https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Service.html
    https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Collection.html
    """
    seen = in_private_key_store(tmp_path, r"""
        import re
        from pathlib import Path

        service = "org.freedesktop.Secret.Service"
        collection_interface = "org.freedesktop.Secret.Collection"
        def call(path, method, *args):
            result = subprocess.run(["gdbus", "call", "--session", "--dest", "org.freedesktop.secrets",
                                     "--object-path", path, "--method", method, *args],
                                    capture_output=True, text=True, check=True, timeout=5)
            return result.stdout.strip()
        def locked():
            result = call(collection, "org.freedesktop.DBus.Properties.Get", collection_interface, "Locked")
            match = re.search(r"<(true|false)>", result)
            assert match, "the service did not return a boolean Locked property"
            return match.group(1) == "true"

        d = os.path.join(base, "vault")
        first = vault(d)
        marker, _ = first.tokenize(EMAIL)
        before_entries = entries()
        before_header = read_envelope_header(d)
        before_files = {name: (Path(d) / name).read_bytes() for name in ("workspace.enc", "markers.index")}
        alias = call("/org/freedesktop/secrets", service + ".ReadAlias", "default")
        paths = re.findall(r"'(/[^']*)'", alias)
        assert len(paths) == 1 and paths[0] != "/", "the private default collection must exist"
        collection = paths[0]
        found = call("/org/freedesktop/secrets", service + ".SearchItems",
                     "{'service': '" + KEYSTORE_SERVICE + "'}")
        item_paths = re.findall(r"'(/[^']*)'", found)
        assert item_paths and all(path.startswith(collection + "/") for path in item_paths)
        assert not locked(), "the fixture must first create a usable unlocked keyring"
        call("/org/freedesktop/secrets", service + ".Lock", "['" + collection + "']")
        assert locked(), "a successful Lock call alone is not evidence that the keyring is locked"

        # The initial object has a decrypted owner cached. A fresh process is required
        # to test opening a vault when its key store is locked at session startup.
        probe = "\n".join([
            "import json, sys",
            "from datafog_guard.config import DEFAULT_ENTITIES",
            "from datafog_guard.errors import GuardError",
            "from datafog_guard.store import EncryptedStore",
            "from datafog_guard.vault import Detector, Vault",
            "try:",
            "    v = Vault(EncryptedStore(sys.argv[1]), Detector(DEFAULT_ENTITIES))",
            "    v.health()",
            "except GuardError as error:",
            "    print(json.dumps({'code': error.code}))",
            "else:",
            "    print(json.dumps({'code': 'opened'}))",
        ])
        other = subprocess.run([sys.executable, "-c", probe, d], capture_output=True, text=True, timeout=15)
        assert other.returncode == 0, "locked-keyring probe crashed instead of returning a guard error"
        result = json.loads(other.stdout.strip())
        still_locked = locked()
        unchanged = all((Path(d) / name).read_bytes() == data for name, data in before_files.items())
        no_file_key = not (Path(d) / "workspace.key").exists()
        same_header = read_envelope_header(d) == before_header

        # Unlock only this session's throwaway login collection, then prove the original
        # mapping still works; no developer login keyring or credential is involved.
        assert result["code"] == "keystore_unavailable"
        assert still_locked and unchanged and same_header and no_file_key

        # --unlock starts a daemon; it does not unlock an already-running one.
        # Use GNOME's control-client UNLOCK protocol against only the fixture socket:
        # https://github.com/GNOME/gnome-keyring/blob/46.2/daemon/control/gkd-control-client.c
        import socket, struct
        password = b"synthetic-test-password\n"
        packet = struct.pack(">III", 12 + len(password), 1, len(password)) + password
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
            control.settimeout(5)
            control.connect(os.path.join(os.environ["GNOME_KEYRING_CONTROL"], "control"))
            control.sendall(b"\0" + packet)  # credentials byte, then framed UNLOCK request
            response = b""
            while len(response) < 8:
                chunk = control.recv(8 - len(response))
                assert chunk, "private daemon closed its unlock response"
                response += chunk
        assert struct.unpack(">II", response) == (8, 0), "private daemon rejected unlock"
        assert not locked(), "the private collection did not unlock for the recovery check"
        recovered = vault(d).restore(marker).text == EMAIL
        print(json.dumps({"code": result["code"], "still_locked": still_locked,
                          "unchanged": unchanged, "same_header": same_header, "no_file_key": no_file_key,
                          "same_entries": entries() == before_entries, "recovered": recovered}))
    """, timeout=75)
    assert seen["code"] == "keystore_unavailable"
    assert seen["still_locked"] is True, "the failing open must not silently unlock the collection"
    assert seen["unchanged"] and seen["same_header"], "the existing vault and marker index must not be rewritten"
    assert seen["no_file_key"] is True, "a locked key store must never trigger a file-key fallback"
    assert seen["same_entries"] and seen["recovered"], "unlocking must recover the original key and markers"
