"""Many short-lived processes plus a long-lived one on the same vault, and crashes mid-commit."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap

from conftest import EMAIL, ENGINE

WORKER = textwrap.dedent("""
    import json, sys
    from datafog_guard.config import DEFAULT_ENTITIES
    from datafog_guard.store import FileVaultStore
    from datafog_guard.vault import Detector, Vault
    vault_dir, worker, rounds = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    pairs = []
    for number in range(rounds):
        # a new Vault object each round, like a new hook process
        vault = Vault(FileVaultStore(vault_dir), Detector(DEFAULT_ENTITIES))
        unique = f"w{worker}n{number}.synthetic@example.com"
        shared = f"shared{number % 10}.synthetic@example.com"
        text = f"{unique} {shared}"
        out, counts = vault.tokenize(text)
        assert "@" not in out
        pairs.append([out, text])
    print(json.dumps(pairs))
""")

RESTORER = textwrap.dedent("""
    import json, sys, time
    from datafog_guard.config import DEFAULT_ENTITIES
    from datafog_guard.store import FileVaultStore
    from datafog_guard.vault import Detector, Vault
    vault = Vault(FileVaultStore(sys.argv[1]), Detector(DEFAULT_ENTITIES))   # long-lived, like the MCP server
    marker = vault.tokenize("seed.synthetic@example.com")[0]
    reloads, seen, checks = 0, None, 0
    deadline = time.time() + float(sys.argv[2])
    while time.time() < deadline:
        assert vault.restore(marker).text == "seed.synthetic@example.com"
        checks += 1
        if vault._head != seen:
            reloads += 1
            seen = vault._head
    print(json.dumps({"checks": checks, "reloads": reloads}))
""")


def spawn(script: str, *args) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", script, *map(str, args)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env={"PYTHONPATH": str(ENGINE), "PATH": "/usr/bin:/bin"})


def test_eight_processes_times_one_hundred_prepares_with_a_concurrent_restorer(box):
    workers, rounds = 8, 100
    restorer = spawn(RESTORER, box.vault, 4)
    processes = [spawn(WORKER, box.vault, worker, rounds) for worker in range(workers)]
    results = []
    for process in processes:
        out, err = process.communicate(timeout=300)
        assert process.returncode == 0, err[-2000:]
        results.extend(json.loads(out))
    out, err = restorer.communicate(timeout=60)
    assert restorer.returncode == 0, err[-2000:]
    observed = json.loads(out)
    assert observed["checks"] > 0 and observed["reloads"] > 1, "the long-lived process must notice new heads"

    assert len(results) == workers * rounds
    vault = box.open_vault()                      # a fresh process sees every marker: nothing was lost
    marker_of: dict[str, str] = {}
    for tokenized, original in results:
        assert vault.restore(tokenized).text == original
        for marker, value in zip(tokenized.split(), original.split()):
            assert marker_of.setdefault(value, marker) == marker, "one value, one marker, in every process"
    assert len(set(marker_of.values())) == len(marker_of) == workers * rounds + 10 + 0
    assert vault.entry_counts() == {"EMAIL": workers * rounds + 10 + 1}   # + the restorer's seed value
    vault.health()


CRASH_AFTER_SAVE = textwrap.dedent("""
    import os, sys
    from datafog_guard.config import DEFAULT_ENTITIES
    from datafog_guard.store import FileVaultStore
    from datafog_guard.vault import Detector, Vault

    class DiesAfterSave(FileVaultStore):
        def compare_and_save(self, expected, new, bundle, annotations):
            saved = super().compare_and_save(expected, new, bundle, annotations)
            if expected is not None:
                os._exit(137)          # killed after the save, before activate and before any text is released
            return saved

    vault = Vault(DiesAfterSave(sys.argv[1]), Detector(DEFAULT_ENTITIES))
    out, _ = vault.tokenize(sys.argv[2])
    print(out)                         # never reached
""")

CRASH_BEFORE_COMMIT_POINT = textwrap.dedent("""
    import os, sys
    import datafog_guard.store as store_module
    from datafog_guard.config import DEFAULT_ENTITIES
    from datafog_guard.vault import Detector, Vault

    real_replace = os.replace
    def replace(source, target):
        if os.path.basename(target) == "HEAD" and os.path.exists(target):
            os._exit(137)              # snapshot file written, pointer not yet switched
        return real_replace(source, target)
    store_module.os.replace = replace

    vault = Vault(store_module.FileVaultStore(sys.argv[1]), Detector(DEFAULT_ENTITIES))
    print(vault.tokenize(sys.argv[2])[0])
""")


def test_kill_between_save_and_activate(box):
    vault = box.open_vault()
    before, _ = vault.tokenize(f"first {EMAIL}")
    crashed = spawn(CRASH_AFTER_SAVE, box.vault, "second bob.synthetic@example.com")
    out, err = crashed.communicate(timeout=60)
    assert crashed.returncode == 137 and out == "", "no text may be released by the crashed process"

    survivor = box.open_vault()
    survivor.health()                                              # the vault is intact
    assert survivor.restore(before).text == f"first {EMAIL}"
    again, _ = survivor.tokenize("second bob.synthetic@example.com")
    assert survivor.restore(again).text == "second bob.synthetic@example.com"
    assert survivor.entry_counts() == {"EMAIL": 2}, "the saved entry is reused, not duplicated"


def test_kill_before_the_commit_point(box):
    vault = box.open_vault()
    before, _ = vault.tokenize(f"first {EMAIL}")
    head = json.loads((box.vault / "HEAD").read_text())
    crashed = spawn(CRASH_BEFORE_COMMIT_POINT, box.vault, "second bob.synthetic@example.com")
    out, _ = crashed.communicate(timeout=60)
    assert crashed.returncode == 137 and out == ""
    assert json.loads((box.vault / "HEAD").read_text()) == head, "the old vault is still the vault"
    survivor = box.open_vault()
    assert survivor.restore(before).text == f"first {EMAIL}"
    after, _ = survivor.tokenize("third carl.synthetic@example.com")
    assert box.open_vault().restore(after).text == "third carl.synthetic@example.com"
    leftovers = [path.name for path in (box.vault / "snapshots").iterdir()]
    assert len(leftovers) <= 3, "the orphaned snapshot is cleaned up by later saves"
