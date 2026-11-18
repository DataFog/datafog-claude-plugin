"""Many short-lived processes plus a long-lived one on the same vault, and processes killed mid-way.

Hooks are separate short processes that may run in parallel; the MCP server and the Bash runner
live longer. All of them share one encrypted vault file and one marker index."""
from __future__ import annotations

import json
import os
import random
import signal
import subprocess
import sys
import textwrap
import time

from conftest import EMAIL, ENGINE, ROOT

OPEN = textwrap.dedent("""
    import json, os, sys, time
    sys.path.insert(0, sys.argv.pop(1))
    from conftest import open_test_vault
""")

WORKER = OPEN + textwrap.dedent("""
    vault_dir, worker, rounds = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    pairs = []
    for number in range(rounds):
        vault = open_test_vault(vault_dir)     # a new Vault object each round, like a new hook process
        unique = f"w{worker}n{number}.synthetic@example.com"
        shared = f"shared{number % 10}.synthetic@example.com"
        text = f"{unique} {shared}"
        out, counts = vault.tokenize(text)
        assert "@" not in out
        assert vault.restore(out).text == text
        pairs.append([out, text])
        vault.store.close()
    print(json.dumps(pairs))
""")

RESTORER = OPEN + textwrap.dedent("""
    vault = open_test_vault(sys.argv[1])       # long-lived, like the MCP server
    marker = vault.tokenize("seed.synthetic@example.com")[0]
    sizes, checks = set(), 0
    deadline = time.time() + float(sys.argv[2])
    while time.time() < deadline:
        assert vault.restore(marker).text == "seed.synthetic@example.com"
        assert vault.tokenize("seed.synthetic@example.com")[0] == marker
        sizes.add(sum(vault.entry_counts().values()))
        checks += 1
    print(json.dumps({"checks": checks, "sizes": len(sizes)}))
""")


def spawn(script: str, *args) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", script, str(ROOT / "tests"), *map(str, args)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env={"PYTHONPATH": str(ENGINE), "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})


def test_eight_processes_times_one_hundred_prepares_with_a_concurrent_restorer(box):
    workers, rounds = 8, 100
    restorer = spawn(RESTORER, box.vault, 4)
    processes = [spawn(WORKER, box.vault, worker, rounds) for worker in range(workers)]
    results = []
    for process in processes:
        out, err = process.communicate(timeout=600)
        assert process.returncode == 0, err[-2000:]
        results.extend(json.loads(out))
    out, err = restorer.communicate(timeout=120)
    assert restorer.returncode == 0, err[-2000:]
    observed = json.loads(out)
    assert observed["checks"] > 0 and observed["sizes"] > 1, "the long-lived process must see other processes' values"

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
    # every value is known without asking core to write again: tokenizing them all changes nothing
    from datafog_guard.store import read_envelope_header
    before = read_envelope_header(str(box.vault))["revision"]
    out, _ = vault.tokenize(" ".join(marker_of))
    assert out.split() == list(marker_of.values())
    assert read_envelope_header(str(box.vault))["revision"] == before


def test_parallel_hook_processes_through_the_real_entry_point(box):
    """Twelve PostToolUse hooks at once, as Claude Code starts them for parallel tool calls."""
    import shapes_recorded as recorded
    payloads = []
    for number in range(12):
        text = f"row {number} user{number}.synthetic@example.com and {EMAIL}\n"
        payloads.append(json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "x"},
                                    "tool_response": recorded.bash(stdout=text), "cwd": str(box.project)}))
    running = [subprocess.Popen([sys.executable, "-m", "datafog_guard", "hook"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=box.env(), cwd=box.project)
               for _ in payloads]
    outputs = [process.communicate(payload.encode(), timeout=120) for process, payload in zip(running, payloads)]
    shared = set()
    vault = box.open_vault()
    for number, (out, err) in enumerate(outputs):
        stdout = json.loads(out)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        assert "@" not in stdout, err
        assert vault.restore(stdout).text == f"row {number} user{number}.synthetic@example.com and {EMAIL}\n"
        shared.add(stdout.split()[-1])
    assert len(shared) == 1, "the shared value has one marker in all twelve processes"
    assert vault.entry_counts() == {"EMAIL": 13}


DIES_AFTER_COMMIT = OPEN + textwrap.dedent("""
    vault = open_test_vault(sys.argv[1])
    real = vault.store.commit
    def commit(pairs):
        real(pairs)
        os._exit(137)      # killed after core saved the markers: before the index is written and before any text is released
    vault.store.commit = commit
    print(vault.tokenize(sys.argv[2])[0])     # never reached
""")

DIES_BEFORE_INDEX = OPEN + textwrap.dedent("""
    vault = open_test_vault(sys.argv[1])
    vault.store.add_to_index = lambda markers: os._exit(137)    # markers saved and checked, index not written
    print(vault.tokenize(sys.argv[2])[0])     # never reached
""")


def test_kill_between_commit_and_release(box):
    vault = box.open_vault()
    before, _ = vault.tokenize(f"first {EMAIL}")
    for script in (DIES_AFTER_COMMIT, DIES_BEFORE_INDEX):
        crashed = spawn(script, box.vault, "second bob.synthetic@example.com")
        out, err = crashed.communicate(timeout=60)
        assert crashed.returncode == 137 and out == "", "no text may be released by the crashed process"
    survivor = box.open_vault()
    survivor.health()                                              # the vault is intact
    assert survivor.restore(before).text == f"first {EMAIL}"
    assert survivor.entry_counts() == {"EMAIL": 1}, "the index does not know the value the dead process stored"
    again, _ = survivor.tokenize("second bob.synthetic@example.com")
    assert survivor.restore(again).text == "second bob.synthetic@example.com"
    assert box.open_vault().entry_counts() == {"EMAIL": 2}, "the saved entry is reused and noted, not duplicated"
    assert box.open_vault().tokenize("second bob.synthetic@example.com")[0] == again


LOOP = OPEN + textwrap.dedent("""
    number = 0
    while True:
        vault = open_test_vault(sys.argv[1])
        text = f"k{sys.argv[2]}n{number}.synthetic@example.com"
        out, _ = vault.tokenize(text)
        print(json.dumps([out, text]), flush=True)      # released: from here on it must restore forever
        number += 1
""")


def test_sigkill_at_random_moments_never_damages_the_vault(box):
    """Writers are killed with SIGKILL while they commit. Whatever they released still restores,
    the vault still opens, and no temporary file with a value is left behind."""
    rng = random.Random(7)
    released = []
    box.open_vault().tokenize(f"first {EMAIL}")
    for round_number in range(12):
        writers = [spawn(LOOP, box.vault, f"{round_number}x{index}") for index in range(3)]
        first = [writer.stdout.readline() for writer in writers]      # every writer is past start-up and committing
        time.sleep(rng.uniform(0.0, 0.12))
        for writer in writers:
            os.kill(writer.pid, signal.SIGKILL)
        for line, writer in zip(first, writers):
            out, _ = writer.communicate(timeout=30)
            released.extend(json.loads(text) for text in (line + out).splitlines() if text.endswith("]"))
    assert len(released) > 30
    vault = box.open_vault()
    vault.health()
    for tokenized, original in released:
        assert vault.restore(tokenized).text == original
    assert vault.tokenize(f"first {EMAIL}")[0] == f"first {box.open_vault().tokenize(EMAIL)[0]}"
    for path in box.vault.iterdir():
        assert b"synthetic@example.com" not in path.read_bytes(), path.name
    leftovers = [path.name for path in box.vault.iterdir()
                 if path.name not in ("workspace.enc", "workspace.key", "workspace.lock", "markers.index")]
    assert len(leftovers) <= 12 * 3, "at most one unfinished temporary file per killed writer"
    later, _ = box.open_vault().tokenize("after.synthetic@example.com")
    assert box.open_vault().restore(later).text == "after.synthetic@example.com"
