"""With the engine broken in every way we can break it:

* PreToolUse denies (or the process exits 2, which Claude Code treats as a block),
* PostToolUse returns the tool's own shape with the content withheld,
* UserPromptSubmit blocks,
* and no real value appears in stdout, stderr or any file the engine writes.

Real values may appear only in ``updatedInput`` (not produced on these paths) and in the vault.
"""
from __future__ import annotations

import json
import os

import pytest
import shapes_recorded as recorded
from conftest import EMAIL, NOTES, SENTINELS, assert_no_sentinel, copy_vault
from datafog_guard.shapes import WITHHELD
from datafog_guard.store import FileVaultStore
from test_hook_protocol import same_shape


def break_corrupt_pointer(box):
    box.open_vault().tokenize(EMAIL)
    (box.vault / "HEAD").write_text("{ this is not json")


def break_corrupt_snapshot(box):
    box.open_vault().tokenize(EMAIL)
    pointer = json.loads((box.vault / "HEAD").read_text())
    snapshot = box.vault / "snapshots" / pointer["snapshot"]
    raw = bytearray(snapshot.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    snapshot.write_bytes(bytes(raw))


def break_locked(box):
    box.open_vault().tokenize(EMAIL)
    box._lock = FileVaultStore(str(box.vault)).lock()
    box._lock.__enter__()
    box.extra_env["DATAFOG_LOCK_TIMEOUT"] = "0.2"


def break_detector_import(box):
    fake = box.tmp / "fake" / "datafog_core"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("raise ImportError('synthetic import failure')\n")
    from conftest import ENGINE
    box.extra_env["PYTHONPATH"] = f"{box.tmp / 'fake'}{os.pathsep}{ENGINE}"


def break_detector_blind(box):
    """A detector that loads but finds nothing (what the 1.5.0 email regression looks like)."""
    fake = box.tmp / "fake"
    fake.mkdir()
    (fake / "sitecustomize.py").write_text(
        "import datafog_core\n"
        "datafog_core.scan = lambda text, config=None: []\n")
    from conftest import ENGINE
    box.extra_env["PYTHONPATH"] = f"{fake}{os.pathsep}{ENGINE}"


def break_unwritable_vault(box):
    box.vault.mkdir()
    os.chmod(box.vault, 0o500)
    if os.access(box.vault, os.W_OK):       # running as root: permissions do not bind, use a file in the way
        os.chmod(box.vault, 0o700)
        box.vault.rmdir()
        box.vault.write_text("not a directory")


def break_bad_config(box):
    (box.data / "config.json").write_text('{"entities": ["EMAIL", "NOT_A_TYPE"]}')


def break_config_not_json(box):
    (box.data / "config.json").write_text("allowlist: noreply@example.com")


def break_recall_capacity(box):
    from datafog_guard.vault import Detector, Vault
    filler = Vault(FileVaultStore(str(box.vault)), Detector(("EMAIL",)), recall_required=False)
    for start in range(0, 3500, 500):
        filler._commit([("API_KEY", f"k{number:07d}" * 12) for number in range(start, start + 500)])


BREAKS = {
    "corrupt_pointer": break_corrupt_pointer,
    "corrupt_snapshot": break_corrupt_snapshot,
    "locked_vault": break_locked,
    "detector_import_failure": break_detector_import,
    "detector_finds_nothing": break_detector_blind,
    "unwritable_vault": break_unwritable_vault,
    "unsupported_entity_in_config": break_bad_config,
    "config_not_json": break_config_not_json,
    "vault_past_recall_capacity": break_recall_capacity,
}


@pytest.fixture(params=sorted(BREAKS))
def broken(box, request):
    BREAKS[request.param](box)
    yield box
    lock = getattr(box, "_lock", None)
    if lock is not None:
        lock.__exit__(None, None, None)
    if box.vault.is_dir():
        os.chmod(box.vault, 0o700)


def check_clean(box, out, result):
    assert_no_sentinel(result.stdout.decode("utf-8", "replace"), "in hook stdout")
    assert_no_sentinel(result.stderr.decode("utf-8", "replace"), "in hook stderr")
    assert_no_sentinel(box.visible_files(), "in a file written by the engine")


PRE_CALLS = [
    ("Read", lambda box: {"file_path": str(box.write("notes.txt", NOTES))}),
    ("Bash", lambda box: {"command": f"echo {EMAIL}", "description": "x"}),
    ("Write", lambda box: {"file_path": str(box.project / "o.txt"), "content": "[[EMAIL_ABC123]] " + NOTES}),
    ("Edit", lambda box: {"file_path": "/p/a", "old_string": "a", "new_string": "[[EMAIL_ABC123]]"}),
    ("Grep", lambda box: {"pattern": EMAIL, "path": str(box.project)}),
    ("Glob", lambda box: {"pattern": "*.txt"}),
    ("WebFetch", lambda box: {"url": "https://example.com", "prompt": NOTES}),
    ("Agent", lambda box: {"prompt": NOTES, "description": "x", "subagent_type": "general-purpose"}),
    ("mcp__crm__lookup", lambda box: {"customer": EMAIL}),
    ("TodoWrite", lambda box: {"todos": []}),
]


@pytest.mark.parametrize("tool,make_input", PRE_CALLS, ids=[name for name, _ in PRE_CALLS])
def test_pre_tool_use_denies_when_the_engine_is_broken(broken, tool, make_input):
    out, result = broken.pre(tool, make_input(broken))
    check_clean(broken, out, result)
    if result.returncode == 2:
        assert out is None and result.stderr      # exit 2: Claude Code blocks the call
        return
    assert result.returncode == 0
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny", "nothing may run while output cannot be protected"
    assert "updatedInput" not in spec
    assert "/datafog:doctor" in spec["permissionDecisionReason"]


@pytest.mark.parametrize("tool", sorted(recorded.ALL))
def test_post_tool_use_withholds_in_the_tools_own_shape(broken, tool):
    tool_input, make = recorded.ALL[tool]
    response = make()
    out, result = broken.post(tool, tool_input, response)
    check_clean(broken, out, result)
    assert result.returncode == 0
    if tool == "Glob":
        assert out is None or out["hookSpecificOutput"]["updatedToolOutput"] == response   # file names only
        return
    new = out["hookSpecificOutput"]["updatedToolOutput"]
    same_shape(response, new)
    assert WITHHELD in json.dumps(new)


def test_withheld_read_keeps_type_path_and_numbers(broken):
    response = recorded.read()
    out, _ = broken.post("Read", {"file_path": "/project/notes.txt"}, response)
    new = out["hookSpecificOutput"]["updatedToolOutput"]
    assert new == {"type": "text", "file": {"content": WITHHELD, "filePath": "/project/notes.txt",
                                           "numLines": response["file"]["numLines"], "startLine": 1,
                                           "totalLines": response["file"]["totalLines"]}}


def test_withheld_bash_and_mcp(broken):
    new = broken.post("Bash", {"command": "x"}, recorded.bash(stderr="e"))[0]["hookSpecificOutput"]["updatedToolOutput"]
    assert new == {"stdout": WITHHELD, "stderr": WITHHELD, "interrupted": False, "isImage": False,
                   "noOutputExpected": False}
    new = broken.post(recorded.MCP_TOOL, {}, recorded.mcp())[0]["hookSpecificOutput"]["updatedToolOutput"]
    assert new == [{"type": "text", "text": WITHHELD}]


def test_prompt_is_blocked_when_the_engine_is_broken(broken):
    out, result = broken.prompt(f"please email {EMAIL}")
    check_clean(broken, out, result)
    assert out["decision"] == "block" and out["hookSpecificOutput"]["suppressOriginalPrompt"] is True


def test_own_commands_stay_usable_when_broken(broken):
    from conftest import ROOT
    out, result = broken.pre("Bash", {"command": f"sh {ROOT / 'scripts' / 'datafog-guard'} doctor"})
    assert out is None and result.returncode == 0
    assert broken.prompt("/datafog:doctor")[0] is None


def test_session_start_says_not_protecting(broken):
    out, result = broken.hook({"hook_event_name": "SessionStart", "source": "startup"})
    check_clean(broken, out, result)
    assert "NOT PROTECTING" in out["systemMessage"]


# -- inputs that break a healthy engine -------------------------------------------
def test_full_vault_denies_reads_of_new_values_and_withholds_output(box, full_vault_dir):
    copy_vault(full_vault_dir, box.vault)
    path = box.write("notes.txt", NOTES)
    out, result = box.pre("Read", {"file_path": str(path)})
    check_clean(box, out, result)
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny" and "vault is full" in spec["permissionDecisionReason"]
    out, result = box.post("Bash", {"command": "x"}, recorded.bash())
    check_clean(box, out, result)
    assert out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] == WITHHELD
    out, result = box.prompt(f"mail {EMAIL}")
    check_clean(box, out, result)
    assert out["decision"] == "block"
    # values the vault already holds are still handled
    out, _ = box.post("Bash", {"command": "x"}, recorded.bash(stdout="id v0000042\n"))
    assert "v0000042" not in out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def test_oversized_output_is_tokenized_in_chunks(box):
    line = f"row {{}} {EMAIL} {' '.join(SENTINELS[1:])} padding padding padding\n"
    big = "".join(line.format(number) for number in range(25_000))
    assert len(big) > 3 * 1024 * 1024
    out, result = box.post("Bash", {"command": "x"}, recorded.bash(stdout=big))
    check_clean(box, out, result)
    stdout = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert stdout.count("\n") == 25_000 and stdout.count("[[EMAIL_") == 25_000


def test_undecodable_text_in_tool_output_is_withheld(box):
    payload = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {},
                          "tool_response": recorded.bash(stdout="X")}).replace('"X"', f'"bad \\ud800 {EMAIL}"')
    result = box.run("hook", stdin=payload)
    out = json.loads(result.stdout)
    check_clean(box, out, result)
    assert out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] == WITHHELD


def test_value_too_large_to_store_denies_the_read(box):
    path = box.write("big.env", "DB=postgres://user:" + "p" * 40_000 + f"@db.example.com/x\nMAIL={EMAIL}\n")
    out, result = box.pre("Read", {"file_path": str(path)})
    check_clean(box, out, result)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("stdin", [b"", b"not json", b"[1,2]", b'{"hook_event_name": "PreToolUse"', b"\xff\xfe"])
def test_unreadable_hook_input_exits_2(box, stdin):
    result = box.run("hook", stdin=stdin)
    assert result.returncode == 2 and result.stdout == b"" and b"blocked" in result.stderr


def test_missing_environment_blocks_through_the_launcher(box):
    """No private Python environment yet: the launcher exits 2 for every hook."""
    import subprocess

    from conftest import ROOT
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/x"}})
    result = subprocess.run(["sh", str(ROOT / "scripts" / "datafog-guard"), "--data-dir", str(box.data), "hook"],
                            input=payload.encode(), capture_output=True, env={"PATH": os.environ["PATH"]})
    assert result.returncode == 2 and result.stdout == b""
    assert b"bootstrap" in result.stderr and b"blocked" in result.stderr
