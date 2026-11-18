"""Where values and keys must never be, and the single message of an unsupported machine."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys

import pytest
import shapes_recorded as recorded
from conftest import EMAIL, NOTES, ROOT, SENTINELS, assert_no_sentinel
from datafog_guard.support import UNSUPPORTED, platform_problem


def key_forms(box) -> list[bytes]:
    key = (box.vault / "workspace.key").read_bytes()
    assert len(key) == 32
    return [key, key.hex().encode(), key.hex().upper().encode(), base64.b64encode(key), base64.urlsafe_b64encode(key)]


def test_the_vault_key_appears_in_no_output_log_or_file_outside_the_vault(box):
    path = box.write("notes.txt", NOTES)
    outputs = []
    for call in (lambda: box.hook({"hook_event_name": "SessionStart", "source": "startup"}),
                 lambda: box.pre("Read", {"file_path": str(path)}),
                 lambda: box.post("Bash", {"command": "x"}, recorded.bash(stdout=NOTES)),
                 lambda: box.pre("Bash", {"command": "echo [[EMAIL_ABC123]]"}),
                 lambda: box.prompt(f"mail {EMAIL}")):
        _, result = call()
        outputs.append(result.stdout + result.stderr)
    for name in ("status", "doctor"):
        result = box.run(name)
        outputs.append(result.stdout + result.stderr)
    everything = b"\n".join(outputs)
    for path in list(box.data.rglob("*")) + list(box.project.rglob("*")) + list(box.home.rglob("*")):
        if path.is_file():
            everything += path.read_bytes()
    for form in key_forms(box):
        assert form not in everything
    assert_no_sentinel(box.visible_files(), "in a file outside the vault")


def test_the_engine_never_handles_the_key_itself():
    """The key goes from the key store (or the key file) into core's native code. The Python engine
    never passes one in, so it cannot end up in a Python traceback, an argument list or the environment."""
    import re
    source = (ROOT / "engine" / "datafog_guard" / "store.py").read_text()
    calls = re.findall(r"ApplicationVault\.open\(([^)]*)\)", source)
    assert len(calls) == 1 and "key=" not in calls[0].replace("allow_file_key=", "")
    uses = [line.strip() for line in source.splitlines() if "KEY_FILE" in line]
    assert len(uses) == 2 and uses[0].startswith("ENVELOPE, LOCK_FILE, KEY_FILE, INDEX_FILE =") \
        and uses[1].startswith("for name in (ENVELOPE, KEY_FILE, INDEX_FILE"), "the key file is only ever deleted (purge)"


def test_no_value_or_key_in_argument_lists_or_environments_of_engine_processes(box):
    """While a hook process works on text full of values, its command line and environment hold none."""
    if not os.path.isdir("/proc/self"):
        pytest.skip("needs /proc")
    box.open_vault().tokenize(NOTES)
    code = ("import json, os, sys\n"
            "from datafog_guard import hook\n"
            "import datafog_guard.vault as vault\n"
            "real = vault.Vault._tokenize\n"
            "def spy(self, texts, limits):\n"
            "    out = real(self, texts, limits)\n"
            "    seen = open('/proc/self/cmdline', 'rb').read() + open('/proc/self/environ', 'rb').read()\n"
            "    open(os.environ['SPY_OUT'], 'wb').write(seen)\n"
            "    return out\n"
            "vault.Vault._tokenize = spy\n"
            "sys.exit(hook.main())\n")
    spy = box.tmp / "spy.bin"
    payload = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "x"},
                          "tool_response": recorded.bash(stdout=NOTES + "new.synthetic@example.com\n")})
    result = subprocess.run([sys.executable, "-c", code], input=payload.encode(), capture_output=True,
                            env=box.env(SPY_OUT=str(spy)), cwd=box.project)
    assert result.returncode == 0 and b"[[EMAIL_" in result.stdout
    seen = spy.read_bytes()
    for value in (*SENTINELS, "new.synthetic@example.com"):
        assert value.encode() not in seen
    for form in key_forms(box):
        assert form not in seen


def test_no_temporary_file_outside_the_vault_and_data_directories(box):
    scratch = box.tmp / "scratch"
    scratch.mkdir()
    path = box.write("notes.txt", NOTES)
    for call in (lambda: box.pre("Read", {"file_path": str(path)}, TMPDIR=str(scratch)),
                 lambda: box.post("Bash", {"command": "x"}, recorded.bash(stdout=NOTES), TMPDIR=str(scratch)),
                 lambda: box.pre("Write", {"file_path": str(box.project / "o.txt"), "content": "x"}, TMPDIR=str(scratch))):
        call()
    assert list(scratch.iterdir()) == [], "the engine and core's vault write nothing to the temp dir"
    for item in box.vault.iterdir():
        assert item.name in ("workspace.enc", "workspace.key", "workspace.lock", "markers.index", "bash-restore.key")


def test_error_messages_and_codes_never_carry_a_value_a_key_or_cores_own_text(box):
    from datafog_guard import store
    for code, (kind, message) in store._MESSAGES.items():
        error = store._translate(type("E", (Exception,), {"code": code})())
        assert isinstance(error, kind) and error.user_message == message
        assert error.code.replace("_", "").isalnum()
    odd = store._translate(type("E", (Exception,), {"code": f"weird {EMAIL} <code>"})(f"detail {EMAIL}"))
    assert EMAIL not in odd.code + odd.user_message and "@" not in odd.code


# -- an unsupported machine: one message, everywhere, and nothing runs unprotected ------------
def test_the_message_is_the_same_in_the_shell_and_in_the_engine():
    bootstrap = (ROOT / "scripts" / "bootstrap.sh").read_text()
    assert f"UNSUPPORTED='{UNSUPPORTED}'" in bootstrap
    assert "'" not in UNSUPPORTED and '"' not in UNSUPPORTED and "\\" not in UNSUPPORTED, "safe inside the shell's JSON line"
    assert platform_problem() is None, "the suite runs on a supported machine"
    readme = (ROOT / "README.md").read_text()
    assert "macOS on Apple Silicon" in readme and "glibc 2.38" in readme


@pytest.fixture
def other_machine(box):
    """A PATH in which `uname` reports a processor the plugin has no vault library for."""
    fake = box.tmp / "fakebin"
    fake.mkdir()
    (fake / "uname").write_text('#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo riscv64 ;; *) echo Linux ;; esac\n')
    (fake / "uname").chmod(0o755)
    return {"PATH": f"{fake}{os.pathsep}{os.environ['PATH']}", "HOME": str(box.tmp)}


def test_bootstrap_stops_before_installing_anything(box, other_machine):
    launcher = ["sh", str(ROOT / "scripts" / "datafog-guard"), "--data-dir", str(box.data)]
    result = subprocess.run([*launcher, "bootstrap"], capture_output=True, text=True, env=other_machine, timeout=60)
    assert result.returncode == 3 and result.stdout.strip() == UNSUPPORTED
    assert not (box.data / "venv").exists()


def test_session_start_and_every_hook_say_so_and_block(box, other_machine):
    launcher = ["sh", str(ROOT / "scripts" / "datafog-guard"), "--data-dir", str(box.data)]
    start = subprocess.run([*launcher, "session-start"], input='{"hook_event_name": "SessionStart"}',
                           capture_output=True, text=True, env=other_machine, timeout=60)
    assert json.loads(start.stdout) == {"systemMessage": UNSUPPORTED}
    for event in ("PreToolUse", "PostToolUse", "UserPromptSubmit"):
        payload = json.dumps({"hook_event_name": event, "tool_name": "Read", "tool_input": {"file_path": "/x"}})
        result = subprocess.run([*launcher, "hook"], input=payload, capture_output=True, text=True,
                                env=other_machine, timeout=60)
        assert result.returncode == 2 and result.stdout == "", "exit 2: Claude Code blocks the call"
        assert result.stderr.strip() == UNSUPPORTED
    for name in ("status", "doctor", "run"):
        result = subprocess.run([*launcher, name, "echo hi"], capture_output=True, text=True, env=other_machine, timeout=60)
        assert result.returncode == 2 and result.stderr.strip() == UNSUPPORTED and result.stdout == ""


@pytest.mark.parametrize("glibc, supported", [("glibc 2.38", True), ("glibc 2.39", True), ("glibc 3.0", True),
                                              ("glibc 2.37", False), ("glibc 2.28", False), ("", False),
                                              ("musl 1.2", False)])
def test_bootstrap_checks_the_c_library_on_linux(box, glibc, supported):
    fake = box.tmp / "fakebin"
    fake.mkdir()
    (fake / "uname").write_text('#!/bin/sh\ncase "$1" in -m) echo x86_64 ;; *) echo Linux ;; esac\n')
    (fake / "getconf").write_text(f'#!/bin/sh\n[ -n "{glibc}" ] || exit 1\necho "{glibc}"\n')
    for name in ("uname", "getconf"):
        (fake / name).chmod(0o755)
    sh = shutil.which("sh")
    result = subprocess.run([sh, str(ROOT / "scripts" / "bootstrap.sh"), "--platform"], capture_output=True, text=True,
                            env={"PATH": f"{fake}{os.pathsep}/usr/bin:/bin"})
    assert (result.returncode == 0) is supported
    assert result.stdout.strip() == ("" if supported else UNSUPPORTED)


def test_engine_on_a_machine_without_the_vault_library_gives_the_same_message(box):
    """The environment exists but the vault library does not load and the platform is not supported
    (for example a data directory copied from another machine)."""
    from test_fail_closed import break_unsupported_machine
    break_unsupported_machine(box)
    out, _ = box.pre("Read", {"file_path": "/x"})
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny" and UNSUPPORTED in reason
    start, _ = box.hook({"hook_event_name": "SessionStart", "source": "startup"})
    assert UNSUPPORTED in start["systemMessage"] and "NOT PROTECTING" in start["systemMessage"]
    assert UNSUPPORTED in box.run("status").stdout.decode()
    doctor = box.run("doctor")
    assert doctor.returncode == 1 and UNSUPPORTED in doctor.stdout.decode() and "[FAIL] supported machine" in doctor.stdout.decode()
