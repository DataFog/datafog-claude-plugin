"""The Bash wrap, run under real shells exactly as the PreToolUse hook rewrites a command."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest
from conftest import API_KEY, CARD, EMAIL, ENGINE, NOTES, PHONE, ROOT, SSN, assert_no_sentinel, corrupt_vault
from datafog_guard import bashwrap, config

SHELLS = [shell for shell in ("bash", "zsh") if shutil.which(shell)]
MODES = ["runner"]
PEM = ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
       "-----END PRIVATE KEY-----")


class Shell:
    """Runs commands through the wrap. The engine is started by a stand-in launcher that uses this
    test's Python instead of the plugin's private environment."""

    def __init__(self, box, shell: str, mode: str):
        self.box, self.shell, self.mode = box, shell, mode
        plugin = box.tmp / "plugin"
        (plugin / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts" / "wrap.sh", plugin / "scripts" / "wrap.sh")
        launcher = plugin / "scripts" / "datafog-guard"
        launcher.write_text(
            "#!/bin/sh\n"
            'while :; do case "$1" in\n'
            "  --data-dir) DATAFOG_DATA_DIR=$2; export DATAFOG_DATA_DIR; shift 2 ;;\n"
            "  --vault-dir) DATAFOG_VAULT_DIR=$2; export DATAFOG_VAULT_DIR; shift 2 ;;\n"
            "  *) break ;; esac; done\n"
            f'exec "{sys.executable}" -I "{ENGINE}/run.py" "$@"\n')
        launcher.chmod(0o755)
        os.environ.update(DATAFOG_DATA_DIR=str(box.data), DATAFOG_VAULT_DIR=str(box.vault),
                          CLAUDE_PLUGIN_ROOT=str(plugin))
        try:
            self.settings = config.load()
        finally:
            for name in ("DATAFOG_DATA_DIR", "DATAFOG_VAULT_DIR", "CLAUDE_PLUGIN_ROOT"):
                os.environ.pop(name, None)
        self.settings.bash_wrap = mode

    def wrapped(self, command: str) -> str:
        return bashwrap.wrap(command, self.settings)

    def run(self, command: str, *, already_wrapped: bool = False, stdin: bytes | None = None, env=None, timeout=120):
        script = command if already_wrapped else self.wrapped(command)
        environment = {"PATH": os.environ["PATH"], "HOME": str(self.box.tmp), "SHELL": shutil.which(self.shell)}
        environment.update(env or {})
        return subprocess.run([self.shell, "-c", script], input=stdin, capture_output=True, cwd=self.box.project,
                              env=environment, timeout=timeout)


@pytest.fixture(params=[(shell, mode) for shell in SHELLS for mode in MODES], ids=lambda p: f"{p[0]}-{p[1]}")
def sh(box, request) -> Shell:
    return Shell(box, *request.param)


@pytest.fixture(params=SHELLS)
def same(box, request) -> Shell:
    return Shell(box, request.param, "runner")


def test_at_least_bash_is_tested():
    assert "bash" in SHELLS


def test_stdout_is_tokenized_and_exit_code_zero(sh):
    sh.box.write("notes.txt", NOTES)
    result = sh.run("cat notes.txt")
    assert result.returncode == 0 and result.stderr == b""
    out = result.stdout.decode()
    assert_no_sentinel(out)
    assert out.count("[[") == 5 and out.count("\n") == NOTES.count("\n")
    assert sh.box.open_vault().restore(out).text == NOTES


@pytest.mark.parametrize("code", [1, 3, 127, 255])
def test_exit_code_is_preserved(sh, code):
    result = sh.run(f"echo before {EMAIL}; (exit {code})")
    assert result.returncode == code and EMAIL.encode() not in result.stdout


def test_failing_command_output_is_tokenized_on_both_streams(sh):
    """A failing Bash command goes to PostToolUseFailure, which cannot replace anything:
    the wrap is the only protection for this case."""
    sh.box.write("notes.txt", NOTES)
    result = sh.run("cat notes.txt; cat notes.txt >&2; cat /nonexistent/file")
    assert result.returncode in (1, 9)
    assert_no_sentinel(result.stdout.decode() + result.stderr.decode())
    assert b"[[EMAIL_" in result.stdout and b"[[EMAIL_" in result.stderr
    assert b"No such file" in result.stderr


def test_stdout_and_stderr_stay_separate(sh):
    result = sh.run(f"echo out {EMAIL}; echo err {PHONE} >&2")
    assert result.stdout.startswith(b"out [[EMAIL_") and result.stderr.startswith(b"err [[PHONE_")
    assert b"err" not in result.stdout and b"out" not in result.stderr


def test_quotes_pipes_and_substitution(sh):
    command = f"""printf '%s\\n' "it's {EMAIL}" 'say "hi"' | tr a-z A-Z | sed 's/HI/$(ok)/'; echo "$(echo {CARD})" `echo back`"""
    result = sh.run(command)
    out = result.stdout.decode()
    assert result.returncode == 0, result.stderr
    assert EMAIL.upper() not in out and CARD not in out
    assert 'SAY "$(ok)"' in out and "back" in out


def test_heredoc(sh):
    command = f"cat <<'EOF'\nline one {EMAIL}\n  $HOME `not run` \"quoted\"\nEOF\necho after"
    result = sh.run(command)
    out = result.stdout.decode()
    assert result.returncode == 0 and EMAIL not in out
    assert '  $HOME `not run` "quoted"\nafter\n' in out and out.startswith("line one [[EMAIL_")


def test_multi_line_script_and_last_status(sh):
    result = sh.run("for i in 1 2 3; do\n  echo \"n=$i\"\ndone\nfalse")
    assert result.stdout == b"n=1\nn=2\nn=3\n" and result.returncode == 1


def test_large_output(sh):
    sh.box.write("big.txt", "".join(f"{n} {EMAIL} {CARD} filler filler filler filler\n" for n in range(40_000)))
    result = sh.run("cat big.txt; echo done >&2")
    out = result.stdout.decode()
    assert result.returncode == 0 and len(out) > 2_000_000
    assert_no_sentinel(out)
    assert out.count("\n") == 40_000 and out.count("[[EMAIL_") == 40_000 and result.stderr == b"done\n"


def test_binary_output(sh):
    sh.box.write("blob.bin", bytes(range(256)) * 64 + b"\n" + EMAIL.encode() + b"\n" + bytes(range(255, -1, -1)))
    result = sh.run("cat blob.bin")
    assert result.returncode == 0 and EMAIL.encode() not in result.stdout
    assert bytes(range(128, 256)) in result.stdout and b"[[EMAIL_" in result.stdout


def test_value_written_in_pieces_across_read_boundaries(sh):
    """The command flushes half a value, pauses, then writes the rest."""
    half = len(EMAIL) // 2
    command = (f"printf 'a %s' '{EMAIL[:half]}'; sleep 0.3; printf '%s b\\n' '{EMAIL[half:]}'; "
               f"printf '{CARD[:7]}'; sleep 0.3; printf '{CARD[7:]}'; sleep 0.2; printf ' {SSN[:5]}'; sleep 0.2; "
               f"printf '{SSN[5:]} {API_KEY[:9]}'; sleep 0.2; echo '{API_KEY[9:]}'")
    result = sh.run(command)
    out = result.stdout.decode()
    assert_no_sentinel(out)
    for label in ("EMAIL", "CREDIT_CARD", "SSN", "API_KEY"):
        assert f"[[{label}_" in out


def test_multi_line_private_key(sh):
    sh.box.write("key.pem", PEM + "\n")
    result = sh.run("echo start; cat key.pem; echo end")
    out = result.stdout.decode()
    assert "MIIEvQ" not in out and "[[PRIVATE_KEY_" in out and out.startswith("start\n") and out.endswith("end\n")


def test_stdin_reaches_the_command(sh):
    result = sh.run("cat", stdin=f"typed {EMAIL}\n".encode())
    assert result.stdout.startswith(b"typed [[EMAIL_")


def test_no_output_and_true(sh):
    result = sh.run("true")
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""


def test_cd_is_seen_by_claude_codes_own_pwd_tracking(same):
    """Claude Code appends its own cwd bookkeeping after the command; the wrapper cds first."""
    (same.box.project / "sub").mkdir()
    result = same.run(same.wrapped("cd sub") + " && pwd -P >| " + str(same.box.tmp / "cwd"), already_wrapped=True)
    assert result.returncode == 0
    assert (same.box.tmp / "cwd").read_text().strip().endswith("/sub")


def test_user_aliases_and_functions_are_not_applied(same):
    """Documented limit: the command runs in a fresh, non-interactive child shell."""
    setup = "shopt -s expand_aliases 2>/dev/null; setopt aliases 2>/dev/null\nalias showmail='echo aliased'\n"
    result = same.run(setup + same.wrapped("showmail"), already_wrapped=True)
    assert result.returncode == 127 and b"aliased" not in result.stdout


def test_positional_parameters_are_not_exposed(same):
    result = same.run('echo "args:$#:$1:"')
    assert result.stdout == b"args:0::\n"


def test_exit_inside_the_command(same):
    result = same.run(f"echo before {EMAIL}; exit 4; echo never")
    assert result.returncode == 4
    assert result.stdout.startswith(b"before [[EMAIL_") and b"never" not in result.stdout


def test_filter_that_cannot_start_means_the_command_does_not_run(same):
    marker = same.box.tmp / "ran"
    same.box.vault.mkdir()
    corrupt_vault(same.box.vault)
    result = same.run(f"touch {marker}; echo {EMAIL}")
    assert result.returncode == 125 and not marker.exists(), "fail closed: the command must not have run"
    assert result.stdout == b"" and b"command was not run" in result.stderr


def test_missing_launcher_means_the_command_does_not_run(same):
    os.unlink(same.settings.launcher)
    marker = same.box.tmp / "ran"
    result = same.run(f"touch {marker}; echo {EMAIL}")
    assert result.returncode in (125, 126, 127) and not marker.exists() and EMAIL.encode() not in result.stdout


def test_vault_filling_up_mid_stream_withholds_the_rest(same, full_vault_dir):
    from conftest import copy_vault
    copy_vault(full_vault_dir, same.box.vault)
    result = same.run(f"echo known v0000001; echo new {EMAIL}; echo more {CARD}")
    out = result.stdout.decode()
    assert_no_sentinel(out)
    assert "v0000001" not in out and "output withheld" in out


def test_temp_files_are_cleaned_up(same):
    tmp = same.box.tmp / "t"
    tmp.mkdir()
    same.run("echo hi", env={"TMPDIR": str(tmp)})
    same.run("exit 3", env={"TMPDIR": str(tmp)})
    import time
    time.sleep(0.3)
    assert list(tmp.iterdir()) == []


