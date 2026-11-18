"""The Bash wrap as an output boundary.

Every test takes the exact command the PreToolUse hook returns and runs it under a real
shell, with stdout and stderr captured the way Claude Code captures them. Nothing the
command does may put a real value on the captured streams.

These started as reproductions from an adversarial review of the first (same-shell) wrap,
which leaked through EXIT traps, saved file descriptors and /proc.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

import pytest
from conftest import EMAIL, ENGINE, NOTES, ROOT, SSN, assert_no_sentinel, corrupt_vault

SHELLS = [shell for shell in ("bash", "zsh") if shutil.which(shell)]
LINUX_PROC = os.path.isdir("/proc/self/fd")


class Hooked:
    """Runs a command exactly as rewritten by the real PreToolUse hook."""

    def __init__(self, box, shell):
        self.box, self.shell = box, shell
        plugin = box.tmp / "plugin"
        (plugin / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts" / "wrap.sh", plugin / "scripts" / "wrap.sh")
        launcher = plugin / "scripts" / "datafog-guard"
        # Stand-in for the launcher: same option handling, this test's Python instead of the private venv.
        launcher.write_text(
            "#!/bin/sh\n"
            'while :; do case "$1" in\n'
            "  --data-dir) DATAFOG_DATA_DIR=$2; export DATAFOG_DATA_DIR; shift 2 ;;\n"
            "  --vault-dir) DATAFOG_VAULT_DIR=$2; export DATAFOG_VAULT_DIR; shift 2 ;;\n"
            "  *) break ;; esac; done\n"
            f'exec "{sys.executable}" -I "{ENGINE}/run.py" "$@"\n')
        launcher.chmod(0o755)
        self.plugin = plugin
        box.write("s.txt", NOTES)

    def command(self, command: str, **env) -> str:
        out, result = self.box.pre("Bash", {"command": command}, CLAUDE_PLUGIN_ROOT=str(self.plugin),
                                   DATAFOG_RESTORE_IN_BASH="allow", **env)
        assert result.returncode == 0, result.stderr
        return out["hookSpecificOutput"]["updatedInput"]["command"]

    def run(self, command: str, timeout: int = 60, extra: str = "", **env):
        script = self.command(command, **env) + extra
        # As under Claude Code, the shell that runs the command has a parent that holds the captured pipes.
        return subprocess.run(["sh", "-c", '"$0" -c "$1"', self.shell, script], capture_output=True,
                              cwd=self.box.project, timeout=timeout,
                              env={"PATH": os.environ["PATH"], "HOME": str(self.box.tmp),
                                   "SHELL": shutil.which(self.shell)})


@pytest.fixture(params=SHELLS)
def hooked(box, request) -> Hooked:
    return Hooked(box, request.param)


def captured(result) -> str:
    return result.stdout.decode("utf-8", "replace") + result.stderr.decode("utf-8", "replace")


# -- the five reproductions from the review ------------------------------------------
REPRODUCTIONS = {
    "exit_trap": "trap 'cat s.txt' EXIT; true",
    "exit_trap_with_set_e": "set -e; trap 'cat s.txt' EXIT; false",
    "saved_fd_10": "cat s.txt >&10",
    "proc_ppid_fd": "cat s.txt > /proc/$PPID/fd/1",
    "proc_filter_fd": "for p in $(pgrep -f 'engine/run[.]py'); do [ $p = $$ ] || cat s.txt >/proc/$p/fd/1; done",
}


@pytest.mark.parametrize("name", sorted(REPRODUCTIONS))
def test_review_reproductions_do_not_leak(hooked, name):
    if "proc" in name and not LINUX_PROC:
        pytest.skip("needs /proc")
    if name == "proc_filter_fd" and os.geteuid() == 0 and not os.environ.get("DATAFOG_TEST_AS_ROOT_ANYWAY"):
        pytest.skip("root may open any process's descriptors; see test_unprivileged_command_cannot_open_the_relays_descriptors")
    result = hooked.run(REPRODUCTIONS[name])
    assert_no_sentinel(captured(result), f"through {name}")


def test_exit_trap_output_is_still_delivered_tokenized(hooked):
    result = hooked.run("trap 'cat s.txt' EXIT; true")
    assert result.stdout.count(b"[[") == 5, "the trap's output goes through the filter, not around it"


# -- other ways to reach the captured streams --------------------------------------------
ATTEMPTS = [
    "exec 3>&1; cat s.txt >&3",
    "exec 3>&2; cat s.txt >&3",
    "cat s.txt >/dev/stdout",
    "cat s.txt >/dev/stderr",
    "cat s.txt >/dev/fd/1",
    "cat s.txt >/dev/fd/2",
    "cat s.txt >/dev/tty",
    "cat s.txt >/proc/self/fd/1",
    "for fd in 3 4 5 6 7 8 9 10 11 12 19 63 255; do cat s.txt >&$fd; done 2>/dev/null; true",
    "for p in /proc/$PPID /proc/$$; do for fd in $p/fd/*; do cat s.txt > $fd; done; done 2>/dev/null; true",
    "pp=$(ps -o ppid= -p $PPID | tr -d ' '); cat s.txt > /proc/$pp/fd/1; true",
    "exec cat s.txt",
    "set -m; cat s.txt & wait",
    "trap 'cat s.txt' TERM INT HUP EXIT; kill -TERM $$; sleep 1",
    "bash -c 'trap \"cat s.txt\" EXIT'",
    "nohup cat s.txt",
    "(setsid cat s.txt) ; sleep 0.3",
]


@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_nothing_reaches_the_captured_streams(hooked, attempt):
    result = hooked.run(attempt)
    assert_no_sentinel(captured(result), f"through: {attempt}")


def test_dev_tty_is_not_available_to_the_command(hooked):
    """Decision: the command runs in its own session with no controlling terminal."""
    result = hooked.run("cat s.txt >/dev/tty; echo status=$?")
    assert b"status=0" not in result.stdout
    assert_no_sentinel(captured(result))


def test_no_inherited_descriptor_above_2_in_the_command(hooked):
    if not LINUX_PROC:
        pytest.skip("needs /proc")
    script = f"exec 7>{hooked.box.tmp}/leak-me\n" + hooked.command("ls /proc/self/fd | tr '\\n' ' '")
    result = subprocess.run([hooked.shell, "-c", script], capture_output=True, cwd=hooked.box.project,
                            env={"PATH": os.environ["PATH"], "HOME": str(hooked.box.tmp)})
    listed = {int(n) for n in result.stdout.split()}
    assert listed <= {0, 1, 2, 3}, listed     # 3 is ls's own handle on the directory


def test_no_ancestor_of_the_command_holds_the_captured_stream(hooked):
    """On Linux: walk up from the command and compare every descriptor of every ancestor
    with the pipe the test captures stdout on."""
    if not LINUX_PROC:
        pytest.skip("needs /proc")
    probe = hooked.box.write("probe.sh", (
        "p=$$\n"
        "while [ \"$p\" -gt 1 ] 2>/dev/null; do\n"
        "  for fd in /proc/$p/fd/*; do printf '%s %s %s\\n' \"$p\" \"$fd\" \"$(readlink $fd 2>/dev/null)\"; done\n"
        "  p=$(awk '/^PPid:/ {print $2}' /proc/$p/status 2>/dev/null)\n"
        "done\n"))
    read_end, write_end = os.pipe()
    capture = os.readlink(f"/proc/self/fd/{write_end}")
    process = subprocess.Popen([hooked.shell, "-c", hooked.command(f"sh {probe}")], stdout=write_end,
                               stderr=subprocess.PIPE, cwd=hooked.box.project,
                               env={"PATH": os.environ["PATH"], "HOME": str(hooked.box.tmp)})
    os.close(write_end)
    out = b""
    while chunk := os.read(read_end, 65536):
        out += chunk
    process.wait()
    lines = out.decode().splitlines()
    assert lines, process.stderr.read()
    holders = [line for line in lines if line.endswith(" " + capture)]
    assert not holders, "an ancestor of the command has the captured stdout open:\n" + "\n".join(holders)
    assert len({line.split()[0] for line in lines}) >= 2, "the walk covered the command and its parent"


AS_NOBODY = """
import json, subprocess, sys
result = subprocess.run(["sh", "-c", '"$0" -c "$1"', "bash", sys.argv[1]], capture_output=True)   # pipes owned by this user
print(json.dumps({"out": result.stdout.decode("utf-8", "replace") + result.stderr.decode("utf-8", "replace")}))
"""


def run_as_unprivileged_user(box, command: str) -> str:
    """Run the hooked command as user nobody, with the capture pipes created by that same user
    (as Claude Code's are). Needs root to switch user."""
    import json
    switch = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]
    if subprocess.run([*switch, sys.executable, "-I", "-c", "import datafog_core"], capture_output=True).returncode:
        pytest.skip("this Python installation is not readable by the unprivileged test user")
    hooked = Hooked(box, "bash")
    wrapped = hooked.command(command)
    subprocess.run(["chown", "-R", "65534:65534", str(box.tmp)], check=True)
    path = box.tmp
    while path.parent != path:
        try:
            # Search AND read: core's ApplicationVault opens every directory above the vault to flush
            # it, and fails where the user may not list one (test_store.py pins that limit).
            os.chmod(path, os.stat(path).st_mode | 0o055)
        except OSError:
            pass
        path = path.parent
    try:
        result = subprocess.run([*switch, sys.executable, "-I", "-c", AS_NOBODY, wrapped], capture_output=True, cwd=box.project, timeout=60,
                                env={"PATH": os.environ["PATH"], "HOME": str(box.tmp)})
    finally:
        subprocess.run(["chown", "-R", f"{os.getuid()}:{os.getgid()}", str(box.tmp)], check=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["out"]


needs_user_switch = pytest.mark.skipif(not LINUX_PROC or os.geteuid() != 0 or not shutil.which("setpriv"),
                                       reason="needs Linux, root and setpriv to run the command as another user")


@needs_user_switch
def test_unprivileged_command_cannot_open_the_relays_descriptors(box):
    """Review reproduction 5. The relay and the monitor are non-dumpable, so a process of the same
    user cannot open /proc/<their pid>/fd/*."""
    out = run_as_unprivileged_user(
        box, "for p in $(pgrep -f 'engine/run[.]py'); do [ $p = $$ ] || cat s.txt > /proc/$p/fd/1; done 2>/dev/null; "
             "for p in $(pgrep -f 'engine/run[.]py'); do [ $p = $$ ] || cat s.txt > /proc/$p/fd/2; done 2>/dev/null; "
             "echo swept $(pgrep -f 'engine/run[.]py' | wc -l)")
    assert "swept" in out and "swept 0" not in out and "swept 1\n" not in out
    assert_no_sentinel(out)


@needs_user_switch
@pytest.mark.xfail(strict=False, reason="KNOWN RESIDUAL on Linux: Claude Code's own shell (an ancestor of the relay, "
                   "not of the command) holds the captured pipe and any process of the same user can reopen it "
                   "through /proc/<pid>/fd. A plugin cannot change that; it needs an OS sandbox.")
def test_known_residual_sweeping_proc_for_any_process_of_the_user(box):
    out = run_as_unprivileged_user(
        box, "for p in $(pgrep -u $(id -u)); do [ $p = $$ ] || cat s.txt > /proc/$p/fd/1; done 2>/dev/null; echo swept")
    assert "swept" in out
    assert_no_sentinel(out)


# -- background jobs ---------------------------------------------------------------------
@pytest.mark.parametrize("command", [
    "(sleep 1; cat s.txt) & echo started",
    "(sleep 1; cat s.txt) & disown; echo started",
    "(sleep 6; cat s.txt) & echo started",
    "nohup sh -c 'sleep 6; cat s.txt' >/dev/stdout 2>&1 & echo started",
])
def test_background_job_writing_after_the_command_returned(hooked, command):
    started = time.time()
    result = hooked.run(command, timeout=40)
    took = time.time() - started
    assert result.returncode == 0 and b"started" in result.stdout
    assert_no_sentinel(captured(result))
    assert took < 5.5, "the wait for background output is bounded"
    time.sleep(max(0, 7 - took) if "sleep 6" in command else 0)   # let the job finish: it must not find a way out


def test_background_output_within_the_grace_period_is_delivered_tokenized(hooked):
    result = hooked.run("(sleep 0.5; cat s.txt) & echo started")
    assert result.stdout.count(b"[[") == 5


# -- attacking the filter -----------------------------------------------------------------
@pytest.mark.parametrize("command", [
    "pkill -f run.py; sleep 0.2; cat s.txt",
    "pkill -KILL -f run.py; sleep 0.2; cat s.txt",
    "kill -KILL $PPID; sleep 0.2; cat s.txt",
    "kill -STOP $PPID; cat s.txt; kill -CONT $PPID",
])
def test_killing_the_filter_loses_output_but_never_leaks(hooked, command):
    result = hooked.run(command, timeout=40)
    assert_no_sentinel(captured(result))


def test_replacing_the_filter_programs_on_path_changes_nothing(hooked):
    fake = hooked.box.tmp / "fakebin"
    fake.mkdir()
    for name in ("python", "python3", "sh", "datafog-guard"):
        (fake / name).write_text("#!/bin/sh\ncat \"$@\" 2>/dev/null; cat\n")
        (fake / name).chmod(0o755)
    result = hooked.run(f"export PATH={fake}:$PATH; cat s.txt; hash -r; cat s.txt")
    assert_no_sentinel(captured(result))
    assert result.stdout.count(b"[[") == 10


# -- what must keep working ------------------------------------------------------------------
def test_exit_code_streams_and_stdin(hooked):
    result = hooked.run(f"echo out {EMAIL}; echo err {SSN} >&2; (exit 7)")
    assert result.returncode == 7
    assert result.stdout.startswith(b"out [[EMAIL_") and result.stderr.startswith(b"err [[SSN_")
    assert b"err" not in result.stdout and b"out" not in result.stderr


def test_cd_in_one_call_is_visible_in_the_next(hooked):
    (hooked.box.project / "sub dir").mkdir()
    hooked.box.write("sub dir/inner.txt", f"inner {EMAIL}\n")
    script = hooked.command("cd 'sub dir'") + "\n" + hooked.command("pwd; cat inner.txt") + '\necho "outer: $(pwd)"'
    result = subprocess.run([hooked.shell, "-c", script], capture_output=True, cwd=hooked.box.project,
                            env={"PATH": os.environ["PATH"], "HOME": str(hooked.box.tmp)})
    out = result.stdout.decode()
    assert result.returncode == 0, result.stderr
    assert f"{hooked.box.project}/sub dir\ninner [[EMAIL_" in out and out.rstrip().endswith("/sub dir")


def test_cd_survives_a_failing_command_but_not_exit(hooked):
    (hooked.box.project / "sub").mkdir()
    result = hooked.run("cd sub; false", extra="; pwd")
    assert result.stdout.decode().strip().endswith("/sub")
    result = hooked.run("cd sub; exit 3", extra="; pwd")
    assert result.stdout.decode().strip() == str(hooked.box.project), "same as Claude Code's own cwd tracking"


def test_variables_and_functions_do_not_persist(hooked):
    """Documented limit of running each command in its own shell."""
    script = hooked.command("export DF_T=1; f() { echo fn; }") + "\n" + hooked.command('echo "[$DF_T]"; f || echo nofn')
    result = subprocess.run([hooked.shell, "-c", script], capture_output=True, cwd=hooked.box.project,
                            env={"PATH": os.environ["PATH"], "HOME": str(hooked.box.tmp)})
    assert b"[]" in result.stdout and b"nofn" in result.stdout


def test_command_does_not_run_unless_the_filter_is_healthy(hooked):
    command = hooked.command(f"touch {hooked.box.tmp}/ran; echo {EMAIL}")
    corrupt_vault(hooked.box.vault)
    result = subprocess.run([hooked.shell, "-c", command], capture_output=True, cwd=hooked.box.project,
                            env={"PATH": os.environ["PATH"], "HOME": str(hooked.box.tmp)})
    assert result.returncode == 125 and not (hooked.box.tmp / "ran").exists()
    assert_no_sentinel(captured(result))


def test_colour_is_discouraged_in_the_command_environment(hooked):
    result = hooked.run('echo "$NO_COLOR/$CLICOLOR"')
    assert result.stdout.strip() == b"1/0"


def test_timeout_kill_of_the_wrapper_takes_the_command_with_it(hooked):
    marker = hooked.box.tmp / "alive"
    process = subprocess.Popen([hooked.shell, "-c", hooked.command(f"sleep 2; touch {marker}")],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=hooked.box.project,
                               env={"PATH": os.environ["PATH"], "HOME": str(hooked.box.tmp)}, start_new_session=True)
    time.sleep(0.8)
    os.killpg(process.pid, 15)
    process.wait(timeout=10)
    time.sleep(2.5)
    assert not marker.exists(), "the command must not outlive a cancelled tool call"
