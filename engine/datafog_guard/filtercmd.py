"""``datafog_guard run``: runs one Bash command behind an output boundary.

The command must never be able to write to the stdout and stderr that Claude Code
captures. So it does not share a process, a descriptor table or an ancestor with them:

    Claude Code's shell             holds the captured stdout/stderr
      └─ relay (this process)       holds them too; reads two pipes, tokenizes, writes
           └─ A                     setsid(), forks the monitor, exits at once
    init (or a subreaper)
      └─ monitor                    orphaned on purpose; holds no pipe and no captured stream
           └─ the command's shell   stdout and stderr are the two pipes, stdin is the caller's
                                    stdin (or /dev/null), every other descriptor is closed

* Whatever the command does - EXIT traps, `exec 3>&1`, `>&10`, /dev/stdout, /dev/fd/N -
  it can only reach the pipes, because nothing else is open in its process.
* Its parent (the monitor) and that parent's parent (init) do not hold the captured
  streams, so /proc/$PPID/fd/1 leads nowhere useful.
* The relay marks itself non-dumpable on Linux, so other processes of the same user
  cannot open its descriptors through /proc/<pid>/fd.
* The command gets its own session: no controlling terminal, so /dev/tty cannot be opened.
* The command is started only after the vault opened and the detector passed its self-test.

What this does not do: Claude Code's own shell, an ancestor of the relay, also holds the
captured streams and is visible in /proc to processes of the same user. A command that
deliberately searches /proc for such a process can still write to it. Closing that
needs an OS sandbox; see the README's threat model.

The child shell loses state between calls. The working directory is carried over: the
child records its final directory in a private file and the wrapper `cd`s there.
Variables, functions and aliases are not carried over.

``datafog_guard filter`` is the plain stdin-to-stdout tokenizer.
"""
from __future__ import annotations

import os
import sys

from .stream import StreamTokenizer, pump

GRACE_SECONDS = 3.0     # how long output of lingering background children is still relayed
# The child shell reads the command from descriptor 3 (a pipe from the monitor) instead of
# receiving it as an argument: with values restored, the command must not sit in the argument
# list of a process (`ps` shows that to every user). Descriptor 3 is closed before the command runs.
CHILD_SCRIPT = (
    '__datafog_f=$1\n'
    'shift\n'
    'if [ -n "${BASH_VERSION-}${ZSH_VERSION-}" ]; then IFS= read -r -d \'\' __datafog_c <&3\n'
    'else __datafog_c=$(cat <&3; printf x); __datafog_c=${__datafog_c%x}; fi\n'
    'exec 3<&-\n'
    'eval "$__datafog_c"\n'
    '__datafog_r=$?\n'
    'pwd -P >"$__datafog_f" 2>/dev/null\n'
    'exit "$__datafog_r"\n'
)


def _vault():
    from .engine import open_vault
    vault, settings = open_vault()
    vault.health()
    return vault, settings


def _log(settings, mode, tokenizers, code=None, restored=None):
    from . import log
    counts: dict = {}
    for tokenizer in tokenizers:
        for name, number in tokenizer.counts.items():
            counts[name] = counts.get(name, 0) + number
    extra = {"restored": restored} if restored else {}
    log.write(settings.log_path, event="BashFilter", mode=mode, replaced=counts,
              withheld=any(t.failed for t in tokenizers), exit_code=code, **extra)


def filter_stdin() -> int:
    """stdin -> stdout."""
    try:
        vault, settings = _vault()
    except Exception:
        sys.stderr.write("datafog: the output filter cannot start; output withheld\n")
        try:
            while sys.stdin.buffer.read(65536):
                pass
        except Exception:
            pass
        return 125
    tokenizer = StreamTokenizer(vault)
    pump(sys.stdin.buffer, sys.stdout.buffer, tokenizer)
    _log(settings, "stdin", [tokenizer])
    return 0


def pick_shell() -> str:
    shell = os.environ.get("SHELL", "")
    if os.path.basename(shell) in ("bash", "zsh") and os.path.isabs(shell) and os.access(shell, os.X_OK):
        return shell
    for candidate in ("/bin/bash", "/usr/bin/bash", "/bin/zsh", "/bin/sh"):
        if os.access(candidate, os.X_OK):
            return candidate
    return "/bin/sh"


def _make_undumpable() -> None:
    """Linux: other processes of this user can then not open /proc/<our pid>/fd/*."""
    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)    # PR_SET_DUMPABLE = 4
    except Exception:
        pass


def _same_file(fd_a: int, fd_b: int) -> bool:
    try:
        a, b = os.fstat(fd_a), os.fstat(fd_b)
    except OSError:
        return False
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _child_env() -> dict:
    env = {key: value for key, value in os.environ.items() if not key.startswith("DATAFOG_")}
    # Defence in depth only: colour codes split values; detection does not rely on this.
    env.update(NO_COLOR="1", CLICOLOR="0")
    env.pop("CLICOLOR_FORCE", None)
    env.pop("FORCE_COLOR", None)
    return env


def _monitor(command: bytes, shell: str, cwd_file: str, out_w: int, err_w: int, status_w: int, life_r: int) -> None:
    """Runs orphaned, in its own session. Starts the command, waits, reports its status. Never returns."""
    import signal
    code = 125
    try:
        cmd_r, cmd_w = os.pipe()
        wake_r, wake_w = os.pipe()
        os.set_blocking(wake_w, False)
        signal.set_wakeup_fd(wake_w)
        signal.signal(signal.SIGCHLD, lambda *_: None)
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, signal.SIG_IGN)       # group-wide signals are meant for the command
        stdin_ok = not (_same_file(0, 1) or _same_file(0, 2))
        child = os.fork()
        if child == 0:
            try:
                for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGCHLD, signal.SIGPIPE):
                    signal.signal(number, signal.SIG_DFL)
                signal.set_wakeup_fd(-1)
                if not stdin_ok:
                    null = os.open(os.devnull, os.O_RDONLY)
                    os.dup2(null, 0)
                os.dup2(out_w, 1)
                os.dup2(err_w, 2)
                if cmd_r != 3:
                    os.dup2(cmd_r, 3)
                os.set_inheritable(3, True)
                os.closerange(4, _max_fd())
                os.execve(shell, [shell, "-c", CHILD_SCRIPT, "datafog", cwd_file], _child_env())
            finally:
                os._exit(127)
        # The monitor keeps nothing the command could use: no pipe ends, no captured stream.
        null = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        for fd in (out_w, err_w, null, cmd_r):
            os.close(fd)
        try:
            # Only now is the command handed over: the child shell waits for it on descriptor 3 and
            # starts it when this end is closed. EPIPE means the shell did not start; its status says so.
            view = memoryview(command)
            while view:
                view = view[os.write(cmd_w, view):]
        except OSError:
            pass
        os.close(cmd_w)
        import select
        while True:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid:
                code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else \
                    (os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status))
                code = code if code >= 0 else 128 - code
                break
            ready, _, _ = select.select([wake_r, life_r], [], [], 5.0)
            if wake_r in ready:
                try:
                    os.read(wake_r, 512)
                except OSError:
                    pass
            if life_r in ready and not os.read(life_r, 64):
                # The relay is gone (tool call cancelled or timed out): stop the command.
                _kill_group(signal.SIGTERM)
                import time
                time.sleep(0.5)
                _kill_group(signal.SIGKILL)
                code = 143
                break
        os.write(status_w, b"%d\n" % code)
    except BaseException:
        try:
            os.write(status_w, b"%d\n" % code)
        except OSError:
            pass
    finally:
        os._exit(0)


def _kill_group(number: int) -> None:
    try:
        os.killpg(os.getpgrp(), number)
    except OSError:
        pass


def _max_fd() -> int:
    try:
        import resource
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        return min(soft if soft > 0 else 4096, 65536)
    except Exception:
        return 4096


def _restore(command: str, ticket: str | None, vault, settings):
    """The bytes to hand to the shell, and counts by type of the markers restored.

    This is the late swap: the only place where real values are put into a Bash command. It
    happens here, in the runner, after the vault opened, and the result goes straight into the
    pipe the child shell reads. It is never printed, logged or put in an environment variable.

    Raises shellsub.Refused when the values cannot be inserted as inert data; the command is
    then not run.
    """
    counts: dict = {}
    text = command
    if ticket is not None and settings.restore_in_bash != "off" and "[[" in command:
        from . import bashwrap, shellsub
        if not bashwrap.ticket_is_valid(ticket, command, settings.vault_dir):
            raise shellsub.Refused("ticket", "its restore ticket does not belong to this command")
        found, _ = vault.restore_spans(command)
        if found:
            spans = [shellsub.Span(*item) for item in found]
            text = shellsub.substitute(command, spans, shellsub.shell_kind(pick_shell())).text
            for span in spans:
                counts[span.entity] = counts.get(span.entity, 0) + 1
    return text.encode("utf-8", "surrogateescape"), counts


def run_child(command: str, cwd_out: str | None, ticket: str | None = None) -> int:
    try:
        vault, settings = _vault()
    except Exception:
        sys.stderr.write("datafog: the output filter cannot start (run /datafog:doctor); the command was not run\n")
        return 125
    try:
        payload, restored = _restore(command, ticket, vault, settings)
    except Exception as error:
        from . import log
        from .errors import safe_code
        why = getattr(error, "text", None) if type(error).__name__ == "Refused" else None
        log.write(settings.log_path, event="BashFilter", mode="runner",
                  refused=getattr(error, "code", safe_code(error)))
        sys.stderr.write("datafog: markers in this command could not be replaced by their values safely"
                         + (f" ({why})" if why else "") + "; the command was not run\n")
        return 125
    import select
    import signal
    import tempfile
    import time

    _make_undumpable()
    private = tempfile.mkdtemp(prefix="datafog-run.")           # 0700
    cwd_file = os.path.join(private, "cwd")
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    status_r, status_w = os.pipe()
    life_r, life_w = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    first = os.fork()
    if first == 0:
        try:
            os.setsid()                                         # new session: no controlling terminal
            for fd in (out_r, err_r, status_r, life_w):
                os.close(fd)
            if os.fork() == 0:
                _monitor(payload, pick_shell(), cwd_file, out_w, err_w, status_w, life_r)
        finally:
            os._exit(0)
    for fd in (out_w, err_w, status_w, life_r):
        os.close(fd)
    os.waitpid(first, 0)
    group = first                                               # the session's process group id

    def forward(number, _frame):
        try:
            os.killpg(group, number)
        except OSError:
            pass
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(number, forward)
        except (OSError, ValueError):
            pass

    sinks = {out_r: (sys.stdout.buffer, StreamTokenizer(vault)), err_r: (sys.stderr.buffer, StreamTokenizer(vault))}
    tokenizers = [pair[1] for pair in sinks.values()]
    open_fds = {out_r, err_r, status_r}
    status = b""
    code: int | None = None
    deadline: float | None = None
    while open_fds - {status_r} or code is None:
        if code is None and status_r not in open_fds:
            code = 125                                          # the monitor died without reporting
        timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        if deadline is not None and timeout == 0.0:
            break                                               # background children still hold the pipes
        try:
            ready, _, _ = select.select(list(open_fds), [], [], timeout)
        except InterruptedError:
            continue
        for fd in ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            if fd == status_r:
                status += data
                if not data:
                    open_fds.discard(fd)
                    try:
                        code = int(status.strip() or b"125")
                    except ValueError:
                        code = 125
                    deadline = time.monotonic() + GRACE_SECONDS
                continue
            sink, tokenizer = sinks[fd]
            if data:
                _write(sink, tokenizer.feed(data))
            else:
                open_fds.discard(fd)
    for sink, tokenizer in sinks.values():
        _write(sink, tokenizer.finish())                        # held partial lines; on error: the notice
    for fd in (out_r, err_r, status_r, life_w):                 # later writes by stragglers get EPIPE
        try:
            os.close(fd)
        except OSError:
            pass
    final_cwd = ""
    try:
        with open(cwd_file, encoding="utf-8", errors="surrogateescape") as handle:
            final_cwd = handle.read().rstrip("\n")
    except OSError:
        pass
    for name in ("cwd",):
        try:
            os.unlink(os.path.join(private, name))
        except OSError:
            pass
    try:
        os.rmdir(private)
    except OSError:
        pass
    if cwd_out and final_cwd and os.path.isabs(final_cwd) and os.path.isdir(final_cwd):
        try:
            fd = os.open(cwd_out, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as handle:
                handle.write(final_cwd)
        except OSError:
            pass
    _log(settings, "runner", tokenizers, code, restored)
    return 125 if code is None else code


def _write(sink, data: bytes) -> None:
    if not data:
        return
    try:
        sink.write(data)
        sink.flush()
    except (OSError, ValueError):
        pass


def main(argv: list[str]) -> int:
    if argv and argv[0] == "run":
        rest = argv[1:]
        cwd_out = ticket = None
        while len(rest) >= 2 and rest[0] in ("--cwd-file", "--restore"):
            if rest[0] == "--cwd-file":
                cwd_out = rest[1]
            else:
                ticket = rest[1]
            rest = rest[2:]
        if len(rest) != 1:
            sys.stderr.write("datafog: usage: run [--cwd-file FILE] [--restore TICKET] <command>; "
                             "the command was not run\n")
            return 125
        return run_child(rest[0], cwd_out, ticket)
    return filter_stdin()
