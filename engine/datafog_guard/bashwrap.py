"""Rewriting Bash commands so their output is tokenized before Claude Code captures it."""
from __future__ import annotations

import re
import shlex

OWN_SUBCOMMANDS = ("status", "doctor", "purge", "bootstrap")
_SHELL_META = re.compile(r"[;&|<>`$()\n\r\\{}*?!~#]")

# Programs that send data to another machine. A heuristic, not a guarantee.
_EGRESS = re.compile(
    r"""(?:^|[\s;&|(`'"=/])(?:
        curl|wget|http|https|xh|httpie|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|ftp|lftp|rsync|rclone|
        mail|mailx|sendmail|mutt|msmtp|swaks|gh|glab|hub|aws|gcloud|gsutil|az|doctl|heroku|flyctl|vercel|netlify|
        kubectl|helm|docker\s+(?:push|login)|podman\s+(?:push|login)|
        git\s+(?:[\w.=-]+\s+)*?(?:push|fetch|pull|clone|remote|ls-remote|send-email)|
        npm\s+(?:publish|login|adduser)|pnpm\s+publish|yarn\s+publish|twine|cargo\s+(?:publish|login)|
        psql|mysql|mongosh?|redis-cli|sqlcmd|
        openssl\s+s_client|slack|telegram-send|ngrok|pbcopy|xclip|wl-copy|osascript|
        dig|host|nslookup|drill|ping6?|traceroute|whois|open|xdg-open|start|say|notify-send|
        smbclient|tftp|rsh|mosh|tailscale|wscat|websocat|grpcurl|mqtt_pub|mosquitto_pub|
        az|terraform|ansible(?:-playbook)?|pip3?\s+download|brew\s+install
    )(?=$|[\s;&|)`'"])""",
    re.VERBOSE,
)
# Network use from scripting-language one-liners and URLs.
_NETWORK_CODE = re.compile(
    r"(?:https?|ftp|sftp|wss?|smtp|ldap|mailto|tcp|udp):(?://)?|/dev/tcp/|/dev/udp/"
    r"|\b(?:requests|urllib\d?|httpx|aiohttp|http\.client|smtplib|ftplib|telnetlib|paramiko|socket|websockets?"
    r"|fetch|axios|XMLHttpRequest|node-fetch|net\.connect|https?\.request|LWP|IO::Socket|Net::HTTP|open-uri"
    r"|TCPSocket|UDPSocket|Invoke-WebRequest|Invoke-RestMethod|file_get_contents|fsockopen|curl_exec)\b")


def is_own_command(command: str, launcher: str) -> bool:
    """True for the plugin's own status/doctor/purge/bootstrap command line, and nothing else.

    These print types and counts only, and must keep working when the engine is unhealthy.
    """
    if _SHELL_META.search(command):
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    if words[:1] == ["sh"]:
        words = words[1:]
    if not words or words[0] != launcher:
        return False
    words = words[1:]
    while words[:1] in (["--data-dir"], ["--vault-dir"]):
        words = words[2:]
    return bool(words) and words[0] in OWN_SUBCOMMANDS


def sends_data_off_machine(command: str) -> bool:
    return bool(_EGRESS.search(command) or _NETWORK_CODE.search(command))


def wrap(command: str, settings, ticket: str | None = None) -> str:
    """Run the command in a separate child shell behind the output filter (scripts/wrap.sh).

    The command is passed on exactly as the model wrote it: markers stay markers here. With a
    ``ticket`` (see :func:`restore_ticket`) the runner puts the real values in at the last
    moment, inside its own process; without one it never does.

    The wrapper function `cd`s to the child's final directory afterwards, so `cd` carries over
    to the next call; nothing else of the child's shell state does.
    """
    quote = shlex.quote
    text = ". %s && __datafog_run %s %s %s %s" % (
        quote(settings.wrap_script), quote(settings.launcher), quote(settings.data_dir),
        quote(settings.vault_dir), quote(command))
    return text + " " + quote(ticket) if ticket else text


# -- the restore ticket ------------------------------------------------------------------------
# The runner restores markers only for a command the PreToolUse hook has examined: the hook
# signs the exact command text with a key kept in the vault directory, and the runner checks the
# signature. Without this, a command could start the runner itself with marker text it built
# at run time (which the hook never saw as a marker) and get values back unasked.
# It is not a defence against code that reads the key or the vault file directly: both are
# readable by the user's own processes (see the README's threat model).
KEY_FILE = "bash-restore.key"


def key_state(vault_dir: str) -> str:
    """"ok", "missing" or "damaged" (present but shorter than a key). Never the key."""
    import os
    try:
        return "ok" if os.path.getsize(os.path.join(vault_dir, KEY_FILE)) >= 32 else "damaged"
    except OSError:
        return "missing"


def _key(vault_dir: str, create: bool) -> bytes | None:
    """The signing key. Only the hook creates it (``create``); the runner never does.

    A key file that is empty or too short (a crash or a full disk while it was written) is replaced
    by the hook. If two hooks replace it at the same moment one of their tickets will not verify and
    that command is not run: fail closed, and the next attempt works.
    """
    import os
    path = os.path.join(vault_dir, KEY_FILE)
    for _ in range(2):
        try:
            with open(path, "rb") as handle:
                key = handle.read()
            if len(key) >= 32:
                return key
            damaged = True
        except OSError:
            damaged = False
        if not create:
            return None
        temporary = "%s.%d.new" % (path, os.getpid())
        try:
            os.makedirs(vault_dir, mode=0o700, exist_ok=True)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(os.urandom(32))
                handle.flush()
                os.fsync(handle.fileno())
            if damaged:
                os.replace(temporary, path)           # the old content was not a key; nothing valid is lost
            else:
                try:
                    os.link(temporary, path)          # never replaces a key another process just made
                except OSError:
                    pass
                os.unlink(temporary)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            return None
    return None


def _sign(key: bytes, command: str) -> str:
    import hashlib
    import hmac
    return hmac.new(key, b"datafog bash restore v1\0" + command.encode("utf-8", "surrogateescape"),
                    hashlib.sha256).hexdigest()


def restore_ticket(command: str, vault_dir: str) -> str | None:
    key = _key(vault_dir, create=True)
    return _sign(key, command) if key else None


def ticket_is_valid(ticket: str, command: str, vault_dir: str) -> bool:
    import hmac
    key = _key(vault_dir, create=False)
    return key is not None and hmac.compare_digest(_sign(key, command), ticket or "")
