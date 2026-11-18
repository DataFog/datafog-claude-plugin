"""``status``, ``purge`` and ``doctor``. Output names entity types, counts and paths; never a value."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

from . import CORE_REQUIREMENT, __version__, config
from .errors import GuardError, safe_code
from .log import describe_counts

PURGE_WORD = "DELETE-VAULT"
MIN_CLAUDE_CODE = (2, 1, 295)


def _problem(error: BaseException) -> str:
    return f"{error.code}: {error.user_message}" if isinstance(error, GuardError) else safe_code(error)


def status_report(for_model: bool = False) -> str:
    settings = config.load()
    lines = [f"DataFog guard {__version__}"]
    try:
        from .engine import open_vault
        vault, _ = open_vault(settings)
        health = vault.health()
        entries = vault.entry_counts()
        lines.append("Protection: ON")
        lines.append(f"Values held in the vault: {sum(entries.values())} ({describe_counts(entries)})")
        lines.append(f"Vault revision: {health['revision']}")
    except Exception as error:
        lines.append(f"Protection: NOT WORKING ({_problem(error)}). Tool calls are blocked until this is fixed.")
    place = {"env": "set by DATAFOG_VAULT_DIR", "user-data": "user data folder, kept when the plugin is uninstalled",
             "plugin-data": "plugin data folder, deleted when the plugin is uninstalled"}[settings.vault_location]
    lines.append(f"Vault location: {place}")
    if not for_model:
        lines.append(f"Vault path: {settings.vault_dir}")
    lines.append("Vault encryption at rest: NONE in this version (owner-only file permissions)")
    lines.append(f"Detected types: {', '.join(settings.entities)}")
    lines.append("Not detected: names of people, addresses without a label, anything in images or PDFs")
    lines.append(f"Allowlisted exact values: {len(settings.allowlist)}")
    lines.append("Bash output: " + ("filtered (each command runs in a separate child shell)"
                                    if settings.bash_wrap == "runner" else "NOT FILTERED (bash_wrap is off)")
                 + f"; background Bash: {settings.background_bash}")
    lines.append(f"Markers in Bash commands: {settings.restore_in_bash} (ask = you approve each command; "
                 "allow = restored silently; off = never restored). Values are put in by the runner when the "
                 "command starts; the command Claude Code shows and records keeps the markers")
    lines.append("Bash permissions: decided by the plugin from your Claude Code allow, ask and deny rules "
                 "(see /datafog:doctor for what it can read)")
    lines.append(f"Files that cannot be checked: {settings.unscannable_policy}")
    lines.append("Restore markers on write: " + ("off" if not settings.restore_on_write else
                 ("only " + ", ".join(settings.restore_on_write_globs) if settings.restore_on_write_globs else "on")))
    return "\n".join(lines)


def purge(argv: list[str]) -> int:
    settings = config.load()
    from .store import FileVaultStore
    store = FileVaultStore(settings.vault_dir)
    info = store.describe()
    if "--confirm" not in argv:
        print("This deletes the DataFog vault at:")
        print(f"  {settings.vault_dir}")
        print(f"Current state: {info.get('state')}, revision {info.get('revision', 0)}.")
        print("After that, every marker issued so far is meaningless: text that still holds markers")
        print("(files Claude wrote with markers, old transcripts, notes) can NEVER be turned back into")
        print("the real values. Files on disk that already hold real values are not affected.")
        print(f"Nothing was deleted. To go ahead, run the same command with:  purge --confirm {PURGE_WORD}")
        return 0
    index = argv.index("--confirm")
    if argv[index + 1:index + 2] != [PURGE_WORD]:
        print(f"Not confirmed; nothing was deleted. The confirmation word is {PURGE_WORD}.")
        return 1
    try:
        existed = store.purge()
        shutil.rmtree(settings.shadow_dir, ignore_errors=True)
    except Exception as error:
        print(f"The vault could not be deleted ({_problem(error)}).")
        return 1
    print("The vault was deleted." if existed else "There was no vault to delete.")
    print("Markers issued before now can no longer be restored. A new, empty vault is created on next use.")
    return 0


def _claude_version() -> tuple[int, ...] | None:
    binary = shutil.which("claude")
    if not binary:
        return None
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    import re
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(part) for part in match.groups()) if match else None


def doctor() -> int:
    settings = config.load()
    failures = 0

    def check(name: str, ok, detail: str = "") -> None:
        nonlocal failures
        state = "ok  " if ok is True else ("FAIL" if ok is False else "note")
        failures += ok is False
        print(f"[{state}] {name}" + (f": {detail}" if detail else ""))

    print(f"DataFog guard {__version__} doctor")
    check("Python 3.10 or later", sys.version_info >= (3, 10), sys.version.split()[0])
    try:
        started = time.perf_counter()
        from importlib.metadata import version

        import datafog_core
        check(f"detector library ({CORE_REQUIREMENT})", True,
              f"datafog-core {version('datafog-core')}, import {1000 * (time.perf_counter() - started):.1f} ms")
        missing = [name for name in settings.entities if name not in datafog_core.capabilities()["entities"]]
        check("configured entity types are supported", not missing, ", ".join(missing))
    except Exception as error:
        check("detector library", False, safe_code(error) + "; run the bootstrap command shown at session start")
    check("configuration files", not settings.problems, "; ".join(settings.problems))
    try:
        from .engine import open_vault
        vault, _ = open_vault(settings)
        started = time.perf_counter()
        vault.health()
        check("vault opens, lock works, detector finds a test value", True,
              f"{1000 * (time.perf_counter() - started):.1f} ms")
        text, counts = vault.tokenize("doctor probe.synthetic@example.com")
        check("tokenize and restore round trip", vault.restore(text).text == "doctor probe.synthetic@example.com")
    except Exception as error:
        check("vault and detector", False, _problem(error))
    if os.name != "nt" and os.path.isdir(settings.vault_dir):
        mode = os.stat(settings.vault_dir).st_mode & 0o777
        check("vault directory is owner-only", mode == 0o700, oct(mode))
    check("vault encryption at rest", None, "none in this version")
    check("vault location", None, f"{settings.vault_location}: {settings.vault_dir}")
    for name in ("launcher", "wrap_script"):
        check(f"plugin file {os.path.basename(getattr(settings, name))}", os.path.exists(getattr(settings, name)))
    for shell in ("bash", "zsh"):
        binary = shutil.which(shell)
        if not binary:
            check(f"Bash output filter under {shell}", None, "shell not installed")
            continue
        from . import bashwrap
        command = bashwrap.wrap("echo probe.synthetic@example.com; (exit 3)", settings)
        try:
            result = subprocess.run([binary, "-c", command], capture_output=True, text=True, timeout=60)
            ok = result.returncode == 3 and "[[EMAIL_" in result.stdout and "probe.synthetic" not in result.stdout
            check(f"Bash output filter under {shell}", ok, "" if ok else f"exit status {result.returncode}")
        except (OSError, subprocess.SubprocessError) as error:
            check(f"Bash output filter under {shell}", False, safe_code(error))
    try:
        from . import bashwrap
        state = bashwrap.key_state(settings.vault_dir)
        check("key that authorises restoring markers in Bash commands", state != "damaged",
              {"ok": "", "missing": "not created yet; the first command with a marker creates it",
               "damaged": "the key file is empty or too short; it is replaced the next time a command with a "
                          "marker is checked (or delete bash-restore.key in the vault directory)"}[state])
    except Exception as error:
        check("key that authorises restoring markers in Bash commands", False, safe_code(error))
    # The late swap: a marker in a command is replaced by its value inside the runner. The output
    # filter turns the value back into a marker, so the check counts characters instead.
    try:
        from . import bashwrap
        from .engine import open_vault
        probe = "doctor probe.synthetic@example.com"
        marker = open_vault(settings)[0].tokenize(probe)[0].split(" ", 1)[1]
        inner = f"printf %s '{marker}' | wc -c"
        ticket = bashwrap.restore_ticket(inner, settings.vault_dir)
        for shell in ("bash", "zsh"):
            binary = shutil.which(shell)
            if binary and settings.restore_in_bash != "off":
                result = subprocess.run([binary, "-c", bashwrap.wrap(inner, settings, ticket)], capture_output=True,
                                        text=True, timeout=60, env=dict(os.environ, SHELL=binary))
                ok = result.returncode == 0 and result.stdout.strip() == str(len(probe.split(" ", 1)[1]))
                check(f"markers in a Bash command are restored inside the runner under {shell}", ok,
                      "" if ok else f"exit status {result.returncode}")
    except Exception as error:
        check("markers in a Bash command are restored inside the runner", False, _problem(error))
    try:
        from . import ccperms
        project = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
        rules = ccperms.load(project)
        detail = (f"{len(rules.allow)} allow, {len(rules.ask)} ask, {len(rules.deny)} deny for Bash and "
                  f"{len(rules.paths)} Read/Edit deny or ask rules (applied to Bash commands too), read from the "
                  "managed, user, project and local settings files (not from command-line flags, server-managed "
                  "settings or session-only choices)")
        if rules.problems:
            check("Claude Code permission rules", False, "could not be read completely: " + ", ".join(rules.problems)
                  + "; no Bash allow rule is applied until this is fixed. " + detail)
        else:
            check("Claude Code permission rules", None, detail)
        for note in rules.notes:
            check("Claude Code permission rules", None, note)
    except Exception as error:
        check("Claude Code permission rules", False, safe_code(error))
    found = _claude_version()
    if found is None:
        check("Claude Code 2.1.295 or later", None, "could not run `claude --version`")
    else:
        check("Claude Code 2.1.295 or later", found >= MIN_CLAUDE_CODE, ".".join(map(str, found)))
    check("@file mentions", None,
          "CLAUDE_CODE_DISABLE_FILE_MENTIONS=1 is set" if os.environ.get("CLAUDE_CODE_DISABLE_FILE_MENTIONS") == "1"
          else "not disabled; prompts with @file are blocked when the file holds values (see README)")
    print("Result: " + ("problems found" if failures else "all checks passed"))
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if argv[0] == "status":
        print(status_report())
        return 0
    if argv[0] == "purge":
        return purge(argv[1:])
    return doctor()
