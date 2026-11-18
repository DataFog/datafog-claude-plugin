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


PROTECTION_TEXT = {
    "credential_store": "encrypted; the key is in the operating system's key store (macOS Keychain, or the "
                        "Secret Service on Linux)",
    "file_key": "encrypted, but the key is a file beside the data (vault_key: file): anyone who can read the "
                "vault directory can read the vault",
}
LEGACY_TEXT = ("an UNENCRYPTED vault from a development build is still in the vault directory. This version "
               "cannot read it; delete it with /datafog:purge")


def status_report(for_model: bool = False) -> str:
    settings = config.load()
    lines = [f"DataFog guard {__version__}"]
    protection = None
    try:
        from .engine import open_vault
        vault, _ = open_vault(settings)
        health = vault.health()
        entries = vault.entry_counts()
        protection = health["protection"]
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
    lines.append("Vault encryption at rest: " + (PROTECTION_TEXT.get(protection, str(protection)) if protection
                                                 else "the vault could not be opened"))
    from .store import legacy_plain_store, vault_path
    if legacy_plain_store(vault_path(settings.vault_dir)):
        lines.append("WARNING: " + LEGACY_TEXT)
    lines.append(f"Detected types: {', '.join(settings.entities)}")
    lines.append("Not detected: names of people, addresses without a label, anything in images or PDFs")
    lines.append(f"Allowlisted exact values: {len(settings.allowlist)}")
    lines.append("Bash output: " + ("filtered (each command runs in a separate child shell)"
                                    if settings.bash_wrap == "runner" else "NOT FILTERED (bash_wrap is off)")
                 + f"; background Bash: {settings.background_bash}")
    lines.append(f"Markers in Bash commands: {settings.restore_in_bash} (ask = you approve each command; "
                 "allow = restored silently; off = never restored). Values are put in by the runner when the "
                 "command starts; the command Claude Code shows and records keeps the markers. Only plain "
                 "commands made of a short list of programs (grep, cat, sort, printf ...) get values")
    lines.append("Extra programs you vouched for (restore_programs_extra): "
                 + (", ".join(sorted(settings.restore_programs_extra)) or "none"))
    lines.append("Bash permissions: decided by the plugin from your Claude Code allow, ask and deny rules "
                 "(see /datafog:doctor for what it can read)")
    lines.append(f"Files that cannot be checked: {settings.unscannable_policy}")
    lines.append("Restore markers on write: " + ("off" if not settings.restore_on_write else
                 ("only " + ", ".join(settings.restore_on_write_globs) if settings.restore_on_write_globs else "on")))
    return "\n".join(lines)


def purge(argv: list[str]) -> int:
    settings = config.load()
    from .engine import open_store
    from .store import KEYSTORE_SERVICE
    store = open_store(settings)
    info = store.describe()
    if "--confirm" not in argv:
        print("This deletes the DataFog vault at:")
        print(f"  {settings.vault_dir}")
        print(f"Current state: {info.get('state')}, revision {info.get('revision', 0)}.")
        if info.get("protection") == "credential_store":
            print("Its key is removed from the operating system's key store as well.")
        if info.get("legacy_plain_store"):
            print("The unencrypted vault of a development build in the same directory is deleted too.")
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
        result = store.purge()
        if os.path.islink(settings.shadow_dir):
            os.unlink(settings.shadow_dir)
        else:
            try:
                shutil.rmtree(settings.shadow_dir)
            except FileNotFoundError:
                pass
    except Exception as error:
        print(f"The vault could not be deleted ({_problem(error)}).")
        return 1
    print("The vault was deleted." if result["existed"] or result["legacy"] else "There was no vault to delete.")
    if result["legacy"]:
        print("The unencrypted vault of a development build was deleted.")
    if result["keystore"] == "removed":
        print("Its key was removed from the operating system's key store.")
    elif result["keystore"] == "left":
        print("Its key could not be removed from the operating system's key store. It opens nothing now that the")
        print(f"vault file is gone. To remove it by hand, delete the entry with service \"{KEYSTORE_SERVICE}\"")
        print(f"and account \"{result['account']}\" (macOS: Keychain Access; Linux: Seahorse or secret-tool).")
    print("Markers issued before now can no longer be restored. A new, empty vault is created on next use.")
    return 1 if result["keystore"] == "left" else 0


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
    from . import VAULT_REQUIREMENT
    from .support import UNSUPPORTED, platform_problem
    problem = platform_problem()
    check("supported machine (macOS on Apple Silicon, or Linux x86_64 with glibc 2.38 or later)", not problem,
          f"{problem}. {UNSUPPORTED}" if problem else "")
    try:
        started = time.perf_counter()
        from importlib.metadata import version

        from .vault import _core
        datafog_core = _core()
        check(f"detector library ({CORE_REQUIREMENT})", True,
              f"datafog-core {version('datafog-core')}, import {1000 * (time.perf_counter() - started):.1f} ms")
        missing = [name for name in settings.entities if name not in datafog_core.capabilities()["entities"]]
        check("configured entity types are supported", not missing, ", ".join(missing))
    except Exception as error:
        check("detector library", False, safe_code(error) + "; run the bootstrap command shown at session start")
    try:
        started = time.perf_counter()
        from importlib.metadata import version

        from .store import _fogvault
        _fogvault()
        check(f"vault library ({VAULT_REQUIREMENT})", True, f"datafog-fogvault {version('datafog-fogvault')}, "
              f"import {1000 * (time.perf_counter() - started):.1f} ms")
    except Exception as error:
        check("vault library", False, safe_code(error) + ("" if problem else
                                                          "; run the bootstrap command shown at session start"))
    check("configuration files", not settings.problems, "; ".join(settings.problems))
    from .store import legacy_plain_store, vault_path
    protection = None
    try:
        from .engine import open_vault
        vault, _ = open_vault(settings)
        started = time.perf_counter()
        protection = vault.health()["protection"]
        check("vault opens (private files, lock, key, decryption) and the detector finds a test value", True,
              f"{1000 * (time.perf_counter() - started):.1f} ms")
        text, counts = vault.tokenize("doctor probe.synthetic@example.com")
        check("tokenize and restore round trip", vault.restore(text).text == "doctor probe.synthetic@example.com")
    except Exception as error:
        check("vault and detector", False, _problem(error))
    directory = vault_path(settings.vault_dir)
    if os.name != "nt" and os.path.isdir(directory):
        mode = os.stat(directory).st_mode & 0o777
        check("vault directory is owner-only", mode == 0o700, oct(mode))
        loose = sorted(name for name in os.listdir(directory)
                       if os.path.isfile(os.path.join(directory, name))
                       and os.stat(os.path.join(directory, name)).st_mode & 0o077)
        check("vault files are owner-only", not loose, ", ".join(loose))
    if protection == "credential_store":
        check("vault encryption at rest", True, PROTECTION_TEXT[protection])
    elif protection == "file_key":
        check("vault encryption at rest", None, PROTECTION_TEXT[protection])
    else:
        check("vault encryption at rest", False, "the vault could not be opened, so nothing can be said")
    if legacy_plain_store(directory):
        check("no unencrypted vault left over", False, LEGACY_TEXT)
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
               "damaged": "the key file is not a 32-byte key; it is replaced the next time a command with a "
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
        unsupported = [rule for rule in rules.paths if rule.unsupported]
        if unsupported:
            check("Read/Edit rules the plugin can interpret", False,
                  f"{len(unsupported)} rule(s) have a pattern with a .. segment (in: "
                  + ", ".join(sorted({rule.source for rule in unsupported})) + "). The plugin cannot say what "
                  "they cover, so no Bash command is approved without a prompt until they are rewritten "
                  "without ..")
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
