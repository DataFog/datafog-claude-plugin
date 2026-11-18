"""Claude Code hook handler: reads one hook event as JSON on stdin, writes a decision as JSON.

What each event can and cannot guarantee (measured on Claude Code 2.1.299):

PreToolUse    fail-closed. With ``onFailure: block`` a crash, a timeout or bad output stops
              the tool. All real protection is placed here: Read is redirected to a
              tokenized copy, Bash is wrapped so its output is filtered as it is produced,
              and every call is refused when the engine is unhealthy.
PostToolUse   fail-OPEN. If this hook crashes or times out, the raw output reaches the model.
              It tokenizes what only exists after the tool ran (Grep, WebFetch, MCP, Agent)
              and is a second line for Read and Bash. On an internal error it returns the
              tool's own shape with the content replaced by a notice.
UserPromptSubmit  can block a prompt but not rewrite it.

Rule for everything in this file: no real value is written to stdout, stderr or the log,
except inside ``updatedInput`` for the built-in tools that need it to do their job: file
content for Write/Edit/NotebookEdit and the pattern for Grep/Glob. Claude Code records those
inputs in its transcript. A Bash command is different: its ``updatedInput`` keeps the markers,
and the runner puts the values in at execution time (the late swap). Reasons and diagnostics
name entity types and counts only.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
import time

from . import bashwrap, config, files, log, shapes
from .errors import GuardError, safe_code

OWN_MCP_PREFIX = "mcp__plugin_datafog_guard__"
EDIT_TOOL = OWN_MCP_PREFIX + "edit_with_markers"
DOCTOR_HINT = "Run /datafog:doctor for details."

MARKER_NOTE = (
    "DataFog guard is active in this session. Personal data and credentials in files, command "
    "output and tool results are replaced by markers such as [[EMAIL_ABC123]] before you see them. "
    "A marker stands for one real value. Rules: (1) Treat a marker as the value itself and copy it "
    "exactly, including the double brackets, whenever you write it to a file, a command or a tool "
    "input; it is swapped back to the real value locally. In Bash commands that happens only if the user allows "
    "it and only in plain commands made of these programs: grep, egrep, fgrep, rg, cat, head, tail, wc, nl, tac, "
    "rev, fold, cut, tr, paste, join, comm, cmp, column, diff, ls, stat, basename, dirname, file, sort, printf "
    "(only printf '%s\\n' style formats), true; joined by | && || ; with redirections to literal paths; no $ "
    "variables or substitutions, no globs, backslashes, heredocs, loops, assignments or cd; the marker as a whole "
    "argument or inside a quoted argument, after a literal -- if the value might start with a dash "
    "(grep -c -- [[M]] file). Any other program (curl, echo, python, sed, awk, git, your own scripts ...) with a "
    "marker is refused: write the value to a file with the Write tool and let the program read the file. (2) "
    "Never try to recover, guess or "
    "print the original value, and never ask the user for it. (3) The built-in Edit tool cannot "
    "match a line that contains a marker: to change such a line use the tool "
    f"{EDIT_TOOL} (same arguments as Edit). (4) Markers sent to web or third-party MCP tools "
    "are NOT swapped back. (5) Background Bash commands are refused; run commands in the foreground. "
    "(6) Each Bash command runs in a fresh shell: `cd` carries over to the next command, but variables, "
    "functions and aliases do not."
)


class Session:
    """Lazy access to the settings and the vault for one hook call."""

    def __init__(self):
        self.settings = config.load()
        self._vault = None

    @property
    def vault(self):
        if self._vault is None:
            from .engine import open_vault
            self._vault, _ = open_vault(self.settings)
        return self._vault

    def health(self) -> None:
        self.vault.health()


def describe(counts) -> str:
    return log.describe_counts(counts)


def failure_text(error: BaseException) -> str:
    if isinstance(error, GuardError):
        return f"{error.code}: {error.user_message}"
    return safe_code(error)


# ---------------------------------------------------------------------------
# PreToolUse
# ---------------------------------------------------------------------------
def pre_output(decision=None, reason=None, updated_input=None, context=None) -> dict | None:
    out: dict = {"hookEventName": "PreToolUse"}
    if decision:
        out["permissionDecision"] = decision
        out["permissionDecisionReason"] = reason or ""
    if updated_input is not None:
        out["updatedInput"] = updated_input
    if context:
        out["additionalContext"] = context
    return {"hookSpecificOutput": out} if len(out) > 1 else None


def deny(reason: str) -> dict:
    return pre_output("deny", reason)   # type: ignore[return-value]


def _restore_fields(session: Session, tool_input: dict, fields, record: dict):
    """Restore markers in the named string fields. Returns (new input or None, counts, unknown)."""
    from collections import Counter
    counts: Counter = Counter()
    unknown = 0
    new_input = None
    for name in fields:
        value = tool_input.get(name)
        if not isinstance(value, str) or "[[" not in value:
            continue
        result = session.vault.restore(value)
        counts.update(result.restored)
        unknown += result.unknown
        if result.text != value:
            new_input = new_input or dict(tool_input)
            new_input[name] = result.text
    if counts:
        record["restored"] = dict(counts)
    if unknown:
        record["unknown_markers"] = unknown
    return new_input, counts, unknown


def _unknown_note(unknown: int) -> str | None:
    if not unknown:
        return None
    return (f"DataFog: {unknown} marker-like string(s) in this input are not known to the vault "
            "(wrong label, changed code, or from a purged vault). They were left unchanged.")


def _redirect_from_shadow(session: Session, tool_input: dict, key: str = "file_path"):
    original = files.original_of(session.settings.shadow_dir, tool_input.get(key) or "")
    if original is None:
        return tool_input, False
    updated = dict(tool_input)
    updated[key] = original
    return updated, True


def pre_read(session: Session, tool_input: dict, record: dict):
    tool_input, moved = _redirect_from_shadow(session, tool_input)
    path = tool_input.get("file_path")
    if not isinstance(path, str) or not path:
        return None
    settings = session.settings
    if files.is_inside(path, settings.vault_dir):
        return deny("DataFog: the vault holds the real values and cannot be read.")
    kind, detail, text = files.classify(path, settings.max_scan_bytes)
    if kind == "absent":
        return pre_output(updated_input=tool_input) if moved else None
    if kind == "unscannable":
        record["unscannable"] = detail
        policy = settings.unscannable_policy
        if policy == "allow":
            return pre_output(updated_input=tool_input) if moved else None
        reason = (f"DataFog cannot check this file for personal data or credentials because {detail}. "
                  "If it is read, its content reaches the model as it is.")
        return pre_output(policy, reason, tool_input if moved else None)
    tokenized, counts = session.vault.tokenize(text)
    if not counts:
        return pre_output(updated_input=tool_input) if moved else None
    record["replaced"] = dict(counts)
    updated = dict(tool_input)
    updated["file_path"] = files.write_shadow(settings.shadow_dir, path, tokenized)
    record["action"] = "read_redirected"
    return pre_output(updated_input=updated)


def _restore_allowed(settings, path) -> bool:
    if not settings.restore_on_write:
        return False
    if not settings.restore_on_write_globs:
        return True
    path = str(path or "")
    return any(fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern)
               for pattern in settings.restore_on_write_globs)


def pre_write_like(session: Session, tool_input: dict, record: dict, fields, path_key="file_path"):
    tool_input, moved = _redirect_from_shadow(session, tool_input, path_key)
    path = tool_input.get(path_key)
    if isinstance(path, str) and path and (files.is_inside(path, session.settings.vault_dir)):
        return deny("DataFog: files inside the vault cannot be written.")
    if isinstance(path, str) and path and os.path.realpath(path) in [
            os.path.realpath(name) for name in _own_config_files(session.settings)]:
        return deny("DataFog: the plugin's own configuration files cannot be written by Claude; only you "
                    "change those settings.")
    new_input, unknown = None, 0
    if _restore_allowed(session.settings, path):
        new_input, _, unknown = _restore_fields(session, tool_input, fields, record)
    if new_input is None and not moved:
        return pre_output(context=_unknown_note(unknown))
    return pre_output(updated_input=new_input or tool_input, context=_unknown_note(unknown))


def _mentions_vault(text: str, settings) -> bool:
    """A cheap guard, not a sandbox: the command or pattern names the vault directory."""
    vault = settings.vault_dir.rstrip("/\\")
    names = {vault, os.path.realpath(vault)}
    home = os.path.expanduser("~")
    for name in list(names):
        if name.startswith(home + os.sep):
            names.add("~" + name[len(home):])
            names.add("$HOME" + name[len(home):])
    return any(name and name in text for name in names)


def _own_config_files(settings) -> list[str]:
    return [os.path.join(settings.data_dir, name) for name in ("config.json", "runtime.json")]


def _names_own_config(text: str, settings) -> bool:
    """A cheap guard, like _mentions_vault: the model must not edit the plugin's settings (for example
    restore_programs_extra, which says which programs may receive real values)."""
    home = os.path.expanduser("~")
    for path in _own_config_files(settings):
        names = {path, os.path.realpath(path)}
        for name in list(names):
            if name.startswith(home + os.sep):
                names.update({"~" + name[len(home):], "$HOME" + name[len(home):]})
        if any(name in text for name in names):
            return True
    return False


def pre_bash(session: Session, tool_input: dict, record: dict, permission_mode: str = "default", cwd: str = ""):
    settings = session.settings
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    if tool_input.get("run_in_background") and settings.background_bash != "allow":
        return deny("DataFog: background commands are refused because their output is read later, outside "
                    "the output filter. Run the command in the foreground (set background_bash to allow to "
                    "change this).")
    if _mentions_vault(command, settings):
        return deny("DataFog: commands that name the vault directory are refused; it holds the real values.")
    if _names_own_config(command, settings):
        return deny("DataFog: commands that name the plugin's own configuration files are refused; only you "
                    "change those settings.")
    if len(command.encode("utf-8", "replace")) > 100_000:
        return deny("DataFog: this command is too long to run behind the output filter. Put it in a script file.")
    # Restoring markers lets the command compute on real values. That is needed for honest work
    # (`grep [[EMAIL_X]] file`) and is also how a manipulated model could unmask a value
    # (`echo [[EMAIL_X]] | base64`). restore_in_bash decides: ask the user, allow, or never restore.
    #
    # Late swap: this hook never puts a real value into the command. The command handed back to
    # Claude Code (updatedInput, and so the permission prompt, the transcript and the record of
    # denied calls) still holds the markers. The runner swaps them in at execution time
    # (filtercmd._restore), and only for a command that carries a ticket made here.
    mode = settings.restore_in_bash
    wrapping = settings.bash_wrap != "off"
    context = ticket = None
    found, unknown = (session.vault.restore_spans(command) if "[[" in command else ([], 0))
    known: dict = {}
    for _, _, entity, _ in found:
        known[entity] = known.get(entity, 0) + 1
    restoring = bool(known) and mode != "off" and wrapping
    egress = False
    if known and not restoring:
        record["markers_not_restored"] = dict(known)
        why = ("restore_in_bash is off" if mode == "off"
               else "bash_wrap is off, and values are only put in by the runner")
        context = (f"DataFog: markers are not restored in Bash commands ({why}), so this command "
                   f"ran with {describe(known)} left as marker text. Use the Write tool or edit_with_markers to "
                   "put real values into files.")
    elif restoring:
        from . import filtercmd, shellsub
        try:
            # A dry run of exactly what the runner will do. The result holds real values and is dropped.
            egress = bashwrap.sends_data_off_machine(
                shellsub.substitute(command, [shellsub.Span(*item) for item in found],
                                    shellsub.shell_kind(filtercmd.pick_shell()),
                                    settings.restore_programs_extra).text)
        except shellsub.Refused as refusal:
            record["restore_refused"] = refusal.code
            return deny(f"DataFog: this command contains markers ({describe(known)}) in a place where the real "
                        f"values cannot be put in safely: {refusal.text}. It was not run. Use a plain command with "
                        "the marker as a whole or quoted argument, or write the values to a file with the Write tool "
                        "and let the command read that file.")
        record["restore"] = dict(known)
        egress = egress or bashwrap.sends_data_off_machine(command)
        if egress and settings.egress_policy == "deny":
            record["egress"] = "deny"
            return deny(f"DataFog: this command would run with real values ({describe(known)}) and looks "
                        "like it sends data to another machine. It was refused (egress_policy is deny).")
        ticket = bashwrap.restore_ticket(command, settings.vault_dir)
        if ticket is None:
            return deny("DataFog: the key that authorises restoring markers in a Bash command could not be read or "
                        "created in the vault directory, so the command was not run. " + DOCTOR_HINT)
    notes = " ".join(note for note in (context, _unknown_note(unknown)) if note) or None
    if not wrapping:
        # The command is not rewritten, so Claude Code applies the user's rules to it as usual.
        return pre_output(context=notes)

    updated = dict(tool_input)
    updated["command"] = bashwrap.wrap(command, settings, ticket)
    record["action"] = "bash_wrapped"
    from . import ccperms
    project = os.environ.get("CLAUDE_PROJECT_DIR") or cwd or os.getcwd()
    rules = ccperms.load(project)
    verdict = ccperms.decide(
        command, rules, mode=permission_mode, markers=describe(known) if restoring else "", restore=mode,
        egress=egress and settings.egress_policy == "ask", tool_input=tool_input, cwd=cwd,
        wrapped=updated["command"], project_dir=project,
        # a value can itself be a path that a Read or Edit rule covers; used for that check only
        marker_values={command[start:end]: value for start, end, _, value in found} if restoring else None)
    record["permission"] = {"step": verdict.step, "mode": permission_mode}
    if rules.problems:
        record["settings_unreadable"] = list(rules.problems)
    if restoring and verdict.step in (4, 5):
        record["restore_in_bash"] = "ask"
        if egress and settings.egress_policy == "ask":
            record["egress"] = "ask"
    if verdict.outcome == "deny":
        return deny(verdict.reason)
    return pre_output(verdict.outcome, verdict.reason, updated, notes)


def pre_tool_use(session: Session, data: dict, record: dict):
    tool = str(data.get("tool_name") or "")
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    settings = session.settings
    if tool == "Bash" and isinstance(tool_input.get("command"), str) and \
            bashwrap.is_own_command(tool_input["command"], settings.launcher):
        record["action"] = "own_command"
        return None
    if tool.startswith(OWN_MCP_PREFIX):
        return None

    # Nothing may run while the engine cannot protect its output: for most tools the output
    # can only be handled after the call, and that later hook cannot fail closed.
    try:
        session.health()
    except Exception as error:
        record["unhealthy"] = safe_code(error)
        return deny(f"DataFog guard cannot protect this call ({failure_text(error)}), so it was blocked. "
                    + DOCTOR_HINT)

    if tool == "Read":
        return pre_read(session, tool_input, record)
    if tool == "Bash":
        return pre_bash(session, tool_input, record, str(data.get("permission_mode") or "default"),
                        str(data.get("cwd") or ""))
    if tool == "PowerShell":
        return deny("DataFog: PowerShell commands are not supported yet; their output cannot be filtered.")
    if tool == "Write":
        return pre_write_like(session, tool_input, record, ("content",))
    if tool == "Edit":
        return pre_write_like(session, tool_input, record, ("old_string", "new_string"))
    if tool == "NotebookEdit":
        return pre_write_like(session, tool_input, record, ("new_source",), "notebook_path")
    if tool in ("Grep", "Glob"):
        target = tool_input.get("path")
        if isinstance(target, str) and target and (files.is_inside(target, settings.vault_dir)
                                                   or files.is_inside(settings.vault_dir, target)):
            return deny("DataFog: searching a directory that contains the vault is refused; "
                        "it holds the real values. Search a narrower path.")
        new_input, _, unknown = _restore_fields(session, tool_input, ("pattern", "path", "glob"), record)
        return pre_output(updated_input=new_input, context=_unknown_note(unknown))
    if tool.startswith("mcp__") and settings.restore_in_mcp_input:
        fields = [name for name, value in tool_input.items() if isinstance(value, str)]
        new_input, _, unknown = _restore_fields(session, tool_input, fields, record)
        return pre_output(updated_input=new_input, context=_unknown_note(unknown))
    # WebFetch, WebSearch, Agent, third-party MCP tools and anything else: markers stay markers,
    # because the input leaves this machine or goes to another model.
    return None


# ---------------------------------------------------------------------------
# PostToolUse
# ---------------------------------------------------------------------------
def post_output(data: dict, replacement) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": replacement}}


def post_tool_use(session: Session, data: dict, record: dict):
    tool = str(data.get("tool_name") or "")
    if tool.startswith(OWN_MCP_PREFIX) or "tool_response" not in data:
        return None
    response = data["tool_response"]
    # A detector that loads but finds nothing would let everything through: check it first.
    session.health()
    replacement, counts, changed = shapes.transform(tool, response, session.vault.tokenize_many)
    if tool == "Read" and isinstance(replacement, dict) and isinstance(replacement.get("file"), dict):
        original = files.original_of(session.settings.shadow_dir, replacement["file"].get("filePath") or "")
        if original is not None:
            # Tell the model the path it asked for, not the path of the tokenized copy.
            if not changed:
                replacement = dict(replacement, file=dict(replacement["file"]))
            replacement["file"]["filePath"] = original
            changed = True
    if counts:
        record["replaced"] = dict(counts)
    return post_output(data, replacement) if changed else None


def post_withheld(data: dict):
    if "tool_response" not in data:
        return None
    return post_output(data, shapes.withheld(str(data.get("tool_name") or ""), data["tool_response"]))


# ---------------------------------------------------------------------------
# UserPromptSubmit
# ---------------------------------------------------------------------------
_MENTION = re.compile(r'(?:^|(?<=\s))@(?:"([^"\n]+)"|\'([^\'\n]+)\'|((?:\\.|[^\s"\\])+))')
_RANGE_SUFFIX = re.compile(r"(?:#L?\d+(?:-L?\d+)?|:\d+(?:-\d+)?)$")
MENTION_MAX_FILES = 200
MENTION_MAX_BYTES = 8 * 1024 * 1024
MENTION_MAX_DEPTH = 4


def mentioned_paths(prompt: str, cwd: str) -> list[str]:
    """Files and directories named by @mentions in a prompt (existing paths only).

    Handles @path, @"path with spaces", @'path', backslash-escaped spaces, ~ and ~user,
    a trailing #L10-20 or :10-20 line range, trailing punctuation, and glob patterns.
    """
    import glob
    found: list[str] = []
    for match in _MENTION.finditer(prompt):
        name = match.group(1) or match.group(2) or re.sub(r"\\(.)", r"\1", match.group(3) or "")
        candidates = [name, _RANGE_SUFFIX.sub("", name), name.rstrip(".,;:!?)]}'\"")]
        candidates.append(_RANGE_SUFFIX.sub("", candidates[-1]))
        hit = False
        for candidate in candidates:
            if not candidate:
                continue
            path = os.path.expanduser(candidate)
            if not os.path.isabs(path):
                path = os.path.join(cwd or os.getcwd(), path)
            if os.path.exists(path):
                if path not in found:
                    found.append(path)
                hit = True
                break
        if not hit and any(char in name for char in "*?["):
            pattern = os.path.expanduser(name)
            if not os.path.isabs(pattern):
                pattern = os.path.join(cwd or os.getcwd(), pattern)
            for path in sorted(glob.glob(pattern, recursive=True))[:MENTION_MAX_FILES + 1]:
                if path not in found:
                    found.append(path)
    return found


def _files_under(path: str):
    """(files, problem) for a mentioned directory, within fixed bounds."""
    collected: list[str] = []
    total = 0
    base_depth = path.rstrip(os.sep).count(os.sep)
    for folder, folders, names in os.walk(path):
        folders[:] = sorted(name for name in folders if name not in (".git", "node_modules", ".venv", "__pycache__"))
        if folder.rstrip(os.sep).count(os.sep) - base_depth >= MENTION_MAX_DEPTH and folders:
            return collected, f"it is nested more than {MENTION_MAX_DEPTH} levels deep"
        for name in sorted(names):
            full = os.path.join(folder, name)
            collected.append(full)
            try:
                total += os.path.getsize(full)
            except OSError:
                pass
            if len(collected) > MENTION_MAX_FILES:
                return collected, f"it holds more than {MENTION_MAX_FILES} files"
            if total > MENTION_MAX_BYTES:
                return collected, f"it holds more than {MENTION_MAX_BYTES // (1024 * 1024)} MiB"
    return collected, None


def check_mentions(session: Session, prompt: str, cwd: str) -> list[str]:
    """One line per mention that must not be attached. Lines name files, types and counts only."""
    from collections import Counter
    problems = []
    budget = MENTION_MAX_FILES
    for path in mentioned_paths(prompt, cwd):
        label = "@" + os.path.basename(path.rstrip(os.sep))
        if os.path.isdir(path):
            members, problem = _files_under(path)
            if problem:
                problems.append(f"{label}/: cannot be checked because {problem}")
                continue
        else:
            members = [path]
        budget -= len(members)
        if budget < 0:
            problems.append(f"{label}: too many mentioned files to check")
            break
        found: Counter = Counter()
        unscannable = 0
        for member in members:
            kind, _, text = files.classify(member, session.settings.max_scan_bytes)
            if kind == "unscannable":
                unscannable += 1
            elif kind == "text" and text:
                found.update(session.vault.contains_values(text))
        suffix = "/" if os.path.isdir(path) else ""
        if found:
            problems.append(f"{label}{suffix}: contains {describe(found)}")
        elif unscannable and session.settings.unscannable_policy != "allow":
            what = f"{unscannable} file(s) in it cannot be checked" if suffix else "it cannot be checked"
            problems.append(f"{label}{suffix}: {what} (image, PDF, binary, not UTF-8 or too large)")
    return problems


def block_prompt(reason: str) -> dict:
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}


def user_prompt_submit(session: Session, data: dict, record: dict):
    prompt = data.get("prompt")
    if not isinstance(prompt, str) or not prompt:
        return None
    try:
        session.health()
    except Exception as error:
        record["unhealthy"] = safe_code(error)
        if prompt.lstrip().startswith("/datafog:"):
            return None   # the plugin's own commands must stay usable to repair it
        return block_prompt(f"DataFog guard cannot check this prompt ({failure_text(error)}), so it was not sent. "
                            + DOCTOR_HINT)
    tokenized, counts = session.vault.tokenize(prompt)
    if counts:
        record["replaced"] = dict(counts)
        return block_prompt(
            f"DataFog: your prompt was not sent because it contains {describe(counts)}. "
            "Claude Code does not let a plugin rewrite a prompt, so submit this version instead "
            "(each marker stands for your value and is swapped back locally when Claude writes it):\n\n"
            + tokenized)
    if os.environ.get("CLAUDE_CODE_DISABLE_FILE_MENTIONS") == "1":
        return None   # @file is then an ordinary Read, which the Read hook covers
    problems = check_mentions(session, prompt, str(data.get("cwd") or ""))
    if problems:
        record["mentions_blocked"] = len(problems)
        return block_prompt(
            "DataFog: your prompt was not sent. An @ mention attaches file content directly, "
            "where no plugin can replace values in it.\n  " + "\n  ".join(problems) + "\n"
            "Remove the @ and ask Claude to read the file(s) instead (for example: \"read notes.txt\"); "
            "reads go through DataFog.")
    return None


# ---------------------------------------------------------------------------
# SessionStart
# ---------------------------------------------------------------------------
def status_line(session: Session, healthy: bool, problem: str = "") -> str:
    settings = session.settings
    place = {"env": "DATAFOG_VAULT_DIR", "user-data": "user data folder (kept on uninstall)",
             "plugin-data": "plugin data folder (deleted on uninstall)"}[settings.vault_location]
    if not healthy:
        return f"DataFog guard: NOT PROTECTING ({problem}). Tool calls are blocked. " + DOCTOR_HINT
    bash = "filtered" if settings.bash_wrap == "runner" else "NOT FILTERED"
    return (f"DataFog guard: on. Vault: {place}, not encrypted at rest. Bash output: {bash}. "
            f"Markers in Bash commands: {settings.restore_in_bash}. "
            f"Detecting: {', '.join(settings.entities)}. Names and free-text addresses are not detected.")


def session_start(session: Session, data: dict, record: dict):
    config.save_runtime_options(session.settings.data_dir)
    files.clean_shadows(session.settings.shadow_dir)
    try:
        session.health()
    except Exception as error:
        record["unhealthy"] = safe_code(error)
        line = status_line(session, False, failure_text(error))
        return {"systemMessage": line,
                "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": line}}
    return {"systemMessage": status_line(session, True),
            "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": MARKER_NOTE}}


# ---------------------------------------------------------------------------
def emit(out) -> int:
    if out:
        sys.stdout.write(json.dumps(out))
        sys.stdout.flush()
    return 0


def main() -> int:
    started = time.perf_counter()
    try:
        data = json.loads(sys.stdin.read())
        if not isinstance(data, dict):
            raise ValueError
    except Exception:
        # Unknown event: exit 2 blocks where blocking is possible.
        sys.stderr.write("DataFog guard: the hook input could not be read; blocked.\n")
        return 2
    event = str(data.get("hook_event_name") or "")
    record: dict = {"event": event, "tool": data.get("tool_name")}
    out = None
    session = None
    try:
        session = Session()
        if event not in ("SessionStart",):
            config.save_runtime_options(session.settings.data_dir)
        if event == "PreToolUse":
            out = pre_tool_use(session, data, record)
        elif event == "PostToolUse":
            out = post_tool_use(session, data, record)
        elif event == "UserPromptSubmit":
            out = user_prompt_submit(session, data, record)
        elif event == "SessionStart":
            out = session_start(session, data, record)
    except BaseException as error:   # includes KeyboardInterrupt/SystemExit: still fail closed
        record["error"] = safe_code(error)
        text = failure_text(error) if isinstance(error, Exception) else "interrupted"
        if event == "PreToolUse":
            out = deny(f"DataFog guard failed while checking this call ({text}), so it was blocked. " + DOCTOR_HINT)
        elif event == "PostToolUse":
            try:
                out = post_withheld(data)
                record["action"] = "withheld"
            except BaseException:
                out = None
        elif event == "UserPromptSubmit":
            out = block_prompt(f"DataFog guard failed while checking this prompt ({text}); it was not sent. "
                               + DOCTOR_HINT)
        elif event == "SessionStart":
            out = {"systemMessage": f"DataFog guard: NOT PROTECTING ({text}). " + DOCTOR_HINT}
    record["ms"] = round((time.perf_counter() - started) * 1000, 1)
    if out and "hookSpecificOutput" in out:
        record["decision"] = out["hookSpecificOutput"].get("permissionDecision")
    try:
        log.write((session.settings if session else config.load()).log_path, **record)
    except BaseException:
        pass
    return emit(out)
