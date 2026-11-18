"""The user's own Claude Code permission rules, applied to a Bash command by the plugin.

Why the plugin does this at all: PreToolUse rewrites every Bash command so that it runs
behind the output filter (bashwrap.wrap). Claude Code evaluates permission rules against
the REWRITTEN command (hooks reference, `updatedInput`: "Claude Code evaluates permission
rules ... against the input your hook returns, not the input Claude sent"), so a rule such
as ``Bash(cat *)`` no longer matches anything. The hook therefore reads the same rules
and returns its own ``permissionDecision`` for the ORIGINAL command.

Posture (after two reviews in which every enumeration of dangerous shell constructs was
bypassed by a neighbouring one): a command is first classified PLAIN or NOT PLAIN by the one
strict recogniser in plain.py. Only a plain command is split into sub-commands, has its
paths checked and can be approved by an allow rule. A command that is not plain is never
approved, and never left undecided, while any deny or ask rule exists: what the plugin finds
in it by scanning can deny it, and finding nothing proves nothing.

The one rule for everything in this file: never more permissive than Claude Code would
be. Where the documentation is silent or ambiguous the stricter reading is used; each such
choice is marked STRICTER below and listed in the README. Extra prompts are acceptable;
an approval Claude Code would not have given is not.

Documentation this follows (code.claude.com/docs/en, read 2026-11):

* permissions  "Rules are evaluated in order: deny, then ask, then allow. The first match in
  that order determines the outcome, and rule specificity doesn't change the order."
* permissions, Wildcard patterns: no ``*`` is an exact match; ``*`` matches any text
  including spaces; a trailing `` *`` that is the rule's only wildcard also matches the
  bare command; the space before a trailing ``*`` is part of the rule; ``:*`` at the end is
  the same as a trailing `` *`` and is a literal colon anywhere else.
* permissions, Compound commands: separators are ``&&``, ``||``, ``;``, ``|``, ``|&``, ``&``
  and newlines; "A rule must match each subcommand independently"; "Deny and ask rules apply
  when any subcommand matches them, including a command nested inside a subshell, a command
  substitution, or a control-flow body".
* permissions, Wrappers: ``timeout``, ``time``, ``nice``, ``nohup``, ``stdbuf``, ``command``,
  ``builtin``, ``noglob`` and bare ``xargs`` are stripped before matching; "A deny or ask rule
  matches past any leading assignment"; "An allow rule won't match past an assignment of any
  other variable" than a known-safe one.
* permissions, Exec wrappers and find actions: a prefix rule cannot approve them; an exact
  rule can.
* permissions, Extend permissions with hooks: "Claude Code evaluates deny and ask rules
  regardless of what a PreToolUse hook returns".
* settings, Settings precedence: managed, command line, project local, shared project, user;
  "Lists merge instead of overriding".
* permissions, Project allow rules and workspace trust: allow rules in a project's
  ``.claude/settings.json`` apply only after the folder was trusted, and never in a ``-p``
  run of an untrusted folder; ``deny`` and ``ask`` rules apply right away.
* permission-modes: what each mode does with ask rules, deny rules and hook approvals.

What the plugin cannot read, and so cannot follow: ``--allowedTools``, ``--disallowedTools``,
``--settings``, ``--setting-sources``, server-managed settings, MDM policies (plist,
registry), rules an embedding host supplies, and "allow for this session" choices that are
not written to disk. Invisible ALLOW rules cost extra prompts. Invisible DENY and ASK rules
are a real limit: Claude Code checks them against the rewritten command, where they
normally do not match.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import sys

from . import plain as grammar

BASH_PARAMS = ("description", "timeout", "run_in_background", "dangerouslyDisableSandbox")
MODES = ("default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions")

# Stripped before matching by Claude Code (permissions, Wrappers) ...
DOC_WRAPPERS = frozenset({"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob", "xargs"})
# ... and programs that also run their arguments as a command. STRICTER: for deny and ask rules these are
# stripped as well; an allow rule with a wildcard never approves a command that starts with any of them.
EXTRA_WRAPPERS = frozenset("""
    env sudo doas exec nocorrect setsid ionice chrt taskset flock watch strace ltrace unbuffer caffeinate chronic
    chroot nsenter unshare runuser pkexec fakeroot
""".split())
WRAPPERS = DOC_WRAPPERS | EXTRA_WRAPPERS
SHELLS = frozenset("sh bash zsh dash ksh mksh ash fish".split())
RESERVED = frozenset("if then elif else fi for while until do done case esac select function time coproc in "
                     "{ } ! [[ ]]".split())
_LEADING_WORDS = frozenset({"if", "then", "elif", "else", "while", "until", "do", "!", "{", "time"})
_FIND_ACTIONS = frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete", "-rm", "-fprint", "-fprint0", "-fprintf",
                           "-fls", "-files0-from"})
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_OPTION_LIKE = re.compile(r"-.*|\d+(?:\.\d+)?[smhd]?|[A-Za-z_][A-Za-z0-9_]*=.*")
_MOUNTED = ("/Volumes", "/System/Volumes", "/media", "/run/media", "/mnt")


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
class Rule:
    __slots__ = ("kind", "spec", "source", "param")

    def __init__(self, kind: str, spec: str | None, source: str, param: tuple[str, str] | None = None):
        self.kind, self.spec, self.source, self.param = kind, spec, source, param

    @property
    def exact(self) -> bool:
        return self.spec is not None and "*" not in self.spec

    def matches(self, text: str) -> bool:
        return spec_matches(self.spec, text)


def spec_matches(spec: str | None, text: str) -> bool:
    """permissions, Wildcard patterns. ``spec`` None is the bare tool name."""
    if spec is None or spec == "*":
        return True
    if spec.endswith(":*"):
        spec = spec[:-2] + " *"
    if "*" not in spec:
        return text == spec
    if spec.endswith(" *") and spec.count("*") == 1:
        prefix = spec[:-2]
        return text == prefix or text.startswith(prefix + " ")
    # `*` matches any text, including spaces. Leftmost matching of the middle parts is complete for
    # patterns that only have `*`, and takes linear time whatever the rule looks like.
    parts = spec.split("*")
    first, last = parts[0], parts[-1]
    if not text.startswith(first) or len(text) < len(first) + len(last) or not text.endswith(last):
        return False
    position, end = len(first), len(text) - len(last)
    for part in parts[1:-1]:
        found = text.find(part, position, end)
        if found < 0:
            return False
        position = found + len(part)
    return True


def parse_rule(entry, kind: str, source: str) -> Rule | None:
    """A rule that concerns the Bash tool, or None. Format: ``Tool`` or ``Tool(specifier)``."""
    if not isinstance(entry, str):
        return None
    entry = entry.strip()
    name, spec = entry, None
    if "(" in entry:
        name, _, rest = entry.partition("(")
        # "Parentheses inside the specifier are literal". A missing closing parenthesis is a malformed
        # rule; for deny and ask it is still honoured (STRICTER), for allow it is skipped.
        if rest.endswith(")"):
            spec = rest[:-1]
        elif kind == "allow":
            return None
        else:
            spec = rest
    name = name.strip()
    if name != "Bash":
        # Tool-name globs: deny and ask rules only ("Allow rules accept tool-name globs only after a
        # literal mcp__<server>__ prefix").
        if kind == "allow" or not any(char in name for char in "*?[") or not fnmatch.fnmatchcase("Bash", name):
            return None
    if spec is None or spec.strip() in ("", "*"):
        return Rule(kind, None, source)
    if kind == "allow" and "\\*" in spec:
        return None         # STRICTER: the docs do not say whether \* is a literal star; such allow rules are skipped
    match = re.fullmatch(r"\s*([A-Za-z_]+)\s*:\s*(.*)", spec, re.DOTALL)
    if match and match.group(1) == "command":
        return None         # "Claude Code ignores it and emits a startup warning"
    if match and match.group(1) in BASH_PARAMS and kind != "allow":
        return Rule(kind, spec, source, (match.group(1), match.group(2).strip()))
    return Rule(kind, spec, source)


CASE_INSENSITIVE = sys.platform == "darwin"       # the default macOS filesystem ignores case and Unicode form
MAX_PATH_LENGTH = 1024
MAX_PATH_SEGMENTS = 64


def _fold(text: str) -> str:
    """Paths and patterns as the filesystem compares them: NFC and case-folded on macOS."""
    if not CASE_INSENSITIVE:
        return text
    import unicodedata
    return unicodedata.normalize("NFC", text).casefold()


def _glob_source(pattern: str) -> str | None:
    """A gitignore-style pattern as regular-expression source over a /-separated relative path.
    ``*`` and ``?`` stay inside one segment, ``**`` crosses directories, ``[...]`` is a class."""
    out, i, n = [], 0, len(pattern)
    while i < n:
        char = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif char == "*":
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == "[":
            end = pattern.find("]", i + 2)
            if end < 0:
                out.append(re.escape(char))
                i += 1
            else:
                body = pattern[i + 1:end].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body + "]")
                i = end + 1
        elif char == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
        else:
            out.append(re.escape(char))
            i += 1
    source = "".join(out)
    try:
        re.compile(source)
    except re.error:
        return None
    return source


class PathRule:
    """A ``Read(pattern)`` or ``Edit(pattern)`` deny or ask rule (permissions, "Read and Edit").

    Pattern kinds, from the documentation's table: ``//path`` absolute; ``~/path`` from the home
    directory; ``/path`` relative to the settings source (the primary working directory for
    project and local settings, ``~/.claude`` for user settings); ``path`` or ``./path`` relative
    to the current directory. "A rule only matches files under its anchor."

    STRICTER than the documentation:
      * every relative pattern matches at any depth below the current directory (documented for
        bare names and for single-directory patterns in deny and ask rules; here for all);
      * a ``!`` pattern (a carve-out from other rules) is ignored, so nothing is carved out;
      * relative patterns are tried against the hook's cwd and against the project directory;
      * ``/path`` in managed settings (anchor not documented) is tried at the project directory
        and at the filesystem root;
      * a bare ``Read`` or ``Edit`` rule (the whole tool) covers every path;
      * a pattern that names only its anchor (``~/``, ``//``, ``.``, ``./``) covers the anchor and
        everything below it; empty and ``.`` segments are dropped (``a//b``, ``a/./b``);
      * a pattern with a ``..`` segment is UNSUPPORTED: the plugin cannot say what it covers, so
        while such a rule exists no Bash command is approved without a prompt.
    """
    __slots__ = ("tool", "kind", "source", "anchors", "relative", "pattern", "everything", "unsupported",
                 "written", "_real", "_compiled")

    def __init__(self, tool: str, kind: str, pattern: str | None, source: str, source_dirs: list[str]):
        self.tool, self.kind, self.source = tool, kind, source
        self.written = pattern or ""
        self.everything = pattern is None or pattern.strip() in ("", "*", "**")
        pattern = (pattern or "").strip()
        self.relative = False
        home = os.path.expanduser("~")
        if pattern.startswith("//"):
            self.anchors, pattern = ["/"], pattern[2:]
        elif pattern == "~" or pattern.startswith("~/"):
            self.anchors, pattern = [home], pattern[2:]
        elif pattern.startswith("/"):
            self.anchors, pattern = list(source_dirs), pattern[1:]
        else:
            self.relative, self.anchors = True, []
        parts = [part for part in pattern.split("/") if part not in ("", ".")]
        self.unsupported = ".." in parts or "\x00" in pattern or len(pattern) > MAX_PATH_LENGTH
        self.pattern = "/".join(parts)          # "" means: the anchor itself and everything below it
        self._compiled: dict = {}
        # "a deny or ask rule written through a symlinked directory with a //, ~/, or / pattern also
        # applies at the directory's real location": the literal leading part of the pattern is resolved.
        self._real: list[tuple[str, str]] = []
        if not self.relative and not self.everything and not self.unsupported:
            literal = 0
            while literal < len(parts) and not any(char in parts[literal] for char in "*?[\\"):
                literal += 1
            for anchor in self.anchors:
                folder = os.path.normpath(os.path.join(anchor, *parts[:literal]))
                try:
                    real = os.path.realpath(folder)
                except (OSError, ValueError):
                    continue
                if literal and real != folder:
                    self._real.append((real, "/".join(parts[literal:])))

    def _regex(self, pattern: str, any_depth: bool):
        """One expression for "this relative path, or a directory above it, matches"."""
        key = (pattern, any_depth, CASE_INSENSITIVE)
        if key not in self._compiled:
            source = _glob_source(_fold(pattern))
            if source is None:                                   # "still guards that exact path"
                source = re.escape(_fold(pattern))
            self._compiled[key] = re.compile(("(?:.*/)?" if any_depth else "") + "(?:" + source + ")(?:/.*)?",
                                             re.DOTALL)
        return self._compiled[key]

    def _anchors(self, cwds: list[str]) -> list[str]:
        found = []
        for anchor in (cwds if self.relative else self.anchors):
            candidates = [anchor]
            try:
                candidates.append(os.path.realpath(anchor))
            except (OSError, ValueError):
                pass
            for folder in candidates:
                folder = os.path.normpath(folder)
                if folder not in found:
                    found.append(folder)
        return found

    def matches(self, path: str, cwds: list[str]) -> bool:
        """``path`` is absolute and normalised. A rule that matches a directory covers what is in it."""
        if self.everything:
            return True
        if self.unsupported:
            return False
        path = _fold(path)
        places = [(anchor, self.pattern, self.relative) for anchor in self._anchors(cwds)]
        places += [(folder, rest, False) for folder, rest in self._real]
        for anchor, pattern, any_depth in places:
            anchor = _fold(anchor)
            prefix = anchor.rstrip("/") + "/"
            if not pattern:
                if path == anchor or path.startswith(prefix):
                    return True
                continue
            if path.startswith(prefix) and self._regex(pattern, any_depth).fullmatch(path[len(prefix):]):
                return True
        return False

    def may_cover_inside(self, folder: str, cwds: list[str]) -> bool:
        """Whether the rule could match something below ``folder`` (or ``folder`` lies in its reach)."""
        if self.everything or self.unsupported:
            return True
        folder = _fold(folder).rstrip("/") + "/"
        for anchor in self._anchors(cwds) + [real for real, _ in self._real]:
            anchor = _fold(anchor).rstrip("/") + "/"
            if anchor.startswith(folder) or folder.startswith(anchor):
                return True
        return False


def parse_path_rule(entry, kind: str, source: str, source_dirs: list[str]) -> PathRule | None:
    """A Read or Edit deny/ask rule, or None. Write(path), NotebookEdit(path) and Glob(path) "never match"."""
    if not isinstance(entry, str) or kind == "allow":
        return None
    entry = entry.strip()
    name, pattern = entry, None
    if "(" in entry:
        name, _, rest = entry.partition("(")
        pattern = rest[:-1] if rest.endswith(")") else rest
    name = name.strip()
    tools = [tool for tool in ("Read", "Edit") if name == tool or
             (any(char in name for char in "*?[") and fnmatch.fnmatchcase(tool, name))]
    if not tools:
        return None
    if pattern is not None and pattern.lstrip().startswith("!"):
        return None                       # a carve-out only loosens other rules: ignored (STRICTER)
    return PathRule("+".join(tools), kind, pattern, source, source_dirs)


class RuleSet:
    def __init__(self):
        self.deny: list[Rule] = []
        self.ask: list[Rule] = []
        self.allow: list[Rule] = []
        self.paths: list[PathRule] = []        # Read and Edit deny and ask rules
        self.problems: list[str] = []          # labels of sources that could not be read completely
        self.allow_usable = True               # False: some source was unreadable, so nothing is allowed by rule
        self.block_outside_reads = False
        self.notes: list[str] = []

    def add(self, other_rules, kind: str, source: str, source_dirs: list[str] | None = None) -> None:
        if not isinstance(other_rules, list):
            if other_rules is not None:
                self.problem(source)
            return
        for entry in other_rules:
            if not isinstance(entry, str):
                self.problem(source)
                continue
            rule = parse_rule(entry, kind, source)
            if rule is not None:
                getattr(self, kind).append(rule)
            path_rule = parse_path_rule(entry, kind, source, source_dirs or [])
            if path_rule is not None:
                self.paths.append(path_rule)

    def problem(self, source: str) -> None:
        if source not in self.problems:
            self.problems.append(source)
        self.allow_usable = False


def managed_dirs() -> list[str]:
    """managed-settings, Where each mechanism stores the policy (file-based)."""
    if sys.platform == "darwin":
        return ["/Library/Application Support/ClaudeCode"]
    if os.name == "nt":
        return [os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "ClaudeCode")]
    return ["/etc/claude-code"]


def config_home(env=None) -> str:
    env = os.environ if env is None else env
    return env.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")


def _salvage(text: str, rules: RuleSet, source: str, source_dirs: list[str] | None = None) -> None:
    """A settings file that is not valid JSON: keep whatever deny and ask entries can still be found
    (for Bash, and Read and Edit path rules)."""
    for kind in ("deny", "ask"):
        for block in re.findall(r'"%s"\s*:\s*\[([^\]]*)' % kind, text):
            for raw in re.findall(r'"((?:[^"\\]|\\.)*)"', block):
                try:
                    entry = json.loads('"%s"' % raw)
                except ValueError:
                    entry = raw
                rule = parse_rule(entry, kind, source)
                if rule is not None:
                    getattr(rules, kind).append(rule)
                path_rule = parse_path_rule(entry, kind, source, source_dirs or [])
                if path_rule is not None:
                    rules.paths.append(path_rule)


def _read(path: str, rules: RuleSet, source: str, source_dirs: list[str] | None = None) -> dict | None:
    """The parsed settings file; None when absent. Problems are recorded, never raised."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(4 * 1024 * 1024)
    except FileNotFoundError:
        return None
    except NotADirectoryError:
        return None
    except OSError:
        rules.problem(source)
        return None
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")
        rules.problem(source)
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        rules.problem(source)
        _salvage(text, rules, source, source_dirs)
        return None
    if not isinstance(data, dict):
        rules.problem(source)
        return None
    return data


def _permissions(data: dict | None, rules: RuleSet, source: str) -> dict:
    if not data:
        return {}
    permissions = data.get("permissions")
    if permissions is None:
        return {}
    if not isinstance(permissions, dict):
        rules.problem(source)
        return {}
    if permissions.get("blockReadsOutsideWorkingDirectories") is True:
        rules.block_outside_reads = True          # "true from any scope" is honoured
    return permissions


def _git_roots(start: str) -> tuple[str | None, str | None]:
    """(root of the repository containing ``start``, root of its main checkout if it is a worktree)."""
    current = os.path.abspath(start)
    for _ in range(64):
        marker = os.path.join(current, ".git")
        if os.path.isdir(marker):
            return current, None
        if os.path.isfile(marker):
            main = None
            try:
                with open(marker, encoding="utf-8", errors="replace") as handle:
                    line = handle.read(4096).strip()
                if line.startswith("gitdir:"):
                    target = line[7:].strip()
                    if not os.path.isabs(target):
                        target = os.path.normpath(os.path.join(current, target))
                    head, separator, _ = target.replace("\\", "/").partition("/.git/worktrees/")
                    if separator:
                        main = head
            except OSError:
                pass
            return current, main
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None, None


def _trusted(folders: list[str], env) -> bool:
    """permissions, What runs before you trust a folder: projects["<path>"].hasTrustDialogAccepted."""
    home = config_home(env)
    candidates = [os.path.join(os.path.expanduser("~"), ".claude.json")]
    if env.get("CLAUDE_CONFIG_DIR"):
        candidates.insert(0, os.path.join(home, ".claude.json"))
    wanted = set()
    for folder in folders:
        wanted.add(folder)
        wanted.add(os.path.realpath(folder))
    for path in candidates:
        try:
            if os.path.getsize(path) > 32 * 1024 * 1024:
                continue
            with open(path, encoding="utf-8") as handle:
                projects = json.load(handle).get("projects")
        except (OSError, ValueError, AttributeError, RecursionError):
            continue
        if isinstance(projects, dict):
            for name in wanted:
                entry = projects.get(name)
                if isinstance(entry, dict) and entry.get("hasTrustDialogAccepted") is True:
                    return True
    return False


def _tracked_by_git(root: str, path: str) -> bool | None:
    """True/False, or None when it cannot be determined."""
    import subprocess
    try:
        result = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", "--", os.path.relpath(path, root)],
                                capture_output=True, timeout=3, stdin=subprocess.DEVNULL,
                                env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"))
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if result.returncode == 0:
        return True
    return False if result.returncode == 1 else None


def load(project_dir: str, env=None, managed=None) -> RuleSet:
    """Read every settings file the plugin can see. Never raises.

    Settings precedence does not matter for the outcome: lists merge, and deny > ask > allow
    whatever file a rule comes from ("deny rules from any scope are evaluated before allow rules").
    """
    env = os.environ if env is None else env
    rules = RuleSet()
    managed_only = False
    project_anchor = [project_dir] if project_dir else []
    managed_anchor = project_anchor + ["/"]

    # 1. Managed settings files: managed-settings.json, then managed-settings.d/*.json in
    #    alphabetical order (managed-settings, "Claude Code merges managed-settings.json first, then
    #    every *.json file in the directory in alphabetical order ... ignores hidden files").
    for directory in (managed_dirs() if managed is None else managed):
        paths = [os.path.join(directory, "managed-settings.json")]
        drop_in = os.path.join(directory, "managed-settings.d")
        try:
            paths += [os.path.join(drop_in, name) for name in sorted(os.listdir(drop_in))
                      if name.endswith(".json") and not name.startswith(".")]
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError:
            rules.problem("managed settings")
        for path in paths:
            data = _read(path, rules, "managed settings", managed_anchor)
            permissions = _permissions(data, rules, "managed settings")
            for kind in ("deny", "ask", "allow"):
                rules.add(permissions.get(kind), kind, "managed settings", managed_anchor)
            if data and data.get("allowManagedPermissionRulesOnly") not in (None, False):
                managed_only = True           # an unreadable value "reads as that value" (the restrictive one)

    def take(path: str, source: str, allow_ok, anchor: list[str]) -> None:
        data = _read(path, rules, source, anchor)
        permissions = _permissions(data, rules, source)
        # STRICTER: with allowManagedPermissionRulesOnly Claude Code ignores deny and ask rules from
        # other files too; they are kept here because they only restrict.
        rules.add(permissions.get("deny"), "deny", source, anchor)
        rules.add(permissions.get("ask"), "ask", source, anchor)
        allow = permissions.get("allow")
        if allow is None:
            return
        if managed_only:
            rules.notes.append(f"allow rules in {source} ignored: allowManagedPermissionRulesOnly")
            return
        if not isinstance(allow, list) or any(not isinstance(entry, str) for entry in allow):
            rules.problem(source)             # STRICTER: Claude Code skips a malformed entry; here it voids allow
            return
        if not any(parse_rule(entry, "allow", source) for entry in allow):
            return                            # nothing for Bash in it: no need to establish trust
        if allow_ok():
            rules.add(allow, "allow", source)
        else:
            rules.notes.append(f"allow rules in {source} not applied: the folder is not recorded as trusted")

    # 2. User settings.
    take(os.path.join(config_home(env), "settings.json"), "user settings", lambda: True, [config_home(env)])

    # 3. Project settings, 4. local project settings.
    if project_dir and os.path.isdir(project_dir):
        root, main = _git_roots(project_dir)
        trust_folder = main or root or project_dir
        cache: dict = {}

        def trusted() -> bool:
            if "trusted" not in cache:
                cache["trusted"] = _trusted([trust_folder], env)
            return cache["trusted"]

        take(os.path.join(project_dir, ".claude", "settings.json"), "project settings", trusted, project_anchor)
        seen = set()
        for folder in (project_dir, root, main):
            if not folder or os.path.realpath(folder) in seen:
                continue
            seen.add(os.path.realpath(folder))
            path = os.path.join(folder, ".claude", "settings.local.json")

            def local_ok(folder=folder, path=path) -> bool:
                # permissions, When your local settings file needs trust: the file counts as the
                # user's own unless it is tracked in git or .claude is a symlink.
                if trusted():
                    return True
                if os.path.islink(os.path.join(folder, ".claude")) or os.path.islink(path):
                    return False
                repository = _git_roots(folder)[0]
                if repository is None:
                    return True
                return _tracked_by_git(repository, path) is False

            take(path, "local project settings", local_ok, project_anchor)
    return rules


# ---------------------------------------------------------------------------
# Reading a command the way the rules see it
# ---------------------------------------------------------------------------
class Split:
    def __init__(self):
        self.commands: list[str] = []      # every sub-command, nested ones included
        self.certain = True                # False: quoting or nesting could not be followed


def _matching(text: str, start: int, split: Split, depth: int) -> int:
    """``start`` is just after an opening ``(``: scan the nested command list, return the index after ``)``."""
    end = _scan(text, start, split, depth + 1, ")")
    return end


def _scan(text: str, i: int, split: Split, depth: int, closer: str) -> int:
    n = len(text)
    current: list[str] = []
    heredocs: list[tuple[str, bool]] = []

    def flush() -> None:
        command = "".join(current).strip()
        current.clear()
        if command:
            split.commands.append(command)

    if depth > 30:
        split.certain = False
        return n
    word_start = True
    while i < n:
        char = text[i]
        if char == closer:
            flush()
            return i + 1
        if char == "\\":
            current.append(text[i:i + 2])
            i += 2
            word_start = False
            continue
        if char == "'":
            end = text.find("'", i + 1)
            if end < 0:
                split.certain = False
                end = n - 1
            current.append(text[i:end + 1])
            i = end + 1
            word_start = False
            continue
        if char == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 2
                elif text[j] == "$" and text[j + 1:j + 2] == "(":
                    j = _matching(text, j + 2, split, depth)
                elif text[j] == "`":
                    j = _backticks(text, j, split, depth)
                else:
                    j += 1
            if j >= n:
                split.certain = False
            current.append(text[i:j + 1])
            i = j + 1
            word_start = False
            continue
        if char == "`":
            end = _backticks(text, i, split, depth)
            current.append(text[i:end])
            i = end
            word_start = False
            continue
        if char == "$" and text[i + 1:i + 2] == "(":
            end = _matching(text, i + 2, split, depth)
            current.append(text[i:end])
            i = end
            word_start = False
            continue
        if char in "<>" and text[i + 1:i + 2] == "(":
            end = _matching(text, i + 2, split, depth)
            current.append(text[i:end])
            i = end
            word_start = False
            continue
        if char == "<" and text.startswith("<<", i) and not text.startswith("<<<", i):
            match = re.match(r"<<-?[ \t]*(['\"]?)([^\s'\"<>;&|()]+)\1", text[i:])
            if match:
                heredocs.append((match.group(2).replace("\\", ""), text.startswith("<<-", i)))
                current.append(match.group(0))
                i += len(match.group(0))
                continue
            split.certain = False
        if char == "(":
            # a subshell, a function body, an array: whatever it is, what is inside counts as commands
            flush()
            i = _matching(text, i + 1, split, depth)
            word_start = True
            continue
        if char == ")":
            split.certain = False          # unbalanced
            flush()
            i += 1
            continue
        if char == "#" and word_start:
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if char == "\n":
            flush()
            i += 1
            for delimiter, strip in heredocs:
                while True:
                    if i >= n:
                        split.certain = False
                        break
                    end = text.find("\n", i)
                    end = n if end < 0 else end
                    line = text[i:end]
                    i = min(end + 1, n)
                    if (line.lstrip("\t") if strip else line) == delimiter:
                        break
            heredocs = []
            word_start = True
            continue
        if char in ";&|":
            if char == "&" and (text[i + 1:i + 2] == ">" or (i and text[i - 1] in "<>")):
                current.append(char)       # &> and >& are redirections
                i += 1
                continue
            flush()
            i += 2 if text[i:i + 2] in ("&&", "||", "|&", ";;") else 1
            word_start = True
            continue
        if char in "{}" and word_start and (i + 1 >= n or text[i + 1] in " \t\n;"):
            flush()
            i += 1
            continue
        current.append(char)
        word_start = char in " \t"
        i += 1
    if closer or heredocs:
        split.certain = False
    flush()
    return n


def _backticks(text: str, i: int, split: Split, depth: int) -> int:
    j = i + 1
    inner: list[str] = []
    while j < len(text) and text[j] != "`":
        if text[j] == "\\" and j + 1 < len(text):
            inner.append(text[j + 1] if text[j + 1] in "`\\$" else text[j:j + 2])
            j += 2
        else:
            inner.append(text[j])
            j += 1
    if j >= len(text):
        split.certain = False
    _scan("".join(inner), 0, split, depth + 1, "")
    return min(j + 1, len(text))


def split_commands(command: str) -> Split:
    """Every sub-command of ``command``: separated by ``&& || ; | |& &`` and newlines, and
    nested in subshells, command and process substitutions, backticks, groups and control flow.
    Tolerant: it never fails; what it cannot follow makes the result uncertain."""
    split = Split()
    try:
        _scan(command, 0, split, 0, "")
    except (RecursionError, IndexError):
        split.certain = False
    if not split.certain:
        # Crude second opinion for deny and ask rules: cut at every operator, quotes ignored.
        for piece in re.split(r"[;&|\n(){}`]+|\$\(", command):
            piece = piece.strip()
            if piece and piece not in split.commands:
                split.commands.append(piece)
    return split


def _words(command: str, keep_redirects: bool = False) -> list[tuple[str, str]]:
    """(raw text, text with quotes removed) for each word. Redirection operators are left out, and
    so are their targets unless ``keep_redirects``."""
    words: list[tuple[str, str]] = []
    raw: list[str] = []
    plain: list[str] = []
    i, n = 0, len(command)
    skip_next = False

    def flush() -> None:
        nonlocal skip_next
        if raw:
            if skip_next:
                skip_next = False
            else:
                words.append(("".join(raw), "".join(plain)))
            raw.clear()
            plain.clear()

    while i < n:
        char = command[i]
        if char in " \t\n":
            flush()
            i += 1
        elif char in "<>" or (char == "&" and command[i + 1:i + 2] == ">"):
            if raw and "".join(raw).isdigit():
                raw.clear()
                plain.clear()
            flush()
            while i < n and command[i] in "<>&|-":
                i += 1
            if not (i < n and command[i].isdigit() and command[i - 1] == "&") and not keep_redirects:
                skip_next = True
        elif char == "\\" and i + 1 < n:
            raw.append(command[i:i + 2])
            plain.append(command[i + 1])
            i += 2
        elif char in "'\"":
            end = command.find(char, i + 1)
            end = n if end < 0 else end
            raw.append(command[i:end + 1])
            plain.append(command[i + 1:end])
            i = end + 1
        else:
            raw.append(char)
            plain.append(char)
            i += 1
    flush()
    return words


def candidates(command: str, depth: int = 0) -> list[str]:
    """The texts a deny or ask rule is tried against for one sub-command.

    From the documentation: the command as written; with leading assignments removed ("matches
    past any leading assignment"); with the documented wrappers removed.
    STRICTER than the documentation, which says a rule "doesn't match the same program invoked
    in a different form": also with the command name unquoted (``\\rm``, ``'rm'``), reduced to
    its base name (``/bin/rm``), after further wrappers (``env``, ``sudo`` ...), and inside
    ``sh -c '...'`` and ``eval``.
    """
    found: list[str] = []

    def add(text: str) -> None:
        text = text.strip()
        if text and text not in found:
            found.append(text)

    add(command)
    words = _words(command)
    add(" ".join(raw for raw, _ in words))
    for _ in range(12):
        while words and (words[0][1] in _LEADING_WORDS or _ASSIGNMENT.match(words[0][0])):
            words = words[1:]
        if not words:
            break
        name = os.path.basename(words[0][1]) or words[0][1]
        rest = " ".join(raw for raw, _ in words[1:])
        add(words[0][0] + " " + rest)
        add(words[0][1] + " " + rest)
        add(name + " " + rest)
        if depth < 3 and (name in SHELLS or name == "eval"):
            inner = [plain for _, plain in words[1:]]
            if name == "eval":
                script = " ".join(inner)
            else:
                script = ""
                for index, word in enumerate(inner[:-1]):
                    if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", word):
                        script = inner[index + 1]
                        break
            for sub in split_commands(script).commands:
                for text in candidates(sub, depth + 1):
                    add(text)
        if name not in WRAPPERS:
            break
        # After a wrapper its own options and their values come first; which words those are depends
        # on the wrapper, so every later starting point is tried.
        for start in range(2, min(len(words), 10)):
            tail = words[start:]
            add(" ".join(raw for raw, _ in tail))
            add(" ".join([os.path.basename(tail[0][1]) or tail[0][1]] + [raw for raw, _ in tail[1:]]))
        words = words[1:]
        while len(words) > 1 and _OPTION_LIKE.fullmatch(words[0][1]):
            words = words[1:]
    return found


def first_rule(rules: list[Rule], split: Split, command: str, tool_input: dict | None = None) -> Rule | None:
    """The first deny or ask rule that matches the command or any of its sub-commands."""
    texts = [command.strip()]
    for sub in split.commands:
        for text in candidates(sub):
            if text not in texts:
                texts.append(text)
    for rule in rules:
        if rule.param is not None and tool_input is not None:
            name, wanted = rule.param
            if name in tool_input and not isinstance(tool_input[name], (dict, list)):
                value = tool_input[name]
                shown = ("true" if value else "false") if isinstance(value, bool) else str(value)
                if spec_matches(wanted, shown):
                    return rule
        if any(rule.matches(text) for text in texts):
            return rule
    return None


def is_simple(command: str, markers=()) -> bool:
    """Whether an allow rule may be applied to this command. Deliberately strict; loosen it here.

    SIMPLE means: PLAIN (plain.py: literal words only, no expansion of any kind), and
      * exactly one command: no ``|``, ``&&``, ``||``, ``;``;
      * no redirection;
      * no newline anywhere, not even inside quotes;
      * at most 10,000 characters.
    """
    if len(command) > 10_000 or "\n" in command:
        return False
    parsed = grammar.recognise(command.strip(), markers)
    return parsed is not None and len(parsed.commands) == 1 and not parsed.commands[0].redirected


def allow_rule_for(rules: RuleSet, command: str, exact_only: bool = False) -> Rule | None:
    """The allow rule that approves a SIMPLE command, or None. The caller checked deny and ask."""
    text = command.strip()
    words = _words(text)
    name = os.path.basename(words[0][1]) if words else ""
    unquoted = bool(words) and words[0][0] == words[0][1]
    # permissions, Exec wrappers and find actions: "A prefix rule ... can't auto-approve" these; "write
    # an exact-match rule for the full command string". STRICTER: the same for every wrapper, including
    # the ones Claude Code strips (the docs do not say whether the unstripped text is matched as well),
    # for shells and eval, and for a command name that is quoted or escaped.
    needs_exact = exact_only or not unquoted or name in WRAPPERS or name in SHELLS or name == "eval" or \
        name in ("watch", "setsid", "ionice", "flock") or \
        (name == "find" and any(plain in _FIND_ACTIONS for _, plain in words[1:]))
    for rule in rules.allow:
        if needs_exact and not rule.exact:
            continue
        if rule.matches(text):
            return rule
    return None


def rm_needs_review(split: Split, cwd: str) -> bool:
    """Whether an ``rm`` or ``rmdir`` in the command could be one of Claude Code's "critical-path
    removals", which "no allow rule or PreToolUse hook" approves (permission-modes, Critical paths).

    Claude Code cannot recognise them inside the rewritten command, so the plugin must not
    approve them either. Documented critical paths: the filesystem root and its direct children,
    the home directory, the working directory and its parents, mounted drive paths, and targets
    built from variables, substitutions or globs. STRICTER: every target that is not a plain
    literal path is treated as critical.
    """
    cwd = os.path.realpath(cwd or os.getcwd())
    home = os.path.realpath(os.path.expanduser("~"))
    for sub in split.commands:
        for text in candidates(sub):
            words = _words(text)
            if not words or os.path.basename(words[0][1]) not in ("rm", "rmdir"):
                continue
            if not split.certain or any(cwd == prefix or cwd.startswith(prefix + "/") for prefix in _MOUNTED):
                return True
            for raw, plain in words[1:]:
                if plain.startswith("-") and raw == plain:
                    continue
                if not plain or plain.startswith("~") or any(char in raw for char in "$`*?[]{}\\"):
                    return True
                target = os.path.normpath(os.path.join(cwd, plain))
                for path in {target, os.path.realpath(target)}:
                    if (path == "/" or os.path.dirname(path) == "/" or path == home or path == cwd
                            or cwd.startswith(path.rstrip("/") + "/")
                            or any(path == prefix or path.startswith(prefix + "/") for prefix in _MOUNTED)):
                        return True
    if not split.certain and re.search(r"(?<![\w.-])(?:rm|rmdir)(?![\w.-])", " ".join(split.commands)):
        return True
    return False


# ---------------------------------------------------------------------------
# Read and Edit rules applied to a Bash command
# ---------------------------------------------------------------------------
_PIECES = re.compile(r"[\s=:,;|&<>()'\"@]+")
_SUFFIXES = re.compile(r"[=:,@]")
_LOOSE = re.compile(r"[\s;|&<>()`$]+")
WALK_LIMIT = 3000
MAX_BASES = 8
MAX_LOOSE_TOKENS = 3000


class PathFinding:
    def __init__(self):
        self.deny: PathRule | None = None      # a deny rule matches a path the command names
        self.ask: PathRule | None = None       # an ask rule matches one
        self.unsure = ""                       # why a path rule may apply although no named path matches


def _texts_of(text: str) -> list[str]:
    """What in one word may be a path: the word, what follows ``=`` ``:`` ``,`` ``@`` in it, and every
    tail of a short-option cluster (``-fPATH``, ``-hfPATH``, ``-nfPATH``)."""
    found = [text]
    for match in _SUFFIXES.finditer(text):
        found.append(text[match.end():])
    if text.startswith("-") and not text.startswith("--"):
        found.extend(text[index:] for index in range(2, min(len(text), 66)))
    return [item for item in dict.fromkeys(found) if item and item != "-"]


def _rule_for(rules: RuleSet, paths: list[str], kind: str, cwds: list[str]) -> PathRule | None:
    for rule in rules.paths:
        if rule.kind == kind and any(rule.matches(path, cwds) for path in paths):
            return rule
    return None


def check_paths(rules: RuleSet, parsed: grammar.Plain, cwd: str, project_dir: str = "",
                marker_values: dict[str, str] | None = None) -> PathFinding:
    """Apply the user's Read and Edit deny and ask rules to what a PLAIN Bash command names.

    permissions, Read and Edit: the rules "apply to ... file commands Claude Code recognizes in Bash,
    such as cat, head, tail, sed, and tee, and to the targets of Bash redirections". Claude Code only
    sees the rewritten command, so the plugin has to do this.

    The command is plain (plain.py), so every word is literal text: nothing in it expands. For each
    word and redirection target, and for what follows ``=`` ``:`` ``,`` ``@`` in it and every tail of
    a short-option cluster:
      * it is taken as a path relative to the working directory AND to every existing directory
        the command names (``tar -C sub``, ``git -C``, ``--directory=``, ``env --chdir``: whatever the
        option is called, the program can only change into a directory that is named);
      * it is checked twice: resolved by the filesystem (symbolic links first, then ``..``, as the
        kernel does) and normalised as text;
      * against Read and Edit rules alike (whether a program reads or writes it is not known).
    A named directory that holds a covered path, or is too large to look through, and a covered
    path that is only mentioned inside a quoted argument (an inline script, a message) make the
    result "unsure": the caller asks, in every mode.

    STRICTER than the documentation, which limits all this to recognised file commands.
    Not covered, as in Claude Code: a command that reads files without naming them, and what a
    program opens on its own.

    ``marker_values`` maps the known markers in the command to their real values: a value may itself
    be a path, so words are checked with the values in place. They are used here and nowhere else.
    """
    finding = PathFinding()
    if not rules.paths:
        return finding
    cwd = os.path.normpath(cwd or os.getcwd())
    cwds = [cwd] + ([os.path.normpath(project_dir)] if project_dir and os.path.normpath(project_dir) != cwd else [])
    home = os.path.expanduser("~")
    direct: list[str] = []
    mentioned: list[str] = []
    for simple in parsed.commands:
        for word in simple.words + [target for _, target in simple.targets]:
            text = word.text
            for marker, value in (marker_values or {}).items():
                text = text.replace(marker, value)
            direct.extend(_texts_of(text))
            if not word.bare and any(char in text for char in " \t\n;|&()'\""):
                for piece in _PIECES.split(text):
                    mentioned.extend(_texts_of(piece) if piece else [])
    direct = list(dict.fromkeys(direct))
    mentioned = [text for text in dict.fromkeys(mentioned) if text not in direct]

    def too_long(text: str) -> bool:
        return len(text) > MAX_PATH_LENGTH or text.count("/") > MAX_PATH_SEGMENTS or "\x00" in text

    def resolved(text: str, bases: list[str]) -> list[str]:
        if text == "~" or text.startswith("~/"):
            text = home + text[1:]
        found = []
        for base in bases:
            joined = text if text.startswith("/") else base.rstrip("/") + "/" + text
            candidates = [os.path.normpath(joined)]
            try:
                candidates.append(os.path.realpath(joined))      # symbolic links first, then "..", like the kernel
            except (OSError, ValueError):
                pass
            for path in candidates:
                if path not in found:
                    found.append(path)
        return found

    # every existing directory the command names is a place a relative path may be meant from
    bases = [cwd]
    for _ in range(2):
        for text in direct:
            if too_long(text) or len(bases) >= MAX_BASES:
                continue
            for path in resolved(text, list(bases)):
                if path not in bases and len(bases) < MAX_BASES and os.path.isdir(path):
                    bases.append(path)

    walked = 0
    for text in direct:
        if too_long(text):
            finding.unsure = finding.unsure or "it names a path too long to check against your Read and Edit rules"
            continue
        paths = resolved(text, bases)
        finding.deny = finding.deny or _rule_for(rules, paths, "deny", cwds)
        finding.ask = finding.ask or _rule_for(rules, paths, "ask", cwds)
        for folder in paths:
            if finding.unsure or finding.deny or not os.path.isdir(folder):
                continue
            if not any(rule.may_cover_inside(folder, cwds) for rule in rules.paths):
                continue
            for base, folders, names in os.walk(folder):
                for name in folders + names:
                    walked += 1
                    inside = os.path.join(base, name)
                    if walked > WALK_LIMIT:
                        finding.unsure = "a directory it names is too large to check against your Read and Edit rules"
                    elif _rule_for(rules, [inside], "deny", cwds) or _rule_for(rules, [inside], "ask", cwds):
                        finding.unsure = "a Read or Edit rule covers something inside a directory it names"
                    if finding.unsure:
                        break
                if finding.unsure:
                    break
    for text in mentioned:
        if finding.unsure:
            break
        if too_long(text):
            continue
        paths = resolved(text, bases)
        if _rule_for(rules, paths, "deny", cwds) or _rule_for(rules, paths, "ask", cwds):
            finding.unsure = "a path covered by a Read or Edit rule is mentioned in it"
    return finding


def scan_paths(rules: RuleSet, command: str, cwd: str, project_dir: str = "") -> PathFinding:
    """Best effort for a command that is NOT plain: look for covered paths in its text.

    A hit denies or asks. No hit proves nothing: the caller never approves such a command without
    a prompt while any rule exists. Text only, bounded, no filesystem access.
    """
    finding = PathFinding()
    if not rules.paths:
        return finding
    cwd = os.path.normpath(cwd or os.getcwd())
    cwds = [cwd] + ([os.path.normpath(project_dir)] if project_dir and os.path.normpath(project_dir) != cwd else [])
    home = os.path.expanduser("~")
    text = command[:grammar.MAX_LENGTH].replace("\\\n", "").replace("\x00", "")
    seen = 0
    for token in _LOOSE.split(text):
        for variant in dict.fromkeys((token, token.replace("'", "").replace('"', "").replace("\\", ""))):
            for piece in _texts_of(variant):
                seen += 1
                if seen > MAX_LOOSE_TOKENS:
                    return finding
                if len(piece) > MAX_PATH_LENGTH or piece.count("/") > MAX_PATH_SEGMENTS:
                    continue
                if piece == "~" or piece.startswith("~/"):
                    piece = home + piece[1:]
                paths = [os.path.normpath(piece if piece.startswith("/") else cwd + "/" + piece)]
                finding.deny = finding.deny or _rule_for(rules, paths, "deny", cwds)
                finding.ask = finding.ask or _rule_for(rules, paths, "ask", cwds)
    return finding


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------
class Decision:
    def __init__(self, outcome: str | None, reason: str, step: int, rule: Rule | None = None, firm: bool = False):
        self.outcome = outcome        # "deny" | "ask" | "allow" | None (leave it to Claude Code)
        self.reason = reason
        self.step = step              # which line of the decision order applied (2-8)
        self.rule = rule
        self.firm = firm              # an ask that no permission mode may turn into an approval


def decide(command: str, rules: RuleSet, *, mode: str = "default", markers: str = "", restore: str = "ask",
           egress: bool = False, tool_input: dict | None = None, cwd: str = "", wrapped: str | None = None,
           project_dir: str = "", marker_values: dict[str, str] | None = None) -> Decision:
    """The permission decision for one Bash command. First match wins:

      1. engine unhealthy            -> deny   (decided before this function is called)
      2. a deny rule matches         -> deny
      3. an ask rule matches         -> ask
      4. known markers, restore=ask  -> ask
      5. markers and data may leave  -> ask
      6. not PLAIN, or not SIMPLE    -> ask   (not PLAIN: firm while any deny or ask rule exists)
      7. an allow rule matches       -> allow
      8. otherwise                   -> ask

    ``markers`` describes the known markers that would be restored ("1 EMAIL"); empty when there
    are none or restoring is off. ``egress`` is the egress heuristic's verdict for a command
    with markers under egress_policy=ask. ``wrapped`` is the rewritten command Claude Code will see.

    Then the permission mode is applied; it never turns a stricter outcome into a weaker one
    except where the user chose that mode for exactly this purpose (see :func:`_for_mode`).
    """
    if mode not in MODES:
        mode = "default"                           # an unknown mode is treated as the strictest interactive one
    spans = []
    for marker in (marker_values or {}):
        start = command.find(marker)
        while marker and start >= 0:
            spans.append((start, start + len(marker)))
            start = command.find(marker, start + len(marker))
    # ONE question first: is the command PLAIN (plain.py)? Only then is it known what it consists of.
    parsed = grammar.recognise(command.strip(), [(start - (len(command) - len(command.lstrip())), end -
                                                (len(command) - len(command.lstrip()))) for start, end in spans])
    if parsed is not None:
        split = Split()
        split.commands = [parsed.source(simple) for simple in parsed.commands]
        paths = check_paths(rules, parsed, cwd, project_dir, marker_values)
    else:
        # Not plain: nothing below is proof. Sub-commands and paths are looked for on a best-effort
        # basis so that a deny or ask rule that visibly applies still does; finding nothing means nothing.
        split = loose_split(command)
        paths = scan_paths(rules, command, cwd, project_dir)

    rule = first_rule(rules.deny, split, command, tool_input)
    if rule:
        return Decision("deny", f"DataFog: a Bash deny rule in your Claude Code {rule.source} matches this command "
                                "(or a part of it), so it was refused.", 2, rule)
    if paths.deny:
        return Decision("deny", f"DataFog: a {paths.deny.tool} deny rule in your Claude Code {paths.deny.source} "
                                "covers a path this command names, so it was refused.", 2)
    if wrapped is not None:
        blocked = first_rule(rules.deny, split_commands(wrapped), wrapped)
        if blocked:
            return Decision("deny", f"DataFog: a Bash deny rule in your Claude Code {blocked.source} matches the "
                                    "plugin's own wrapper command, so Claude Code refuses every Bash command while "
                                    "the plugin is on. Narrow that rule or set bash_wrap to off.", 2, blocked)

    def ask(step: int, reason: str, found: Rule | None = None, firm: bool = False) -> Decision:
        return _for_mode(Decision("ask", reason, step, found, firm), mode, rules, wrapped)

    if paths.ask:
        return ask(3, f"DataFog: a {paths.ask.tool} ask rule in your Claude Code {paths.ask.source} covers a path "
                      "this command names.", firm=True)
    rule = first_rule(rules.ask, split, command, tool_input)
    if rule:
        return ask(3, f"DataFog: a Bash ask rule in your Claude Code {rule.source} matches this command "
                      "(or a part of it).", rule)
    if wrapped is not None:
        rule = first_rule(rules.ask, split_commands(wrapped), wrapped)
        if rule:
            return ask(3, f"DataFog: a Bash ask rule in your Claude Code {rule.source} matches the plugin's own "
                          "wrapper command, so Claude Code asks for every Bash command while the plugin is on.", rule)
    if markers and restore == "ask":
        return ask(4, f"DataFog: this command contains markers ({markers}). If you approve, the real values are put "
                      "in when it runs; its output is still filtered, but a command can transform a value (encode "
                      "it, count it) in ways the filter cannot recognise."
                      + (" It also looks like it sends data to another machine." if egress else ""))
    if markers and egress:
        return ask(5, f"DataFog: this command would run with real values ({markers}) and looks like it sends data "
                      "to another machine.")
    unsupported = [rule for rule in rules.paths if rule.unsupported]
    if parsed is None:
        # Never allow, never "no decision" while a rule exists the plugin could be misreading the command
        # around: the ask is then firm (it stays an ask in bypassPermissions and auto, a deny in dontAsk).
        restrictive = bool(rules.deny or rules.ask or rules.paths or rules.block_outside_reads
                           or rm_needs_review(split, cwd))
        return ask(6, "DataFog: this is not a plain command (it has a variable, a substitution, a pattern, an "
                      "escape, a heredoc, a group, a loop, an assignment, a shell builtin or the like), so the "
                      "plugin cannot tell with certainty what it runs or which files it names. Your Bash allow "
                      "rules were not applied" + (", and because you have deny or ask rules it is not approved "
                                                  "without a prompt in any permission mode." if restrictive else "."),
                   firm=restrictive)
    # Checks Claude Code makes itself in every mode and cannot make inside the rewritten command.
    firm = ""
    if unsupported:
        firm = ("DataFog: a Read or Edit rule in your Claude Code " + unsupported[0].source + " has a pattern the "
                "plugin cannot interpret (it contains ..), so no Bash command is approved without a prompt until "
                "that rule is rewritten. /datafog:doctor lists such rules.")
    elif paths.unsure:
        firm = (f"DataFog: you have Read or Edit deny or ask rules, and this command cannot be cleared against "
                f"them: {paths.unsure}. It is not approved without a prompt.")
    elif rules.block_outside_reads:
        firm = ("DataFog: permissions.blockReadsOutsideWorkingDirectories is on and the plugin cannot check which "
                "files a command reads, so it is not approved without a prompt.")
    elif rm_needs_review(split, cwd):
        firm = ("DataFog: Claude Code checks rm and rmdir targets itself, in every permission mode, and cannot do "
                "that inside the plugin's wrapper, so this removal is not approved without a prompt.")
    if firm:
        return ask(8, firm, firm=True)
    if not is_simple(command, [(start - (len(command) - len(command.lstrip())), end -
                                (len(command) - len(command.lstrip()))) for start, end in spans]):
        return ask(6, "DataFog: this is more than one simple command (it has a pipe, a list, a redirection or more "
                      "than one line), so your Bash allow rules were not applied.")
    if not rules.allow_usable:
        return ask(8, "DataFog: a Claude Code settings file could not be read (" + ", ".join(rules.problems)
                   + "), so no Bash allow rule was applied.")
    # permission-modes: in auto mode "broad allow rules that grant arbitrary code execution are dropped";
    # "Narrow rules such as Bash(npm test) stay in effect". STRICTER: only exact rules count in auto mode.
    rule = allow_rule_for(rules, command, exact_only=(mode == "auto"))
    if rule:
        return _for_mode(Decision("allow", f"DataFog: allowed by a Bash allow rule in your Claude Code {rule.source}.",
                                  7, rule), mode, rules, wrapped)
    return ask(8, "DataFog: no Bash allow rule in the Claude Code settings files the plugin can read matches "
                  "this command.")


def loose_split(command: str) -> Split:
    """Sub-commands of a command that is not plain, for deny and ask rules only: the tolerant scan AND a
    crude cut at every operator with quotes ignored. Uncertain by definition."""
    text = command[:grammar.MAX_LENGTH].replace("\x00", "")
    split = split_commands(text)
    split.certain = False
    for source in (text, text.replace("\\\n", "")):
        for piece in re.split(r"[;&|\n(){}`]+|\$\(", source)[:MAX_LOOSE_TOKENS]:
            piece = piece.strip()
            if piece and piece not in split.commands:
                split.commands.append(piece)
    return split


def _wrapper_is_allowed(rules: RuleSet, wrapped: str | None) -> bool:
    """True when the user's allow rules would approve the rewritten command on their own."""
    if not wrapped or not rules.allow_usable:
        return False
    parts = split_commands(wrapped).commands
    usable = [rule for rule in rules.allow if rule.spec is not None]      # bare `Bash` is dropped in auto mode
    return bool(parts) and all(any(rule.matches(text) for rule in usable for text in candidates(part))
                               for part in parts)


def _for_mode(decision: Decision, mode: str, rules: RuleSet, wrapped: str | None) -> Decision:
    """Apply the permission mode (permission-modes page). Deny decisions never reach this function.

    default, acceptEdits   as decided. (acceptEdits approves some file commands inside the working
                           directory on its own; the plugin cannot check paths, so those ask.)
    plan                   never allow: "your PreToolUse hook's allow has no effect on a ... call that
                           isn't read-only"; whether the rewritten command counts as read-only is not
                           the plugin's to decide. allow -> ask.
    auto                   ask rules and marker commands still ask ("A hook's ask also forces a
                           permission prompt in auto mode"). An allow from an exact rule stays. Everything
                           else is left to Claude Code (no decision), so the classifier reviews the
                           rewritten command - unless the user's allow rules would approve the wrapper
                           itself, in which case the plugin asks.
    dontAsk                "auto-denies every tool call that would otherwise prompt": ask -> deny.
    bypassPermissions      the user opted out of prompts: steps 6 and 8 -> allow. Deny rules still deny,
                           ask rules still ask ("Explicit ask rules ... still prompt"), and so do marker
                           commands (steps 4 and 5) and the "firm" asks: removals Claude Code would have
                           checked, commands the plugin cannot parse, blockReadsOutsideWorkingDirectories.
    """
    if mode in ("default", "acceptEdits"):
        return decision
    if mode == "plan":
        if decision.outcome == "allow":
            return Decision("ask", "DataFog: plan mode. " + decision.reason.replace("DataFog: ", "")
                            + " The plugin does not approve commands while planning.", decision.step, decision.rule)
        return decision
    if mode == "dontAsk":
        if decision.outcome == "ask":
            return Decision("deny", decision.reason + " Permission mode dontAsk: a command that would need a "
                            "prompt is denied.", decision.step, decision.rule)
        return decision
    if mode == "auto":
        if decision.outcome == "ask" and decision.step in (6, 8) and not decision.firm \
                and not _wrapper_is_allowed(rules, wrapped):
            return Decision(None, "", decision.step)
        return decision
    # bypassPermissions
    if decision.outcome == "ask" and decision.step in (6, 8) and not decision.firm:
        return Decision("allow", "DataFog: permission mode bypassPermissions.", decision.step)
    return decision
