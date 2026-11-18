"""Putting real values back into a Bash command as inert data ("late swap").

This runs inside the plugin's runner, after the vault is open and immediately before the
command is handed to the shell. The PreToolUse hook runs the same code as a dry run, to
refuse a command early, and throws the result away.

THREAT NOTE
-----------
Who chooses what:

* The MODEL chooses the whole command text and therefore the quoting around every marker.
  The model may have been manipulated by text it read (prompt injection), so the command
  must be treated as written by an adversary who wants a value to end up somewhere it is
  parsed as code.
* The VALUE OWNER chooses nothing. A value is whatever was found in a file or in output:
  an e-mail address, a key, a credential URI. It can contain quotes, ``$( )``, backticks,
  ``;``, ``|``, ``&``, parentheses, backslashes, blanks, glob characters, a leading ``-``,
  newlines and non-ASCII text. Whoever planted the value (a web page, a ticket, a log
  line) may have shaped it as an attack: ``a[$(cmd)]`` runs cmd wherever a shell expects a
  variable name or a number.

Goal: a value can never execute.

HISTORY, AND WHY THIS FILE IS SMALL
-----------------------------------
The first version modelled a good part of bash and zsh (substitutions, heredocs, loops,
assignments) and refused what it knew to be dangerous. Two reviews each found a way to run a
value through something it did not know to be dangerous: ``RANDOM=[[M]]`` (assigning to a
special variable evaluates arithmetic), ``x=[[M]]; printf -v "$x" y``, ``${!x}``, ``${y:x}``,
``wait -p "$x"``, zsh ``export "$x"``. The pattern is that a value placed safely into a
VARIABLE is then used by the rest of the command in a place that evaluates it.

So the rule is now the other way round. A command that contains a marker is restored only
if the WHOLE command fits a small positive grammar (plain.py) in which a value cannot
reach anything but the argument list of an external program:

1. The command is PLAIN (see plain.py): simple commands joined by ``|``, ``&&``, ``||``, ``;``
   or newlines, with redirections to and from literal paths. No ``$`` of any kind, so no
   variable can carry a value anywhere; no backticks, backslashes, globs, braces, heredocs,
   here-strings, subshells, groups, loops, conditionals, functions, assignments, background.
2. Every command name, in EVERY simple command of the command, is a literal unquoted word on a
   short allow-list of programs that were read option by option and treat their arguments as
   data (RESTORE_PROGRAMS below, with the audit), plus what the user vouched for in the
   restore_programs_extra setting. A deny-list of "programs that run their arguments" was tried
   first and lost: ``perl5.36 -e``, ``git -c alias.x=!cmd``, ``tar --checkpoint-action=exec=``.
   ``printf`` is accepted only with a literal format made of text, ``%s`` and ``%%``.
3. A marker stands only in an argument: as a whole unquoted word, or inside a single- or
   double-quoted part of an argument. Never in a command name or a redirection target, and
   never as a piece of an unquoted word.
4. A value that would START an argument with ``-`` is refused unless a literal ``--`` word
   stands earlier in the same command: after ``--`` programs take what follows as operands,
   so the value cannot be read as an option.
5. A value with a NUL byte is refused.

Encoding, for the three places a marker can stand:

    unquoted word    'value'                      every ' written as '\\''
    in '...'         the value in place           every ' written as '\\''
    in "..."         close the quote, 'value', open it again

Anything else raises :class:`Refused` and the command is NOT run (fail closed).

What this cannot do (see the README): the lists of wrapping and code-reading programs are
finite; an external program may itself treat an argument as code (a query, a pattern, a
template); shell start-up files that redefine programs as aliases or functions
(``~/.zshenv``, ``BASH_ENV``) are not modelled; and while a command runs, the programs it
starts have the value in their argument list (visible in ``ps``).
"""
from __future__ import annotations

import os
import re

from . import plain


class Refused(Exception):
    """The command cannot take values safely. ``code`` and ``text`` never contain command or value text."""

    def __init__(self, code: str, text: str):
        super().__init__(code)
        self.code = code
        self.text = text


class Span:
    """A known marker in the command: ``[start, end)`` in characters, its type and its real value."""
    __slots__ = ("start", "end", "entity", "value")

    def __init__(self, start: int, end: int, entity: str, value: str):
        self.start, self.end, self.entity, self.value = start, end, entity, value


class Result:
    def __init__(self, text: str, restored: int, left_literal: int = 0):
        self.text = text                  # the command with values in place
        self.restored = restored          # markers replaced
        self.left_literal = left_literal  # always 0 now; kept for callers


def shell_kind(path: str) -> str:
    name = os.path.basename(path or "")
    return name if name in ("bash", "zsh") else "sh"


# ---------------------------------------------------------------------------------------------
# THE ALLOW-LIST. A marker is restored only when EVERY simple command of the whole command runs a
# program named here (or in the user's restore_programs_extra setting). Third review: "any external
# program except the ones on a list" still ran values as code (perl5.36 -e, git -c alias.x=!cmd,
# tar --checkpoint-action=exec=, rsync -e, man -P, fzf --preview ...). The set of programs that
# can run an argument is open-ended; the set below was read option by option.
#
# Audit (GNU coreutils 9 / grep 3 / diffutils 3 / ripgrep 14 / util-linux, and the BSD/macOS
# variants). "exec" = can the program be made to run another program or evaluate text, through an
# option or an operand? Environment variables are not a value path: the grammar has no assignments.
#
#   program            exec-capable or value-shaped risk                         decision
#   grep egrep fgrep   none (GNU and BSD). -f FILE reads patterns from a file.   args may hold markers
#   rg                 --pre CMD, --pre-glob, --hostname-bin run a program.      refused: those options
#                      -z runs fixed decompressors by name; not value-driven.
#   cat head tail      none. tail -f/--pid only wait.                            args may hold markers
#   wc nl tac rev      none (wc --files0-from reads a list of names).            args may hold markers
#   fold cut tr paste  none.                                                     args may hold markers
#   join comm cmp      none.                                                     args may hold markers
#   column             none.                                                     args may hold markers
#   diff               none in diff itself (sdiff and diff3 are not listed).     args may hold markers
#   ls stat            none. stat -c/--printf/-f take a format: output only.     args may hold markers
#   basename dirname   pure text.                                                args may hold markers
#   file               -m/--magic-file loads a magic database, -C compiles one.  refused: -m -C (and long)
#   sort               --compress-program runs a program; -o/--output and        refused: those options
#                      -T/--temporary-directory write where an argument says.
#   printf             builtin. -v NAME evaluates NAME; %d %i %o %u %x %X %c     only `printf [--] FORMAT
#                      and * evaluate the argument as arithmetic in zsh; %b       args`, FORMAT literal with
#                      and %q reinterpret it.                                    %s and %% only
#   true  :            ignore their arguments.                                   args may hold markers
#   uniq               the second operand is an OUTPUT file.                     listed, no marker in its args
#   tee cp mv mkdir    write to or create what an argument names: a value        listed, no marker in their
#   touch              would choose the path that is written.                    args (may stand in a pipeline)
#
# Left out on purpose: echo (zsh and dash interpret backslashes in its arguments, so a value is not
# delivered byte for byte; use printf '%s\n'), jq (the filter is a program), find (-exec, -delete,
# -fprintf ...), sed, awk, xargs, every shell and interpreter, env, sudo, git, tar, make, every pager,
# and every network tool (curl, wget, ssh, scp, rsync, nc): a real value must not leave the machine
# through a silent path. To use a value with any other program, write it to a file with the Write
# tool (which restores locally) and let the program read the file.
# ---------------------------------------------------------------------------------------------
MARKER_ARGUMENTS = frozenset("""
    grep egrep fgrep rg cat head tail wc nl tac rev fold cut tr paste join comm cmp column diff ls stat
    basename dirname file sort printf true :
""".split())
NO_MARKER_ARGUMENTS = frozenset({"uniq", "tee", "cp", "mv", "mkdir", "touch"})
RESTORE_PROGRAMS = MARKER_ARGUMENTS | NO_MARKER_ARGUMENTS
# Options that are refused, anywhere in a command that holds a marker: (long names, short letters).
# A long option is refused by any unambiguous-looking abbreviation too (GNU accepts prefixes).
FORBIDDEN_OPTIONS = {
    "rg": (("pre", "pre-glob", "hostname-bin"), ""),
    "sort": (("compress-program", "output", "temporary-directory", "files0-from", "random-source"), "oT"),
    "file": (("magic-file", "compile", "files-from"), "mCf"),
}
# An absolute path is accepted only into these directories; a relative path (./grep, bin/grep) never.
SYSTEM_DIRECTORIES = frozenset({"/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"})
BUILTIN_NAMES = frozenset({"printf", "true", ":"})          # shell builtins on the list: bare name only
_PRINTF_FORMAT = re.compile(r"(?:[^%\\]|%%|%s|\\[nt\\]|\\0(?![0-7]))*")

# Defence in depth only (the allow-list decides): these may not be vouched for in
# restore_programs_extra either, because no argument discipline makes them inert.
_SHELLS = frozenset("sh bash zsh dash ksh mksh ksh93 ash fish csh tcsh busybox pwsh powershell rbash".split())
NEVER = _SHELLS | frozenset({"eval", "exec", "xargs", "parallel", "env", "sudo", "doas", "su", "ssh", "command",
                             "builtin", "source", ".", "time", "nohup", "nice", "timeout"})
ANYWHERE = _SHELLS | frozenset({"eval", "exec", "xargs", "parallel", "-exec", "-execdir", "-ok", "-okdir"})

_WHY = {
    "grammar": "a command that contains markers must be made of plain commands only: programs with literal, "
               "optionally quoted arguments, joined by | && || ; or newlines, with redirections to literal "
               "paths; no $ of any kind, no backticks, backslashes, globs, braces, heredocs, subshells, loops, "
               "conditionals, assignments or background jobs",
    "command": "every program in a command that contains markers must be on the plugin's short list of programs "
               "that treat their arguments as data (grep, rg, cat, head, tail, wc, sort, cut, tr, diff, ls, stat, "
               "printf and a few more; see the README), called by bare name. To use a value with any other "
               "program, write it to a file with the Write tool and let the program read the file",
    "options": "an option that makes the program run another program or write where an argument says is used "
               "in a command that contains markers",
    "bystander": "a marker is an argument of a program that writes to or creates what its arguments name "
                 "(uniq, tee, cp, mv, mkdir, touch)",
    "placement": "a marker may stand only as a whole unquoted argument or inside a quoted argument; not in a "
                 "command name, a redirection target or as part of an unquoted word",
    "printf": "printf takes markers only as printf 'FORMAT' ARGUMENTS with a literal format that uses %s and %% "
              "only (other conversions evaluate their argument in zsh)",
    "option": "a value starts with '-' and could be read as an option; put a literal -- before it in the command",
    "value": "a value contains a NUL byte",
}


def _refuse(code: str) -> Refused:
    return Refused(code, _WHY[code])


def _single(value: str) -> str:
    return value.replace("'", "'\\''")


def program_of(name: str, extra: frozenset = frozenset()) -> str | None:
    """The listed program a command name stands for, or None. Exact names only: `grep`, or
    `/usr/bin/grep` in a system directory. No version suffixes, no relative paths."""
    directory, base = os.path.split(name)
    if directory:
        if directory not in SYSTEM_DIRECTORIES or base in BUILTIN_NAMES:
            return None
    return base if base in RESTORE_PROGRAMS or base in extra else None


def _check_names(parsed: plain.Plain, extra: frozenset = frozenset()) -> None:
    """Every simple command of the whole command, with or without a marker of its own."""
    for simple in parsed.commands:
        first = simple.words[0]
        if not first.bare or first.markers or first.tilde:
            raise _refuse("command")
        program = program_of(first.text, extra)
        if program is None:
            raise _refuse("command")
        for word in simple.words:
            if os.path.basename(word.text) in ANYWHERE or word.text in ANYWHERE:
                raise _refuse("command")
        if any(target.markers for _, target in simple.targets):
            raise _refuse("placement")
        if program in NO_MARKER_ARGUMENTS and any(word.markers for word in simple.words):
            raise _refuse("bystander")
        long_names, letters = FORBIDDEN_OPTIONS.get(program, ((), ""))
        for word in simple.words[1:]:
            text = word.text
            if text.startswith("--") and len(text) > 2:
                given = text[2:].split("=", 1)[0]
                if any(name.startswith(given) or given.startswith(name) for name in long_names):
                    raise _refuse("options")
            elif text.startswith("-") and len(text) > 1 and any(letter in text for letter in letters):
                raise _refuse("options")


def substitute(command: str, spans: list[Span], shell: str = "bash", extra=frozenset()) -> Result:
    """The command with every known marker replaced by its value as inert data.

    Raises :class:`Refused` unless the whole command fits the grammar in the module docstring.
    ``shell`` is accepted for callers; the grammar is the same for bash, zsh and sh.
    ``extra`` are the program names the user vouched for (restore_programs_extra).
    """
    spans = sorted(spans, key=lambda span: span.start)
    if not spans:
        return Result(command, 0)
    if any("\x00" in span.value for span in spans):
        raise _refuse("value")
    parsed = plain.parse(command, [(span.start, span.end) for span in spans])
    if parsed is None:
        raise _refuse("grammar")
    _check_names(parsed, frozenset(extra))
    by_start = {span.start: span for span in spans}
    edits: list[tuple[int, int, str]] = []
    for simple in parsed.commands:
        words = simple.words
        if os.path.basename(words[0].text) == "printf":
            # `printf -v NAME` assigns, and bash evaluates NAME. zsh evaluates the argument of every numeric
            # conversion (%d %i %o %u %x %X %c, and * for a width) as arithmetic, where `a[$(cmd)]` runs cmd;
            # %b and %q reinterpret the argument. So: `printf [--] FORMAT args...`, FORMAT a literal made of
            # ordinary text, \n, \t, \\, %% and %s. Options end at the format.
            index = 2 if len(words) > 2 and words[1].text == "--" and words[1].bare else 1
            if len(words) <= index or words[index].markers or words[index].text.startswith("-"):
                raise _refuse("printf")
            if any(word.markers for word in words[1:index]) or not _PRINTF_FORMAT.fullmatch(words[index].text):
                raise _refuse("printf")
        dashes = False                         # a literal `--` word was seen in this command
        for word in words[1:]:
            for start, end, kind, offset in word.markers:
                span = by_start[start]
                if kind == "bare" and (len(word.parts) != 1 or word.start != start or word.end != end):
                    raise _refuse("placement")       # a marker glued to other unquoted text
                if span.value.startswith("-") and offset == 0 and not dashes:
                    raise _refuse("option")
                if kind == "bare":
                    text = "'" + _single(span.value) + "'"
                elif kind == "single":
                    text = _single(span.value)
                else:
                    text = "\"'" + _single(span.value) + "'\""
                edits.append((start, end, text))
            if word.text == "--" and word.bare and not word.markers:
                dashes = True
    if len(edits) != len(spans):
        raise _refuse("placement")
    out, position = [], 0
    for start, end, text in sorted(edits):
        out.append(command[position:start])
        out.append(text)
        position = end
    out.append(command[position:])
    return Result("".join(out), len(edits))
