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
2. Every command name is a literal, unquoted word that is an external program. No shell
   keyword or builtin is accepted except ``echo``, ``true``, ``:`` (they evaluate nothing) and
   ``printf`` in the form ``printf LITERAL-FORMAT args...`` (``printf -v NAME`` evaluates NAME).
   Programs that run their arguments as a command or read them as a program are refused:
   ``env``, ``sudo``, ``xargs``, shells, ``eval``, ``awk``, ``sed``, interpreters, ``ssh``, ``make``,
   ``docker``, ``find`` with ``-exec`` ... (REPARSE_PROGRAMS, WRAPPING_PROGRAMS, ANYWHERE).
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


# The only shell builtins a command with markers may use.
ALLOWED_BUILTINS = frozenset({"echo", "printf", "true", ":"})
# Programs that parse their input or arguments as shell or as a program.
_SHELLS = frozenset("sh bash zsh dash ksh mksh ksh93 ash fish csh tcsh busybox pwsh powershell rbash".split())
REPARSE_PROGRAMS = _SHELLS | frozenset("""
    xargs parallel ssh su at batch crontab script watch tmux screen expect
    perl ruby node nodejs deno bun php lua luajit Rscript R osascript tclsh wish irb pry ipython julia groovy
    scala jshell erl elixir guile racket clisp sbcl ghci
""".split())
_PYTHON = re.compile(r"^(?:python|pypy)[0-9.]*$")
# Any word equal to one of these, wherever it stands (`docker exec c sh -c ...`, `find -exec ...`).
ANYWHERE = _SHELLS | frozenset({"eval", "exec", "xargs", "parallel", "-exec", "-execdir", "-ok", "-okdir"})
# Programs that run their arguments as a command, or read an argument as a program in their own
# language. This list is a heuristic and is finite.
WRAPPING_PROGRAMS = frozenset("""
    env sudo doas nohup nice timeout stdbuf setsid ionice chrt taskset flock strace ltrace gdb lldb valgrind
    unbuffer caffeinate chronic chroot nsenter unshare systemd-run runuser pkexec fakeroot proot firejail
    bwrap docker podman nerdctl kubectl oc lxc vagrant ansible ansible-playbook mosh rsh direnv devbox mise
    npx pnpm yarn npm bunx uv uvx pipx poetry pdm hatch tox nox make gmake just task cargo go gradle mvn
    bazel awk gawk mawk nawk sed gsed ed ex vi vim nvim emacs sqlite3 psql mysql mariadb mongosh mongo
    redis-cli sqlcmd duckdb clickhouse-client bc dc m4 gnuplot octave time command builtin
""".split())

_WHY = {
    "grammar": "a command that contains markers must be made of plain commands only: programs with literal, "
               "optionally quoted arguments, joined by | && || ; or newlines, with redirections to literal "
               "paths; no $ of any kind, no backticks, backslashes, globs, braces, heredocs, subshells, loops, "
               "conditionals, assignments or background jobs",
    "command": "a command that contains markers may only run external programs (plus echo, true, : and printf "
               "with a literal format), and not ones that run their arguments as a command or read them as a "
               "program (for example env, sudo, xargs, a shell, eval, awk, sed, an interpreter, ssh, make, docker)",
    "placement": "a marker may stand only as a whole unquoted argument or inside a quoted argument; not in a "
                 "command name, a redirection target or as part of an unquoted word",
    "printf": "printf takes markers only after a literal format: printf 'FORMAT' ARGUMENTS",
    "option": "a value starts with '-' and could be read as an option; put a literal -- before it in the command",
    "value": "a value contains a NUL byte",
}


def _refuse(code: str) -> Refused:
    return Refused(code, _WHY[code])


def _single(value: str) -> str:
    return value.replace("'", "'\\''")


def _check_names(parsed: plain.Plain) -> None:
    for simple in parsed.commands:
        first = simple.words[0]
        name = first.text
        base = os.path.basename(name)
        if not first.bare or first.markers or first.tilde or not base or "=" in name or name.startswith("-"):
            raise _refuse("command")
        if base in plain.SHELL_WORDS and base not in ALLOWED_BUILTINS:
            raise _refuse("command")
        if base in REPARSE_PROGRAMS or base in WRAPPING_PROGRAMS or _PYTHON.match(base):
            raise _refuse("command")
        for word in simple.words:
            if os.path.basename(word.text) in ANYWHERE or word.text in ANYWHERE:
                raise _refuse("command")
        if any(target.markers for _, target in simple.targets):
            raise _refuse("placement")


def substitute(command: str, spans: list[Span], shell: str = "bash") -> Result:
    """The command with every known marker replaced by its value as inert data.

    Raises :class:`Refused` unless the whole command fits the grammar in the module docstring.
    ``shell`` is accepted for callers; the grammar is the same for bash, zsh and sh.
    """
    spans = sorted(spans, key=lambda span: span.start)
    if not spans:
        return Result(command, 0)
    if any("\x00" in span.value for span in spans):
        raise _refuse("value")
    parsed = plain.parse(command, [(span.start, span.end) for span in spans])
    if parsed is None:
        raise _refuse("grammar")
    _check_names(parsed)
    by_start = {span.start: span for span in spans}
    edits: list[tuple[int, int, str]] = []
    for simple in parsed.commands:
        words = simple.words
        if words[0].text == "printf":
            # `printf -v NAME` assigns, and bash evaluates NAME. Only `printf [--] LITERAL-FORMAT args...`:
            # options end at the format.
            index = 2 if len(words) > 2 and words[1].text == "--" and words[1].bare else 1
            if len(words) <= index or words[index].markers or words[index].text.startswith("-"):
                raise _refuse("printf")
            if any(word.markers for word in words[1:index]):
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
