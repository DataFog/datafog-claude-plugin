"""One strict recogniser for "plain" shell commands, shared by everything that reasons about a
Bash command: restoring markers (shellsub.py) and applying permission rules (ccperms.py).

Posture. Two reviews showed that listing dangerous shell constructs loses: each fix was
bypassed by a neighbouring construct. So nothing here tries to understand the shell. It
accepts a small grammar it can read with certainty and calls everything else NOT PLAIN.
Callers never approve, restore or split a command that is not plain.

PLAIN (the whole command must fit; this is the definition quoted in the README):

    command   := simple ( separator simple )*  [ ";" ]        blank lines are allowed
    separator := "|"  |  "&&"  |  "||"  |  ";"  |  newline
    simple    := name ( word | redirection )*
    redirection := [digits] ( ">" | ">>" | "<" ) word          to or from a literal path
                 | "&>" word | "&>>" word
                 | [digits] ( ">&" | "<&" ) ( digits | "-" )    descriptor duplication
    word      := one or more of
                   bare text      letters, digits and  _ @ % + = : , . / -
                   '...'          anything but a single quote (the shell reads nothing inside)
                   "..."          anything but  "  $  `  and backslash
                 optionally starting with  ~  or  ~/  (the user's own home directory);
                 not starting with an unquoted "="
    name      := a word that is not an assignment (no "=") and does not start with "-"

Not plain, therefore: outside single quotes, any ``$`` (variables, ``$( )``, ``${ }``, ``$(( ))``,
``$'..'``), any backtick and any backslash (escapes and line continuations); unquoted
``* ? [ ] { } ~user ! # ^ ( )``, ``&`` (background), ``|&``, here-documents, here-strings, ``<>``, ``>|``, process substitution,
subshells, groups, assignments, comments, a NUL byte, a carriage return, and anything longer
than MAX_LENGTH. Shell keywords and most builtins are not accepted as a command name
(:func:`name_problem`): control flow, ``eval``, ``source``, ``export``, ``set``, ``alias`` ... A
directory-changing command (``cd``, ``pushd``, ``popd``) is plain only as the single command
of a call, because after it relative paths mean something else.

Known markers (``[[EMAIL_7KQ4ZM]]``) are passed in by position and count as literal text; any
other ``[`` outside quotes is a glob and makes the command not plain.
"""
from __future__ import annotations

import os

MAX_LENGTH = 20_000
MAX_WORDS = 2_000
_BARE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-")
_DIGITS = frozenset("0123456789")

# Every reserved word and builtin of bash 5, zsh 5.9 and dash. tests/test_plain.py fails when an
# installed shell knows one that is missing here.
KEYWORDS = frozenset("""
    if then elif else fi case esac for select while until do done in function time coproc { } ! [[ ]]
    repeat foreach end nocorrect noglob always
""".split())
BUILTINS = frozenset("""
    . : [ alias autoload bg bind bindkey break builtin bye caller cd chdir command compadd comparguments
    compcall compctl compdescribe compfiles compgen compgroups complete compopt compquote compset comptags
    comptry compvalues continue declare dirs disable disown echo echotc echoti emulate enable eval exec exit
    export false fc fg float functions getln getopts hash help history integer jobs kill let limit local log
    logout mapfile popd print printf private pushd pushln pwd r read readarray readonly rehash return sched
    set setopt shift shopt source suspend test times trap true ttyctl type typeset ulimit umask unalias
    unfunction unhash unlimit unset unsetopt vared wait whence where which zcompile zformat zle zmodload
    zparseopts zregexparse zstyle -
""".split())
SHELL_WORDS = KEYWORDS | BUILTINS
# Builtins a plain command may use. None of them evaluates an argument, changes how later text is
# read, or changes the directory (cd and friends are handled separately, see name_problem).
PLAIN_BUILTINS = frozenset({"echo", "printf", "true", "false", ":", "pwd", "test", "kill", "wait", "type",
                            "which", "exit"})
MOVES = frozenset({"cd", "chdir", "pushd", "popd"})


class Word:
    """One word. ``text`` is what the program receives (quotes removed). ``parts`` are
    ``(kind, start, end)`` with kind "bare", "single" or "double" and the span of the content in
    the command text. ``markers`` are ``(start, end, kind, offset of the marker in text)``."""
    __slots__ = ("start", "end", "text", "parts", "markers", "tilde")

    def __init__(self, start: int):
        self.start, self.end = start, start
        self.text = ""
        self.parts: list[tuple[str, int, int]] = []
        self.markers: list[tuple[int, int, str, int]] = []
        self.tilde = False

    @property
    def bare(self) -> bool:
        return all(kind == "bare" for kind, _, _ in self.parts)


class Simple:
    __slots__ = ("start", "end", "words", "targets")

    def __init__(self, start: int):
        self.start, self.end = start, start
        self.words: list[Word] = []
        self.targets: list[tuple[str, Word]] = []      # (operator, target word) of file redirections

    @property
    def name(self) -> str:
        return self.words[0].text


class Plain:
    def __init__(self, text: str, commands: list[Simple], separators: list[str]):
        self.text, self.commands, self.separators = text, commands, separators

    def source(self, simple: Simple) -> str:
        return self.text[simple.start:simple.end]


def parse(text: str, markers: tuple[tuple[int, int], ...] | list[tuple[int, int]] = ()) -> Plain | None:
    """The command as a :class:`Plain`, or None when it is not plain. Never raises; linear time."""
    try:
        return _parse(text, markers)
    except (IndexError, ValueError, RecursionError):
        return None


def _parse(text: str, markers) -> Plain | None:
    n = len(text)
    if n == 0 or n > MAX_LENGTH or "\x00" in text or "\r" in text:
        return None
    marker_at = {}
    for start, end in markers:
        if not 0 <= start < end <= n:
            return None
        marker_at[start] = end
    commands: list[Simple] = []
    separators: list[str] = []
    current: Simple | None = None
    need_command = False            # after | && || a command must follow
    words = 0
    i = 0

    def word(position: int) -> tuple[Word, int] | None:
        item = Word(position)
        chunks: list[str] = []
        length = 0
        j = position
        if text[j] == "=":
            return None                           # zsh replaces =name by the path of a command
        if text[j] == "~":
            if j + 1 < n and text[j + 1] not in "/ \t\n;|&<>":
                return None                       # ~user, ~+, ~-: not the plain home directory
            item.tilde = True
            chunks.append("~")
            length = 1
            item.parts.append(("bare", j, j + 1))
            j += 1
        while j < n:
            char = text[j]
            if j in marker_at:
                end = marker_at[j]
                item.markers.append((j, end, "bare", length))
                item.parts.append(("bare", j, end))
                chunks.append(text[j:end])
                length += end - j
                j = end
            elif char in _BARE:
                begin = j
                while j < n and text[j] in _BARE and j not in marker_at:
                    j += 1
                item.parts.append(("bare", begin, j))
                chunks.append(text[begin:j])
                length += j - begin
            elif char == "'" or char == '"':
                kind = "single" if char == "'" else "double"
                close = text.find(char, j + 1)
                if close < 0:
                    return None
                if kind == "double" and any(bad in text[j + 1:close] for bad in ("$", "`", "\\")):
                    return None
                position_in = j + 1
                while True:
                    inside = min((start for start in marker_at if position_in <= start < close), default=-1)
                    if inside < 0:
                        break
                    if marker_at[inside] > close:
                        return None
                    item.markers.append((inside, marker_at[inside], kind, length + inside - (j + 1)))
                    position_in = marker_at[inside]
                item.parts.append((kind, j + 1, close))
                chunks.append(text[j + 1:close])
                length += close - (j + 1)
                j = close + 1
            elif char in " \t\n;|&<>":
                break
            else:
                return None
        if j == position:
            return None
        item.end = j
        item.text = "".join(chunks)
        return item, j

    while i < n:
        char = text[i]
        if char in " \t":
            i += 1
            continue
        if char == "\n" or char == ";":
            if current is None:
                if char == ";" or need_command:
                    return None                   # ";" with no command before it, or "a &&" + newline
                i += 1
                continue
            commands.append(current)
            separators.append(char)
            current = None
            i += 1
            continue
        if char == "|" or (char == "&" and text[i:i + 2] == "&&"):
            operator = text[i:i + 2] if text[i:i + 2] in ("||", "&&") else "|"
            if current is None or text[i:i + 2] == "|&":
                return None
            commands.append(current)
            separators.append(operator)
            current = None
            need_command = True
            i += len(operator)
            continue
        # a redirection, with an optional descriptor number in front
        j = i
        while j < n and text[j] in _DIGITS:
            j += 1
        if j < n and (text[j] in "<>" or (j == i and text[j:j + 2] == "&>")):
            if current is None:
                return None                       # a redirection before the command name
            operator = next((op for op in ("&>>", "&>", ">>", ">&", "<&", ">", "<") if text.startswith(op, j)), "")
            after = j + len(operator)
            if not operator or (after < n and text[after] in "<>|(&") or text[after:after + 1] == "":
                return None                       # << <<< <> >| <( >( and an operator at the end
            if operator in (">&", "<&"):
                k = after
                while k < n and text[k] in _DIGITS:
                    k += 1
                if k == after and text[after:after + 1] == "-":
                    k = after + 1
                if k == after or (k < n and text[k] not in " \t\n;|&<>"):
                    return None
                i = k
                continue
            while after < n and text[after] in " \t":
                after += 1
            found = word(after) if after < n else None
            if found is None:
                return None
            current.targets.append((operator, found[0]))
            current.end = i = found[1]
            continue
        if char == "&":
            return None                           # background
        found = word(i)
        if found is None:
            return None
        words += 1
        if words > MAX_WORDS:
            return None
        if current is None:
            current = Simple(found[0].start)
            need_command = False
        current.words.append(found[0])
        current.end = i = found[1]
    if current is not None:
        commands.append(current)
    elif need_command or not commands:
        return None
    for simple in commands:
        if not simple.words:
            return None
    return Plain(text, commands, separators)


def name_problem(plain: Plain) -> str:
    """Why the command names of a parsed command keep it from being plain; "" when they do not."""
    for simple in plain.commands:
        first = simple.words[0]
        name = first.text
        base = os.path.basename(name)
        if not name or "=" in name or name.startswith("-") or first.markers or not base:
            return "name"
        if base in MOVES:
            if len(plain.commands) > 1 or simple.targets:
                return "moves"
            continue
        if base in SHELL_WORDS and base not in PLAIN_BUILTINS:
            return "builtin"
    return ""


def recognise(text: str, markers=()) -> Plain | None:
    """The one question callers ask: is this command plain? Returns its parse, or None."""
    plain = parse(text, markers)
    if plain is None or name_problem(plain):
        return None
    return plain
