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
  line) may have shaped it as an attack.

Goal: a value can never execute. Concretely, the text inserted for a marker is, in the
parse the shell performs on the command, exactly one piece of literal data, and the
program that receives it sees exactly the value's bytes.

How:

1. A conservative lexer walks the command and knows, at every marker, which quoting context
   the shell is in. It models a deliberately small part of bash and zsh. Everything it
   does not model raises :class:`Refused`; the command is then NOT run (fail closed). It
   never guesses.
2. Per context the value is written in the one encoding that context cannot interpret:

   ==================  =====================================================================
   unquoted            ``'value'`` with every ``'`` written as ``'\\''``; text next to it
                       joins the same word
   single-quoted       the value in place, every ``'`` written as ``'\\''``
   double-quoted       the double quote is closed, ``'value'`` is written as above, and the
                       double quote is opened again. This is used instead of backslash
                       escapes so that nothing inside the value is ever read by the
                       double-quote rules (``$``, backtick, ``\\``, and ``!`` if history
                       expansion were on).
   ``$'...'``          the value in place, ``\\`` written as ``\\\\`` and ``'`` as ``\\'``
   heredoc, quoted     the value in place; values with a newline are refused, and so is a
   delimiter           line that would equal the delimiter
   heredoc, unquoted   the value in place with ``\\``, ``$`` and backtick escaped; same two
   delimiter           refusals
   ``$( )``            the lexer recurses; contexts inside are the ones above
   backticks           the lexer recurses, and the inserted text gets the extra backtick
                       layer (``\\`` doubled, backtick escaped)
   comment             the marker is left as it is (nothing runs there)
   ==================  =====================================================================

3. A marker is refused where putting data there would change what runs: as (part of) a
   command name, a redirection target, a heredoc delimiter, directly after an unquoted
   ``$`` or backslash, inside ``${ }``, arithmetic, ``[[ ]]``, ``case``, arrays, function
   definitions, or in the arguments of a program that itself runs its arguments
   (``env``, ``sudo``, ``timeout`` ...) or parses them as code (``awk``, ``sed``,
   ``sqlite3`` ...).
4. A value that was inserted safely can still be executed LATER by the command itself:
   ``x=[[M]]; eval "$x"``, ``echo [[M]] | sh``, ``let y=x``. No lexer can follow data
   through a script, so any command that contains such a second parse anywhere (``eval``,
   a shell, ``xargs``, ``ssh``, an interpreter, arithmetic, most shell builtins) is
   refused as a whole when it contains markers.

What this cannot do (see the README): a value that starts with ``-`` is delivered exactly
and the receiving program may read it as an option; the lists of wrapping and
code-parsing programs are finite; shell start-up files that change the shell's grammar
(aliases in ``~/.zshenv``, ``BASH_ENV``) are not modelled; and while a command runs, the
programs it starts have the value in their argument list (visible in ``ps``).
"""
from __future__ import annotations

import os
import re

MAX_DEPTH = 40


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
    def __init__(self, text: str, restored: int, left_literal: int):
        self.text = text                  # the command with values in place
        self.restored = restored          # markers replaced
        self.left_literal = left_literal  # markers left as they are (inside comments)


def shell_kind(path: str) -> str:
    name = os.path.basename(path or "")
    return name if name in ("bash", "zsh") else "sh"


# -- what a command word means ---------------------------------------------------------------
# Reserved words after which the next word is again a command. None of them takes options.
TRANSPARENT = frozenset({"if", "then", "elif", "else", "while", "until", "do", "!", "{"})
# Builtins whose arguments are plain data, whatever the data is. Audit of each (a value may start with
# "-" and so be read as an option, and may be shaped like `a[$(cmd)]`, which bash evaluates wherever a
# variable NAME is expected):
#   : true false   ignore their arguments.
#   echo           options are -n -e -E only: they change the output, nothing is evaluated.
#   for            `for i in WORDS`: words are data. A marker as the loop variable is a syntax error.
#   printf         has -v NAME, and NAME is evaluated. Accepted only in the form checked in end():
#                  a literal format as first argument, markers after it.
# Not here on purpose: cd, chdir, pushd (a value would choose the directory later commands run in),
# test and [ (-v NAME, arithmetic operands), and everything that takes a variable name (read, unset,
# wait -p, getopts, mapfile, export -f ...), which is refused in PASSIVE or UNSAFE_BUILTINS.
ARG_SAFE = frozenset({":", "true", "false", "echo", "printf", "for"})
# `export NAME=value`: accepted only in exactly that form.
ASSIGN_BUILTINS = frozenset({"export", "readonly", "local"})
# May appear in a command that restores markers elsewhere, but take no marker themselves.
PASSIVE = frozenset({"exit", "return", "break", "continue", "shift", "wait", "set", "umask", "times", "jobs",
                     "kill", "type", "which", "whence", "where", "pwd", "popd", "dirs", "fi", "done", "}",
                     "cd", "chdir", "pushd",
                     "bg", "fg", "disown", "test", "[", "in"})
_ARITH_TEST = frozenset({"-eq", "-ne", "-lt", "-le", "-gt", "-ge", "-v", "-R", "-o", "-a"})
# Every other bash/zsh builtin and reserved word: it can evaluate a string or a variable as code or as
# arithmetic, load code, or start a syntax this lexer does not model. Present anywhere -> nothing is restored.
UNSAFE_BUILTINS = frozenset("""
    . source eval exec command builtin trap let declare typeset integer float private alias unalias enable
    bind bindkey complete compgen compopt compctl compadd comparguments compcall compdescribe compfiles
    compgroups compquote compset comptags comptry compvalues mapfile readarray read coproc select function
    case esac [[ ]] repeat foreach end nocorrect noglob emulate autoload zmodload zcompile zle sched functions
    unfunction vared zstyle zformat zparseopts zregexparse fc r history print pushln getln setopt unsetopt
    shopt disable hash unhash rehash limit unlimit ulimit ttyctl echotc echoti log logout bye suspend caller
    help getopts unset time - always
""".split())
# Programs that parse their input or arguments as shell or as a program.
_SHELLS = frozenset("sh bash zsh dash ksh mksh ksh93 ash fish csh tcsh busybox pwsh powershell rbash".split())
REPARSE_PROGRAMS = _SHELLS | frozenset("""
    xargs parallel ssh su at batch crontab script watch tmux screen expect
    perl ruby node nodejs deno bun php lua luajit Rscript R osascript tclsh wish irb pry ipython julia groovy
    scala jshell erl elixir guile racket clisp sbcl ghci
""".split())
_PYTHON = re.compile(r"^(?:python|pypy)[0-9.]*$")
# Any word equal to one of these, wherever it stands (`docker exec c sh -c ...`, `find -exec ...`).
ANYWHERE = _SHELLS | frozenset({"eval", "xargs", "parallel", "-exec", "-execdir", "-ok", "-okdir"})
# Programs that run their arguments as a command, or read an argument as a program in their own
# language. A marker in the same simple command is refused. This list is a heuristic and is finite.
WRAPPING_PROGRAMS = frozenset("""
    env sudo doas nohup nice timeout stdbuf setsid ionice chrt taskset flock strace ltrace gdb lldb valgrind
    unbuffer caffeinate chronic chroot nsenter unshare systemd-run runuser pkexec fakeroot proot firejail
    bwrap docker podman nerdctl kubectl oc lxc vagrant ansible ansible-playbook mosh rsh direnv devbox mise
    npx pnpm yarn npm bunx uv uvx pipx poetry pdm hatch tox nox make gmake just task cargo go gradle mvn
    bazel awk gawk mawk nawk sed gsed ed ex vi vim nvim emacs sqlite3 psql mysql mariadb mongosh mongo
    redis-cli sqlcmd duckdb clickhouse-client bc dc m4 gnuplot octave
""".split())
# Variables whose value decides what code runs.
_RISKY_NAMES = frozenset("""
    PATH IFS ENV BASH_ENV SHELL SHELLOPTS BASHOPTS PS0 PS1 PS2 PS3 PS4 PROMPT PROMPT_COMMAND ZDOTDIR FPATH
    CDPATH HOME EDITOR VISUAL PAGER MANPAGER BROWSER TERMCAP TERMINFO NODE_OPTIONS GLOBIGNORE HISTFILE
    BASH_XTRACEFD TMPDIR LESSOPEN LESSCLOSE fpath path cdpath module_path MODULE_PATH
""".split())
_RISKY_PREFIXES = ("LD_", "DYLD_", "PYTHON", "PERL", "RUBY", "GIT_", "NODE_", "npm_", "NPM_", "BASH_", "ZSH_",
                   "DATAFOG_", "CLAUDE_", "JAVA_", "_JAVA", "LUA_", "GEM_", "BUNDLE_")

_ASSIGN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\+?=")
_SUBSCRIPT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\[")
_FD_VAR = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}[<>]")
_SAFE_PARAM = re.compile(r"[A-Za-z0-9_#@*?!:+=%/^,.\- ]*")
_WORD_END = " \t\n;&|<>)"
_REDIRECTS = ("<<<", "<<-", "<<", "<>", "<&", ">>", ">&", ">|", "&>>", "&>", "<", ">")

_WHY = {
    "command_word": "a marker is used as, or inside, a command name",
    "redirect": "a marker is used as a redirection target or heredoc delimiter",
    "escape": "a marker follows a backslash or an unquoted $, or is split by shell syntax",
    "expansion": "a marker is inside ${...}, arithmetic, or an old-style substitution",
    "syntax": "the command uses shell syntax the restorer does not model with certainty",
    "second_parse": "the command contains a program or builtin that evaluates text as code (for example "
                    "eval, a shell, xargs, ssh, an interpreter, arithmetic)",
    "wrapper": "a marker is an argument of a program that runs its arguments as a command or parses them "
               "as a program (for example env, sudo, timeout, awk, sed)",
    "assignment": "a marker is assigned to a variable that controls what code runs, or is used in an "
                  "assignment form the restorer does not model",
    "heredoc": "a marker in a heredoc could end the heredoc or cannot be written there safely",
    "value": "a value contains a NUL byte or a newline that cannot be represented in this place",
    "unbalanced": "the command has unbalanced quotes or brackets",
}


def _refuse(code: str) -> Refused:
    return Refused(code, _WHY[code])


def _risky_name(name: str) -> bool:
    return name in _RISKY_NAMES or name.startswith(_RISKY_PREFIXES)


def _single(value: str) -> str:
    return value.replace("'", "'\\''")


class _Frame:
    """One simple command (and, for nesting, every command it encloses)."""
    __slots__ = ("expect_command", "program", "dynamic", "markers", "args", "next_kind", "compound")

    def __init__(self):
        self.expect_command = True
        self.program: str | None = None
        self.dynamic = False
        self.markers = 0
        self.args: list[tuple[str, int, int, bool]] = []     # (literal text, markers in it, start, dynamic)
        self.next_kind: str | None = None
        self.compound = False


class _Word:
    __slots__ = ("kind", "start", "name", "markers", "dynamic", "glob", "literal")

    def __init__(self, kind: str, start: int):
        self.kind, self.start = kind, start
        self.name: str | None = None
        self.markers = 0
        self.dynamic = False          # holds an expansion: its text is not known before it runs
        self.glob = False             # holds an unquoted * ? or [
        self.literal: list[str] = []


class _Lexer:
    def __init__(self, text: str, spans: list[Span], shell: str):
        self.s, self.n, self.i = text, len(text), 0
        self.shell = shell
        self.out: list[str] = []
        self.at: dict[int, Span] = {}
        self.covered = bytearray(self.n + 1)
        last = 0
        for span in sorted(spans, key=lambda item: item.start):
            if not (last <= span.start < span.end <= self.n):
                raise _refuse("syntax")
            if "\x00" in span.value:
                raise _refuse("value")
            self.at[span.start] = span
            for position in range(span.start, span.end):
                self.covered[position] = 1
            last = span.end
        self.frames: list[_Frame] = []
        self.pending: list[tuple[str, bool, bool]] = []     # heredocs: (delimiter, quoted, strip tabs)
        self.backtick = False
        self.depth = 0
        self.newline_ok = False
        self.restored = 0
        self.left_literal = 0
        self.global_refusal: str | None = None

    # -- low level -------------------------------------------------------------------------
    def take(self, count: int = 1) -> None:
        """Copy ``count`` characters unchanged. No marker may be consumed this way."""
        end = self.i + count
        if end > self.n:
            raise _refuse("unbalanced")
        s = self.s
        for position in range(self.i, end):
            if self.covered[position]:
                raise _refuse("escape")
            char = s[position]
            if char == "\n" and self.pending and not self.newline_ok:
                raise _refuse("heredoc")
            if char == "\\" and self.backtick and position + 1 < self.n and s[position + 1] in "\\$`":
                raise _refuse("syntax")       # the backtick layer would rewrite this before the inner parse
        self.out.append(s[self.i:end])
        self.i = end

    def peek(self, offset: int = 0) -> str:
        position = self.i + offset
        return self.s[position] if position < self.n else ""

    @property
    def frame(self) -> _Frame:
        return self.frames[-1]

    def blanks(self) -> None:
        while self.i < self.n:
            char = self.s[self.i]
            if char in " \t":
                self.take()
            elif char == "\\" and self.peek(1) == "\n":
                self.take(2)
            else:
                return

    # -- markers ---------------------------------------------------------------------------
    def marker(self, mode: str, word: _Word | None) -> None:
        span = self.at[self.i]
        value = span.value
        if word is not None:
            if word.kind == "command":
                raise _refuse("command_word")
            if word.kind == "redirect":
                raise _refuse("redirect")
            if word.kind == "assign" and (word.name is None or _risky_name(word.name)):
                raise _refuse("assignment")
            if self.s[word.start] == "=":
                raise _refuse("syntax")           # zsh: =name is replaced by the path of a command
        previous = self.s[self.i - 1] if self.i else ""
        if mode in ("bare", "double", "heredoc") and previous == "$":
            raise _refuse("escape")
        if mode == "bare":
            text = "'" + _single(value) + "'"
        elif mode == "single":
            text = _single(value)
        elif mode == "double":
            text = "\"'" + _single(value) + "'\""
        elif mode == "ansi":
            text = value.replace("\\", "\\\\").replace("'", "\\'")
        elif mode == "heredoc_quoted":
            if "\n" in value:
                raise _refuse("value")
            text = value
        else:   # heredoc with an unquoted delimiter
            if "\n" in value:
                raise _refuse("value")
            text = value.replace("\\", "\\\\").replace("$", "\\$").replace("`", "\\`")
        if self.backtick:
            text = text.replace("\\", "\\\\").replace("`", "\\`")
        self.out.append(text)
        self.i = span.end
        self.restored += 1
        if word is not None:
            word.markers += 1
        for frame in self.frames:
            frame.markers += 1

    # -- commands --------------------------------------------------------------------------
    def begin(self) -> None:
        self.frames.append(_Frame())

    def end(self) -> None:
        frame = self.frames.pop()
        if frame.next_kind is not None:
            raise _refuse("syntax")               # an operator without its word
        program = os.path.basename(frame.program) if frame.program else None
        if program in ("test", "[") and any(arg[0] in _ARITH_TEST for arg in frame.args):
            self.global_refusal = self.global_refusal or "second_parse"
        if not frame.markers:
            return
        if frame.dynamic:
            raise _refuse("command_word")
        if program is None or frame.compound:
            return
        if program in WRAPPING_PROGRAMS or program in PASSIVE:
            raise _refuse("wrapper")
        if program in ASSIGN_BUILTINS:
            for text, markers, start, _ in frame.args:
                if text.startswith("-"):
                    raise _refuse("assignment")
                if markers:
                    match = _ASSIGN.match(self.s, start)
                    if not match or _risky_name(match.group(1)):
                        raise _refuse("assignment")
        if program == "printf":
            # `printf -v NAME` assigns, and bash evaluates NAME (`a[$(cmd)]` runs cmd). A value that is
            # "-v" must never stand where an option can: only `printf LITERAL-FORMAT args...` is accepted,
            # optionally after a literal `--`. Options end at the format, so later values are data.
            args = frame.args[1:] if frame.args and frame.args[0][0] == "--" and not frame.args[0][1] else frame.args
            if not args or args[0][1] or args[0][3] or args[0][0].startswith("-"):
                raise _refuse("assignment")

    def commands(self, closer: str) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise _refuse("syntax")
        self.begin()
        while True:
            self.blanks()
            if self.i >= self.n:
                if closer or self.pending:
                    raise _refuse("unbalanced")
                break
            char = self.s[self.i]
            if char == closer:
                if self.pending:
                    raise _refuse("heredoc")
                self.end()
                self.take()
                self.depth -= 1
                return
            if char == ")" or char == "`":
                raise _refuse("unbalanced")
            if char == "\n":
                self.end()
                self.newline()
                self.begin()
            elif char == "#":
                self.comment()
            elif char in ";&|":
                if self.s.startswith("&>", self.i):
                    self.redirect()
                    continue
                if self.s[self.i:self.i + 2] in (";;", ";&", ";|"):
                    raise _refuse("syntax")
                self.take(2 if self.s[self.i:self.i + 2] in ("&&", "||", "|&") else 1)
                self.end()
                self.begin()
            elif char == "(":
                frame = self.frame
                if self.peek(1) == "(" or not frame.expect_command or frame.program is not None:
                    raise _refuse("syntax")
                self.take()
                self.nested(")")
                frame.program, frame.expect_command, frame.compound = "(", False, True
            elif char in "<>":
                if self.peek(1) == "(":
                    self.word()
                else:
                    self.redirect()
            elif char.isdigit() and self._fd_prefix():
                self.redirect()
            else:
                self.word()
        self.end()
        self.depth -= 1

    def _fd_prefix(self) -> bool:
        position = self.i
        while position < self.n and self.s[position].isdigit():
            position += 1
        if position < self.n and self.s[position] in "<>" and not self.covered[position]:
            self.take(position - self.i)
            return True
        return False

    def nested(self, closer: str) -> None:
        if self.pending:
            raise _refuse("heredoc")
        self.commands(closer)

    def newline(self) -> None:
        self.newline_ok = True
        try:
            self.take()
            pending, self.pending = self.pending, []
            for delimiter, quoted, strip in pending:
                self.heredoc_body(delimiter, quoted, strip)
        finally:
            self.newline_ok = False

    def comment(self) -> None:
        while self.i < self.n and self.s[self.i] != "\n":
            if self.i in self.at:
                span = self.at[self.i]
                self.out.append(self.s[span.start:span.end])
                self.i = span.end
                self.left_literal += 1
            elif self.s[self.i] in "'\"\\$`":
                raise _refuse("syntax")       # if the shell did not read this as a comment, quoting would shift
            else:
                self.take()

    # -- redirections and heredocs -----------------------------------------------------------
    def redirect(self) -> None:
        operator = next(op for op in _REDIRECTS if self.s.startswith(op, self.i))
        self.take(len(operator))
        if operator in ("<<", "<<-"):
            self.heredoc_start(operator == "<<-")
            return
        if operator == "<<<" and self.shell == "sh":
            raise _refuse("syntax")
        self.blanks()
        if self.i >= self.n or self.s[self.i] in "\n;&|<>()#":
            raise _refuse("syntax")
        self.frame.next_kind = "herestring" if operator == "<<<" else "redirect"
        self.word()

    def heredoc_start(self, strip: bool) -> None:
        if self.backtick:
            raise _refuse("syntax")
        self.blanks()
        delimiter: list[str] = []
        quoted = False
        began = self.i
        while self.i < self.n and self.s[self.i] not in _WORD_END + "(":
            char = self.s[self.i]
            if char == "'" or char == '"':
                quoted = True
                self.take()
                while self.peek() != char:
                    if self.i >= self.n:
                        raise _refuse("unbalanced")
                    if self.s[self.i] in "$`\\\n":
                        raise _refuse("syntax")
                    delimiter.append(self.s[self.i])
                    self.take()
                self.take()
            elif char == "\\":
                quoted = True
                if self.peek(1) in ("", "\n"):
                    raise _refuse("syntax")
                delimiter.append(self.peek(1))
                self.take(2)
            elif char in "$`":
                raise _refuse("syntax")
            else:
                delimiter.append(char)
                self.take()
        if self.i == began or not delimiter:
            raise _refuse("syntax")
        self.pending.append(("".join(delimiter), quoted, strip))

    def heredoc_body(self, delimiter: str, quoted: bool, strip: bool) -> None:
        s = self.s
        while True:
            if self.i >= self.n:
                raise _refuse("unbalanced")           # no line holds the delimiter
            stop = s.find("\n", self.i)
            last = stop < 0
            stop = self.n if last else stop
            line = s[self.i:stop]
            if (line.lstrip("\t") if strip else line) == delimiter:
                self.take(stop - self.i)
                if not last:
                    self.take()
                return
            if not quoted and (len(line) - len(line.rstrip("\\"))) % 2:
                raise _refuse("heredoc")              # a continuation line: where the body ends is not certain
            if not any(self.covered[position] for position in range(self.i, stop)):
                self.take(stop - self.i)
            else:
                mark, begin = len(self.out), self.i
                while self.i < stop:
                    char = s[self.i]
                    if self.i in self.at:
                        if strip and self.at[self.i].value.startswith("\t") and not line[:self.i - begin].strip("\t"):
                            raise _refuse("heredoc")      # <<- would strip the value's own leading tabs
                        self.marker("heredoc_quoted" if quoted else "heredoc", None)
                    elif quoted:
                        self.take()
                    elif char == "\\":
                        if self.i + 1 >= stop:
                            raise _refuse("heredoc")
                        self.take(2)
                    elif char == "`" or (char == "$" and self.peek(1) in "({['\""):
                        raise _refuse("expansion")
                    else:
                        self.take()
                written = "".join(self.out[mark:])
                if written.strip(" \t") == delimiter or "\n" in written:
                    raise _refuse("heredoc")
            if last:
                raise _refuse("unbalanced")
            self.take()

    # -- words -----------------------------------------------------------------------------
    def word(self) -> None:
        frame = self.frame
        kind = frame.next_kind or ("command" if frame.expect_command else "arg")
        frame.next_kind = None
        word = _Word(kind, self.i)
        s = self.s
        if kind == "command":
            match = _ASSIGN.match(s, self.i)
            if match and not any(self.covered[position] for position in range(match.start(), match.end())):
                word.kind, word.name = "assign", match.group(1)
                self.take(match.end() - self.i)
                if self.peek() == "(":
                    raise _refuse("assignment")
            elif _SUBSCRIPT.match(s, self.i):
                raise _refuse("assignment")
            elif _FD_VAR.match(s, self.i):
                raise _refuse("syntax")
        first = True
        while self.i < self.n:
            char = s[self.i]
            if first and char in "<>" and self.peek(1) == "(":
                if self.shell == "sh":
                    raise _refuse("syntax")
                self.take(2)
                self.nested(")")
                word.dynamic = True
                first = False
                continue
            first = False
            if char in _WORD_END or (char == "`" and self.backtick):
                break
            if self.i in self.at:
                self.marker("bare", word)
            elif char == "(":
                raise _refuse("syntax")               # function definition, array, glob qualifier, extglob
            elif char == "\\":
                if self.i + 1 >= self.n:
                    raise _refuse("unbalanced")
                if s[self.i + 1] != "\n":
                    word.literal.append(s[self.i + 1])
                self.take(2)
            elif char == "'":
                self.single(word)
            elif char == '"':
                self.double(word)
            elif char == "$":
                self.dollar(word)
            elif char == "`":
                self.backticks()
                word.dynamic = True
            else:
                if char in "*?[":
                    word.glob = True
                word.literal.append(char)
                self.take()
        self.end_word(word)

    def end_word(self, word: _Word) -> None:
        frame = self.frame
        literal = "".join(word.literal)
        if not word.dynamic and os.path.basename(literal) in ANYWHERE:
            self.global_refusal = self.global_refusal or "second_parse"
        if word.kind == "command":
            if word.dynamic or (word.glob and literal != "["):
                frame.dynamic, frame.expect_command = True, False
                self.global_refusal = self.global_refusal or "second_parse"   # `$cmd` may be eval or a shell
                return
            if literal in TRANSPARENT:
                return
            frame.program, frame.expect_command = literal, False
            base = os.path.basename(literal)
            if base in UNSAFE_BUILTINS or base in REPARSE_PROGRAMS or _PYTHON.match(base):
                self.global_refusal = self.global_refusal or "second_parse"
        elif word.kind in ("arg", "herestring"):
            frame.args.append((literal, word.markers, word.start, word.dynamic))

    def single(self, word: _Word) -> None:
        self.take()
        while True:
            if self.i >= self.n:
                raise _refuse("unbalanced")
            if self.i in self.at:
                self.marker("single", word)
            elif self.s[self.i] == "'":
                self.take()
                return
            else:
                word.literal.append(self.s[self.i])
                self.take()

    def double(self, word: _Word) -> None:
        self.take()
        while True:
            if self.i >= self.n:
                raise _refuse("unbalanced")
            char = self.s[self.i]
            if self.i in self.at:
                self.marker("double", word)
            elif char == '"':
                self.take()
                return
            elif char == "\\":
                if self.i + 1 >= self.n:
                    raise _refuse("unbalanced")
                word.literal.append(self.s[self.i + 1])
                self.take(2)
            elif char == "`":
                raise _refuse("syntax")
            elif char == "$":
                self.dollar(word, quoted=True)
            else:
                word.literal.append(char)
                self.take()

    def dollar(self, word: _Word, quoted: bool = False) -> None:
        following = self.peek(1)
        if following == "'" and not quoted:
            if self.shell == "sh":
                raise _refuse("syntax")
            self.take(2)
            while True:
                if self.i >= self.n:
                    raise _refuse("unbalanced")
                char = self.s[self.i]
                if self.i in self.at:
                    self.marker("ansi", word)
                elif char == "\\":
                    self.take(2)
                    word.dynamic = True
                elif char == "'":
                    self.take()
                    return
                else:
                    word.literal.append(char)
                    self.take()
        if following == '"' and not quoted:
            raise _refuse("syntax")                   # $"..." (translated string)
        word.dynamic = True
        if following == "(":
            if self.peek(2) == "(":
                raise _refuse("expansion")            # arithmetic, or too close to it to tell
            self.take(2)
            self.nested(")")
        elif following == "{":
            close = self.s.find("}", self.i + 2)
            if close < 0 or not _SAFE_PARAM.fullmatch(self.s, self.i + 2, close):
                raise _refuse("expansion")
            if any(self.covered[position] for position in range(self.i, close + 1)):
                raise _refuse("expansion")
            self.take(close + 1 - self.i)
        elif following == "[":
            raise _refuse("expansion")
        else:
            self.take()

    def backticks(self) -> None:
        if self.backtick or self.pending:
            raise _refuse("syntax")
        self.take()
        self.backtick = True
        self.commands("`")
        self.backtick = False


def substitute(command: str, spans: list[Span], shell: str = "bash") -> Result:
    """The command with every known marker replaced by its value as inert data.

    Raises :class:`Refused` when that cannot be done with certainty. ``shell`` is "bash", "zsh"
    or "sh" (anything else that runs the command; fewer forms are accepted then).
    """
    if "\x00" in command:
        raise _refuse("syntax")
    lexer = _Lexer(command, spans, shell)
    try:
        lexer.commands("")
    except RecursionError:
        raise _refuse("syntax") from None
    if lexer.frames or lexer.i != lexer.n:
        raise _refuse("unbalanced")
    if lexer.restored and lexer.global_refusal:
        raise _refuse(lexer.global_refusal)
    if lexer.restored + lexer.left_literal != len(spans):
        raise _refuse("syntax")
    return Result("".join(lexer.out), lexer.restored, lexer.left_literal)
