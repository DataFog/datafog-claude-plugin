"""The late swap: real values are put into a Bash command inside the runner, as inert data.

Threat model (see engine/datafog_guard/shellsub.py): the model chooses the command and the
quoting around a marker; the value's owner chooses nothing; a value must never execute.

Three layers of proof, all under real bash and real zsh:
  * every nasty value x every supported context, substituted and run by the shell directly;
  * random values over a hostile alphabet x every context;
  * the same contexts through the real runner (wrap.sh, launcher, filtercmd), which is what
    Claude Code executes.
Each asserts (1) the receiving program got exactly the value's bytes, (2) no side-effect
file appeared, (3) the exit status is the command's own.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess

import pytest
from conftest import standin_plugin
from datafog_guard import bashwrap, shellsub
from datafog_guard.shellsub import Refused, Span, substitute

SHELLS = [shell for shell in ("bash", "zsh") if shutil.which(shell)]
# The runner falls back to /bin/sh when neither bash nor zsh exists. The lexer then works in its "sh"
# mode, which accepts fewer forms; that mode is checked against dash where it is installed.
PLAIN_SH = [shell for shell in ("dash",) if shutil.which(shell)]
SH_ONLY_REFUSES = {"ansi_c", "ansi_c_inside", "here_string", "here_string_double", "process_substitution"}


def kind_of(shell: str) -> str:
    return shell if shell in ("bash", "zsh") else "sh"
M = "[[ACCOUNT_NUMBER_000000]]"          # a stand-in marker for tests that give the value directly

BIG = ("$(touch PWNED)`touch PWNED`'\";|&<>(){}[]*?!~#\\ \t%s%n-rf é日本語 " * 80)[:4096]
NASTY = [
    "plain", "a b", "  lead and trail  ", "", "-rf", "--help", "-", "--", "-v", "-n", "-e", "-p", "-a", "-f",
    "a[$(touch PWNED)]", "x[`touch PWNED`]", "-va[$(touch PWNED)]", "*", "?", "[a-z]*", "~", "~root", "#x",
    "$HOME", "${HOME}", "$0", "$$", "$(touch PWNED)", "`touch PWNED`", "$((1+1))", "$[1+1]", "${x:-$(touch PWNED)}",
    "'; touch PWNED; '", "\"; touch PWNED; \"", "; touch PWNED", "| touch PWNED", "& touch PWNED &",
    "&& touch PWNED", "|| touch PWNED", "(touch PWNED)", "{ touch PWNED; }", ">PWNED", "<PWNED", ">>PWNED 2>&1",
    "\\", "\\\\", "abc\\", "\\'; touch PWNED; \\'", "\\\"; touch PWNED; \\\"", "\\$(touch PWNED)", "\\`touch PWNED\\`",
    "'", "''", "'\\''", "\"", "a'b\"c", "$'\\x41'; touch PWNED", "'$(touch PWNED)'", "\"$(touch PWNED)\"",
    "!!", "!$", "!touch PWNED", "=touch", "{a,b}", "x;y", "%s%n%d", "\\n", "\\x41\\101\\u0041", "EOF", "E O F",
    "EOF; touch PWNED", "a\tb", "\ttab first", "\r", "a\rb", "héllo wörld", "日本語 ✓ 🙂", "\u202eabc", "\x7f\x01\x1b[31m",
    "x@example.com;touch${IFS}PWNED", "postgres://u:$(touch PWNED)@h/db?x=`touch PWNED`", BIG,
]
MULTILINE = ["line1\nline2", "\ntouch PWNED\n", "EOF\ntouch PWNED", "x\nEOF\ntouch PWNED\n: <<EOF", "abc\n", "\n",
             "'\ntouch PWNED\n'"]
ALL_VALUES = NASTY + MULTILINE


def argv(*parts):
    return lambda value: b"".join(part.replace("{v}", value).encode() + b"\0" for part in parts)


def data(text):
    return lambda value: text.replace("{v}", value).encode()


# name -> (command template, what the receiver must have got, supports values with a newline)
# `dump ID args...` records its arguments, `sdump ID` its stdin, `edump ID` the variable X.
CONTEXTS = {
    "unquoted": ("dump {id} {m}", argv("{v}"), True),
    "unquoted_glued": ("dump {id} a{m}b", argv("a{v}b"), True),
    "unquoted_twice": ("dump {id} {m} -- {m}", argv("{v}", "--", "{v}"), True),
    "single": ("dump {id} '{m}'", argv("{v}"), True),
    "single_inside": ("dump {id} 'a {m} $b'", argv("a {v} $b"), True),
    "single_after_backslash": ("dump {id} 'a\\{m}'", argv("a\\{v}"), True),
    "double": ('dump {id} "{m}"', argv("{v}"), True),
    "double_inside": ('dump {id} "a {m} b"', argv("a {v} b"), True),
    "double_after_variable": ('dump {id} "$EMPTY{m}$EMPTY"', argv("{v}"), True),
    "ansi_c": ("dump {id} $'{m}'", argv("{v}"), True),
    "ansi_c_inside": ("dump {id} $'a\\t{m}\\tb'", argv("a\t{v}\tb"), True),
    "mixed_quotes": ("dump {id} x'{m}'\"{m}\"{m}", argv("x{v}{v}{v}"), True),
    "command_substitution": ("dump {id} \"$(printf '%s.' {m})\"", argv("{v}."), True),
    "command_substitution_double": ("dump {id} \"$(printf '%s.' \"{m}\")\"", argv("{v}."), True),
    "command_substitution_nested": ("dump {id} \"$(printf '%s.' \"$(printf '%s.' '{m}')\")\"", argv("{v}.."), True),
    "backticks": ("x=`printf '%s.' {m}`; dump {id} \"$x\"", argv("{v}."), True),
    "backticks_single": ("x=`printf '%s.' '{m}'`; dump {id} \"$x\"", argv("{v}."), True),
    "backticks_double": ("x=`printf '%s.' \"{m}\"`; dump {id} \"$x\"", argv("{v}."), True),
    "assignment": ('x={m}; dump {id} "$x"', argv("{v}"), True),
    "assignment_double": ('x="{m}"; dump {id} "$x"', argv("{v}"), True),
    "assignment_prefix": ("X={m} edump {id}", data("{v}"), True),
    "export": ("export X={m}; edump {id}", data("{v}"), True),
    "subshell": ("(dump {id} {m})", argv("{v}"), True),
    "group": ("{ dump {id} {m}; }", argv("{v}"), True),
    "if": ("if true; then dump {id} {m}; fi", argv("{v}"), True),
    "for": ('for i in {m}; do dump {id} "$i"; done', argv("{v}"), True),
    "and_list": ("true && dump {id} {m}", argv("{v}"), True),
    "pipeline": ("printf '%s' {m} | sdump {id}", data("{v}"), True),
    "here_string": ("sdump {id} <<< {m}", data("{v}\n"), True),
    "here_string_double": ('sdump {id} <<< "{m}"', data("{v}\n"), True),
    "process_substitution": ("cat <(printf '%s' {m}) | sdump {id}", data("{v}"), True),
    "heredoc_quoted": ("sdump {id} <<'EOF'\n{m}\nEOF", data("{v}\n"), False),
    "heredoc_quoted_inside": ("sdump {id} <<'EOF'\na {m} $b `c`\nEOF", data("a {v} $b `c`\n"), False),
    "heredoc_double_quoted_delimiter": ('sdump {id} <<"E O F"\n{m} x\nE O F', data("{v} x\n"), False),
    "heredoc_escaped_delimiter": ("sdump {id} <<\\EOF\n{m}\nEOF", data("{v}\n"), False),
    "heredoc_unquoted": ("sdump {id} <<EOF\n{m}\nEOF", data("{v}\n"), False),
    "heredoc_unquoted_inside": ("sdump {id} <<EOF\na {m} $EMPTY b\nEOF", data("a {v}  b\n"), False),
    "heredoc_tabs": ("sdump {id} <<-EOF\n\tx{m}\n\tEOF", data("x{v}\n"), False),
    "printf_after_format": ("printf '%s\\0' {m} > \"$DUMP_DIR/{id}\"", argv("{v}"), True),
    "printf_after_dashes": ("printf -- '%s|%s' {m} {m} > \"$DUMP_DIR/{id}\"", data("{v}|{v}"), True),
    "echo_first_argument": ("echo x {m} > /dev/null; dump {id} {m}", argv("{v}"), True),
    "comment": ("dump {id} x # {m}", argv("x"), True),
}
# A value alone on a heredoc line may not equal the delimiter.
ALONE_ON_LINE = {"heredoc_quoted": "EOF", "heredoc_escaped_delimiter": "EOF", "heredoc_unquoted": "EOF"}

# Places where a value is never put: the command is refused as a whole.
REFUSED = {
    "command name": "{m}",
    "command name with arguments": "{m} -v x",
    "part of a command name": "./{m}",
    "quoted command name": '"{m}" x',
    "command name after an assignment": "X=1 {m}",
    "command name after a keyword": "if {m}; then :; fi",
    "command name in a pipeline": "true | {m}",
    "command name in a substitution": "echo $({m})",
    "command name in backticks": "echo `{m}`",
    "output redirection target": "echo x > {m}",
    "append redirection target": "echo x >> '{m}'",
    "input redirection target": "cat < {m}",
    "stderr redirection target": 'ls 2> "{m}"',
    "heredoc delimiter": "cat <<{m}\nx\n{m}",
    "eval": "eval echo {m}",
    "eval of a variable set from a marker": 'x={m}; eval "$x"',
    "sh -c": 'sh -c "echo {m}"',
    "bash -c": "bash -c 'echo {m}'",
    "zsh -c with an argument": "zsh -c 'echo \"$1\"' _ {m}",
    "piped into a shell": "echo {m} | sh",
    "xargs": "echo {m} | xargs echo",
    "xargs running the value": "xargs {m}",
    "ssh": "ssh host echo {m}",
    "find -exec": "find . -exec echo {m} ';'",
    "docker exec sh": 'docker exec c sh -c "echo {m}"',
    "parameter expansion": "echo ${x:-{m}}",
    "arithmetic expansion": "echo $(( {m} ))",
    "arithmetic command": "(( x = {m} ))",
    "old arithmetic": "echo $[{m}]",
    "arithmetic elsewhere in the command": "x={m}; echo $((x))",
    "let": "x={m}; let y=x",
    "declare -i": "declare -i x={m}",
    "conditional expression": "[[ {m} == x ]]",
    "test with an arithmetic operator": 'x={m}; [ "$x" -eq 1 ]',
    "case": "case {m} in x) ;; esac",
    "array": "a=({m})",
    "array element": "a[{m}]=1",
    "function definition": "f() { echo {m}; }; f",
    "env": "env X=1 echo {m}",
    "sudo": "sudo echo {m}",
    "timeout": "timeout 5 echo {m}",
    "nohup": "nohup echo {m}",
    "command": "command echo {m}",
    "exec": "exec echo {m}",
    "time": "time echo {m}",
    "awk program": "awk '/{m}/' f",
    "sed script": "sed 's/{m}//' f",
    "python -c": "python3 -c 'print(\"{m}\")'",
    "perl -e": "perl -e 'print \"{m}\"'",
    "sqlite3": "sqlite3 db \"select '{m}'\"",
    "after a backslash": "echo \\{m}",
    "after a backslash in double quotes": 'echo "\\{m}"',
    "after a backslash in $'...'": "echo $'\\{m}'",
    "after a dollar sign": "echo ${m}",
    "after a dollar sign in double quotes": 'echo "${m}"',
    "backticks inside double quotes": 'echo "`echo {m}`"',
    "escaped characters inside backticks": "echo `echo \\$x {m}`",
    "translated string": 'echo $"{m}"',
    "substitution in an unquoted heredoc line": "cat <<EOF\n$(echo {m})\nEOF",
    "after a dollar sign in a heredoc": "cat <<EOF\n${m}\nEOF",
    "after a backslash in a heredoc": "cat <<EOF\n\\{m}\nEOF",
    "heredoc with a continuation line": "cat <<EOF\nx \\\n{m}\nEOF",
    "heredoc without an end": "cat <<EOF\n{m}\n",
    "heredoc inside backticks": "x=`cat <<EOF\n{m}\nEOF\n`",
    "PATH assignment": "PATH={m} ls",
    "LD_PRELOAD assignment": "LD_PRELOAD={m} ls",
    "IFS assignment": "IFS={m}; ls",
    "export PATH": "export PATH={m}",
    "export with an option": "export -n X={m}",
    "export of a bare value": "export {m}",
    "printf -v": "printf -v x %s {m}",
    "printf with a marker as the format": "printf {m} x",
    "printf with a marker before the format": "printf {m} %s x",
    "printf with only markers": "printf {m} {m} hi",
    "printf with an option before the format": "printf -- -v {m}",
    "printf with a variable format": 'printf "$fmt" {m}',
    "printf with a quoted marker as the format": 'printf "{m}" x',
    "cd": "cd {m}",
    "pushd": "pushd {m}",
    "test -v": "test -v {m}",
    "[ -n": "[ -n {m} ]",
    "wait": "wait {m}",
    "unset": "unset {m}",
    "getopts": "getopts {m} name",
    "mapfile": "mapfile {m}",
    "export -f": "export -f {m}",
    "readonly of a bare value": "readonly {m}",
    "hash": "hash {m}",
    "type": "type {m}",
    "read": "read x <<< {m}",
    "trap": "trap 'echo {m}' EXIT",
    "source": "source ./x {m}",
    "alias": "alias x={m}",
    "variable as the command": "$cmd {m}",
    "glob as the command": "/bin/ech? {m}",
    "exit status argument": "exit {m}",
    "kill argument": "kill {m}",
    "zsh repeat": "repeat 2 {m}",
    "zsh equals expansion": "echo ={m}",
    "unterminated single quote": "echo '{m}",
    "unterminated double quote": 'echo "{m}',
    "unterminated substitution": "echo $(echo {m}",
    "trailing backslash": "echo {m} \\",
    "extended glob or qualifier": "echo {m}(.)",
    "process substitution as the command": "<(echo {m})",
    "comment with quotes before a marker": "echo a # it's\necho {m}",
    "coproc": "coproc echo {m}",
    "select": "select x in {m}; do :; done",
    "brace variable redirection": "{fd}>x echo {m}",
    "newline inside quotes while a heredoc is pending": "cat <<EOF '\n' {m}\nx\nEOF",
}


def render(template: str, marker: str, ident: str = "0") -> str:
    return template.replace("{id}", ident).replace("{m}", marker)


def spans_for(command: str, values: dict[str, str]) -> list[Span]:
    spans = []
    for marker, value in values.items():
        start = command.find(marker)
        while start >= 0:
            spans.append(Span(start, start + len(marker), "ACCOUNT_NUMBER", value))
            start = command.find(marker, start + 1)
    return sorted(spans, key=lambda span: span.start)


def sub(template: str, value: str, shell: str = "bash") -> str:
    command = render(template, M)
    return substitute(command, spans_for(command, {M: value}), shell).text


def expected_refusal(name: str, value: str) -> bool:
    """Values a context cannot take: a newline in a heredoc, a line equal to the delimiter, a tab under <<-."""
    if name == "comment":
        return False
    multiline_ok = CONTEXTS[name][2]
    if "\n" in value and not multiline_ok:
        return True
    if ALONE_ON_LINE.get(name) == value.strip(" \t") and name in ALONE_ON_LINE:
        return True
    return False


class Bin:
    """The receiving programs: they record exactly what they were given, as bytes."""

    def __init__(self, tmp):
        self.bin, self.dumps, self.cwd = tmp / "bin", tmp / "dumps", tmp / "cwd"
        for folder in (self.bin, self.dumps, self.cwd):
            folder.mkdir()
        scripts = {
            "dump": '#!/bin/sh\nid=$1; shift\nfor a in "$@"; do printf \'%s\\0\' "$a"; done > "$DUMP_DIR/$id"\n',
            "sdump": '#!/bin/sh\ncat > "$DUMP_DIR/$1"\n',
            "edump": '#!/bin/sh\nprintf \'%s\' "$X" > "$DUMP_DIR/$1"\n',
        }
        for name, text in scripts.items():
            path = self.bin / name
            path.write_text(text)
            path.chmod(0o755)

    def env(self, shell: str) -> dict:
        return {"PATH": f"{self.bin}:{os.environ['PATH']}", "DUMP_DIR": str(self.dumps), "HOME": str(self.cwd),
                "SHELL": shutil.which(shell) or shell, "LC_ALL": "C.UTF-8"}

    def got(self, ident) -> bytes | None:
        try:
            return (self.dumps / str(ident)).read_bytes()
        except FileNotFoundError:
            return None

    def side_effects(self) -> list[str]:
        return sorted(os.listdir(self.cwd))

    def reset(self) -> None:
        for path in self.dumps.iterdir():
            path.unlink()


@pytest.fixture
def receivers(tmp_path) -> Bin:
    return Bin(tmp_path)


# -- the lexer on its own ------------------------------------------------------------------------
def test_each_context_is_written_in_its_own_encoding():
    value = "a'b\"c$d`e\\f"
    assert sub("x {m}", value) == "x 'a'\\''b\"c$d`e\\f'"
    assert sub("x '{m}'", value) == "x 'a'\\''b\"c$d`e\\f'"
    assert sub('x "p{m}q"', value) == "x \"p\"'a'\\''b\"c$d`e\\f'\"q\""
    assert sub("x $'{m}'", value) == "x $'a\\'b\"c$d`e\\\\f'"
    assert sub("x <<'E'\n{m}\nE", value) == "x <<'E'\n" + value + "\nE"
    assert sub("x <<E\n{m}\nE", value) == "x <<E\na'b\"c\\$d\\`e\\\\f\nE"
    assert sub("y=`x {m}`", value) == "y=`x 'a'\\\\''b\"c$d\\`e\\\\f'`"
    assert sub("x # {m}", value) == "x # " + M


def test_result_counts_and_untouched_text():
    command = f"grep -c {M} notes.txt # {M}"
    result = substitute(command, spans_for(command, {M: "v"}))
    assert (result.text, result.restored, result.left_literal) == (f"grep -c 'v' notes.txt # {M}", 1, 1)
    plain = "echo [[NOT_A_MARKER]] 'x' \"$y\" $(z) | cat"
    assert substitute(plain, []).text == plain


@pytest.mark.parametrize("name", sorted(REFUSED))
@pytest.mark.parametrize("shell", ["bash", "zsh", "sh"])
def test_unsupported_places_are_refused(name, shell):
    for value in ("plain", "$(touch PWNED)", "'; touch PWNED; '"):
        with pytest.raises(Refused) as info:
            sub(REFUSED[name], value, shell)
        assert "PWNED" not in info.value.text and "plain" not in info.value.code and M not in info.value.text


def test_refusal_reasons_never_hold_command_or_value_text():
    for template in REFUSED.values():
        try:
            sub(template, "SECRETVALUE")
        except Refused as refusal:
            assert "SECRET" not in refusal.text + refusal.code and "{m}" not in refusal.text


@pytest.mark.parametrize("name", [name for name, spec in CONTEXTS.items() if not spec[2]])
def test_newlines_are_refused_in_heredocs(name):
    for value in MULTILINE:
        with pytest.raises(Refused):
            sub(CONTEXTS[name][0], value)


def test_values_that_would_end_a_heredoc_are_refused():
    for name, delimiter in ALONE_ON_LINE.items():
        for value in (delimiter, " " + delimiter, delimiter + "\t"):
            with pytest.raises(Refused):
                sub(CONTEXTS[name][0], value)
        assert delimiter + "x" in sub(CONTEXTS[name][0], delimiter + "x")
    with pytest.raises(Refused):
        sub("cat <<-EOF\n\t{m}\n\tEOF", "\tEOF")
    with pytest.raises(Refused):
        sub("cat <<-EOF\n\t{m}\n\tEOF", "\tx")           # <<- would strip the value's own tab


def test_nul_is_refused_everywhere():
    for name, (template, _, _) in CONTEXTS.items():
        if name != "comment":
            with pytest.raises(Refused):
                sub(template, "a\0b")


def test_sh_accepts_fewer_forms():
    for name in ("ansi_c", "here_string", "process_substitution"):
        with pytest.raises(Refused):
            sub(CONTEXTS[name][0], "v", "sh")
    assert sub(CONTEXTS["double"][0], "v", "sh")


def test_every_builtin_and_reserved_word_of_the_installed_shells_is_classified():
    """A builtin this file does not know would be treated as an ordinary program, whose arguments
    may take values. A new shell version that adds one must fail here."""
    known = (shellsub.TRANSPARENT | shellsub.ARG_SAFE | shellsub.ASSIGN_BUILTINS | shellsub.PASSIVE
             | shellsub.UNSAFE_BUILTINS)
    listed = set()
    if shutil.which("bash"):
        listed |= set(subprocess.run(["bash", "-c", "compgen -b; compgen -k"], capture_output=True,
                                     text=True).stdout.split())
    if shutil.which("zsh"):
        listed |= set(subprocess.run(
            ["zsh", "-fc", "zmodload zsh/parameter; print -l ${(k)builtins} ${(k)reswords} ${(k)dis_builtins}"],
            capture_output=True, text=True).stdout.split())
    assert listed, "no shell to ask"
    assert not listed - known, sorted(listed - known)


# -- every nasty value in every context, run by the real shells -----------------------------------
def run_shell(receivers: Bin, shell: str, script: str, timeout: int = 120):
    return subprocess.run([shell, "-c", script], capture_output=True, cwd=receivers.cwd, env=receivers.env(shell),
                          stdin=subprocess.DEVNULL, timeout=timeout)


@pytest.mark.parametrize("shell", SHELLS + PLAIN_SH)
@pytest.mark.parametrize("name", sorted(CONTEXTS))
def test_nasty_values_arrive_exactly_and_never_run(receivers, shell, name):
    template, expect, _ = CONTEXTS[name]
    if kind_of(shell) == "sh" and name in SH_ONLY_REFUSES:
        with pytest.raises(Refused):
            sub(template, "plain", "sh")
        return
    ran = refused = 0
    for number, value in enumerate(ALL_VALUES):
        command = render(template, M, str(number))
        try:
            text = substitute(command, spans_for(command, {M: value}), kind_of(shell)).text
        except Refused:
            assert expected_refusal(name, value), f"{name}: unexpected refusal of value #{number}"
            refused += 1
            continue
        assert not expected_refusal(name, value), f"{name}: value #{number} should have been refused"
        result = run_shell(receivers, shell, text + "\n(exit 37)")
        assert result.returncode == 37, (name, number, result.stderr[-300:])
        assert receivers.got(number) == expect(value), (name, number, repr(value)[:60])
        assert receivers.side_effects() == [], (name, number, repr(value)[:60])
        ran += 1
    assert ran >= len(NASTY) - 3 and ran + refused == len(ALL_VALUES)


ALPHABET = list("'\"\\$`;|&()<>{}[]*?!~#= \t\n-%^,.:/@") + ["a", "b", "EOF", "PWNED", "touch PWNED", "$(", "${", "é", "日"]


@pytest.mark.parametrize("shell", SHELLS)
def test_random_values_in_every_context(receivers, shell):
    """Fuzz: 300 random values over a hostile alphabet, in every context, one shell run per context."""
    rng = random.Random(20261117)
    values = ["".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 14))) for _ in range(300)]
    checked = 0
    for name, (template, expect, _) in sorted(CONTEXTS.items()):
        receivers.reset()
        lines, wanted = [], {}
        for number, value in enumerate(values):
            command = render(template, M, str(number))
            try:
                lines.append(substitute(command, spans_for(command, {M: value}), shell).text)
            except Refused:
                assert expected_refusal(name, value), (name, repr(value))
                continue
            assert not expected_refusal(name, value), (name, repr(value))
            wanted[number] = expect(value)
        result = run_shell(receivers, shell, "\n".join(lines) + "\n(exit 37)")
        assert result.returncode == 37, (name, result.stderr[-300:])
        for number, want in wanted.items():
            assert receivers.got(number) == want, (name, repr(values[number]))
        assert receivers.side_effects() == [], name
        checked += len(wanted)
    assert checked > 300 * (len(CONTEXTS) - 8)


@pytest.mark.parametrize("shell", SHELLS)
def test_several_markers_and_values_in_one_command(receivers, shell):
    values = {f"[[ACCOUNT_NUMBER_00000{n}]]": value for n, value in
              enumerate(["$(touch PWNED)", "'; touch PWNED; '", "a b", "\\", "`touch PWNED`"])}
    markers = list(values)
    command = (f"dump 0 {markers[0]} '{markers[1]}' \"{markers[2]}{markers[3]}\" $'{markers[4]}' && "
               f"sdump 1 <<EOF\n{markers[0]} {markers[1]}\nEOF\n(exit 5)")
    text = substitute(command, spans_for(command, values), shell).text
    result = run_shell(receivers, shell, text)
    got = list(values.values())
    assert result.returncode == 5
    assert receivers.got(0) == b"".join(part.encode() + b"\0" for part in (got[0], got[1], got[2] + got[3], got[4]))
    assert receivers.got(1) == f"{got[0]} {got[1]}\n".encode()
    assert receivers.side_effects() == []


# -- through the real runner ------------------------------------------------------------------------
class Runner:
    """Runs a command exactly as Claude Code would after the hook rewrote it: the rewritten
    command line under a real shell, with the restore ticket the hook issues."""

    def __init__(self, box, receivers: Bin, shell: str):
        self.box, self.receivers, self.shell = box, receivers, shell
        self.plugin, self.settings = standin_plugin(box)

    def run(self, command: str, *, ticket: object = True, env: dict | None = None, timeout: int = 120):
        if ticket is True:
            ticket = bashwrap.restore_ticket(command, self.settings.vault_dir)
        script = bashwrap.wrap(command, self.settings, ticket if isinstance(ticket, str) else None)
        environment = self.receivers.env(self.shell)
        environment.update(env or {})
        return subprocess.run([self.shell, "-c", script], capture_output=True, cwd=self.receivers.cwd,
                              env=environment, stdin=subprocess.DEVNULL, timeout=timeout), script


@pytest.fixture(params=SHELLS)
def runner(box, receivers, request) -> Runner:
    return Runner(box, receivers, request.param)


@pytest.fixture
def seeded(box):
    """marker -> value for every nasty value a real vault accepts.

    Every value is stored so that it comes back byte for byte (core compares values loosely, so a
    value that differs from an earlier one only in white space or case gets a variant label). Core
    refuses a value that is only white space. The runner is checked against what the vault returns."""
    from datafog_guard.errors import GuardError
    vault = box.open_vault()
    stored = {}
    for value in NASTY + MULTILINE:
        if not value:
            continue
        try:
            marker = vault._markers_for({value: ["ACCOUNT_NUMBER"]})[value]
        except GuardError:
            continue
        stored[marker] = vault.restore_spans(marker)[0][0][3]
    assert len(stored) >= len(NASTY) + len(MULTILINE) - 6
    return stored


def test_runner_restores_every_nasty_value_in_every_context(runner, seeded):
    """The real path: wrap.sh -> launcher -> runner -> child shell. One runner call per context."""
    total = 0
    for name, (template, expect, _) in sorted(CONTEXTS.items()):
        runner.receivers.reset()
        lines, wanted = [], {}
        for number, (marker, value) in enumerate(seeded.items()):
            if expected_refusal(name, value):
                continue
            lines.append(render(template, marker, str(number)))
            wanted[number] = expect(value)
        command = "\n".join(lines) + "\n(exit 37)"
        result, script = runner.run(command)
        assert result.returncode == 37, (name, result.stderr[-400:])
        for number, want in wanted.items():
            assert runner.receivers.got(number) == want, (name, number)
        assert runner.receivers.side_effects() == [], name
        for value in ("touch PWNED", "日本語", "héllo"):
            assert value not in script                       # what Claude Code is given holds markers only
        total += len(wanted)
    assert total > len(NASTY) * (len(CONTEXTS) - 2)
    log = runner.box.visible_files()
    assert "PWNED" not in log and "日本語" not in log and '"restored"' in log


@pytest.mark.parametrize("name", ["command name", "eval", "sh -c", "output redirection target", "xargs", "awk program",
                                  "parameter expansion", "after a backslash", "ssh", "piped into a shell"])
def test_runner_refuses_unsupported_places_and_runs_nothing(runner, seeded, name):
    marker = next(m for m, value in seeded.items() if value == "$(touch PWNED)")
    command = "touch RAN; " + render(REFUSED[name], marker)
    result, _ = runner.run(command)
    assert result.returncode == 125
    assert b"could not be replaced by their values safely" in result.stderr and b"the command was not run" in result.stderr
    assert b"PWNED" not in result.stderr and marker.encode() not in result.stderr
    assert runner.receivers.side_effects() == []             # not even the harmless first part ran


def test_printf_never_takes_an_option_or_a_variable_name_from_a_value(runner, receivers):
    """Review finding: `printf [[M0]] [[M1]] hi` with the values `-v` and `a[$(cmd)]` ran cmd, because
    bash evaluates the NAME given to -v. printf takes markers only after a literal format."""
    option, name = runner.box.seed("-v"), runner.box.seed("a[$(touch PWNED)]")
    for command in (f"printf {option} {name} hi", f"printf '{option}' \"{name}\" hi", f"printf -- {option} {name}",
                    f"x=1; printf {option} {name} hi"):
        with pytest.raises(Refused):
            substitute(command, spans_for(command, {option: "-v", name: "a[$(touch PWNED)]"}), runner.shell)
        result, _ = runner.run(command)
        assert result.returncode == 125 and receivers.side_effects() == [], command
    # after a literal format the same two values are plain data
    result, _ = runner.run(f"printf '%s %s' {option} {name} > \"$DUMP_DIR/0\"")
    assert result.returncode == 0 and receivers.got(0) == b"-v a[$(touch PWNED)]" and receivers.side_effects() == []


def test_runner_refuses_multiline_values_in_heredocs(runner, seeded):
    marker = next(m for m, value in seeded.items() if value == "EOF\ntouch PWNED")
    result, _ = runner.run(f"sdump 0 <<EOF\n{marker}\nEOF")
    assert result.returncode == 125 and runner.receivers.got(0) is None and runner.receivers.side_effects() == []


def test_runner_without_a_ticket_leaves_markers_as_text(runner, seeded):
    marker = next(m for m, value in seeded.items() if value == "a b")
    result, _ = runner.run(f"dump 0 '{marker}'; (exit 3)", ticket=None)
    assert result.returncode == 3 and runner.receivers.got(0) == marker.encode() + b"\0"


def test_runner_rejects_a_ticket_for_another_command(runner, seeded):
    marker = next(m for m, value in seeded.items() if value == "a b")
    other = bashwrap.restore_ticket("echo something else", runner.settings.vault_dir)
    for ticket in (other, "0" * 64, "x"):
        result, _ = runner.run(f"dump 0 '{marker}'", ticket=ticket)
        assert result.returncode == 125 and runner.receivers.got(0) is None


def test_a_command_cannot_get_values_by_starting_the_runner_itself(runner, seeded):
    """The oracle the ticket closes: marker text built at run time, which the hook never saw."""
    marker = next(m for m, value in seeded.items() if value == "a b")
    launcher = runner.settings.launcher
    inner = f"dump 0 '{marker}'"
    half = len(marker) // 2
    command = (f"m='{marker[:half]}''{marker[half:]}'; sh {launcher} --data-dir {runner.settings.data_dir} "
               f"--vault-dir {runner.settings.vault_dir} run \"dump 0 '$m'\"")
    assert marker not in command
    result, _ = runner.run(command, ticket=None)
    assert runner.receivers.got(0) == marker.encode() + b"\0", result.stderr
    # ... and with a ticket for the outer command, the inner one still has none
    result, _ = runner.run(command)
    assert runner.receivers.got(0) == marker.encode() + b"\0"
    assert inner  # the inner command text was never signed


def test_restore_off_never_restores_even_with_a_ticket(runner, seeded):
    marker = next(m for m, value in seeded.items() if value == "a b")
    (runner.box.data / "config.json").write_text('{"restore_in_bash": "off", "vault_key": "file"}')
    result, _ = runner.run(f"dump 0 '{marker}'")
    assert result.returncode == 0 and runner.receivers.got(0) == marker.encode() + b"\0"


def test_unknown_markers_stay_as_text(runner, seeded):
    marker = next(m for m, value in seeded.items() if value == "a b")
    unknown = "[[ACCOUNT_NUMBER_ZZZZZZ]]"
    result, _ = runner.run(f"dump 0 '{unknown}' '{marker}'")
    assert result.returncode == 0 and runner.receivers.got(0) == unknown.encode() + b"\0a b\0"


def test_values_are_in_no_argument_list_or_environment_except_of_programs_the_command_starts(runner, seeded):
    """While the command runs, a process list must not show the value for the wrapper shell, the
    launcher, the relay, the monitor or the child shell. It does show it for a program the command
    itself starts with the value as an argument: that is unavoidable and documented."""
    if not os.path.isdir("/proc/self"):
        pytest.skip("needs /proc")
    import uuid
    value = "datafog-probe-" + uuid.uuid4().hex               # unique, so other processes on the machine cannot match
    marker = runner.box.seed(value)
    pattern = value[:-1] + "[" + value[-1] + "]"              # the probe's own arguments must not match
    out = runner.receivers.dumps / "ps"
    (runner.receivers.bin / "psprobe").write_text(
        "#!/bin/sh\nfor p in /proc/[0-9]*; do\n"
        f"  if tr '\\0' ' ' < $p/cmdline 2>/dev/null | grep -q '{pattern}'; then echo \"ARGV $(tr '\\0' ' ' < $p/cmdline)\"; fi\n"
        f"  if grep -qa '{pattern}' $p/environ 2>/dev/null; then echo \"ENV $(tr '\\0' ' ' < $p/cmdline)\"; fi\n"
        f"done > {out}\n")
    (runner.receivers.bin / "hold").write_text("#!/bin/sh\nsleep 2\n")
    for name in ("psprobe", "hold"):
        (runner.receivers.bin / name).chmod(0o755)
    result, _ = runner.run(f"X='{marker}'; dump 0 \"$X\"; psprobe")
    assert result.returncode == 0, result.stderr
    assert runner.receivers.got(0) == value.encode() + b"\0"        # the shell did hold the value
    assert out.read_text() == ""
    result, _ = runner.run(f"hold '{marker}' & sleep 0.5; psprobe; wait")
    lines = out.read_text().splitlines()
    assert lines and all(line.startswith("ARGV") and "/hold " in line for line in lines), lines


def test_exit_status_and_output_filter_still_apply_with_restored_values(runner, box):
    from conftest import EMAIL
    marker = box.seed(EMAIL, "EMAIL")
    (runner.receivers.cwd / "notes.txt").write_text(f"Contact: {EMAIL}\nother line\n")
    result, script = runner.run(f"grep -c {marker} notes.txt; grep {marker} notes.txt; (exit 9)")
    out = result.stdout.decode()
    assert result.returncode == 9 and out.startswith("1\n")
    assert EMAIL not in out and marker in out and EMAIL not in script and EMAIL not in result.stderr.decode()
    (runner.receivers.cwd / "notes.txt").unlink()


# -- structural fuzz: random command shapes around a marker -------------------------------------------
# The contexts above are the ones the lexer is meant to support. This asks the opposite question:
# is there ANY command shape the lexer accepts in which a value runs? Commands are random sequences of
# shell fragments with markers dropped in; whenever the lexer accepts one, it is run under the real
# shell with values built to execute `pwn` if they are ever parsed as code or used as a command name.
FRAGMENTS = [
    "echo", ":", "true", "printf '%s'", "printf", "printf --", "echo -n", "cd", "test", "[", "wait", "export", "x=", "X=1", "export Y=", "if", "then", "else", "fi", "for i in", "do", "done",
    "while", "!", "{", "}", "(", ")", ";", "&&", "||", "|", "&", "\n", " ", " ", " ", "'", '"', "\\", "$", "$(", "`",
    "${", "}", "$'", "$((", "))", "<<EOF", "<<'EOF'", "<<-EOF", "EOF", "<<<", ">", "<", ">>", "2>", "&>", ">&",
    "/dev/null", "#", "a", "b", "-n", "--", "=", "~", "*", "[", "]", "[[", "]]", "env", "nice", "nohup", "command",
    "exec", "builtin", "eval", "time", "sh -c", "source", ".", "trap", "noglob", "nocorrect", "-", "repeat 1", "coproc",
    "xargs", "cat", "test", "case", "in", "esac", "function f", "f()", "select", "until", "local", "readonly", "declare",
    "typeset", "let", "read", "set", "unset", "\t", "\\\n", "$x", "$@", "%", "^", ",", ":", "+=", "a=(", "<(", ">(",
    "=(", "|&", ";;", "&!", "&|", "$[", '$"', "{a,", "..", "@", "?(", "+(",
]
# A second vocabulary without the words that make the lexer refuse outright, so more commands are accepted.
PLAIN_FRAGMENTS = [fragment for fragment in FRAGMENTS if fragment not in {
    "eval", "sh -c", "source", ".", "trap", "xargs", "case", "esac", "function f", "f()", "select", "declare", "typeset",
    "let", "read", "unset", "$((", "))", "[[", "]]", "coproc", "repeat 1", "exec", "builtin", "command", "time", "$[",
    "a=(", "=(", "?(", "+(", "-", "noglob", "nocorrect", "set", "test", '$"', ";;", "local", "readonly", "until", "while",
    "env", "nice", "nohup", "cat"}]
# Two markers in one command get these in order: an option that takes a NAME, then a NAME that runs code.
CANARY_PAIRS = [("-v", "a[$(pwn)]"), ("-v", "x[`pwn`]"), ("-p", "a[$(pwn)]"), ("-a", "a[$(pwn)]"), ("--", "$(pwn)"),
                ("-n", "a[$(pwn)]"), ("-va[$(pwn)]", "x"), ("-f", "pwn"), ("-c", "pwn"), ("-e", "a[$(pwn)]")]
CANARIES = ["pwn", "$(pwn)", "a[$(pwn)]", "-va[$(pwn)]", "`pwn`", "'; pwn; '", "\"; pwn; \"", "\\'; pwn; \\'", "; pwn", "| pwn", "\npwn\n", "x\npwn",
            "&& pwn", "a[$(pwn)]", "\\\"; pwn; \\\"", "EOF\npwn", "$'\\x27'; pwn; '", "');pwn;('", "}; pwn; {", "*/../pwn"]


def structural_fuzz(tmp, shell: str, fragments: list[str], count: int, seed: int) -> tuple[int, list]:
    """Returns (commands the lexer accepted and that were run, [(command, value)] in which the value ran)."""
    rng = random.Random(seed)
    bin_dir, cwd, flag = tmp / "fuzzbin", tmp / "fuzzcwd", tmp / "PWNED"
    for folder in (bin_dir, cwd):
        folder.mkdir(exist_ok=True)
    (bin_dir / "pwn").write_text(f"#!/bin/sh\ntouch {flag}\n")
    (bin_dir / "pwn").chmod(0o755)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(cwd)}
    accepted, hits = 0, []
    for _ in range(count):
        parts = [rng.choice(fragments) for _ in range(rng.randint(1, 9))]
        for _ in range(rng.choice([1, 1, 1, 2])):
            parts.insert(rng.randint(0, len(parts)), M)
        command = "".join(part if rng.random() < 0.35 else part + " " for part in parts)
        trials: list = list(rng.sample(CANARIES, 3)) + [rng.choice(CANARY_PAIRS)]
        for value in trials:
            try:
                spans = spans_for(command, {M: value if isinstance(value, str) else "?"})
                if not isinstance(value, str):
                    for number, span in enumerate(spans):
                        span.value = value[number % 2]
                text = substitute(command, spans, kind_of(shell)).text
            except Refused:
                continue
            accepted += 1
            try:
                subprocess.run([shell, "-c", text], cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                               timeout=10)
            except subprocess.TimeoutExpired:
                pass
            if flag.exists():
                flag.unlink()
                hits.append((command, value))
    return accepted, hits


@pytest.mark.parametrize("shell", SHELLS + PLAIN_SH)
@pytest.mark.parametrize("vocabulary", ["all", "plain"])
def test_no_accepted_command_shape_lets_a_value_run(tmp_path, shell, vocabulary):
    fragments = FRAGMENTS if vocabulary == "all" else PLAIN_FRAGMENTS
    accepted, hits = structural_fuzz(tmp_path, shell, fragments, 2500, seed=len(shell) + len(vocabulary))
    assert not hits, hits[:5]
    assert accepted > 300, "the fuzz must actually run commands"


def test_the_structural_fuzz_would_notice_a_broken_lexer(tmp_path, monkeypatch):
    """The fuzz above proves something only if it fails for a lexer with a hole. Two holes are made here."""
    with monkeypatch.context() as patch:
        patch.setattr(shellsub, "_single", lambda value: value)             # quotes in a value are not escaped
        assert structural_fuzz(tmp_path, "bash", PLAIN_FRAGMENTS, 400, seed=5)[1]
    original = shellsub._Lexer.marker

    def marker(self, mode, word):                                           # a marker may be a command name
        if word is not None and word.kind == "command":
            word.kind = "arg"
        return original(self, mode, word)
    with monkeypatch.context() as patch:
        patch.setattr(shellsub._Lexer, "marker", marker)
        assert structural_fuzz(tmp_path, "bash", PLAIN_FRAGMENTS, 400, seed=5)[1]
    assert not structural_fuzz(tmp_path, "bash", PLAIN_FRAGMENTS, 400, seed=5)[1]
