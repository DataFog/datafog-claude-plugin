"""The late swap: real values are put into a Bash command inside the runner, as inert data.

Threat model (see engine/datafog_guard/shellsub.py): the model chooses the command and the
quoting around a marker; the value's owner chooses nothing; a value must never execute.

A command with a marker is restored only if the WHOLE command fits a small positive grammar
(plain.py, shellsub.py); everything else is refused. Three layers of proof, under real bash,
zsh and dash:
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
# The runner falls back to /bin/sh when neither bash nor zsh exists; the grammar is the same, and it is
# checked against dash where it is installed.
PLAIN_SH = [shell for shell in ("dash",) if shutil.which(shell)]


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


# name -> (command template, what the receiver must have got, a value starting with "-" is accepted)
# `dump ID args...` records its arguments, `sdump ID` its stdin. {dir} is the literal dump directory
# (the grammar has no variables).
CONTEXTS = {
    "unquoted": ("dump {id} {m}", argv("{v}"), False),
    "unquoted_after_dashes": ("dump {id} -- {m} {m}", argv("--", "{v}", "{v}"), True),
    "single": ("dump {id} '{m}'", argv("{v}"), False),
    "single_inside": ("dump {id} 'a {m} $b `c` \\d'", argv("a {v} $b `c` \\d"), True),
    "single_after_backslash": ("dump {id} 'a\\{m}'", argv("a\\{v}"), True),
    "double": ('dump {id} "{m}"', argv("{v}"), False),
    "double_inside": ('dump {id} "a {m} b"', argv("a {v} b"), True),
    "double_twice": ('dump {id} "x{m}|{m}"', argv("x{v}|{v}"), True),
    "option_single": ("dump {id} --to='{m}'", argv("--to={v}"), True),
    "option_double": ('dump {id} --to="{m}" -x', argv("--to={v}", "-x"), True),
    "quoted_parts_joined": ("dump {id} pre'{m}'\"{m}\"post", argv("pre{v}{v}post"), True),
    "several_arguments": ("dump {id} -- {m} '{m}' \"{m}\"", argv("--", "{v}", "{v}", "{v}"), True),
    "and_list": ("true && dump {id} -- {m}", argv("--", "{v}"), True),
    "or_list": ("rc 1 || dump {id} -- '{m}'", argv("--", "{v}"), True),
    "semicolon": ("true; dump {id} -- {m}; true", argv("--", "{v}"), True),
    "newline": ("true\ndump {id} -- {m}\n\ntrue", argv("--", "{v}"), True),
    "pipeline": ("printf '%s' -- {m} | sdump {id}", data("--{v}"), True),
    "pipeline_three": ("printf '%s' x '{m}' | cat | sdump {id}", data("x{v}"), False),
    "printf_after_format": ("printf '%s\\0' -- {m} > {dir}/{id}", argv("--", "{v}"), True),
    "printf_dashes_format": ("printf -- '%s|%s' x{m} \"y{m}\" > {dir}/{id}", None, True),
    "redirections": ("dump {id} -- {m} > /dev/null 2>&1 < /dev/null", argv("--", "{v}"), True),
    "echo": ("echo x -- {m} > /dev/null; dump {id} -- {m}", argv("--", "{v}"), True),
    "path_program": ("{bin}/dump {id} -- {m}", argv("--", "{v}"), True),
    "home_argument": ("dump {id} ~/x -- {m}", argv("{home}/x", "--", "{v}"), True),
}
del CONTEXTS["printf_dashes_format"]          # x{m} is a marker glued to unquoted text: refused (see REFUSED)

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
    # -- accepted before the positive grammar, refused now -------------------------------------------
    'formerly accepted: ansi_c': "dump {id} $'{m}'",
    'formerly accepted: ansi_c_inside': "dump {id} $'a\\t{m}\\tb'",
    'formerly accepted: assignment': 'x={m}; dump {id} "$x"',
    'formerly accepted: assignment_double': 'x="{m}"; dump {id} "$x"',
    'formerly accepted: assignment_prefix': 'X={m} edump {id}',
    'formerly accepted: backticks': 'x=`printf \'%s.\' {m}`; dump {id} "$x"',
    'formerly accepted: backticks_double': 'x=`printf \'%s.\' "{m}"`; dump {id} "$x"',
    'formerly accepted: backticks_single': 'x=`printf \'%s.\' \'{m}\'`; dump {id} "$x"',
    'formerly accepted: command_substitution': 'dump {id} "$(printf \'%s.\' {m})"',
    'formerly accepted: command_substitution_double': 'dump {id} "$(printf \'%s.\' "{m}")"',
    'formerly accepted: command_substitution_nested': 'dump {id} "$(printf \'%s.\' "$(printf \'%s.\' \'{m}\')")"',
    'formerly accepted: comment': 'dump {id} x # {m}',
    'formerly accepted: double_after_variable': 'dump {id} "$EMPTY{m}$EMPTY"',
    'formerly accepted: export': 'export X={m}; edump {id}',
    'formerly accepted: for': 'for i in {m}; do dump {id} "$i"; done',
    'formerly accepted: group': '{ dump {id} {m}; }',
    'formerly accepted: here_string': 'sdump {id} <<< {m}',
    'formerly accepted: here_string_double': 'sdump {id} <<< "{m}"',
    'formerly accepted: heredoc_double_quoted_delimiter': 'sdump {id} <<"E O F"\n{m} x\nE O F',
    'formerly accepted: heredoc_escaped_delimiter': 'sdump {id} <<\\EOF\n{m}\nEOF',
    'formerly accepted: heredoc_quoted': "sdump {id} <<'EOF'\n{m}\nEOF",
    'formerly accepted: heredoc_quoted_inside': "sdump {id} <<'EOF'\na {m} $b `c`\nEOF",
    'formerly accepted: heredoc_tabs': 'sdump {id} <<-EOF\n\tx{m}\n\tEOF',
    'formerly accepted: heredoc_unquoted': 'sdump {id} <<EOF\n{m}\nEOF',
    'formerly accepted: heredoc_unquoted_inside': 'sdump {id} <<EOF\na {m} $EMPTY b\nEOF',
    'formerly accepted: if': 'if true; then dump {id} {m}; fi',
    'formerly accepted: mixed_quotes': 'dump {id} x\'{m}\'"{m}"{m}',
    'formerly accepted: process_substitution': "cat <(printf '%s' {m}) | sdump {id}",
    'formerly accepted: subshell': '(dump {id} {m})',
    'formerly accepted: unquoted_glued': 'dump {id} a{m}b',
    # -- second review: a value placed safely in a variable and evaluated later -----------------------
    "review: RANDOM assignment": "RANDOM={m}",
    "review: OPTIND assignment": "OPTIND={m}",
    "review: HISTCMD assignment": "HISTCMD={m}",
    "review: SRANDOM assignment": "SRANDOM={m}",
    "review: RANDOM append": "RANDOM+={m}",
    "review: export RANDOM": "export RANDOM={m}",
    "review: readonly OPTIND": "readonly OPTIND={m}",
    "review: for RANDOM in": "for RANDOM in {m}; do :; done",
    "review: printf -v through a variable": 'x={m}; printf -v "$x" y',
    "review: printf -v in a loop": 'for x in {m}; do printf -v "$x" y; done',
    "review: printf with a glob as the option": "touch ./-v; printf ?v {m} x",
    "review: indirect expansion": "x={m}; echo ${!x}",
    "review: substring offset": "x={m}; echo ${y:x}",
    "review: substring length": "x={m}; echo ${y:0:x}",
    "review: positional slice": "x={m}; echo ${*:x}",
    "review: positional slice length": "x={m}; echo ${@:1:x}",
    "review: prompt expansion": "x={m}; echo ${x@P}",
    "review: wait -p": 'x={m}; wait -p "$x" -n',
    "review: test with an option from a variable": 'o=-v; y={m}; [ $o "$y" ]',
    "review: zsh export of a variable": 'x={m}; export "$x"',
    "review: zsh set -A": 'x={m}; set -A "$x" 1',
    # -- the grammar's edges ----------------------------------------------------------------------------
    "marker glued to unquoted text": "dump 0 x{m}",
    "marker glued to an option": "dump 0 --to={m}",
    "two markers glued": "dump 0 {m}{m}",
    "marker glued to a quoted part": "dump 0 {m}'x'",
    "any variable in the command": "grep {m} $HOME/f",
    "a variable in double quotes": 'grep {m} "$f"',
    "a glob elsewhere in the command": "grep {m} *.txt",
    "a brace expansion elsewhere": "grep {m} {a,b}.txt",
    "another user's home": "grep {m} ~root/f",
    "a backslash elsewhere": "grep {m} a\\ b",
    "a line continuation": "grep {m} \\\nf",
    "a background job": "grep {m} f &",
    "stderr pipe": "grep {m} f |& cat",
    "a comment": "grep {m} f # note",
    "an assignment before the command": "LC_ALL=C grep {m} f",
    "a standalone assignment elsewhere": "x=1; grep {m} f",
    "a quoted command name": "'grep' {m} f",
    "a keyword elsewhere": "if true; then grep {m} f; fi",
    "a builtin elsewhere": "set -e; grep {m} f",
    "cd elsewhere": "cd sub; grep {m} f",
    "test": "test -n {m}",
    "kill": "kill {m}",
    "exec as an argument": "nice exec {m}",
    "printf without a format": "printf {m}",
    "printf format from a marker after --": "printf -- {m} x",
    "marker in a redirection": "grep x f > '{m}'",
    "a here-string": "grep x <<< {m}",
    "clobber redirection": "grep {m} f >| out",
    "a carriage return": "grep {m} f\r",
    "zsh equals expansion elsewhere": "grep {m} =ls",
}


def render(template: str, marker: str, ident: str = "0", receivers=None) -> str:
    places = {"{dir}": str(receivers.dumps) if receivers else "/tmp/dumps",
              "{bin}": str(receivers.bin) if receivers else "/tmp/bin"}
    for name, value in places.items():
        template = template.replace(name, value)
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
    """The one value-dependent refusal left: a value that would start an argument with "-" where no
    literal `--` stands before it."""
    return value.startswith("-") and not CONTEXTS[name][2]


class Bin:
    """The receiving programs: they record exactly what they were given, as bytes."""

    def __init__(self, tmp):
        self.bin, self.dumps, self.cwd = tmp / "bin", tmp / "dumps", tmp / "cwd"
        for folder in (self.bin, self.dumps, self.cwd):
            folder.mkdir()
        scripts = {
            "dump": '#!/bin/sh\nid=$1; shift\nfor a in "$@"; do printf \'%s\\0\' "$a"; done > "$DUMP_DIR/$id"\n',
            "sdump": '#!/bin/sh\ncat > "$DUMP_DIR/$1"\n',
            "rc": '#!/bin/sh\nexit "$1"\n',
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

    def want(self, expect, value: str) -> bytes:
        return expect(value).replace(b"{home}", str(self.cwd).encode())

    def side_effects(self) -> list[str]:
        return sorted(os.listdir(self.cwd))

    def reset(self) -> None:
        for path in self.dumps.iterdir():
            path.unlink()


@pytest.fixture
def receivers(tmp_path) -> Bin:
    return Bin(tmp_path)


# -- the grammar on its own ----------------------------------------------------------------------
def test_each_place_is_written_in_its_own_encoding():
    value = "a'b\"c$d`e\\f"
    assert sub("x {m}", value) == "x 'a'\\''b\"c$d`e\\f'"
    assert sub("x '{m}'", value) == "x 'a'\\''b\"c$d`e\\f'"
    assert sub('x "p{m}q"', value) == "x \"p\"'a'\\''b\"c$d`e\\f'\"q\""
    assert sub("x --to='{m}' | y \"{m}\" > out 2>&1", "v") == "x --to='v' | y \"\"'v'\"\" > out 2>&1"


def test_result_counts_and_untouched_text():
    command = f"grep -c {M} notes.txt"
    result = substitute(command, spans_for(command, {M: "v"}))
    assert (result.text, result.restored) == ("grep -c 'v' notes.txt", 1)
    plain_text = "echo [[NOT_A_MARKER]] 'x' \"$y\" $(z) | cat"
    assert substitute(plain_text, []).text == plain_text, "a command without known markers is never touched"


@pytest.mark.parametrize("name", sorted(REFUSED))
@pytest.mark.parametrize("shell", ["bash", "zsh", "sh"])
def test_everything_outside_the_grammar_is_refused(name, shell):
    for value in ("plain", "$(touch PWNED)", "'; touch PWNED; '", "a[$(touch PWNED)]"):
        with pytest.raises(Refused) as info:
            sub(REFUSED[name], value, shell)
        assert "PWNED" not in info.value.text and "plain" not in info.value.code and M not in info.value.text


def test_refusal_reasons_never_hold_command_or_value_text():
    for template in REFUSED.values():
        try:
            sub(template, "SECRETVALUE")
        except Refused as refusal:
            assert "SECRET" not in refusal.text + refusal.code and "{m}" not in refusal.text


def test_a_value_that_starts_with_a_dash_needs_a_literal_double_dash():
    for value in ("-v", "-rf", "--help", "-", "--"):
        for template in ("grep {m} f", "grep '{m}' f", 'grep "{m}" f', "grep -e {m} f", "grep f; grep -- x; grep {m}",
                         "printf '%s' {m}"):
            with pytest.raises(Refused) as info:
                sub(template, value)
            assert info.value.code == "option"
        for template in ("grep -- {m} f", "grep -e x -- '{m}' \"{m}\"", "grep 'x{m}' f", 'grep "--to={m}" f',
                         "grep --to='{m}' f", "printf '%s' -- {m}"):
            assert value in sub(template, value)
    # the -- must be a literal word of the same command, before the marker, and not itself a value
    for template in ("grep '--' {m}", "grep {m} --", "grep -- x | grep {m}", "grep {m2} {m}"):
        command = render(template, M).replace("{m2}", "[[ACCOUNT_NUMBER_000001]]")
        spans = spans_for(command, {M: "-v", "[[ACCOUNT_NUMBER_000001]]": "--"})
        with pytest.raises(Refused):
            substitute(command, spans)


def test_nul_is_refused_everywhere():
    for template, _, _ in CONTEXTS.values():
        with pytest.raises(Refused):
            sub(template, "a\0b")


def test_every_builtin_and_reserved_word_of_the_installed_shells_is_known():
    """A builtin plain.py does not know would count as an external program, whose arguments may take
    values. A new shell version that adds one must fail here."""
    from datafog_guard import plain
    listed = set()
    if shutil.which("bash"):
        listed |= set(subprocess.run(["bash", "-c", "compgen -b; compgen -k"], capture_output=True,
                                     text=True).stdout.split())
    if shutil.which("zsh"):
        listed |= set(subprocess.run(
            ["zsh", "-fc", "zmodload zsh/parameter; print -l ${(k)builtins} ${(k)reswords} ${(k)dis_builtins}"],
            capture_output=True, text=True).stdout.split())
    if shutil.which("dash"):
        listed |= {name for name in plain.BUILTINS | plain.KEYWORDS if subprocess.run(
            ["dash", "-c", 'case $(type "$1" 2>/dev/null) in *builtin*|*keyword*|*reserved*) exit 0;; esac; exit 1',
             "_", name], capture_output=True).returncode == 0}
    assert len(listed) > 100, "no shell to ask"
    assert not listed - plain.SHELL_WORDS, sorted(listed - plain.SHELL_WORDS)
    assert shellsub.ALLOWED_BUILTINS <= plain.BUILTINS


# -- every nasty value in every context, run by the real shells -----------------------------------
def run_shell(receivers: Bin, shell: str, script: str, timeout: int = 120):
    return subprocess.run([shell, "-c", script], capture_output=True, cwd=receivers.cwd, env=receivers.env(shell),
                          stdin=subprocess.DEVNULL, timeout=timeout)


@pytest.mark.parametrize("shell", SHELLS + PLAIN_SH)
@pytest.mark.parametrize("name", sorted(CONTEXTS))
def test_nasty_values_arrive_exactly_and_never_run(receivers, shell, name):
    template, expect, _ = CONTEXTS[name]
    ran = refused = 0
    for number, value in enumerate(ALL_VALUES):
        command = render(template, M, str(number), receivers)
        try:
            text = substitute(command, spans_for(command, {M: value}), kind_of(shell)).text
        except Refused:
            assert expected_refusal(name, value), f"{name}: unexpected refusal of value #{number}"
            refused += 1
            continue
        assert not expected_refusal(name, value), f"{name}: value #{number} should have been refused"
        result = run_shell(receivers, shell, text + "\nrc 37")
        assert result.returncode == 37, (name, number, result.stderr[-300:])
        assert receivers.got(number) == receivers.want(expect, value), (name, number, repr(value)[:60])
        assert receivers.side_effects() == [], (name, number, repr(value)[:60])
        ran += 1
    assert ran >= len(ALL_VALUES) - 20 and ran + refused == len(ALL_VALUES)


ALPHABET = list("'\"\\$`;|&()<>{}[]*?!~#= \t\n-%^,.:/@") + ["a", "b", "EOF", "PWNED", "touch PWNED", "$(", "${", "é", "日"]


@pytest.mark.parametrize("shell", SHELLS + PLAIN_SH)
def test_random_values_in_every_context(receivers, shell):
    """Fuzz: 300 random values over a hostile alphabet, in every context, one shell run per context."""
    rng = random.Random(20261117)
    values = ["".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 14))) for _ in range(300)]
    checked = 0
    for name, (template, expect, _) in sorted(CONTEXTS.items()):
        receivers.reset()
        lines, wanted = [], {}
        for number, value in enumerate(values):
            command = render(template, M, str(number), receivers)
            try:
                lines.append(substitute(command, spans_for(command, {M: value}), kind_of(shell)).text)
            except Refused:
                assert expected_refusal(name, value), (name, repr(value))
                continue
            assert not expected_refusal(name, value), (name, repr(value))
            wanted[number] = receivers.want(expect, value)
        result = run_shell(receivers, shell, "\n".join(lines) + "\nrc 37")
        assert result.returncode == 37, (name, result.stderr[-300:])
        for number, want in wanted.items():
            assert receivers.got(number) == want, (name, repr(values[number]))
        assert receivers.side_effects() == [], name
        checked += len(wanted)
    assert checked > 280 * len(CONTEXTS)


@pytest.mark.parametrize("shell", SHELLS)
def test_several_markers_and_values_in_one_command(receivers, shell):
    values = {f"[[ACCOUNT_NUMBER_00000{n}]]": value for n, value in
              enumerate(["$(touch PWNED)", "'; touch PWNED; '", "a b", "\\", "`touch PWNED`", "-v", "a[$(touch PWNED)]"])}
    markers = list(values)
    command = (f"dump 0 -- {markers[0]} '{markers[1]}' \"{markers[2]}{markers[3]}\" {markers[5]} {markers[6]} && "
               f"printf '%s|%s' -- {markers[4]} | sdump 1\nrc 5")
    text = substitute(command, spans_for(command, values), shell).text
    result = run_shell(receivers, shell, text)
    got = list(values.values())
    assert result.returncode == 5
    assert receivers.got(0) == b"".join(part.encode() + b"\0" for part in
                                        ("--", got[0], got[1], got[2] + got[3], got[5], got[6]))
    assert receivers.got(1) == f"--|{got[4]}".encode()
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

    The vault stores what it gives back on restore: core refuses a value that is only whitespace
    and normalises a tab or carriage return inside a value to a blank. The runner is checked
    against the value the vault returns."""
    from datafog_guard.errors import GuardError
    vault = box.open_vault()
    stored = {}
    for value in NASTY + MULTILINE:
        if not value:
            continue
        try:
            marker = vault._commit([("ACCOUNT_NUMBER", value)])[value]
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
            lines.append(render(template, marker, str(number), runner.receivers))
            wanted[number] = runner.receivers.want(expect, value)
        command = "\n".join(lines) + "\nrc 37"
        result, script = runner.run(command)
        assert result.returncode == 37, (name, result.stderr[-400:])
        for number, want in wanted.items():
            assert runner.receivers.got(number) == want, (name, number)
        assert runner.receivers.side_effects() == [], name
        for value in ("touch PWNED", "日本語", "héllo"):
            assert value not in script                       # what Claude Code is given holds markers only
        total += len(wanted)
    assert total > (len(seeded) - 20) * len(CONTEXTS)
    log = runner.box.visible_files()
    assert "PWNED" not in log and "日本語" not in log and '"restored"' in log


REVIEW_CASES = sorted(name for name in REFUSED if name.startswith(("review:", "printf", "formerly accepted")))


@pytest.mark.parametrize("name", REVIEW_CASES + ["command name", "eval", "sh -c", "output redirection target", "xargs",
                                                 "awk program", "parameter expansion", "after a backslash", "ssh",
                                                 "piped into a shell", "any variable in the command", "cd"])
def test_runner_refuses_everything_outside_the_grammar_and_runs_nothing(runner, box, name):
    """Every case from the reviews, through the real path, with the value that ran in the review."""
    marker = box.seed("a[$(touch PWNED)]")
    command = "touch RAN\n" + render(REFUSED[name], marker)
    result, _ = runner.run(command)
    assert result.returncode == 125, (name, result.stderr[-300:])
    assert b"could not be replaced by their values safely" in result.stderr and b"the command was not run" in result.stderr
    assert b"PWNED" not in result.stderr and marker.encode() not in result.stderr
    assert runner.receivers.side_effects() == []             # not even the harmless first line ran


def test_printf_never_takes_an_option_or_a_variable_name_from_a_value(runner, receivers):
    """First review: `printf [[M0]] [[M1]] hi` with the values `-v` and `a[$(cmd)]` ran cmd, because bash
    evaluates the NAME given to -v. printf takes markers only after a literal format, and a value that
    starts with "-" only after a literal `--`."""
    option, name = runner.box.seed("-v"), runner.box.seed("a[$(touch PWNED)]")
    for command in (f"printf {option} {name} hi", f"printf '{option}' \"{name}\" hi", f"printf -- {option} {name}",
                    f"printf '%s' {option} {name}", f"printf -v {name} x", f"true; printf {option} {name} hi"):
        with pytest.raises(Refused):
            substitute(command, spans_for(command, {option: "-v", name: "a[$(touch PWNED)]"}), runner.shell)
        result, _ = runner.run(command)
        assert result.returncode == 125 and receivers.side_effects() == [], command
    result, _ = runner.run(f"printf '%s %s %s' -- {option} {name} > {receivers.dumps}/1")
    assert result.returncode == 0 and receivers.got(1) == b"-- -v a[$(touch PWNED)]"
    assert receivers.side_effects() == []


def test_runner_without_a_ticket_leaves_markers_as_text(runner, seeded):
    marker = next(m for m, value in seeded.items() if value == "a b")
    result, _ = runner.run(f"dump 0 '{marker}'; rc 3", ticket=None)
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
    half = len(marker) // 2
    command = (f"m='{marker[:half]}''{marker[half:]}'; sh {launcher} --data-dir {runner.settings.data_dir} "
               f"--vault-dir {runner.settings.vault_dir} run \"dump 0 '$m'\"")
    assert marker not in command
    result, _ = runner.run(command, ticket=None)
    assert runner.receivers.got(0) == marker.encode() + b"\0", result.stderr
    # ... and with a ticket for the outer command, the inner one still has none
    result, _ = runner.run(command)
    assert runner.receivers.got(0) == marker.encode() + b"\0"


def test_restore_off_never_restores_even_with_a_ticket(runner, seeded):
    marker = next(m for m, value in seeded.items() if value == "a b")
    (runner.box.data / "config.json").write_text('{"restore_in_bash": "off"}')
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
    pattern = value[:-1] + "[" + value[-1] + "]"              # the probe's own grep must not match itself
    out = runner.receivers.dumps / "ps"
    (runner.receivers.bin / "psprobe").write_text(
        "#!/bin/sh\nfor p in /proc/[0-9]*; do\n"
        f"  if tr '\\0' ' ' < $p/cmdline 2>/dev/null | grep -q '{pattern}'; then echo \"ARGV $(tr '\\0' ' ' < $p/cmdline)\"; fi\n"
        f"  if grep -qa '{pattern}' $p/environ 2>/dev/null; then echo \"ENV $(tr '\\0' ' ' < $p/cmdline)\"; fi\n"
        f"done > {out}\n")
    (runner.receivers.bin / "psprobe").chmod(0o755)
    result, _ = runner.run(f"psprobe '{marker}'")
    assert result.returncode == 0, result.stderr
    lines = out.read_text().splitlines()
    # only the program that was given the value shows it: /bin/sh .../psprobe VALUE
    assert lines and all(line.startswith("ARGV") and "/psprobe " in line for line in lines), lines


def test_exit_status_and_output_filter_still_apply_with_restored_values(runner, box):
    from conftest import EMAIL
    marker = box.seed(EMAIL, "EMAIL")
    (runner.receivers.cwd / "notes.txt").write_text(f"Contact: {EMAIL}\nother line\n")
    result, script = runner.run(f"grep -c {marker} notes.txt; grep {marker} notes.txt; rc 9")
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
# A second vocabulary made of what the grammar accepts, plus the programs it must refuse, so that many
# commands ARE accepted and run: this is the one that tests the grammar rather than the refusals.
PLAIN_FRAGMENTS = (
    ["echo", "printf '%s'", "printf", "printf --", "true", ":", "cat", "grep", "ls", "./x", "/bin/echo", "tee"] * 2
    + ["env", "sh -c", "eval", "xargs", "test", "cd", "nice", "exec", "command", "time", "sudo", "awk", "find . -exec",
       "export", "read", "wait", "set", "x=", "X=1"]
    + [" ", " ", " ", " ", "|", "&&", "||", ";", "\n", "> /dev/null", "2>&1", "< /dev/null", ">> /dev/null"]
    + ["--", "--", "-n", "-e", "-v", "a", "b", "'c d'", '"e f"', "--to=", "'", '"', "~/x", "=", "x'", '"y']
)
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
    assert accepted > (300 if vocabulary == "plain" else 20), "the fuzz must actually run commands"


def test_the_structural_fuzz_would_notice_a_broken_grammar(tmp_path, monkeypatch):
    """The fuzz above proves something only if it fails for a grammar with a hole. Three holes are made."""
    with monkeypatch.context() as patch:
        patch.setattr(shellsub, "_single", lambda value: value)             # quotes in a value are not escaped
        assert structural_fuzz(tmp_path, "bash", PLAIN_FRAGMENTS, 600, seed=5)[1]
    with monkeypatch.context() as patch:
        patch.setattr(shellsub, "_check_names", lambda parsed: None)        # any program or builtin may take a value
        assert structural_fuzz(tmp_path, "bash", PLAIN_FRAGMENTS, 600, seed=5)[1]
    from datafog_guard import plain
    with monkeypatch.context() as patch:                                    # $ and backticks are let through
        patch.setattr(plain, "_BARE", plain._BARE | frozenset("$`()"))
        assert structural_fuzz(tmp_path, "bash", PLAIN_FRAGMENTS + ["$(", ")", "`", "$(", ")", "`"] * 4, 1500, seed=5)[1]
    assert not structural_fuzz(tmp_path, "bash", PLAIN_FRAGMENTS, 600, seed=5)[1]
