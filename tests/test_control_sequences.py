"""Values split or disguised by terminal control sequences must still be replaced.

`grep --color=always 45 file` prints an SSN as 123-<ESC>[01;31m45<ESC>[m-6789. A detector that
looks at the raw bytes sees no SSN. Detection therefore also runs on a view of the text with
control sequences removed, and on a view rendered the way a terminal would show it; a finding
is mapped back to the original bytes and the whole original span is replaced.
"""
from __future__ import annotations

import json
import shutil

import pytest
import shapes_recorded as recorded
from conftest import CARD, EMAIL, PHONE, SSN
from test_bash_boundary import SHELLS, Hooked

ESC = "\x1b"
RED, RESET = f"{ESC}[01;31m", f"{ESC}[m"


def split(value: str, at: int, left: str = RED, right: str = RESET, width: int = 2) -> str:
    return value[:at] + left + value[at:at + width] + right + value[at + width:]


DISGUISES = {
    "sgr_colour": split(SSN, 4),
    "sgr_colour_email": split(EMAIL, 3, width=5),
    "erase_line_k": SSN[:4] + f"{ESC}[K" + SSN[4:],
    "osc_hyperlink": f"{ESC}]8;;https://example.org{ESC}\\" + EMAIL[:6] + f"{ESC}]8;;\x07" + EMAIL[6:],
    "two_char_escape": SSN[:3] + f"{ESC}(B" + SSN[3:],
    "c0_bell": CARD[:5] + "\x07" + CARD[5:],
    "nul_byte": SSN[:6] + "\x00" + SSN[6:],
    "delete_char": SSN[:6] + "\x7f" + SSN[6:],
    "backspace_bold": "".join(f"{c}\b{c}" for c in SSN),
    "backspace_underline": "".join(f"_\b{c}" for c in EMAIL),
    "backspace_correction": SSN[:5] + "X\b" + SSN[5:],
    "carriage_return_join": EMAIL[:8] + "\r" + EMAIL[8:],
    "carriage_return_overwrite": "XXXXXXXXXXX\r" + SSN,
    "carriage_return_partial": SSN[:4] + "00" + SSN[6:] + "\r" + SSN[:6],
    "zero_width_space": EMAIL[:4] + "​" + EMAIL[4:],
    "zero_width_joiner": SSN[:3] + "‍" + SSN[3:],
    "word_joiner": CARD[:9] + "⁠" + CARD[9:],
    "bom_inside": EMAIL[:10] + "﻿" + EMAIL[10:],
    "bidi_override": "‮" + EMAIL[:5] + "‬" + EMAIL[5:],
    "bidi_isolate": EMAIL[:5] + "⁦⁩" + EMAIL[5:],
    "soft_hyphen": EMAIL[:7] + "­" + EMAIL[7:],
    "many_colours": "".join(f"{ESC}[3{i % 8}m{c}" for i, c in enumerate(PHONE)) + RESET,
}
PLAIN = (SSN, EMAIL, CARD, PHONE)


def clean_of_values(text: str) -> bool:
    """No value is present, even after stripping everything a terminal would not show."""
    import re
    stripped = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[ -/]*[0-~]", "", text)
    stripped = re.sub(r"[\x00-\x08\x0b-\x1f\x7f­​-‏‪-‮⁠-⁩﻿]", "", stripped)
    return not any(value in text or value in stripped for value in PLAIN)


@pytest.mark.parametrize("name", sorted(DISGUISES))
def test_tokenize_replaces_a_disguised_value_and_restores_the_original_bytes(box, name):
    vault = box.open_vault()
    text = f"before\nvalue {DISGUISES[name]} after\nnext line\n"
    if name.startswith("carriage_return"):      # a carriage return rewrites the line from its first column
        text = f"before\n{DISGUISES[name]}\nnext line\n"
    out, counts = vault.tokenize(text)
    assert sum(counts.values()) >= 1, "nothing was detected"
    assert clean_of_values(out), repr(out)
    assert out.startswith("before\n") and out.endswith("next line\n")
    assert vault.restore(out).text == text, "write-back restores exactly what was there, sequences included"


@pytest.mark.parametrize("name", sorted(DISGUISES))
def test_post_tool_use_replaces_a_disguised_value(box, name):
    out, _ = box.post("Bash", {"command": "x"}, recorded.bash(stdout=f"row\n{DISGUISES[name]}\nend\n"))
    assert out is not None, "the output was passed through unchanged"
    assert clean_of_values(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"])


@pytest.mark.parametrize("name", ["sgr_colour", "backspace_bold", "zero_width_space", "carriage_return_overwrite"])
def test_read_shadow_copy_replaces_a_disguised_value(box, name):
    path = box.write("captured.log", f"log start\n{DISGUISES[name]}\nlog end\n")
    out, _ = box.pre("Read", {"file_path": str(path)})
    assert out is not None, "the file was treated as clean"
    assert clean_of_values(open(out["hookSpecificOutput"]["updatedInput"]["file_path"], encoding="utf-8").read())


def test_prompt_with_a_zero_width_split_value_is_blocked(box):
    out, _ = box.prompt(f"mail {DISGUISES['zero_width_space']} please")
    assert out and out["decision"] == "block" and clean_of_values(json.dumps(out, ensure_ascii=False))


def test_plain_text_with_ordinary_whitespace_is_untouched(box):
    text = "tab\there\r\nwindows line\r\nplain \x1b[32mgreen\x1b[0m word\n"
    out, counts = box.open_vault().tokenize(text)
    assert out == text and not counts


def test_colour_codes_next_to_a_value_are_kept(box):
    vault = box.open_vault()
    text = f"{RED}{EMAIL}{RESET} ok\n"
    out, _ = vault.tokenize(text)
    assert out.startswith(RED + "[[EMAIL_") and out.endswith(f"]]{RESET} ok\n")


# -- through the real hook and wrapper, under real shells ---------------------------------
@pytest.fixture(params=SHELLS)
def hooked(box, request) -> Hooked:
    return Hooked(box, request.param)


@pytest.mark.skipif(not shutil.which("grep"), reason="needs grep")
def test_grep_colour_always_review_reproduction(hooked):
    hooked.box.write("secrets.txt", f"ssn {SSN}\nmail {EMAIL}\ncard {CARD}\n")
    for command in ("grep --color=always '05' secrets.txt", "grep --color=always synthetic secrets.txt",
                    "grep --color=always -n 4242 secrets.txt"):
        result = hooked.run(command)
        out = result.stdout.decode()
        assert result.returncode == 0 and "[[" in out, (command, out)
        assert clean_of_values(out), (command, out)


def test_stream_with_values_written_in_coloured_pieces(hooked):
    pieces = split(SSN, 4)
    command = (f"printf '%s' '{pieces[:9]}'; sleep 0.2; printf '%s\\n' '{pieces[9:]}'; "
               f"printf 'a\\rb {DISGUISES['zero_width_space']}\\n'; printf '%s\\n' \"$(printf '{EMAIL[:5]}\\b\\b')\"")
    result = hooked.run(command)
    assert clean_of_values(result.stdout.decode()), result.stdout


def test_progress_output_with_carriage_returns_is_delivered(hooked):
    result = hooked.run("printf '10%%\\r50%%\\r100%%\\n'; echo done")
    assert result.stdout == b"10%\r50%\r100%\ndone\n"
