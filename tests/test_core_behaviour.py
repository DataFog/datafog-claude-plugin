"""What datafog-core 1.7 finds, seen through the plugin's tokenize path.

Core 1.5 to 1.7 changed where an e-mail address and a phone number begin and end. These tests
pin the differences from 1.4.0 that matter to the plugin: the ones where less text is replaced
(good: the marker stands for the address only) and the ones where a value that 1.4.0 hid is now
left visible to the model (documented in the README under "Known gaps").

Tests named ``..._today`` describe a known limit of core 1.7.0 exactly as it is; they only run
on that version, so an upgrade does not fail on them. Each has a sibling marked ``xfail`` that
states the correct outcome and starts passing when core fixes it.
"""
from __future__ import annotations

from importlib.metadata import version

import pytest
from conftest import EMAIL
from datafog_guard.vault import MARKER_RE

CORE_VERSION = version("datafog-core")
only_core_1_7_0 = pytest.mark.skipif(CORE_VERSION != "1.7.0",
                                     reason="pins the behaviour of datafog-core 1.7.0 exactly")


def tokenize(box, text: str) -> tuple[str, list[str]]:
    """(tokenized text, the real values the markers stand for, in order)."""
    vault = box.open_vault()
    out, _ = vault.tokenize(text)
    assert vault.restore(out).text == text, "whatever was replaced must restore exactly"
    spans, unknown = vault.restore_spans(out)
    assert unknown == 0
    return out, [value for _, _, _, value in spans]


# -- (a) text joined in front of an address is no longer part of the match -------------------
@pytest.mark.parametrize("text, before, after", [
    (f"user=ada&email={EMAIL}", "user=ada&email=", ""),
    (f"1042|Ada Synthetic|{EMAIL}|active", "1042|Ada Synthetic|", "|active"),
    (f"GET /lookup?user=ada&contact={EMAIL}&page=2 HTTP/1.1", "GET /lookup?user=ada&contact=", "&page=2 HTTP/1.1"),
    (f"a={EMAIL}&b=1", "a=", "&b=1"),
    (f"*{EMAIL}*", "*", "*"),
    (f"10.0.0.7:{EMAIL}", "10.0.0.7:", ""),
    (f"2026-11-17,{EMAIL}", "2026-11-17,", ""),
    (f"see [1].{EMAIL}", "see [1].", ""),
])
def test_only_the_address_is_replaced_after_a_separator_or_label(box, text, before, after):
    out, values = tokenize(box, text)
    assert values == [EMAIL]
    assert out.startswith(before) and out.endswith(after)
    assert MARKER_RE.fullmatch(out[len(before):len(out) - len(after)])


def test_a_phone_in_front_of_an_address_is_its_own_value(box):
    out, values = tokenize(box, f"415-555-0134,{EMAIL}")
    assert values == ["415-555-0134", EMAIL]
    assert out.count("[[PHONE_") == 1 and out.count("[[EMAIL_") == 1


@pytest.mark.parametrize("prefix", ["12345", "415-555-0134", "10.0.0.7", "2026-11-17"])
def test_digits_written_directly_onto_an_address_stay_hidden_with_it(box, prefix):
    """No separator at all: core reads the digits as part of the local part. Nothing is visible."""
    out, values = tokenize(box, f"{prefix}{EMAIL}")
    assert EMAIL not in out and "example.com" not in out and "ada.synthetic" not in out
    assert len(values) == 1 and values[0].endswith(EMAIL)


# -- (b) known issue: https://github.com/DataFog/datafog-core/issues/272 ----------------------
ISSUE_272 = "alice@example.comとbob@example.net"


@only_core_1_7_0
def test_issue_272_a_non_ascii_letter_between_two_addresses_leaves_a_domain_visible_today(box):
    """KNOWN ISSUE (core #272), accepted by the owner and documented in the README.

    A non-ASCII letter that touches an address is absorbed into the match. Between two addresses
    this gives ONE value, ``alice@example.comとbob``, and the second address's domain,
    ``@example.net``, reaches the model.
    """
    out, values = tokenize(box, ISSUE_272)
    assert values == ["alice@example.comとbob"]
    assert MARKER_RE.fullmatch(out[:-len("@example.net")]) and out.endswith("@example.net")


@pytest.mark.xfail(strict=False, reason="datafog-core #272: fixed in core after 1.7.0")
def test_issue_272_both_addresses_are_hidden(box):
    out, values = tokenize(box, ISSUE_272)
    assert "example.net" not in out and "example.com" not in out and "bob" not in out
    assert len(values) == 2


@only_core_1_7_0
@pytest.mark.parametrize("text, value", [
    (f"連絡先{EMAIL}", f"連絡先{EMAIL}"),
    (f"{EMAIL}に送信", f"{EMAIL}に送信"),
    (f"é{EMAIL}", f"é{EMAIL}"),
])
def test_issue_272_a_single_address_stays_hidden_but_takes_the_neighbouring_letters_today(box, text, value):
    """Same cause, no leak: the marker covers the address and the non-ASCII letters touching it."""
    out, values = tokenize(box, text)
    assert values == [value] and MARKER_RE.fullmatch(out)


@pytest.mark.parametrize("text", [f"連絡先 {EMAIL} に送信", f"{EMAIL}。bob.synthetic@example.net",
                                  f"{EMAIL}　bob.synthetic@example.net", f"メール：{EMAIL}"])
def test_addresses_separated_from_other_scripts_by_space_or_punctuation_are_found(box, text):
    out, values = tokenize(box, text)
    assert "example" not in out and values[0] == EMAIL


# -- phone numbers 1.4.0 found and 1.7 does not (documented limits) ---------------------------
@only_core_1_7_0
@pytest.mark.parametrize("text", [
    "2.415.555.0134",            # a dotted number directly after "<digit>." reads as a decimal
    "ver 10.415.555.0134",
    "2,415.5550134",             # after "<digit>," an unsigned number with exactly one dot
    "(415)\n555-0134",           # a number wrapped across a line break
    "415 555\n0134",
])
def test_phone_shapes_core_1_7_does_not_report_today(box, text):
    """Documented limit: core 1.7 does not report these, core 1.4.0 did. The text passes unchanged."""
    out, values = tokenize(box, text)
    assert out == text and values == []


@only_core_1_7_0
def test_a_plus_number_wrapped_across_a_line_is_hidden_up_to_the_break_today(box):
    out, values = tokenize(box, "+44 20 7946\n0958")
    assert values == ["+44 20 7946"] and out.endswith("\n0958")


@pytest.mark.parametrize("text, value", [
    ("3.415-555-0134", "415-555-0134"),
    ("row 2,415-555-0134,ok", "415-555-0134"),
    ("1,+1.4155550134", "+1.4155550134"),
])
def test_phone_shapes_next_to_a_number_that_are_reported(box, text, value):
    _, values = tokenize(box, text)
    assert values == [value]
