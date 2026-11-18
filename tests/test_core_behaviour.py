"""What datafog-core 1.7 finds, seen through the plugin's tokenize path.

Core 1.5 to 1.7 changed where an e-mail address and a phone number begin and end. These tests
pin the differences from 1.4.0 that matter to the plugin: the ones where less text is replaced
(good: the marker stands for the address only) and the ones where a value that 1.4.0 hid is now
left visible to the model (documented in the README under "Known gaps").

Tests named ``..._today`` describe a known limit of core 1.7.0 exactly as it is; they only run
on that version, so an upgrade does not fail on them. The adjacent-email leak is mitigated
by covering the joined addresses as one reversible value until core fixes their boundaries.
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


def test_issue_272_both_addresses_are_hidden(box):
    out, values = tokenize(box, ISSUE_272)
    assert "example.net" not in out and "example.com" not in out and "bob" not in out
    assert values and MARKER_RE.fullmatch(out)


@pytest.mark.parametrize("text", [
    "alice@example.comとbob@example.netとcarol@example.org",
    "alice@example.comßbob@example.net",
    "alice@example.com\u0301bob@example.net",
    "alice@example.com和bob@bücher.example",
    "連絡先はalice@example.comまたはbob@example.netです",
])
def test_joined_email_tail_is_hidden_and_restores_exactly(box, text):
    out, values = tokenize(box, text)
    assert "@" not in out and "example" not in out and "bücher" not in out
    assert values


def test_email_tail_mitigation_preserves_non_email_suffix(box):
    text = "alice@example.comとbob@example.net, next @notadomain"
    out, values = tokenize(box, text)
    assert out.endswith(", next @notadomain") and "example" not in out
    assert values


def test_email_tail_mitigation_respects_configuration_and_allowlist():
    from datafog_guard.vault import Detector
    assert Detector(("PHONE",)).spans(ISSUE_272) == []
    assert Detector(("EMAIL",), (ISSUE_272,)).spans(ISSUE_272) == []


def test_email_tail_mitigation_holds_the_whole_value_at_a_stream_cut(box):
    vault = box.open_vault()
    cut = len("alice@example.comとbob".encode())
    out, consumed, _ = vault.tokenize_prefix(ISSUE_272, cut)
    assert out == "" and consumed == 0
    out, consumed, _ = vault.tokenize_prefix(ISSUE_272, len(ISSUE_272.encode()))
    assert "@" not in out and consumed == len(ISSUE_272.encode())
    assert vault.restore(out).text == ISSUE_272


def test_joined_email_mitigation_does_not_rescan_already_covered_tails(monkeypatch):
    import datafog_core
    from datafog_guard.vault import Detector

    original = datafog_core.scan
    calls = 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(datafog_core, "scan", counted)
    count = 400
    text = "と".join(["alice@example.com"] * count)
    spans = Detector(("EMAIL",)).spans(text)
    assert spans[0].start == 0 and spans[-1].end == len(text.encode())
    assert calls <= count + 1, "each stranded domain is validated at most once, not once per earlier finding"


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
