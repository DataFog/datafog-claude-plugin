"""Tokenizer and restore behaviour against the real datafog-core."""
from __future__ import annotations

import re
from collections import Counter

import pytest
from conftest import CARD, EMAIL, NOTES, PHONE, SENTINELS, copy_vault, seed_values
from datafog_guard.errors import ConfigError, TokenizeError, VaultFull
from datafog_guard.vault import MARKER_RE, Span, merge_spans

MARKER = re.compile(r"\[\[[A-Z0-9_]+_[0-9A-Z]{6}\]\]")


def test_round_trip_and_types(box):
    vault = box.open_vault()
    out, counts = vault.tokenize(NOTES)
    for value in SENTINELS:
        assert value not in out
    assert counts == Counter({"EMAIL": 1, "PHONE": 1, "SSN": 1, "CREDIT_CARD": 1, "API_KEY": 1})
    assert len(MARKER.findall(out)) == 5
    assert out.count("\n") == NOTES.count("\n")
    result = vault.restore(out)
    assert result.text == NOTES and result.total == 5 and result.unknown == 0


def test_marker_format_is_cores(box):
    out, _ = box.open_vault().tokenize(f"mail {EMAIL}")
    marker = out.split()[1]
    assert MARKER_RE.fullmatch(marker) and marker.startswith("[[EMAIL_")


def test_same_value_same_marker_across_processes(box):
    first, _ = box.open_vault().tokenize(f"a {EMAIL}")
    second, _ = box.open_vault().tokenize(f"b {EMAIL} c")
    assert first.split()[1] == second.split()[1]


def test_text_without_values_does_not_touch_the_vault(box):
    vault = box.open_vault()
    out, counts = vault.tokenize("nothing to see here\n")
    assert out == "nothing to see here\n" and not counts
    assert not box.vault.exists()


def test_tokenizing_twice_is_stable(box):
    vault = box.open_vault()
    once, _ = vault.tokenize(NOTES)
    twice, counts = vault.tokenize(once)
    assert twice == once and not counts


def test_recall_catches_a_value_the_detector_misses(box):
    vault = box.open_vault()
    vault.tokenize("account number 000123456789")
    bare = "ref 000123456789 again"
    assert not vault.detector.spans(bare), "precondition: the detector alone does not find the bare number"
    out, counts = vault.tokenize(bare)
    assert "000123456789" not in out and counts == Counter({"ACCOUNT_NUMBER": 1})
    assert vault.restore(out).text == bare


@pytest.mark.parametrize("text, hidden", [
    ("ref 000123456789 again", True),
    ("ref (000123456789), again", True),
    ("REF-000123456789.", True),
    ("x000123456789y", False),            # inside a longer word or number: not the value
    ("0001234567890", False),
    ("_000123456789", False),
])
def test_known_values_match_whole_not_inside_a_longer_word(box, text, hidden):
    box.open_vault().tokenize("account number 000123456789")
    out, counts = box.open_vault().tokenize(text)
    assert ("000123456789" not in out) is hidden and bool(counts) is hidden


def test_known_values_match_whatever_the_case_and_white_space(box):
    """As core's recall did: a known card number is found with other spacing, and restores exactly."""
    vault = box.open_vault()
    seed_values(vault, [("ACCOUNT_NUMBER", "Policy AB 77 31")])
    for text in ("see policy ab 77 31 here", "POLICY  AB\t77\n31", "Policy AB 77 31"):
        fresh = box.open_vault()
        out, counts = fresh.tokenize(text)
        assert "77" not in out and counts == Counter({"ACCOUNT_NUMBER": 1}), text
        assert box.open_vault().restore(out).text == text
    assert box.open_vault().tokenize("Policy AB 77 31")[0] == seed_values(vault, [("ACCOUNT_NUMBER", "Policy AB 77 31")])["Policy AB 77 31"]


def test_known_value_matching_never_touches_marker_text(box):
    vault = box.open_vault()
    marker = vault.tokenize(EMAIL)[0]
    seed_values(vault, [("ACCOUNT_NUMBER", marker[2:-2].split("_")[1])])      # a value equal to a marker's code
    out, counts = box.open_vault().tokenize(f"keep {marker} as it is")
    assert out == f"keep {marker} as it is" and not counts


def test_known_values_in_a_large_text_with_a_large_vault(box):
    """The narrowing step for big inputs finds the same values as the plain search."""
    import datafog_guard.vault as module
    vault = box.open_vault()
    seed_values(vault, [("ACCOUNT_NUMBER", f"acct-{number:05d}-zz") for number in range(800)])
    text = "\n".join(f"line {number} filler filler" for number in range(3000)) + "\nsee ACCT-00777-ZZ and acct-00003-zz\n"
    plain, _ = box.open_vault().tokenize(text)
    saved, module.PREFILTER_WORK = module.PREFILTER_WORK, 1
    try:
        narrowed, counts = box.open_vault().tokenize(text)
    finally:
        module.PREFILTER_WORK = saved
    assert counts == Counter({"ACCOUNT_NUMBER": 2}) and "00777" not in narrowed and "00003" not in narrowed
    assert box.open_vault().restore(narrowed).text == text and plain.count("[[") == 2


HOSTILE = ["a\tb", "a\r\nb", "a\rb", "a\nb", "a b", "A\u00a0B", " lead", "trail ", "it's \"q\" $(x) `y` \\", "x\x00y",
           "é\u200bz", "ＡＢ", "tab\tin\tside", "-rf --", "'; rm -rf ~; '", "line1\nline2\n\nline4", "\x1b[31mred\x1b[0m",
           "名前 太郎", "a" * 30_000]


def test_hostile_values_round_trip_exactly(box):
    """Core treats values that differ only in case or white space as one; every one must still come
    back byte for byte, in this process and in a new one. (White space around a value is trimmed
    before it is stored: the marker replaces the trimmed part and the rest stays in the text.)"""
    vault = box.open_vault()
    markers = {}
    for value in HOSTILE:
        markers[value] = seed_one_exact(vault, value)
    assert len(set(markers.values())) == len(HOSTILE), "one marker per distinct byte string"
    fresh = box.open_vault()
    for value, marker in markers.items():
        assert fresh.restore(f"<{marker}>").text == f"<{value}>", repr(value[:20])
        spans, unknown = fresh.restore_spans(f"<{marker}>")
        assert spans == [(1, 1 + len(marker), "ACCOUNT_NUMBER", value)] and unknown == 0
    again = box.open_vault()
    assert {value: again._markers_for({value: ["ACCOUNT_NUMBER"]})[value] for value in HOSTILE} == markers


def seed_one_exact(vault, value: str) -> str:
    return vault._markers_for({value: ["ACCOUNT_NUMBER"]})[value]


@pytest.mark.parametrize("value", ["  ", "\t", "\n", ""])
def test_a_value_of_only_white_space_is_refused(box, value):
    """Core refuses it. It cannot come from detection: spans are trimmed first."""
    with pytest.raises(TokenizeError):
        box.open_vault()._markers_for({value: ["ACCOUNT_NUMBER"]})
    assert merge_spans([Span(0, max(1, len(value)), "EMAIL")], value.encode() or b" ") == []


def test_case_variants_restore_exactly(box):
    """Core folds case when comparing values; a write-back must still be byte-exact."""
    vault = box.open_vault()
    text = "Ada.Synthetic@Example.com then ada.synthetic@example.com then ADA.SYNTHETIC@EXAMPLE.COM"
    out, counts = vault.tokenize(text)
    assert "@" not in out and counts["EMAIL"] == 3
    assert len(set(MARKER.findall(out))) == 3
    assert vault.restore(out).text == text
    assert box.open_vault().restore(out).text == text


def test_overlapping_findings_are_merged():
    data = b"x postgres://u:pw@db.example.com/x y"
    spans = merge_spans([Span(2, 34, "CREDENTIAL_URI"), Span(15, 32, "EMAIL"), Span(30, 36, "PHONE")], data)
    assert spans == [Span(2, 36, "CREDENTIAL_URI")]


def test_credential_uri_with_nested_email(box):
    vault = box.open_vault()
    text = "db postgres://user:hunter2pass@db.example.com:5432/app ok"
    out, _ = vault.tokenize(text)
    assert "hunter2pass" not in out and vault.restore(out).text == text


def test_multibyte_text(box):
    vault = box.open_vault()
    text = f"é😀 {EMAIL} ü — {PHONE} 日本語"
    out, _ = vault.tokenize(text)
    assert EMAIL not in out and PHONE not in out and vault.restore(out).text == text


def test_marker_lookalikes_do_not_break_tokenizing(box):
    """Core's prepare rejects unknown marker-like text; the engine must cope."""
    vault = box.open_vault()
    known, _ = vault.tokenize(EMAIL)
    text = f"[[SECTION_HEADER]] [[EMAIL_ZZZZZZ]] [[FOO_BAR_BAZ12]] {known[2:-2]} arr[[0]] {PHONE} {known}"
    out, counts = vault.tokenize(text)
    assert PHONE not in out and counts == Counter({"PHONE": 1})
    assert "[[SECTION_HEADER]] [[EMAIL_ZZZZZZ]] [[FOO_BAR_BAZ12]]" in out


# -- restore tolerance ---------------------------------------------------
def _known_marker(vault) -> str:
    return vault.tokenize(EMAIL)[0]


def test_restore_leaves_unknown_marker_and_restores_the_rest(box):
    vault = box.open_vault()
    marker = _known_marker(vault)
    result = vault.restore(f"a {marker} b [[EMAIL_ZZZZZZ]] c {marker}")
    assert result.text == f"a {EMAIL} b [[EMAIL_ZZZZZZ]] c {EMAIL}"
    assert result.unknown == 1 and result.restored == Counter({"EMAIL": 2})


def test_restore_never_uses_a_wrong_label(box):
    vault = box.open_vault()
    marker = _known_marker(vault)
    wrong = "[[PHONE_" + marker[-8:]
    result = vault.restore(f"x {wrong} y")
    assert result.text == f"x {wrong} y" and result.unknown == 1 and not result.total


def test_restore_lowercase_marker_follows_core(box):
    """Core treats markers case-insensitively, so a lower-cased marker is the same marker."""
    vault = box.open_vault()
    marker = _known_marker(vault)
    result = vault.restore(f"x {marker.lower()} y")
    assert result.text == f"x {EMAIL} y" and result.restored == Counter({"EMAIL": 1})


@pytest.mark.parametrize("damage", [
    lambda m: m[2:-2],          # no brackets at all
    lambda m: m[:-1],           # one closing bracket missing
    lambda m: m[1:],            # one opening bracket missing
    lambda m: "[ [" + m[2:],    # broken opening
    lambda m: m[:-3] + "]]",    # code one character short
])
def test_restore_leaves_damaged_markers(box, damage):
    vault = box.open_vault()
    marker = _known_marker(vault)
    broken = damage(marker)
    result = vault.restore(f"x {broken} y {marker}")
    assert result.text == f"x {broken} y {EMAIL}"


def test_restore_with_no_vault(box):
    result = box.open_vault().restore("x [[EMAIL_ABC123]] y")
    assert result.text == "x [[EMAIL_ABC123]] y" and result.unknown == 1
    assert not box.vault.exists()


# -- limits ----------------------------------------------------------------
def test_input_larger_than_one_prepare_batch(box):
    vault = box.open_vault()
    line = f"row {{}} {EMAIL} {CARD} filler filler filler filler filler\n"
    text = "".join(line.format(number) for number in range(22_000))
    assert len(text) > 1024 * 1024
    out, counts = vault.tokenize(text)
    assert EMAIL not in out and CARD not in out
    assert counts == Counter({"EMAIL": 22_000, "CREDIT_CARD": 22_000})
    assert vault.restore(out).text == text


def test_many_distinct_values_need_several_commits(box):
    vault = box.open_vault()
    text = "\n".join(f"user{number}.synthetic@example.com" for number in range(2500))
    out, counts = vault.tokenize(text)
    assert "@" not in out and counts["EMAIL"] == 2500
    assert vault.entry_counts() == {"EMAIL": 2500}
    assert box.open_vault().restore(out).text == text


def test_value_too_large_fails_closed(box):
    vault = box.open_vault()
    huge = "postgres://user:" + "p" * 40_000 + "@db.example.com/x"
    with pytest.raises(TokenizeError):
        vault.tokenize(f"uri {huge}")


def test_full_vault_fails_closed_with_a_clear_message(box, full_vault_dir):
    copy_vault(full_vault_dir, box.vault)
    vault = box.open_vault()
    with pytest.raises(VaultFull) as caught:
        vault.tokenize(f"new {EMAIL}")
    assert "20,000" in caught.value.user_message and EMAIL not in caught.value.user_message
    assert vault.restore("[[EMAIL_ZZZZZZ]]").unknown == 1          # restoring still works
    out, counts = vault.tokenize("known v0000007 here")            # and so do values already held
    assert "v0000007" not in out and counts == Counter({"ACCOUNT_NUMBER": 1})


def test_known_values_are_matched_however_much_the_vault_holds(box):
    """Core's own recall stopped at roughly 256 KiB of stored values; the plugin's matching does not."""
    vault = box.open_vault()
    for start in range(0, 3500, 500):
        seed_values(vault, [("API_KEY", f"k{number:07d}" * 12) for number in range(start, start + 500)])
    fresh = box.open_vault()
    fresh.health()
    out, counts = fresh.tokenize(f"new {EMAIL} and {'k0003499' * 12} again")
    assert EMAIL not in out and "k0003499" not in out and counts == Counter({"EMAIL": 1, "API_KEY": 1})


# -- configuration -----------------------------------------------------------
def test_default_entities_exclude_noisy_types(box):
    out, counts = box.open_vault().tokenize("ip 10.1.2.3 date 2024-01-02 zip 94107 id 123e4567-e89b-12d3-a456-426614174000")
    assert not counts and "10.1.2.3" in out


def test_noisy_types_can_be_enabled(box):
    vault = box.open_vault(("IP_ADDRESS", "UUID"))
    out, counts = vault.tokenize("ip 10.1.2.3 id 123e4567-e89b-12d3-a456-426614174000")
    assert counts == Counter({"IP_ADDRESS": 1, "UUID": 1})


def test_allowlist_is_exact_and_never_stored(box):
    vault = box.open_vault(("EMAIL",), allowlist=frozenset({"noreply@example.com"}))
    out, counts = vault.tokenize(f"from noreply@example.com to {EMAIL}")
    assert "noreply@example.com" in out and EMAIL not in out and counts == Counter({"EMAIL": 1})
    assert vault.entry_counts() == {"EMAIL": 1}


def test_unknown_entity_is_a_config_error(box):
    vault = box.open_vault(("EMAIL", "NOT_A_TYPE"))
    with pytest.raises(ConfigError):
        vault.tokenize("x")


def test_known_detection_limits_are_what_the_readme_says(box):
    """Names and unlabelled addresses are not detected. If this changes, update the README."""
    out, counts = box.open_vault().tokenize("Ada Lovelace lives at 12 Example Street, Springfield")
    assert not counts


