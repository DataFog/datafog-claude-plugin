"""Tokenizer and restore behaviour against the real datafog-core."""
from __future__ import annotations

import re
from collections import Counter

import pytest
from conftest import CARD, EMAIL, NOTES, PHONE, SENTINELS, copy_vault
from datafog_guard.errors import ConfigError, RecallUnavailable, TokenizeError, VaultFull
from datafog_guard.store import FileVaultStore
from datafog_guard.vault import MARKER_RE, Detector, Span, Vault, merge_spans

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
    assert not box.vault.exists() or FileVaultStore(str(box.vault)).peek_head() is None


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
    """prepare() and recall() in core reject unknown marker-like text; the engine must cope."""
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


def test_vault_too_large_for_recall_fails_closed(box):
    """Core's recall stops working once stored values pass roughly 256 KiB in total."""
    filler = Vault(FileVaultStore(str(box.vault)), Detector(("EMAIL",)), recall_required=False)
    for start in range(0, 3500, 500):
        filler._commit([("API_KEY", f"k{number:07d}" * 12) for number in range(start, start + 500)])
    with pytest.raises(RecallUnavailable):
        box.open_vault().tokenize(f"new {EMAIL}")
    with pytest.raises(RecallUnavailable):
        box.open_vault().health()
    out, counts = filler.tokenize(f"new {EMAIL}")                   # opt-out: detector only
    assert EMAIL not in out


# -- configuration -----------------------------------------------------------
def test_default_entities_exclude_noisy_types(box):
    out, counts = box.open_vault().tokenize("ip 10.1.2.3 date 2024-01-02 zip 94107 id 123e4567-e89b-12d3-a456-426614174000")
    assert not counts and "10.1.2.3" in out


def test_noisy_types_can_be_enabled(box):
    vault = Vault(FileVaultStore(str(box.vault)), Detector(("IP_ADDRESS", "UUID")))
    out, counts = vault.tokenize("ip 10.1.2.3 id 123e4567-e89b-12d3-a456-426614174000")
    assert counts == Counter({"IP_ADDRESS": 1, "UUID": 1})


def test_allowlist_is_exact_and_never_stored(box):
    vault = Vault(FileVaultStore(str(box.vault)), Detector(("EMAIL",), allowlist=frozenset({"noreply@example.com"})))
    out, counts = vault.tokenize(f"from noreply@example.com to {EMAIL}")
    assert "noreply@example.com" in out and EMAIL not in out and counts == Counter({"EMAIL": 1})
    assert vault.entry_counts() == {"EMAIL": 1}


def test_unknown_entity_is_a_config_error(box):
    vault = Vault(FileVaultStore(str(box.vault)), Detector(("EMAIL", "NOT_A_TYPE")))
    with pytest.raises(ConfigError):
        vault.tokenize("x")


def test_known_detection_limits_are_what_the_readme_says(box):
    """Names and unlabelled addresses are not detected. If this changes, update the README."""
    out, counts = box.open_vault().tokenize("Ada Lovelace lives at 12 Example Street, Springfield")
    assert not counts


