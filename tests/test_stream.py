"""The stream tokenizer: no value may slip through because of where a read happened to end."""
from __future__ import annotations

import random

import pytest
from conftest import API_KEY, CARD, EMAIL, PHONE, SENTINELS, SSN, assert_no_sentinel
from datafog_guard import stream
from datafog_guard.stream import WITHHELD_NOTICE, StreamTokenizer

PEM = ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
       "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n-----END PRIVATE KEY-----")


def feed_in_pieces(vault, data: bytes, sizes) -> bytes:
    tokenizer = StreamTokenizer(vault)
    out, position = b"", 0
    for size in sizes:
        if position >= len(data):
            break
        out += tokenizer.feed(data[position:position + size])
        position += size
    out += tokenizer.feed(data[position:])
    out += tokenizer.finish()
    assert not tokenizer.failed
    return out


@pytest.mark.parametrize("size", [1, 2, 3, 7, 16, 64, 1000])
def test_value_split_across_reads_is_caught(box, size):
    vault = box.open_vault()
    text = f"start {EMAIL} mid {CARD}\nnext {SSN} {API_KEY}\nlast line without newline {PHONE}"
    out = feed_in_pieces(vault, text.encode(), [size] * (len(text) // size + 1)).decode()
    assert_no_sentinel(out)
    assert vault.restore(out).text == text


def test_every_split_point_of_a_line(box):
    vault = box.open_vault()
    text = f"contact {EMAIL} card {CARD} end\n"
    expected = vault.tokenize(text)[0]
    for cut in range(1, len(text)):
        assert feed_in_pieces(vault, text.encode(), [cut]).decode() == expected, cut


def test_random_chunking_of_mixed_output(box):
    vault = box.open_vault()
    rng = random.Random(7)
    lines = [f"row {n} {rng.choice(SENTINELS)} and {rng.choice(SENTINELS)} é😀" for n in range(400)]
    text = "\n".join(lines) + "\n" + PEM + "\ntail\n"
    out = feed_in_pieces(vault, text.encode(), [rng.randint(1, 300) for _ in range(5000)]).decode()
    assert_no_sentinel(out)
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEF" not in out and "[[PRIVATE_KEY_" in out
    assert vault.restore(out).text == text


def test_multi_line_value_is_held_until_complete(box):
    vault = box.open_vault()
    tokenizer = StreamTokenizer(vault)
    first, rest = PEM[:120], PEM[120:]
    out = tokenizer.feed(("before\n" + first).encode())
    assert out == b"before\n", "nothing of an open key block is released"
    out += tokenizer.feed(rest.encode() + b"\nafter\n") + tokenizer.finish()
    assert b"MIIEvQ" not in out and b"[[PRIVATE_KEY_" in out and out.endswith(b"after\n")


def test_partial_line_is_held_until_newline_or_end(box):
    tokenizer = StreamTokenizer(box.open_vault())
    assert tokenizer.feed(b"ada.synthetic@exam") == b""
    out = tokenizer.feed(b"ple.com\n")
    assert out.startswith(b"[[EMAIL_") and out.endswith(b"]]\n")
    assert tokenizer.feed(b"prompt> ") == b"" and tokenizer.finish() == b"prompt> "


def test_carriage_return_progress_output_is_held_until_the_line_ends(box):
    """A carriage return can complete a value on the same line, so it does not release output."""
    tokenizer = StreamTokenizer(box.open_vault())
    assert tokenizer.feed(b"10%\r20%\r") == b""
    assert tokenizer.feed(b"100%\n") == b"10%\r20%\r100%\n"


def test_very_long_line_without_newline(box, monkeypatch):
    monkeypatch.setattr(stream, "MAX_HOLD", 4096)
    monkeypatch.setattr(stream, "FORCED_MARGIN", 512)
    vault = box.open_vault()
    text = " ".join(f"{EMAIL} {CARD} x{n}" for n in range(3000))     # ~150 KB, one line
    out = feed_in_pieces(vault, text.encode(), [997] * 400).decode()
    assert_no_sentinel(out)
    assert vault.restore(out).text == text


def test_multibyte_character_split_across_reads(box):
    vault = box.open_vault()
    text = f"é😀 日本 {EMAIL} ü\n" * 5
    for size in (1, 2, 3, 5):
        assert vault.restore(feed_in_pieces(vault, text.encode(), [size] * 400).decode()).text == text


def test_binary_output_passes_and_text_in_it_is_tokenized(box):
    vault = box.open_vault()
    data = b"\xff\xfe\x00\x01 " + EMAIL.encode() + b" \x80\x81\n" + bytes(range(256)) + b"\n" + CARD.encode() + b"\n"
    out = feed_in_pieces(vault, data, [50] * 20)
    assert EMAIL.encode() not in out and CARD.encode() not in out
    assert out.startswith(b"\xff\xfe\x00\x01 [[EMAIL_") and bytes(range(128, 256)) in out


def test_failure_withholds_everything_after_it(box):
    class Broken:
        def tokenize_prefix(self, text, limit):
            raise RuntimeError(f"boom {EMAIL}")

    tokenizer = StreamTokenizer(Broken())
    assert tokenizer.feed(f"{EMAIL}\n".encode()) == WITHHELD_NOTICE
    assert tokenizer.feed(f"{CARD}\n".encode()) == b"" and tokenizer.finish() == b""
    assert tokenizer.failed


def test_empty_stream(box):
    tokenizer = StreamTokenizer(box.open_vault())
    assert tokenizer.feed(b"") == b"" and tokenizer.finish() == b""
