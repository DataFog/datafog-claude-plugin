"""Tokenizing stream filter for command output.

Output is released line by line. A piece of output is held back while a value
could still be incomplete in it:

* the text after the last line feed (a value split across two reads, or by a carriage return),
* everything from a ``-----BEGIN`` line whose ``-----END`` has not arrived yet,
* a detected value that crosses the point where the output would be cut.

Each release goes through the vault (prepare, save, activate) before a byte is
written. On any error the filter stops writing output for good, prints one
notice and keeps reading so the command is not blocked.
"""
from __future__ import annotations

import re

MAX_HOLD = 256 * 1024      # a line longer than this is cut at a safe point instead of being held
FORCED_MARGIN = 64 * 1024  # kept back on a forced cut; larger than any value the vault stores
HARD_LIMIT = 4 * 1024 * 1024
WITHHELD_NOTICE = b"[datafog: output withheld, it could not be checked]\n"
_INVALID = re.compile("([\udc80-\udcff]+)")
_BEGIN = b"-----BEGIN "
_END = b"-----END "


class StreamTokenizer:
    def __init__(self, vault):
        self.vault = vault
        self.buffer = b""
        self.failed = False
        self.counts: dict = {}

    def feed(self, data: bytes) -> bytes:
        if self.failed:
            return b""
        self.buffer += data
        try:
            return self._release(final=False)
        except Exception:
            return self._fail()

    def finish(self) -> bytes:
        if self.failed:
            return b""
        try:
            return self._release(final=True)
        except Exception:
            return self._fail()

    def _fail(self) -> bytes:
        self.failed = True
        self.buffer = b""
        return WITHHELD_NOTICE

    def _count(self, counts) -> None:
        for name, number in counts.items():
            self.counts[name] = self.counts.get(name, 0) + number

    def _release(self, final: bool) -> bytes:
        buffer = self.buffer
        if not buffer:
            return b""
        if final:
            limit = len(buffer)
        else:
            # Only a line feed ends a line. A carriage return does not: text after it can
            # overwrite, and so complete, a value on the same line.
            limit = buffer.rfind(b"\n") + 1
            if limit == 0 and len(buffer) > MAX_HOLD:
                limit = len(buffer) - FORCED_MARGIN
            begin = buffer.rfind(_BEGIN)
            if begin != -1 and buffer.find(_END, begin) == -1 and len(buffer) - begin <= MAX_HOLD:
                limit = min(limit, begin)
            if limit <= 0:
                return b""
        try:
            text = buffer.decode("utf-8")
        except UnicodeDecodeError as error:
            if not final and error.start >= len(buffer) - 3 and error.reason == "unexpected end of data":
                # An incomplete character at the very end: wait for the rest of it.
                if limit > error.start:
                    limit = error.start
                text = buffer[:error.start].decode("utf-8")
                if limit <= 0:
                    return b""
            else:
                return self._release_binary(limit)
        out, consumed, counts = self.vault.tokenize_prefix(text, limit)
        self._count(counts)
        if consumed == 0 and not final and len(buffer) > HARD_LIMIT:
            raise RuntimeError("cannot find a safe place to cut the output")
        if final and consumed < len(text.encode("utf-8")):
            raise RuntimeError("output left over at end of stream")
        self.buffer = buffer[consumed:]
        return out.encode("utf-8")

    def _release_binary(self, limit: int) -> bytes:
        """Output that is not valid UTF-8: tokenize the valid runs, pass the other bytes through."""
        head = self.buffer[:limit].decode("utf-8", errors="surrogateescape")
        pieces = _INVALID.split(head)
        valid = [piece for index, piece in enumerate(pieces) if index % 2 == 0]
        tokenized, counts = self.vault.tokenize_many(valid)
        self._count(counts)
        for index, piece in enumerate(tokenized):
            pieces[index * 2] = piece
        self.buffer = self.buffer[limit:]
        return "".join(pieces).encode("utf-8", errors="surrogateescape")


def pump(source, sink, tokenizer: StreamTokenizer, chunk: int = 65536) -> None:
    """Copy a binary stream through the tokenizer until end of file."""
    read = getattr(source, "read1", None) or source.read
    while True:
        try:
            data = read(chunk)
        except (OSError, ValueError):
            data = b""
        if not data:
            break
        _write(sink, tokenizer.feed(data))
    _write(sink, tokenizer.finish())


def _write(sink, data: bytes) -> None:
    if not data:
        return
    try:
        sink.write(data)
        sink.flush()
    except (OSError, ValueError):
        pass   # the reader went away; keep draining so the command is not blocked
