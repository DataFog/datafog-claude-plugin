"""Detection, tokenization and restoration on top of datafog-core's encrypted application vault.

Order of a tokenization, which must not change:

    find values (detector + values the vault already knows)
    -> known values take the marker they already have        nothing is written
    -> new values: store.commit                              core assigns markers and saves them,
                                                             encrypted and flushed, before it returns
    -> check each new marker restores to exactly its value
    -> note the new markers in the marker index
    -> release the tokenized text

If any step fails, an exception is raised and no text is released.

Facts about core 1.7 and its ApplicationVault this module is built around (all checked against
the real libraries):

* ``prepare_and_commit`` rejects text holding marker-like strings the vault does not know, so
  markers are obtained by committing a small text made of the distinct new values only, and
  are spliced into the original text here.
* It rejects partially overlapping findings, so overlaps are merged first.
* Core folds case and white space when it compares values: ``Ada@Example.com`` and
  ``ada@example.com`` share one marker, which restores to whichever was seen first; ``a\tb``,
  ``a\r\nb`` and ``a b`` likewise. A value whose marker would restore to different bytes is
  stored under a variant label (``EMAIL_V2``) instead, so that restoration is always exact.
  A value that is only white space is refused by core; spans are trimmed, so none is ever sent.
* ApplicationVault has no ``recall`` and no lookup. Known values are matched here, against the
  values of the markers in the store's marker index, with the rules core's recall had: the
  whole value, ignoring case and the amount of white space, and not inside a longer word or
  number.
* Limits: 1 MiB of text and 10,000 findings per call, 20,000 live entries.
"""
from __future__ import annotations

import re
from collections import Counter, namedtuple

from .errors import EngineUnavailable, TokenizeError, VaultError
from .store import MARKER_RE, EncryptedStore, StoreError

ANY_CASE_MARKER_RE = re.compile(MARKER_RE.pattern, re.IGNORECASE)   # core restores markers in any case
MAX_VALUE_BYTES = 32 * 1024          # larger findings are refused, which bounds every stored value
VALUES_PER_COMMIT = 1000
BYTES_PER_COMMIT = 256 * 1024
MAX_VARIANTS = 9
ENTRY_LIMIT = 20_000
# Known-value matching looks for every known value in the text. Past this many (values x text
# characters) the values are first narrowed to those whose first characters occur in the text.
PREFILTER_WORK = 50_000_000
GRAM = 4


# Characters a terminal does not show, or that move the cursor. A value split by one of them
# is invisible to a detector that reads the raw bytes.
_HIDDEN = "\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff"
_NEEDS_VIEWS = re.compile("[" + _HIDDEN + "]|\r(?!\n)")
_ESCAPE = re.compile(
    "\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)?"     # OSC ... BEL or ST
    "|\x1b\\[[0-?]*[ -/]*[@-~]"                         # CSI
    "|\x1b[ -/]*[0-~]"                                    # other escape sequences
    "|\x1b")
_HIDDEN_CHAR = re.compile("[" + _HIDDEN + "\r]")


def _views(text: str):
    """Two extra readings of a text that holds control characters.

    "stripped": escape sequences and invisible characters removed, so the pieces of a split
    value join up. "rendered": additionally backspace and carriage return are applied the way a
    terminal would, so overstruck or overwritten text reads as it is displayed.

    Returns (views, escapes). Each view is (text, origins) where origins[i] is the (start, end)
    byte range in the original text of the view's i-th character. ``escapes`` lists the byte
    ranges of the escape sequences.
    """
    escapes: list[tuple[int, int]] = []
    stripped_chars: list[str] = []
    stripped_origin: list[tuple[int, int]] = []
    rendered_chars: list[str] = []
    rendered_origin: list[tuple[int, int]] = []
    line: list[tuple[str, int, int]] = []
    cursor = 0
    position = 0        # byte offset in the original
    index = 0
    length = len(text)

    def flush():
        nonlocal line, cursor
        for char, start, end in line:
            rendered_chars.append(char)
            rendered_origin.append((start, end))
        line, cursor = [], 0

    while index < length:
        char = text[index]
        if char == "\x1b":
            match = _ESCAPE.match(text, index)
            size = len(match.group().encode("utf-8", "surrogatepass")) if match else 1
            escapes.append((position, position + size))
            position += size
            index = match.end() if match else index + 1
            continue
        code = ord(char)
        size = 1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
        if char == "\n" or (char == "\r" and index + 1 < length and text[index + 1] == "\n"):
            flush()
            stripped_chars.append(char)
            stripped_origin.append((position, position + size))
            rendered_chars.append(char)
            rendered_origin.append((position, position + size))
        elif char == "\b":
            cursor = max(0, cursor - 1)
        elif char == "\r":
            cursor = 0
        elif _HIDDEN_CHAR.match(char):
            pass
        else:
            stripped_chars.append(char)
            stripped_origin.append((position, position + size))
            cell = (char, position, position + size)
            if cursor < len(line):
                line[cursor] = cell
            else:
                line.append(cell)
            cursor += 1
        position += size
        index += 1
    flush()
    return [("".join(stripped_chars), stripped_origin), ("".join(rendered_chars), rendered_origin)], escapes


def _core():
    try:
        import datafog_core
    except Exception as error:   # missing, wrong architecture, broken install
        raise EngineUnavailable("the datafog-core library cannot be loaded") from error
    return datafog_core


class Span(namedtuple("Span", "start end entity known", defaults=(False,))):
    """A value in a text: byte offsets into its UTF-8 form, and the entity type.

    ``known`` is set for values found by recall: the vault already holds them under this type.
    """
    __slots__ = ()


class RestoreResult:
    def __init__(self, text: str, restored: Counter, unknown: int):
        self.text = text
        self.restored = restored      # entity type -> markers restored
        self.unknown = unknown        # marker-like strings left untouched

    @property
    def total(self) -> int:
        return sum(self.restored.values())


def marker_label(marker: str) -> str:
    match = MARKER_RE.fullmatch(marker)
    return match.group(1) if match else "UNKNOWN"


def base_entity(label: str) -> str:
    """EMAIL_V2 -> EMAIL."""
    return re.sub(r"_V[2-9]$", "", label)


class Detector:
    """Thin wrapper over ``datafog_core.scan`` with the configured entity list and allowlist."""

    def __init__(self, entities, allowlist=frozenset()):
        self.entities = tuple(entities)
        self.allowlist = frozenset(allowlist)
        self._config: dict | None = None

    def config(self) -> dict:
        if self._config is None:
            core = _core()
            supported = core.capabilities()["entities"]
            bad = [name for name in self.entities if "text" not in supported.get(name, {}).get("scopes", [])]
            if bad or not self.entities:
                from .errors import ConfigError
                raise ConfigError("unsupported entity types in the configuration: " + ", ".join(sorted(bad)) if bad
                                  else "the entity list is empty")
            config: dict = {"entities": list(self.entities)}
            if "UUID" in self.entities:
                config["detect_uuid"] = True
            self._config = config
        return self._config

    def spans(self, text: str) -> list[Span]:
        config = self.config()
        try:
            findings = _core().scan(text, config)
        except UnicodeError as error:
            raise TokenizeError("the text is not valid Unicode", "undecodable_text") from error
        spans = []
        for finding in findings:
            if finding.matched_text in self.allowlist:
                continue
            spans.append(Span(finding.byte_range.start, finding.byte_range.end, finding.entity_type))
        return spans

    def self_test(self) -> None:
        """Fail if the configuration is unusable or the detector does not find a value it must find."""
        self.config()
        if "EMAIL" in self.entities:
            probe = "contact probe.synthetic@example.com now"
            if not any(span.entity == "EMAIL" for span in Detector(("EMAIL",)).spans(probe)):
                raise EngineUnavailable("the detector failed its self-test", "detector_self_test_failed")
        else:
            self.spans("probe")


def merge_spans(spans: list[Span], data: bytes) -> list[Span]:
    """Trim white space off each span, then merge overlapping spans into one covering all of them."""
    trimmed = []
    for span in spans:
        start, end = span.start, span.end
        while start < end and data[start:start + 1].isspace():
            start += 1
        while end > start and data[end - 1:end].isspace():
            end -= 1
        if end > start:
            trimmed.append(Span(start, end, span.entity, span.known))
    trimmed.sort(key=lambda s: (s.start, -(s.end - s.start), not s.known))
    merged: list[Span] = []
    for span in trimmed:
        if merged and span.start < merged[-1].end:
            last = merged[-1]
            if span.end > last.end:     # partial overlap: cover both, keep the first (longer or earlier) type
                merged[-1] = Span(last.start, span.end, last.entity, False)
            elif span.start == last.start and span.end == last.end and span.known and not last.known:
                merged[-1] = span
            continue
        merged.append(span)
    return merged


class _Known:
    """The values the vault holds, as this process last read them. Lives in memory only."""

    __slots__ = ("stamp", "vault_id", "marker_of", "markers", "folded")

    def __init__(self, stamp, vault_id, values: dict[str, str]):
        self.stamp = stamp
        self.vault_id = vault_id
        self.markers = list(values)                    # every known marker
        self.marker_of: dict[str, str] = {}            # exact value -> its first marker
        self.folded: dict[str, list[str]] = {}         # value with case and white space folded -> values
        for marker, value in values.items():
            self.add(marker, value, count=False)

    def add(self, marker: str, value: str, count: bool = True) -> None:
        if count:
            self.markers.append(marker)
        if value not in self.marker_of:
            self.marker_of[value] = marker
            self.folded.setdefault(_fold(value), []).append(value)


def _fold(value: str) -> str:
    return " ".join(value.split()).casefold()


def _value_pattern(value: str):
    """A value as core's recall matched it: any white space between its parts, any case, and not
    directly against a letter, digit or underscore where the value itself begins or ends with one."""
    parts = value.split()
    body = r"\s+".join(re.escape(part) for part in parts)
    before = r"(?<!\w)" if re.match(r"\w", parts[0]) else ""
    after = r"(?!\w)" if re.search(r"\w$", parts[-1]) else ""
    return re.compile(before + body + after, re.IGNORECASE)


class Vault:
    """One process's view of the vault. Safe to use from several threads of one process."""

    def __init__(self, store: EncryptedStore, detector: Detector):
        self.store = store
        self.detector = detector
        self._known: _Known | None = None
        import threading
        self._mutex = threading.RLock()

    # -- loading -----------------------------------------------------------
    def ensure_exists(self) -> None:
        with self._mutex:
            self.store.open(create=True)

    def health(self) -> dict:
        """Run the detector's self-test and open the vault (creating it when there is none), which
        checks its permissions, takes its lock, fetches its key and decrypts it. Raises when unhealthy."""
        with self._mutex:
            self.detector.self_test()
            self.store.open(create=True)
            info = self.store.describe()
            return {"revision": info.get("revision", 0), "protection": self.store.protection}

    def _load_known(self) -> _Known | None:
        """The known values, re-read when another process added to the vault. None without a vault."""
        if self.store.open(create=False) is None:
            self._known = None
            return None
        stamp, vault_id = self.store.index_stamp(), self.store.vault_id()
        known = self._known
        if known is not None and known.stamp == stamp and known.vault_id == vault_id:
            return known
        try:
            values = self.store.values_for(self.store.read_index())
        except StoreError as error:
            raise VaultError("the vault could not be read", "vault_" + error.code) from None
        if self.store.vault_id() != vault_id:          # the vault was replaced while it was read
            values = self.store.values_for(self.store.read_index())
            vault_id = self.store.vault_id()
        self._known = _Known(stamp, vault_id, values)
        return self._known

    def entry_counts(self) -> dict:
        """Values held, by marker label. Counts what the vault confirms, not what the index claims."""
        with self._mutex:
            known = self._load_known()
            return dict(Counter(marker_label(marker) for marker in known.markers)) if known else {}

    # -- finding values ----------------------------------------------------
    def _known_spans(self, known: _Known, text: str, out: list[Span]) -> None:
        """Byte spans of known values in ``text``. Text that is itself a marker is never matched."""
        if not known.folded:
            return
        folded_text = _fold(text)
        candidates = known.folded
        if len(candidates) * len(folded_text) > PREFILTER_WORK:
            grams = {folded_text[index:index + GRAM] for index in range(len(folded_text) - GRAM + 1)}
            candidates = {key: values for key, values in candidates.items() if len(key) < GRAM or key[:GRAM] in grams}
        hits = [key for key in candidates if key in folded_text]
        if not hits:
            return
        markers = [(match.start(), match.end()) for match in ANY_CASE_MARKER_RE.finditer(text)]
        ascii_only = text.isascii()
        for key in hits:
            values = known.folded[key]
            entity = marker_label(known.marker_of[values[0]])
            if any(value in self.detector.allowlist for value in values):
                continue
            for match in _value_pattern(values[0]).finditer(text):
                start, end = match.span()
                if any(left < end and start < right for left, right in markers):
                    continue
                if not ascii_only:
                    start = len(text[:start].encode("utf-8", "surrogatepass"))
                    end = start + len(match.group().encode("utf-8", "surrogatepass"))
                out.append(Span(start, end, entity, True))

    def _raw_spans(self, known: _Known | None, text: str) -> list[Span]:
        """Detector findings plus known values for one text, as byte spans into that text."""
        spans = self.detector.spans(text)
        if known is not None:
            self._known_spans(known, text, spans)
        return spans

    def find_spans(self, text: str, data: bytes | None = None) -> list[Span]:
        """Every value to replace in ``text``: detector findings plus values the vault already knows.

        When the text holds terminal control sequences or invisible characters, it is also read
        with them removed and as a terminal would render it; a value found that way is mapped
        back to the original bytes, and the whole original span (sequences included) is replaced.
        """
        with self._mutex:
            if data is None:
                try:
                    data = text.encode("utf-8")
                except UnicodeError as error:
                    raise TokenizeError("the text is not valid Unicode", "undecodable_text") from error
            known = self._load_known()
            spans = self._raw_spans(known, text)
            if _NEEDS_VIEWS.search(text):
                from bisect import bisect_left, bisect_right
                seen = {text}
                views, escapes = _views(text)
                raw, spans = spans, []
                for view, origin in views:
                    if view in seen or not view:
                        continue
                    seen.add(view)
                    starts, total = [], 0
                    for char in view:
                        starts.append(total)
                        code = ord(char)
                        total += 1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
                    for span in self._raw_spans(known, view):
                        first = bisect_right(starts, span.start) - 1
                        last = bisect_left(starts, span.end) - 1
                        cells = origin[first:last + 1]
                        if cells:
                            spans.append(Span(min(c[0] for c in cells), max(c[1] for c in cells), span.entity,
                                              span.known and first == last))
                # "<ESC>[31mada@example.com" read raw gives the bogus value "31mada@example.com".
                # A raw finding that begins or ends inside an escape sequence is dropped when a
                # view found the real value at the same place; otherwise it is kept.
                inside = {edge for start, end in escapes for edge in range(start + 1, end)}
                for span in raw:
                    cut = span.start in inside or span.end in inside
                    if not (cut and any(other.start < span.end and span.start < other.end for other in spans)):
                        spans.append(span)
            merged = merge_spans(spans, data)
            for span in merged:
                if span.end - span.start > MAX_VALUE_BYTES:
                    raise TokenizeError("a detected value is too large to store", "value_too_large")
            return merged

    # -- assigning markers ---------------------------------------------------
    def _commit(self, pairs: list[tuple[str, str]]) -> dict[str, str]:
        """Store (entity, value) pairs in the vault. Returns value -> marker.

        Core gives a value it already holds (compared loosely) the marker it has; the caller
        checks exactness. The markers are durable when this returns.
        """
        try:
            markers = self.store.commit(pairs)
        except StoreError as error:
            raise TokenizeError("the vault refused the values", "prepare_" + error.code) from None
        return {value: marker for (_, value), marker in zip(pairs, markers)}

    def _markers_for(self, wanted: dict[str, list[str]]) -> dict[str, str]:
        """value -> marker, for values with their candidate entity types (most trusted first)."""
        known = self._load_known()
        markers: dict[str, str] = {}
        pending = []
        for value in wanted:
            marker = known.marker_of.get(value) if known is not None else None
            if marker is not None:
                markers[value] = marker        # byte-exact: it was read back from the vault
            else:
                pending.append(value)
        if not pending:
            return markers
        attempt = {value: 0 for value in pending}
        fresh: dict[str, str] = {}             # marker -> value, to note in the index
        for _ in range(MAX_VARIANTS + 8):
            if not pending:
                break
            pairs = []
            for value in pending:
                candidates, index = wanted[value], attempt[value]
                if index < len(candidates):
                    entity = candidates[index]
                else:
                    variant = index - len(candidates) + 2
                    if variant > MAX_VARIANTS:
                        raise TokenizeError("a value cannot be stored so that it restores exactly", "no_exact_marker")
                    entity = f"{base_entity(candidates[-1])}_V{variant}"
                pairs.append((entity, value))
            assigned: dict[str, str] = {}
            batch: list[tuple[str, str]] = []
            size = 0
            for pair in pairs + [None]:   # type: ignore[list-item]
                if pair is None or len(batch) >= VALUES_PER_COMMIT or size + len(pair[1]) > BYTES_PER_COMMIT:
                    if batch:
                        assigned.update(self._commit(batch))
                    batch, size = [], 0
                if pair is not None:
                    batch.append(pair)
                    size += len(pair[1].encode("utf-8")) + 1
            # Exactness check: core compares values loosely, a write-back must be byte-exact.
            try:
                restored = self.store.values_for([assigned[value] for value in pending])
            except StoreError as error:
                raise TokenizeError("the vault did not restore the values it was given",
                                    "restore_check_" + error.code) from None
            still = []
            for value in pending:
                marker = assigned[value]
                if marker not in restored:
                    raise TokenizeError("the vault did not restore the values it was given", "restore_check_failed")
                if restored[marker] == value:
                    markers[value] = marker
                    fresh[marker] = value
                else:
                    attempt[value] += 1
                    still.append(value)
            pending = still
        if pending:
            raise TokenizeError("a value cannot be stored so that it restores exactly", "no_exact_marker")
        if known is None or known.vault_id != self.store.vault_id():
            self._known = None                 # the vault was created or replaced just now: read it afresh
            known = self._load_known()
        have = set(known.markers) if known is not None else set()
        missing = [marker for marker in fresh if marker not in have]
        before, after = self.store.add_to_index(missing)
        if known is not None:
            for marker in missing:
                known.add(marker, fresh[marker])
            # Ours was the only change since the index was read: keep what is in memory.
            known.stamp = after if before == known.stamp else None
        return markers

    def tokenize_many(self, texts: list[str]) -> tuple[list[str], Counter]:
        """Replace every value in each text by its marker. Returns the texts and counts by entity type."""
        results, counts, _ = self._tokenize(texts, None)
        return results, counts

    def tokenize(self, text: str) -> tuple[str, Counter]:
        results, counts = self.tokenize_many([text])
        return results[0], counts

    def tokenize_prefix(self, text: str, limit: int) -> tuple[str, int, Counter]:
        """Tokenize the start of ``text`` up to byte ``limit``, never cutting through a value.

        The whole text is examined, so a value that crosses ``limit`` is seen; the cut then
        moves back to where that value starts. Returns (tokenized prefix, bytes consumed, counts).
        """
        results, counts, cuts = self._tokenize([text], [limit])
        return results[0], cuts[0], counts

    def _tokenize(self, texts: list[str], limits: list[int] | None):
        with self._mutex:
            plans = []
            wanted: dict[str, list[str]] = {}
            cuts = []
            for index, text in enumerate(texts):
                try:
                    data = text.encode("utf-8")
                except UnicodeError as error:
                    raise TokenizeError("the text is not valid Unicode", "undecodable_text") from error
                spans = self.find_spans(text, data) if text else []
                if limits is not None:
                    cut = max(0, min(limits[index], len(data)))
                    while 0 < cut < len(data) and (data[cut] & 0xC0) == 0x80:
                        cut -= 1
                    for span in spans:
                        if span.start < cut < span.end:
                            cut = span.start
                    spans = [span for span in spans if span.end <= cut]
                    data = data[:cut]
                    cuts.append(cut)
                plans.append((data, spans))
                for span in spans:
                    value = data[span.start:span.end].decode("utf-8")
                    candidates = wanted.setdefault(value, [])
                    if span.entity not in candidates:
                        # Types the vault already uses for this value come first.
                        candidates.insert(0, span.entity) if span.known else candidates.append(span.entity)
            if not wanted:
                return [data.decode("utf-8") for data, _ in plans], Counter(), cuts
            markers = self._markers_for(wanted)
            counts: Counter = Counter()
            results = []
            for data, spans in plans:
                parts, position = [], 0
                for span in spans:
                    marker = markers[data[span.start:span.end].decode("utf-8")]
                    parts.append(data[position:span.start])
                    parts.append(marker.encode("utf-8"))
                    position = span.end
                    counts[base_entity(marker_label(marker))] += 1
                parts.append(data[position:])
                results.append(b"".join(parts).decode("utf-8"))
            return results, counts, cuts

    def contains_values(self, text: str) -> Counter:
        """Counts by type of values in ``text``, without changing the vault."""
        data = text.encode("utf-8")
        return Counter(base_entity(span.entity) for span in self.find_spans(text, data))

    # -- restoring -----------------------------------------------------------
    def restore(self, text: str) -> RestoreResult:
        """Put real values back for every marker the vault knows.

        Marker-like text the vault does not know (unknown code, wrong label, damaged or
        missing brackets) is left exactly as it is and counted in ``unknown``.
        """
        with self._mutex:
            if "[[" not in text:
                # Bare codes without brackets are never restored, so there is nothing to do.
                return RestoreResult(text, Counter(), 0)
            try:
                return self._restore(text, depth=0)
            except StoreError as error:
                if error.code == "no_vault":
                    return RestoreResult(text, Counter(), len(ANY_CASE_MARKER_RE.findall(text)))
                raise VaultError("the vault could not restore the text", "restore_" + error.code) from None
            except UnicodeError as error:
                raise TokenizeError("the text is not valid Unicode", "undecodable_text") from error

    def _restore(self, text: str, depth: int) -> RestoreResult:
        report = self.store.restore_report(text)
        issues = sorted((issue["byteRange"]["start"], issue["byteRange"]["end"]) for issue in report["issues"])
        data = text.encode("utf-8")
        skip = bytearray(len(data) + 1)
        for start, end in issues:
            for position in range(start, min(end, len(data))):
                skip[position] = 1
        restored: Counter = Counter()
        ascii_only = text.isascii()
        for match in ANY_CASE_MARKER_RE.finditer(text):
            start = match.start() if ascii_only else len(text[:match.start()].encode("utf-8"))
            if not skip[start]:
                restored[base_entity(match.group(1).upper())] += 1
        if report["text"] is not None and not issues:
            return RestoreResult(report["text"], restored, 0)
        if depth >= 2:
            return RestoreResult(text, Counter(), len(issues))
        parts, position, unknown = [], 0, len(issues)
        total: Counter = Counter()
        for start, end in issues + [(len(data), len(data))]:
            if start > position:
                piece = self._restore(data[position:start].decode("utf-8"), depth + 1)
                parts.append(piece.text)
                total.update(piece.restored)
                unknown += piece.unknown
            parts.append(data[position if start < position else start:end].decode("utf-8"))
            position = max(position, end)
        return RestoreResult("".join(parts), total, unknown)

    def restore_spans(self, text: str) -> tuple[list[tuple[int, int, str, str]], int]:
        """Where the known markers are: ``([(start, end, type, real value)], unknown)``.

        Offsets are in characters. Used to put values into a Bash command one marker at a
        time (see shellsub.py); the values are never written anywhere by this method.
        """
        with self._mutex:
            if "[[" not in text:
                return [], 0
            matches = list(ANY_CASE_MARKER_RE.finditer(text))
            try:
                unknown = self._restore(text, depth=0).unknown
                values = self.store.values_for([match.group(0) for match in matches])
            except StoreError as error:
                if error.code == "no_vault":
                    return [], len(matches)
                raise VaultError("the vault could not restore the text", "restore_" + error.code) from None
            except UnicodeError as error:
                raise TokenizeError("the text is not valid Unicode", "undecodable_text") from error
            spans = [(match.start(), match.end(), base_entity(match.group(1).upper()), values[match.group(0)])
                     for match in matches if match.group(0) in values]
            return spans, unknown

    def marker_counts(self, text: str) -> tuple[Counter, int]:
        """(known markers by type, unknown marker-like strings) in ``text``; changes nothing."""
        result = self.restore(text)
        return result.restored, result.unknown
