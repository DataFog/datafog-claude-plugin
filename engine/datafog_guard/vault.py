"""Detection, tokenization and restoration on top of datafog-core's Workspace.

Order of a tokenization, which must not change:

    find values (detector + recall of values the vault already knows)
    -> Workspace.prepare            assign markers, nothing is durable yet
    -> store.compare_and_save       persist core's candidate bundle
    -> Workspace.activate_saved     only now are the markers valid
    -> check each marker restores to exactly its value
    -> release the tokenized text

If any step fails, an exception is raised and no text is released.

Facts about core 1.4 this module is built around (all checked against the real library):

* ``prepare`` and ``recall`` reject text holding marker-like strings the vault does not
  know, so markers are obtained by preparing a small text made of the distinct values
  only, and are spliced into the original text here.
* ``prepare`` rejects partially overlapping findings, so overlaps are merged first.
* Core folds case and trims white space when it compares values: ``Ada@Example.com`` and
  ``ada@example.com`` share one marker, which restores to whichever was seen first.
  A value whose marker would restore to different bytes is stored under a variant
  label (``EMAIL_V2``) instead, so that restoration is always exact.
* Limits: 1 MiB of text and 10,000 findings per call, 20,000 live entries, and ``recall``
  stops working once the stored values pass roughly 256 KiB in total.
"""
from __future__ import annotations

import os
import re
import time
from collections import Counter, namedtuple

from .errors import EngineUnavailable, RecallUnavailable, TokenizeError, VaultBusy, VaultCorrupt, VaultError, VaultFull
from .store import Head, VaultStore

MARKER_RE = re.compile(r"\[\[([A-Z][A-Z0-9_]*)_([0-9A-Z]{6})\]\]")
ANY_CASE_MARKER_RE = re.compile(MARKER_RE.pattern, re.IGNORECASE)   # core restores markers in any case
MAX_VALUE_BYTES = 32 * 1024          # larger findings are refused, which bounds every stored value
RECALL_WINDOW = 512 * 1024
RECALL_OVERLAP = 2 * MAX_VALUE_BYTES  # a stored value always fits whole inside one window
VALUES_PER_COMMIT = 1000
BYTES_PER_COMMIT = 256 * 1024
SAVE_RETRIES = 60
MAX_VARIANTS = 9
ENTRY_LIMIT = 20_000


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


class Vault:
    """One process's view of the vault. Safe to use from several threads of one process."""

    def __init__(self, store: VaultStore, detector: Detector, recall_required: bool = True):
        self.store = store
        self.detector = detector
        self.recall_required = recall_required
        self._workspace = None
        self._head: Head | None = None
        self._annotations: dict = {}
        self._recall_ok: bool | None = None
        import threading
        self._mutex = threading.RLock()

    # -- loading -----------------------------------------------------------
    @staticmethod
    def _head_of(core_head) -> Head:
        return Head(int(core_head.revision), bytes(core_head.commit_id).hex())

    def _load(self, create: bool):
        """Return a workspace at the stored head, reloading when another process moved it."""
        core = _core()
        stored = self.store.peek_head()
        if self._workspace is not None and stored == self._head:
            return self._workspace
        self._workspace, self._head, self._recall_ok = None, None, None
        snapshot = self.store.load()
        if snapshot is None:
            if not create:
                return None
            workspace = core.Workspace.create(os.urandom(16), os.urandom(16))
            head = self._head_of(workspace.head())
            self.store.compare_and_save(None, head, workspace.export_bundle(), {"entries": {}})
            snapshot = self.store.load()   # ours, or the one a concurrent creator won with
            if snapshot is None:
                raise VaultError("the vault could not be created", "vault_create_failed")
        try:
            workspace = core.Workspace.open_bundle(snapshot.bundle)
        except Exception as error:
            raise VaultCorrupt("the vault snapshot cannot be opened") from error
        if self._head_of(workspace.head()) != snapshot.head:
            raise VaultCorrupt("the vault snapshot does not match its pointer")
        self._workspace, self._head, self._annotations = workspace, snapshot.head, snapshot.annotations
        return workspace

    def ensure_exists(self) -> None:
        with self._mutex:
            self._load(create=True)

    def health(self) -> dict:
        """Open the vault, take and release its lock, and run the detector. Raises when unhealthy."""
        with self._mutex:
            self.detector.self_test()
            self._load(create=True)
            lock = getattr(self.store, "lock", None)
            if lock is not None:
                with lock():
                    pass
            if self.recall_required:
                self._check_recall(self._workspace)
            return {"revision": self._head.revision if self._head else 0, "entries": self.entry_counts()}

    def entry_counts(self) -> dict:
        with self._mutex:
            if self._workspace is None:
                self._load(create=False)
            entries = self._annotations.get("entries") if isinstance(self._annotations, dict) else None
            return dict(entries) if isinstance(entries, dict) else {}

    # -- finding values ----------------------------------------------------
    def _check_recall(self, workspace) -> bool:
        if self._recall_ok is None:
            try:
                workspace.recall("probe")
                self._recall_ok = True
            except Exception:
                self._recall_ok = False
        if not self._recall_ok and self.recall_required:
            raise RecallUnavailable(
                "the vault holds too many values for known-value matching to work; "
                "run /datafog:purge, or set recall_required to false to rely on the detector alone")
        return self._recall_ok

    def _marker_issues(self, workspace, text: str) -> list[tuple[int, int]]:
        """Byte ranges of marker-like strings the vault does not accept (they break recall)."""
        if "[[" not in text and "_" not in text:
            return []
        report = workspace.restore_report(text)
        return sorted((issue["byteRange"]["start"], issue["byteRange"]["end"]) for issue in report["issues"])

    def _recall_window(self, workspace, data: bytes, offset: int, out: list[Span]) -> None:
        core = _core()
        try:
            findings = workspace.recall(data.decode("utf-8"))["findings"]
        except core.DataFogWorkspaceError as error:
            if error.code != "resource_limit":
                raise TokenizeError("known-value matching failed", "recall_failed") from error
            if not self._check_recall(workspace):
                return
            if len(data) <= 4096:
                raise TokenizeError("the text holds too many values to process", "too_many_values") from error
            self._recall_range(workspace, data, offset, out, window=max(4096, len(data) // 2))
            return
        for item in findings:
            start, end = item["byteRange"]["start"], item["byteRange"]["end"]
            if item["finding"]["matchedText"] in self.detector.allowlist:
                continue
            out.append(Span(offset + start, offset + end, item["finding"]["entityType"], True))

    def _recall_range(self, workspace, data: bytes, offset: int, out: list[Span], window: int) -> None:
        if len(data) <= window:
            self._recall_window(workspace, data, offset, out)
            return
        overlap = min(RECALL_OVERLAP, window // 2)
        position = 0
        while position < len(data):
            end = min(len(data), position + window)
            while end < len(data) and (data[end] & 0xC0) == 0x80:
                end += 1
            self._recall_window(workspace, data[position:end], offset + position, out)
            if end >= len(data):
                break
            position = end - overlap
            while (data[position] & 0xC0) == 0x80:
                position -= 1

    def _raw_spans(self, workspace, text: str, data: bytes) -> list[Span]:
        """Detector findings plus recall hits for one text, as byte spans into that text."""
        spans = self.detector.spans(text)
        if workspace is not None and self._check_recall(workspace):
            position = 0
            for start, end in self._marker_issues(workspace, text) + [(len(data), len(data))]:
                if start > position:
                    self._recall_range(workspace, data[position:start], position, spans, RECALL_WINDOW)
                position = max(position, end)
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
            workspace = self._load(create=False)
            spans = self._raw_spans(workspace, text, data)
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
                    for span in self._raw_spans(workspace, view, view.encode("utf-8")):
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
        """prepare -> save -> activate for (entity, value) pairs. Returns value -> marker."""
        core = _core()
        text = "\n".join(value for _, value in pairs)
        last_error: Exception | None = None
        for attempt in range(SAVE_RETRIES):
            if attempt:
                self._workspace = None
                import random
                time.sleep(min(0.2, 0.002 * (2 ** min(attempt, 6))) * random.random())
            workspace = self._load(create=True)
            findings, offset = [], 0
            for entity, value in pairs:
                size = len(value.encode("utf-8"))
                findings.append(core.WorkspaceFinding(entity, value, core.TextRange(offset, offset + size),
                                                      source="scanner", needs_review=False))
                offset += size + 1
            try:
                change = workspace.prepare(text, findings, os.urandom(16))
            except core.DataFogWorkspaceError as error:
                if error.code == "resource_limit":
                    raise VaultFull(
                        f"the vault is full (core allows {ENTRY_LIMIT:,} live entries); new values cannot be "
                        "protected until it is emptied with /datafog:purge") from error
                raise TokenizeError("the vault refused the values", "prepare_" + str(error.code)) from error
            try:
                preview = change.preview()
                output = preview["text"].encode("utf-8")
                transformations = sorted(preview["transformations"], key=lambda t: t["sourceByteRange"]["start"])
                if len(transformations) != len(pairs):
                    raise TokenizeError("the vault did not assign a marker to every value", "prepare_incomplete")
                markers: dict[str, str] = {}
                for (_, value), item in zip(pairs, transformations):
                    marker = output[item["outputByteRange"]["start"]:item["outputByteRange"]["end"]].decode("utf-8")
                    if not MARKER_RE.fullmatch(marker):
                        raise TokenizeError("the vault returned an unexpected marker", "prepare_bad_marker")
                    markers[value] = marker
                expected, candidate = change.expected_head(), change.candidate_head()
                if expected != candidate:
                    # Markers the workspace cannot restore yet are the new entries: count them by type.
                    entries = Counter(self.entry_counts())
                    distinct = sorted(set(markers.values()))
                    joined = "\n".join(distinct).encode("utf-8")
                    for issue in workspace.restore_report(joined.decode("utf-8"))["issues"]:
                        marker = joined[issue["byteRange"]["start"]:issue["byteRange"]["end"]].decode("utf-8")
                        entries[marker_label(marker)] += 1
                    saved = self.store.compare_and_save(self._head_of(expected), self._head_of(candidate),
                                                        change.export_candidate_bundle(), {"entries": dict(entries)})
                    if not saved:
                        change.discard()
                        last_error = VaultBusy("the vault changed while it was being updated")
                        continue
                    self._annotations = {"entries": dict(entries)}
                workspace.activate_saved(change, expected, candidate)
                self._head = self._head_of(candidate)
                self._recall_ok = None
                return markers
            except BaseException:
                try:
                    change.discard()
                except Exception:
                    pass
                raise
        raise last_error or VaultBusy("the vault changed while it was being updated")

    def _markers_for(self, wanted: dict[str, list[str]]) -> dict[str, str]:
        """value -> marker, for values with their candidate entity types (most trusted first)."""
        markers: dict[str, str] = {}
        attempt = {value: 0 for value in wanted}
        pending = list(wanted)
        for _ in range(MAX_VARIANTS + 8):
            if not pending:
                return markers
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
            separator = f"\n<{os.urandom(8).hex()}>\n"
            workspace = self._load(create=False)
            if workspace is None:
                raise VaultError("the vault disappeared while it was being updated", "vault_missing")
            restored = workspace.restore(separator.join(assigned[value] for value in pending)).split(separator)
            if len(restored) != len(pending):
                raise TokenizeError("the vault did not restore the values it was given", "restore_check_failed")
            still = []
            for value, back in zip(pending, restored):
                if back == value:
                    markers[value] = assigned[value]
                else:
                    attempt[value] += 1
                    still.append(value)
            pending = still
        raise TokenizeError("a value cannot be stored so that it restores exactly", "no_exact_marker")

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
            workspace = self._load(create=False)
            if workspace is None:
                return RestoreResult(text, Counter(), len(ANY_CASE_MARKER_RE.findall(text)))
            try:
                return self._restore(workspace, text, depth=0)
            except UnicodeError as error:
                raise TokenizeError("the text is not valid Unicode", "undecodable_text") from error

    def _restore(self, workspace, text: str, depth: int) -> RestoreResult:
        report = workspace.restore_report(text)
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
                piece = self._restore(workspace, data[position:start].decode("utf-8"), depth + 1)
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
            workspace = self._load(create=False)
            if workspace is None:
                return [], len(matches)
            try:
                unknown = self._restore(workspace, text, depth=0).unknown
                spans = []
                for match in matches:
                    report = workspace.restore_report(match.group(0))
                    if report["issues"] or report["text"] is None:
                        continue
                    spans.append((match.start(), match.end(), base_entity(match.group(1).upper()), report["text"]))
                return spans, unknown
            except UnicodeError as error:
                raise TokenizeError("the text is not valid Unicode", "undecodable_text") from error

    def marker_counts(self, text: str) -> tuple[Counter, int]:
        """(known markers by type, unknown marker-like strings) in ``text``; changes nothing."""
        result = self.restore(text)
        return result.restored, result.unknown
