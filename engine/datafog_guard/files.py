"""Files on disk: deciding whether a file can be checked, and tokenized shadow copies for Read."""
from __future__ import annotations

import hashlib
import os
import stat
import time

from .store import atomic_write, secure_dir

# Read renders these itself (images, PDFs); their content cannot be checked as text.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".tif", ".ico", ".heic", ".avif", ".pdf",
}
SHADOW_MAX_AGE = 7 * 24 * 3600


def classify(path: str, max_bytes: int):
    """Return (kind, detail, text).

    kind is "absent" (nothing to check: missing or a directory; the tool reports that itself),
    "text" (with the decoded text) or "unscannable" (with a short reason that names no content).
    """
    try:
        info = os.stat(path)
    except OSError:
        return "absent", "", None
    if stat.S_ISDIR(info.st_mode):
        return "absent", "", None
    if not stat.S_ISREG(info.st_mode):
        return "unscannable", "it is not a regular file", None
    if os.path.splitext(path)[1].lower() in BINARY_EXTENSIONS:
        return "unscannable", "it is an image or PDF", None
    if info.st_size > max_bytes:
        return "unscannable", f"it is larger than the {max_bytes // 1024} KiB scan limit", None
    try:
        with open(path, "rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        return "unscannable", "it cannot be opened", None
    if len(data) > max_bytes:
        return "unscannable", f"it is larger than the {max_bytes // 1024} KiB scan limit", None
    if b"\x00" in data:
        return "unscannable", "it is a binary file", None
    try:
        return "text", "", data.decode("utf-8")
    except UnicodeDecodeError:
        return "unscannable", "it is not UTF-8 text", None


def _key(path: str) -> str:
    return hashlib.sha256(os.path.realpath(path).encode("utf-8", "surrogateescape")).hexdigest()[:20]


def write_shadow(shadow_dir: str, original: str, tokenized: str) -> str:
    """Write the tokenized copy (owner-only, same basename) and return its path."""
    secure_dir(shadow_dir)
    key = _key(original)
    folder = os.path.join(shadow_dir, key)
    secure_dir(folder)
    atomic_write(os.path.join(shadow_dir, key + ".origin"),
                 os.path.abspath(original).encode("utf-8", "surrogateescape"))
    shadow = os.path.join(folder, os.path.basename(original))
    atomic_write(shadow, tokenized.encode("utf-8"))
    return shadow


def original_of(shadow_dir: str, path: str) -> str | None:
    """If ``path`` is one of our shadow copies, the path of the real file; else None."""
    if not path or not shadow_dir:
        return None
    try:
        root = os.path.realpath(shadow_dir)
        real = os.path.realpath(path)
    except (OSError, ValueError):
        return None
    if not real.startswith(root + os.sep):
        return None
    key = real[len(root) + 1:].split(os.sep, 1)[0]
    try:
        with open(os.path.join(root, key + ".origin"), "rb") as handle:
            return handle.read().decode("utf-8", "surrogateescape")
    except OSError:
        return None


def is_inside(path: str, directory: str) -> bool:
    try:
        root = os.path.realpath(directory)
        real = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    return real == root or real.startswith(root + os.sep)


def clean_shadows(shadow_dir: str) -> None:
    """Remove shadow copies not rewritten for a week. They hold markers only, never real values."""
    try:
        names = os.listdir(shadow_dir)
    except OSError:
        return
    cutoff = time.time() - SHADOW_MAX_AGE
    for name in names:
        if not name.endswith(".origin"):
            continue
        path = os.path.join(shadow_dir, name)
        try:
            if os.stat(path).st_mtime < cutoff:
                import shutil
                shutil.rmtree(os.path.join(shadow_dir, name[:-7]), ignore_errors=True)
                os.unlink(path)
        except OSError:
            pass
