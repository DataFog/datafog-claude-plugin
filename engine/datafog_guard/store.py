"""Vault storage: datafog-core's encrypted application vault, plus a small marker index.

The values live in ``datafog_fogvault.ApplicationVault`` (a separate package of the core
project). It keeps one encrypted file per application, takes an OS file lock around every
change, and holds the 256-bit key in the operating system's key store (macOS Keychain, Secret
Service on Linux). This module is the only place that talks to it.

    <vault dir>/              0700
        workspace.enc         0600  ApplicationVault: XChaCha20-Poly1305 ciphertext of core's snapshot
        workspace.lock        0600  ApplicationVault: cross-process lock
        workspace.key         0600  ONLY with vault_key=file: the key, in the clear, beside the data
        markers.index         0600  ours: the markers issued so far (no values; see below)
        bash-restore.key      0600  ours: signs restore tickets for Bash commands (bashwrap.py)

What ApplicationVault 1.7 offers is: open, prepare_and_commit, restore, restore_report, forget,
head, operations, close. What it does not offer, and how this module fills the gap:

* No way to ask "is this value known, and what is its marker" without writing: every
  ``prepare_and_commit``, also for values it already holds, rewrites the whole encrypted
  file and uses one of roughly 100,000 operation records. So the engine must find known
  values itself. ``markers.index`` lists the markers issued (a marker is what the model
  sees; it is not a secret). Restoring all of them in one call gives the known values in
  memory, and only values that are really new are sent to ``prepare_and_commit``.
  The same list gives the entry counts for ``status`` and the known-value matching that
  core's ``Workspace.recall`` used to do (ApplicationVault has no recall).
  The index is a cache of facts the vault itself is the authority for: a marker missing from
  it (a crash between commit and append) is added again the next time its value is detected,
  because core gives a repeated value its old marker; a marker the vault does not know is
  ignored.
* No delete. ``purge`` removes the files under the vault's own lock and removes the key
  from the key store with the operating system's own tool, best effort.
* Every restore re-reads and decrypts the file. Callers batch markers into one call.

There is no unencrypted mode and no fallback to one. A plain-file vault written by a
development build (``HEAD``, ``meta.json``, ``snapshots/``) is never read; ``doctor`` reports it
and ``purge`` deletes it.
"""
from __future__ import annotations

import os
import re
import stat
import time

from . import APP_ID
from .errors import (
    EngineUnavailable,
    KeyStoreUnavailable,
    VaultBusy,
    VaultCorrupt,
    VaultError,
    VaultFull,
    VaultLocked,
)

MARKER_RE = re.compile(r"\[\[([A-Z][A-Z0-9_]*)_([0-9A-Z]{6})\]\]")
KEY_MODES = ("keystore", "file")
ENVELOPE, LOCK_FILE, KEY_FILE, INDEX_FILE = "workspace.enc", "workspace.lock", "workspace.key", "markers.index"
LEGACY_NAMES = ("HEAD", "meta.json", "snapshots", "lock")     # the unencrypted store of development builds
KEYSTORE_SERVICE = "DataFog.ApplicationVault.v1"               # the name core stores the key under
RESTORE_CHUNK_BYTES = 512 * 1024                               # core takes 1 MiB of text per call
_PROTECTION = {1: "credential_store", 2: "file_key", 3: "external_key"}
_INDEX_HEADER = "# datafog marker index v1 "


def atomic_write(path: str, data: bytes) -> None:
    """Write a file so readers see the old or the new content, never a mix. Owner-only."""
    directory = os.path.dirname(path)
    temp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    _fsync_dir(directory)


def _fsync_dir(directory: str) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def secure_dir(path: str) -> None:
    """Create a directory for the owner only, or check that an existing one is safe to use."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    if os.name == "nt":
        return   # relies on the user profile's ACLs; POSIX modes do not apply
    info = os.stat(path)
    if info.st_uid != os.getuid():
        raise VaultError("the vault directory belongs to another user", "vault_insecure")
    if info.st_mode & 0o077:
        os.chmod(path, 0o700)


class FileLock:
    """Exclusive cross-process lock on a file: fcntl on POSIX, msvcrt on Windows."""

    def __init__(self, path: str, timeout: float = 10.0):
        self.path = path
        self.timeout = timeout
        self._fd: int | None = None

    def __enter__(self) -> "FileLock":
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.timeout
        delay = 0.001
        try:
            while True:
                if self._try_lock(fd):
                    self._fd = fd
                    return self
                if time.monotonic() >= deadline:
                    raise VaultLocked("another process holds the vault lock")
                time.sleep(delay)
                delay = min(delay * 2, 0.05)
        except BaseException:
            if self._fd is None:
                os.close(fd)
            raise

    @staticmethod
    def _try_lock(fd: int) -> bool:
        if os.name == "nt":
            import msvcrt
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)   # type: ignore[attr-defined]
                return True
            except OSError:
                return False
        import fcntl
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def __exit__(self, *exc) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)   # type: ignore[attr-defined]
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _fogvault():
    try:
        import datafog_fogvault
    except Exception as error:   # no wheel for this machine, or a broken install
        from .support import UNSUPPORTED, platform_problem
        if platform_problem():
            raise EngineUnavailable(UNSUPPORTED, "unsupported_platform") from error
        raise EngineUnavailable("the datafog-fogvault library cannot be loaded; run the bootstrap command "
                                "shown at session start", "vault_library_unavailable") from error
    return datafog_fogvault


def vault_path(directory: str) -> str:
    """The directory as ApplicationVault must be given it: absolute, with symbolic links in the
    directories above it resolved (``/tmp`` and ``/var`` are links on macOS). The vault directory
    itself is not resolved: core refuses a vault directory that is a symbolic link, and so do we.
    """
    directory = os.path.abspath(directory)
    parent, name = os.path.split(directory.rstrip(os.sep) or os.sep)
    return os.path.join(os.path.realpath(parent), name) if name else directory


def read_envelope_header(directory: str) -> dict | None:
    """What the encrypted file says about itself in the clear: ids, revision, key mode. No key needed."""
    fd = None
    try:
        fd = os.open(os.path.join(directory, ENVELOPE), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return {"state": "vault_insecure"}
        head = os.read(fd, 512)
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)
    return _parse_envelope_header(head)


def _parse_envelope_header(head: bytes) -> dict:
    try:
        if head[:8] != b"DFAPP001":
            return {"state": "vault_unsupported"}
        size = head[12]
        end = 13 + size
        return {"state": "ok", "app_id": head[13:end].decode("ascii"), "vault_id": head[end:end + 16].hex(),
                "revision": int.from_bytes(head[end + 32:end + 40], "little"),
                "protection": _PROTECTION.get(head[end + 56], "unknown")}
    except (IndexError, UnicodeError):
        return {"state": "vault_corrupt"}


def legacy_plain_store(directory: str) -> bool:
    """True when the directory holds the unencrypted file store of a development build."""
    return os.path.isfile(os.path.join(directory, "HEAD")) or os.path.isdir(os.path.join(directory, "snapshots"))


_MESSAGES = {
    "credential_store_unavailable": (
        KeyStoreUnavailable,
        "the operating system's key store, where the vault's key is kept, is locked, not available or refused "
        "access (macOS: the login Keychain; Linux: a Secret Service such as GNOME Keyring). Unlock it or allow "
        "access and try again. On a machine without one, see vault_key in the README"),
    "key_required": (
        VaultError,
        "the vault's key is missing or the vault was created with a different vault_key setting (keystore or "
        "file) than the one in use now. Use the setting it was created with, or delete the vault with "
        "/datafog:purge"),
    "vault_integrity": (
        VaultCorrupt,
        "the encrypted vault file is damaged, or the key in the key store is not the key it was written with"),
    "unsupported_envelope": (VaultError, "the vault file was written by a version this plugin cannot read"),
    "unsafe_permissions": (
        VaultError,
        "the vault directory or a file in it is open to other users, is not yours or is not a regular file; "
        "the plugin does not repair this by itself (expected: directory 0700, files 0600)"),
    "unsafe_path": (VaultError, "the vault directory is not a safe path (it must be absolute and not a symbolic link)"),
    "storage_error": (
        VaultError,
        "the vault cannot be read or written (the disk, or a directory above the vault that this user cannot list)"),
    "vault_busy": (VaultLocked, "another process holds the vault lock"),
    "workspace_conflict": (VaultBusy, "the vault changed while it was being updated"),
    "invalid_app_id": (VaultError, "internal: the application id was refused"),
    "invalid_key": (VaultError, "internal: the key was refused"),
}
_CODES = {"credential_store_unavailable": "keystore_unavailable", "key_required": "vault_key_mismatch",
          "unsafe_permissions": "vault_insecure", "unsafe_path": "vault_insecure",
          "storage_error": "vault_unreadable", "unsupported_envelope": "vault_unsupported"}
# After these the handle is dead or stale (closed by core, or the vault was replaced under it).
_REOPEN = ("owner_closed", "outcome_unknown", "saved_but_not_activated", "vault_integrity", "storage_error",
           "key_required")


class StoreError(Exception):
    """A core error by its controlled code. Core's messages are codes only; nothing else is kept."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _translate(error: BaseException) -> VaultError:
    code = str(getattr(error, "code", "") or "unknown")
    if code not in _MESSAGES:
        return VaultError("the vault reported an error", "vault_" + re.sub(r"[^a-z0-9_]", "", code)[:40])
    kind, message = _MESSAGES[code]
    return kind(message, _CODES.get(code))


def _flock(fd: int, timeout: float) -> None:
    """Exclusive lock on an open file, released when the descriptor is closed."""
    import fcntl
    deadline = time.monotonic() + timeout
    delay = 0.001
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise VaultLocked("another process holds the vault lock") from None
            time.sleep(delay)
            delay = min(delay * 2, 0.05)


class EncryptedStore:
    """One process's handle on the application vault and its marker index.

    Not safe for concurrent use from several threads; :class:`~datafog_guard.vault.Vault` serialises.
    """

    def __init__(self, directory: str, key_mode: str = "keystore", lock_timeout: float = 10.0):
        if key_mode not in KEY_MODES:
            raise VaultError("vault_key must be keystore or file", "config_error")
        self.directory = vault_path(directory)
        self.key_mode = key_mode
        self.lock_timeout = lock_timeout
        self._owner = None
        self._index_path = os.path.join(self.directory, INDEX_FILE)

    # -- opening -----------------------------------------------------------
    def exists(self) -> bool:
        return os.path.isfile(os.path.join(self.directory, ENVELOPE))

    def _prepare_directory(self) -> None:
        """Create the directory private, or tighten one that does not hold a vault yet.

        A directory the user made with plain ``mkdir`` is 0755. Core refuses it and repairs
        nothing; before any vault exists there is nothing to protect yet, so it is made private
        here. A loose directory that already holds a vault is left for core to refuse.
        """
        if os.name == "nt" or os.path.islink(self.directory):
            return
        try:
            info = os.stat(self.directory)
        except FileNotFoundError:
            try:
                os.makedirs(self.directory, mode=0o700, exist_ok=True)
            except OSError as error:
                raise VaultError("the vault directory cannot be created", "vault_unreadable") from error
            return
        if info.st_uid == os.geteuid() and info.st_mode & 0o077 and not self.exists():
            os.chmod(self.directory, 0o700)

    def open(self, create: bool):
        """The open vault, or None when there is none and ``create`` is false.

        Opening is the health check: the directory and files are private, the lock can be taken,
        the key is available from where the vault says it is, and the file decrypts.
        """
        if self._owner is not None:
            # A long-lived process: another process may have purged the vault, or replaced it.
            header = read_envelope_header(self.directory)
            if header is not None and header.get("vault_id") == self.vault_id():
                return self._owner
            self.close()
        if not create and not self.exists():
            return None
        fogvault = _fogvault()
        self._prepare_directory()
        deadline = time.monotonic() + self.lock_timeout
        while True:
            try:
                owner = fogvault.ApplicationVault.open(APP_ID, directory=self.directory,
                                                       allow_file_key=self.key_mode == "file")
                break
            except fogvault.FogVaultWorkspaceError as error:
                if error.code == "vault_busy" and time.monotonic() < deadline:
                    continue
                raise _translate(error) from None
        mode = owner.protection_mode
        if mode != {"keystore": "credential_store", "file": "file_key"}[self.key_mode]:
            owner.close()                 # never reached with core 1.7, which refuses first; kept as a guard
            raise VaultError(_MESSAGES["key_required"][1], "vault_key_mismatch")
        self._owner = owner
        return owner

    def close(self) -> None:
        owner, self._owner = self._owner, None
        if owner is not None:
            try:
                owner.close()
            except Exception:
                pass

    @property
    def protection(self) -> str | None:
        """"credential_store" or "file_key" for an open vault."""
        return self._owner.protection_mode if self._owner is not None else None

    def vault_id(self) -> str | None:
        return self._owner.vault_id.hex() if self._owner is not None else None

    def _call(self, create: bool, action, retry_busy: bool = True):
        """Run ``action(owner)``. Reopens once when the handle went stale, waits out a busy lock."""
        fogvault = _fogvault()
        deadline = time.monotonic() + self.lock_timeout
        reopened = False
        conflicts = 0
        while True:
            owner = self.open(create)
            if owner is None:
                raise StoreError("no_vault")
            try:
                return action(owner)
            except fogvault.FogVaultWorkspaceError as error:
                code = str(error.code)
                if code in _REOPEN:
                    self.close()
                    if not reopened:
                        reopened = True
                        continue
                    raise _translate(error) from None
                if code == "vault_busy" and retry_busy and time.monotonic() < deadline:
                    continue
                if code == "workspace_conflict" and conflicts < 20 and time.monotonic() < deadline:
                    conflicts += 1
                    continue
                if code in _MESSAGES:
                    raise _translate(error) from None
                raise StoreError(code) from None

    # -- the three things the engine needs -------------------------------------
    def commit(self, pairs: list[tuple[str, str]]) -> list[str]:
        """Store (entity, value) pairs; returns their markers in order. Durable before it returns.

        A value core already holds (compared loosely: case and white space) gets its old marker.
        Raises StoreError with core's code when core refuses the values.
        """
        separator = "\x1e%s\x1e" % os.urandom(8).hex()
        findings, offset, step = [], 0, len(separator)
        for entity, value in pairs:
            size = len(value.encode("utf-8"))
            findings.append({"entityType": entity, "matchedText": value,
                             "range": {"unit": "utf8_bytes", "start": offset, "end": offset + size}})
            offset += size + step
        text = separator.join(value for _, value in pairs)
        try:
            output = self._call(True, lambda owner: owner.prepare_and_commit(text, findings, os.urandom(16), True))
        except StoreError as error:
            if error.code == "resource_limit":
                raise VaultFull(
                    "the vault is full (core allows 20,000 values and about 100,000 changes per vault); new "
                    "values cannot be protected until it is emptied with /datafog:purge") from None
            raise
        markers = output.split(separator)
        if len(markers) != len(pairs) or not all(MARKER_RE.fullmatch(marker) for marker in markers):
            raise StoreError("unexpected_markers")
        return markers

    def restore_report(self, text: str) -> dict:
        """Core's restore report: ``text`` (None when there are issues) and ``issues`` with byte ranges."""
        return self._call(False, lambda owner: owner.restore_report(text))

    def values_for(self, markers: list[str]) -> dict[str, str]:
        """marker -> real value, for the markers the vault knows. Unknown ones are left out.

        One call to core per chunk (two when a chunk holds unknown markers), because every
        call re-reads and decrypts the vault file.
        """
        found: dict[str, str] = {}
        chunk: list[str] = []
        size = 0
        for marker in list(dict.fromkeys(markers)) + [None]:   # type: ignore[list-item]
            if marker is None or size + len(marker) + 20 > RESTORE_CHUNK_BYTES:
                if chunk:
                    self._restore_chunk(chunk, found)
                chunk, size = [], 0
            if marker is not None:
                chunk.append(marker)
                size += len(marker) + 20
        return found

    def _restore_chunk(self, markers: list[str], found: dict[str, str]) -> None:
        for _ in range(4):
            if not markers:
                return
            separator = "\x1e%s\x1e" % os.urandom(8).hex()
            starts, offset = [], 0
            for marker in markers:
                starts.append(offset)
                offset += len(marker) + len(separator)      # markers and the separator are ASCII
            report = self.restore_report(separator.join(markers))
            issues = report["issues"]
            if not issues and report["text"] is not None:
                values = report["text"].split(separator)
                if len(values) != len(markers):
                    continue                                 # a value held the separator: draw another
                found.update(zip(markers, values))
                return
            from bisect import bisect_right
            bad = {bisect_right(starts, issue["byteRange"]["start"]) - 1 for issue in issues}
            if not bad:
                raise StoreError("restore_failed")
            markers = [marker for index, marker in enumerate(markers) if index not in bad]
        raise StoreError("restore_failed")

    # -- the marker index --------------------------------------------------------
    def index_stamp(self):
        """Changes whenever the index file does. Cheap: one stat."""
        try:
            info = os.stat(self._index_path)
        except OSError:
            return None
        return (info.st_ino, info.st_size, info.st_mtime_ns)

    def read_index(self) -> list[str]:
        """The markers issued from the open vault, oldest first. Empty when the index is another vault's."""
        fd = None
        try:
            fd = os.open(self._index_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise VaultError("the marker index is not a regular file", "vault_insecure")
            with os.fdopen(fd, "rb") as handle:
                fd = None
                lines = handle.read().decode("ascii", "replace").split("\n")
        except OSError:
            return []
        finally:
            if fd is not None:
                os.close(fd)
        if lines[0] != _INDEX_HEADER + str(self.vault_id()):
            return []
        return list(dict.fromkeys(line for line in lines[1:] if MARKER_RE.fullmatch(line)))

    def add_to_index(self, markers: list[str]):
        """Append markers under an exclusive lock on the index file; an index of another vault is replaced.

        Returns (stamp before, stamp after), so a caller whose copy matched "before" knows its
        copy plus these markers matches "after".
        """
        if not markers or self._owner is None:
            return None, None
        header = (_INDEX_HEADER + str(self.vault_id()) + "\n").encode("ascii")
        fd = os.open(self._index_path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            _flock(fd, self.lock_timeout)
            info = os.fstat(fd)
            before = (info.st_ino, info.st_size, info.st_mtime_ns)
            payload = b""
            if os.pread(fd, len(header), 0) != header:
                os.ftruncate(fd, 0)
                payload = header
            elif os.pread(fd, 1, info.st_size - 1) != b"\n":
                payload = b"\n"                               # a torn last line from a crash: end it
            payload += "".join(marker + "\n" for marker in markers).encode("ascii")
            os.write(fd, payload)
            os.fsync(fd)
            info = os.fstat(fd)
            return before, (info.st_ino, info.st_size, info.st_mtime_ns)
        finally:
            os.close(fd)                                      # also releases the lock

    # -- describing and deleting ---------------------------------------------------
    def describe(self) -> dict:
        """State without opening the vault (no key needed): safe to call when it is broken."""
        info: dict = {"backend": "application-vault", "directory": self.directory, "encrypted_at_rest": True,
                      "legacy_plain_store": legacy_plain_store(self.directory)}
        header = read_envelope_header(self.directory)
        if header is None:
            info["state"] = "empty"
            return info
        info.update(header)
        try:
            info["bytes"] = os.stat(os.path.join(self.directory, ENVELOPE)).st_size
        except OSError:
            pass
        return info

    def purge(self) -> dict:
        """Delete the vault, its marker index, its key and any plain store of a development build.

        Returns {"existed", "legacy", "keystore"}; ``keystore`` is "none" (no key there), "removed",
        or "left" (the key store entry could not be removed; it is 32 random bytes that open
        nothing once the vault file is gone).
        """
        result: dict = {"existed": False, "legacy": False, "keystore": "none", "account": ""}
        self.close()
        directory_fd = None
        lock_fd = None
        try:
            try:
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            except FileNotFoundError:
                return result
            info = os.fstat(directory_fd)
            if info.st_uid != os.geteuid():
                raise VaultError("the vault directory belongs to another user", "vault_insecure")
            lock_fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                              0o600, dir_fd=directory_fd)
            info = os.fstat(lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise VaultError("the vault lock is not a safe regular file", "vault_insecure")
            _flock(lock_fd, self.lock_timeout)
            header = None
            try:
                info = os.stat(ENVELOPE, dir_fd=directory_fd, follow_symlinks=False)
                result["existed"] = True
                if stat.S_ISREG(info.st_mode):
                    fd = os.open(ENVELOPE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                    try:
                        if not stat.S_ISREG(os.fstat(fd).st_mode):
                            raise VaultError("the vault file is not a regular file", "vault_insecure")
                        header = _parse_envelope_header(os.read(fd, 512))
                    finally:
                        os.close(fd)
            except FileNotFoundError:
                pass

            def remove_file(name: str, parent: int = directory_fd) -> None:
                try:
                    os.unlink(name, dir_fd=parent)
                except FileNotFoundError:
                    pass

            for name in (ENVELOPE, KEY_FILE, INDEX_FILE, "bash-restore.key"):   # the data first
                remove_file(name)
            try:
                info = os.stat("snapshots", dir_fd=directory_fd, follow_symlinks=False)
                result["legacy"] = True
                if stat.S_ISDIR(info.st_mode):
                    snapshots_fd = os.open("snapshots", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                           dir_fd=directory_fd)
                    try:
                        for name in os.listdir(snapshots_fd):
                            remove_file(name, snapshots_fd)
                        os.fsync(snapshots_fd)
                    finally:
                        os.close(snapshots_fd)
                    os.rmdir("snapshots", dir_fd=directory_fd)
                else:
                    remove_file("snapshots")
            except FileNotFoundError:
                pass
            for name in ("HEAD", "meta.json", "lock"):
                try:
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    result["legacy"] = True
                except FileNotFoundError:
                    pass
                remove_file(name)
            os.fsync(directory_fd)
            if header and header.get("protection") == "credential_store" and header.get("app_id") == APP_ID \
                    and header.get("vault_id"):
                result["account"] = f"{APP_ID}/{header['vault_id']}"
                result["keystore"] = "removed" if remove_keystore_entry(result["account"]) else "left"
            return result
        except OSError as error:
            raise VaultError("the vault could not be fully deleted; check its directory and file permissions",
                             "purge_failed") from error
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            if directory_fd is not None:
                os.close(directory_fd)


def remove_keystore_entry(account: str) -> bool:
    """Remove the vault key from the OS key store. ApplicationVault 1.7 has no call for this, so the
    system's own tool is used. The account is ``<app id>/<vault id>``: not a secret."""
    import shutil
    import subprocess
    import sys
    if sys.platform == "darwin":
        argv = ["/usr/bin/security", "delete-generic-password", "-s", KEYSTORE_SERVICE, "-a", account]
    elif shutil.which("secret-tool"):
        argv = ["secret-tool", "clear", "service", KEYSTORE_SERVICE, "username", account]
    else:
        return False
    try:
        return subprocess.run(argv, capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
