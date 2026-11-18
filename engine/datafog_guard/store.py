"""Vault storage.

The engine talks to storage through :class:`VaultStore`, whose only write is
compare-and-save on the workspace head. That is all a backend has to offer,
so core's own vault helper or a remote store can replace the file store later.

The v1 backend is :class:`FileVaultStore`: a directory holding core's snapshot
bytes unmodified, a pointer file naming the current snapshot, and a small
metadata file. It is NOT encrypted at rest; it relies on owner-only file
permissions.

    <vault dir>/              0700
        meta.json             0600  vault id, app id, contract version, created
        HEAD                  0600  {revision, commit_id, snapshot, sha256, annotations}
        snapshots/<rev>-<commit>.dfv   0600  core's bundle bytes, unmodified
        lock                  0600  cross-process lock for compare-and-save

A save writes the new snapshot (temp file, fsync, rename) and then replaces
HEAD the same way. HEAD is the commit point: a crash before it leaves an
unreferenced snapshot file and the old vault intact.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import namedtuple

from . import APP_ID
from .errors import VaultCorrupt, VaultError, VaultLocked


class Head(namedtuple("Head", "revision commit_id")):
    """A workspace head: revision number and commit id (hex)."""
    __slots__ = ()

    def name(self) -> str:
        return f"{self.revision:012d}-{self.commit_id}"


class Snapshot:
    def __init__(self, head: Head, bundle: bytes, annotations: dict | None = None):
        self.head = head
        self.bundle = bundle                      # core's snapshot bytes, unmodified
        self.annotations = annotations or {}      # small non-secret counters (types and counts)


class VaultStore:
    """The storage interface. Its only write is compare-and-save on the workspace head."""

    def peek_head(self) -> Head | None:
        """The current head without the snapshot bytes (cheap), or None for an empty vault."""
        raise NotImplementedError

    def load(self) -> Snapshot | None:
        """The current snapshot, or None for an empty vault."""
        raise NotImplementedError

    def compare_and_save(self, expected: Head | None, new: Head, bundle: bytes, annotations: dict) -> bool:
        """Save ``bundle`` as head ``new`` only if the stored head is still ``expected``.

        Returns False, changing nothing, when the head moved (the caller reloads and retries).
        """
        raise NotImplementedError


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


class FileVaultStore(VaultStore):
    def __init__(self, directory: str, lock_timeout: float = 10.0):
        self.directory = directory
        self.lock_timeout = lock_timeout
        self._head_path = os.path.join(directory, "HEAD")
        self._meta_path = os.path.join(directory, "meta.json")
        self._snapshots = os.path.join(directory, "snapshots")
        self._lock_path = os.path.join(directory, "lock")

    # -- reading ---------------------------------------------------------
    def _read_pointer(self) -> dict | None:
        try:
            with open(self._head_path, "rb") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise VaultError("the vault cannot be read", "vault_unreadable") from error
        try:
            pointer = json.loads(raw)
            Head(int(pointer["revision"]), str(pointer["commit_id"]))
            str(pointer["snapshot"]), str(pointer["sha256"])
        except (ValueError, KeyError, TypeError) as error:
            raise VaultCorrupt("the vault pointer file is damaged") from error
        return pointer

    def peek_head(self) -> Head | None:
        pointer = self._read_pointer()
        return Head(int(pointer["revision"]), str(pointer["commit_id"])) if pointer else None

    def load(self) -> Snapshot | None:
        for _ in range(8):
            pointer = self._read_pointer()
            if pointer is None:
                return None
            name = os.path.basename(pointer["snapshot"])
            try:
                with open(os.path.join(self._snapshots, name), "rb") as handle:
                    bundle = handle.read()
            except FileNotFoundError:
                # A writer replaced HEAD and removed the snapshot we were about to read.
                if self._read_pointer() == pointer:
                    raise VaultCorrupt("the vault snapshot file is missing")
                continue
            except OSError as error:
                raise VaultError("the vault cannot be read", "vault_unreadable") from error
            if hashlib.sha256(bundle).hexdigest() != pointer["sha256"]:
                raise VaultCorrupt("the vault snapshot does not match its checksum")
            annotations = pointer.get("annotations")
            return Snapshot(Head(int(pointer["revision"]), str(pointer["commit_id"])), bundle,
                            annotations if isinstance(annotations, dict) else {})
        raise VaultError("the vault kept changing while it was read", "vault_busy")

    def metadata(self) -> dict:
        try:
            with open(self._meta_path, encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    # -- writing ---------------------------------------------------------
    def _prepare_dirs(self) -> None:
        secure_dir(self.directory)
        secure_dir(self._snapshots)

    def lock(self) -> FileLock:
        self._prepare_dirs()
        return FileLock(self._lock_path, self.lock_timeout)

    def compare_and_save(self, expected: Head | None, new: Head, bundle: bytes, annotations: dict) -> bool:
        with self.lock():
            pointer = self._read_pointer()
            current = Head(int(pointer["revision"]), str(pointer["commit_id"])) if pointer else None
            if current != expected:
                return False
            if not os.path.exists(self._meta_path):
                from datafog_core import workspace_contract_version
                meta = {"vault_id": os.urandom(16).hex(), "app_id": APP_ID,
                        "contract_version": workspace_contract_version(),
                        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "format": "datafog-file-vault-1", "encrypted_at_rest": False}
                atomic_write(self._meta_path, json.dumps(meta, indent=2).encode("utf-8"))
            name = new.name() + ".dfv"
            atomic_write(os.path.join(self._snapshots, name), bundle)
            new_pointer = {"revision": new.revision, "commit_id": new.commit_id, "snapshot": name,
                           "sha256": hashlib.sha256(bundle).hexdigest(), "annotations": annotations}
            atomic_write(self._head_path, json.dumps(new_pointer, sort_keys=True).encode("utf-8"))   # commit point
            self._collect_garbage(keep={name, os.path.basename(pointer["snapshot"]) if pointer else name})
            return True

    def _collect_garbage(self, keep: set[str]) -> None:
        """Remove old snapshots. The previous one stays so a reader that just read HEAD still finds it."""
        try:
            names = os.listdir(self._snapshots)
        except OSError:
            return
        now = time.time()
        for name in names:
            if name in keep:
                continue
            path = os.path.join(self._snapshots, name)
            try:
                if name.endswith(".tmp") and now - os.stat(path).st_mtime < 300:
                    continue   # possibly another writer's file in progress
                os.unlink(path)
            except OSError:
                pass

    def purge(self) -> bool:
        """Delete the vault. Markers issued from it can never be restored afterwards."""
        if not os.path.isdir(self.directory):
            return False
        with self.lock():
            existed = os.path.exists(self._head_path)
            for path in (self._head_path, self._meta_path):   # HEAD first: the vault is gone from here on
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            try:
                for name in os.listdir(self._snapshots):
                    os.unlink(os.path.join(self._snapshots, name))
            except OSError:
                pass
            return existed

    def describe(self) -> dict:
        info: dict = {"backend": "file", "directory": self.directory, "encrypted_at_rest": False}
        try:
            pointer = self._read_pointer()
        except VaultError as error:
            info["state"] = error.code
            return info
        if pointer is None:
            info["state"] = "empty"
            return info
        info["state"] = "ok"
        info["revision"] = pointer["revision"]
        try:
            info["bytes"] = os.stat(os.path.join(self._snapshots, os.path.basename(pointer["snapshot"]))).st_size
        except OSError:
            info["state"] = "vault_corrupt"
        info.update({key: value for key, value in self.metadata().items() if key in ("vault_id", "created", "app_id")})
        return info
