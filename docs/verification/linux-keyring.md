# Private Linux keyring regression verification

On 2026-11-18, all six tests in `tests/test_keystore.py` passed inside an isolated
Ubuntu 24.04 `linux/amd64` Docker container, emulated on the development host.
Environment: Python 3.12.3, glibc 2.39 (Ubuntu 2.39-0ubuntu8.9),
gnome-keyring-daemon 46.1, `datafog-core==1.7.0`, and `datafog-fogvault==1.7.0`.
The repository was mounted read-only; the venv, test homes, D-Bus sessions,
keyrings, and vaults lived in the disposable container. No host credentials,
configuration directories, or keychains were mounted. This focused result does
not substitute for the final candidate's Linux CI matrix.

Command (inside the container):

```sh
/tmp/test-env/bin/python -m pytest tests/test_keystore.py -q \
  -p no:cacheprovider --basetemp=/tmp/datafog-keystore-tests-protocol2
```

Result: six tests passed, none skipped. The host Ruff check for the changed test
also passed.

## Fixture failure and correction

The earlier Linux CI failure occurred during recovery after the locked-vault
probe. The fixture discarded the daemon's control location and used the invalid
`XDG_RUN_DIR` variable. It now sets `XDG_RUNTIME_DIR`, uses an explicit private
`GNOME_KEYRING_CONTROL` directory with mode 0700, and checks that the expected
control socket exists. During diagnosis, mode 0755 caused the daemon to silently
select a different directory, despite returning success.

A second `gnome-keyring-daemon --unlock` invocation did not unlock the existing
private daemon. Its zero exit status and matching control-directory output were
insufficient evidence of recovery. The test now sends GNOME's existing-daemon
UNLOCK request directly to that fixture's Unix control socket, with a bounded
socket timeout and an asserted success response. The synthetic password includes
the same newline used at fixture startup. No developer password is involved.

The test verifies the default collection actually contains the DataFog items,
checks the real `Locked` property before and after locking, and opens the vault
in a bounded fresh subprocess. Before attempting recovery, it asserts
`keystore_unavailable`, a still-locked collection, unchanged encrypted data and
header, and no file-key fallback. It then verifies actual unlock, restoration of
the original marker, and unchanged key-store entries. A timeout fails the test;
it is not treated as fail-closed evidence.

Protocol and behavior references:

- [GNOME control client](https://github.com/GNOME/gnome-keyring/blob/46.2/daemon/control/gkd-control-client.c)
- [GNOME control operation/result codes](https://github.com/GNOME/gnome-keyring/blob/46.2/daemon/control/gkd-control-codes.h)
- [GNOME daemon initialization](https://github.com/GNOME/gnome-keyring/blob/46.2/daemon/gkd-main.c)
- [Secret Service methods](https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Service.html)
- [Collection Locked property](https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Collection.html)

The control protocol is GNOME-specific test infrastructure. This evidence does
not claim KWallet or other Secret Service implementations were exercised.
