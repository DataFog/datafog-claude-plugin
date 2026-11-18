#!/bin/sh
# Create or verify the plugin's private Python environment.
#
#   bootstrap.sh <data dir> [--force]
#
# Idempotent. Fast path: when venv/.datafog-installed names the current requirement,
# nothing is done. Uses uv when it is installed, otherwise python -m venv and pip.
# Exit status 0 means the environment is ready.

DATA=$1
FORCE=$2
REQUIREMENT='datafog-core>=1.4.0,<1.5'
STAMP="$DATA/venv/.datafog-installed"

venv_python() {
  if [ -x "$DATA/venv/bin/python" ]; then echo "$DATA/venv/bin/python"
  elif [ -x "$DATA/venv/Scripts/python.exe" ]; then echo "$DATA/venv/Scripts/python.exe"
  fi
}

if [ "$FORCE" != "--force" ] && [ -n "$(venv_python)" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$REQUIREMENT" ]; then
  exit 0
fi

mkdir -p "$DATA" || { echo "datafog bootstrap: cannot create $DATA"; exit 1; }
chmod 700 "$DATA" 2>/dev/null

# One installer at a time. A lock older than ten minutes is treated as abandoned.
LOCK="$DATA/bootstrap.lock"
tries=0
while ! mkdir "$LOCK" 2>/dev/null; do
  if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +10 2>/dev/null)" ]; then rmdir "$LOCK" 2>/dev/null; continue; fi
  tries=$((tries + 1))
  if [ "$tries" -gt 240 ]; then echo "datafog bootstrap: another install is still running"; exit 1; fi
  sleep 0.5
done
trap 'rmdir "$LOCK" 2>/dev/null' EXIT INT TERM

# Another session may have finished the install while we waited.
if [ "$FORCE" != "--force" ] && [ -n "$(venv_python)" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$REQUIREMENT" ]; then
  exit 0
fi

echo "datafog bootstrap: installing $REQUIREMENT into $DATA/venv ($(date))"
rm -f "$STAMP"

find_python() {
  for candidate in python3.13 python3.12 python3.14 python3.11 python3.10 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

ok=1
if command -v uv >/dev/null 2>&1; then
  if [ -z "$(venv_python)" ] || [ "$FORCE" = "--force" ]; then
    SYSTEM_PYTHON=$(find_python) || SYSTEM_PYTHON='>=3.10'
    uv venv --quiet --allow-existing --python "$SYSTEM_PYTHON" "$DATA/venv" || ok=0
  fi
  [ "$ok" = 1 ] && { uv pip install --quiet --python "$(venv_python)" "$REQUIREMENT" || ok=0; }
else
  if [ -z "$(venv_python)" ] || [ "$FORCE" = "--force" ]; then
    SYSTEM_PYTHON=$(find_python) || {
      echo "datafog bootstrap: no Python 3.10 or later found. Install Python 3.10+ or uv (https://docs.astral.sh/uv/), then start a new session."
      exit 1
    }
    "$SYSTEM_PYTHON" -m venv "$DATA/venv" || ok=0
  fi
  [ "$ok" = 1 ] && { "$(venv_python)" -m pip install --quiet --disable-pip-version-check "$REQUIREMENT" || ok=0; }
fi

if [ "$ok" = 1 ] && "$(venv_python)" -c 'import datafog_core; datafog_core.scan("probe")' 2>/dev/null; then
  printf '%s' "$REQUIREMENT" > "$STAMP"
  echo "datafog bootstrap: ready"
  exit 0
fi
echo "datafog bootstrap: FAILED. To install by hand: create a Python 3.10+ virtual environment at $DATA/venv and run its pip: pip install '$REQUIREMENT'"
exit 1
