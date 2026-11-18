#!/bin/bash
# Double-click (macOS) or run from a terminal to check the DataFog plugin against your
# real Claude Code, unattended.
#
# It runs tests/live/run_live.py from this checkout in a fresh temp dir: about 29 short
# headless `claude -p` runs against a throwaway project of synthetic files, with a
# temporary vault. Your real vault, your Keychain and your plugin data are not touched: the
# temporary vault keeps its key in a file. Hard caps: 30 runs, 180 s each, 30 minutes in
# total. It uses your Claude Code login and usage.
#
# Optional: LIVE_KEYCHAIN=1 adds one case that stores the key of a second throwaway vault in
# your real Keychain (one new entry, removed again at the end). This is the only way to see
# the Keychain prompts and timing a real user gets. Run it from a terminal:
#     LIVE_KEYCHAIN=1 tests/live/run-live.command
#
# Results are copied to <repo>/.live/results/ (results.md first; DONE or ABORTED is the
# last file written). Needs: python3, Claude Code 2.1.295+, and uv or Python 3.10+ with
# access to PyPI for the plugin's private environment.
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS="$REPO/.live/results"
PATH="$PATH:$HOME/.local/bin:$HOME/.claude/local:$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin"
export PATH

TMP="$(mktemp -d "${TMPDIR:-/tmp}/datafog-live.XXXXXX")" || { echo "LIVE ABORTED: mktemp failed"; exit 1; }
if [ -e "$RESULTS" ]; then mv "$RESULTS" "$REPO/.live/results-previous-$(date +%Y%m%d-%H%M%S)"; fi
mkdir -p "$RESULTS"

{
  echo "DataFog plugin live check, unattended run. Started: $(date)"
  echo "repo: $REPO   commit: $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)   temp dir: $TMP"
  if ! command -v python3 > /dev/null 2>&1; then
    echo "LIVE ABORTED: python3 not found on PATH"
  else
    python3 "$REPO/tests/live/run_live.py" "$TMP"
  fi
  echo "Finished: $(date)"
} 2>&1 | tee "$TMP/driver.log"

# Copy the evidence next to the repo. Everything in it is synthetic test data.
for name in results.md results.json status.txt seed.json bootstrap.txt plugin-validate.txt; do
  if [ -f "$TMP/log/$name" ]; then cp "$TMP/log/$name" "$RESULTS/$name"; fi
done
if [ -d "$TMP/log/runs" ]; then cp -R "$TMP/log/runs" "$RESULTS/runs"; fi
if [ -f "$TMP/data/log/guard.log" ]; then cp "$TMP/data/log/guard.log" "$RESULTS/guard.log"; fi
cp "$TMP/driver.log" "$RESULTS/driver.log"

FINAL="$(grep -E '^LIVE (DONE|ABORTED)' "$TMP/driver.log" | tail -n 1)"
case "$FINAL" in
  "LIVE DONE"*) echo "DONE $(date)" > "$RESULTS/DONE" ;;
  "LIVE ABORTED"*) echo "${FINAL#LIVE ABORTED: }" > "$RESULTS/ABORTED" ;;
  *) FINAL="LIVE ABORTED: the driver ended without a status line"; echo "${FINAL#LIVE ABORTED: }" > "$RESULTS/ABORTED" ;;
esac

echo
echo "$FINAL"
echo "Results: $RESULTS/results.md"
if [ -t 0 ]; then read -r -p "Press Return to close this window. " _; fi
