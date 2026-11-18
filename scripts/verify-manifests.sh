#!/bin/sh
# Validate both manifests explicitly: validating the repository directory may select
# only its marketplace. This does not execute plugin hooks or require model login.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLAUDE_BIN=${CLAUDE_BIN:-claude}
if ! command -v "$CLAUDE_BIN" >/dev/null 2>&1; then
  echo 'Claude Code is required. CI uses @anthropic-ai/claude-code@2.1.327.' >&2
  exit 1
fi
# Isolate validation from a developer's installed plugins/settings. Keep credentials
# out of CI: schema/directory-subset checks do not need an authenticated model call.
VALIDATION_CONFIG=$(mktemp -d)
trap 'rm -rf "$VALIDATION_CONFIG"' EXIT HUP INT TERM
export CLAUDE_CONFIG_DIR="$VALIDATION_CONFIG"
export DISABLE_AUTOUPDATER=1
"$CLAUDE_BIN" --version
"$CLAUDE_BIN" plugin validate --strict "$ROOT/.claude-plugin/plugin.json"
"$CLAUDE_BIN" plugin validate --strict "$ROOT/.claude-plugin/marketplace.json"
