#!/bin/sh
# Locates the datafog-hook engine and execs it (hooks protocol: JSON on
# stdin, decision on stdout). $1 controls behavior when no engine is found:
#   warn   — tell the user how to install, exit 1 (non-blocking error)
#   silent — exit 0 so advisory hooks never nag
if command -v datafog-hook >/dev/null 2>&1; then
  exec datafog-hook
fi
if command -v uvx >/dev/null 2>&1; then
  exec uvx --from 'datafog>=4.6.0' datafog-hook
fi
if [ "$1" = "warn" ]; then
  echo 'datafog plugin: engine not installed — run: pip install datafog' >&2
  exit 1
fi
exit 0
