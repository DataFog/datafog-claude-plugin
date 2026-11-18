# DataFog guard: wrapper for the Bash tool. Sourced, not executed. bash (3.2+) and zsh.
#
#   . wrap.sh && __datafog_run <launcher> <data dir> <vault dir> <command> [<restore ticket>]
#
# <command> is the text the model wrote; markers such as [[EMAIL_7KQ4ZM]] are still markers
# here. With a restore ticket (made by the PreToolUse hook for exactly this command) the
# runner puts the real values in, inside its own process, just before the child shell reads
# the command. They never appear in this shell: not in its arguments, variables or
# environment.
#
# The command does NOT run in this shell. It runs in a separate child shell whose only
# stdout and stderr are pipes read by the DataFog filter, so nothing it does (traps, saved
# file descriptors, /dev/stdout) can reach the output Claude Code captures. See
# engine/datafog_guard/filtercmd.py.
#
# Carried over from the child: its exit status and its final working directory.
# Not carried over: variables, functions, aliases, shell options.
#
# Fail closed: if the filter cannot start, the command is not run and the status is 125.

__datafog_run() {
  __df_cwd=$(mktemp "${TMPDIR:-/tmp}/datafog-cwd.XXXXXXXX") || {
    echo "datafog: cannot create a temporary file; the command was not run" >&2
    return 125
  }
  if [ -n "${5:-}" ]; then
    "$1" --data-dir "$2" --vault-dir "$3" run --cwd-file "$__df_cwd" --restore "$5" "$4"
  else
    "$1" --data-dir "$2" --vault-dir "$3" run --cwd-file "$__df_cwd" "$4"
  fi
  __df_rc=$?
  if [ -s "$__df_cwd" ]; then
    __df_dir=$(cat "$__df_cwd")
    [ -d "$__df_dir" ] && cd -- "$__df_dir"
  fi
  rm -f "$__df_cwd"
  return "$__df_rc"
}
