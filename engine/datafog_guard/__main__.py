"""Entry point: ``python -m datafog_guard <subcommand>``.

Each subcommand imports only what it needs, to keep hook start-up short.
"""
import sys


def main() -> int:
    argv = sys.argv[1:]
    command = argv[0] if argv else ""
    if command == "hook":
        from .hook import main as run
        return run()
    if command in ("filter", "run"):
        from .filtercmd import main as run_filter
        return run_filter(argv)
    if command == "mcp":
        from .mcp_server import main as run
        return run()
    if command in ("status", "purge", "doctor"):
        from .cli import main as run_cli
        return run_cli(argv)
    sys.stderr.write("usage: datafog_guard hook | filter | run | mcp | status | purge | doctor\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
