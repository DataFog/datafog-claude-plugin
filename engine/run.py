"""Start the engine without trusting the current directory.

The launcher runs ``python -I engine/run.py <subcommand>``. Isolated mode keeps the project
directory (the hook's working directory), PYTHONPATH and the user site-packages out of the
import path, so a file in the project named like one of our imports cannot be loaded.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Compiled files go to the plugin data directory, never next to the sources or into the project.
_data = os.environ.get("DATAFOG_DATA_DIR") or os.environ.get("CLAUDE_PLUGIN_DATA")
if _data and not _data.startswith("${"):
    sys.pycache_prefix = os.path.join(_data, "pycache")
else:
    sys.dont_write_bytecode = True

from datafog_guard.__main__ import main  # noqa: E402

sys.exit(main())
