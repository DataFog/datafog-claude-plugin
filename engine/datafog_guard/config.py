"""Settings: where things live and what is protected.

Order of precedence, lowest first:
  1. built-in defaults
  2. ``<data dir>/runtime.json``   plugin options, saved by the hooks because the Bash
                                   filter and the MCP server do not receive them
  3. ``<data dir>/config.json``    the user's own config file
  4. ``CLAUDE_PLUGIN_OPTION_*``    plugin options (present in hook processes only)
  5. ``DATAFOG_*``                 environment overrides

Nothing here imports the detector, so it is cheap to load.
"""
from __future__ import annotations

import json
import os
import sys

DEFAULT_ENTITIES = (
    "EMAIL", "PHONE", "SSN", "CREDIT_CARD", "API_KEY", "BEARER_TOKEN", "JWT", "PRIVATE_KEY",
    "CREDENTIAL_URI", "US_ROUTING_NUMBER", "NPI", "ACCOUNT_NUMBER",
)
# Supported, but off by default because they are noisy in code.
NOISY_ENTITIES = ("DATE", "IP_ADDRESS", "ZIP_CODE", "STREET_ADDRESS", "UUID")

UNSCANNABLE_POLICIES = ("ask", "deny", "allow")
BASH_WRAPS = ("runner", "off")
RESTORE_IN_BASH = ("ask", "allow", "off")
# What happens when a Bash command contains markers. Restoring them lets a manipulated model
# compute on real values (`echo [[EMAIL_X]] | base64`), so the default is to ask the user.
DEFAULT_RESTORE_IN_BASH = "ask"
MIB = 1024 * 1024


class Settings:
    """Resolved settings. A plain class: importing dataclasses costs more than the rest of the hook."""

    def __init__(self, data_dir: str, vault_dir: str, vault_location: str, plugin_root: str,
                 keep_vault_on_uninstall: bool = True, problems: list[str] | None = None):
        self.data_dir = data_dir
        self.vault_dir = vault_dir
        self.vault_location = vault_location        # "env" | "user-data" | "plugin-data"
        self.plugin_root = plugin_root
        self.entities: tuple[str, ...] = DEFAULT_ENTITIES
        self.allowlist: frozenset[str] = frozenset()
        self.unscannable_policy = "ask"
        self.restore_on_write = True
        self.restore_on_write_globs: tuple[str, ...] = ()
        self.bash_wrap = "runner"
        self.restore_in_bash = DEFAULT_RESTORE_IN_BASH
        self.background_bash = "deny"               # "deny" | "allow"
        self.egress_policy = "ask"                  # "ask" | "deny" | "allow"
        self.restore_in_mcp_input = False
        # Programs the USER vouches for: "this program treats its arguments as data". Read from
        # config.json in the plugin data dir and from DATAFOG_RESTORE_PROGRAMS_EXTRA only.
        self.restore_programs_extra: frozenset[str] = frozenset()
        self.recall_required = True
        self.keep_vault_on_uninstall = keep_vault_on_uninstall
        self.max_scan_bytes = 5 * MIB
        # config mistakes; they make the engine unhealthy
        self.problems: list[str] = problems if problems is not None else []

    @property
    def shadow_dir(self) -> str:
        return os.path.join(self.data_dir, "shadow")

    @property
    def log_path(self) -> str:
        return os.path.join(self.data_dir, "log", "guard.log")

    @property
    def launcher(self) -> str:
        return os.path.join(self.plugin_root, "scripts", "datafog-guard")

    @property
    def wrap_script(self) -> str:
        return os.path.join(self.plugin_root, "scripts", "wrap.sh")


def plugin_root() -> str:
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root and not root.startswith("${"):
        return root
    # engine/datafog_guard/config.py -> plugin root
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def data_dir() -> str:
    for name in ("DATAFOG_DATA_DIR", "CLAUDE_PLUGIN_DATA"):
        value = os.environ.get(name)
        if value and not value.startswith("${"):
            return value
    return os.path.join(os.path.expanduser("~"), ".claude", "plugins", "data", "datafog-datafog")


def user_data_vault_dir() -> str:
    """The per-OS user data directory, which survives a plugin uninstall."""
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "DataFog", "vaults", "claude-code")
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        return os.path.join(base, "DataFog", "vaults", "claude-code")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    return os.path.join(base, "datafog", "vaults", "claude-code")


def _truthy(value, default):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.replace("\n", ",").split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


def _read_json(path: str, problems: list[str], label: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        problems.append(f"{label} cannot be read as JSON")
        return {}
    if not isinstance(data, dict):
        problems.append(f"{label} must be a JSON object")
        return {}
    return data


# plugin option name -> config key
PLUGIN_OPTIONS = {
    "KEEP_VAULT_ON_UNINSTALL": "keep_vault_on_uninstall",
    "UNSCANNABLE_FILE_POLICY": "unscannable_policy",
    "ENTITIES": "entities",
}
# environment variable -> config key
ENV_OVERRIDES = {
    "DATAFOG_ENTITIES": "entities",
    "DATAFOG_ALLOWLIST": "allowlist",
    "DATAFOG_UNSCANNABLE_POLICY": "unscannable_policy",
    "DATAFOG_RESTORE_ON_WRITE": "restore_on_write",
    "DATAFOG_BASH_WRAP": "bash_wrap",
    "DATAFOG_RESTORE_IN_BASH": "restore_in_bash",
    "DATAFOG_BACKGROUND_BASH": "background_bash",
    "DATAFOG_EGRESS_POLICY": "egress_policy",
    "DATAFOG_RECALL_REQUIRED": "recall_required",
    "DATAFOG_MAX_SCAN_BYTES": "max_scan_bytes",
    "DATAFOG_KEEP_VAULT_ON_UNINSTALL": "keep_vault_on_uninstall",
}


def plugin_options_from_env() -> dict:
    found = {}
    for option, key in PLUGIN_OPTIONS.items():
        value = os.environ.get("CLAUDE_PLUGIN_OPTION_" + option)
        if value is not None and not value.startswith("${"):
            found[key] = value
    return found


def save_runtime_options(directory: str) -> None:
    """Persist the plugin options seen by a hook so the filter and MCP server use the same ones."""
    options = plugin_options_from_env()
    if not options:
        return
    path = os.path.join(directory, "runtime.json")
    try:
        with open(path, encoding="utf-8") as handle:
            if json.load(handle) == options:
                return
    except (OSError, ValueError):
        pass
    from .store import atomic_write
    os.makedirs(directory, mode=0o700, exist_ok=True)
    atomic_write(path, json.dumps(options, sort_keys=True).encode("utf-8"))


def load() -> Settings:
    problems: list[str] = []
    directory = data_dir()
    merged: dict = {}
    merged.update(_read_json(os.path.join(directory, "runtime.json"), problems, "runtime.json"))
    own_config = _read_json(os.path.join(directory, "config.json"), problems, "config.json")
    merged.update(own_config)
    merged.update(plugin_options_from_env())
    for name, key in ENV_OVERRIDES.items():
        if os.environ.get(name) not in (None, ""):
            merged[key] = os.environ[name]

    keep = _truthy(merged.get("keep_vault_on_uninstall"), True)
    env_vault = os.environ.get("DATAFOG_VAULT_DIR")
    if env_vault and not env_vault.startswith("${"):
        vault_dir, location = env_vault, "env"
    elif keep:
        vault_dir, location = user_data_vault_dir(), "user-data"
    else:
        vault_dir, location = os.path.join(directory, "vault"), "plugin-data"

    settings = Settings(data_dir=directory, vault_dir=vault_dir, vault_location=location,
                        plugin_root=plugin_root(), keep_vault_on_uninstall=keep, problems=problems)

    entities = [name.upper() for name in _as_list(merged.get("entities"))]
    if entities and entities != ["DEFAULT"]:
        settings.entities = tuple(dict.fromkeys(entities))
    settings.allowlist = frozenset(_as_list(merged.get("allowlist")))

    policy = str(merged.get("unscannable_policy", "ask")).strip().lower()
    if policy not in UNSCANNABLE_POLICIES:
        problems.append("unscannable_policy must be ask, deny or allow")
        policy = "deny"
    settings.unscannable_policy = policy

    restore = merged.get("restore_on_write", True)
    if isinstance(restore, (list, tuple)) or (isinstance(restore, str) and _truthy(restore, None) is None):
        settings.restore_on_write = True
        settings.restore_on_write_globs = tuple(_as_list(restore))
    else:
        settings.restore_on_write = _truthy(restore, True)

    wrap = str(merged.get("bash_wrap", "runner")).strip().lower()
    if wrap not in BASH_WRAPS:
        problems.append("bash_wrap must be runner or off (the same-shell mode was removed: it leaked)")
        wrap = "runner"
    settings.bash_wrap = wrap
    for key in ("background_bash", "egress_policy", "restore_in_bash"):
        allowed = {"background_bash": ("deny", "allow"), "egress_policy": ("ask", "deny", "allow"),
                   "restore_in_bash": RESTORE_IN_BASH}[key]
        value = str(merged.get(key, getattr(settings, key))).strip().lower()
        if value not in allowed:
            problems.append(f"{key} must be one of: {', '.join(allowed)}")
            value = "off" if key == "restore_in_bash" else "deny"
        setattr(settings, key, value)
    settings.restore_in_mcp_input = _truthy(merged.get("restore_in_mcp_input"), False)
    # Not taken from runtime.json or plugin options: only the user's own config file and environment.
    extra = os.environ.get("DATAFOG_RESTORE_PROGRAMS_EXTRA") or own_config.get("restore_programs_extra")
    if extra is not None:
        import re

        from .plain import SHELL_WORDS
        from .shellsub import NEVER
        names = _as_list(extra)
        bad = [name for name in names if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name)
               or name in SHELL_WORDS or name in NEVER]
        if bad or not isinstance(extra, (str, list, tuple)) or (isinstance(extra, (list, tuple)) and any(
                not isinstance(name, str) for name in extra)):
            problems.append("restore_programs_extra must be a list of plain program names (no paths, no shell "
                            "builtins, no shells or programs that only run other programs)")
        else:
            settings.restore_programs_extra = frozenset(names)
    settings.recall_required = _truthy(merged.get("recall_required"), True)
    try:
        settings.max_scan_bytes = max(1024, int(merged.get("max_scan_bytes", settings.max_scan_bytes)))
    except (TypeError, ValueError):
        problems.append("max_scan_bytes must be a number")
    return settings
