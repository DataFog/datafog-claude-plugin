"""Shared fixtures. All data is synthetic."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT / "engine"

# Synthetic sentinels: each must be detected, and none may ever appear where the model can see it.
EMAIL = "ada.synthetic@example.com"
CARD = "4242 4242 4242 4242"
SSN = "078-05-1120"
PHONE = "415-555-0134"
# Written in two pieces so secret scanners do not mistake this documented example for a real key.
API_KEY = "sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc"
SENTINELS = (EMAIL, CARD, SSN, PHONE, API_KEY)
NOTES = (
    "Support notes (synthetic test data)\n\n"
    f"Primary contact: {EMAIL}\n"
    f"Phone: {PHONE}\n"
    f"SSN on file: {SSN}\n"
    f"Card on file: {CARD}\n"
    f"STRIPE_KEY={API_KEY}\n"
    "End of notes\n"
)


def open_test_vault(directory, entities=None, allowlist=frozenset()):
    """A Vault on a throwaway directory, with the key in a file there (never the OS key store)."""
    from datafog_guard.config import DEFAULT_ENTITIES
    from datafog_guard.store import EncryptedStore
    from datafog_guard.vault import Detector, Vault
    return Vault(EncryptedStore(str(directory), key_mode="file"), Detector(entities or DEFAULT_ENTITIES, allowlist))


def assert_no_sentinel(text: str, where: str = "") -> None:
    for value in SENTINELS:
        assert value not in text, f"real value leaked {where}"


class Sandbox:
    """A throwaway plugin data dir, vault dir and project dir, plus helpers to run the engine."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.data = tmp / "data"
        self.vault = tmp / "vault"
        self.project = tmp / "project"
        self.home = tmp / "home"
        self.data.mkdir()
        self.project.mkdir()
        self.home.mkdir()
        self.extra_env: dict[str, str] = {}

    def env(self, **extra) -> dict:
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("DATAFOG_", "CLAUDE_"))}
        env.update({
            "PYTHONPATH": str(ENGINE), "PYTHONDONTWRITEBYTECODE": "1",
            "DATAFOG_DATA_DIR": str(self.data), "DATAFOG_VAULT_DIR": str(self.vault),
            # Tests never touch the operating system's key store: the vault key is a file in the
            # throwaway vault directory. test_keystore.py covers what happens without this.
            "DATAFOG_VAULT_KEY": "file",
            "CLAUDE_PLUGIN_ROOT": str(ROOT), "CLAUDE_PROJECT_DIR": str(self.project),
            # The hook reads the user's Claude Code settings (~/.claude/settings.json, ~/.claude.json):
            # tests must never see the real ones.
            "HOME": str(self.home),
        })
        env.update(self.extra_env)
        env.update({key: value for key, value in extra.items() if value is not None})
        for key, value in extra.items():
            if value is None:
                env.pop(key, None)
        return env

    def run(self, *argv, stdin: str | bytes = "", env: dict | None = None, timeout: int = 120):
        data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
        return subprocess.run([sys.executable, "-m", "datafog_guard", *argv], input=data,
                              capture_output=True, env=env or self.env(), cwd=self.project, timeout=timeout)

    def hook(self, payload: dict, **env_extra):
        """Run one hook event. Returns (parsed stdout or None, completed process)."""
        result = self.run("hook", stdin=json.dumps(payload), env=self.env(**env_extra))
        out = result.stdout.decode("utf-8")
        return (json.loads(out) if out.strip() else None), result

    def pre(self, tool: str, tool_input: dict, permission_mode: str | None = None, **env_extra):
        payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
                   "cwd": str(self.project), "session_id": "s", "tool_use_id": "t"}
        if permission_mode:
            payload["permission_mode"] = permission_mode
        return self.hook(payload, **env_extra)

    def claude_settings(self, scope: str, permissions: dict | str) -> Path:
        """Write a Claude Code settings file: scope is "user", "project" or "local"."""
        path = {"user": self.home / ".claude" / "settings.json",
                "project": self.project / ".claude" / "settings.json",
                "local": self.project / ".claude" / "settings.local.json"}[scope]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(permissions if isinstance(permissions, str) else json.dumps({"permissions": permissions}),
                        encoding="utf-8")
        return path

    def trust_project(self) -> None:
        (self.home / ".claude.json").write_text(json.dumps(
            {"projects": {str(self.project): {"hasTrustDialogAccepted": True}}}), encoding="utf-8")

    def seed(self, value: str, entity: str = "ACCOUNT_NUMBER") -> str:
        """Store one value in the vault as it is and return its marker."""
        return seed_values(self.open_vault(), [(entity, value)])[value]

    def post(self, tool: str, tool_input: dict, tool_response, **env_extra):
        return self.hook({"hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": tool_input,
                          "tool_response": tool_response, "cwd": str(self.project)}, **env_extra)

    def prompt(self, text: str, **env_extra):
        return self.hook({"hook_event_name": "UserPromptSubmit", "prompt": text, "cwd": str(self.project)},
                         **env_extra)

    def open_vault(self, entities=None, allowlist=frozenset()):
        return open_test_vault(self.vault, entities, allowlist)

    def write(self, name: str, content: str | bytes) -> Path:
        path = self.project / name
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        return path

    def visible_files(self) -> str:
        """Everything the engine wrote outside the vault itself: logs, shadow copies, runtime files."""
        chunks = []
        for path in self.data.rglob("*"):
            if path.is_file() and "venv" not in path.parts:
                chunks.append(path.read_bytes().decode("utf-8", "replace"))
        return "\n".join(chunks)


def standin_plugin(box: "Sandbox"):
    """A copy of the plugin's scripts whose launcher uses this test's Python instead of the private
    environment. Returns (plugin directory, settings that point at it and at the sandbox)."""
    from datafog_guard import config
    plugin = box.tmp / "plugin"
    if not plugin.exists():
        (plugin / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts" / "wrap.sh", plugin / "scripts" / "wrap.sh")
        launcher = plugin / "scripts" / "datafog-guard"
        launcher.write_text(
            "#!/bin/sh\n"
            'while :; do case "$1" in\n'
            "  --data-dir) DATAFOG_DATA_DIR=$2; export DATAFOG_DATA_DIR; shift 2 ;;\n"
            "  --vault-dir) DATAFOG_VAULT_DIR=$2; export DATAFOG_VAULT_DIR; shift 2 ;;\n"
            "  *) break ;; esac; done\n"
            f'exec "{sys.executable}" -I "{ENGINE}/run.py" "$@"\n')
        launcher.chmod(0o755)
    names = ("DATAFOG_DATA_DIR", "DATAFOG_VAULT_DIR", "DATAFOG_VAULT_KEY", "CLAUDE_PLUGIN_ROOT")
    saved = {name: os.environ.get(name) for name in names}
    os.environ.update(DATAFOG_DATA_DIR=str(box.data), DATAFOG_VAULT_DIR=str(box.vault), DATAFOG_VAULT_KEY="file",
                      CLAUDE_PLUGIN_ROOT=str(plugin))
    try:
        settings = config.load()
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    return plugin, settings


@pytest.fixture
def box(tmp_path) -> Sandbox:
    return Sandbox(tmp_path)


@pytest.fixture(scope="session")
def full_vault_dir(tmp_path_factory) -> Path:
    """A vault filled to core's limit of 20,000 live entries (built once)."""
    directory = tmp_path_factory.mktemp("fullvault") / "vault"
    vault = open_test_vault(directory)
    for start in range(0, 20_000, 1000):
        seed_values(vault, [("ACCOUNT_NUMBER", f"v{number:07d}") for number in range(start, start + 1000)])
    return directory


def seed_values(vault, pairs) -> dict:
    """Store (entity, value) pairs as they are, as a tokenization would. Returns value -> marker."""
    markers = vault._commit(pairs)
    vault.store.add_to_index(list(markers.values()))
    return markers


def copy_vault(source: Path, target: Path) -> None:
    shutil.copytree(source, target)
    os.chmod(target, 0o700)
