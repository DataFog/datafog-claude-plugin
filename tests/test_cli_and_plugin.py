"""status / purge / doctor, configuration, and the plugin's own files."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest
from conftest import EMAIL, NOTES, ROOT, assert_no_sentinel, corrupt_vault
from datafog_guard import CORE_REQUIREMENT, VAULT_REQUIREMENT, config


def text_of(result) -> str:
    return result.stdout.decode() + result.stderr.decode()


def test_status_names_types_counts_and_how_the_vault_is_encrypted(box):
    box.open_vault().tokenize(NOTES)
    out = text_of(box.run("status"))
    assert "Protection: ON" in out and "Values held in the vault: 5" in out and "1 EMAIL" in out
    assert "encryption at rest: encrypted, but the key is a file beside the data" in out
    assert str(box.vault) in out and "set by DATAFOG_VAULT_DIR" in out and "WARNING" not in out
    assert "Not detected: names of people" in out
    assert_no_sentinel(out)


def test_status_never_echoes_allowlist_values(box):
    (box.data / "config.json").write_text(json.dumps({"allowlist": ["noreply@example.com", EMAIL]}))
    out = text_of(box.run("status", env=box.env(DATAFOG_ALLOWLIST="ops@example.com,team@example.com")))
    assert "Allowlisted exact values: 2" in out
    assert "example.com" not in out
    out = text_of(box.run("doctor"))
    assert "example.com" not in out.replace("probe.synthetic@example.com", "")


def test_purge_needs_the_confirmation_word(box):
    vault = box.open_vault()
    marker = vault.tokenize(EMAIL)[0]
    first = box.run("purge")
    assert first.returncode == 0 and "Nothing was deleted" in text_of(first) and "NEVER" in text_of(first)
    assert box.open_vault().restore(marker).text == EMAIL
    wrong = box.run("purge", "--confirm", "yes")
    assert wrong.returncode == 1 and box.open_vault().restore(marker).text == EMAIL
    done = box.run("purge", "--confirm", "DELETE-VAULT")
    assert done.returncode == 0 and "The vault was deleted" in text_of(done)
    assert box.open_vault().restore(marker).text == marker
    assert "There was no vault" in text_of(box.run("purge", "--confirm", "DELETE-VAULT"))
    assert_no_sentinel(text_of(first) + text_of(done))


def test_doctor_reports_each_check_and_fails_on_a_broken_vault(box):
    out = text_of(box.run("doctor"))
    for line in ("[ok  ] Python 3.10 or later", "[ok  ] detector library", "[ok  ] tokenize and restore round trip",
                 "[ok  ] vault directory is owner-only", "[ok  ] vault files are owner-only", "[ok  ] vault library",
                 "[ok  ] supported machine", "[note] vault encryption at rest: encrypted, but the key is a file"):
        assert line in out, out
    assert_no_sentinel(out)
    corrupt_vault(box.vault)
    broken = box.run("doctor")
    assert broken.returncode == 1 and "[FAIL] vault and detector: vault_corrupt" in text_of(broken)


def test_unknown_subcommand(box):
    assert box.run("nonsense").returncode == 2


# -- configuration ----------------------------------------------------------------
def load(monkeypatch, tmp_path, **env):
    for name in list(os.environ):
        if name.startswith(("DATAFOG_", "CLAUDE_", "XDG_")):
            monkeypatch.delenv(name)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return config.load()


def test_default_vault_location_is_the_user_data_dir(monkeypatch, tmp_path):
    settings = load(monkeypatch, tmp_path)
    assert settings.vault_location == "user-data" and settings.keep_vault_on_uninstall
    monkeypatch.setattr(config.sys, "platform", "linux")
    assert config.user_data_vault_dir() == str(tmp_path / "home/.local/share/datafog/vaults/claude-code")
    monkeypatch.setenv("XDG_DATA_HOME", "/xdg")
    assert config.user_data_vault_dir() == "/xdg/datafog/vaults/claude-code"
    monkeypatch.setattr(config.sys, "platform", "darwin")
    assert config.user_data_vault_dir() == str(tmp_path / "home/Library/Application Support/DataFog/vaults/claude-code")


def test_vault_goes_to_plugin_data_when_not_kept(monkeypatch, tmp_path):
    settings = load(monkeypatch, tmp_path, CLAUDE_PLUGIN_OPTION_KEEP_VAULT_ON_UNINSTALL="false")
    assert settings.vault_location == "plugin-data" and settings.vault_dir == str(tmp_path / "data" / "vault")


def test_env_vault_dir_wins(monkeypatch, tmp_path):
    settings = load(monkeypatch, tmp_path, DATAFOG_VAULT_DIR="/somewhere/vault",
                    CLAUDE_PLUGIN_OPTION_KEEP_VAULT_ON_UNINSTALL="false")
    assert (settings.vault_location, settings.vault_dir) == ("env", "/somewhere/vault")


def test_plugin_options_reach_processes_that_do_not_receive_them(monkeypatch, tmp_path):
    """The Bash filter and the MCP server get no CLAUDE_PLUGIN_OPTION_* variables."""
    load(monkeypatch, tmp_path, CLAUDE_PLUGIN_OPTION_KEEP_VAULT_ON_UNINSTALL="false",
         CLAUDE_PLUGIN_OPTION_ENTITIES="EMAIL, ssn", CLAUDE_PLUGIN_OPTION_UNSCANNABLE_FILE_POLICY="deny")
    config.save_runtime_options(str(tmp_path / "data"))
    settings = load(monkeypatch, tmp_path)
    assert settings.vault_location == "plugin-data" and settings.entities == ("EMAIL", "SSN")
    assert settings.unscannable_policy == "deny"


def test_precedence_and_defaults(monkeypatch, tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "config.json").write_text(json.dumps(
        {"entities": ["EMAIL"], "allowlist": ["a@example.com"], "bash_wrap": "off", "egress_policy": "deny",
         "restore_in_bash": "off"}))
    settings = load(monkeypatch, tmp_path)
    assert settings.entities == ("EMAIL",) and settings.bash_wrap == "off" and settings.egress_policy == "deny"
    assert settings.restore_in_bash == "off"
    assert settings.allowlist == frozenset({"a@example.com"}) and not settings.problems
    settings = load(monkeypatch, tmp_path, DATAFOG_ENTITIES="PHONE,SSN", DATAFOG_BASH_WRAP="runner",
                    DATAFOG_RESTORE_IN_BASH="allow")
    assert settings.entities == ("PHONE", "SSN") and settings.bash_wrap == "runner"
    assert settings.restore_in_bash == "allow"
    removed = load(monkeypatch, tmp_path, DATAFOG_BASH_WRAP="same-shell")
    assert removed.problems and "removed" in removed.problems[0], "the leaky same-shell mode is gone, not ignored"
    assert load(monkeypatch, tmp_path / "other").entities == config.DEFAULT_ENTITIES
    for noisy in config.NOISY_ENTITIES:
        assert noisy not in config.DEFAULT_ENTITIES


def test_invalid_settings_are_problems_not_silent_defaults(monkeypatch, tmp_path):
    settings = load(monkeypatch, tmp_path, DATAFOG_UNSCANNABLE_POLICY="whatever", DATAFOG_BASH_WRAP="magic")
    assert len(settings.problems) == 2 and settings.unscannable_policy == "deny"


# -- plugin files -------------------------------------------------------------------
def test_every_hook_entry_blocks_on_failure_and_uses_the_launcher():
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]
    assert set(hooks) == {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse"}
    for event, groups in hooks.items():
        assert len(groups) == 1 and len(groups[0]["hooks"]) == 1, f"{event}: exactly one hook"
        entry = groups[0]["hooks"][0]
        assert entry["type"] == "command" and entry["onFailure"] == "block", event
        assert entry["command"].startswith('sh "${CLAUDE_PLUGIN_ROOT}/scripts/datafog-guard" ')
        assert entry["timeout"] >= 30
    assert hooks["PreToolUse"][0]["matcher"] == "*", "one PreToolUse hook for all tools: only one may rewrite input"
    assert hooks["PostToolUse"][0]["matcher"] == "*"


def test_manifests():
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert plugin["name"] == "datafog" and plugin["version"] == "0.2.0-dev"
    options = plugin["userConfig"]
    assert options["keep_vault_on_uninstall"]["type"] == "boolean" and options["keep_vault_on_uninstall"]["default"] is True
    assert options["unscannable_file_policy"]["options"] == ["ask", "deny", "allow"]
    assert set(options) == {name.lower() for name in config.PLUGIN_OPTIONS}
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    assert market["plugins"][0]["name"] == "datafog"
    servers = json.loads((ROOT / ".mcp.json").read_text())["mcpServers"]
    assert list(servers) == ["guard"] and servers["guard"]["args"][-1] == "mcp"
    from datafog_guard.hook import OWN_MCP_PREFIX
    assert OWN_MCP_PREFIX == f"mcp__plugin_{plugin['name']}_guard__"


def test_commands_exist_and_purge_cannot_be_invoked_by_the_model():
    for name in ("status", "purge", "doctor"):
        body = (ROOT / "commands" / f"{name}.md").read_text()
        assert body.startswith("---\ndescription:") and f'datafog-guard" --data-dir "${{CLAUDE_PLUGIN_DATA}}" {name}' in body
    purge = (ROOT / "commands" / "purge.md").read_text()
    assert "disable-model-invocation: true" in purge and "--confirm DELETE-VAULT" in purge and "never be restored" in purge


def test_dependency_pin_is_the_same_everywhere():
    assert CORE_REQUIREMENT == "datafog-core>=1.7.0,<1.8"
    assert VAULT_REQUIREMENT == "datafog-fogvault>=1.7.0,<1.8"
    bootstrap = (ROOT / "scripts" / "bootstrap.sh").read_text()
    assert f"CORE_REQUIREMENT='{CORE_REQUIREMENT}'" in bootstrap and f"VAULT_REQUIREMENT='{VAULT_REQUIREMENT}'" in bootstrap
    project = (ROOT / "pyproject.toml").read_text()
    assert f'"{CORE_REQUIREMENT}"' in project and f'"{VAULT_REQUIREMENT}"' in project
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert f'"{CORE_REQUIREMENT}" "{VAULT_REQUIREMENT}"' in workflow


def test_launcher_ignores_modules_in_the_working_directory():
    """The hook's working directory is the user's project: nothing in it may be imported."""
    launcher = (ROOT / "scripts" / "datafog-guard").read_text()
    assert 'exec "$PY" -I "$ROOT/engine/run.py" "$@"' in launcher


def test_run_py_is_not_fooled_by_project_files(box):
    import sys
    for name in ("json.py", "datafog_core.py", "datafog_guard.py", "os.py"):
        box.write(name, "raise SystemExit('project file was imported')\n")
    env = box.env()
    env.pop("PYTHONPATH")
    probe = (f"import subprocess, sys; sys.exit(subprocess.run([sys.executable, '-I', r'{ROOT}/engine/run.py', 'status'],"
             f" cwd=r'{box.project}').returncode)")
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, env=env, cwd=box.tmp)
    assert result.returncode == 0 and b"Protection: ON" in result.stdout, result.stdout + result.stderr


def test_shell_scripts_parse():
    for name in ("datafog-guard", "bootstrap.sh", "wrap.sh"):
        assert subprocess.run(["sh", "-n", str(ROOT / "scripts" / name)]).returncode == 0
    for shell in ("bash", "zsh"):
        if shutil.which(shell):
            assert subprocess.run([shell, "-n", str(ROOT / "scripts" / "wrap.sh")]).returncode == 0


def test_engine_has_no_third_party_imports_besides_core_and_its_vault():
    import ast
    import sys
    allowed = set(sys.stdlib_module_names) | {"datafog_core", "datafog_fogvault", "datafog_guard"}
    for path in (ROOT / "engine" / "datafog_guard").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            for name in names:
                assert name.split(".")[0] in allowed, f"{path.name} imports {name}"


def test_hook_start_up_does_not_import_heavy_modules(box):
    code = ("import sys, io, json\n"
            "sys.stdin = io.StringIO(json.dumps({'hook_event_name': 'PreToolUse', 'tool_name': 'Glob', 'tool_input': {}}))\n"
            "from datafog_guard import hook\nhook.main()\n"
            "heavy = {'subprocess', 'asyncio', 'http', 'urllib', 'email', 'ssl', 'socket', 'logging', 'argparse',"
            " 'multiprocessing', 'concurrent', 'unittest', 'xml', 'sqlite3', 'ctypes'}\n"
            "print(sorted(heavy & {name.split('.')[0] for name in sys.modules}))\n")
    import sys
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=box.env())
    assert result.stdout.strip().endswith("[]"), result.stdout + result.stderr


# -- bootstrap (needs PyPI) -----------------------------------------------------------
@pytest.mark.network
@pytest.mark.skipif(os.environ.get("DATAFOG_TEST_NETWORK") != "1", reason="set DATAFOG_TEST_NETWORK=1 to run")
def test_bootstrap_installs_once_and_the_launcher_then_works(box):
    launcher = ["sh", str(ROOT / "scripts" / "datafog-guard"), "--data-dir", str(box.data), "--vault-dir", str(box.vault)]
    env = {"PATH": os.environ["PATH"], "HOME": str(box.tmp), "DATAFOG_VAULT_KEY": "file"}   # no OS key store in tests
    for name in ("HTTPS_PROXY", "https_proxy", "SSL_CERT_FILE", "UV_NATIVE_TLS", "REQUESTS_CA_BUNDLE", "PIP_CERT",
                 "UV_SYSTEM_CERTS"):
        if name in os.environ:
            env[name] = os.environ[name]
    payload = json.dumps({"hook_event_name": "SessionStart", "source": "startup"}).encode()
    first = subprocess.run([*launcher, "session-start"], input=payload, capture_output=True, env=env, timeout=600)
    out = json.loads(first.stdout)
    assert "DataFog guard: on" in out["systemMessage"], (box.data / "log" / "bootstrap.log").read_text()
    stamp = box.data / "venv" / ".datafog-installed"
    assert stamp.read_text() == f"{CORE_REQUIREMENT} {VAULT_REQUIREMENT}"
    before = stamp.stat().st_mtime_ns
    import time
    started = time.time()
    again = subprocess.run([*launcher, "bootstrap"], capture_output=True, env=env, timeout=60)
    assert again.returncode == 0 and time.time() - started < 2 and stamp.stat().st_mtime_ns == before
    status = subprocess.run([*launcher, "status"], capture_output=True, env=env, timeout=60)
    assert b"Protection: ON" in status.stdout
    doctor = subprocess.run([*launcher, "doctor"], capture_output=True, env=env, timeout=120)
    assert b"[ok  ] Bash output filter under bash" in doctor.stdout and b"[FAIL]" not in doctor.stdout, doctor.stdout
    pre = subprocess.run([*launcher, "hook"], capture_output=True, env=env, timeout=60, input=json.dumps(
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo hi"}}).encode())
    assert b"__datafog_run" in pre.stdout


def test_session_start_without_any_way_to_install_says_what_to_run(box):
    payload = json.dumps({"hook_event_name": "SessionStart", "source": "startup"}).encode()
    empty = box.tmp / "emptybin"
    empty.mkdir()
    for tool in ("sh", "cat", "mkdir", "chmod", "find", "rmdir", "rm", "date", "sed", "printf", "dirname", "sleep",
                 "uname", "getconf"):
        found = shutil.which(tool)
        if found:
            (empty / tool).symlink_to(found)
    result = subprocess.run(["sh", str(ROOT / "scripts" / "datafog-guard"), "--data-dir", str(box.data), "session-start"],
                            input=payload, capture_output=True, env={"PATH": str(empty), "HOME": str(box.tmp)}, timeout=60)
    out = json.loads(result.stdout)
    assert "NOT protecting" in out["systemMessage"] and "bootstrap" in out["systemMessage"]
    assert "Tool calls are blocked" in out["systemMessage"]
    log = (box.data / "log" / "bootstrap.log").read_text()
    assert "no Python 3.10 or later found" in log
