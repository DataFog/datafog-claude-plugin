"""The unattended live driver, run against the simulator in tests/live/fake_claude.py.

This checks the driver's own plumbing (caps, confinement, parsing, checks) and runs
hooks.json, the launcher and the engine together. It says nothing about real Claude Code.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import pytest
from conftest import ROOT

DRIVER = ROOT / "tests" / "live" / "run_live.py"
FAKE = ROOT / "tests" / "live" / "fake_claude.py"
needs_network = pytest.mark.skipif(os.environ.get("DATAFOG_TEST_NETWORK") != "1",
                                   reason="builds the private environment from PyPI; set DATAFOG_TEST_NETWORK=1")


def drive(work, *, claude=FAKE, **env):
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("DATAFOG_", "SIM_", "LIVE_"))}
    # The plugin's hook reads the user's Claude Code settings. A real live run must use the real home
    # (the login is there); under test it is an empty one, so the developer's own rules cannot interfere.
    home = os.path.join(str(work), "home")
    if os.path.isdir(str(work)) and str(work).startswith(tempfile.gettempdir()):
        os.makedirs(home, exist_ok=True)
        environment.setdefault("UV_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "uv"))
        environment["HOME"] = home
    environment.update(env)
    result = subprocess.run([sys.executable, str(DRIVER), str(work), "--claude", str(claude)], capture_output=True,
                            text=True, env=environment, timeout=900)
    return result, result.stdout.strip().splitlines()[-1]


def checks(work) -> dict:
    data = json.loads(open(os.path.join(work, "log", "results.json")).read())
    return {(case["case"], check["name"]): check["status"] for case in data["cases"] for check in case["checks"]}


def test_refuses_to_run_outside_the_temp_dir(tmp_path):
    # Not the parent of the temp dir: on macOS that parent is itself under /var/folders, an accepted root.
    for outside in ("/", "/usr"):
        result, last = drive(outside)
        assert result.returncode == 1 and last.startswith("LIVE ABORTED") and "temp dir" in last
    result, last = drive("/nonexistent/dir")
    assert last.startswith("LIVE ABORTED")


def test_aborts_on_an_old_claude(tmp_path):
    old = tmp_path / "claude"
    old.write_text("#!/bin/sh\necho '2.1.200 (Claude Code)'\n")
    old.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix="datafog-live.") as work:
        result, last = drive(work, claude=old)
        assert last.startswith("LIVE ABORTED") and "2.1.295" in last
        assert open(os.path.join(work, "log", "status.txt")).read().startswith("ABORTED")


@needs_network
def test_full_run_against_the_simulator():
    with tempfile.TemporaryDirectory(prefix="datafog-live.") as work:
        result, last = drive(work)
        assert last == "LIVE DONE", result.stdout[-3000:]
        found = checks(work)
        assert "FAIL" not in found.values() and "FINDING" not in found.values(), \
            {key: value for key, value in found.items() if value in ("FAIL", "FINDING")}
        assert len({case for case, _ in found}) == 29
        report = open(os.path.join(work, "log", "results.md")).read()
        assert "L17-engine-breaks-mid-session" in report and "Hook time inside the engine" in report
        strict = "no real value in the transcript, the result record, permission_denials, stderr, the debug log " \
                 "or the guard log"
        for case in ("L18-bash-marker-ask", "L19-bash-marker-allow", "L25-bash-nasty-value"):
            assert found[(case, strict)] == "PASS"
        assert found[("L25-bash-nasty-value", "the program received exactly the hostile value, as one argument")] == "PASS"
        assert found[("L22-bash-denied", "the hook denied it by the project's deny rule (step 2)")] == "PASS"
        assert found[("L26-bash-read-deny", "the command did not run")] == "PASS"
        assert found[("L27-bash-read-deny-directory", "the command did not run")] == "PASS"
        assert found[("L28-bash-read-deny-quoted-glob", "the command did not run")] == "PASS"
        assert found[("L29-bash-marker-not-plain", "the hook refused to restore a marker in a command that is "
                                                    "not plain")] == "PASS"
        assert not os.path.exists(os.path.join(work, "project", "PWNED"))


@needs_network
def test_driver_reports_findings_and_leaks():
    with tempfile.TemporaryDirectory(prefix="datafog-live.") as work:
        result, last = drive(work, SIM_IGNORE_HOOK_ALLOW="1", SIM_STRICT_READ_TRACKING="1")
        found = checks(work)
        assert last == "LIVE DONE"
        name = "a simple command matched by an allow rule in settings.local.json ran without a prompt"
        assert found[("L02-bash-ok", name)] == "FAIL", "the hook allowed it and the command still did not run"
        assert found[("L10-write-over-read", "Write over a file that was read through a shadow copy succeeded")] == "FINDING"
    with tempfile.TemporaryDirectory(prefix="datafog-live.") as work:
        result, last = drive(work, SIM_NO_HOOKS="1")
        found = checks(work)
        assert found[("L01-read", "no real value in any tool result sent to the model")] == "FAIL", \
            "without the hooks the driver must see the leak"
        assert found[("L13-at-file", "the model never wrote a real value")] == "FAIL"


@needs_network
def test_caps_stop_the_run():
    with tempfile.TemporaryDirectory(prefix="datafog-live.") as work:
        result, last = drive(work, LIVE_MAX_RUNS="3")
        assert last == "LIVE DONE" and "runs used: 3, skipped by a cap: 26" in result.stdout
        assert "SKIPPED" in checks(work).values()
