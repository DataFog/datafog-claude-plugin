#!/usr/bin/env python3
"""Test a cached project/local install using the existing Claude login.

Creates a uniquely named temporary local marketplace containing a source snapshot.
Only that marketplace and its local-scope installation are removed afterwards.
Does not copy credentials, set CLAUDE_CONFIG_DIR, or use --plugin-dir.
Run after freezing the candidate: python3 tests/live/run_installed_readiness.py
"""
import hashlib
import json
import os
import pathlib
import pty
import select
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

import run_live as live


def trust_fixture(driver):
    """Accept only this generated workspace's real host trust prompt; no model request."""
    master, slave = pty.openpty()
    process = subprocess.Popen(["claude", "--setting-sources", "project,local", "--ax-screen-reader", "--tools", ""],
                               cwd=driver.project, env=driver.env(), stdin=slave, stdout=slave, stderr=slave,
                               start_new_session=True)
    os.close(slave)
    transcript = bytearray()
    accepted = False
    deadline = time.monotonic() + 90
    try:
        while process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 1)
            if ready:
                try:
                    transcript.extend(os.read(master, 65536))
                except OSError:
                    break
            text = transcript.decode(errors="replace")
            if not accepted and "Accessing workspace" in text and "Enter y/n:" in text:
                os.write(master, b"y\r")
                accepted = True
            if accepted and "DataFog guard: on." in text:
                return True
        return False
    finally:
        pathlib.Path(driver.log, "fixture-trust-pty.txt").write_bytes(transcript)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        os.close(master)


def main():
    source = pathlib.Path(live.REPO)
    work = pathlib.Path(tempfile.mkdtemp(prefix="datafog-installed."))
    snapshot = work / "plugin-source"
    snapshot.mkdir()
    marketplace = "datafog-readiness-" + uuid.uuid4().hex[:12]
    plugin_id = "datafog@" + marketplace
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=source).decode().split("\0")
    hashes = {}
    for name in filter(None, names):
        path = source / name
        if not path.is_file():
            continue
        if path.is_symlink():
            raise SystemExit("Snapshot refuses symlinks: " + name)
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    subprocess.run(["git", "init", "-b", "readiness-fixture", str(snapshot)], check=True, capture_output=True)
    subprocess.run(["git", "add", "--all"], cwd=snapshot, check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.name=DataFog readiness fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-m", "Snapshot candidate for cached install verification"], cwd=snapshot, check=True, capture_output=True)
    fixture_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=snapshot, text=True).strip()
    catalog_root = work / "marketplace"
    catalog_path = catalog_root / ".claude-plugin/marketplace.json"
    catalog_path.parent.mkdir(parents=True)
    catalog = json.loads((snapshot / ".claude-plugin/marketplace.json").read_text())
    catalog["name"] = marketplace
    catalog["plugins"][0]["source"] = {"source": "url", "url": snapshot.as_uri(), "sha": fixture_sha}
    catalog_path.write_text(json.dumps(catalog, indent=2))
    provenance = {"revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
                  "source_sha256": hashes, "marketplace": marketplace,
                  "fixture_git_sha": fixture_sha,
                  "snapshot_change": "Plugin files unchanged. Separate unique marketplace uses pinned local Git source to force cached execution."}
    (work / "provenance.json").write_text(json.dumps(provenance, indent=2))
    driver = live.Driver(str(work), "claude")
    driver.plugin_dir = None
    driver.reset_fixtures()
    pathlib.Path(driver.data).mkdir()
    pathlib.Path(driver.data, "config.json").write_text(json.dumps({"vault_key": "file"}))
    outside = work / "outside-project.txt"
    outside.write_text("ORIGINAL SYNTHETIC FIXTURE\n")
    report = {"marketplace": marketplace, "work": str(work), "cases": [], "cleanup": []}
    print("Installed evidence directory: " + str(work), flush=True)

    def command(label, args):
        result = subprocess.run(["claude", *args], cwd=driver.project, env=driver.env(),
                                capture_output=True, text=True, timeout=120)
        pathlib.Path(driver.log, label + ".txt").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(label + " failed; see evidence log")
        return result.stdout

    try:
        command("marketplace-add", ["plugin", "marketplace", "add", str(catalog_root), "--scope", "local", "--json"])
        command("install", ["plugin", "install", plugin_id, "--scope", "local", "--json"])
        plugins = json.loads(command("installed-list", ["plugin", "list", "--json"]))
        installed = next(p for p in plugins if p["id"] == plugin_id and p["scope"] == "local")
        cache = pathlib.Path(installed["installPath"])
        report["installed"] = installed
        report["cache_matches_source"] = all((cache / name).is_file() and hashlib.sha256((cache / name).read_bytes()).hexdigest() == digest
                                            for name, digest in hashes.items()
                                            if name.startswith(("engine/", "scripts/", "hooks/")) or name == ".mcp.json")
        report["fresh_bootstrap"] = not pathlib.Path(driver.data, "venv").exists()
        report["interactive_first_start"] = trust_fixture(driver)
        config = json.loads((pathlib.Path.home() / ".claude.json").read_text())
        report["fixture_trust_recorded"] = config.get("projects", {}).get(str(pathlib.Path(driver.project).resolve()), {}).get("hasTrustDialogAccepted") is True

        def run(name, prompt, check):
            result = driver.run(name, prompt + " Do not retry a refused call or use alternative tools.")
            if not result:
                raise RuntimeError("Host run cap reached")
            checks = check(result)
            checks["successful host process"] = result.exit_code == 0 and not result.timed_out
            checks["no sentinel in model tool results"] = not live.leaked("\n".join(x["text"] for x in result.tool_results))
            checks["loaded installed cached plugin"] = any(p.get("name") == "datafog" and pathlib.Path(p.get("path", "")).resolve() == cache.resolve()
                                                           for p in result.init.get("plugins", []))
            row = {"case": name, "version": result.init.get("claude_code_version"), "checks": checks,
                   "transcript": result.path}
            report["cases"].append(row)
            print(json.dumps(row), flush=True)
            (work / "installed-results.json").write_text(json.dumps(report, indent=2))

        run("installed-read", "Use Read on notes.txt and report the Primary contact line.",
            lambda r: {"Read returned markers": any(live.MARKER.search(x["text"]) for x in r.results_of("Read")),
                       "first startup bootstrapped engine": driver.engine_python() is not None})
        run("installed-bash", "Run exactly this Bash command: cat notes.txt. Report its output.",
            lambda r: {"Bash returned markers": any(live.MARKER.search(x["text"]) for x in r.results_of("Bash"))})
        run("installed-mcp-edit", 'Use Read on notes.txt. Append " (verified)" to the Primary contact line using '
            'DataFog edit_with_markers with the exact full line as old_string. Do not use built-in Edit.',
            lambda r: {"MCP edit called": any(x["name"] == live.EDIT_TOOL for x in r.tool_uses),
                       "real value plus suffix on disk": live.SENTINELS["EMAIL ada"] + " (verified)" in (driver.disk("notes.txt") or ""),
                       "no marker on disk": not live.MARKER.search(driver.disk("notes.txt") or "")})
        run("installed-mcp-project-boundary", "This is a synthetic scope-denial test. Call DataFog edit_with_markers once with "
            + json.dumps({"file_path": str(outside), "old_string": "ORIGINAL SYNTHETIC FIXTURE", "new_string": "CHANGED SYNTHETIC FIXTURE"})
            + ". The expected result is refusal because the path is outside the project. Do not use other tools.",
            lambda r: {"MCP edit called": any(x["name"] == live.EDIT_TOOL for x in r.tool_uses),
                       "server refused outside project": any("outside the project directory" in x["text"] for x in r.results_of(live.EDIT_TOOL)),
                       "outside fixture unchanged": outside.read_text() == "ORIGINAL SYNTHETIC FIXTURE\n"})
    finally:
        for label, args in (("uninstall", ["plugin", "uninstall", plugin_id, "--scope", "local", "--json"]),
                            ("marketplace-remove", ["plugin", "marketplace", "remove", marketplace, "--scope", "local", "--json"]),
                            ("purge-fixture-session", ["purge", driver.project, "--yes"])):
            try:
                command(label, args)
                report["cleanup"].append({"step": label, "success": True})
            except Exception as error:
                report["cleanup"].append({"step": label, "success": False, "error": str(error)})
        remaining = json.loads(command("post-cleanup-list", ["plugin", "list", "--json"]))
        report["cleanup_verified"] = not any(p["id"] == plugin_id for p in remaining)
        (work / "installed-results.json").write_text(json.dumps(report, indent=2))
    passed = report.get("cache_matches_source") and report.get("fresh_bootstrap") and report.get("interactive_first_start") and report.get("fixture_trust_recorded") and len(report["cases"]) == 4
    passed = passed and all(all(row["checks"].values()) for row in report["cases"]) and all(row["success"] for row in report["cleanup"]) and report["cleanup_verified"]
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
