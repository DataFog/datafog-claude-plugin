#!/usr/bin/env python3
"""Additional real-host readiness probes; never a substitute for the main live suite.

Run: python3 tests/live/run_readiness.py [case-name ...]
Creates a temporary project and file-key vault. Uses the existing Claude login.
No user settings or real vault are changed. Results stay in the printed temp path.
The model must make the requested call for a probe to pass.
"""
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import time

from run_live import EDIT_TOOL, MARKER, SENTINELS, Driver, leaked


def main():
    work = tempfile.mkdtemp(prefix="datafog-readiness.")
    driver = Driver(work, "claude")
    driver.tools += ",TaskStop"
    print("Evidence directory: " + work, flush=True)
    diff = subprocess.check_output(["git", "diff", "HEAD"], cwd=pathlib.Path(__file__).resolve().parents[2])
    pathlib.Path(work, "provenance.json").write_text(json.dumps({
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "dirty": bool(diff),
    }, indent=2))
    error = driver.prepare_engine()
    if error:
        raise SystemExit(error)
    evidence = []
    observer = pathlib.Path(work, "observe-mode.py")
    observer.write_text("import json,sys\nd=json.load(sys.stdin)\n"
                        "row={k:d.get(k) for k in ('tool_name','tool_use_id','permission_mode','agent_id','agent_type')}\n"
                        "with open(sys.argv[1],'a') as f: f.write(json.dumps(row)+'\\n')\n")

    def run(name, prompt, check, mode="acceptEdits", setup=None, env=None):
        if sys.argv[1:] and name not in sys.argv[1:]:
            return
        driver.reset_fixtures()
        if setup:
            setup(pathlib.Path(driver.project))
        observed_path = pathlib.Path(work, "log", name + "-hook-inputs.jsonl")
        settings_path = pathlib.Path(driver.project, ".claude", "settings.local.json")
        settings = json.loads(settings_path.read_text())
        settings.setdefault("hooks", {}).setdefault("PreToolUse", []).append({"matcher": "*", "hooks": [{
            "type": "command", "command": "python3 " + shlex.quote(str(observer)) + " " + shlex.quote(str(observed_path))}]})
        settings_path.write_text(json.dumps(settings))
        result = driver.run(name, prompt + " Do not retry a refused call or use alternative tools.", mode=mode, env=env)
        checks = check(result) if result else {"run completed": False}
        if result:
            checks["successful host process"] = result.exit_code == 0 and not result.timed_out
            checks["no sentinel in model tool results"] = not leaked("\n".join(x["text"] for x in result.tool_results))
        row = {"case": name, "checks": checks, "version": result.init.get("claude_code_version") if result else None,
               "transcript": result.path if result else None,
               "observed_hook_inputs": [json.loads(line) for line in observed_path.read_text().splitlines()] if observed_path.exists() else []}
        evidence.append(row)
        pathlib.Path(work, "log", "readiness.json").write_text(json.dumps(evidence, indent=2))
        print(json.dumps(row), flush=True)

    run("reviewer-read", "Use Read on notes.txt and report the Primary contact line.",
        lambda r: {"Read returned markers": any(MARKER.search(x["text"]) for x in r.results_of("Read"))})
    run("reviewer-bash", "Run exactly this Bash command: cat notes.txt. Report its output.",
        lambda r: {"Bash returned markers": any(MARKER.search(x["text"]) for x in r.results_of("Bash"))})
    def enable_sandbox(project):
        path = project / ".claude/settings.local.json"
        settings = json.loads(path.read_text())
        settings["sandbox"] = {"enabled": True, "failIfUnavailable": True,
                               "autoAllowBashIfSandboxed": False, "allowUnsandboxedCommands": False,
                               "filesystem": {"allowWrite": [driver.data, driver.vault]}}
        path.write_text(json.dumps(settings))

    run("sandbox-bash", "Run exactly this Bash command: cat notes.txt. Do not disable or bypass the sandbox.",
        lambda r: {"Bash returned markers": any(MARKER.search(x["text"]) for x in r.results_of("Bash")),
                   "no tool requested sandbox bypass": all(not x["input"].get("dangerouslyDisableSandbox") for x in r.tool_uses)},
        setup=enable_sandbox)
    def sandbox_boundary(project):
        enable_sandbox(project)
        (project / "sandbox-probe.sh").write_text("printf blocked > sandbox-protected.txt\ncat notes.txt\n")
        path = project / ".claude/settings.local.json"
        settings = json.loads(path.read_text())
        settings["permissions"]["allow"].append("Bash(sh sandbox-probe.sh)")
        settings["sandbox"]["filesystem"]["denyWrite"] = [str(project / "sandbox-protected.txt")]
        path.write_text(json.dumps(settings))

    run("sandbox-boundary", "Run exactly one Bash call: sh sandbox-probe.sh. Do not retry, disable or bypass the sandbox.",
        lambda r: {"Bash returned markers": any(MARKER.search(x["text"]) for x in r.results_of("Bash")),
                   "sandbox blocked protected write": not os.path.exists(os.path.join(driver.project, "sandbox-protected.txt")),
                   "host output reports denied operation": any("not permitted" in x["text"].lower() or "permission denied" in x["text"].lower() for x in r.results_of("Bash")),
                   "no tool requested sandbox bypass": all(not x["input"].get("dangerouslyDisableSandbox") for x in r.tool_uses)},
        setup=sandbox_boundary)
    run("reviewer-mcp-edit", 'Use Read on notes.txt. Append " (verified)" to the Primary contact line using '
        'only DataFog edit_with_markers with the exact full line as old_string; do not use built-in Edit.',
        lambda r: {"MCP edit called": any(x["name"] == EDIT_TOOL for x in r.tool_uses),
                   "real value restored on disk": SENTINELS["EMAIL ada"] + " (verified)" in (driver.disk("notes.txt") or ""),
                   "no marker on disk": not MARKER.search(driver.disk("notes.txt") or "")})
    run("built-in-edit-marker-old-string", 'Use Read on notes.txt. Append " (checked)" to the Primary contact line using '
        'the built-in Edit tool with the exact full line including its marker as old_string.',
        lambda r: {"Edit called": any(x["name"] == "Edit" for x in r.tool_uses),
                   "host rejects marker old_string before hook": any("String to replace not found" in x["text"] for x in r.results_of("Edit")),
                   "file unchanged": "(checked)" not in (driver.disk("notes.txt") or "")})
    run("built-in-edit-marker-new-string", 'Use Read on notes.txt. Use the built-in Edit tool once to replace '
        'the exact old_string "Status: waiting on reply" with "Status: contact " followed by the email marker '
        'from the Primary contact line. Do not put a marker in old_string.',
        lambda r: {"Edit called": any(x["name"] == "Edit" for x in r.tool_uses),
                   "real value restored on disk": "Status: contact " + SENTINELS["EMAIL ada"] in (driver.disk("notes.txt") or "")})

    def script_fixture(project, body):
        (project / "probe.sh").write_text(body)
        path = project / ".claude/settings.local.json"
        settings = json.loads(path.read_text())
        settings["permissions"]["allow"].append("Bash(sh probe.sh)")
        path.write_text(json.dumps(settings))

    run("runner-complete-output", "Run exactly one Bash call: sh probe.sh. Report the first and last output lines.",
        lambda r: {"all stdout lines collected": all("OUT-%04d" % i in "\n".join(x["text"] for x in r.results_of("Bash")) for i in range(100)),
                   "all stderr lines collected": all("ERR-%04d" % i in "\n".join(x["text"] for x in r.results_of("Bash")) for i in range(100))},
        setup=lambda p: script_fixture(p, "i=0\nwhile [ $i -lt 100 ]; do printf 'OUT-%04d\\n' \"$i\"; printf 'ERR-%04d\\n' \"$i\" >&2; i=$((i+1)); done\n"))

    def timeout_checks(result):
        time.sleep(6)  # The script's delayed side effect must not survive timeout.
        calls = [x for x in result.tool_uses if x["name"] == "Bash"]
        return {"requested short timeout used": bool(calls) and calls[0]["input"].get("timeout", 999999) <= 1000,
                "host reported timeout": any("timed out" in x["text"].lower() for x in result.results_of("Bash")),
                "descendant side effect absent": not os.path.exists(os.path.join(driver.project, "SURVIVED"))}

    def background_checks(result):
        time.sleep(6)
        return {"host auto-backgrounded despite foreground request": any("moved to the background" in x["text"] for x in result.results_of("Bash")),
                "background command completed its side effect": os.path.exists(os.path.join(driver.project, "SURVIVED"))}

    run("runner-timeout-background", "Run one Bash call with command sh probe.sh, timeout 1000 milliseconds, and run_in_background false. Then stop.",
        background_checks, setup=lambda p: script_fixture(p, "sleep 5\nprintf 'survived' > SURVIVED\n"))
    run("runner-timeout-no-background", "Run one Bash call with command sh probe.sh, timeout 1000 milliseconds, and run_in_background false. Then stop.",
        timeout_checks, setup=lambda p: script_fixture(p, "sleep 5\nprintf 'survived' > SURVIVED\n"),
        env={"CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1"})

    def cancellation_checks(result):
        time.sleep(12)
        return {"TaskStop called": any(x["name"] == "TaskStop" for x in result.tool_uses),
                "host confirmed stop": any(not x["is_error"] for x in result.results_of("TaskStop")),
                "descendant side effect absent": not os.path.exists(os.path.join(driver.project, "SURVIVED"))}

    run("runner-cancel", "Run one Bash call with command sh probe.sh, timeout 1000 milliseconds, and run_in_background false. "
        "If the host moves it to the background, immediately use TaskStop on that task ID. Do not wait for completion. Then stop.",
        cancellation_checks, setup=lambda p: script_fixture(p, "sleep 10\nprintf 'survived' > SURVIVED\n"))
    for mode in ("dontAsk", "plan", "bypassPermissions", "auto"):
        def denied(r):
            calls = [x for x in r.tool_uses if x["name"] == "Bash"]
            denials = r.result.get("permission_denials") or []
            return {"Bash attempted": bool(calls), "host denied call": bool(denials),
                    "denied command retains marker": bool(denials) and all(MARKER.search(json.dumps(x)) for x in denials),
                    "denial contains no raw value": not leaked(json.dumps(denials))}
        run("mode-marker-" + mode, "Run exactly one Bash call: grep -cxF '" + driver.nasty_marker + "' nasty.txt. If refused, stop.", denied, mode=mode)
    run("subagent-mode", "Use the Agent tool to create one general-purpose subagent. Its task is to use Read on plain.txt and report its first line. Do not read the file yourself.",
        lambda r: {"subagent Read observed": any(x["subagent"] and x["name"] == "Read" for x in r.tool_uses)})
    subprocess.run(["claude", "--version"], check=True)
    selected = {r["case"] for r in evidence}
    if set(sys.argv[1:]) - selected:
        raise SystemExit("Unknown cases: " + ", ".join(sorted(set(sys.argv[1:]) - selected)))
    raise SystemExit(0 if evidence and all(all(r["checks"].values()) for r in evidence) else 1)


if __name__ == "__main__":
    main()
