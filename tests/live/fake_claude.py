#!/usr/bin/env python3
"""A small stand-in for the `claude` CLI, used ONLY to test run_live.py and to exercise
hooks.json, the launcher and the engine together without a Claude Code login.

It is a simulation written from the hook documentation and the spike's recordings. It
proves nothing about how Claude Code really behaves: that is what the live run is for.

What it does for `claude -p <prompt> --plugin-dir <dir> --output-format stream-json ...`:
runs the plugin's real hook commands (SessionStart, UserPromptSubmit, PreToolUse,
PostToolUse) around a scripted list of tool calls chosen by the `[case:ID]` tag in the
prompt, executes the tools for real in the working directory, and prints stream-json.
The scripted "model" repeats what it saw, so a leak in a tool result shows up in its text.

Bash permissions, as measured on Claude Code 2.1.299 in a headless run: the plugin rewrites every
Bash command, the user's allow rules do not match the rewritten text, so a Bash call runs only
when the PreToolUse hook itself returns "allow". "ask" or no decision ends as a denial (nobody can
answer), "deny" is a refusal. The simulator reads no settings files itself: the hook does.

Switches (environment):
  SIM_IGNORE_HOOK_ALLOW=1        a hook "allow" for Bash is not honoured (the call is denied), to show
                                 what the driver reports if Claude Code behaved that way
  SIM_STRICT_READ_TRACKING=1     Write/Edit of an existing file is refused unless that exact
                                 path was the one Read actually opened
  SIM_NO_HOOKS=1                 run no hooks at all (what an unprotected session looks like)
"""
import json
import os
import re
import subprocess
import sys

VERSION = "2.1.299 (Claude Code) [fake_claude simulator]"
MARKER = re.compile(r"\[\[[A-Z][A-Z0-9_]*_[0-9A-Z]{6}\]\]")
EDIT_TOOL = "mcp__plugin_datafog_guard__edit_with_markers"


def emit(row):
    sys.stdout.write(json.dumps(row) + "\n")
    sys.stdout.flush()


class Session:
    def __init__(self, plugin, prompt):
        self.plugin = os.path.abspath(plugin)
        self.prompt = prompt
        self.cwd = os.getcwd()
        self.mode = sys.argv[sys.argv.index("--permission-mode") + 1] if "--permission-mode" in sys.argv \
            else "default"
        self.project = self.cwd
        self.hooks = {}
        if os.environ.get("SIM_NO_HOOKS") != "1":
            with open(os.path.join(self.plugin, "hooks", "hooks.json")) as handle:
                self.hooks = json.load(handle)["hooks"]
        self.count = 0
        self.denials = []
        self.read_paths = set()
        self.said = []
        self.env = dict(os.environ, CLAUDE_PLUGIN_ROOT=self.plugin, CLAUDE_PROJECT_DIR=self.project,
                        CLAUDE_PLUGIN_DATA=os.environ.get("DATAFOG_DATA_DIR") or
                        os.path.join(os.path.dirname(self.cwd), "sim-plugin-data"))

    # -- hooks ---------------------------------------------------------------
    def hook(self, event, payload):
        """Run the plugin's hook for an event. Returns (parsed JSON or None, blocked by failure)."""
        groups = self.hooks.get(event) or []
        if not groups:
            return None, False
        entry = groups[0]["hooks"][0]
        command = entry["command"].replace("${CLAUDE_PLUGIN_ROOT}", self.plugin)
        payload = dict(payload, hook_event_name=event, session_id="sim", cwd=self.cwd,
                       transcript_path="/dev/null", permission_mode=self.mode)
        try:
            result = subprocess.run(["sh", "-c", command], input=json.dumps(payload).encode(), capture_output=True,
                                    env=self.env, cwd=self.cwd, timeout=entry.get("timeout", 60))
        except subprocess.TimeoutExpired:
            return None, entry.get("onFailure") == "block"
        if result.returncode == 2:
            return {"_stderr": result.stderr.decode(errors="replace")}, True
        try:
            out = json.loads(result.stdout) if result.stdout.strip() else None
        except ValueError:
            return None, entry.get("onFailure") == "block"
        if result.returncode != 0:
            return out, entry.get("onFailure") == "block"
        return out, False

    # -- tools -----------------------------------------------------------------
    def execute(self, tool, tool_input):
        """Returns (structured response, text the model sees, is_error)."""
        if tool == "Read":
            path = tool_input["file_path"]
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            self.read_paths.add(os.path.realpath(path))
            lines = content.count("\n")
            return ({"type": "text", "file": {"content": content, "filePath": path, "numLines": lines,
                                              "startLine": 1, "totalLines": lines}}, None, False)
        if tool == "Bash":
            tracker = os.path.join(os.path.dirname(self.project), "sim-cwd")
            script = 'eval "$SIM_COMMAND"\n__sim_rc=$?\npwd -P >| "$SIM_CWD_FILE"\nexit $__sim_rc'
            result = subprocess.run(["bash", "-c", script], capture_output=True, cwd=self.cwd,
                                    env=dict(os.environ, SIM_COMMAND=tool_input["command"], SIM_CWD_FILE=tracker),
                                    stdin=subprocess.DEVNULL, timeout=120)
            try:
                with open(tracker) as handle:
                    self.cwd = handle.read().strip() or self.cwd
            except OSError:
                pass
            out, err = result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace")
            if result.returncode != 0:
                return None, "Exit code %d\n%s%s" % (result.returncode, out, err), True
            return ({"stdout": out, "stderr": err, "interrupted": False, "isImage": False,
                     "noOutputExpected": False}, None, False)
        if tool == "Grep":
            path = os.path.join(self.cwd, tool_input.get("path") or ".")
            matched = []
            with open(path, encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if re.search(tool_input["pattern"], line):
                        matched.append("%d:%s" % (number, line.rstrip("\n")))
            return ({"content": "\n".join(matched), "filenames": [], "mode": "content", "numFiles": 0,
                     "numLines": len(matched), "totalLines": len(matched)}, None, False)
        if tool in ("Write", "Edit"):
            path = tool_input["file_path"]
            exists = os.path.exists(path)
            if exists and os.environ.get("SIM_STRICT_READ_TRACKING") == "1" and \
                    os.path.realpath(path) not in self.read_paths:
                return None, "File has not been read yet. Read it first before writing to it.", True
            original = open(path, encoding="utf-8").read() if exists else None
            if tool == "Write":
                content = tool_input["content"]
            else:
                if original is None or tool_input["old_string"] not in original:
                    return None, "String to replace not found in file.", True
                content = original.replace(tool_input["old_string"], tool_input["new_string"], 1)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            return ({"type": "update" if exists else "create", "filePath": path, "content": content,
                     "originalFile": original, "structuredPatch": [], "userModified": False},
                    "The file %s has been %s." % (path, "updated" if exists else "created"), False)
        if tool == EDIT_TOOL:
            with open(os.path.join(self.plugin, ".mcp.json")) as handle:
                server = json.load(handle)["mcpServers"]["guard"]
            env = dict(self.env)
            for key, value in (server.get("env") or {}).items():
                env[key] = re.sub(r"\$\{(\w+)(?::-([^}]*))?\}",
                                  lambda m: self.env.get(m.group(1)) or (m.group(2) or ""), value)
            argv = [a.replace("${CLAUDE_PLUGIN_ROOT}", self.plugin) for a in [server["command"], *server["args"]]]
            requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "edit_with_markers", "arguments": tool_input}}]
            result = subprocess.run(argv, input="".join(json.dumps(r) + "\n" for r in requests).encode(),
                                    capture_output=True, env=env, cwd=self.project, timeout=120)
            reply = json.loads(result.stdout.decode().strip().splitlines()[-1])["result"]
            return reply["content"], None, bool(reply.get("isError"))
        raise ValueError(tool)

    @staticmethod
    def visible(tool, response):
        if tool == "Read":
            return "\n".join("%6d\t%s" % (n, line) for n, line in
                             enumerate(response["file"]["content"].splitlines(), response["file"]["startLine"]))
        if tool == "Bash":
            return response["stdout"] + response["stderr"]
        if tool == "Grep":
            return response["content"]
        if isinstance(response, list):
            return "\n".join(item.get("text", "") for item in response)
        return json.dumps(response)

    def call(self, tool, tool_input, parent=None):
        """One tool call with its hooks. Returns the text the model sees."""
        self.count += 1
        use_id = "toolu_sim%03d" % self.count
        emit({"type": "assistant", "parent_tool_use_id": parent,
              "message": {"content": [{"type": "tool_use", "id": use_id, "name": tool, "input": tool_input}]}})
        text, is_error = self._call(tool, tool_input, use_id, parent)
        emit({"type": "user", "parent_tool_use_id": parent,
              "message": {"content": [{"type": "tool_result", "tool_use_id": use_id, "content": text,
                                       "is_error": is_error}]}})
        return text

    def _call(self, tool, tool_input, use_id, parent):
        if tool == "Edit":   # Claude Code validates Edit against the file before any hook runs
            try:
                with open(tool_input["file_path"], encoding="utf-8") as handle:
                    if tool_input["old_string"] not in handle.read():
                        return "String to replace not found in file.", True
            except OSError:
                return "File does not exist.", True
        base = {"tool_name": tool, "tool_input": tool_input, "tool_use_id": use_id}
        if parent:
            base.update(agent_id="agent_sim", agent_type="general-purpose")
        out, failed = self.hook("PreToolUse", base)
        spec = (out or {}).get("hookSpecificOutput") or {}
        if failed:
            return "PreToolUse hook blocked the call: " + str((out or {}).get("_stderr", "hook failed")), True
        decision = spec.get("permissionDecision")
        if decision == "deny":
            return spec.get("permissionDecisionReason", "denied"), True
        if decision == "ask":
            self.denials.append({"tool_name": tool, "tool_use_id": use_id,
                                 "tool_input": spec.get("updatedInput", tool_input)})
            return ("This call needs permission and nobody can answer in a headless run. "
                    + spec.get("permissionDecisionReason", "")), True
        tool_input = spec.get("updatedInput", tool_input)
        if tool == "Bash" and (decision != "allow" or os.environ.get("SIM_IGNORE_HOOK_ALLOW") == "1"):
            # the record of a denied call holds the command as the hook rewrote it
            self.denials.append({"tool_name": tool, "tool_use_id": use_id, "tool_input": tool_input})
            return "Permission to use Bash with this command has been denied.", True
        if tool == "Agent":
            report = self.script_subagent(use_id)
            response = {"agentId": "agent_sim", "agentType": "general-purpose", "status": "completed",
                        "content": [{"type": "text", "text": report}], "prompt": tool_input.get("prompt", ""),
                        "totalToolUseCount": 1}
            text, is_error = None, False
        else:
            try:
                response, text, is_error = self.execute(tool, tool_input)
            except Exception as error:
                return "Tool failed: %s" % type(error).__name__, True
        if is_error and response is None:
            return text, True            # PostToolUseFailure: nothing can be replaced
        out, _ = self.hook("PostToolUse", dict(base, tool_input=tool_input, tool_response=response))
        spec = (out or {}).get("hookSpecificOutput") or {}
        if "updatedToolOutput" in spec:
            response = spec["updatedToolOutput"]
            text = None if tool in ("Read", "Bash", "Grep", EDIT_TOOL, "Agent") else text
        if tool == "Agent":
            return response["content"][0]["text"], False
        return (text if text is not None else self.visible(tool, response)), is_error

    # -- the scripted "model" ----------------------------------------------------
    def line(self, text, needle):
        """A line as the model saw it (line-number prefix removed)."""
        for line in text.splitlines():
            if needle in line:
                return line.split("\t", 1)[-1]
        return ""

    def body(self, text):
        return "\n".join(line.split("\t", 1)[-1] for line in text.splitlines()) + "\n"

    def script_subagent(self, parent):
        seen = self.call("Read", {"file_path": os.path.join(self.project, "config.env")}, parent=parent)
        return "The SUPPORT_EMAIL line is: " + self.line(seen, "SUPPORT_EMAIL")

    def script(self, case):
        path = lambda name: os.path.join(self.project, name)   # noqa: E731
        if case.startswith("probe"):
            return "LIVE_OK"
        if case == "L01-read":
            seen = self.call("Read", {"file_path": path("notes.txt")})
            return self.line(seen, "Primary contact") + "\n" + self.line(seen, "Test card")
        if case.startswith("L02"):
            return self.call("Bash", {"command": "cat config.env", "description": "Print config.env"})
        if case == "L03-bash-fail":
            return self.call("Bash", {"command": "cat notes.txt missing-file.txt"})
        if case == "L04-bash-cd":
            self.call("Bash", {"command": "cd sub"})
            second = self.call("Bash", {"command": "pwd"})
            return second + self.call("Bash", {"command": "cat inner.env"})
        if case == "L05-bash-exit-trap":
            return self.call("Bash", {"command": "sh trap-step.sh"})
        if case == "L06-bash-colour":
            return self.call("Bash", {"command": "grep --color=always 05 notes.txt"})
        if case in ("L18-bash-marker-ask", "L19-bash-marker-allow"):
            seen = self.call("Read", {"file_path": path("notes.txt")})
            value = self.line(seen, "Primary contact").split(": ", 1)[-1]
            return self.call("Bash", {"command": "grep -c %s notes.txt" % value})
        if case == "L25-bash-nasty-value":
            seen = self.call("Read", {"file_path": path("handoff.txt")})
            value = self.line(seen, "Deploy token").split(": ", 1)[-1]
            return self.call("Bash", {"command": "grep -cxF -- %s nasty.txt" % value})
        if case == "L21-bash-complex":
            return self.call("Bash", {"command": "cat config.env | head -2"})
        if case == "L22-bash-denied":
            return self.call("Bash", {"command": "rm scratch.tmp"})
        if case == "L23-bash-ask-rule":
            return self.call("Bash", {"command": "git push origin main"})
        if case == "L28-bash-read-deny-quoted-glob":
            return self.call("Bash", {"command": 'cat "s"ecret.en*'})
        if case == "L29-bash-marker-unlisted-program":
            seen = self.call("Read", {"file_path": path("notes.txt")})
            value = self.line(seen, "Primary contact").split(": ", 1)[-1]
            return self.call("Bash", {"command": "./argdump %s" % value})
        if case == "L26-bash-read-deny":
            return self.call("Bash", {"command": "cat secret.env"})
        if case == "L27-bash-read-deny-directory":
            return self.call("Bash", {"command": "grep -r NOTE ."})
        if case == "L24-bash-untrusted-project-allow":
            return self.call("Bash", {"command": "wc -l plain.txt"})
        if case == "L07-grep":
            return self.call("Grep", {"pattern": "synthetic", "path": "customers.csv", "output_mode": "content"})
        if case == "L08-write-restore":
            seen = self.call("Read", {"file_path": path("notes.txt")})
            value = self.line(seen, "Primary contact").split(": ", 1)[-1]
            return self.call("Write", {"file_path": path("contact.txt"), "content": value})
        if case == "L09-edit-tool":
            seen = self.call("Read", {"file_path": path("notes.txt")})
            old = self.line(seen, "Primary contact")
            return self.call(EDIT_TOOL, {"file_path": path("notes.txt"), "old_string": old,
                                         "new_string": old + " (verified)"})
        if case == "L10-write-over-read":
            seen = self.call("Read", {"file_path": path("notes.txt")})
            return self.call("Write", {"file_path": path("notes.txt"), "content": self.body(seen) + "Reviewed: yes\n"})
        if case == "L11-edit-plain-line":
            self.call("Read", {"file_path": path("notes.txt")})
            return self.call("Edit", {"file_path": path("notes.txt"), "old_string": "Status: waiting on reply",
                                      "new_string": "Status: resolved"})
        if case == "L12-plain-file":
            self.call("Read", {"file_path": path("plain.txt")})
            return self.call("Edit", {"file_path": path("plain.txt"), "old_string": "tag the release",
                                      "new_string": "tag and publish the release"})
        if case == "L13-at-file":       # reached only when the prompt was not blocked: the attachment is in context
            return open(path("notes.txt")).read()
        if case == "L14-prompt-pii":
            return "Hello! (written for " + " ".join(w for w in self.prompt.split() if "@" in w) + ")"
        if case == "L15-subagent":
            return self.call("Agent", {"description": "Read SUPPORT_EMAIL", "subagent_type": "general-purpose",
                                       "prompt": "Read config.env and report the SUPPORT_EMAIL line."})
        if case == "L16-engine-broken":
            first = self.call("Read", {"file_path": path("notes.txt")})
            second = self.call("Bash", {"command": "cat config.env"})
            return "Read said: %s\nBash said: %s" % (first, second)
        if case == "L17-engine-breaks-mid-session":
            first = self.call("Bash", {"command": "sh break-step.sh"})
            second = self.call("Read", {"file_path": path("notes.txt")})
            third = self.call("Bash", {"command": "cat config.env"})
            return "1: %s\n2: %s\n3: %s" % (first, second, third)
        return "I have no script for this prompt."

    def run(self):
        tools = ["Read", "Write", "Edit", "Bash", "Grep", "Glob", "Agent"]
        if self.hooks:
            tools += [EDIT_TOOL, "mcp__plugin_datafog_guard__protection_status"]
        emit({"type": "system", "subtype": "init", "cwd": self.cwd, "tools": tools, "permissionMode": "acceptEdits",
              "claude_code_version": VERSION, "plugins": [{"name": "datafog", "path": self.plugin}],
              "mcp_servers": [{"name": "plugin:datafog:guard", "status": "connected"}]})
        self.hook("SessionStart", {"source": "startup"})
        out, failed = self.hook("UserPromptSubmit", {"prompt": self.prompt})
        if failed or (out or {}).get("decision") == "block":
            emit({"type": "result", "subtype": "error_during_execution", "is_error": True, "result": "",
                  "num_turns": 0, "permission_denials": []})
            return 0
        match = re.search(r"\[case:([^\]]+)\]", self.prompt)
        final = self.script(match.group(1) if match else "probe")
        emit({"type": "assistant", "parent_tool_use_id": None, "message": {"content": [{"type": "text", "text": final}]}})
        emit({"type": "result", "subtype": "success", "is_error": False, "result": final, "num_turns": self.count + 1,
              "permission_denials": self.denials})
        return 0


def main(argv):
    if argv[:1] == ["--version"]:
        print(VERSION)
        return 0
    if argv[:2] == ["plugin", "validate"]:
        print("fake_claude: validation is not simulated")
        return 0
    if "-p" not in argv:
        print("fake_claude: only -p is simulated", file=sys.stderr)
        return 2
    prompt = argv[argv.index("-p") + 1]
    if "--plugin-dir" not in argv:
        print("LIVE_OK" if "LIVE_OK" in prompt else "ok")
        return 0
    if "--setting-sources" not in argv or argv[argv.index("--setting-sources") + 1:][:1] != ["project,local"]:
        print("fake_claude: live runs must isolate fixture settings with --setting-sources project,local",
              file=sys.stderr)
        return 2
    if "--strict-mcp-config" in argv:
        print("fake_claude: strict MCP config would hide the plugin's own MCP tools", file=sys.stderr)
        return 2
    return Session(argv[argv.index("--plugin-dir") + 1], prompt).run()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
