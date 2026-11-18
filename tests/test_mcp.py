"""The plugin's MCP server over real stdio JSON-RPC."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys

import pytest
from conftest import CARD, EMAIL, NOTES, PHONE, assert_no_sentinel, corrupt_vault

EDIT = "edit_with_markers"


class Client:
    def __init__(self, box, **env):
        self.box = box
        self.process = subprocess.Popen([sys.executable, "-m", "datafog_guard", "mcp"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                        env=box.env(**env), cwd=box.project)
        self.number = 0
        self.raw = ""

    def request(self, method, params=None):
        self.number += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.number, "method": method,
                                             "params": params or {}}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        self.raw += line
        reply = json.loads(line)
        assert reply["id"] == self.number
        return reply

    def call(self, name, **arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})["result"]
        assert list(result) == ["content", "isError"] and result["content"][0]["type"] == "text"
        return result["content"][0]["text"], result["isError"]

    def close(self) -> str:
        self.process.stdin.close()
        self.process.wait(timeout=20)
        return self.raw + self.process.stdout.read() + self.process.stderr.read()


@pytest.fixture
def client(box):
    client = Client(box)
    yield client
    everything = client.close()
    assert_no_sentinel(everything, "in an MCP response")
    assert_no_sentinel(box.visible_files(), "in a file written by the engine")


def test_protocol_handshake_and_tool_list(client):
    reply = client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
    assert reply["result"]["protocolVersion"] == "2025-06-18"
    assert reply["result"]["serverInfo"]["name"] == "datafog-guard"
    client.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    tools = client.request("tools/list")["result"]["tools"]
    assert [tool["name"] for tool in tools] == [EDIT, "protection_status"]
    assert tools[0]["inputSchema"]["required"] == ["file_path", "old_string", "new_string"]
    assert client.request("ping")["result"] == {}
    assert client.request("no/such")["error"]["code"] == -32601


def tokenized_notes(box):
    path = box.write("notes.txt", NOTES)
    return path, box.open_vault().tokenize(NOTES)[0]


def test_edit_a_line_that_holds_a_marker(box, client):
    path, shown = tokenized_notes(box)
    old = shown.splitlines()[2]                       # "Primary contact: [[EMAIL_...]]"
    marker = old.split(": ")[1]
    text, error = client.call(EDIT, file_path=str(path), old_string=old, new_string=f"Main contact: {marker} (verified)")
    assert not error
    assert "1 replacement(s) at line(s) 3" in text and "1 EMAIL" in text or "2 EMAIL" in text
    assert path.read_text() == NOTES.replace(f"Primary contact: {EMAIL}", f"Main contact: {EMAIL} (verified)")


def test_edit_can_move_a_value_between_lines(box, client):
    path, shown = tokenized_notes(box)
    card_marker = shown.splitlines()[5].split(": ")[1]
    text, error = client.call(EDIT, file_path=str(path), old_string="End of notes", new_string=f"Backup card: {card_marker}")
    assert not error and "line(s) 8" in text
    assert path.read_text().endswith(f"Backup card: {CARD}\n")


def test_edit_uniqueness_rule_matches_the_builtin_edit(box, client):
    path = box.write("dup.txt", f"to {EMAIL}\ncc {EMAIL}\nbcc {EMAIL}\n")
    marker = box.open_vault().tokenize(EMAIL)[0]
    text, error = client.call(EDIT, file_path=str(path), old_string=marker, new_string="x@example.org")
    assert error and "matches 3 places" in text and path.read_text().count(EMAIL) == 3
    text, error = client.call(EDIT, file_path=str(path), old_string=f"\ncc {marker}", new_string="\ncc nobody")
    assert not error and "line(s) 1" in text      # the match starts at the end of line 1
    text, error = client.call(EDIT, file_path=str(path), old_string=marker, new_string="[[EMAIL_ZZZZZZ]]", replace_all=True)
    assert not error and "2 replacement(s) at line(s) 1, 3" in text and "1 marker-like" in text
    assert path.read_text() == "to [[EMAIL_ZZZZZZ]]\ncc nobody\nbcc [[EMAIL_ZZZZZZ]]\n"


def test_edit_errors_reveal_nothing(box, client):
    path, shown = tokenized_notes(box)
    for arguments, needle in [
        (dict(file_path=str(path), old_string="not in the file", new_string="x"), "not found"),
        (dict(file_path=str(path), old_string="[[EMAIL_ZZZZZZ]]", new_string="x"), "not known to the vault"),
        (dict(file_path=str(path), old_string="same", new_string="same"), "nothing to change"),
        (dict(file_path=str(path), old_string="", new_string="x"), "empty"),
        (dict(file_path=str(box.project / "missing.txt"), old_string="a", new_string="b"), "does not exist"),
        (dict(file_path=str(path), old_string=5, new_string="b"), "must be strings"),
    ]:
        text, error = client.call(EDIT, **arguments)
        assert error and needle in text, text
    assert path.read_text() == NOTES


def test_edit_refuses_paths_outside_the_project_and_inside_storage(box, client):
    outside = box.tmp / "outside.txt"
    outside.write_text(NOTES)
    link = box.project / "link.txt"
    link.symlink_to(outside)
    box.open_vault().tokenize(EMAIL)
    for target in (outside, link, box.vault / "workspace.enc", box.vault / "markers.index", box.data / "runtime.json", "/etc/hosts",
                   box.project / ".." / "outside.txt"):
        text, error = client.call(EDIT, file_path=str(target), old_string="a", new_string="b")
        assert error and "Refused" in text, target
    assert outside.read_text() == NOTES


@pytest.mark.parametrize("scope", ["user", "project", "local"])
@pytest.mark.parametrize("tool", ["Read", "Edit"])
@pytest.mark.parametrize("kind", ["deny", "ask"])
def test_edit_respects_file_permissions_in_every_scope(box, client, scope, tool, kind):
    path = box.write("protected.txt", "original")
    box.claude_settings(scope, {kind: [f"{tool}(./protected.txt)"]})
    text, error = client.call(EDIT, file_path=str(path), old_string="original", new_string="changed")
    assert error and f"{tool} {kind} rule" in text
    assert path.read_text() == "original"


def test_edit_checks_alias_and_real_target_permissions(box, client):
    target = box.write("protected.txt", "original")
    link = box.project / "alias.txt"
    link.symlink_to(target)
    for rule in ("Edit(./protected.txt)", "Read(./alias.txt)"):
        box.claude_settings("local", {"deny": [rule]})
        text, error = client.call(EDIT, file_path=str(link), old_string="original", new_string="changed")
        assert error and "deny rule" in text
        assert target.read_text() == "original" and link.is_symlink()


@pytest.mark.parametrize("settings", ['{"permissions":', {"deny": ["Edit(../secret)"]}])
def test_edit_refuses_unreadable_or_unsupported_permissions(box, client, settings):
    path = box.write("notes.txt", "original")
    box.claude_settings("user", settings)
    text, error = client.call(EDIT, file_path=str(path), old_string="original", new_string="changed")
    assert error and "Refused" in text
    assert path.read_text() == "original"


def test_edit_reloads_rules_between_calls_and_allows_uncovered_files(box, client):
    path = box.write("notes.txt", "original")
    box.claude_settings("local", {"deny": ["Read(./other.txt)"]})
    _, error = client.call(EDIT, file_path=str(path), old_string="original", new_string="first")
    assert not error
    box.claude_settings("local", {"deny": ["Edit(./notes.txt)"]})
    text, error = client.call(EDIT, file_path=str(path), old_string="first", new_string="second")
    assert error and "deny rule" in text and path.read_text() == "first"


def test_edit_through_a_shadow_path_edits_the_real_file(box, client):
    path = box.write("notes.txt", NOTES)
    out, _ = box.pre("Read", {"file_path": str(path)})
    shadow = out["hookSpecificOutput"]["updatedInput"]["file_path"]
    text, error = client.call(EDIT, file_path=shadow, old_string="End of notes", new_string="Fin")
    assert not error and path.read_text().endswith("Fin\n")
    assert "End of notes" in open(shadow).read(), "the shadow copy itself is not edited"


def test_edit_keeps_permissions_and_crlf(box, client):
    path = box.write("win.txt", f"a\r\nmail {EMAIL}\r\nz\r\n".encode())
    os.chmod(path, 0o640)
    marker = box.open_vault().tokenize(EMAIL)[0]
    text, error = client.call(EDIT, file_path=str(path), old_string=f"mail {marker}", new_string=f"email {marker}")
    assert not error
    assert path.read_bytes() == f"a\r\nemail {EMAIL}\r\nz\r\n".encode()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640


def test_edit_internal_symlink_updates_target_without_replacing_link(box, client):
    target = box.write("target.txt", "original")
    link = box.project / "alias.txt"
    link.symlink_to(target)
    _, error = client.call(EDIT, file_path=str(link), old_string="original", new_string="updated")
    assert not error and link.is_symlink() and target.read_text() == "updated"


@pytest.mark.parametrize("change", ["in_place", "replace", "symlink", "remove"])
def test_edit_snapshot_refuses_intervening_file_changes(box, change):
    from datafog_guard.mcp_server import EditableFile, ToolError

    path = box.write("target.txt", "original")
    other = box.write("other.txt", "new save")
    with EditableFile(str(path), str(box.project), 1024) as target:
        assert target.read() == b"original"
        if change == "in_place":
            path.write_text("new save")   # same length: size alone is insufficient
        elif change == "replace":
            os.replace(other, path)
        else:
            path.unlink()
            if change == "symlink":
                path.symlink_to(other)
        with pytest.raises(ToolError, match="changed while preparing"):
            target.replace(b"plugin edit")
    assert not list(box.project.glob("*.tmp"))
    if change != "remove":
        assert path.read_text() == "new save"
    else:
        assert not path.exists()


def test_edit_snapshot_refuses_replaced_parent_directory(box):
    from datafog_guard.mcp_server import EditableFile, ToolError

    (box.project / "nested").mkdir()
    path = box.write("nested/target.txt", "original")
    with EditableFile(str(path), str(box.project), 1024) as target:
        target.read()
        path.parent.rename(box.project / "moved")
        path.parent.mkdir()
        path.write_text("new save")
        with pytest.raises(ToolError, match="changed while preparing"):
            target.replace(b"plugin edit")
    assert path.read_text() == "new save"
    assert (box.project / "moved" / "target.txt").read_text() == "original"
    assert not list(box.project.rglob("*.tmp"))


def test_edit_snapshot_refuses_retargeted_alias_before_reading(box):
    from datafog_guard.mcp_server import EditableFile, ToolError

    original = box.write("original.txt", "original")
    other = box.tmp / "outside.txt"
    other.write_text("outside")
    link = box.project / "alias.txt"
    link.symlink_to(original)
    target = EditableFile(str(link), str(box.project), 1024)
    link.unlink()
    link.symlink_to(other)
    with target:
        with pytest.raises(ToolError, match="changed while preparing"):
            target.read()
    assert original.read_text() == "original" and other.read_text() == "outside"


def test_server_refuses_alias_retargeted_between_permission_check_and_open(box, monkeypatch):
    from datafog_guard import ccperms
    from datafog_guard.mcp_server import Server

    for key, value in box.env().items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    safe = box.write("safe.txt", "original")
    denied = box.write("denied.txt", "original")
    link = box.project / "alias.txt"
    link.symlink_to(safe)
    box.claude_settings("local", {"deny": ["Edit(./denied.txt)"]})
    original_check = ccperms.check_file_path
    first = True

    def retarget_after_check(*args, **kwargs):
        nonlocal first
        result = original_check(*args, **kwargs)
        if first:
            first = False
            link.unlink()
            link.symlink_to(denied)
        return result

    monkeypatch.setattr(ccperms, "check_file_path", retarget_after_check)
    result = Server().call_tool({"name": EDIT, "arguments": {
        "file_path": str(link), "old_string": "original", "new_string": "changed"}})
    assert result["isError"] and "changed while preparing" in result["content"][0]["text"]
    assert safe.read_text() == "original" and denied.read_text() == "original"


def test_edit_snapshot_serializes_cooperating_editors(box):
    from datafog_guard.mcp_server import EditableFile, ToolError

    path = box.write("target.txt", "original")
    with EditableFile(str(path), str(box.project), 1024) as first:
        first.read()
        with pytest.raises(ToolError, match="another process"):
            with EditableFile(str(path), str(box.project), 1024):
                pytest.fail("the same original file must not be edited concurrently")
        first.replace(b"first edit")
    with EditableFile(str(path), str(box.project), 1024) as second:
        assert second.read() == b"first edit"
        second.replace(b"second edit")
    assert path.read_text() == "second edit"


def test_edit_snapshot_read_remains_bounded_if_file_grows(box, monkeypatch):
    from datafog_guard.mcp_server import EditableFile, ToolError

    path = box.write("target.txt", "small")
    with EditableFile(str(path), str(box.project), 10) as target:
        original_read = os.read
        read_bytes = 0

        def growing_read(fd, size):
            nonlocal read_bytes
            path.write_bytes(b"x" * 100)
            result = original_read(fd, size)
            read_bytes += len(result)
            return result

        monkeypatch.setattr(os, "read", growing_read)
        with pytest.raises(ToolError, match="too large"):
            target.read()
        assert read_bytes == 11


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires Unix FIFO")
def test_edit_refuses_fifo_without_waiting_for_a_writer(box, client):
    path = box.project / "pipe"
    os.mkfifo(path)
    text, error = client.call(EDIT, file_path=str(path), old_string="old", new_string="new")
    assert error and "not a regular file" in text


def test_long_lived_server_sees_markers_created_after_it_started(box, client):
    path = box.write("a.txt", f"contact {PHONE}\n")
    client.request("initialize")
    client.call("protection_status")                      # the server has opened the (empty) vault
    out, _ = box.pre("Read", {"file_path": str(path)})    # a hook process creates the marker later
    shown = open(out["hookSpecificOutput"]["updatedInput"]["file_path"]).read().strip()
    text, error = client.call(EDIT, file_path=str(path), old_string=shown, new_string=shown + " (mobile)")
    assert not error and path.read_text() == f"contact {PHONE} (mobile)\n"


def test_protection_status_has_types_and_counts_only(box, client):
    box.open_vault().tokenize(NOTES)
    text, error = client.call("protection_status")
    assert not error and "Protection: ON" in text and "1 EMAIL" in text and "encryption at rest: encrypted" in text
    assert str(box.vault) not in text, "the model does not need the vault path"


def test_server_with_a_broken_vault_reports_without_details(box):
    box.write("notes.txt", NOTES)
    corrupt_vault(box.vault, b"corrupt " + EMAIL.encode())
    client = Client(box)
    text, error = client.call(EDIT, file_path=str(box.project / "notes.txt"), old_string="End", new_string="Fin")
    assert error and "vault_corrupt" in text and "Nothing was changed" in text
    text, _ = client.call("protection_status")
    assert "NOT WORKING" in text
    assert_no_sentinel(client.close())
    assert (box.project / "notes.txt").read_text() == NOTES


def test_project_dir_placeholder_falls_back_to_cwd(box):
    path = box.write("a.txt", "one\n")
    client = Client(box, CLAUDE_PROJECT_DIR="${CLAUDE_PROJECT_DIR}")
    text, error = client.call(EDIT, file_path=str(path), old_string="one", new_string="two")
    client.close()
    assert not error and path.read_text() == "two\n"
