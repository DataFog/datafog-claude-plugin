"""Tool output shapes exactly as recorded from Claude Code 2.1.299 (spike run, 222 hook events).

Keys, nesting and value types are the recorded ones; the text content is synthetic.
"""
from conftest import CARD, EMAIL, NOTES, PHONE


def read(path="/project/notes.txt", content=NOTES):
    lines = content.count("\n")
    return {"type": "text", "file": {"content": content, "filePath": path, "numLines": lines, "startLine": 1,
                                     "totalLines": lines}}


def grep(content=f"2:1,Customer 01,{EMAIL},{PHONE}\n3:2,Customer 02,bob.synthetic@example.com,{CARD}"):
    return {"content": content, "filenames": [], "mode": "content", "numFiles": 0, "numLines": 2, "totalLines": 2}


def glob():
    return {"filenames": ["customers.csv"], "numFiles": 1, "totalMatches": 1, "countIsComplete": True,
            "truncated": False, "durationMs": 14}


def bash(stdout=f"# synthetic test data\nSUPPORT_EMAIL={EMAIL}\n", stderr=""):
    return {"stdout": stdout, "stderr": stderr, "interrupted": False, "isImage": False, "noOutputExpected": False}


def webfetch(result=f"The page lists the contact {EMAIL}."):
    return {"result": result, "url": "https://example.com", "code": 200, "codeText": "OK", "bytes": 577,
            "durationMs": 1931}


def write(content=EMAIL, path="/project/out.txt"):
    return {"type": "create", "filePath": path, "content": content, "originalFile": None, "structuredPatch": [],
            "userModified": False}


def mcp(text=f"Customer 01 (synthetic). Email: {EMAIL}. Phone: {PHONE}. Card on file: {CARD}."):
    return [{"type": "text", "text": text}]


def agent(text=f"The read worked. Line 2 holds SUPPORT_EMAIL={EMAIL}."):
    return {
        "agentId": "a510af15cfde09b6f", "agentType": "general-purpose", "canContinueAgent": False,
        "content": [{"type": "text", "text": text}],
        "harnessNoteCount": 0, "harnessSectionHash": "b8ff11c26ec056a9", "harnessTailCount": 0,
        "prompt": f"Read config.env and report the value {EMAIL}", "resolvedModel": "claude-opus-5-5",
        "status": "completed",
        "toolStats": {"bashCount": 0, "editFileCount": 0, "linesAdded": 0, "linesRemoved": 0, "otherToolCount": 0,
                      "readCount": 1, "searchCount": 0},
        "totalDurationMs": 14838, "totalTokens": 156703, "totalToolUseCount": 1,
        "usage": {"cache_creation": {"ephemeral_1h_input_tokens": 0, "ephemeral_5m_input_tokens": 8958},
                  "cache_creation_input_tokens": 8958, "cache_read_input_tokens": 147419, "fallback_credit": None,
                  "inference_geo": "global", "input_tokens": 2,
                  "iterations": [{"cache_creation": {"ephemeral_1h_input_tokens": 0, "ephemeral_5m_input_tokens": 8958},
                                  "cache_creation_input_tokens": 8958, "cache_read_input_tokens": 147419,
                                  "input_tokens": 2, "output_tokens": 324, "type": "message"}],
                  "output_tokens": 324, "output_tokens_details": {"thinking_tokens": 75},
                  "server_tool_use": {"web_fetch_requests": 0, "web_search_requests": 0},
                  "service_tier": "standard", "speed": "standard"},
    }


MCP_TOOL = "mcp__plugin_datafog-spike_fixture__lookup_customer"
ALL = {
    "Read": ({"file_path": "/project/notes.txt"}, read),
    "Grep": ({"output_mode": "content", "path": "/project", "pattern": "synthetic"}, grep),
    "Glob": ({"pattern": "*.csv"}, glob),
    "Bash": ({"command": "cat config.env", "description": "Print config.env contents"}, bash),
    "WebFetch": ({"prompt": "What is the page title?", "url": "https://example.com"}, webfetch),
    "Write": ({"content": EMAIL, "file_path": "/project/out.txt"}, write),
    MCP_TOOL: ({"customer_id": "1"}, mcp),
    "Agent": ({"description": "Read SUPPORT_EMAIL", "prompt": "Read config.env", "run_in_background": False,
               "subagent_type": "general-purpose"}, agent),
}
