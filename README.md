# DataFog — offline PII firewall for Claude Code

Stop PII from leaving your machine through agent tool calls. This plugin
scans every outbound tool invocation (shell commands, web requests, file
writes, MCP tools) in ~70ms, fully offline, and warns — or blocks — when it
finds emails, phone numbers, credit cards, or SSNs.

## Install

The plugin needs the [datafog](https://pypi.org/project/datafog/) engine
(one dependency, no network calls, no models):

```bash
pip install datafog
```

Then, in Claude Code:

```
/plugin marketplace add DataFog/datafog-claude-plugin
/plugin install datafog@datafog
```

That's it. Ask Claude to `curl` something containing a test credit card
number and watch it get intercepted:

> DataFog PII firewall: Bash input contains CREDIT_CARD x1, EMAIL x1.
> Redact or tokenize these values before sending them anywhere.

(If you have [uv](https://docs.astral.sh/uv/) installed, you can skip the
`pip install` — the hook falls back to `uvx` and auto-installs on first
use.)

## What it does

| Event | Behavior |
|---|---|
| `PreToolUse` | Gates outbound tool calls. Default `ask` shows you what was found before the call runs; set `deny` to hard-block. |
| `UserPromptSubmit` | Non-blocking: warns Claude your prompt contains PII so it avoids repeating it into files, code, or logs. |
| `PostToolUse` | Non-blocking: warns when a tool result (file read, API response) carries PII into the conversation. |

## Configuration

Set in your `~/.claude/settings.json` `env` block (or shell):

- `DATAFOG_HOOK_ACTION` — `ask` (default) or `deny`.
  **If you run with permissions relaxed** (`--dangerously-skip-permissions`
  or auto-accept), use `deny`: an `ask` is silently auto-approved in those
  modes, while `deny` is enforced in every mode.
- `DATAFOG_HOOK_ENTITIES` — comma-separated entity types. Default:
  `EMAIL,PHONE,CREDIT_CARD,SSN`. Noisier types (`IP_ADDRESS`, `DOB`,
  `ZIP`) are opt-in — version strings, dates, and 5-digit numbers are
  everywhere in coding sessions.

## What it protects against — honestly

The realistic risk in agent sessions is **second-order leakage**: you paste
a real stack trace or customer record while debugging, and forty turns
later the agent hardcodes that email into a committed test fixture, a
GitHub issue, or a Slack message. This plugin catches PII at the moment of
re-emission, before the write or network call.

What it does *not* cover:

- **PII you hand the agent directly** (a bank statement, a log file) — by
  the time anything can scan it, it's already in the session context.
  Redact before sharing: `datafog` ships a CLI for that.
- **Obfuscated data** — base64, file indirection (`curl -d @file`), env
  var expansion. This is a seatbelt against accidental leakage, not armor
  against deliberate exfiltration.
- **Images and PDFs** — regex sees text only.
- A hook failure fails **open** (your session never breaks), which means
  that call went unscanned.

## How it works

The hook speaks Claude Code's hooks protocol via the `datafog-hook`
console script from the [datafog](https://github.com/DataFog/datafog-python)
package: JSON in on stdin, permission decision out on stdout. Findings are
reported as entity-type counts only — matched values are never echoed into
transcripts. Everything runs locally; nothing about your session leaves
your machine.

## License

Apache-2.0, same as [datafog-python](https://github.com/DataFog/datafog-python).
