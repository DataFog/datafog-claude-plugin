# DataFog for Claude Code

Keeps personal data and credentials out of the model's context in Claude Code during
normal work.

**What this is for, and what it is not.** DataFog protects against *accidental* exposure:
values that would otherwise reach the model and the model provider simply because Claude
read a file, ran a command or called a tool while doing its job. It is **not a sandbox
against a model that is actively trying to unmask values.** A model that has been
manipulated (for example by a prompt injection in a file it read) and is allowed to run
commands can recover values: by transforming them so the detector no longer recognises
them, by cutting them into pieces, or by going around the output filter with operating
system facilities. If you need protection against that, you need an OS-level sandbox and
strict permission rules; this plugin does not replace them.

Before Claude sees the content of a file, the output of a command or the result of a
tool, DataFog replaces the values it detects with reversible markers such as
`[[EMAIL_7KQ4ZM]]`. When Claude writes a marker back to a file or a command, the
marker is swapped for the real value on your machine. The table that maps markers to
values (the vault) never leaves your machine and is never shown to the model.

**Status: 0.2.0-dev. Not released.** The design rests on a 31-run spike against
Claude Code 2.1.299, and the engine has an automated test suite, but this build has
not yet been run in a live Claude Code session. [What is not verified yet](#not-verified-yet)
lists every such point. Read [Known gaps](#known-gaps) before you rely on it.

## Requirements

- Claude Code **2.1.295 or later** (the plugin depends on `onFailure: "block"` for hooks).
- macOS or Linux, with `sh` and `bash` or `zsh`. Windows is not supported in this version.
- `uv`, or Python 3.10 or later with `pip`, and access to PyPI on first start. The plugin
  builds a private Python environment in its data directory and installs one dependency,
  `datafog-core>=1.7.0,<1.8`. Detection runs locally; nothing is sent anywhere.

## Install

```
/plugin install datafog --marketplace DataFog/datafog-claude-plugin
```

Start a new session. The first start installs the private environment (a few seconds)
and prints one status line, for example:

```
DataFog guard: on. Vault: user data folder (kept on uninstall), not encrypted at rest. Bash output: filtered. Markers in Bash commands: ask. Detecting: EMAIL, PHONE, ...
```

If the environment cannot be installed, the status line says exactly which command to
run, and every tool call is blocked until it is fixed. The plugin does not run
unprotected in silence.

## What is detected

Detection is `datafog-core`'s rule-based scanner. Default set for coding sessions:

`EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `API_KEY`, `BEARER_TOKEN`, `JWT`, `PRIVATE_KEY`,
`CREDENTIAL_URI`, `US_ROUTING_NUMBER`, `NPI`, `ACCOUNT_NUMBER`

Off by default because they are noisy in code, and can be turned on: `DATE`,
`IP_ADDRESS`, `ZIP_CODE`, `STREET_ADDRESS`, `UUID`.

Once a value is in the vault it is also recognised wherever it appears again, even
where the scanner alone would miss it (for example an account number without its label).

An e-mail address is replaced without the text joined in front of it: in
`user=ada&email=ada@example.com`, `1042|Ada|ada@example.com|active` or a URL query string,
the marker stands for the address only (core 1.4 took part of the surrounding text into
the value). Digits written directly onto an address with no separator
(`12345ada@example.com`) are still part of the value.

**Not detected:**

- **Names of people.** Free-text names are not detected at all.
- **Addresses without a label**, and anything else that has no recognisable format.
- **Many credential formats.** `API_KEY` covers the formats core 1.7 knows (for example
  GitHub and Stripe keys). In our checks it did not find AWS access keys, OpenAI
  project keys, Slack tokens or `password=...` assignments. Do not treat this plugin as
  a secret scanner.
- Routing numbers, NPIs and account numbers need a label next to them
  (`routing number 021000021`) the first time they are seen.
- Anything inside images and PDFs.
- Some e-mail addresses and phone numbers in particular surroundings; see
  [Known gaps](#known-gaps) 18 and 19.

## How each path is protected

| Path | Mechanism | If the plugin fails |
| :- | :- | :- |
| **Read** | Before the read, the file is scanned. If it holds values, a tokenized copy is written to the plugin's data directory (owner-only) and the read is redirected to it. Files without values are read as usual. | The read is blocked. |
| **Read** of an image, PDF, binary, non-UTF-8 or very large file | Cannot be checked. You are asked each time (configurable: `ask`, `deny`, `allow`). | The read is blocked. |
| **Bash** | The command runs in a separate child shell whose only stdout and stderr are pipes read by a local filter, which tokenizes output as it is produced. This also covers failing commands, EXIT traps and background jobs. See [How Bash commands run](#how-bash-commands-run). | The command does not run. |
| **Bash command containing markers** | You are asked first (`restore_in_bash`, default `ask`). The command Claude Code is given, shows you and records keeps the markers; the plugin's runner puts the real values in at the moment the command starts, as inert data. A marker in a place where that cannot be done safely is refused. See [Markers in Bash commands](#markers-in-bash-commands). | The command does not run. |
| **Bash permissions** | The plugin decides `allow`, `ask` or `deny` from your own Claude Code rules, applied to the command as Claude wrote it. See [Bash permissions](#bash-permissions). | The command does not run. |
| **Write**, **Edit**, **NotebookEdit** | Markers in the new content are swapped for real values before the tool runs. The built-in tool needs the real content, so it is handed over in the tool input, and **Claude Code records that input in its transcript.** | The write is blocked. |
| **Grep**, **Glob** | Markers in the pattern and path are swapped for real values (handed over in the tool input, so **recorded in Claude Code's transcript**, like Write); Grep output is tokenized after the tool ran. | See next row. |
| **Grep, WebFetch, WebSearch, MCP tools, subagent results, any other tool** | Output is tokenized after the tool ran. Before the tool runs, the plugin checks that the vault opens, the lock works and the detector finds a test value, and refuses the call if not. | If the plugin breaks *between* that check and the result (hard crash, timeout), **the raw output reaches the model.** Claude Code offers no way to prevent this for output that only exists after a tool ran. |
| **Your prompt** | Scanned when you submit it. If it holds values, it is not sent; you are shown the same prompt with markers to submit instead. A plugin cannot rewrite a prompt. | The prompt is blocked. |
| **`@file` and `@directory` mentions** | Blocked when a mentioned file, or any file in a mentioned directory, holds values or cannot be checked; you are told to ask Claude to read the files instead. Directories are checked up to 200 files, 8 MiB and 4 levels; beyond that the prompt is blocked with the reason. See [settings](#settings-the-plugin-cannot-set-for-you). | The prompt is blocked. |
| **Subagents** | The same hooks run for a subagent's tool calls. | As above. |

Markers sent to WebFetch, WebSearch, subagents and third-party MCP tools are **not**
swapped back: that input leaves your machine or goes to another model.

### How Bash commands run

Each Bash command runs in its own child shell, started by the filter, in its own session.
The child's stdout and stderr are pipes to the filter; every other file descriptor is
closed; its parent process does not hold Claude Code's output either. So whatever the
command does (an `EXIT` trap, `exec 3>&1`, `>&10`, `/dev/stdout`, `/dev/fd/1`) it can only
write into the filter. `/dev/tty` is not available to commands (they have no terminal).

Consequences you will notice:

- **`cd` carries over** to the next command, as usual.
- **Exported variables, shell functions and aliases defined in one command do not carry
  over to the next.** Put them in the same command, or in a script.
- **Your shell aliases and functions are not applied.** Commands run in a plain
  non-interactive `bash` or `zsh` (whichever `$SHELL` is), which does not read your
  interactive start-up files.
- **Background jobs** started with `&` keep running, but **their output is cut off 3
  seconds after the command returns**; what they print later is discarded. Following a
  background process (tailing a dev server Claude started earlier, reading its output in a
  later call) is **not supported**: redirect its output to a file and read the file.
  `run_in_background` is refused by default.
- `NO_COLOR=1` and `CLICOLOR=0` are set for commands. Colour codes that still appear are
  handled (see below), this only reduces noise.
- Each command costs about 70 ms extra for the runner, and the PreToolUse hook takes about
  45 ms (10 ms of it inside the engine, the rest is starting Python). Measured on a Linux
  container; reading your permission rules and the late swap added about 2 ms to the hook
  and nothing measurable to the runner.

Values split or hidden by terminal control sequences are still found. Detection also runs
on the text with escape sequences and invisible characters removed, and on the text as a
terminal would render it (backspace overstrike, carriage-return overwrite), in command
output, tool output and files alike. `123-<ESC>[01;31m45<ESC>[m-6789` from
`grep --color=always` becomes one marker, and writing that marker back restores the
original bytes.

### Markers in Bash commands

Swapping a marker for the real value inside a command is necessary for honest work
(`grep [[EMAIL_7KQ4ZM]] customers.csv`), and it is also how a manipulated model could
compute on a value: `echo [[EMAIL_7KQ4ZM]] | base64` would print an encoding the filter
cannot recognise, and `wc -c` would print its length. So by default
(`restore_in_bash: ask`) you are asked each time a command contains known markers. The
reason shown names entity types and counts only. `allow` restores without asking; `off`
never restores, leaves the marker text in the command and tells Claude so. Markers the
vault does not know are always left as text.

**Where the swap happens (the "late swap").** The hook never puts a real value into the
command. What it hands back to Claude Code is your command, wrapped, **with the markers
still in it**, plus a ticket: a signature over exactly that command text, made with a key
kept in the vault directory. So the permission prompt, the session transcript and the
record of a denied call show `grep -c [[EMAIL_7KQ4ZM]] notes.txt`, not the address. When
the command runs, the plugin's runner opens the vault, checks the ticket, puts the values
in, and passes the result to the child shell through a pipe. The restored command is never
printed, logged, written to a file, placed in an environment variable or in the argument
list of the runner or of the shell. Without a valid ticket the runner restores nothing, so
a command cannot start the runner itself to get values back.

What remains unavoidable while the command runs: a program the command starts with a value
as an argument has it in its own argument list (`ps` shows it to every user on the machine
for as long as that program runs), and the shell that runs the command holds it in memory.

**Values are inserted as data, never as shell syntax.** The model chooses the command and
the quoting around a marker, and may have been manipulated into choosing it badly; whoever
planted a value may have shaped it as an attack (`'; rm -rf ~; '`, `$(...)`). A lexer for
bash and zsh works out the quoting context at each marker and writes the value in the one
form that context cannot interpret:

| Marker is | Example | Written as |
| :- | :- | :- |
| unquoted, an argument or part of one | `grep [[M]] f`, `--to=[[M]]` | `'value'`, every `'` as `'\''` |
| in single quotes | `'a [[M]] b'` | the value in place, every `'` as `'\''` |
| in double quotes | `"a [[M]] b"` | the double quote is closed, `'value'`, and opened again |
| in `$'...'` | `$'a\t[[M]]'` | the value in place, `\` and `'` escaped |
| in a heredoc with a quoted delimiter | `<<'EOF'` | the value in place |
| in a heredoc with an unquoted delimiter | `<<EOF` | the value in place, `\`, `$` and backtick escaped |
| in an assignment or `export NAME=` | `TOKEN=[[M]] ./deploy` | as above for its quoting |
| in a here-string | `<<< "[[M]]"` | as above for its quoting |
| inside `$( ... )`, backticks, `( ... )`, `{ ...; }`, `if`, `for`, a pipeline or list | | the lexer recurses; the rules above apply inside |
| in a comment | `# [[M]]` | left as it is |

**The command is refused (not run, with a reason that names no value)** when a marker is:
the command name or part of it; a redirection target or heredoc delimiter; directly after
an unquoted `$` or a backslash; inside `${...}`, arithmetic, `[[ ]]`, `case`, an array or a
function definition; in a heredoc if the value contains a newline or would form the
delimiter line; an argument of a program that runs its arguments as a command or reads
them as a program (`env`, `sudo`, `timeout`, `nohup`, `docker`, `make`, `awk`, `sed`,
`sqlite3` and others); assigned to a variable that decides what code runs (`PATH`, `IFS`,
`LD_PRELOAD` and others). It is also refused when the command contains, anywhere, something
that evaluates text a second time: `eval`, `source`, `trap`, `sh`/`bash`/`zsh`, `xargs`,
`ssh`, `python`/`perl`/`node`/`ruby`, arithmetic (`$(( ))`, `let`, `declare -i`), a command
name that is a variable, and most shell builtins. A value containing a NUL byte is refused
everywhere. Anything the lexer does not model with certainty is refused too. Refusal is
the default on purpose; Claude is told to put the marker in a plain or quoted argument, or
to write the value to a file with the Write tool and let the command read the file.

This is tested under real bash, zsh and dash: about 90 hostile values in each of 42
contexts, 300 random values per context, the same through the real runner, and random
command shapes around markers, checking that the receiving program got exactly the value,
that nothing inside a value ran, and that the exit status is the command's own.

Limits of the swap that no test removes:

- **A value that starts with `-` is delivered exactly**, and the program may read it as an
  option. Use `--` before it where the program supports that.
- **The lists of wrapping and code-reading programs are finite.** A program outside them
  that treats an argument as code (a query language, a template, a pattern) gets the value
  as one argument and may interpret it.
- **What the command does with a value afterwards is its own business.** `x=[[M]]; rm $x`
  inserts the value safely, and then the shell splits `$x` into words.
- **Shell start-up files** (`~/.zshenv`, `BASH_ENV`) that define aliases or change shell
  options are not modelled. Options that change quoting (zsh `RC_QUOTES`) can alter the
  value a program receives; they cannot make it run.
- `printf` takes markers only after a literal format (`printf '%s\n' [[M]]`), and `cd` takes
  none: a value must not become an option, a variable name or the working directory.
- If neither bash nor zsh is available the runner uses `/bin/sh` and accepts fewer forms.

Grep and Glob patterns are always restored, through the tool input (see
[Traces](#traces-left-in-claude-codes-records)). Note that match/no-match and match counts
tell the model something about a value too.

If a command with markers also looks like it sends data to another machine (`curl`, `wget`,
`nc`, `scp`, `rsync`, `git push`, `gh`, `mail`, `dig`, `ping`, `open`, cloud CLIs, a URL in
the command or in a value), you are asked even with `restore_in_bash: allow`, and with
`egress_policy: deny` it is refused. This is a list of known programs, not a guarantee.

### Bash permissions

The plugin rewrites every Bash command so that it runs behind the output filter. Claude
Code evaluates your permission rules against the rewritten command, so a rule such as
`Bash(cat *)` no longer matches anything by itself. Without more, every Bash call would
prompt, or be denied in a headless run. The hook therefore returns its own decision,
computed from **your Claude Code rules applied to the command as Claude wrote it** (before
wrapping, markers not restored). The aim is to be never more permissive than Claude Code
would be; where the documentation is silent, the stricter reading is used.

**Which rules.** Exactly these kinds, and no others:

- `Bash` and `Bash(...)` entries in `permissions.allow`, `permissions.ask` and
  `permissions.deny`;
- `Read(...)` and `Edit(...)` entries in `permissions.deny` and `permissions.ask` (see
  [Read and Edit rules](#read-and-edit-rules-apply-to-bash-commands) below). `Read` and
  `Edit` *allow* rules approve nothing for Bash. `Write(path)`, `NotebookEdit(path)` and
  `Glob(path)` rules never match anything in Claude Code and are ignored here too;
- deny and ask rules whose tool name is a pattern that matches `Bash`, `Read` or `Edit`
  (such as `*`).

`WebFetch`, `Agent`, MCP and sandbox settings play no part in the plugin's decision.

They are read from the settings files Claude Code documents: the managed settings file
(`/etc/claude-code/managed-settings.json` on Linux, `/Library/Application
Support/ClaudeCode/` on macOS, plus `managed-settings.d/*.json`), your user settings
(`~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json`), the project's
`.claude/settings.json` and `.claude/settings.local.json`. Lists from all files merge, and
a deny from any file beats an allow from any file. Rule syntax is Claude Code's: `Bash`,
`Bash(exact command)`, `Bash(prefix *)`, `Bash(prefix:*)`, `*` anywhere; a trailing ` *`
also matches the bare command; the space before `*` is a word boundary (`Bash(ls *)` does
not match `lsof`). Allow rules in a project's shared `.claude/settings.json` count only if
the folder is recorded as trusted in `~/.claude.json`, as in Claude Code, which never
applies them in an untrusted `claude -p` run. `/datafog:doctor` shows how many rules the
plugin read and from where.

**The decision, first match wins:**

1. The engine is unhealthy: **deny**.
2. A Bash deny rule matches the command or any sub-command of it, or a Read or Edit deny
   rule covers a path the command names: **deny**, in every permission mode.
3. A Bash ask rule matches the command or any sub-command, or a Read or Edit ask rule
   covers a path the command names: **ask**.
4. The command contains known markers and `restore_in_bash` is `ask`: **ask**.
5. The command contains known markers and looks like it sends data away: **ask**.
6. The command is not a simple command: **ask**.
7. An allow rule matches the simple command: **allow**.
8. Otherwise: **ask**.

For steps 2 and 3 the command is split at `&&`, `||`, `;`, `|`, `|&`, `&` and newlines, and
commands inside `$( )`, backticks, subshells, groups and `if`/`for`/`while` bodies count
too. Leading `NAME=value` assignments and the wrappers Claude Code strips (`timeout`,
`time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`, bare `xargs`) are
removed before matching.

#### Read and Edit rules apply to Bash commands

Claude Code applies your `Read` and `Edit` deny and ask rules to file commands it
recognises in Bash (its documentation names `cat`, `head`, `tail`, `sed` and `tee`) and to
redirection targets. It cannot do that inside the rewritten command, so the plugin does,
and more strictly:

- **Every word of every sub-command is treated as a possible path**, not only the
  arguments of known file commands: also redirection targets (`<`, `>`, `>>`, `>|`, `&>`,
  `2>`), the part after `=` or `:` (`dd if=secret.env`, `--file=secret.env`) and a path
  after `@`. Each is checked as written and with symbolic links resolved, against `Read`
  and `Edit` rules alike, since the plugin does not know whether a program reads or writes
  its operand. On macOS paths are compared without regard to case.
- A **deny** rule that covers such a path denies the command in every mode, including
  `bypassPermissions`. An **ask** rule asks in every mode (and denies in `dontAsk`).
- **When a path cannot be known before the command runs, the command is never approved
  without a prompt**, in any mode, as long as you have at least one `Read` or `Edit` deny
  or ask rule: a variable (`cat $F`), a substitution, a glob (`cat *.txt`; globs are also
  expanded and each result checked), a brace expansion, a `cd` inside a compound command,
  a command the plugin cannot parse, a covered path that is only mentioned inside a quoted
  script (`sh -c '...'`, `python -c "..."`), and a directory operand that holds a covered
  path or is too large to check (`grep -r x .`, `tar c .`; up to 3,000 entries are looked
  at). The plugin asks here rather than denies: nothing shows that the covered file is
  touched, and Claude Code documents these rules as best-effort for Bash.
- Pattern syntax is Claude Code's: `//path` absolute, `~/path` from your home directory,
  `/path` relative to the settings source (the project directory for project and local
  settings, `~/.claude` for user settings), `path` or `./path` relative to the current
  directory; `*` and `?` within one path segment, `**` across directories. Stricter than
  documented: every relative pattern matches at any depth below the current directory,
  `!` carve-outs are ignored (nothing is carved out), and a bare `Read` or `Edit` deny
  rule covers every path, which denies nearly every Bash command.

What this still does not cover, as in Claude Code: a command that reads files without
naming them (`grep -r pattern` with no path, `git grep`, `git diff`), and whatever a
program opens by itself (a script, a build, a test run). Rules given by command-line
flags, a server or MDM are invisible here like the Bash ones. A `Read` rule is therefore
not a boundary around a file; a sandbox is.

Having any `Read` or `Edit` deny rule makes every Bash command with a glob or a variable
ask. That is the price of not letting such a command through unchecked.

**A "simple command" is deliberately narrow for now.** Exactly one command: no `;`, `&&`,
`||`, `|` or `&`; no redirection (`<`, `>`), heredoc or process substitution; no subshell,
`$( )` or backtick; no `{ }`; no leading `NAME=value`; no newline; no backslash outside
single quotes; `$` only as `$NAME` or `${NAME}`; not starting with a shell keyword; at most
10,000 characters. Anything may stand inside single quotes, and inside double quotes
everything except `$(`, backtick and backslash. So `git commit -m "fix (scope): a; b"` is
simple and `cat a.txt | head` is not. **A command that is not simple always asks, even if
each part matches one of your allow rules.** Claude Code itself would approve
`cat a.txt | head` when both parts are allowed; the plugin does not yet. This is the main
source of extra prompts and is meant to be loosened later (`ccperms.is_simple`).

**Stricter than Claude Code, on purpose:**

- Deny and ask rules also match a program written another way: `\rm`, `'rm'`, `/bin/rm`,
  `env rm`, `sudo rm`, `xargs -n1 rm`, `sh -c 'rm ...'`, `eval 'rm ...'`. Claude Code's
  documentation says such forms are not stopped by a rule.
- An allow rule with a wildcard never approves a command that starts with a program that
  runs its arguments (`env`, `sudo`, `timeout`, `command`, `xargs`, `watch`, a shell,
  `eval`, `find` with `-exec` or `-delete`) or whose name is quoted. An exact rule does.
- `rm` and `rmdir` are approved by rule only for plain paths below the working directory.
  Claude Code refuses to let any rule or hook approve removals of "critical paths" (`/`,
  `~`, the working directory, targets built from variables or globs), and it cannot
  recognise them inside the rewritten command; the plugin asks for all of those instead.
- In `auto` mode only allow rules without a wildcard count.
- If any settings file cannot be read or parsed, no allow rule is applied at all. Deny and
  ask rules that can still be found in it (Bash, Read and Edit) are kept.
- `Read` and `Edit` rules are applied to every word of a command, not only to the file
  commands Claude Code recognises; see above.
- With `permissions.blockReadsOutsideWorkingDirectories` on, nothing is approved by rule.
- Leading `NAME=value` makes a command not simple, also for variables Claude Code treats
  as safe.
- Claude Code runs a built-in set of read-only commands (`ls`, `cat`, `grep` and others)
  without a rule. The plugin does not: add allow rules for the ones you use
  (`Bash(ls *)`, `Bash(cat *)`, `Bash(grep *)`, `Bash(git status)`).

**Permission modes** (from the `permission_mode` the hook receives):

| Mode | What the plugin returns |
| :- | :- |
| `default`, `acceptEdits` | as decided above. The file commands `acceptEdits` approves by itself (`mkdir`, `mv`, `cp` ... inside the project) ask, because the plugin cannot check paths. |
| `plan` | never `allow`; a command your rules allow asks. |
| `auto` | deny and ask rules and marker commands as above; an exact allow rule allows; everything else is left to Claude Code, so its classifier reviews the rewritten command. |
| `dontAsk` | every `ask` becomes `deny`, as that mode does. |
| `bypassPermissions` | steps 6 and 8 become `allow`. Deny rules (Bash, Read, Edit) still deny; ask rules, marker commands (steps 4 and 5), `rm` of a possibly critical path, and a command that cannot be cleared against your Read and Edit rules still ask. |

**Limits you should know:**

- **Rules the plugin cannot read do not take part.** That is everything not in the files
  above: `--allowedTools`, `--disallowedTools`, `--settings`, `--setting-sources`,
  server-managed settings, MDM policies, and "allow for this session" choices. An
  invisible *allow* rule only costs you prompts. An invisible ***deny* or *ask* rule is
  not enforced for Bash while the plugin wraps commands**: Claude Code checks it against
  the rewritten command, where it normally does not match, and the plugin does not know
  it exists. Put Bash deny rules in a settings file. The same holds for
  `allowManagedPermissionRulesOnly` delivered by a server or MDM: the plugin would still
  apply your own allow rules.
- **Claude Code still checks your deny and ask rules against the rewritten command**,
  whatever the hook returns. The rewritten command is
  `. <plugin>/scripts/wrap.sh && __datafog_run <launcher> <data dir> <vault dir> '<your command>'`.
  A deny rule that matches that text, such as `Bash(. *)` or `Bash(* && *)`, blocks every
  Bash command while the plugin is on. The plugin detects this for the rules it can read
  and says so in the denial instead of failing silently.
- **"Yes, and don't ask again" on a prompt** makes Claude Code save a rule for the
  rewritten command, which the plugin does not use. Add a rule for the original command to
  a settings file by hand.
- With `bash_wrap: off` the command is not rewritten, the plugin returns no decision,
  and Claude Code applies your rules itself; markers are then never restored.

### Editing a line that contains a marker

The built-in Edit tool compares `old_string` with the file on disk before any plugin
code runs. The file holds the real value, so an `old_string` containing a marker is
never found. The plugin adds a tool for this, `edit_with_markers` (same arguments as
Edit), which swaps the markers locally, applies the edit with Edit's "must match exactly
once" rule, and returns line numbers and counts only. Claude is told about it at session
start. It refuses paths outside the project directory.

## Known gaps

Ways a real value can still reach the model or leave a trace.

**Inherent limits. These follow from the design and will not be fixed by a bug fix:**

1. **Values the detector does not recognise** are not replaced. See *Not detected* above.
2. **Any transformation of a value is invisible to the detector.** If a command prints a
   value base64-encoded, reversed, hex-dumped, compressed, encrypted, URL-encoded, or prints
   facts about it (its length, a hash, whether it matches a pattern), the output passes.
3. **A value cut part-way leaks the part.** `head -c 20 file` can end in the middle of an
   e-mail address; the prefix is not a detectable value and is passed.
4. **Output-only tools are protected by a fail-open hook.** For Grep, WebFetch, WebSearch,
   MCP tools and subagent results, the replacement happens after the tool ran. If the
   plugin crashes or times out at that point, Claude Code delivers the raw output. The
   health check before the call narrows this; it cannot close it.
5. **A manipulated model that may run commands can recover values** by combining the
   above. With `restore_in_bash: ask` it needs your approval to run a command on a marker,
   but it can also run commands on the *files* that hold the values (`base64 notes.txt`).
   Protection against that is the job of permission rules and a sandbox.
6. **On Linux, a command can go around the output filter through `/proc`.** Claude Code's
   own shell holds the pipe its output is read from, and any process of the same user can
   reopen that pipe through `/proc/<pid>/fd`. The plugin makes sure the command's own
   ancestors do not hold it and that its own filter process cannot be opened this way, but
   it cannot hide Claude Code's processes. This takes a deliberate search; it does not
   happen by accident. macOS has no `/proc`.

**Other gaps:**

7. **Images and PDFs are not scanned.** With the default `ask` policy, approving the read
   shows the content to the model unchecked.
8. **`@` mentions bypass hooks.** The plugin blocks the prompt when a mentioned file or
   directory holds values, but it only sees the prompt text; a mention form it does not
   recognise is not caught. Set `CLAUDE_CODE_DISABLE_FILE_MENTIONS=1` (below).
9. **Telemetry.** Claude Code's own OpenTelemetry and analytics, if enabled, may record tool
   output before the plugin replaces it.
10. **Claude Code's own records hold real values for file tools, not for Bash.** See
    [Traces left in Claude Code's records](#traces-left-in-claude-codes-records).
11. **The vault is not encrypted at rest in this version.** It is protected by owner-only
    file permissions (directory `0700`, files `0600`). Anyone who can read your files can
    read it. The plugin refuses Read, Write, Edit and Grep on the vault directory and Bash
    commands that name it; a command that reaches it indirectly is only covered by the
    output filter.
12. **Bash, Read and Edit permission rules that the plugin cannot read are not enforced for
    Bash commands**, commands that are not simple always ask, and a `Read` deny rule does not
    stop a command that reads the file without naming it. See [Bash permissions](#bash-permissions).
13. **File names and paths are never tokenized**, including in Glob and Grep results.
14. **Binary command output** is passed through; text inside it is tokenized, but a value
    split by invalid bytes is not found.
15. **A value over 32 KiB** cannot be stored; a file containing one cannot be read through
    the plugin. A single Bash command over 100 KB is refused.
16. **Edits made by other tools.** Anything that writes files without going through Write,
    Edit, the plugin's edit tool or an approved Bash command (for example another MCP
    server) gets markers, not values.
17. **A value restored into a Bash command is visible in the process list** for as long as
    a program the command started holds it as an argument, and a value that starts with `-`
    may be read as an option. See [Markers in Bash commands](#markers-in-bash-commands).
18. **KNOWN ISSUE: an e-mail domain can reach the model when a non-ASCII letter touches the
    address** ([datafog-core #272](https://github.com/DataFog/datafog-core/issues/272),
    present in core 1.5.0 to 1.7.0). A letter or digit outside ASCII written directly against
    an address, with no space or punctuation between, is read as part of the address. For a
    single address that only makes the marker cover a little more (`連絡先ada@example.com`
    becomes one marker). **Between two addresses it leaks:** `alice@example.comとbob@example.net`
    is read as one value, `alice@example.comとbob`, and the model sees
    `[[EMAIL_…]]@example.net`: the second person's real domain. This happens in text written
    without spaces (Japanese, Chinese, Thai, also `…@a.example.orgßname@…`). A space, a
    full-width space or punctuation such as `。` or `：` between the letter and the address
    avoids it. The plugin does not work around this; it is fixed in core after 1.7.0 and
    goes away with the next core release the plugin moves to.
19. **Phone numbers core 1.7 does not report, which core 1.4 did.** They pass to the model
    unchanged: a dotted number directly after a digit and a dot (`2.415.555.0134`, read as a
    decimal); after a digit and a comma, a number whose only separator is one dot
    (`2,415.5550134`); and a number wrapped across a line break (`(415)` at the end of one
    line and `555-0134` on the next). A `+` number wrapped across a line break is replaced
    only up to the break (`+44 20 7946` / `0958` leaves `0958`). `3.415-555-0134` and CSV
    rows such as `2,415-555-0134` are found.

Behaviour worth knowing that is not a leak:

- **Case and exactness.** `datafog-core` treats `Ada@Example.com` and `ada@example.com` as
  the same value. To make sure a write-back is byte-exact, the plugin gives a second
  spelling its own marker with a variant label (`[[EMAIL_V2_...]]`).
- **Line numbers.** A tokenized copy has the same number of lines as the file, except where
  a value spans several lines (a private key block), which becomes one marker.
- **Markers the vault does not know** (wrong label, changed code, from a purged vault) are
  left exactly as written and reported to Claude as a count. Lower-cased markers are
  accepted, as core defines them. One unknown marker never fails a whole write.
- **Limits.** Core allows 20,000 values in a vault, and its known-value matching stops
  working when the stored values pass roughly 256 KiB in total, which can come first.
  At either limit the plugin stops (new values cannot be protected) and says so; the
  remedy today is `/datafog:purge`. `recall_required: false` trades the second limit
  for detector-only matching.

## Traces left in Claude Code's records

What ends up in files that Claude Code itself writes (the session transcript under
`~/.claude/projects/`, its debug log, the `permission_denials` list of a headless run) and
in what it shows you. The model's context holds markers in every row.

| Path | Real value in Claude Code's records? |
| :- | :- |
| Tool results (Read, Bash output, Grep, MCP ...) | No. They are replaced before Claude Code stores them, with the fail-open exception in gap 4. |
| **Bash command**, any `restore_in_bash` setting, approved, denied or refused | **No.** The recorded and displayed command holds the marker. The value exists only inside the runner and the processes of the command while it runs. |
| **Write, Edit, NotebookEdit** content | **Yes.** The built-in tool must receive the real content, so the plugin puts it into the tool input, and Claude Code records that input. Its permission prompt and diff show it to you as well. |
| **Grep and Glob** pattern, path and glob | **Yes**, for the same reason, whenever they contain a marker. |
| `edit_with_markers` (the plugin's own edit tool) | No. Its input keeps the markers and its result names line numbers and counts. The file on disk gets the real value. |
| Third-party MCP tool input with `restore_in_mcp_input: true` | Yes, and the value leaves this process. Off by default. |
| Your own prompt | A prompt that holds a value is blocked before it is sent; Claude Code may still keep what you typed in its prompt history. |
| The plugin's own log and status output | No. Entity types, counts, decision steps and error codes only. |
| Telemetry, if you enabled it | See gap 9. |

The vault and the shadow copies of files are the plugin's own records: the vault holds the
values by design; shadow copies hold markers only.

## Decisions

Design decisions that were considered and settled, so they are not reopened by accident.

- **`restore_in_bash` defaults to `ask`.** Restoring a marker into a command lets the
  command compute on the value, which is an oracle for a manipulated model. `allow` and
  `off` are available. The late swap does not change this default: it removes the value
  from Claude Code's records, not the oracle.
- **Late swap.** Bash commands are restored inside the runner at execution time, never in
  the hook's output. Before this, the restored command sat in the permission prompt, the
  transcript and the record of denied calls, even for a command you refused.
- **Refuse rather than guess.** A marker in a place the lexer cannot classify with
  certainty makes the whole command fail closed. The alternative, leaving that one marker
  unrestored and running the rest, was rejected: the command would run with a mix of real
  values and marker text and do something nobody intended.
- **Double quotes are closed and reopened around a value** instead of escaping the value
  for double quotes, so no character of a value is ever read under double-quote rules.
- **Bash permissions follow your Claude Code rules, read from the settings files**, and
  are never more permissive than Claude Code. Extra prompts are accepted as the cost.
- **"Simple command" starts strict.** It is one function with tests, to be loosened once
  the live behaviour is known.
- **Read and Edit deny rules deny a Bash command that names a covered path; what cannot
  be checked asks.** Denying everything that might touch a covered path (every glob, every
  directory) was rejected: it would make such rules unusable. Allowing it was rejected
  too: it would let a rule be bypassed with `cat s*.env`.
- **The test-only switch `DATAFOG_TEST_ALLOW_WRAPPED_BASH` was removed.** Tests and the
  live driver use settings files, like a user would.

## Settings the plugin cannot set for you

A plugin cannot change your Claude Code settings. These two are worth adding to
`~/.claude/settings.json` yourself.

Make `@file` mentions go through the Read tool, where the plugin can replace values
(Claude Code 2.1.299 or later):

```json
{
  "env": {
    "CLAUDE_CODE_DISABLE_FILE_MENTIONS": "1"
  }
}
```

Deny rules for the vault itself and for files you never want read, even as markers.
Adjust the paths to your machine and projects. With the plugin on, these `Read` rules
also apply to Bash commands that name such a path, in every permission mode (see
[Read and Edit rules](#read-and-edit-rules-apply-to-bash-commands)). They do not block
Bash as a whole: a command that names none of these paths is decided by your `Bash`
rules as before. Two consequences to expect: a command with a glob or a variable in it
asks instead of being approved by rule, and so does a command over a directory that
holds one of these files (for example `grep -r x .` in a project with a `.env`).
Do not add a bare `Read` or `Edit` deny rule (without a path): it covers every path
and denies nearly every Bash command.

```json
{
  "permissions": {
    "deny": [
      "Read(~/Library/Application Support/DataFog/**)",
      "Read(~/.local/share/datafog/**)",
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(./secrets/**)",
      "Read(**/*.pem)"
    ]
  }
}
```

## The vault

One vault serves all your projects, so a value has the same marker everywhere.

| | Location |
| :- | :- |
| `DATAFOG_VAULT_DIR` is set | that directory |
| "Keep the vault when the plugin is uninstalled" is on (default) | macOS `~/Library/Application Support/DataFog/vaults/claude-code`; Linux `$XDG_DATA_HOME/datafog/vaults/claude-code` or `~/.local/share/datafog/vaults/claude-code` |
| the option is off | `${CLAUDE_PLUGIN_DATA}/vault`, which Claude Code deletes when the plugin is uninstalled |

It holds `datafog-core`'s workspace snapshot unmodified, a pointer file and a small
metadata file. **It is not encrypted at rest.** Writes are atomic, and concurrent
sessions are coordinated with a file lock and a compare-and-save on the vault's head.

If the vault is deleted, every marker issued from it is meaningless. Text that still
holds markers (a file Claude wrote through another tool, notes, old transcripts) can
then never be turned back into real values.

## Commands

- `/datafog:status` shows whether protection is on, where the vault is, and entity types
  and counts. Never values.
- `/datafog:doctor` checks the installation and says what to fix.
- `/datafog:purge` deletes the vault after an explicit confirmation step.

## Configuration

Plugin options (asked when the plugin is enabled, also under `/config`):

| Option | Default | Meaning |
| :- | :- | :- |
| `keep_vault_on_uninstall` | on | Where the vault lives; see above. |
| `unscannable_file_policy` | `ask` | Reads of files that cannot be checked: `ask`, `deny` or `allow`. |
| `entities` | empty (default set) | Comma-separated entity types to detect. |

More settings go in `config.json` in the plugin's data directory
(`~/.claude/plugins/data/<plugin id>/config.json`), or in environment variables, which win:

| Key | Environment variable | Default | Meaning |
| :- | :- | :- | :- |
| `entities` | `DATAFOG_ENTITIES` | default set | Entity types to detect. |
| `allowlist` | `DATAFOG_ALLOWLIST` | none | Exact values never replaced (for example `noreply@example.com`). Never printed by any command. |
| `unscannable_policy` | `DATAFOG_UNSCANNABLE_POLICY` | `ask` | As above. |
| `restore_on_write` | `DATAFOG_RESTORE_ON_WRITE` | `true` | `false`, or a list of path globs to restrict restoring to (`*.env,*.csv`). |
| `bash_wrap` | `DATAFOG_BASH_WRAP` | `runner` | `off` runs commands unwrapped and leaves only the after-the-fact replacement, which is not fail-closed and does not cover failing commands. Markers in commands are then never restored, and Claude Code applies your permission rules itself. |
| `restore_in_bash` | `DATAFOG_RESTORE_IN_BASH` | `ask` | Commands that contain markers: `ask` you first, `allow` (restore without asking), or `off` (never restore; markers stay as text). Values are put in by the runner, so this needs `bash_wrap: runner`. |
| `background_bash` | `DATAFOG_BACKGROUND_BASH` | `deny` | `allow` wraps background commands like any other. |
| `egress_policy` | `DATAFOG_EGRESS_POLICY` | `ask` | For commands with markers (and restoring not `off`) that look like they send data away: `ask`, `deny`, `allow`. |
| `restore_in_mcp_input` | | `false` | Swap markers back in input to third-party MCP tools. Real values then leave this process. |
| `recall_required` | `DATAFOG_RECALL_REQUIRED` | `true` | Stop when known-value matching is unavailable (see Limits). |
| `max_scan_bytes` | `DATAFOG_MAX_SCAN_BYTES` | 5 MiB | Larger files count as "cannot be checked". |
| | `DATAFOG_VAULT_DIR` | | Vault directory. |

A setting the plugin cannot understand makes it stop and say so; it does not fall back
to a default in silence.

## Not verified yet

The mechanisms below were shown to work in the spike with a stand-in implementation, or
are new in this build. None has been run in a live session with this engine.
`tests/live/` settles them.

- Read redirect, Write restore and Grep/MCP output replacement with the real engine.
- The Bash runner inside Claude Code: that `cd` carries over between calls, that Claude
  Code collects all output, and that a cancelled or timed-out command is stopped.
- The Bash runner on macOS. It was tested on Linux with bash 5 and zsh 5.9 only: process
  re-parenting, the `/dev/fd` and `/dev/tty` behaviour and bash 3.2 are untested there
  (including `read -d ''`, which the child shell uses to receive the command).
- **Bash permissions, all of it against live Claude Code.** The decision logic is tested
  against the documentation, not against Claude Code:
  - that a hook `allow` runs a rewritten command without a prompt, in an interactive
    session and in `claude -p`;
  - what the permission prompt for a hook `ask` looks like, that it shows the command with
    markers, and what "Yes, and don't ask again" saves from it;
  - that the record of a denied call (`permission_denials`) holds the marker command;
  - `plan` mode: whether Claude Code would have run a command that the plugin makes ask;
  - `auto` mode: that leaving the decision to Claude Code sends the rewritten command to
    the classifier, how the classifier judges it, and that a hook `ask` forces a prompt;
  - `dontAsk` mode: that a hook `allow` runs and that the plugin's `deny` reads well;
  - `bypassPermissions` mode: **what a hook `ask` does there** (steps 3, 4, 5 and the `rm`
    check rely on it prompting; the documentation says ask *rules* still prompt in this
    mode and does not say it for hooks);
  - that `permission_mode` reaches the hook with the documented values, also in subagents;
  - whether Claude Code's own rule matching agrees with the plugin's for your rules (the
    documented examples are tests; undocumented cases use the stricter reading);
  - that `~/.claude.json` records trust under `projects["<path>"].hasTrustDialogAccepted`
    as documented, and where that file is when `CLAUDE_CONFIG_DIR` is set;
  - whether Claude Code's `Read`/`Edit` path matching agrees with the plugin's beyond the
    documented examples, and which Bash commands it applies those rules to itself;
  - managed settings: whether a server-managed or MDM policy is in force (invisible to the
    plugin), in which case Claude Code ignores the managed settings *file* the plugin reads.
- Whether Claude Code lets Write or Edit change a file that was read through a redirected
  copy (its read-before-write check may not count that read).
- What the built-in Edit tool's result shows the model after the plugin replaced it.
- That the plugin's MCP server receives the project directory and starts on first install.
- How a blocked prompt and an `ask` decision look to you.
- Behaviour when Claude Code's own Bash sandbox is enabled (the runner starts the command in a new session).
- Anything on Windows.

To run the live check on your machine (about 27 short headless `claude -p` runs in a
throwaway temp project with a temporary vault; your real vault is not touched; hard caps
of 30 runs, 180 seconds each, 30 minutes in total):

```sh
tests/live/run-live.command          # or double-click it in Finder
```

Results land in `.live/results/results.md`.

## Development

```sh
uv venv && uv pip install "datafog-core>=1.7.0,<1.8" pytest ruff mypy
DATAFOG_TEST_NETWORK=1 .venv/bin/python -m pytest    # the flag enables tests that build the private environment
.venv/bin/ruff check . && .venv/bin/mypy
```

Layout: `engine/datafog_guard/` (the engine; entry `python -m datafog_guard <hook|run|filter|mcp|status|purge|doctor>`),
`scripts/` (launcher, environment bootstrap, shell wrapper), `hooks/hooks.json`,
`.mcp.json`, `commands/`, `tests/`, `tests/live/`. For Bash: `shellsub.py` (the lexer that
puts values into a command as data, with its threat note), `ccperms.py` (reading and applying
your Claude Code permission rules), `filtercmd.py` (the runner), `bashwrap.py` (the rewrite
and the restore ticket).

All test data is synthetic (`ada.synthetic@example.com`, test card `4242 4242 4242 4242`).

## License

Apache-2.0. See [LICENSE](LICENSE).
