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
not yet been run in a live Claude Code session, and its use of the macOS Keychain has not
been run on a Mac at all. [What is not verified yet](#not-verified-yet)
lists every such point. Read [Known gaps](#known-gaps) before you rely on it.

## Requirements

- Claude Code **2.1.295 or later** (the plugin depends on `onFailure: "block"` for hooks).
- **A supported machine** (see [Supported machines](#supported-machines)): macOS on Apple
  Silicon, or Linux on x86_64 with glibc 2.38 or later, each with a key store the plugin can
  use. Anywhere else the plugin does not run and blocks tool calls; there is no reduced mode.
- `sh` and `bash` or `zsh`.
- `uv`, or Python 3.10 or later with `pip`, and access to PyPI on first start. The plugin
  builds a private Python environment in its data directory and installs two packages of
  the DataFog core project: `datafog-core>=1.7.0,<1.8` (the detector) and
  `datafog-fogvault>=1.7.0,<1.8` (the encrypted vault). Detection and storage are local;
  nothing is sent anywhere.

### Supported machines

| Machine | Supported | Vault key is kept in |
| :- | :- | :- |
| macOS 11 or later on Apple Silicon (arm64) | yes | the login Keychain |
| Linux x86_64, glibc 2.38 or later (Ubuntu 24.04, Debian 13, Fedora 39 and later), desktop session | yes | the Secret Service (GNOME Keyring, KWallet) |
| The same Linux without a Secret Service (server, container, SSH session, CI) | only with `vault_key: file`, which is weaker; see [The vault](#the-vault) | a file beside the vault |
| macOS on Intel | **no** | |
| Linux on ARM, or with an older glibc (Ubuntu 22.04, Debian 12, RHEL 9, Amazon Linux 2023), or with musl (Alpine) | **no** | |
| Windows | **no** (the vault library exists for Windows x64; the rest of the plugin does not yet) | |

The limit comes from the vault: `datafog-fogvault` 1.7.0 is published as compiled packages
for exactly `macosx_11_0_arm64`, `manylinux_2_38_x86_64` and `win_amd64`, and the plugin has
no other place to keep values. **On an unsupported machine it fails closed.** The installer,
the session start line, every hook, `/datafog:status` and `/datafog:doctor` give the same
message, and tool calls are blocked until you disable or uninstall the plugin:

```
DataFog does not support this machine. It needs macOS on Apple Silicon, or Linux on x86_64 with glibc 2.38 or later. Nothing is protected and tool calls are blocked; disable or uninstall the plugin to work without it.
```

The same holds when the key store cannot be used (locked, missing, access refused): the
message names the key store, and nothing runs unprotected.

## Install

```
/plugin install datafog --marketplace DataFog/datafog-claude-plugin
```

Start a new session. The first start installs the private environment (a few seconds)
and prints one status line, for example:

```
DataFog guard: on. Vault: user data folder (kept on uninstall), encrypted, key in the system key store. Bash output: filtered. Markers in Bash commands: ask. Detecting: EMAIL, PHONE, ...
```

The first start also creates the vault and stores its key in your key store. On macOS this
adds one entry to the login Keychain (service `DataFog.ApplicationVault.v1`); macOS may ask
you to allow access, see [Not verified yet](#not-verified-yet).

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
It is matched as a whole value, whatever its case and however its parts are spaced, and
not inside a longer word or number (`000123456789` is not found inside `x000123456789y`).

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
| **Grep, WebFetch, WebSearch, MCP tools, subagent results, any other tool** | Output is tokenized after the tool ran. Before the tool runs, the plugin checks that the vault opens (its lock can be taken, its key is available, it decrypts) and that the detector finds a test value, and refuses the call if not. | If the plugin breaks *between* that check and the result (hard crash, timeout), **the raw output reaches the model.** Claude Code offers no way to prevent this for output that only exists after a tool ran. |
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
  50 ms (most of it is starting Python). Measured on a Linux container; see
  [Speed](#speed) for the numbers with the encrypted vault.

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
11. **The vault is encrypted at rest, and that protects against less than it may sound.**
    The file on disk is ciphertext and its key is in your operating system's key store, so
    a copy of the file (a backup, a synced folder, a stolen disk image without your login)
    reveals no value. It does **not** protect against a program running as you while you
    are logged in: such a program can ask the key store for the key the same way the plugin
    does, or start the plugin's own Python. The plugin refuses Read, Write, Edit and Grep on
    the vault directory and Bash commands that name it; a command that reaches it indirectly
    is only covered by the output filter. With `vault_key: file` the key lies beside the
    data and a copy of the directory reveals everything. What is **not** encrypted: the
    marker index (the markers issued, no values), the number of values, the vault's ids and
    revision, and the key that signs restore tickets for Bash commands.
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
- **Limits.** Core allows 20,000 values in a vault, and about 100,000 changes to it (each
  batch of *new* values is one change; values the vault already holds cost none). At the
  limit the plugin stops (new values cannot be protected) and says so; values it already
  holds keep working. The remedy today is `/datafog:purge`.
- **Each process that replaces values holds the vault's values in its memory** while it
  runs (to recognise them), as core's own code did before.

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
- **One encrypted vault, no unencrypted fallback.** Values are kept only in core's
  application vault. A machine without the vault library or without a usable key store is
  not supported: the plugin fails closed there instead of storing values in the clear. The
  unencrypted file store of earlier development builds is gone and is not migrated.
- **The key store is the default; a key file is an explicit, documented downgrade**
  (`vault_key: file`) for machines that have no key store, never chosen automatically.
- **Known values are matched by the plugin, from a marker index.** Core's application vault
  has no way to look a value up without writing, and no known-value matching. The plugin
  keeps the list of markers it issued (not secret, not authoritative) and restores them in
  memory to recognise values. Asking core to store every detected value again was rejected:
  it rewrites the whole vault each time and uses up core's limit of about 100,000 changes.
- **The Bash restore-ticket key stays a small file in the vault directory**, not an entry in
  the vault. It guards against a command starting the runner by itself, not against a
  program that can read your files, and such a program could equally open the vault through
  the key store. Putting it in the vault would add a marker that must never be restored.
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

The vault is the table that maps markers to real values. There is **one vault for this
plugin, shared by all your projects**, so a value has the same marker everywhere.

**Where it lives**

| | Location |
| :- | :- |
| `DATAFOG_VAULT_DIR` is set | that directory |
| "Keep the vault when the plugin is uninstalled" is on (default) | macOS `~/Library/Application Support/DataFog/vaults/claude-code`; Linux `$XDG_DATA_HOME/datafog/vaults/claude-code` or `~/.local/share/datafog/vaults/claude-code` |
| the option is off | `${CLAUDE_PLUGIN_DATA}/vault`, which Claude Code deletes when the plugin is uninstalled |

**How it is stored.** The plugin uses the application vault of the DataFog core project
(`ApplicationVault` in the `datafog-fogvault` package) and adds two small files of its own:

| File | Mode | What it is |
| :- | :- | :- |
| `workspace.enc` | 0600 | Core's vault: every value, encrypted (XChaCha20-Poly1305, a 256-bit random key). The application id, a random vault id, the revision and the key mode are readable in its header; the values are not. |
| `workspace.lock` | 0600 | Core's lock file. Every change holds it from reading the vault to the finished, flushed write. |
| `workspace.key` | 0600 | **Only with `vault_key: file`.** The key itself. |
| `markers.index` | 0600 | The plugin's list of markers issued so far (such as `[[EMAIL_7KQ4ZM]]`). No values. It lets the plugin recognise known values and count them without changing the vault; if it is lost or damaged, nothing breaks and it fills up again. |
| `bash-restore.key` | 0600 | The plugin's key for signing restore tickets ([Markers in Bash commands](#markers-in-bash-commands)). Not the vault key, and it decrypts nothing. |

The directory is 0700. The plugin makes a new or still empty directory private itself. If
the directory or a file of an existing vault is open to other users, is not yours, or the
vault directory is a symbolic link, the vault is refused and nothing is repaired silently:
`/datafog:doctor` says which.

**Where the key is.** By default (`vault_key: keystore`) the key is created once, stored in
your operating system's key store, and read from there by every plugin process:

- macOS: the login Keychain, one entry with service `DataFog.ApplicationVault.v1` and
  account `claude-code/<vault id>`.
- Linux: the Secret Service (GNOME Keyring, KWallet), same service and account.

Each vault directory has its own vault id and its own key, so two different
`DATAFOG_VAULT_DIR`s never share one. The key is never written to a file, a log, an
environment variable or a command line by the plugin; it is handled inside core's compiled
code only.

If the key store is locked, not running or refuses access, the plugin stops with
`keystore_unavailable` and blocks tool calls. It never creates a second key for an existing
vault and never switches to a key file on its own. If the entry was deleted from the key
store, the vault cannot be opened again by anyone: delete it with `/datafog:purge`.

**`vault_key: file` (opt-in, weaker).** For machines without a key store (a Linux server,
a container, CI) you can set `vault_key` to `file` in `config.json`, or
`DATAFOG_VAULT_KEY=file`, **before the vault is first created**. The key is then a file,
`workspace.key`, in the vault directory. The vault file is still ciphertext, but anyone who
can copy the directory has both, so this protects only against someone who gets
`workspace.enc` alone. A vault keeps the mode it was created with: opening it with the other
setting fails with `vault_key_mismatch` (purge it to change).

**Several sessions at once.** Hooks are separate short processes and may run in parallel,
next to the long-lived Bash runner and the plugin's MCP server. Changes are serialised by
core's lock and each one is written completely and flushed before a marker is handed out, so
a crash leaves the old vault or the new one, never half of one. A value that is already known
is recognised without writing.

**Uninstalling: keep or delete.** This is the plugin option "Keep the vault when the plugin
is uninstalled":

- **On (default): keep.** The vault stays in your user data folder and its key stays in
  your key store. Markers that are still in your files can be restored after you install
  the plugin again. To remove everything later, run `/datafog:purge` before uninstalling, or
  delete the folder above and the key store entry by hand.
- **Off: delete.** The vault is in the plugin's data folder and Claude Code deletes it on
  uninstall. The key store entry is left behind (Claude Code does not know about it); it is
  32 random bytes that open nothing once the vault file is gone. Run `/datafog:purge` before
  uninstalling to remove it too, or delete it in Keychain Access (search for `DataFog`).

`/datafog:purge` deletes the vault file, the marker index, the ticket key, the key file if
there is one, and the entry in the key store (on macOS with `security
delete-generic-password`, on Linux with `secret-tool`, because core has no call for it; if
that fails, purge tells you the service and account to delete by hand).

If the vault is deleted, every marker issued from it is meaningless. Text that still
holds markers (a file Claude wrote through another tool, notes, old transcripts) can
then never be turned back into real values.

**Coming from a development build.** Builds before this one kept the vault unencrypted in
the same directory (`HEAD`, `meta.json`, `snapshots/`). This version never reads those
files. `/datafog:status` and `/datafog:doctor` say so when they are still there, and
`/datafog:purge` deletes them; nothing is migrated.

**Limits of the vault library (core 1.7.0) worth knowing:**

- **Every directory above the vault must be listable by you**, not only passable. On a
  shared Linux machine where `/home` has mode 0711 the vault cannot be opened
  (`vault_unreadable`). Put the vault elsewhere with `DATAFOG_VAULT_DIR`.
- Core waits at most 5 seconds for the vault's lock; the plugin retries up to
  `DATAFOG_LOCK_TIMEOUT` (default 10) seconds in total and then stops with `vault_locked`.
- Restoring an older copy of the vault directory rolls the vault back; markers issued since
  are then unknown. The encryption does not detect that.
- 20,000 values and about 100,000 changes per vault; see [Known gaps](#known-gaps).

### Speed

Wall time of one whole process (starting Python, opening the vault, the work), median and
95th percentile of 40 runs, on a Linux x86_64 container (4 KiB-scale inputs, small vault).
"Before" is the unencrypted file store of the development build with the same core 1.7.0.

| Process | Before | Encrypted, key in a file | Encrypted, key in the Secret Service |
| :- | -: | -: | -: |
| PreToolUse hook for a Bash command | 45 / 61 ms | 50 / 63 ms | 56 / 59 ms |
| PostToolUse rewrite, 1 known value | 47 / 49 ms | 51 / 65 ms | 58 / 75 ms |
| PostToolUse rewrite, 10 known values | 46 / 49 ms | 52 / 72 ms | 58 / 96 ms |
| PostToolUse rewrite, 200 known values | 55 / 66 ms | 55 / 60 ms | 60 / 78 ms |
| PreToolUse Write, one marker restored | 44 / 55 ms | 47 / 52 ms | 57 / 78 ms |
| Runner, command without markers | 69 / 83 ms | 72 / 76 ms | 80 / 97 ms |
| Runner, one marker restored | 73 / 86 ms | 77 / 88 ms | 86 / 116 ms |

Starting Python alone is 11 ms of each. With 19,000 values in the vault a rewrite takes
about 220 ms (150 ms before) and a Bash command with a marker about 320 ms (185 ms before),
because core reads and decrypts the whole vault for each operation. **The macOS Keychain
was not measured** (no Mac was available for this build); the optional live case below does.

## Commands

- `/datafog:status` shows whether protection is on, where the vault is, how it is
  encrypted and where its key is, and entity types and counts. Never values.
- `/datafog:doctor` checks the installation and says what to fix: supported machine, both
  libraries, the vault (permissions, lock, key, decryption), leftovers of a development
  build, the Bash filter, your permission rules.
- `/datafog:purge` deletes the vault and its key after an explicit confirmation step.

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
| `vault_key` | `DATAFOG_VAULT_KEY` | `keystore` | Where the vault's key is kept: `keystore` (macOS Keychain, Linux Secret Service) or `file` (beside the vault; weaker, for machines without a key store). Fixed when the vault is created. See [The vault](#the-vault). |
| `max_scan_bytes` | `DATAFOG_MAX_SCAN_BYTES` | 5 MiB | Larger files count as "cannot be checked". |
| | `DATAFOG_VAULT_DIR` | | Vault directory. Must be an absolute path whose parent directories you can list. |
| | `DATAFOG_LOCK_TIMEOUT` | 10 | Seconds to wait for the vault's lock before stopping. |

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
- **The macOS Keychain, all of it.** The key-store mode was run on Linux against a private
  GNOME Keyring only. On a Mac, to be checked by hand or with the optional live case
  (`LIVE_KEYCHAIN=1`, below): that creating the entry at first start does not prompt; whether
  macOS asks "python wants to use your confidential information" when a hook reads the key,
  how often, and what "Always Allow" does; whether the question comes back after the
  plugin's Python is updated or its private environment is rebuilt (the Keychain ties its
  permission to the program that created the entry, and that program is the Python in the
  plugin's data directory); what happens while the Keychain is locked, in an SSH session and
  right after login; how long reading the key takes in a hook; that a hook waiting on a
  Keychain question ends as a blocked call and not as an unprotected one; and that
  `/datafog:purge` removes the entry (`security delete-generic-password`).
- The Secret Service with KWallet, and with a keyring that is locked when a session starts.
- Whether Claude Code lets Write or Edit change a file that was read through a redirected
  copy (its read-before-write check may not count that read).
- What the built-in Edit tool's result shows the model after the plugin replaced it.
- That the plugin's MCP server receives the project directory and starts on first install.
- How a blocked prompt and an `ask` decision look to you.
- Behaviour when Claude Code's own Bash sandbox is enabled (the runner starts the command in a new session).
- Anything on Windows.

To run the live check on your machine (about 27 short headless `claude -p` runs in a
throwaway temp project with a temporary vault whose key is a file in the temp directory;
your real vault and your Keychain are not touched; hard caps of 30 runs, 180 seconds each,
30 minutes in total):

```sh
tests/live/run-live.command          # or double-click it in Finder
```

Because of that, the standard run does not exercise the Keychain. One optional, clearly
separate case does: `LIVE_KEYCHAIN=1 tests/live/run-live.command` adds `L28-keychain`,
which makes a second throwaway vault with its key in your real key store (one new entry),
uses it from several processes, measures it, and deletes the vault and that entry again.

Results land in `.live/results/results.md`.

## Development

```sh
uv venv && uv pip install "datafog-core>=1.7.0,<1.8" "datafog-fogvault>=1.7.0,<1.8" pytest ruff mypy
DATAFOG_TEST_NETWORK=1 .venv/bin/python -m pytest    # the flag enables tests that build the private environment
.venv/bin/ruff check . && .venv/bin/mypy
```

Tests never use your key store: every test vault keeps its key in a file in the test's
temp directory. `tests/test_keystore.py` runs the key-store mode against a private Secret
Service (its own D-Bus session and GNOME Keyring in a temp directory) and needs Linux with
`dbus-run-session`, `gnome-keyring-daemon` and `secret-tool`; elsewhere it is skipped.

Layout: `engine/datafog_guard/` (the engine; entry `python -m datafog_guard <hook|run|filter|mcp|status|purge|doctor>`),
`scripts/` (launcher, environment bootstrap, shell wrapper), `hooks/hooks.json`,
`.mcp.json`, `commands/`, `tests/`, `tests/live/`. For the vault: `store.py` (core's encrypted
application vault, the marker index, purge) and `vault.py` (finding values, assigning markers,
restoring). For Bash: `shellsub.py` (the lexer that
puts values into a command as data, with its threat note), `ccperms.py` (reading and applying
your Claude Code permission rules), `filtercmd.py` (the runner), `bashwrap.py` (the rewrite
and the restore ticket).

All test data is synthetic (`ada.synthetic@example.com`, test card `4242 4242 4242 4242`).

## License

Apache-2.0. See [LICENSE](LICENSE).
