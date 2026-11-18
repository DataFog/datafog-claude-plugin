# Reporting a vulnerability

Report security vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/DataFog/datafog-claude-plugin/security/advisories/new).
Private reporting is enabled for this repository. Use public issues for non-sensitive
bugs and support questions only.

Include the plugin version or commit, Claude Code version, operating system, relevant
configuration and a minimal reproduction using synthetic data. Describe the expected
behavior and what happened. Do not send real credentials, vault/key files, personal data
or unredacted transcripts. If a demonstration needs a sensitive artifact, describe it
first so a safe reproduction can be arranged.

The current release is supported for fixes on the platforms listed in the README.
Older releases should be updated before retesting. No response-time guarantee is made.

DataFog reduces accidental exposure of detected values. It is not a sandbox against
malicious agents or programs running as the same user. Read the README's known gaps
when evaluating a report; unexpected exposure on an advertised protected path is still
worth reporting.
