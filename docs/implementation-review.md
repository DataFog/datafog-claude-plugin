# Independent candidate diff review

Reviewed 2026-11-18 while preparing 0.2.1. Scope: joined-email mitigation in `vault.py`, resource-link metadata in `shapes.py`, exact-file permission checks in `ccperms.py`, and descriptor-based MCP editing in `mcp_server.py`. This is a focused review, not proof that every repository behavior is verified.

## Findings resolved during review

1. **Repeated email-tail scans could time out hooks.** A joined sequence of 1,000 addresses (~20 KB) produced 500 overlapping expanded spans and took 0.793 seconds; 100 addresses took 0.010 seconds. The initial mitigation repeatedly scanned already covered tails. After tracking covered email ranges, the same 1,000-address case produced one span in 0.0045 seconds; 10,000 addresses (~200 KB) took 0.0437 seconds. A deterministic detector-call-count regression now bounds repeated probes, avoiding machine-dependent timing assertions.
2. **Alias retargeting could evade a file deny rule.** A temporary-project reproduction changed `alias.txt` from `safe.txt` to `denied.txt` immediately after `check_file_path` returned. The earlier server then captured the new realpath and edited the denied file. The revised server captures its target before authorization, checks both alias and captured path, and refuses if the alias changes before reading or replacing. The same reproduction now raises a path-change error; both files remain unchanged.

## Verification and limits

- Independently ran the core-behavior, hook-protocol and MCP suites successfully after these fixes. The implementation workstream separately ran the broader permission/MCP/core set. Final full-suite and platform CI evidence must refer to the committed release candidate.
- Resource-link tests check display-text tokenization while preserving response shape and identity fields. Resource URIs deliberately remain untouched; README and privacy disclosures now say so.
- Editor tests cover effective file rules, ask/deny, alias and real-target policies, permissions/CRLF, changed files/parents, bounded reads, FIFO refusal and cooperating-editor locking. Full-server race reproduction was independently exercised, not merely inferred from the helper class.
- The editor does not provide an atomic filesystem compare-and-swap against noncooperating writers between its final identity check and rename. It also cannot enforce server/MDM policies unavailable to the plugin. Those are explicit boundaries, not closed verification gates.
- No further blocking defect was found in this focused diff review after the two fixes. This does not waive outstanding interactive, Linux, release or portal gates.
