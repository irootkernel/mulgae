# Workflows

Every review-like command requires exactly one target:

```text
--workspace
--stage
--dirty
--diff REVISION_RANGE
--patch RELATIVE_PATH
--stdin
```

Common commands:

```bash
mulgae review --diff origin/main...HEAD --objective "Review before merge."
mulgae status --run r_...
mulgae findings --run r_... --severity high
mulgae report --run r_... --output-path reports/review.md
```

Inspect the capture and configured execution envelope without running providers:

```bash
mulgae review --stage --preflight --output json
```

Preflight performs complete immutable capture, directory-view admission, and
capture-manifest construction, then reports
the exact source file set transmitted to every selected role, each role's
provider route, effective provider timeouts, AGY permission mode, and enclosing
role-path/run budgets. `qualification` is `not_run`: preflight does not discover,
qualify, repair, or invoke a provider, and it creates no session, run,
diagnostics, publication, or durable review artifact. The workspace manifest is
listed separately as `generated_at_execution`; its ephemeral filesystem identity
is not represented as source evidence.

Source capture has no fixed file-count, aggregate-byte, per-file, diff, patch,
stdin, or capture-manifest ceiling. Preflight still rejects malformed paths,
reserved namespaces, selected symlinks and special files, invalid raster
signatures, and files excluded by capture policy. Other malformed preflight
projections use `preflight_result_validation_failed`.
Both include a safe stage and next-action hint without creating diagnostics or
printing captured paths. Human failures from every command include a stable
code, public stage, and minimum remediation hint.

An explicit AGY `safe` mode produces a warning because headless tool requests
may be denied. A no-change target reports `status: no_change` with no
transmissions or execution budget. `--preflight` cannot be combined with
`--session`.

Child workflows create new immutable runs:

```bash
mulgae followup --run latest --finding F001 --dirty
mulgae delta --since-run latest --dirty --roles logic,testing
mulgae rerun --run latest --role logic --provider zcode
```

`followup` checks one finding, `delta` reviews changes relative to a prior run,
and `rerun` repeats one prior attempt. Use `--output json` for machine-readable
command envelopes.

An MCP client may start one attached stdio process rooted at the current
canonical project directory or an explicit absolute path:

```bash
mulgae mcp
mulgae mcp --project-root /absolute/path/to/repository
```

The process accepts MCP `2026-07-28` only, writes newline-delimited JSON-RPC to
stdout, writes bounded diagnostics to stderr, and stops when the client closes
stdin. The project root is fixed at startup. It provides `preflight_review`,
`run_review`, `list_runs`, `get_run`, and `list_findings`. Preflight is
execution-free and returns a bounded plan summary. `run_review` completes in
the foreground and accepts workspace, stage, dirty, diff, or patch targets;
stdin is reserved for JSON-RPC and cannot carry review content. Query tools
return bounded verified projections, not report or source bodies. Their
`mulgae://` report and evidence resource links expose integrity-checked content
in chunks of at most 16 KiB, with SHA-256, offset, total length, completion, and
continuation metadata. All tools use the common
`mulgae-mcp-tool-result.v1` structured envelope, where `request_changes` is a
completed review rather than a transport failure.

Clients that attach a progress token to `run_review` receive an admission
notification, monotonic periodic heartbeats, and a terminal notification before
the result. Cancelling the MCP request cancels that foreground review and its
provider processes. Progress is optional and best-effort; it never changes the
review outcome or publication authority.
