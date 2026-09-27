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
mulgae inspect --run r_... --limit 100 --output json
mulgae findings --run r_... --severity high --limit 100 --output json
mulgae read-finding --run r_... --finding F001 --output json
mulgae read-report --run r_... --role logic --output json
mulgae excerpt --run r_... --finding F001 --current-target-sha256 sha256:... --evidence-index 0 --output json
mulgae report --run r_... --output-path reports/review.md
```

`findings`, `excerpt`, and `followup --finding` read committed structured
findings. With `validation.extraction.enabled`, a role that returned only a
free-form report still reaches them: Mulgae transcribes that accepted report on
the same provider and verifies each quote against the captured target. A role
that already spent its second invocation on a retry or a failed repair is not
transcribed, so the run reports `mixed`.

Inspect the capture and configured execution envelope without running providers:

```bash
mulgae review --stage --preflight --output json
```

Preflight performs complete immutable capture, directory-view admission, and
capture-manifest construction, then reports
the exact source file set transmitted to every selected role, each role's
provider route, effective provider timeouts, and enclosing
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

A no-change target reports `status: no_change` with no
transmissions or execution budget. `--preflight` cannot be combined with
`--session`.

For a Git worktree, save the preflight `project_binding` and
`request_receipt.request_digest`, then supply both to execution:

```bash
mulgae review --stage --expected-project-binding "$binding" --expected-request-digest "$request_digest" --output json
```

Use the same target, roles, objective, and artist selectors as preflight. A source
or policy change returns `request_digest_mismatch` before provider work. A foreign
worktree returns `project_binding_mismatch`. `--preflight` accepts the expected
binding alone. Successful execution reports `guarded: true`; omitting both guards
keeps ordinary unguarded execution. Repeating an accepted guard creates a new run.
Non-Git workspace review remains available without guards.

Child workflows create new immutable runs:

```bash
mulgae followup --run latest --finding F001 --dirty
mulgae delta --since-run latest --dirty --roles logic,testing
mulgae rerun --run latest --attempt a_019f596a-cf80-7c67-b265-f37053d51ccf
mulgae rerun --run latest --role logic --provider zcode-logic
```

`followup` checks one finding, `delta` reviews changes relative to a prior run,
and `rerun` repeats one prior attempt. `delta` requires an explicit `--roles`
list. In the alternate rerun selector, `--provider` is the exact persisted
provider instance, not a provider family name. Run child workflows from an
initialized Git worktree root. If `project_root_mismatch` reports that the
Mulgae artifact root is unavailable, confirm the canonical root first; run
`mulgae init` there only when initialization is intended and explicitly
authorized. Use `--output json` for machine-readable command envelopes,
including rejected syntax, unresolved selectors, cancellation, and typed
artifact or security failures.

For an unpublished failed run, inspect `status --run r_... --output json` first.
When `failed_run_recovery.available` is true, rerun each returned `attempt_id`
with `rerun --run r_... --attempt a_... --replay exact --output json`.
Preserve `accepted_roles`; a recovery manifest does not publish a final review.
A failed rerun may retain another recovery source, so inspect its returned run ID
before retrying. Missing sources, including v0.1.19 diagnostic-only failures,
cannot be reconstructed from logs. Internal errors do not authorize an unlimited
retry loop.

After exact role reruns have committed, compose an incomplete root without
invoking providers again:

```bash
mulgae compose --root-run r_... --recovery-run r_... --output json
```

Provide one unique exact recovery run for every missing selected role; `latest`
is never accepted. Preserve the returned deterministic composite `run_id`. If
the result says `status_required`, inspect that ID with `status` instead of
blindly retrying the mutation.

New composites support receipt-bound finding, report, and indexed evidence
reads through the CLI and MCP. They retain exact original findings, portable
source receipts, and copied evidence, so allowed source-run cleanup does not
break those reads. A failed recovery source carries its recovery manifest digest
and attempt identity, without claiming a published review. Historical composites
may return `evidence_unavailable`; they are never upgraded in place. Existing
`status`, `report`, and redacted `export` behavior remains available.

For MCP, an uncertain `compose_review` publication returns
`composite_publication_incomplete`, non-null `session_id` and `run_id` values,
and `retryable: false`. Inspect that exact run before repeating the mapping.

An MCP client may start one attached stdio process rooted at the current
canonical project directory or an explicit absolute path:

```bash
mulgae mcp
mulgae mcp --project-root /absolute/path/to/repository
```

The process prefers MCP `2026-07-28` through `server/discover`. Legacy
`initialize` negotiates `2025-11-25` or `2025-06-18`; naming the newer protocol
without discovery falls back to `2025-11-25`. It writes newline-delimited
JSON-RPC to stdout, writes bounded diagnostics to stderr, and stops when the
client closes stdin. Every nonempty input record must end with LF; a partial
final record is rejected without dispatch. The project root is fixed at startup.
It provides
`preflight_review`, `run_review`, `start_review`, `await_review`,
`cancel_review`, `compose_review`, `get_context`, `list_runs`, `get_run`, `inspect_review`, and `list_findings`.
Preflight is execution-free and returns a bounded plan summary. `run_review`
completes in the foreground and accepts workspace, stage, dirty, diff, or patch
targets; stdin is reserved for JSON-RPC and cannot carry review content.
`start_review` accepts the same arguments and returns one process-local
invocation ID before completion. `await_review` waits eventfully on that exact
identity and may be repeated without starting another run. Cancelling an await
ends only that observer. `cancel_review` is the sole explicit cancellation tool;
its acknowledgement is not terminal, so await the final result. The invocation
registry retains at most 64 identities, may discard oldest terminal identities
to admit a new start, and has no recovery after server exit. Query
tools return bounded verified projections, not report or source bodies. Their
`mulgae://` report and evidence resource links expose integrity-checked content
in chunks of at most 16 KiB, with SHA-256, offset, total length, completion, and
continuation metadata. All tools use the common
`mulgae-mcp-tool-result.v1` structured envelope, where `request_changes` is a
completed review rather than a transport failure. Errors include nullable
session and run IDs; a terminal `await_review` error also includes its exact
invocation ID. When a failed `run_review` returns both, inspect that exact run
with `get_run`. A diagnostic-only result is limited to a completed `failed`
or `cancelled` status and has no publication authority or findings;
`run_status_unavailable` means allocation succeeded but no durable published or
terminal diagnostic status survived. Never retry `run_review`, because a second
call creates a new run. Never retry an uncertain `start_review`; re-await the
preserved invocation only while the same MCP session is alive.

Clients that attach a progress token to `run_review` receive an admission
notification, monotonic periodic heartbeats, and a terminal notification before
the result. Cancelling the MCP request cancels that foreground review and its
provider processes. Progress is optional and best-effort; it never changes the
review outcome or publication authority. Lifecycle awaits emit no heartbeat
loop, and an `await_cancelled` result is retryable without cancelling execution.
Terminal awaits remain repeatable for retained identities.
`invocation_limit_reached` is non-retryable and occurs only when 64 reviews are
still running. `invocation_registry_closed` is
non-retryable and means an await observed the server session ending while the
transport could still deliver a result. Closing MCP stdin ends the transport,
so pending calls may end without a response while their reviews are cancelled
and drained before process exit.

## Compare an attached server's project

Run `mulgae context --output json` from the independently selected repository and
compare `result.project_binding` with `get_context`'s `data.project_binding`.
The server retains its startup directory descriptors and rejects a lookup after
root or Git-directory replacement. It cannot select another root per request.
Canonical path aliases agree; separate checkouts and linked worktrees differ.
Both lookups are read-only and need no Mulgae configuration or provider setup.
Context advertises `v1` for project binding, execution guards, capture identity,
inspection, finding pages and details, report content, indexed evidence, and
composite evidence. Check each needed field; an empty value means unavailable.
Historical evidence can remain unavailable even when the reader supports it.

For an attached server with matching binding and guard support, call
`preflight_review` with `expected_project_binding`. Reuse its exact target,
objective, roles, and other selectors on `start_review`, adding
the same `expected_project_binding` and the preflight
`request_receipt.request_digest` as `expected_request_digest`. Call start once,
preserve its invocation ID, and await it. Guard mismatches stop before provider work; a second accepted
start creates another run. The complete capture identity covers retained source
material independently of request-only inputs such as objective or roles.

When the attached client cannot expose a required native capability, select the
CLI from the independently chosen root before execution. Do not retarget the
attached server or restart an uncertain review. Older clients and binaries keep
their legacy reads, but separate status/count queries and later raw artifact
reads do not establish one publication snapshot. Report which guarantees the
legacy output cannot provide.

### Verified finding pages and details

`inspect` defaults to severity `low`; `findings` still requires `--severity`.
Both accept `--limit` (1 to 1,000, default 100), `--cursor`,
`--expected-project-binding` and `--expected-publication-receipt`.
`finding_count` is the filtered total. Follow `next_cursor` with the same command,
unchanged selectors, and expected receipt to read another page from the same
verified publication. An empty cursor ends the result.

`read-finding` returns complete finding JSON through bounded UTF-8 chunks.
For the next chunk, pass the returned `next_offset` as `--offset`, together with
`--expected-publication-receipt` and `--expected-content-sha256`. The MCP finding
`detail` resource returns the corresponding continuation URI. Stop when
`next_offset` is null. A changed receipt, digest or project fails the read.
Inspection reports publication authority, coverage, structured extraction, and
CI separately. Reports-only output can have no structured findings while its
original role reports remain available. Diagnostic-only runs have no publication
receipt. Historical capture support can be unavailable even when the final review
remains readable. A missing bound capture or evidence artifact is corruption,
not historical unavailability.

### Lossless reports and indexed evidence

`read-report --run ID` reads rendered Markdown; add `--role ROLE` for an
original role report. It creates no file. `excerpt` keeps the required
`--current-target-sha256` and accepts zero-based `--evidence-index` plus the
same content selectors as `read-finding`. Supplying a new selector chooses
receipt-bound chunks. Legacy excerpt calls and `report --output-path` retain
their existing behavior.

Read every chunk until `next_offset` is null, preserving both returned digests
and the expected project binding. MCP inspection returns role-report and
indexed-evidence URIs; follow `io.mulgae/nextURI` without rebuilding it. Text
chunks preserve UTF-8 and exact bytes. A complete report has no size ceiling.
Legacy resource URIs keep their historical continuation mode and do not gain
receipt binding. Missing historical evidence is unavailable; corrupt bound
support fails rather than falling back to the working tree.
