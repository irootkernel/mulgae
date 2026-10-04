# Workflows

Every review requires exactly one original-source selector:

| Selector | Source and scope |
|---|---|
| `--workspace` | Tracked and nonignored untracked regular files in the original workspace |
| `--stage` | HEAD to the actual index; unborn HEAD uses an empty base; conflicts fail |
| `--head` | Every file in the resolved HEAD tree |
| `--commit REVISION` | Resolved commit against its first parent; a root commit uses an empty base |
| `--diff LEFT..RIGHT` | Direct comparison of the resolved endpoints |
| `--diff LEFT...RIGHT` | Merge-base comparison against the resolved right endpoint |

Workspace and index state must remain unchanged while the review runs. Mulgae
retains root identities and resolves committed operands once; it does not create
a source snapshot, checkout, worktree, full-source archive, content fingerprint,
or drift monitor. `.gitignore` affects workspace discovery; `.mulgaeignore` is
neither generated nor processed. Ignoring a path is not a filesystem sandbox.

Use the same selected target, roles, objective and artist inputs for preflight
and execution. Obtain the project binding independently from the intended root:

```bash
mulgae context --output json
mulgae review --stage --preflight --expected-project-binding "$binding" --output json
mulgae review --stage --expected-project-binding "$binding" --output json
```

The optional project binding rejects a different or replaced Git worktree.
An unguarded non-Git workspace remains supported; its binding and preflight
project-binding capability are empty. Supplying an expected Git binding fails
closed on that root.
It is not an idempotency key or a content/request digest. Retired capture-bound
request guards, `--dirty`, `--patch`, `--stdin`, `followup`, `delta`, `rerun`, and
`compose` are rejected before provider execution. Request no automatic fallback.

Preflight v8 reports source selection identity, candidate count, native read
plan, configured routes, timeouts and enclosing budgets. Its source identity
hashes selection metadata, not workspace/index file contents. It discovers and
invokes no provider and creates no run, diagnostics or publication. Ordinary
preflight lists source paths; selected artist inputs also validate the brief
and PNG/JPEG/WebP bytes. CLI emits the full native read plan; MCP summarizes it
with `read_count` and source-selection metadata. No source or provider-content
byte ceiling applies.

A no-change selection publishes zero attempts and no provider identity. Its
preflight has `status: no_change`, no transmissions and an eligible execution
budget with reason `no_change`, zero active lanes and zero invocations.
`--preflight` cannot be combined with `--session`.

Inspect the exact completed run:

```bash
mulgae status --run r_... --output json
mulgae inspect --run r_... --output json
mulgae findings --run r_... --severity low --output json
mulgae read-finding --run r_... --finding F001 --output json
mulgae read-report --run r_... --role logic --output json
mulgae excerpt --run r_... --finding F001 --source-identity-sha256 sha256:... --evidence-index 0 --output json
mulgae report --run r_... --output-path reports/review.md
mulgae export --run r_... --output json
```

Preserve inspection's binding, publication receipt and source identity on
content reads and continuations. Follow every returned cursor and content
chunk. Reports remain authoritative when extraction is mixed or reports-only;
zero extracted findings do not prove a clean report.

Attached MCP exposes `get_context`, `preflight_review`, `run_review`,
`start_review`, `await_review`, `cancel_review`, `list_runs`, `get_run`,
`inspect_review`, and `list_findings`. Prefer one start and one pending await
on its exact returned invocation. An interrupted await ends only the observer.
Explicit cancellation still requires awaiting terminal completion; a lost start
response never authorizes another start.

Historical ordinary, child, composite, failed and no-change records remain
verified and unchanged. Query, report, export, cleanup ancestry protection and
provider-free P0/P1/P2 reconciliation remain supported. They grant no source
replay or new child/composite execution authority.
