# Architecture

## Dependency direction

Mulgae follows a domain-first, ports-and-adapters design:

```text
main
  -> internal/composition
      -> internal/entrypoint/mulgae
      -> internal/entrypoint/mcp
      -> internal/app/*
      -> internal/adapters/*
      -> internal/builtin

internal/entrypoint/mulgae -> internal/app/* -> internal/domain
                                             -> internal/ports
internal/entrypoint/mcp ----------------------> external MCP SDK
internal/adapters/* --------------------------> internal/ports
```

The domain and application packages do not depend on CLI parsing, provider
process details, or concrete storage. Adapters implement ports;
`internal/composition` wires concrete implementations into the application,
and the root `main.go` delegates process execution to that package. Architecture
tests enforce this direction and keep every other Go file out of the repository
root.

## Package map

| Area | Responsibility |
|---|---|
| `main.go` | Darwin/arm64 process shim and release linker variables |
| `internal/composition` | Executable bootstrap, build identity, and production graph |
| `internal/entrypoint/mulgae` | CLI grammar, dispatch, output, selector resolution |
| `internal/entrypoint/mcp` | Attached stdio MCP grammar, protocol admission, and tool projection |
| `internal/app/reviewrun` | Target capture, planning, qualification, prompts, orchestration |
| `internal/app/review` | Assignments, coordination, aggregation, results |
| `internal/app/validation` | Wire parsing, trusted-field injection, checks, repair |
| `internal/app/publication` | Manifests, attempts, final artifacts, recovery, integrity |
| `internal/app/{followup,delta,rerun}` | Child-run lineage and specialized reviews |
| `internal/app/childrun` | Child-run execution and publication engine |
| `internal/app/{query,report,clean,export}` | Inspection and artifact lifecycle |
| `internal/domain` | IDs, findings, failures, states, roles, immutable values |
| `internal/ports` | Interfaces and safe values crossing application boundaries |
| `internal/adapters/providercli` | Provider profiles, qualification, credentials, invocation |
| `internal/adapters/workspace` | Isolated directory views and descriptor-bound workspaces |
| `internal/adapters/filesystem` | Secure project-local storage and publication |
| `internal/adapters/jsonschema` | Offline Draft 2020-12 validation |
| `internal/builtin` | Embedded schemas, prompts, examples, and help |
| `assets` | Repository-root human-authored role document, embedded into the binary |
| `internal/roles` | Role document schema, parsing, and whole-catalog validation |
| `internal/app/roleassets` | Single application-layer reader of the role document |
| `skills` | Optional, source-distributed AI-agent operating guidance; not a runtime authority or embedded binary asset |
| `test/e2e` | Black-box binary integration, artist fixture, and live-provider E2E tests |

## Role catalog

`assets/roles.yaml` is the one human-authored source for the fixed review roles.
It carries each role's review guidance, its ordered `provider_preferences`, and
the artist input defaults. `go:embed` patterns cannot escape their own package
directory, so the root `assets` package embeds the document and `internal/builtin`
overlays it into the contract catalog under the same checksum inventory as every
embedded file.

The document is a generation-time authority only. `mulgae init` derives the
default provider assignment it writes into a new project from the preference
order intersected with the providers it configured. Nothing resolves a
configured value from embedded bytes, and the policy in `.mulgae/config.yaml`
is never re-derived after init. Machine paths are independently admitted from
the untracked `.mulgae/local.yaml` authority.

## Review flow

1. The entrypoint parses one canonical command request.
2. Project-local configuration is admitted against platform and locality rules.
3. The requested target is captured immutably.
4. The planner selects roles and each role's configured provider.
5. Mulgae composes trusted prompt layers and one capture-owned immutable
   directory view shared by every role in the run. A single tree is available
   under `current/`; a Git comparison exposes both `before/` and `after/`.
6. Provider executions run independently within the explicit
   `max_active_lanes` process capacity, with adapter-owned tool boundaries and
   per-invocation process isolation against that shared directory view.
7. The provider result arrives on the transport declared for that route: a
   Mulgae-owned staged file the adapter validates and reads back after the
   process terminates, or process stdout.
8. UTF-8 provider output becomes Mulgae-owned free-form role reports without a
   fixed report-size ceiling; bounded previews remain private diagnostics;
   optional exact JSON may be structured-extracted and normalized with
   Mulgae-owned identity/state. Prose is not treated as a schema document.
9. One constrained repair on the same provider occurs only when an explicit
   transition authorizes it. A role never moves to another provider: a failed
   role is reported with its typed reason while peer roles continue.
   When `validation.extraction.enabled` is set and a role was accepted with a
   free-form report only, Mulgae instead schedules one structured extraction
   trailer as invocation 2 of the same attempt, provider, and role. It
   transcribes the accepted report into the same wire contract and enters the
   identical validation and evidence path. Repair and extraction compete for
   that single second invocation, so a role path is never widened. The trailer
   is isolated from wave verdict reduction only for bounded failures: an
   ordinary provider or transcription failure fails the trailer alone, leaves
   the accepted report untouched, and cannot stop a peer role. A protected
   failure keeps its canonical precedence and reduces normally, because
   security, configuration, artifact, cancellation, and internal failures never
   authorize publication.
10. Evidence for structured findings is checked against the captured target.
11. Publication atomically commits the manifest, role reports, and at most one
    final review, recording the transport that carried each accepted role
    report. Captured content is retained as a reference-only manifest plus
    deduplicated SHA-256 blobs for immutable child-run reconstruction.

## Attached MCP transport

`mulgae mcp [--project-root ABSOLUTE_PATH]` starts one process-scoped stdio
server. Composition resolves the selected path to a canonical anchored root
before constructing the server; the root cannot change during the process.
`internal/entrypoint/mcp` owns newline-delimited JSON-RPC. It advertises
`2026-07-28`, `2025-11-25`, and `2025-06-18` in newest-first order, negotiates
those exact versions, rejects older or session-incoherent requests with the
structured unsupported-version code, and keeps the latest protocol as its
preferred contract. The two legacy versions are a bounded compatibility floor
for current Codex and Claude Code stdio clients, not a generic compatibility
shim. Empty EOF is a normal attached-client shutdown. A nonempty record that
reaches EOF without LF termination is rejected before dispatch as malformed
transport. Cancellation uses Mulgae exit 9, malformed or failed transport uses
exit 10, and invalid command grammar uses exit 2.

Stdout is protocol-only. The MCP SDK logger is disabled and bounded public
diagnostics use stderr. The transport exposes `preflight_review`, `run_review`,
`list_runs`, `get_run`, and `list_findings`, plus bounded verified report and
finding-evidence resource templates. The MCP package owns strict tool and URI
grammar, chunk limits, and the common result envelope; composition binds those
surfaces to the same preflight, review, report, and verified publication-query
services used by the CLI. `get_run` first resolves publication and falls back to
the bounded runtime-diagnostic query only for the typed publication-not-found
case. Publication corruption, security failures, and other query failures never
enter the fallback. It does not duplicate capture, execution, query, or
publication policy. Review calls run in the foreground so request completion
replaces completion polling, while preflight, list, lookup, and resource reads
remain bounded read-only projections.

When `run_review` carries an MCP progress token, the entrypoint emits a fixed
admission message, monotonically increasing periodic heartbeats with an unknown
total, and a final completion or stopped message before returning the tool
result. Notifications are best-effort observations and never change review
state or failure precedence. The SDK maps `notifications/cancelled` for the
request directly onto the handler context; that same context reaches capture,
provider subprocesses, and terminal publication. Mulgae does not maintain a
second cancellation registry or detach review work from the requesting client.
The persistent SDK transport deliberately separates its connection context from
active handler contexts, so the entrypoint additionally joins every request to
the process-scoped `Serve` context. Client `notifications/cancelled` and process
SIGINT or SIGTERM therefore remain distinct cancellation sources that converge
on the same foreground review context.

Preflight omits the unbounded per-file inventory from its MCP result and returns
only target identity, file-set counts and byte totals, generated paths,
transmission routes, and execution budget. Committed report and evidence bytes
are re-verified for every resource read and divided into canonical byte-offset
chunks no larger than 16 KiB. UTF-8 report chunks never split a code point;
evidence uses the MCP blob form to preserve exact bytes. Full-content digest,
offset, total length, completion, and continuation URI travel as resource
metadata rather than being mixed into the content.

## Concurrency, cancellation, and storage

Application routes, budgets, runtime definitions, and process requests identify
providers directly; they contain no concurrency or scheduling key. Each run
owns a registry and one temporary namespace generation per provider instance,
so independent runs can invoke the same configured provider concurrently. A run
cannot register one provider instance twice, and
an impossible concurrent reuse of one instance within the same registry fails
immediately as an internal invariant instead of waiting. The coordinator
enforces the process-local `max_active_lanes` capacity plus per-role and per-run
invocation ceilings, and schedules a single same-provider retry or constrained
repair only after the initial wave is committed. The mutually exclusive second
slot preserves the existing two-invocation ceiling. There is no user-global capacity authority: provider-side
concurrency or rate limits remain provider outcomes, and operators choose the
number of Mulgae processes they run.

Role-path deadlines are calculated from initial-to-second-invocation dependencies and the
process capacity. Before an invocation starts, the runtime still requires
enough enclosing budget for the provider's complete configured timeout window;
removing provider locks does not weaken that check. Provider-observed timeouts
remain distinct from an enclosing deadline exhausted before provider start.

Project-local publication retains a context-aware filesystem lock because it
mutates shared durable state. It serializes publication to one project across
processes without coordinating provider execution or different project roots.
Cancellation propagates to subprocesses and terminal publication. When
cancellation is observed together with a protected artifact, security, or
internal failure, canonical failure precedence preserves the protected failure
instead of projecting the operation as cancellation.

`.mulgae/config.yaml` contains Git-shareable policy. `.mulgae/local.yaml`
contains private machine paths, while the remaining `.mulgae/` tree contains
durable review state. Temporary provider workspaces and namespaces live outside
the project and are removed after use.

Runtime assets are ordinary files under `internal/builtin/assets`, included with
`go:embed`. `CHECKSUMS.sha256` is generated from those files and validated
before the catalog serves any asset.
