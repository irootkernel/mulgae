# Mulgae architecture

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
| `internal/app/recovery` | Immutable failed-run inputs, accepted partial results, replay admission |
| `internal/app/publication` | Manifests, attempts, final artifacts, recovery, integrity |
| `internal/app/reviewcompose` | Exact composite admission, lineage and target verification, recomputation |
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
   Mulgae-owned staged file for ZCode and Grok reviews that the adapter validates
   and reads back after the process terminates, or Codex's final assistant
   message from a completed app-server turn.
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
`2026-07-28`, `2025-11-25`, and `2025-06-18` in newest-first order and keeps the
latest discovery protocol as its preferred contract. Legacy `initialize`
negotiates `2025-11-25` or `2025-06-18`; naming `2026-07-28` without discovery
falls back to `2025-11-25`. Older or session-incoherent requests fail with the
structured unsupported-version code. The two legacy versions are a bounded
compatibility floor for current Codex and Claude Code stdio clients, not a
generic compatibility shim. Empty EOF is a normal attached-client shutdown. A
nonempty record that reaches EOF without LF termination is rejected before
dispatch as malformed transport. Cancellation uses Mulgae exit 9, malformed or
failed transport uses exit 10, and invalid command grammar uses exit 2.

Stdout is protocol-only. The MCP SDK logger is disabled and bounded public
diagnostics use stderr. The transport exposes `preflight_review`, `run_review`,
`start_review`, `await_review`, `cancel_review`, `compose_review`, `list_runs`,
`get_context`, `get_run`, `inspect_review`, and `list_findings`, plus bounded
verified report, finding-detail and finding-evidence resource templates. The MCP
package owns strict tool and URI grammar, chunk limits, and the common result
envelope; composition binds those
surfaces to the same preflight, review, report, and verified publication-query
services used by the CLI. `compose_review` and CLI `compose` call the same
provider-free application mutation, so exact admission, deterministic identity,
atomic publication, and retry reconciliation cannot drift between transports.
`get_run` first resolves publication and uses the bounded runtime-diagnostic
query as a fallback only for the typed publication-not-found case. For a
resolved non-committed publication state, it also reads the session-bound
diagnostic status to merge a safe diagnostic summary. Publication corruption,
security failures, and other publication-query failures never enter the
fallback. Diagnostic corruption and other non-not-found diagnostic failures
remain fail-closed. It does not duplicate capture, execution, query, or
publication policy. `run_review` remains a request-owned foreground
compatibility path. The
process-local invocation registry separately gives each `start_review` identity
one server-owned execution and an event-driven completion channel.
`await_review` observes that channel under its request context without owning the
execution context; repeated waits clone the same cached terminal result.
`cancel_review` is the only client tool that cancels a registry-owned execution.
The registry retains at most 64 identities, may discard oldest terminal
identities to admit a new start, admits no new work after shutdown,
cancels and drains active reviews within one minute, and is discarded without
recovery when the MCP process exits. Preflight, list, lookup, and resource reads
remain bounded read-only projections.

When `run_review` carries an MCP progress token, the entrypoint emits a fixed
admission message, monotonically increasing periodic heartbeats with an unknown
total, and a final completion or stopped message before returning the tool
result. Notifications are best-effort observations and never change review
state or failure precedence. The SDK maps `notifications/cancelled` for a
foreground `run_review` directly onto the handler context, which reaches
capture, provider subprocesses, and terminal publication. Cancellation or
timeout of `await_review` releases only that observer; explicit `cancel_review`
reaches the server-owned execution and its provider processes exactly once. The
persistent SDK transport separates its connection context from active handler
contexts, so the entrypoint joins foreground handlers and registry executions
to the process-scoped `Serve` context. SIGINT, SIGTERM, or transport shutdown
therefore cancels and drains provider and publication work instead of leaving a
late child execution.

Preflight omits the unbounded per-file inventory from its MCP result and returns
only target identity, file-set counts and byte totals, generated paths,
transmission routes, and execution budget. Committed report and evidence bytes
are re-verified for every resource read and divided into canonical byte-offset
chunks no larger than 16 KiB. UTF-8 report chunks never split a code point;
text evidence uses UTF-8 and binary content uses the MCP blob form. Full-content digest,
offset, total length, completion, and continuation URI travel as resource
metadata rather than being mixed into the content.

Query owns the observation for report and indexed-evidence reads. It supplies
a snapshot-bound reader to the existing report renderer, then reobserves P2
before returning a content chunk. Original role reports and every excerpt are
verified against that same support index. CLI adapters and MCP backends share
these reads, including receipt and complete-byte digest checks. Legacy MCP
URI mode preserves its prior continuation boundaries; it cannot silently
switch to the new receipt-bound mode. Report-to-file remains a separate writer.

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
the project and are removed after use. Grok model and reasoning-effort policy
belongs only to the shared file; its executable belongs only to the local file.
For a new project, init writes `grok-4.7` and `high` unless explicitly
overridden. It never re-derives an existing shared policy, so an omitted field in
an existing Config v4 file retains provider-default behavior.
Production composition resolves the shared values once into the Grok runtime
template used by review, retry, repair, extraction, qualification, and
heartbeat paths.

Runtime assets are ordinary files under `internal/builtin/assets`, included with
`go:embed`. `CHECKSUMS.sha256` is generated from those files and validated
before the catalog serves any asset.

## Planned extension ownership

The [accepted two-Epic design](../architecture-decision-records/verified-review-iteration.md)
and [roadmap](../roadmap/README.md#adopted-execution-order) adopt the following
changes. They are future structure, not additional current runtime components.

```text
EPIC-007: independent project identity
            -> native preflight/execution guard
            -> existing immutable capture and provider execution
            -> verified publication receipt
            -> coherent CLI/MCP inspection and content reads

EPIC-008: captured Review Brief
            -> assigned requirements assessment
            -> immutable review result
            -> one selected-finding batch against one new target
            -> provider-free comparison of exact results
```

| Concern | Application and boundary ownership |
|---|---|
| Local project identity | Domain/app typed binding and inward port; descriptor/Git observation in filesystem/workspace adapters; transport never decides root equality |
| Complete capture identity | `app/capture` owns canonical target/sides/file-set/context identity, distinct from patch and request digests; `reviewrun` owns request admission, `publication` retains verification support, and `query` verifies it |
| Native guard | `reviewrun` capture/planning admission before qualification; request identity includes the complete capture and request-only policy, objective, and route dimensions |
| Verified reads | `query` owns coherent publication receipt and provenance; `report` renders admitted content; CLI/MCP only parse and project bounded pages |
| Composite evidence | `reviewcompose` selects exact sources; `publication` owns copied support and atomic commit; query does not chase live source runs |
| Brief capture and framing | Existing review input/archive and prompt owners; project-authored requirements stay untrusted data |
| Assessment | `validation` checks assigned IDs and captured support; `publication` retains normal assessments or provider-free no-change unverified records; `query`/`report` expose evaluation state separately from findings |
| Batch followup | A focused source/selection use case reuses `followup`/`childrun` and the existing coordinator/lane budget; one captured target and one immutable run |
| Comparison | A provider-free application query revalidates before/after and every selected followup receipt on each page, checks complete capture equality for resolution transfer, and reduces conflicts without choosing a winner |

Reuse existing typed values and ports where their meaning matches. Introduce a
small use-case owner only when a new responsibility requires one; do not build a
generic execution framework, parallel storage authority, or infrastructure
abstraction merely to accommodate these features. Architecture tests must keep
CLI/MCP, provider process, filesystem, and domain dependency boundaries intact.

EPIC-007 must close independently with current objective/context input. EPIC-008
extends its request identity for Briefs and batch selections after acceptance.
The existing invocation registry remains the lifecycle owner; a batch start
reuses await/cancel without adding durable job recovery or a second scheduler.

Brief-aware empty Git diffs remain on the existing provider-free no-change
branch, after input and guard validation. `publication` must retain the Brief
and selected unverified requirements without attempts or role reports; preflight
and reads expose evaluation not run. A workspace assessment requires an explicit
new request, not an alternate provider path hidden inside completion mode.

Before/after comparison does not require equal captures. Transferring a followup
resolution does require equal complete evaluated-current and after captures,
not equal request digests. Comparison continuations bind the complete selected
receipt vector, including followups unrelated to the current page. An unreadable
selected publication fails that page; conflicting intact assessments produce
unverified with stable reasons and preserved evidence. These policies belong in
the application use case, not separate CLI/MCP reducers.


### Project-context ownership

`query.ProjectContextService` serves CLI `context` and MCP `get_context` through
`ports.ProjectBindingObserver`. The Git adapter opens descriptors for the root,
worktree Git directory, and common Git directory without invoking Git. The
adapter derives canonical filesystem path spelling from each descriptor with
Darwin `F_GETPATH`, so case aliases resolve to the same identity. The
application hashes the versioned observation; transports expose only that digest
and implemented capability versions. MCP retains the startup lease until
shutdown. Revalidation compares the held descriptors and freshly resolved
anchors, including device, inode, and birth time, while ordinary file changes
do not change the binding. Directory and metadata admission rejects symlinks in
Git metadata, unsafe ownership or writable anchors, and malformed pointers.

Receipt-bound inspection belongs to `internal/app/query`. It verifies a single
publication observation, complete retained capture support and ordered finding
pages. CLI and MCP supply a revalidated project lease and project binding. They
project that result without independently reopening final files or combining
status and finding reads. Finding-detail chunks share query-owned digest and
continuation policy; the MCP resource layer only maps content and continuation
URIs to the protocol envelope.
