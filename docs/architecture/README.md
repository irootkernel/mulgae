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
| `internal/app/reviewrun` | Live source admission, planning, qualification, prompts, orchestration |
| `internal/app/review` | Assignments, coordination, aggregation, results |
| `internal/app/validation` | Wire parsing, trusted-field injection, checks, repair |
| `internal/app/recovery` | Historical failed-run support validation and inspection |
| `internal/app/publication` | Manifests, attempts, final artifacts, recovery, integrity |
| `internal/app/compositesupport` | Portable copied source receipts, findings, evidence and per-role capture verification |
| `internal/app/{query,report,clean,export}` | Inspection and artifact lifecycle |
| `internal/domain` | IDs, findings, failures, states, roles, immutable values |
| `internal/ports` | Interfaces and safe values crossing application boundaries |
| `internal/adapters/providercli` | Provider profiles, qualification, credentials, invocation |
| `internal/adapters/workspace` | Neutral reviewer home, qualification fixtures and descriptor-bound roots |
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

1. CLI/MCP admits one live selector against the canonical original root.
2. Configuration, source/Git locality and optional independent binding are
   checked before allocating a run or constructing provider authority.
3. The planner preserves selected roles, configured providers and bounded lanes.
4. A no-change selection closes its source and publishes zero attempts without
   provider discovery, qualification or invocation.
5. Nonempty execution retains a source lease and pinned neutral reviewer home.
   The prompt contains trusted guidance, explicit native reads and selection
   metadata, with framed untrusted context/objective and no copied source tree.
6. Qualification uses Mulgae-owned synthetic fixtures. Each invocation owns its
   isolated credentials/scratch and mandatory native source restrictions.
7. The runtime collects a complete correlated protocol assistant report.
   Optional same-provider repair or extraction shares the one second slot;
   protected failures retain precedence and deny publication.
8. Live evidence is checked against its declared source side, preserving selected
   raster bytes and verified excerpts. Workspace/index stability is the caller's
   responsibility; committed operands stay fixed.
9. Every provider drains before source closure. Failed drain retains exact cleanup
   ownership for a bounded retry and cannot create publication authority.
10. Source closure precedes atomic P0/P1/P2 publication of v3 results and support.
    Query verifies retained evidence without reading today's source.

## Live reviewer execution

The public execution path separates `LiveSourceReader` from `ReviewerHome`
through `LiveReviewExecution`. The source adapter retains project and Git
directory identity; the reviewer-home adapter pins the neutral directory and
reads its safe regular guide once. `reviewrun` loads the common guidance and
`review` composes it with the unchanged role prompt and a typed native read plan.
Workspace reads use original paths; index and committed reads use fixed Git
operands and a deterministic environment.

`providercli` binds the sealed invocation to a descriptor for the neutral cwd,
retains per-invocation credential and scratch namespaces, and collects complete
correlated assistant reports. ZCode and Grok require the process adapter's
outer Seatbelt policy for both live review and extraction. It denies source,
Git and guide writes and credential reads, writes and links. It also denies
Unix socket access at all protected roots and permits writes to `/dev/null`.
Grok runs with its own sandbox off inside this mandatory guard.
ZCode also admits its existing private short socket directory by canonical
identity; protected denials override writable-root overlap. Codex retains its
native read-only profile with explicit credential-root denial. These controls
do not claim general IPC or process containment. The outer policy permits
reads outside credential roots and network access outside protected Unix socket
paths; it is not a global read or network allowlist. ZCode's native Bash tool
has no Grok-style exact-command permission gate. Live execution rejects
non-printable or invalid UTF-8 policy roots before producing Seatbelt or native
provider configuration, preventing cross-grammar escape mismatches.

Before a guarded launch, descriptor-based metadata inspection rejects regular
files with hardlink aliases in credential or writable roots. The policy also
denies links outside those writable roots. Source and Git trees retain ordinary
hardlinks. Admission observes cancellation and the request timeout; the runner
closes the consumed neutral descriptor on every return after request admission.

TASK-038 connects this path to both public transports. Full provider/client
certification remains TASK-039 work; no snapshot fallback is available.

Live evidence verification reads the declared original source side through
`LiveSourceReader`. A separate proof type binds verified excerpts and selected
raster bytes to source selection metadata. It cannot be used as a captured-target
proof. `evidence` owns the common source metadata and support checks used by
publication and query; neither application package imports the other.

`publication` writes live v3 roots through the existing P0/P1/P2 engine. It
retains selection metadata, required excerpts, normalized findings, complete role
reports, and selected PNG/JPEG/WebP bytes. Source closure is recorded separately
from snapshot and workspace provenance. `query` verifies these stored members
before inspection or content reads and never falls back to original files.
Receipt v2 and export v2 name source selection explicitly. Historical captured
readers keep their existing versions and meaning. Source replay is
explicitly unavailable, including after successful publication recovery.

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
`start_review`, `await_review`, `cancel_review`, `list_runs`,
`get_context`, `get_run`, `inspect_review`, and `list_findings`, plus bounded
verified report, finding-detail, finding-evidence and source-image templates. The MCP
package owns strict tool and URI grammar, chunk limits, and the common result
envelope; composition binds those
surfaces to the same preflight, review, report, and verified publication-query
services used by the CLI. Retired child and composition mutations have no
current public or creation path. Historical query and provider-free publication
reconciliation retain their existing ownership.
`get_run` first resolves publication and uses the bounded runtime-diagnostic
query as a fallback only for the typed publication-not-found case. For a
resolved non-committed publication state, it also reads the session-bound
diagnostic status to merge a safe diagnostic summary. Publication corruption,
security failures, and other publication-query failures never enter the
fallback. Diagnostic corruption and other non-not-found diagnostic failures
remain fail-closed. It does not duplicate source admission, execution, query, or
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
source admission, provider subprocesses, and terminal publication. Cancellation or
timeout of `await_review` releases only that observer; explicit `cancel_review`
reaches the server-owned execution and its provider processes exactly once. The
persistent SDK transport separates its connection context from active handler
contexts, so the entrypoint joins foreground handlers and registry executions
to the process-scoped `Serve` context. SIGINT, SIGTERM, or transport shutdown
therefore cancels and drains provider and publication work instead of leaving a
late child execution.

Preflight v8 returns source selection identity, candidate counts, transmission
routes, warnings and execution budget. MCP omits the native read plan. Preflight
does not reserve state or supply a content fingerprint; execution separately
compares the independently observed project binding before qualification. Committed report and evidence bytes
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
durable review state. Synthetic qualification workspaces and provider namespaces live outside the
project and are removed after use. Live review reads original source from the
neutral reviewer home. Grok model and reasoning-effort policy
belongs only to the shared file; its executable belongs only to the local file.
For a new project, init writes `grok-4.7` and `high` unless explicitly
overridden. It never re-derives an existing shared policy, so an omitted field in
an existing Config v5 file retains provider-default behavior.
Production composition resolves the shared values once into the Grok runtime
template used by review, retry, repair, extraction, qualification, and
heartbeat paths.

Runtime assets are ordinary files under `internal/builtin/assets`, included with
`go:embed`. `CHECKSUMS.sha256` is generated from those files and validated
before the catalog serves any asset.

## Composite support ownership

Composite creation and child/replay execution owners are retired. Historical
`compositesupport`, capture archive decoders, recovery readers and publication
reconciliation retain their existing integrity responsibilities. They verify
stored source receipts, findings, evidence, provider provenance and captures.

Committed composite reads verify these local copies. They require no source-run
lookup, and expose a common capture only when every selected role has the same
verified capture identity. Recovery sources retain their recovery-manifest identity without claiming
P2 publication. Existing cleanup retention and export allowlists remain separate
application policies; copied private content does not enter exports implicitly.

## Planned extension ownership

EPIC-008 is held for redesign after EPIC-009. Its old capture/batch ownership
map below records the earlier design, not current executable packages or APIs.

The [accepted two-Epic design](../architecture-decision-records/verified-review-iteration.md)
and [roadmap](../roadmap/README.md#adopted-execution-order) adopt the following
ownership boundaries. The EPIC-007 identity, admission, verified-read and
composite-support owners are implemented; EPIC-008 remains planned.

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
| Composite evidence | `reviewcompose` selects exact sources; `compositesupport` builds and verifies portable copies; `publication` commits them atomically; `query` reads the copies without chasing source runs |
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
