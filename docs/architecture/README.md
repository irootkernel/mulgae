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
internal/app/*, internal/ports, internal/adapters/* -> internal/artifactwire
internal/app/{query,report}, internal/adapters/* -> internal/strictjson
```

The domain and application packages do not depend on CLI parsing, provider
process details, or concrete storage. Adapters implement ports;
`internal/composition` wires concrete implementations into the application,
and the root `main.go` delegates process execution to that package. Architecture
tests enforce this direction and keep every other Go file out of the repository
root.

`internal/artifactwire` owns matching primitive persisted DTOs for runtime
support, publication restart/journal/status, epochs, lineage and corruption
diagnostics, plus shared ordinary and composite components. It also owns their
format/schema identifiers and pure path spelling and lexical helpers. Its
production import allowlist is `fmt` and `strings`.
`TestWireLeafDependencyDirection` checks every production source file, including
inactive build tags. Domain packages retain their existing prohibition on
repository imports.

Publication keeps serializers, field presence, version selection and custom
composite marshal-selection behavior. Query and report keep destination DTOs, caller wrappers and
semantic verification. Ports keep domain ID/role admission, artifact-kind
policy, scope checks, `SafeRelativePath` construction and error ordering;
filesystem adapters keep storage, locking and durability checks. Path helpers
only concatenate or format strings, without cleaning or validating them.
Positive padded ordinals remain distinct from excerpt digits, which accept zero
and leading zeroes.

Distinct final/manifest containers, optionality, canonical encodings and digest
domains remain with their current owners. Archive codecs, failed recovery and
copied composite support retain their validation and digest rules while using
the shared identifiers and spellings. The filesystem's named artifact wrapper
and ports' named corruption wrapper retain their decoder type names. DTOs and
path strings confer no validated identity, replay or publication authority.

`internal/strictjson.DecodeObject` owns only the identical query/report
strict-object mechanics. It checks raw UTF-8, rejects empty or non-object roots,
scans decoded keys recursively for duplicates with `UseNumber`, checks trailing
data, then decodes into the caller's destination with `DisallowUnknownFields`
and checks EOF again. Destination types still determine numeric and field-type
acceptance. Escaped surrogate handling retains `encoding/json` behavior.

Its production import allowlist is `bytes`, `encoding/json`, `fmt`, `io` and
`unicode/utf8`; the leaf-import guard requires both leaf packages to exist and
checks tagged files too. Query/report keep their local wrapper functions and
errors. Provider review/followup, schema-adapter, filesystem, MCP, capability,
corruption, archive, diagnostic/cleanup and protocol-line parsers retain
their separate implementations and acceptance rules.

### Ownership guards

The ownership checks parse non-test Go files, including inactive and
ignore-tagged files, outside `.git` and `vendor`. They enforce exact import
namespaces and their descendants:

- Application packages cannot import adapters, `internal/builtin`, entrypoints
  or composition.
- Ports cannot import application packages, adapters, entrypoints or composition.
- Application and domain packages cannot import `os/user`.
- Production files cannot import `internal/testsupport` or
  `internal/adapters/fakeprovider`.

The CLI package must declare exactly one `ReviewRequest`, as a direct alias
of `internal/app/reviewrun.Request`. MCP entrypoint packages cannot import the
CLI namespace. In `internal/composition/mcp_backend.go`, the route guard rejects
CLI `Parse` and `ParseResolved` references, `Application.Run` method expressions,
and direct `Run` calls or method values through identified backend Application
fields. Protected CLI dot imports are rejected.

Backend and field value matching follows parentheses, dereference and
address-of wrappers (`ParenExpr`, `StarExpr` and `UnaryExpr` with `token.AND`),
including mixed nesting, while retaining lexical declaration identity.
Import-qualifier and type matching remain separate. Unrelated local and
parameter objects retain separate identity.
Calls, indexing, type assertions, receives and other operators stop the value
walk. Assignment aliases, interface flow and call graphs remain outside this
syntax check and require typed-pipeline tests and review.

The general dependency check retains its existing build-ignore policy.
Test-only fake-provider consumers and legitimate CLI dispatch elsewhere in
composition remain supported. These guards preserve existing product contracts.

## Package map

| Area | Responsibility |
|---|---|
| `main.go` | Darwin/arm64 process shim and release linker variables |
| `internal/composition` | Executable bootstrap, build identity, and production graph |
| `internal/entrypoint/mulgae` | CLI grammar, dispatch, output, selector resolution |
| `internal/entrypoint/mcp` | Attached stdio MCP grammar, protocol admission, and tool projection |
| `internal/app/runstatus` | Publication-first status acquisition, missing-only fallback, session-bound diagnostic merging |
| `internal/app` | Shared operational error-tree selection and canonical precedence |
| `internal/app/reviewrun` | Typed review requests, role/artist selection, live source admission, planning, qualification, prompts, orchestration |
| `internal/app/review` | Assignments, coordination, aggregation, results |
| `internal/app/validation` | Wire parsing, trusted-field injection, checks, repair |
| `internal/app/recovery` | Historical failed-run support validation and inspection |
| `internal/app/publication` | Manifests, attempts, final artifacts, recovery, integrity |
| `internal/app/compositesupport` | Portable copied source receipts, findings, evidence and per-role capture verification |
| `internal/app/{query,report,clean,export}` | Inspection and artifact lifecycle |
| `internal/domain` | IDs, findings, failures, states, roles, immutable values |
| `internal/ports` | Interfaces and safe values crossing application boundaries |
| `internal/artifactwire` | Shared persisted DTOs, format/schema identifiers, path spelling and lexical helpers |
| `internal/strictjson` | Shared strict-object mechanics for query/report, without destination or semantic policy |
| `internal/adapters/providercli` | Provider profiles, qualification, credentials, invocation, neutral reviewer home |
| `internal/adapters/process` | Bounded Darwin process runner, Seatbelt launch boundaries, and `__mulgae_paneexec_v1` trampoline |
| `internal/adapters/herdr` | Isolated per-run `herdr-core` terminal runtime lifecycle, RPC client, watchdog, and `TerminalSessionRunner` |
| `internal/adapters/workspace` | Qualification fixtures and descriptor-bound roots |
| `internal/adapters/filesystem` | Secure project-local storage and publication |
| `internal/adapters/jsonschema` | Offline Draft 2020-12 validation |
| `internal/builtin` | Embedded schemas, prompts, examples, and help |
| `assets` | Repository-root human-authored role document, embedded into the binary |
| `internal/roles` | Role document schema, parsing, and whole-catalog validation |
| `internal/app/roleassets` | Single application-layer reader of the role document |
| `skills` | Optional, source-distributed AI-agent operating guidance; not a runtime authority or embedded binary asset |
| `test/e2e` | Black-box binary integration, artist fixture, and live-provider E2E tests |

### Internal file responsibilities

These files keep responsibilities within their existing packages. Public APIs
and runtime behavior are unchanged.

| Package | File responsibility |
|---|---|
| `internal/app/query` | [excerpt.go](../../internal/app/query/excerpt.go) contains committed finding excerpt reads, rendering and persisted-source access. Service orchestration and schema initializers remain in `service.go`. |
| `internal/adapters/filesystem` | [publication_documents_darwin.go](../../internal/adapters/filesystem/publication_documents_darwin.go) contains publication document types and interpretation, retaining the filesystem's distinct JSON mechanics and Darwin/arm64 activation. Storage, locking and durability operations remain in `publicationstore_darwin.go`. |
| `internal/entrypoint/mulgae` | [doctor_handlers.go](../../internal/entrypoint/mulgae/doctor_handlers.go) contains doctor projection, local-service wiring and human formatting. Shared constants, provider handlers and dispatch remain in `handlers.go`. |

The [relocation checks](../implementation-tips/README.md#ownership-guard-and-relocation-checks)
describe verification for these file boundaries.

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

## Review request ownership

`internal/app/reviewrun.Request` owns the immutable review fields consumed by
normal execution and preflight. Transports construct it from typed selectors,
session IDs and project bindings through `NewRequest`; the constructor copies
role and artist input slices and allocates no run or provider resources.
`ResolveRequest` returns an `AdmittedRequest` after selecting enabled project
roles and resolving artist defaults and request overrides. It retains whether
the caller selected roles explicitly, including automatic artist intent after
repeated resolution. This selection grants no source or execution authority.

CLI parsing retains its flag grammar, validation order, 12000-byte objective
bound and request JSON projection. Its `ReviewRequest` is an alias of the
application value; the temporary syntax draft exists only while parsing flags.
MCP validates its public JSON grammar and 4096-byte objective bound, then maps
fields directly through `mcpentry.NewReviewRequest`. Composition passes that
request to the existing execution or preflight bridge without constructing argv
or parsing a CLI invocation.

MCP preserves empty objective and empty role-list normalization, canonical role
ordering, and rejection of control characters and objectives beginning with
`--`. Public guard validation still precedes backend mapping; mapping checks
identity, objective syntax, roles and binding in their existing order. Direct
backend callers retain the former mapping's 12000-byte objective guard and CSV
role normalization; the public tool handler remains bounded at 4096 bytes.
Transport envelopes, startup-lease revalidation and deferred preparation stay
with their existing owners. Source admission, provider construction and
publication still require the later live execution checks.

## Configuration admission ownership

`internal/app/config` owns the shared source, attestor, source confirmation
sequence and native-account and native-home authority comparisons. Each caller
keeps its dependency checks, original error causes, failure mapping and
confirmation positions. The shared function performs no observation beyond
those three confirmations and does not cache their results.

The application-owned account observer returns lookup availability, home, raw
UID, effective UID and lookup error. `internal/adapters/environment` performs
the OS lookup and retains the build-bound native-home override. Config sources,
split sources, codecs, locality attestors, environment inspectors, clocks and
version observers retain their existing interfaces. The config adapter selects
the filesystem locality fallback from the existing `.git` observation;
composition injects that selection capability at the caller's former position.
No admission policy is added to ports.

Composition supplies source factories, codecs, account observers, locality
selection and the init service constructor. Init keeps destination collision
checks before account observation, both native-home observations around service
construction, repeated application admission, renderer prevalidation and receipt
checks. Config keeps resolution before account comparison. Normal review checks
the account before configuration, while preflight continues to resolve policy
without that account check. Target and spawn confirmations use the shared
sequence at their existing positions.

`doctor.LocalService` owns local v9 diagnosis and readiness reductions through
injected source, codec, account, locality, inspector, version and clock
capabilities. Composition supplies the service constructor and build platform
metadata without another platform observation. CLI doctor and providers call
this same service; envelopes, schema validation and human formatting remain in
the CLI. Recorded-evidence diagnosis remains with `doctor.Service`.

A final native-home mismatch clears configured IDs, provider inventory and
assignment observations before the existing model validation. It preserves
earlier permitted discovery/version effects and returns unsafe readiness with
exit 8. Providers can then perform its independent recorded-evidence reads.
The source and native-home confirmation positions are unchanged.

## Run status and failure selection

`internal/app/runstatus` owns publication-first acquisition through a two-method
publication query and the bounded diagnostic query port. It checks the resolved
artifact root and run identity, falls back only for a complete missing-only
cause tree, and merges diagnostic summaries through the resolved session/run
lookup for noncommitted publication status. Committed status never consults
diagnostics. Its result distinguishes publication, diagnostic-only and
unavailable status, retaining the original error and acquisition phase for the
transport's existing failure projection. `RunStatusView` at the CLI boundary is
an alias of the application-owned safe publication view.

A missing-only tree may contain ordinary or typed single-error wrappers,
single-child joins and joins made entirely of missing causes. An independent
artifact, security, internal, raw or cancellation sibling prevents fallback or
missing-diagnostic suppression. CLI status and MCP get_run use this same policy.
MCP's receipt-bound inspect path also uses the shared predicate while retaining
its own coherent-read and binding revalidation sequence.

CLI and MCP keep their envelopes, messages, permitted exits, retryability and
field-presence rules. CLI diagnostic-only status accepts pending and running
states as well as terminal failure states. MCP admits only completed failed or
cancelled diagnostic-only records and exposes no publication authority for
them. The CLI omits session identity from ordinary publication status; MCP
retains session identity and its nullable status fields. MCP also preserves a
sole diagnostic cancellation without adding an artifact wrapper.

`internal/app.SelectFailure` owns depth-first error-tree class selection, with
parents before causes and joined children in their original order. Equal ranks
retain the first observed cause. CLI mode applies the caller's fallback to raw
observations, suppressing it under typed single-cause wrappers but restarting
it for each independent joined child. MCP mode ignores raw leaves. Both modes
recognize cancellation/deadline leaves and preserve original cause identity.
The canonical ranks remain in `FailurePrecedence`; transport-specific guard,
read/source, preparation, publication and invocation lifecycle recognition and
public error rendering remain with their existing owners.

## Review flow

The configured provider inventory is ZCode and Grok. Composition preserves
undrained namespace children before closing reviewer-home or workspace ownership.

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
7. The runtime collects a complete correlated protocol assistant report for
   protocol providers or a post-`ESRCH` validated staged output (projected under
   `result_transport: "stdout"`) for managed terminal providers. Optional
   same-provider repair or extraction shares the one second slot; protected
   failures retain precedence and deny publication.
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

Within `providercli`, `protocol_mechanics.go` owns diagnostic-ID sanitization
and string-response matching for ZCode. Family adapters retain request prefixes,
outstanding state, wire parsing and the consequences of an invalid authoritative
identifier. Cancellation, EOF and process-exit rules remain local, including
ZCode's accepted post-turn stream end.

`terminal_provider.go` owns the reusable provider-agnostic managed terminal
execution driver over `ports.TerminalSessionRunner` (supporting both OSC 7501
and non-OSC terminal profiles, single- or multi-home disposable profiles,
read-only `<scratch>/input/<id>/prompt.md` staging protected via `ReadOnlyRoots`,
per-invocation end-of-prompt completion nonces, parameterized post-`ESRCH`
`stagedOutputLease` validation with `B-1` stability/survivor controls,
`StartupTimeout` carving, launch-boundary `ExitedBeforeReport` classification,
and structured core-state precedence). `grok_terminal.go` implements Grok's
`1.0.89` terminal profile (`PaneTTY`-only, minimal disposable `requirements.toml`
in disposable `GROK_HOME`, projected `0600` `.grok/auth.json`, purpose-scoped
`--tools`, and `B-1` Bash gate for index/commit reviews only). `internal/adapters/herdr`
manages the lazily started per-run isolated `herdr-core` daemon, parent-death
watchdog, and JSON-RPC lifecycle; `productionRuntimeGraph` is the sole owner of
`terminalSession.Close()` (invoked first in `cleanupRoots()` and explicitly on
the retained-cleanup error branch of `StartReviewRun`), while `Registry` and
`CurrentProbe` borrow the session runner and `Registry.Close` drains only its
own labeled panes. ZCode never starts `herdr-core`.

`providercli` binds the sealed invocation to a descriptor for the neutral cwd,
retains per-invocation credential and scratch namespaces, and collects complete
correlated assistant reports for protocol providers or post-`ESRCH` validated
staged reports (published as `result_transport: "stdout"`) for terminal-runtime
providers. ZCode and Grok require the process adapter's outer Seatbelt policy
for both live review and extraction, and both providers deny shared `herdr-core`
control-plane roots and sockets. Seatbelt denies source,
Git and guide writes and credential reads, writes and links. It also denies
Unix socket access at all protected roots and permits writes to `/dev/null`.
Native tool path admission runs body-free through the source port: the source
reader checks the path, protected roots, namespace, file kind and namespace
identity through descriptors and inventories, while evidence reads keep their
byte and stability verification. Admission therefore validates no content: a
raster-extension file whose bytes fail the signature is admitted for a
provider tool, but still fails closed with `unsupported_content` whenever it
is claimed as evidence.
ZCode also admits its existing private short socket directory by canonical
identity; protected denials override writable-root overlap. These controls
do not claim general IPC or process containment. The outer policy permits
reads outside credential roots and network access outside protected Unix socket
paths; it is not a global read or network allowlist. Live execution rejects
non-printable or invalid UTF-8 policy roots before producing Seatbelt or native
provider configuration, preventing cross-grammar escape mismatches.

Before a guarded launch, descriptor-based metadata inspection rejects regular
files with hardlink aliases in credential or writable roots. The policy also
denies links outside those writable roots. Source and Git trees retain ordinary
hardlinks. Admission observes cancellation and the request timeout; the runner
closes the consumed neutral descriptor on every return after request admission.

Guarded launches pass through a trusted child before starting `sandbox-exec`.
The child marks all inherited descriptors above stderr close-on-exec, including
the pinned directory handle. The parent duplicates that handle atomically with
close-on-exec; its existing descriptors and flags remain unchanged. This barrier
also applies to guarded requests without a pinned directory. A child-side launch
failure remains an ordinary failed invocation under the existing retry policy.

Conversation drivers may half-close stdin with `ProviderSessionExchange.CloseInput`
and continue receiving through stdout EOF. A driver that needs the provider's
natural shutdown must drain that stream before returning; returning starts the
existing bounded teardown. Half-close is idempotent and preserves stdin receipts.
Conversation and bounded post-output teardown disable their caller-cancellation
and request-timeout channel arms after the first observation, so cancellation
and timeout are consumed once while driver and process-group drain complete,
and conversation stdout line assembly scans each incoming chunk once from a
monotone frontier while spooling raw capture bytes unchanged.

CLI and MCP share this execution path. Provider, client, and integrated-gate
verification follows the [implementation guidance](../implementation-tips/README.md#verification-for-the-adopted-review-epics);
no snapshot fallback is available.

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
Publication epoch allocation streams `.mulgae/store/epochs/` in bounded batches
without a 4096-entry directory ceiling while validating every member's naming,
ownership, mode, and symlink safety, and composition enforces equality between
the JSON Schema validator's `MaxInputBytes` and
`PublicationStructuredMemberMaxBytes`. Receipt v2 and export v2 name source
selection explicitly. Historical captured
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
verified report, finding-detail, finding-evidence, source-image and
requirement-content templates. The MCP
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

Preflight v9 returns source selection identity, candidate counts, transmission
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
invocation ceilings through a single-goroutine batched FIFO event loop: after
`PrepareInitial` freezes all initial inputs, initial role invocations pass an
initial shared start gate before any worker starts; completed results are
drained in non-blocking ready batches and committed in canonical fixed role
order; generated same-provider follow-ups (retry, constrained repair, or
optional structured extraction in the mutually exclusive second invocation slot)
are admitted immediately in FIFO order with `InvocationDispatched` recorded
before each follow-up start gate opens, without waiting for slower peer roles to
finish `001-initial`; any run-stopping condition or context/deadline stop drains
every remaining in-flight invocation before committing terminal state or
authorizing worker shutdown; and per-role trace projections remain deterministic
alongside strictly deterministic `RoleSummaries`, `Findings`, `Outcomes`, and
`RunState`. The mutually exclusive second slot preserves the existing
two-invocation ceiling. There is no user-global capacity authority: provider-side
concurrency or rate limits remain provider outcomes, and operators choose the
number of Mulgae processes they run.

Provider qualification groups equivalent shareable runtime profiles—including
same-profile ZCode and Grok role routes, whose sibling direct-execution
authorities are minted by the adapter through
`DeriveEquivalentRouteDirectExecutionAuthority` while retaining independent
per-instance namespaces—and keeps distinct-profile routes in separate groups. Qualification runs in original-order batches that hold at most
one group per family, so only distinct families overlap and same-family groups
wait for a later batch. The batch runner merges route, evidence, failure and
observation contributions in original group order through the first failed
group, while cleanup ownership merges from every started group, including
groups after that failure. A panic inside group admission becomes a
payload-free typed internal failure, and the group's recorded acquisitions
stay owned for cleanup. Qualification probes are not counted against the
process-wide `max_active_lanes` capacity, which bounds review invocations;
the coordinator's initial shared start gate and that capacity are unchanged.

Role-path deadlines are calculated from initial-to-second-invocation dependencies and the
process capacity. Before an invocation starts, the runtime still requires
enough enclosing budget for the provider's complete configured timeout window;
removing provider locks does not weaken that check. Provider-observed timeouts
remain distinct from an enclosing deadline exhausted before provider start, and
both timeout conditions project `AttemptTimedOut` paired with `FailureTimeout`
so published run manifests preserve the `AttemptTimedOut == (FailureClass == FailureTimeout)`
invariant. When an enclosing run deadline expires while a role with an already
accepted output is awaiting or executing optional structured extraction, the
coordinator terminates only the extraction invocation and completes the role as
`AttemptSucceeded` / `RoleTaskSucceeded` with its accepted report intact. A run
stopped by the enclosing run deadline projects `RunCompleted` when every role
ended `RoleTaskSucceeded` and `RunFailed` when any role failed; higher-precedence
non-timeout stops never project `AttemptTimedOut` even if the run deadline
expires concurrently.

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

The retired creation paths have been removed: the `reviewrun` capture facade,
the sequential `review.Service` and its result snapshots, prompt replay issuance,
historical captured, child and artist publication construction, followup
preparation, composite candidate construction, their publication wrappers, and
the v1 fixture encoder.
`capture` owns the manifest contract and its tests. `review` retains assignments,
templates, the coordinator, provider runtime, evidence and shared identity helpers.

Ordinary `prompt.Compiler.Compile` still reserves source/execution identities and
wire bindings. Historical replay values, parsing and validation remain readable.
`ports` retains the v1 decoder and the dynamic v2 archive serializer used by query
reconstruction. `compositesupport` retains capture encoding and verification.
Publication keeps its shared live Build/validation, private durable engine,
canonical composite recovery encoding and historical format discrimination.
It refuses absent live authority before emitting a new bundle, after the existing
Build input checks. Historical DTO fields and absent-marker hash contributions
remain part of their retained contracts.

Historical `compositesupport`, capture archive decoders, recovery readers and
publication reconciliation retain their existing integrity responsibilities. They verify
stored source receipts, findings, evidence, provider provenance and captures.

Committed composite reads verify these local copies. They require no source-run
lookup, and expose a common capture only when every selected role has the same
verified capture identity. Recovery sources retain their recovery-manifest identity without claiming
P2 publication. Existing cleanup retention and export allowlists remain separate
application policies; copied private content does not enter exports implicitly.

## Immutable value lifetime and proof ownership

Verified operation reuse keeps verification at the real input, filesystem,
process and provider boundaries. A value proven inside one verified operation
is reused only within the lifetime that proved it: one in-memory value
(provider packets and immutable publication artifacts), one publication
invocation (a live candidate's review-independent support), one public query
call (its read context), or one live Git source reader (fixed commit-side
inventories and, for each execution Git configuration file, the digest of the
last successfully parsed bytes). A new request, including an MCP continuation
chunk, verifies afresh. There is no process-wide cache, stat-only security
shortcut, source snapshot or new provider-content byte ceiling, and
deterministic call and traversal counts, never timing, prove the reuse.

Provider packets and immutable publication artifacts (`ImmutablePublicationArtifact`
and `FinalReviewArtifact` in `internal/ports`) verify their exact-byte digest once,
over exactly the bytes they retain, in their validating constructors. The
unexported proof bit that records this is a lifetime fact about one in-memory
value whose representation cannot change after construction: private storage,
defensive copies at mutable byte boundaries, and no in-package mutation paths.
Repeated validity checks on such a value skip only the digest recomputation its
constructor already performed; every other value, including zero values and
in-package literals, keeps the full exact-byte verification. The proof never
extends to process-success classification: `ProcessObservation`,
`ProviderExecutionObservation`, and every receipt or termination fact keep their
complete validation, and observation getters return deep copies that own their
packet, stdout, and stderr bytes. The proof never replaces disk, provider, or
transport re-verification: stdin write receipts, staged-output receipts, prompt
files, and publication store read-backs hash the actual bytes they observe.

Exact equality (`Equal`) and length (`ByteLength`) accessors compare or measure
private storage without copying content; they are byte-exact comparisons, not
validity checks. `internal/ports` and `internal/app/publication` each carry a
disabled-by-default counting seam used only by in-package tests to count digest,
defensive-copy, and support-construction helper calls deterministically; each
instrumented helper pays one disabled atomic load per call, production never
enables it, and its counts are never treated as evidence about external state.

A live publication (`PreparedLiveCandidate`, including the provider-free
no-change form) binds its candidate twice inside one `publishCandidate`
invocation: once to the fixed preflight review ID, so schema and size
rejection stay ahead of review-ID issuance, and once to the issued ID. The
support members whose paths and bytes do not depend on the review ID (evidence
excerpts, attempt artifacts, runtime artifacts, role reports, and live source
support) are constructed and digested by the first binding, in the historical
builder's member order, and reused at the same positions by the issued binding,
which rebuilds only the review-ID-bound members: normalized findings, support
index, lineage edge, final review, staged copy, manifest, epoch record, journal,
and status. The manifest reuses the constructed role-report identities instead
of digesting the markdown again. Each binding still runs the complete build
prologue, schema-validates the final review and manifest, and validates the
assembled bundle. The reuse lifetime is one publication invocation: the shares
are never cached across invocations or processes, and a resumed or recovered
live publication constructs fresh. The retained `Build` requires live source
authority after its existing context, validator, candidate, review-ID, time and
epoch checks. Historical readers and recovery retain their verification and
encoding responsibilities. Durable persistence, read-back, and sync behavior
are unchanged.

Verified reads own a query-local, per-call read context
(`internal/app/query`). Each public entry point — inspection, status, finding
detail, report and evidence content, excerpt rendering, and the legacy report
render through `WithVerifiedSnapshot` — owns exactly one context and discards
it on return; "at most once" below holds within that context. Some entry
points delegate to other public entry points (`Inspect`'s diagnostic branch
calls `ReadRunStatus`, `ReadRunStatus` on a not-published run calls
`ReadFailedRunRecovery`, exact-replay recovery verification calls
`ReadCommittedAttempt`, and `ResolveCommittedAttempt` calls `ReadCommitted`
then `ReadCommittedAttempt`); each nested public call verifies freshly in its
own context, exactly as before this change.
The context records, per consumed publication, the initial P2 observation, the
verified support-index identities, and the dependency edges that the
retirement and composition walks discover. It stores no support-artifact
bodies of its own; what it retains until the call returns is each consumed
publication's verified review — the structured final and manifest view, plus
a composite's bound support — and that publication's initial binding. The
context is never attached to the `Service`, a returned review, or the MCP
backend, so a separate request, including an MCP continuation chunk, verifies
freshly.
Within the call each consumed publication's snapshot read and whole-support
verification run at most once, and every served artifact (excerpt, role
report, source image, captured member) is still read at the point it is
served, digest-bound to the verified index with the full path/kind/digest
checks; only the per-artifact re-observation is gone. Before returning, the
context re-observes every consumed publication in dependency postorder —
each after all of its dependencies, a shared ancestor once, the requested
publication last — and compares decision, epoch and snapshot identities.
Every publication-identity change still observable at that confirmation is
detected; a transient state with different bytes fails its digest-bound
read, and one with identical bytes cannot change the returned data.
Read-contract errors detected after verification — a receipt or cursor
mismatch, an invalid cursor, or source-replay unavailability — return without
that final confirmation, so under a concurrent publication change such an
error can surface instead of the artifact failure the earlier per-artifact
re-observation reported first; no data is returned either way. Excerpt
binding follows the two read families: receipt-bound content reads (report
and evidence content) bind every excerpt digest to the verified index, and
live publications are always index-bound; the legacy excerpt and render path
(`RenderExcerptAt` and the snapshot opener reader, used by
`report --output-path`, `excerpt` and the legacy MCP report resource) keeps
the claim-verified direct read for every historical publication, with or
without an index, as it always has.
No content cap or source snapshot is introduced.

The live Git source reader (`internal/adapters/gittarget`) carries its own
reader-local retention, guarded by its mutex. It retains the fixed commit-side
path-to-object inventories already admitted for the selector, each bound to
the immutable base or head commit resolved at admission (the listing
dereferences that commit's tree); index and worktree observations stay fresh
on every call, and a retained inventory is reused only after the same root
and Git metadata checks that guard a fresh inventory command. Retained
commit-side membership does not prove that the object is currently
available: evidence reads still fetch each blob by its bound object ID and
fail closed when it is unavailable. For each of the two execution Git
configuration files, the reader retains at most the digest of the last
successfully parsed bytes. The reader skips the parse only when freshly
verified bytes match that digest; otherwise it parses and replaces the
digest only on success. Failures are never cached. Both forms of retention
live inside one reader, are cleared on Close, and start fresh in a new
reader; there is no process-wide cache, no stat-only shortcut, and no
caching of `.mulgae` configuration admission. An unexported per-reader
function field routes the config byte read so in-package tests can observe
it; production always routes it to the descriptor-verified metadata read.

## Requirements-assessment ownership

The [revised EPIC-008 design](../architecture-decision-records/verified-review-iteration.md#reduced-epic-008-scope)
and [roadmap](../roadmap/README.md#epic-008-review-completeness-and-iteration)
define optional requirements assessment within the current original-source review
path. Admission, provider-free preflight, assessment execution/publication and
verified CLI/MCP inspection share the existing owners. Requirements execution
requires the existing Git/common-directory binding; objective-only non-Git
workspace execution remains supported.

```text
optional requirements input + existing objective
            -> assigned role assessment on the selected original source
            -> validated, hash-bound ordinary/no-change result support
            -> existing verified CLI/MCP inspection and reports
```

| Concern | Application and boundary ownership |
|---|---|
| Input and assignment | `reviewrun` admits the optional safe requirements file and selected owner roles before qualification; adapters provide secure file access |
| Prompt framing | Existing prompt/review owners treat requirements as untrusted data without duplicating role or provider defaults |
| Assessment | `validation` checks assigned IDs, owners, verdicts and source evidence independently from ordinary findings |
| Publication | `publication` retains exact input and normalized assessment support; no-change results contain explicit unverified items without attempts or reports |
| Verified reads | `query` verifies publication-bound assessment support; `report` renders it; CLI/MCP project the common result |
| Artifact lifecycle | Existing `clean` and `export` owners extend only their owned allowlists and preserve privacy and lineage rules |

TASK-027 exposes admission and provider-free preflight; TASK-028 implements
internal execution/publication. TASK-029 enables public requirements-bearing
execution and its capability only with the necessary verified CLI/MCP reads.
Keep objective-only execution available and use the existing capability mechanism.

The current admission path uses `ports.RequirementsInputReader` on the retained
project lease for local invocation data. It does not call the selected-side source
reader or inventory extra files. `reviewrun.AdmitRequirementsInput` validates and
owns the exact bytes; CLI/MCP expose only the bounded preflight summary. The
live application service completes input and binding admission before invoking
the existing secure writer or allocating a run. CLI/MCP use this same service;
unsupported non-Git requirements requests fail before those effects.

The runtime retains verifier-owned assessment content independently
of its finding/report output. `validation` owns strict unbounded assessment
admission and the trusted in-memory provider-output v3 composition;
`review` owns section retention and shared-slot scheduling through the existing
coordinator. `publication.WithRequirements` binds exact input, bounded metadata
and per-item content to the v4 candidate, support index, final and manifest.
The optimized live builder shares those support members across preflight and
issued-review bindings. Source verification finishes before lease closure;
restart uses retained hash-bound members and never consults current source.

Reuse existing typed values, inward ports, live source readers, provider lanes
and invocation ceilings. The requirements file is immutable invocation data;
its admitted local bytes need not exist in the reviewed index or commit and
are reused by prompts and publication. It creates no source snapshot or
full-content identity. Workspace/index consistency remains caller-maintained,
while committed evidence uses resolved
Git objects. Do not restore capture-bound guards or retired execution packages.

Every existing admitted no-change target, including empty-tree HEAD, stays on
the provider-free branch after requirements admission. Publication retains
selected IDs, owners and `unverified/no_change_target` results with zero
attempts/reports. Preflight and
reads show evaluation not run. An explicit new target is needed to assess a
workspace; there is no implicit fallback.

Existing extraction policy and the shared additional-invocation allowance remain
unchanged. Validation preserves independent valid sections without claiming
success from unparseable content; protected failures still deny publication.
Query/report keep valid provider assessments distinct from Mulgae-derived
placeholders and do not infer finding availability from assessment success.

The existing invocation registry owns start/await/cancel. No batch use case,
comparison reducer, resolution-transfer authority, persistent campaign or
second scheduler is part of this scope. EPIC-007's historical capture and
composite outcomes remain with their supported readers.


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

Requirements support metadata has one strict semantic decoder in `validation`.
`publication` retains its serialization wrapper and atomic filesystem lifecycle;
`query` verifies the complete retained input/content set and final receipt per
call. Separate requirements cursors preserve finding filters and pagination.
`report` consumes content through that verified snapshot. No read consults the
current project source or provider runtime, and cleanup/export retain their
existing run ownership, lineage and privacy boundaries.

## Haepari review coordination

EPIC-016 places grant policy in the application review lifecycle, native
operations behind `internal/ports`, concrete Haepari `managed-execution/v1`
(`advisory-lock/v1`) integration in `internal/adapters/haepari`, private
diagnostic intent persistence (`diagnostics/s_<uuidv7>/r_<uuidv7>/haepari-lock.json`)
in `internal/adapters/filesystem` and wiring in `internal/composition`.
`TASK-076` establishes the port, adapter and durable acquisition identity.
`TASK-077` connects `LiveService.Execute` and composition to one owned grant
before qualification, and `TASK-078` adds read-only `borrowedReview` protection
under `HAEPARI_LOCK_GRANT` alongside `ownedReview` behind the shared
`reviewProtection` interface. CLI, foreground MCP and asynchronous MCP share
acquisition or read-only borrowed admission, deadline monitoring and bounded
terminal cleanup while entrypoints retain transport grammar and lifecycle.
Independent deadline monitoring cancels work even when renewal or list
monitoring is stalled. The private v2 (owned) and v3 (borrowed) intents separate
native observation from local drain proof; filesystem cleanup protects unknown
proof and rechecks it before unlinking either linked tree, while allowing
verified v3 child artifacts to be cleaned independently of the parent grant.
No-change execution and preflight perform no controller access. Migration,
paired-skill and release qualification remain pending. Aquarium and `use-mulgae`
retain their existing execution path without an outer lock wrapper. Provider-free
operations retain their existing boundaries. Verified committed reads may use a
same-run coordination diagnostic summary as a best-effort supplement; its
absence or failure cannot revoke valid P2. Independently invalid P2 still fails
verification. The [specification](../specs/haepari-review-coordination.md) owns
behavior and the [ADR](../architecture-decision-records/haepari-review-coordination.md)
owns the decision.
