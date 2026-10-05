# Security requirements and trust model

## Trust model

Mulgae treats the project, target, project context, and provider output as
untrusted. Trusted code owns configuration admission, source selection, execution
policy, schema compilation, identity, evidence verification, state reduction,
and publication.

The attached MCP boundary is local stdio only. It fixes one canonical project
root before serving requests, admits only protocols `2026-07-28`, `2025-11-25`,
and `2025-06-18`, rejects a version change within one session, and reserves
stdout exclusively for newline-delimited JSON-RPC. Each nonempty input record
must be LF-terminated; an unterminated record at EOF is rejected before parsing
or dispatch. Client parameters remain untrusted and do not acquire provider,
publication, configuration, approval, or path authority merely by crossing the
MCP transport. Tool arguments are strictly decoded and bounded. Current review
requests admit only `workspace`, `stage`, `head`, `commit` and `diff`. Stdin is
transport-only. Capture-bound guards and child/replay/compose mutations are
rejected before provider execution. Query tools expose verified, project-confined
status, artifact identities and bounded finding summaries. Native paths, provider
transcripts, report bodies and source bytes are absent from tool results.

Report and evidence bodies are available through project-confined `mulgae://`
templates. Each read re-verifies committed support, admits canonical byte offsets
and returns at most 16 KiB with integrity and continuation metadata. Live evidence
URIs bind the finding to its source identity; historical capture URIs retain their
original target binding. Malformed, stale or damaged support fails closed without
reflecting requested paths. Source-image resources preserve binary evidence.

Failed tool results expose only bounded Mulgae-owned recovery identity. A failed
`run_review` or terminal `await_review` includes both session and run IDs when
allocation occurred and is never marked retryable; provider details, runtime
diagnostics, and native paths remain private. Historical P0/P1 records can still be reconciled without a provider. Their
verified identities never authorize replay or a new composite publication.

Historical `failed_run_recovery` inspection retains exactly seven fields: `available`,
nullable `source_kind`, nullable `run_id`, nullable `manifest_sha256`,
`accepted_roles`, `retry_attempts` (each containing `role` and `attempt_id`),
and nullable `unavailable_reason`. An available source sets `available` to true,
uses `source_kind: failed_run_recovery`, supplies its run ID and manifest hash,
and returns the verified accepted-role and retry-attempt inventories. An
unavailable source sets `available` to false, leaves source identity null,
returns empty inventories, and supplies only one of
`source_not_retained`, `source_invalid`, `publication_in_progress`, or
`published_review` as its reason. The projection carries no publication or
final-review authority, artifact/report/role-report URI, finding or outcome
axis, raw event stream, provider transcript, or native path.

`get_run` may expose `kind: status_read` for the ordinary publication-status
path, including P0 and P1 observations, and for a verified retained
failed/cancelled recovery. It may expose the separate bounded diagnostic status
projection only after a typed publication-not-found result. That projection has
no publication authority, artifact URI, report URI, findings, raw event stream,
or provider transcript, and admits only a completed `failed` or `cancelled`
status. Other publication failures remain fail-closed, and an allocated identity
with no diagnostic status or only a nonterminal snapshot returns
`run_status_unavailable` instead of inventing recoverable state. Pure query
cancellation remains cancellation; cancellation joined with diagnostic damage
retains artifact-failure precedence.

Both ordinary and diagnostic-only status may expose a bounded
`diagnostic_summary`. It contains only fixed diagnostic tokens, Mulgae-owned
identities, and domain-separated SHA-256 fingerprints of provider session and
turn identifiers. Raw provider identifiers remain in the private invocation
status. An ordinary publication status accepts this summary only when its
session identity matches the diagnostic run.

Optional `run_review` progress notifications contain only fixed Mulgae
lifecycle messages, an admitted bounded client token, and a monotonic counter;
they do not expose paths, source, provider output, run identity, or artifact
content.
Notification delivery failure cannot weaken review or publication policy.
The lifecycle registry exists only inside one MCP process and retains at most 64
identities. Oldest terminal identities may be discarded to admit a new start.
A start request cannot supply or reuse an identity, unknown identities fail
closed, and terminal results are cloned before returning to an observer.
Cancelling or timing out `await_review` cannot reach provider work.
Only an explicit `cancel_review` request marks client cancellation intent; its
acknowledgement grants no terminal or publication authority. Process shutdown
closes admission before cancelling and draining active executions, and a later
server cannot recover or claim those invocation identities.

Standard MCP request cancellation still reaches the existing foreground
`run_review` context. The entrypoint also joins foreground handlers and
registry-owned executions to the process context so SIGINT or SIGTERM cancels
provider and publication work instead of merely closing transport around it.

### Local project binding

CLI `context` and MCP `get_context` inspect directory descriptors and Git-location
metadata without reading project policy, credentials, or provider state. The
root, worktree Git directory, common Git directory, and Git-location pointers
must be owned by the current user and not group- or world-writable. Git pointers
must be regular files with one link; symbolic links in Git metadata fail closed.
The requested root may be a canonical path alias. Its resolved location, device,
inode, and birth time form the private input to the public binding digest.

MCP retains the startup descriptors and rejects changed anchors on context
lookup and before review dispatch. A non-Git workspace retains a root-only
startup lease, without a Git binding, and rejects root replacement or newly
introduced Git metadata. The caller compares this digest with an independent
CLI lookup from the requested root. The digest does not authenticate an untrusted
host or grant permission to retarget the server. Execution compares the
independently observed `expected_project_binding` before qualification.
Preflight is advisory and does
not reserve source state; `context` advertises only implemented capabilities.

## Provider isolation

Default setup and inspection are non-live. `doctor` may execute only the exact
adapter-owned local version argv in a disposable empty home; it projects no
credentials or project directory and sends no prompt or source. `providers`
does not execute a live model request. Neither command starts an MCP server,
creates a review run, or records remote logs.

The separate `heartbeat` command crosses the live boundary only when
`--authorize-live-request` is present. The handler rejects an unapproved request
before composing provider infrastructure, reading credentials, or executing a
provider process. An approved heartbeat may authenticate, use the network,
incur cost, and create remote logs, but its packet is fixed Mulgae-owned
synthetic content and carries no repository source, diff, review prompt, or user
content. Its result has no review, publication, or durable qualification
authority.

Providers read admitted original workspace, index and resolved Git sources.
Their process and session cwd is the pinned neutral `~/.mulgae/home`, with a safe
regular guide preserved and injected once. Project and ancestor instructions are
not loaded as authority; selected project context is framed as untrusted data.
No source tree, patch or full-source archive is copied for a new review.

Each run owns its provider registry and disposable namespace generations. There
is no provider-key queue across independent runs. Shared installed credentials
do not become a hidden scheduling authority; provider rejection, quota and
rate limits remain typed outcomes of the affected run. Subprocesses use fixed
adapter commands, explicit credential projection, execution budgets,
cancellation and verified terminal process drain.

Provider-authored content documents are projected through Mulgae-owned nested
allowlists after strict JSON parsing. Unknown additions and attempted Mulgae-owned
fields are discarded, then trusted values are injected; discarded values are
never logged. Diagnostics retain only bounded JSON Pointer paths and a total
count. This tolerance does not apply to process, transport, lifecycle, workspace,
evidence, or publication receipts, and malformed JSON, duplicate keys,
unverifiable evidence, and semantic contradictions remain fail-closed.

Original workspace and index contents must remain unchanged for the duration of
review. Root descriptor checks detect changed anchors, not all content drift or
an atomic content snapshot. Committed scopes use resolved object IDs. Trusted
Git reads disable hooks, fsmonitor, external diff, textconv and lazy fetch.
Project configuration cannot introduce executable commands.

### Provider read and write boundaries

All live reports come from complete, correlated assistant turns. Review, repair
and extraction receive no report-file write grant. Private namespaces and
scratch are removed after verified provider drain.

- ZCode uses its app-owned Electron runtime and app-server launcher, fixed
  protocol configuration and disabled write/plan tools. Review and extraction
  require an outer Seatbelt guard; the adapter never falls back to an unguarded
  launch. Fixed runtime preferences remain local-only. Unexpected interaction
  requests, incomplete turns and protocol parse failures fail closed.
- Grok uses ACP v1 without MCP servers or subagents and admits text roles only.
  Its native sandbox is off only inside the mandatory outer Seatbelt guard.
  In live review conversations, admitted file and Git reads remain correlated
  and bounded at the protocol boundary. Completed and failed native tool
  operations must match the read plan even when Grok omits a permission request.
  Missing tool identity, inputs or completion prevents report acceptance;
  partial input grants no authority.
  Structured extraction receives no review read plan; its filesystem access
  remains subject to the outer guard.
  Optional model and reasoning policy comes only from shared project
  configuration; exact acknowledgement is required before prompting.
- Codex uses one app-server process and ephemeral thread per invocation, native
  read-only permissions and approvals disabled. All configured credential roots
  are denied to model tools. Only the selected authentication file enters its
  disposable home; user config, rules, skills and plugins are not projected.
  Loaded project instructions and unexpected server requests fail closed.

The outer guard protects source, Git and neutral-guide roots from writes. It
also denies reads, writes, links and Unix sockets at every configured credential
root, including unselected profiles and aliases. These controls are not general
process, IPC, network or read containment: ordinary network requests and reads
outside protected credential roots remain possible. Ignore rules select scope;
they do not restrict filesystem access. Historical staged-file receipts and
snapshot metadata remain readable, but grant no current execution authority.

## Credentials and secrets

Credentials remain owned by the installed provider. Mulgae projects only the
provider-specific files and environment required by the adapter into a
temporary namespace. The namespace supplies disposable provider homes, temp
and scratch areas independently of the neutral reviewer cwd. Commit only the machine-path-free project
policy at `.mulgae/config.yaml`. Do not commit `.mulgae/local.yaml`,
credentials, provider homes, any other `.mulgae/` artifacts, or exported review
bundles.

ZCode admission binds its app's v2 desktop state and current Z.AI Individual
Coding Plan account. Legacy CLI config is not live authentication authority.
Admitted provider state is projected only through the adapter-owned disposable
namespace. Cleanup zeroes credential content only through a verified single-link
regular descriptor on the namespace device with the expected owner. Unsafe
replacement paths are removed without writing through them. User settings,
history, logs and caches are not projected.

Codex authentication is copied from a descriptor-anchored credential home into
the invocation's disposable `CODEX_HOME`. Legacy configuration uses native
`~/.codex/auth.json`; named profiles use the exact machine-local home configured
for that profile. Each profile gets a distinct provider instance, qualification
group, and namespace, so authentication authority is never derived across
profiles even when they share one executable. Mulgae does not admit an API-key
environment variable, and Codex model tools cannot read the projected credential
directory. Only `auth.json` is copied; user config, rules, skills, and plugins are
not projected. The copy is mode `0600`, remains bound to its namespace
generation, and is removed during terminal namespace cleanup.

Runtime diagnostics and exports must not disclose secrets or native paths.
Exports reject credential-shaped fixed-prefix GitHub, Slack and secret-key tokens
before packaging, including bare tokens without assignment or bearer labels. A
new diagnostic field is a data-release boundary and requires review. Provider
session and turn identifiers are private diagnostic data. Public status may
expose only their domain-separated SHA-256 fingerprints, which bind the
provider instance and identifier kind before hashing.

Human CLI output renders terminal control characters as visible escapes, keeping
line feeds and tabs for formatting. This includes provider prose, report content
and legacy excerpt output. Stored artifacts and machine-readable content retain
their original bytes; presentation escaping does not change evidence identities.

Workspace discovery uses tracked and nonignored untracked paths according to
Git's ignore rules. `.mulgaeignore` is neither processed nor generated, and an
existing user file is preserved. Selection rejects unsafe paths, unsupported
source kinds and unresolved index conflicts before provider work. Ignored paths
are not a physical read restriction; keep sensitive material outside the
admitted readable boundary. Source admission does not use credential-pattern
matching as a substitute for operator scope policy.

New runs retain source selection metadata, verified excerpt bytes and selected
PNG/JPEG/WebP evidence alongside findings and complete role reports. Raster
extension and signature must agree; bodies remain binary. They do not retain
full source archives. Historical capture readers verify stored manifests and
blobs without consulting current source. Missing historical evidence remains
distinct from corruption.

Source observations, prompt payloads, role reports and complete provider stdout
and stderr have no product byte ceiling. Process lifetimes, protocol transport,
structured artifacts, concurrency and diagnostic metadata remain independently
bounded. Public diagnostics and redacted exports must not expose native paths,
credentials or raw provider transcripts.

A credential-like provider raw stream may be omitted from private diagnostics,
but that diagnostic drop does not turn an otherwise valid review into a
provider failure. Canonical final reviews and path-authorized run support retain
validated source evidence; unvalidated writes and exported projections continue
to use their existing redaction and secret-rejection boundaries.


Qualification diagnostics use the same private secure writer as review process
streams. Probe packets and version/capability streams are persisted before
fixture cleanup; scanner rejection drops the offending stream. Diagnostic run
identity allocated before qualification does not confer admission or P2
publication authority. Public errors expose only the diagnostic artifact
reference and typed failure, never the raw probe response.

## Validation and fail-closed behavior

Provider assistant stdout and stderr are captured completely without a product
byte ceiling. Markdown/free-form role reports are the primary consumable
success form; public diagnostic metadata and exact structured finding
extraction remain separate. Structured extraction is optional: Mulgae may apply one constrained
repair, then validate that wire with schema checks, trusted-field injection, and
semantic/evidence rules. Prose is not schema-validated as review JSON. External
schema loading is disabled. Mulgae owns trusted identity, evidence verification
state, and publication.

When `validation.extraction.enabled` is set, an accepted role report re-enters
one further prompt on the same provider as an untrusted `prior_report` payload,
never as a trusted layer, and the extraction contract states that it is data to
transcribe rather than instructions or authority. That invocation gets the same
read-only live source authority, no write grant, and always returns on
stdout. It cannot emit identity, verification, coverage, or publication state,
and Mulgae rather than the provider owns the resulting completeness and
limitations. Only a bounded extraction failure is absorbed into the accepted report. A
protected failure observed during that invocation keeps its canonical
precedence and reduces through the ordinary coordinator path, so security,
mutation, configuration, artifact, cancellation, and internal failures still
deny publication. The trailer can lose its own transcription; it can never
launder a protected failure into role success.

Evidence begins as `claimed`; only Mulgae can mark it verified, stale, invalid,
or unverifiable. Security, configuration, integrity, cancellation, and internal
failures never authorize repair or publication.

Mulgae output remains advisory after every technical check passes.

## Historical composite evidence isolation

Retained composites bind copied source findings, available evidence, source receipts
and per-role capture support through support-index v2 before publication.
Committed reads verify the copies and their final/source mappings without
reading source runs or the current working tree. Missing bound copies and digest
mismatches are integrity failures; historical absence remains explicit.

Published source receipts retain verified P2 identities. Failed-run recovery
receipts retain their recovery-manifest digest and attempt without a fabricated
review ID or publication epoch. Copied provider provenance preserves retirement
checks after source cleanup. A common capture requires equal verified captures
for every selected role, including roles without findings.

Local finding details expose copied `source_finding` and `source_receipt` through
the receipt-bound read path. The export allowlist excludes the additional copied
private content. Native cleanup policy still controls source deletion and keeps
its existing failed-recovery-root protection. Existing legacy P2 composites are
reused unchanged and gain no evidence through an implicit upgrade.

## Adopted extension security requirements

The following requirements record the frozen pre-cutover
[verified review contracts](verified-review-contracts.md) and deferred
[review completeness and iteration](review-completeness-and-iteration.md).
Current execution follows [live workspace and Git review](live-workspace-and-git-review.md).
Capture, Brief, batch-followup and comparison requirements need redesign after
EPIC-009 acceptance; they do not authorize retired execution.

- Native binding must distinguish equal-content worktrees using independently
  established local identity. A server's own response is not its own proof of
  matching the requested root. Revalidate the anchored root and keep absolute
  paths and credentials out of public receipts and portable exports.
- Guard comparison must precede qualification and every provider transmission.
  Compare and execute the same admitted immutable capture/plan; preserve existing
  spawn-time isolation checks. A matching guard does not authorize duplicate
  starts or authenticate a malicious host.
- Keep complete capture identity separate from the existing patch digest and
  request identity. Bind target kinds/sides, all file paths and exact digests,
  capture policy, and support context to retained verification material. Missing
  historical support is unavailable, not permission to compare patches alone;
  damaged bound support remains an integrity error.
- Verified inspection and continuations must remain bound to exact publication
  identities and fail on corruption, replacement, or cleanup. New reads cannot
  write reports, repair old artifacts, or invoke a provider. Per-page limits
  cannot become source, prompt, or report-content ceilings.
- New composite evidence must be hash-bound and self-contained. Historical
  evidence absence cannot authorize a read of current files or an implicit
  upgrade. Export redaction remains separate from local evidence-read access.
- Review Briefs and criteria are untrusted data. Validate Unicode, duplicate IDs,
  role ownership, paths, exclusions, and captured-side references. Explicit file
  selection does not bypass ignore or control-path restrictions. No test,
  command, network fetch, or provider permission follows from Brief prose.
- Assessment and batch output cannot assign trusted identity, manufacture
  verification, or promote missing evidence to success. Keep malformed optional
  assessment sections isolated from valid ordinary findings, while protected
  failures retain their current publication-denial precedence.
- Empty Git diffs with a Brief must still validate inputs and guards, then retain
  zero provider calls and explicit unverified/no_change_target results. Persist
  the exact Brief and selected requirements without fabricated attempts/reports.
  Never silently select workspace, rewrite references, or infer met from no findings.
- Batch execution reuses one target and existing invocation ceilings; observer
  cancellation stays separate from execution cancellation. No per-finding retry
  loop, provider substitution, implicit recovery, or parent-artifact mutation.
- Comparison verifies exact source-finding binding and full evaluated-current/
  after capture equality before transferring a followup resolution. Before and
  after may differ; distinct review objectives do not require distinct captures.
- Bind every comparison continuation to before/after and the complete selected
  followup ID/receipt set, filters, and contract versions. Revalidate all of it on
  every page; deletion, replacement, or corruption fails the page rather than
  silently dropping evidence or returning a semantic unverified row.
- Preserve conflicting intact followup verdicts and after observations under
  stable unverified conflict reasons. Do not settle them by ordering, recency,
  provider preference, or votes; distinguish inconclusive claims from negative
  verdicts. Non-observation, changed requirements, absent extraction, and
  ambiguous correspondence cannot silently become resolved or met.

## Reporting vulnerabilities

Do not open a public issue containing credentials, private source, raw provider
transcripts, or `.mulgae/` artifacts. Share the smallest redacted reproduction
through the repository owner's private security contact.
