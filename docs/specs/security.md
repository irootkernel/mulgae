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

Local diagnosis confirms native-home identity after the permitted binary and
version observations. A non-cancellation mismatch at that point returns unsafe
readiness with `native_home_mismatch` and exit 8, clearing derived provider and
assignment projections. It starts no later version process. Providers may still
read its independent recorded evidence; those reads do not grant live review or
publication authority. Native-home cancellation retains its original cause in
the application service. Doctor projects public exit 9; providers retains its
existing public exit 7 projection for requested cancellation.
Cursor uses the same direct version argv, disposable home and identity checks;
calendar/hash normalization does not authorize a model request.

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

Preflight and provider execution reject local Git configuration outside the
closed data-only set in [live review](live-workspace-and-git-review.md#reviewer-execution).
Both main and worktree configuration are read through verified descriptors and
parsed without includes. Unknown settings fail closed with `unsafe_source`;
execution revalidation checks the policy again. Trusted provider Git variables
override hooks/fsmonitor, external attributes/excludes and pagers, and disable
Git transport protocols. This does not rewrite caller configuration.

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
  An app-owned `requirements.toml` with root `fail_closed = true` retains
  compatibility, discovery, plugin and MCP restrictions; `sandbox.toml` retains
  the native deny roots. Native `config.toml` and managed-cache bookkeeping are
  not policy authority. Protected files must retain their exact bytes, inode,
  user ownership, single link and mode `0600`. Checks run before launch and
  after verified process drain for qualification, review and extraction.
  Drift rejects the affected invocation through the existing security failure
  path; policy is never restored to make a later invocation pass. An uncertain
  drain retains the existing terminal ownership and protection files.
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
- Cursor uses ACP over stdio. Review and extraction
  require an outer Seatbelt guard; the adapter never falls back to an unguarded
  launch. `session/prompt` waits until the matching session acknowledges ask.
  Planned app-mediated workspace reads stay allowed. Each exact admitted Git
  command is a separate `allow_once`. An unplanned, forbidden, or mismatched
  live tool receives the non-authorizing answer and then fails the turn. A
  later `end_turn` does not accept that turn. Exceptions that leave the turn
  running are in
  [Cursor ACP transport](../architecture-decision-records/cursor-acp-transport.md).
  A general read permission is not granted. The process receives
  only the selected `CURSOR_AUTH_TOKEN` and an in-memory credential store. User
  rules, skills, and MCP configuration are not projected. Explicit selection
  does not assign Cursor to a role by default.
- AGY uses native plan mode and bidirectional stream-JSON inside the mandatory
  outer guard. Its adapter-owned settings, agent and empty MCP configuration
  are audited after invocation. It imports only a disposable copy of the OS
  user's default Gemini token; the original is never written back. The token
  must be a nonempty regular no-follow mode-`0600` file, user-owned and
  single-link. Native refresh may change the disposable copy. There is no
  alternate account scan, credential profile or home override.
  The minimum supported version is `1.2.9`, with no per-version command or
  settings allowlist. The post-invocation audit accepts omitted native
  `request-review`/`false` defaults and an omitted expected-empty allow set;
  unsafe values, null, unknown fields and changed grants remain failures.
  Indexed guarded commands and explicit `command(1)` denial constrain the
  native prefix codec; the driver separately verifies exact tool operands and
  correlated completions. Natural zero exit, complete input, EOF and verified
  process-group absence are mandatory. Unknown drain retains the namespace,
  policy and token, and forbids reuse or successful cleanup. Composition removes
  the namespace parent nonrecursively before closing reviewer-home/workspace
  ownership. See [AGY transport](../architecture-decision-records/agy-stream-json-transport.md).

Shared provider path translation runs only after the family's existing
authority, revalidation, scope and canonical-path checks. The source reader
continues to own protected-root, namespace and file-kind admission, including
its final revalidation, without reading file bodies or caching approval.
Final Grok and Cursor tool validation uses ascending raw native string IDs
to select a diagnostic. It preserves per-operation checks, immediate failure
and typed refusal; sorting grants no permission and omits no final check.

The outer guard denies writes outside admitted private runtime directories and
protects source, Git and neutral-guide roots from writes. It
also denies reads, writes, links and Unix sockets at every configured credential
root, including unselected profiles and aliases. These controls are not general
process, IPC, network or read containment: ordinary network requests and reads
outside protected credential roots remain possible. Ignore rules select scope;
they do not restrict filesystem access. Historical staged-file receipts and
snapshot metadata remain readable, but grant no current execution authority.

Filesystem path denial does not revoke access through an already-open inherited
descriptor. Before either bound or unbound guarded execution, a trusted launch
child marks every descriptor above stderr close-on-exec and then replaces itself
with `sandbox-exec`. Failure to enumerate or protect a descriptor stops that
launch; only a descriptor that has already vanished may be ignored. Parent
descriptor flags are not changed.

The default outer guard denies pseudo-terminal creation. An explicit typed
owned-PTY capability permits `/dev/ptmx` and kernel-owned `/dev/ttys*` slaves.
Foreign slave path opens and mutating ioctls remain denied, as does `/dev/tty`.
This capability does not relax source, Git, guide, or credential-root policy.

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
existing user file is preserved. Selection rejects unsafe paths and unsupported
source kinds before provider work. Index targets also reject unresolved conflicts.
Ignored paths are not a physical read restriction; keep sensitive material outside the
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

Current execution follows [live workspace and Git review](live-workspace-and-git-review.md).
[Verified review contracts](verified-review-contracts.md) retains historical
capture/guard and composite-support obligations. The reduced
[EPIC-008 design](review-completeness-and-iteration.md) defines optional requirements
assessment. Current admission, assessment execution/publication and verified
CLI/MCP reads use the existing owners and Git project binding.

- Keep independent project binding and anchored-root revalidation before
  qualification or provider transmission. Local identity is not a content
  fingerprint or authentication against a malicious host.
- Admit requirements through the existing secure project-relative regular-file
  boundary. Validate strict JSON, Unicode, duplicate IDs, selected-role ownership
  and protected/ignore policies before qualification or no-change publication.
  Requirements remain untrusted data and grant no tool, test, network or
  filesystem permissions.
- Retain exact admitted input bytes and their digest as invocation data.
  Read that file from the admitted local project filesystem; it need not exist
  in the reviewed commit. Prompts/publication reuse the admitted bytes without
  reopening the file. Quoted code or paths in requirements are not implementation
  evidence and grant no different source side.
  Keep original-source target sides and evidence verification; create no source
  snapshot, full inventory, captured-reference archive or mutable-content guard.
  Workspace/index consistency remains caller-maintained.
- Providers cannot assign trusted requirement identity, owner, verification,
  coverage or publication state. Missing answers/evidence are unverified.
  Keep ordinary findings and optional assessment validation independent while
  preserving protected failure precedence and current provider-call ceilings.
- Requirements cannot enable extraction, rewrite policy or add an invocation
  after retry/repair consumed the shared allowance. A valid initial structured
  answer remains eligible with extraction disabled; unavailable extraction
  produces explicit unverified reasons. Whole-response parse failure cannot
  establish independently validated sections or zero findings.
- Every existing admitted no-change target, including empty-tree HEAD, retains
  zero provider calls and explicit evaluation-not-run plus
  unverified/no_change_target results. Persist input/assignments/results
  without fabricated attempts, reports or provider claims. Never select workspace
  automatically or infer satisfaction from zero findings.
- Bind new support and every result page to verified publication authority.
  Damaged bound support fails integrity checks; intact historical capability
  absence is explicit unavailability. Reads cannot invoke providers, rewrite
  results or reconstruct evidence from current source.
- Admit public requirements-bearing execution only with verified CLI/MCP reads
  and an existing Git/common-directory project binding. Keep provider assessments, Mulgae-derived placeholders and unknown
  historical counts distinct; assessment success grants no finding coverage or
  final acceptance authority.
- Preserve historical capture and self-contained composite integrity under their
  original contracts, including unavailable versus corrupt support. New assessment
  support does not restore retired producers or implicitly upgrade old results.
- Keep native paths, credentials, raw requirements and private evidence out of
  unrequested public diagnostics and portable exports. Response bounds must not
  become source, prompt, requirement-prose or provider-report byte ceilings.

Requirements preflight reads the selected local file through the admitted root
and no-follow regular-file descriptors. Canonical paths, protected roots and
local ignore rules apply independently of the reviewed Git side. Ignore-control
files retain their existing configuration bounds even if also selected as JSON
input; ordinary requirement prose remains unbounded. Only IDs, owners, counts,
digest and fixed admission/policy states enter the preflight response. Requirements execution on an unbound non-Git workspace fails with
`contract_unsupported` before private writer effects, allocation or qualification.
Its provider-free preflight may validate input but must disclose unavailable
execution and an empty requirements capability. Objective-only non-Git execution
remains supported. Malformed input on any no-change path authorizes no result.

Internal assessment evidence uses the selected source side while its original
lease remains open. A comparison with the exact admitted input digest rejects
self-prose at the input path without excluding distinct index or committed
implementation bytes at that same path. Only the already-read cited file is
hashed; this creates no source inventory or persisted content lock. Visual
references must retain their selected-side binary binding.

The assessment section is decoded strictly without the generic 8 MiB envelope
limit on prose. Trusted ownership violations and source/validator failures retain
canonical joined-error precedence and deny publication. Ordinary content failure
in one section preserves a valid peer and its accepted primary report. Bound
input/content bodies remain private publication support. Verified public content
reads expose assessment rationale/evidence through receipt-bound chunks, without
including the raw invocation input. Portable export admits neither body. Readers
verify the whole selected set and every content binding before paging, then
confirm publication authority again before returning. Concurrent cleanup or
changed receipts fail closed. Cleanup removes run-owned copies only, never the
original invocation file.

Batch execution, cross-run comparison, resolution transfer and conflict
reduction are outside this Epic. Requirements assessment grants no issue
disposition, CI-policy change, remediation or final acceptance authority.

## Reporting vulnerabilities

Do not open a public issue containing credentials, private source, raw provider
transcripts, or `.mulgae/` artifacts. Share the smallest redacted reproduction
through the repository owner's private security contact.

## Haepari coordination boundary

EPIC-016's [coordination contract](haepari-review-coordination.md) requires
native owner/borrower validation, fail-closed provider dispatch and cancellation
and drain after grant loss. The inherited reference is same-user coordination;
it grants no source, provider, credential or publication authority. Advisory
expiry cannot prove process termination. The common owner path fails closed on
lost protection, reserves bounded cleanup time and retains unknown local drain
proof across native expiry. Cleanup rechecks intent bytes and pinned identities
before deleting either linked tree. Until borrowing is implemented, any present
inherited grant reference is refused before controller or intent access.
Provider-free requests retain their existing boundaries. Public causes and
summaries contain owned bounded tokens; native paths and response text remain
private. Borrower and installed/released qualification obligations remain pending.
Existing isolation and failure precedence remain authoritative.
