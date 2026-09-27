# Security requirements and trust model

## Trust model

Mulgae treats the project, target, project context, and provider output as
untrusted. Trusted code owns configuration admission, target capture, execution
policy, schema compilation, identity, evidence verification, state reduction,
and publication.

The attached MCP boundary is local stdio only. It fixes one canonical project
root before serving requests, admits only protocols `2026-07-28`, `2025-11-25`,
and `2025-06-18`, rejects a version change within one session, and reserves
stdout exclusively for newline-delimited JSON-RPC. Each nonempty input record
must be LF-terminated; an unterminated record at EOF is rejected before parsing
or dispatch. Client parameters remain untrusted and do not acquire provider,
publication, configuration, approval, or path authority merely by crossing the
MCP transport. Tool arguments are strictly decoded and bounded. `compose_review`
admits one exact root and one to seven unique exact recovery IDs, invokes no
provider, and grants authority only after shared publication reaches P2.
`run_review` and `start_review` admit no stdin target, and query tools expose
only verified, project-confined status, artifact identities, and bounded finding
summaries. Native paths, provider transcripts, report bodies, and captured
source are not part of these tool results. Report and evidence
bodies are available only through project-confined `mulgae://` templates. Each
read re-verifies the committed source, admits only canonical byte offsets, and
returns at most 16 KiB with integrity and continuation metadata. Evidence URIs
bind the finding to the current target SHA-256; stale, malformed, oversized, or
relocated content fails closed without reflecting the requested URI or native
path.

Failed tool results expose only bounded Mulgae-owned recovery identity. A failed
`run_review` or terminal `await_review` includes both session and run IDs when
allocation occurred and is never marked retryable; provider details, runtime
diagnostics, and native paths remain private. An uncertain composite publication
exposes only its deterministic session/run identity and requires exact status
reconciliation; it never authorizes blind retry.

The `failed_run_recovery` projection has exactly seven fields: `available`,
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
lookup. The caller compares this digest with an independent CLI lookup from the
requested root. The digest does not authenticate an untrusted host or grant
permission to retarget the server. Execution guards are a separate contract;
`context` advertises only implemented capabilities.

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

Providers do not receive live access to the project tree. Mulgae captures the
target and materializes a controlled workspace. Subprocesses use adapter-owned
commands against that immutable directory view, isolated output, explicit
credential projection, execution bounds, process-local per-instance
namespace ownership, cancellation, and terminal process-state checks. Each run
owns its provider registry and namespace generations; no provider-key queue or
lock coordinates independent runs. That independence is deliberate even when
provider processes ultimately use one installed account: Mulgae does not turn
shared credentials into a hidden scheduling authority. Provider rejection,
quota, and rate-limit responses remain typed outcomes of the affected run.
Prompt packets identify the
generated `._mulgae_review_target.txt` file by path, digest, and size rather than
re-embedding patch, stdin, or old/new target bytes for every role. Providers read
that file and surrounding project content selectively from the sealed directory
view.

Provider-authored content documents are projected through Mulgae-owned nested
allowlists after strict JSON parsing. Unknown additions and attempted Mulgae-owned
fields are discarded, then trusted values are injected; discarded values are
never logged. Diagnostics retain only bounded JSON Pointer paths and a total
count. This tolerance does not apply to process, transport, lifecycle, workspace,
evidence, or publication receipts, and malformed JSON, duplicate keys,
unverifiable evidence, and semantic contradictions remain fail-closed.

The workspace is materialized as ordinary read-only files (`0444`) and
directories (`0555`). A single tree appears under `current/`; Git comparisons
appear under `before/` and `after/`. Mulgae revalidates the view through retained
descriptors before and after every invocation. Post-execution drift overrides
provider success, so a provider that mutates the view cannot produce a
publishable result.

Project configuration cannot introduce an executable command.

### Per-family write posture

Write authority is not uniform across families, and it is no longer accurate to
say that no provider ever holds it.

- ZCode review and qualification invocations speak the app-server protocol:
  the adapter launches the app-owned Electron runtime as
  `[runtime, launcher, app-server, --stdio]` with `ELECTRON_RUN_AS_NODE=1` and conducts one
  newline-delimited protocol conversation over the child's stdin and stdout,
  replacing the former one-shot print invocation without a fallback. Review
  conversations request `yolo` mode with the adapter-owned denylist
  `Bash,Edit,NotebookEdit,WebSearch,WebFetch,EnterPlanMode,ExitPlanMode`.
  `Write` is deliberately enabled so ZCode can place its role report at the one
  absolute path Mulgae chose. The plan tools are denied because the protocol's
  plan flow persists `plan-<session>.md` files inside the workspace, which the
  sealed snapshot's drift detection must continue to reject. ZCode
  qualification conversations use plan mode with all tools denied; their
  capability evidence is the conversation's captured assistant text. The
  server's runtime-preferences request is answered with a fixed local-only
  object, and every other server-initiated interaction request is left
  unanswered. A missing turn completion, a reported turn failure, or an
  unparseable protocol message fails closed through typed classification, with
  the stderr token classification retained as the fallback. The protocol
  driver records bounded phase, terminal, correlation, and receipt facts before
  process teardown. These facts allow a protocol failure followed by expected
  SIGTERM teardown to keep its provider failure classification instead of
  becoming an internal invariant failure. Because the
  app-server binds a per-process unix socket under its temp directory, ZCode
  namespaces redirect `TMPDIR`, `TMP`, and `TEMP` to the short shared
  mode-`0700` runtime directory `/tmp/mulgae-zcode`; a namespace-rooted temp
  path exceeds the kernel socket path limit. Socket names carry process-unique
  random identifiers, and the directory is never used for review content.
- Grok speaks ACP v1 with no MCP servers. Mulgae projects only the native
  authentication file and an adapter-owned workspace policy into a disposable
  Grok home. Review may approve one correlated `Write` request to the exact
  staged report destination; shell, web, subagent, sibling, traversal, symlink,
  repeated-write, and unrecognized requests fail closed. Qualification and
  extraction receive no write authority. Grok is admitted only for text roles.
  Optional model and reasoning-effort values are admitted only from shared
  project policy, never from machine-local config or ambient provider config.
  New initialization writes the Mulgae-owned `grok-4.7` and `high` defaults into
  that shared authority instead of injecting them later at runtime.
  The adapter requires exact ACP acknowledgement before prompting and does not
  substitute a model or effort when Grok rejects or normalizes the request.
- Codex launches one stdio app-server process and one ephemeral thread per
  invocation. Mulgae disables approvals and applies its read-only permission
  profile over the immutable workspace. The projected `~/.codex` directory is
  denied to model tools. Only the selected authentication file enters the
  disposable home; project instructions have a zero-byte allowance. Web,
  apps, plugins, browser, hooks, image generation, and multi-agent features
  are disabled. The driver rejects loaded instruction sources and unexpected
  server requests, including approval requests. It accepts report text only
  from a completed, correlated turn; protocol stdout remains private evidence.

### Staging boundary

A ZCode or Grok review launch receives exactly one write target: a fresh
per-invocation directory Mulgae creates with `0700` under the provider's
disposable namespace scratch area, holding the single Mulgae-chosen filename
`role-report.md`. That directory is outside the sealed workspace view and
outside `.mulgae`. The exact absolute path is stated only by the prompt's last trusted
layer; a staged launch whose packet lacks that layer fails closed before the
process starts, and a staging destination the adapter did not itself choose is
refused.

After the process has fully terminated, the adapter validates the staged file
through the directory and parent descriptors it retained at creation, so no
step re-resolves a path the provider could have replaced. It rejects symbolic
links, files with more than one hard link, non-regular files, a file on another
device, any extra directory entry, ownership or mode drift, staging-directory
identity drift, content that changed while it was read,
invalid UTF-8, embedded NUL, and empty or whitespace-only content. Accepted
bytes remain untrusted provider output and enter the same acceptance pipeline
as stdout bytes; they are then copied into the Mulgae-owned
`role-reports/<role>.md`, and the provider-owned inode is never published.
Staging is removed on every exit path, and a cleanup that cannot be proven
overrides provider success as an artifact failure. Missing or unusable staged
content is an operational invalid-provider-output outcome that may be repaired;
a boundary violation is a security fail-closed outcome that never authorizes
repair or publication.

### ZCode residual risk (owner-accepted)

ZCode exposes no path-scoped write permission, so the `Write` grant above is
not confined to the staging directory by the provider itself. Its tool controls
are name-based: local ZCode 0.16.1 rejects `--allowed-tools` at runtime, so
Mulgae uses an explicit denylist, which can enable or deny `Write` wholesale
but cannot bind it to one directory. Containment is therefore entirely
Mulgae-side: the review workspace is a read-only `0444`/`0555` directory view whose
post-execution drift check overrides provider success; the process runs in a
disposable namespace with projected `HOME`, `TMPDIR`, and scratch; only the
staging directory is ever read back as trusted-path input, and only after full
process termination; and everything read back is validated and copied rather
than published in place. Outside those layers, a stray absolute-path write is
not blocked by Mulgae, and the live project tree is git-managed, so such a
write remains user-detectable rather than silent. This residual risk is an
explicit owner decision recorded against live capability evidence, not an
oversight; it applies to ZCode review invocations only.

## Credentials and secrets

Credentials remain owned by the installed provider. Mulgae projects only the
provider-specific files and environment required by the adapter into a
temporary namespace. That namespace also supplies the disposable `HOME`,
`TMPDIR`, and scratch area holding any per-invocation staging directory, so
staging is removed with the namespace it belongs to and never reaches a
credential or project location. Commit only the machine-path-free project
policy at `.mulgae/config.yaml`. Do not commit `.mulgae/local.yaml`,
credentials, provider homes, any other `.mulgae/` artifacts, or exported review
bundles.

ZCode receives its descriptor-anchored legacy CLI config when present. Mulgae
also converts that same source into ZCode's current personal-provider format
inside the disposable home because app-server does not perform the standalone
launcher's legacy import. Both projected files are mode `0600`, retain the
source's identity and digest as spawn authority, and are zeroed and removed at
terminal drain. A provider-created replacement is zeroed only when its opened
descriptor proves that it is a single-link regular file on the namespace device
with the namespace owner. Cleanup never writes through an unsafe replacement;
it removes the namespace name and completes descriptor-anchored namespace
teardown instead. Desktop credential stores, settings, history, logs, caches,
and other ZCode runtime state are not projected.

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

Runtime diagnostics and exports must not disclose secrets or native paths. A
new diagnostic field is a data-release boundary and requires review. Provider
session and turn identifiers are private diagnostic data. Public status may
expose only their domain-separated SHA-256 fingerprints, which bind the
provider instance and identifier kind before hashing.

Tracked `.gitignore`, `.mulgaeignore`, and the exact `.mulgae/config.yaml` file
are trusted capture-policy inputs, not provider evidence. Their presence does
not invalidate a repository, but their paths and contents are omitted from Git
targets, patch/stdin targets, captured snapshots, evidence, manifests, and
provider workspaces. Every other tracked `.mulgae/**` path remains forbidden. A
patch or stdin target containing only excluded control content fails as
`no_reviewable_content`; an equivalent Git target is a no-change capture.
Reserved namespaces such as `.git/**` and `.mulgae/**` other than the exact
project policy exception, malformed paths, path collisions, and selected
symlinks remain fail-closed.

Review capture does not apply secret-pattern detection to source files,
security fixtures, objectives, or provider packets. A configured provider is
therefore authorized to receive every file in the captured workspace view, including
credential-like placeholders and test data. Use `.mulgaeignore` to exclude
`.env` files, credential files, generated data, or any other path that must not
be transmitted. The immutable v3 `._mulgae_workspace_manifest.json` supplied
in each provider workspace lists the exact transmitted paths, sizes, hashes,
media types, and capture dispositions.

All eligible regular files are preserved byte-for-byte. Supported PNG, JPEG,
and WebP files receive image media types only after extension and signature
validation; other non-text files use `application/octet-stream`. Added and
modified hinted rasters are listed as primary artist metadata with explicit
before/after sides. Line-based
evidence readers omit their bodies instead of decoding them as UTF-8. Invalid
raster signatures fail as `unsupported_content` with the affected path.
The artist may inspect any other captured image for history or comparison; the
primary manifest is not an access allowlist. Git's textual binary-diff marker for every non-text file is
path-only; the reference-only captured archive manifest, its support-indexed
SHA-256 blobs, and the workspace manifest bind the actual non-text bytes. Dirty
capture revalidates those bytes before admission.

Source capture has no fixed file-count or byte ceiling. Provider execution,
output, diagnostics, structured publication members, and fixed-size storage
reads remain independently bounded. Source-sized target material, capture
manifests and blobs, artist inputs, prompt stdin, and the support index are
persisted at their actual size. Provider-authored reports are streamed and have
no fixed report-size ceiling.

For example, a repository may start with:

```gitignore
.env
.env.*
*.pem
*.key
credentials/
```

These entries are examples, not a built-in policy: repository owners remain in
control of the paths shared with their selected providers. Output redaction,
configuration credential admission, immutable workspace isolation, and provider
sandboxing remain enforced independently of capture admission.

A credential-like provider raw stream may be omitted from private diagnostics,
but that diagnostic drop does not turn an otherwise valid review into a
provider failure. Canonical final reviews and path-authorized run support retain
validated source evidence; unvalidated writes and exported projections continue
to use their existing redaction and secret-rejection boundaries.


Qualification diagnostics use the same private secure writer as review process
streams. Probe packets and version/capability streams are persisted before
fixture cleanup; scanner rejection drops the offending stream. Diagnostic run
identity allocated before child qualification does not confer admission or P2
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
read-only immutable workspace view, no write grant, and always returns on
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

## Composite evidence isolation

New composites bind copied source findings, available evidence, source receipts
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

The following requirements cover the implemented
[verified review contracts](verified-review-contracts.md) and the planned
[review completeness and iteration](review-completeness-and-iteration.md).
Brief, batch-followup, and comparison requirements remain future obligations.

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
