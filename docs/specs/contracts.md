# Contracts and artifacts

## Versioning

The public contract surface starts at v1. Configuration uses `version: 4`;
machine documents use identifiers such as `mulgae-run-manifest.v1`; prompts and
role definitions also carry v1 identities.

The initial release is a clean break from the pre-release prototype. Mulgae
does not read old command names, paths, environment variables, or schema
versions.

Composite recovery uses independent composite manifest and final-review
contracts. Published roots retain v1; failed-run recovery roots use v2.
Reruns whose source is a recovery manifest use `mulgae-run-manifest.v2` and
`mulgae-review-artifact.v2`. Existing
`mulgae-run-manifest.v1` and `mulgae-review-artifact.v1` documents retain their
ordinary review and child-run meanings and remain readable. A composite's
`review_composition` records its exact root and role sources; it never overloads
captured target `composite_identity` or child `immutable_lineage`.

The stable composition failure reasons are `composite_target_mismatch`,
`composite_target_digest_invalid`, `composite_lineage_mismatch`,
`composite_role_not_required`, `composite_role_already_satisfied`,
`composite_recovery_incomplete`, `composite_recovery_unavailable`,
`composite_selection_ambiguous`, `composite_validation_failed`, and
`composite_publication_incomplete`.

Config `version: 4` is additive rather than frozen: a release may add an
optional project-policy field without changing the version, and an omitted
field keeps its documented default. Compatibility therefore runs one way. A
newer Mulgae reads a `config.yaml` written by an older Config v4 release, but
the YAML decoder rejects unknown fields, so an older Mulgae rejects a file that
a newer one wrote with `config_yaml_invalid`. Because `config.yaml` is the Git-shareable
authority, every collaborator on a project must run a Mulgae at least as new as
the release that last wrote that file. Raising the config version instead would
not help: an older binary still could not read the newer file, and every
existing project would additionally have to re-initialize, since earlier
versions are rejected rather than migrated.

## Configuration

Configuration has two authorities:

```text
<canonical-project-root>/.mulgae/config.yaml
<canonical-project-root>/.mulgae/local.yaml
```

The Git-shareable `config.yaml` selects provider families and models, role
assignments, validation policy, resource ceilings, and CI thresholds. The
untracked, mode-`0600` `local.yaml` supplies the native home and provider
executable, ZCode app-bundle, and Codex credential-home paths. Neither file can add arbitrary
provider commands. Mulgae admits them only as a matching pair and reports their
merged value through `config --mode effective` and field ownership through
`config --mode provenance`. Provider stdout and stderr have no configurable or
fixed product byte ceiling.

Codex may additionally declare a Git-shareable
`default_credential_profile` and role-level `credential_profile` overrides.
The matching local authority contains the exact, lexically ordered
`credential_homes` entries. Those paths identify credential sources only:
Mulgae projects `<home>/auth.json`, never the home's `config.toml`, rules,
skills, plugins, or other contents. When the named fields are absent, the
legacy singleton uses `<native_user.home>/.codex`. Named and legacy forms are
both Config v4; partially named or unmatched pairs are rejected.

For ZCode, Mulgae descriptor-anchors the native
`<native_user.home>/.zcode/cli/config.json` source. When present, each isolated
invocation receives an exact legacy copy plus a generated
`.zcode/v2/provider_config.json` containing the equivalent supported personal
provider, model, and default-selection rules. Unselected provider-ID collisions
follow ZCode's last-wins import behavior; a collision involving the selected
provider fails closed as ambiguous. Mulgae rejects a selected provider or model
that cannot be imported and applies the admitted selection before it sends the
review prompt. Desktop and account sign-in state is not projected.
This conversion is required because current ZCode app-server does not run the
launcher's standalone legacy import. The local
authority records only the canonical ZCode app bundle. Mulgae derives and binds
the app-owned Electron runtime, bundled `zcode.cjs`, and built-in provider
configuration, then launches app-server with `ELECTRON_RUN_AS_NODE=1`.

`mulgae init` creates both files in a new project. When a clone already has the
shared file, init creates only the missing local file and rejects project-policy
options. `init --refresh-local` atomically replaces only `local.yaml` and
rejects project-policy options. Earlier config versions, including v2, are
rejected and are never migrated automatically.

Manual Config v3 migration changes both `version` fields to `4`. In the ZCode
local entry, remove `node_executable` and `launcher`, then set `app_bundle` to
their canonical containing app bundle. The standard value is
`/Applications/ZCode.app`. The shared policy must be valid Config v4 before
`init --refresh-local` can rebuild the local authority.

Each Config v4 pathname is installed atomically, but initial creation of the two
files is not one filesystem transaction. If `config.yaml` commits and the local
install fails before commitment, init returns `committed: false`,
`write_state: project_committed_local_missing`, `destination_state: present`,
and retryable reason `init_local_write_failed`. Here `destination_state`
describes the stable `config_uri`; the write state records that no matching
local authority was admitted. After resolving any conflicting local pathname,
plain `mulgae init` resumes from this supported shared-only state without
rewriting project policy. A failure after `local.yaml` installs remains
`installed_unconfirmed` because the complete pair may already be durable.

The existing `config_uri` remains `.mulgae/config.yaml` as the stable public
project-policy URI. Configuration SHA-256 fields bind a domain-separated,
ordered framing of both canonical files so a change to either authority changes
the effective configuration identity. Provenance uses `project`, `local`,
`default`, and `code` sources.

The build-owned role document at `assets/roles.yaml` supplies the *initial*
role-to-provider assignment and artist input defaults that `mulgae init` writes.
That is a generation-time default only: once the shared file exists, its policy
is never re-derived from embedded bytes.

For a new project that selects Grok, init writes `grok-4.7` and `high` as the
project-owned model and reasoning-effort policy unless that dimension has an
explicit init override. This generation-time default does not reinterpret an
existing Config v4 file: an absent field there continues to select Grok's
provider default independently.

See the complete shared
[`project-config.yaml`](../../internal/builtin/assets/examples/project-config.yaml)
and machine-local
[`local-config.yaml`](../../internal/builtin/assets/examples/local-config.yaml)
examples.

## Execution budgets and failure reduction

Configuration v2 retains `resources.max_active_lanes` as the explicit number of
provider invocations one Mulgae process may run at once. It is not a provider
identity and does not coordinate another process or project. Machine command
and review-preflight v2 documents describe execution as
`budget.role_paths[]`; each entry identifies `role`, `provider_instance`,
`invocation_count`, `transition_count`, `invocation_timeouts`, and `deadline`.
The array contains at most the seven unique review roles, with at most two
invocations and one transition per role path. The second slot is exactly one of
a same-provider retry after `provider_unavailable`/`provider_turn_failed`, a
constrained repair after eligible invalid output, or a structured extraction
after a role is accepted with a free-form report only; it can never be more
than one.

The capacity-aware run deadline and `role_path_deadline` ceiling include the
configured provider timeout for every possible invocation. Immediately before
provider execution, Mulgae requires enough remaining enclosing budget to grant
the complete provider timeout window. If that window cannot be guaranteed, the
provider is not started and the enclosing execution timeout is reported. A
provider process that starts and reaches its own timeout remains a distinct
provider-observed timeout.

Independent failures are reduced through one operational precedence before
runtime status or CLI exit projection: internal, artifact, security,
cancellation, configuration, login-required, invalid provider output, then
provider failure classes. Consequently, a cancellation or deadline observed
while a typed publication, security, or internal failure is being returned does
not hide the higher-precedence failure. Pure cancellation and deadline outcomes
continue to use exit 9.

Recovery retention refusal does not replace the original execution failure or
its exit. An independently failing mandatory provider drain, abort, or workspace
cleanup remains subject to the same operational precedence and may determine the
final failure class and exit. This distinction does not add a public failure
class or status enum.

Failed-run recovery retention is a cooperative ten-minute process-lifetime
budget, not a public command contract. Public JSON, schema versions, and exit
codes are unchanged. An expired retention context refuses further preparation,
sealing, and persistence, and must not install a new recovery manifest. Workspace
release that already completed remains the actual receipt state. Mandatory
cleanup after that refusal still follows the ordinary detached drain policy.

## Embedded versioned contracts

Schemas use JSON Schema Draft 2020-12 and live in
[`internal/builtin/assets/schemas`](../../internal/builtin/assets/schemas).
The catalog selects one current schema for each source kind and retains the
documented predecessors needed for backward reads. Every schema has one paired
valid example. The catalog covers command, doctor, and MCP tool results,
provider/platform evidence, provider review values, repair and validation
values, run/final artifacts, clean/export values, and the embedded file catalog.
`mulgae-mcp-tool-result.v1` is the common structured
content envelope for MCP tools. It binds a Mulgae-issued request identity and
tool name to `success`, `request_changes`, or a typed `error` outcome. The
error object always carries nullable `session_id` and `run_id` fields. They are
both non-null only when Mulgae allocated that exact run before failure. `get_run`
returns `kind: status_read` for the ordinary verified publication-status path,
including P0 and P1 observations, and for a verified retained failed/cancelled
recovery. Only when publication is absent and a completed `failed` or `cancelled`
diagnostic status survived a typed publication-not-found result does it return
`kind: diagnostic_status_read` with `publication_authority: false`, no artifact
or report URI, and `recovery_action: rerun_review`. When artifact failure wins
the existing precedence while reading status, the query layer retains a safe
`corrupt` status with the known identity and
`failed_run_recovery.unavailable_reason: source_invalid` alongside the typed
artifact failure; public CLI and MCP adapters emit the typed error and do not
expose that status as a successful result. Pure cancellation, security,
configuration, and internal query failures return their typed error without a
status projection. If neither durable status exists it returns the
non-retryable artifact error `run_status_unavailable`; allocation identity or a
nonterminal diagnostic snapshot alone does not claim durable queryability.
Both status forms may include `diagnostic_summary`. This bounded projection
contains the failed invariant identity, component, and phase, Mulgae-owned
provider, attempt, and invocation identities, the protocol terminal state, and
domain-separated SHA-256 fingerprints of provider session and turn identifiers.
Raw provider identifiers remain private. The publication-status path accepts
the summary only from a diagnostic record with the same session identity.
`run_review` failures are not retryable because another call
creates a distinct run. `start_review` is also non-idempotent and returns the
Mulgae request identity as its process-local invocation identity. A successful
start reports `state: running` and `cancellation_requested: false`; it does not
claim durable run allocation. `await_review` accepts exactly that `i_...`
identity, waits eventfully, and returns the same bounded terminal outcome and
run identity as `run_review`, plus the exact `invocation_id` it observed.
Repeated terminal awaits do not re-execute the
review. Cancelling or timing out an await returns retryable `await_cancelled`
without cancelling execution. `cancel_review` is an idempotent mutation: only
the first active cancellation reports `cancellation_accepted: true`, and every
acknowledgement remains nonterminal. Unknown invocation identities return
non-retryable `invocation_not_found`. The registry retains at most 64 identities.
Oldest terminal identities may be discarded to admit a new start; await of a
discarded identity is `invocation_not_found`. `invocation_limit_reached` is
non-retryable and occurs only when 64 reviews are still running. Identities are
discarded without recovery when the server exits. A server-ending await that can
still receive a transport result returns
non-retryable `invocation_registry_closed` rather than observer-only
`await_cancelled`. Empty stdin EOF ends the transport itself, so pending calls
may receive no response even though shutdown still cancels and drains their
server-owned reviews. Invocation state is never recovered after server exit.
When provider qualification prevents `run_review` from producing a review
result, the planner preserves every qualification failure recorded for the
selected roles. If every such failure has reason `rate_limit` and operational
precedence does not select a higher failure class, the tool returns the
readiness error code `provider_rate_limited` at stage `execution`; terminal
`await_review` preserves the same error. A mixture with another provider-class
qualification failure remains `review_unavailable`, so the narrower code does
not hide another prerequisite. A higher-precedence failure retains its normal
projection. On these mutating tools the rate-limit error is non-retryable:
another `run_review` would create a distinct run, while terminal await already
describes the completed invocation. This flag does not claim that the provider
condition is permanent. An allocated failure retains its exact session and run
identities, and terminal await also retains its invocation identity.

A rate limit observed during provider execution rather than qualification
completes the tool invocation with `outcome: success`, `terminal_exit_code: 4`,
and a `rate_limit` reason. Its run may commit with incomplete coverage and must
be inspected before recovering the failed role. Tool success in this case
describes transport and run completion, not a successful review verdict.

The tool grammar comprises `preflight_review`, `run_review`,
`start_review`, `await_review`, `cancel_review`, `compose_review`, `list_runs`,
`get_run`, and `list_findings`. An uncertain `compose_review` publication
returns `composite_publication_incomplete`, the deterministic non-null
`session_id` and `run_id`, and `retryable: false`; clients inspect that exact
run before deciding whether to repeat the same mapping. An admission rejection
before entering the publication boundary returns one of the stable composition
reason codes other than `composite_publication_incomplete`, without a
reconciliation identity, and remains safe to correct and retry. Once the
mutation enters the publication boundary, any failure, including a lock or
cancellation failure that wrote nothing, returns
`composite_publication_incomplete` with the deterministic identity. If an exact
reconciliation read reports that run as unavailable, nothing was committed and
the same exact mapping may be repeated. Before journal creation, an exact
composition replay validates and reuses the persisted candidate's review ID,
creation time, and bytes, adopts matching durable support files, and writes only
missing members. Conflicting or unsafe material fails closed; ordinary immutable
writes still reject replacement. Review targets are workspace, stage,
dirty, diff, or patch; stdio is reserved for JSON-RPC and is not a review
target. Run pages admit a limit from 1 through 100, finding responses admit at
most 1,000 summaries, and no tool result embeds report or source bodies.
`request_changes` means the review completed with a policy rejection; it is not
an MCP call failure.

The attached transport prefers MCP `2026-07-28` through `server/discover` and
admits only that version, `2025-11-25`, or `2025-06-18`. Discovery lists all
three newest first. Legacy `initialize` negotiates `2025-11-25` or `2025-06-18`;
a request naming `2026-07-28` without discovery falls back to `2025-11-25`. The
legacy handshake fixes its negotiated version for the session, so a later
request cannot claim a different version. Older versions receive the structured
unsupported-version error and the supported-version list. Each input record
must end with LF and remain within the transport frame bound. Empty EOF is a
clean client shutdown; EOF after any nonempty unterminated record is a malformed
transport and the record is never dispatched.

`run_review` honors a standard integer or at-most-128-byte string progress token
in request metadata; other token values are ignored. If admitted, progress
starts at zero, increases monotonically through periodic heartbeats, has no
declared total, and ends with a completion or stopped notification before a
non-cancelled tool result. Without a progress token no progress notification is
sent. A standard MCP cancellation notification for the call cancels its
foreground context; cancellation does not create a detached run, and no
terminal progress notification is attempted after the context is cancelled.
Progress delivery is best-effort and cannot alter the tool outcome or canonical
failure precedence.

Lifecycle tools deliberately emit no periodic heartbeat. `start_review` returns
after synchronous admission, `await_review` blocks on the registry completion
channel, and `cancel_review` only acknowledges the cancellation request. The
terminal await remains authoritative even when cancellation was requested.

The `verified_review_report` template uses
`mulgae://runs/{run_id}/report{?offset}`. The
`verified_finding_evidence` template uses
`mulgae://runs/{run_id}/findings/{finding_id}/evidence{?target_sha256,offset}`.
Every read re-resolves the project-confined run and reuses the verified report
or current-target excerpt service. A response contains at most 16 KiB and
publishes the full-content SHA-256, byte offset, chunk byte length, total byte
length, completion flag, and canonical next URI in `io.mulgae/*` metadata.
Offsets are zero-based byte offsets and must be a canonical continuation; a
report offset cannot split UTF-8. Evidence is returned as an exact-byte blob.
Composite finding summaries set `evidence_resource_uri` to `null` because
composite runs do not publish current-target evidence excerpts; their status,
findings, report, and export surfaces remain available.

Schema validation is necessary but not sufficient. Services also enforce
trusted field ownership, identity relationships, state transitions, path
locality, evidence freshness, and publication cardinality.

## Field ownership

Providers may propose finding content and evidence claims, but do not assign:

- session, run, attempt, review, or finding identities;
- target or source identity;
- provider/role identity;
- verification state;
- final content, coverage, publication, or CI outcomes.

Mulgae injects or derives those fields after validation. A constrained repair
may change only explicitly allowed provider-owned paths.

## Artifact layout

The ordinary run layout below includes an optional retained recovery namespace
for failed or cancelled runs. A top-level review file grants final-review
authority only after a verified P2 commit.

```text
.mulgae/
  diagnostics/
    s_<uuidv7>/
      r_<uuidv7>/
        status.json
        mulgae-runtime.jsonl
        qualification/
          a_<uuidv7>/
            request/stdout.raw
            version/{stdout,stderr}.raw
            capability/{stdout,stderr}.raw
        attempts/
  exports/
    r_<uuidv7>.zip
    r_<uuidv7>.manifest.json
  s_<uuidv7>/
    r_<uuidv7>/
      manifest.json
      runtime.jsonl
      attempts/
      validation/
      role-reports/
        <role>.md
      target/
        target.bytes
        target-manifest.json
        captured-review.json
        blobs/
          sha256-<hex>
      recovery/
        manifest.json
        blobs/
          sha256-<hex>
      review_<uuidv7>.json
```

A committed composite recovery run is provider-free and uses the following
self-contained delta from the ordinary run layout:

```text
.mulgae/
  s_<uuidv7>/
    r_<composite-uuidv7>/
      manifest.json
      status.json
      publication/
        journal.json
      role-reports/
        <role>.md
      support/
        index.json
      validation/
        final-candidate.json
      target/
        target.bytes
        target-manifest.json
        captured-review.json
        blobs/
          sha256-<hex>
      review_<uuidv7>.json
  store/
    epochs/
      epoch_<20-digit-number>.json
    lineage-edges/
      e_<uuidv7>.json
```

It contains no provider runtime stream, attempts, or provider validation output.
The `validation/final-candidate.json` file retains the immutable publication
candidate for interruption recovery; it is not a provider validation result.
The copied role reports, target support, immutable lineage edge, and epoch make
the composite readable after its source runs are cleaned. The captured-review
manifest and blobs are present when the root retained a captured archive.

For an ordinary run, `manifest.json` is the run index and integrity record. A
completed run has at most one top-level final review. Failed, repaired, and
extracted candidates remain beneath `attempts/`. A structured extraction
trailer adds
`attempts/<a_...>/candidate.extracted.NNN.json`,
`attempts/<a_...>/invocations/002-extract/{stdout,stderr}.raw`, and
`prompts/<a_...>/002-extract.{stdin,manifest.json}`. A role still has exactly
one attempt: the trailer is invocation 2 of that attempt, not a second attempt.

`export --run <id>` writes the redacted bundle and its sidecar manifest beneath
`.mulgae/exports/` unless the operator supplies a safe project-relative
`--output-path`. Mulgae does not modify project Git ignore configuration;
repositories should ignore `/.mulgae/*` and re-include only
`!/.mulgae/config.yaml`.

Composite exports retain findings without current-target excerpt evidence. Their
source identity names the committed composite run and review, and their current
identity contains only the target digest; no finding/excerpt identity is
fabricated. Export remains available after the source runs have been cleaned.

`target/captured-review.json` is a reference-only v2 capture manifest. Exact
target, workspace, project-context, and evidence bytes are stored once under
`target/blobs/sha256-<hex>` and may be shared by any number of manifest entries.
Every blob and the manifest itself is independently support-indexed and verified
before rerun, followup, or delta reconstructs a captured workspace. Existing v1
single-file archives remain readable, but new publications never embed source
bytes as base64 in `captured-review.json`. The in-process handoff uses a
deterministic bundle of the same reference manifest and deduplicated raw blobs;
it does not recreate the v1 base64 JSON representation.

Source capture has no fixed file-count, aggregate-byte, per-file, diff, patch,
or stdin ceiling. Every eligible regular file is preserved byte-for-byte in the
immutable snapshot; Git comparisons expose complete `before/` and `after/`
trees, while single-tree reviews expose `current/`. `.mulgaeignore`, reserved
namespaces, canonical-path checks, and special-file rejection remain the source
admission boundaries. The exact tracked `.mulgae/config.yaml` path is an
admitted capture control and is excluded from provider inputs; every other
tracked `.mulgae/**` path is rejected. Operational execution, provider output,
diagnostics, structured publication members, and fixed-size storage reads
retain their separate limits.

Target material, capture manifests and blobs, artist inputs, prompt stdin, and
the support index are source-sized support artifacts and are persisted at their
actual size. They are not subjected to the structured control-member ceiling.

A malformed source-side or provider-view capture is reported with its typed
capture failure. Malformed preflight service projections return
`preflight_result_validation_failed`. Preflight remains execution-free and does
not create a diagnostic artifact for this failure.

Every human-readable command failure includes a stable code, public pipeline
stage, and a safe next-action hint. Machine output retains its closed reason shape;
specific reason messages remain stable, while otherwise opaque fallback
messages include the failed stage, code, and safe action.

Successful selected roles also publish exactly one Mulgae-owned free-form role
report under `role-reports/<role>.md`. Mulgae alone writes trusted publication
state; providers never write into it. Additive `manifest.role_reports[]`
records role, path, digest, byte length, `provider_instance`, selected
`attempt_id`, `content_type` (`text/markdown`), and the required `transport`
(`staged_file` or `stdout`) that carried the accepted bytes for that role. It
never invents `source_invocation_id`. CLI success envelopes expose
project-relative `role_report_uris` derived from the verified committed
manifest inventory. Attempt `stdout.raw` remains private capture evidence and
is never the primary report URI.

`transport` is adapter-owned per provider family, not configurable. ZCode and
Grok review invocations use `staged_file`; Codex uses `stdout`. For Codex,
`stdout` carries the final assistant message extracted from correlated
app-server stdout frames. The raw frame stream remains private process
evidence and is never a report.
For a failed review invocation, model-authored stdout remains private process
evidence but never classifies a native provider condition; stderr has that
authority. Qualification may classify native failures from both stdout and
stderr after a process failure or failed capability-proof validation.
ZCode review and qualification invocations speak the ZCode app-server protocol:
the adapter launches the app-owned Electron runtime as
`[runtime, launcher, app-server, --stdio]` with `ELECTRON_RUN_AS_NODE=1` and
delivers every packet inside one newline-delimited protocol conversation over
the child's stdin and stdout, so no prompt, mode, or tool policy ever appears on the argv. The
conversation's turn completion, not child exit, is the provider's terminal
review fact. A protocol failure remains a provider failure when bounded process
teardown ends the app server with SIGTERM; that signal does not invalidate the
driver's recorded session receipts. Protocol stdout transcripts are never
report content. When ZCode emits a quota marker with the generic
`Turn execution failed` diagnostic, quota determines the typed outcome. When it
emits the native `rate_limit_error` token or the recognized provider
business-error marker with that generic diagnostic, the explicit marker
determines the typed rate-limit outcome while the protocol session and process
evidence remain attached. Other rate-limit prose does not override the generic
turn-failure classification.

Grok review, extraction, qualification, and heartbeat invocations speak ACP v1
over stdio. Review output is accepted only from the exact staged
`role-report.md` after one correlated `allow_once` permission for the matching
session, tool-call ID, edit kind, `Write` variant, and absolute destination.
Qualification and extraction use only correlated assistant-message chunks.
Protocol negotiation, authentication, session completion, permission denial,
and teardown failures retain typed provider causes. Optional
`providers.grok.model` and `providers.grok.reasoning_effort` values come only
from Git-shareable project policy. Omitted dimensions preserve Grok's provider
defaults independently in an existing Config v4 file. New initialization writes
`grok-4.7` and `high` unless the corresponding dimension is explicitly
overridden. Mulgae preserves configured spelling, binds both values to
qualification identity, and requires exact ACP acknowledgement before any
prompt; rejection or normalization fails closed without fallback.

Codex review, extraction, and qualification use one ephemeral app-server thread
and one turn per invocation over stdio. Mulgae sends `initialize`,
`thread/start`, and `turn/start`, then accepts the final assistant message only
after the matching `turn/completed` reports success. Qualification constrains
that message with its fixture schema through `turn/start.outputSchema`.
Unexpected server requests, loaded instruction sources, malformed frames,
missing final text, and failed or missing turn completion fail closed. Codex
provider qualification requires 0.154.0 or newer; the separate Codex MCP
client minimum remains 0.149.0.

Exact replay (`rerun --replay exact`) preserves the source attempt's framed review
input and provider route. On a `staged_file` route Mulgae replaces only the
expired Mulgae-owned output-destination layer with a fresh per-launch grant;
stdout routes preserve their complete stored stdin bytes.
Followup, delta, recomposed rerun, and rerun record `transport` identically,
read from the terminal observation of the selected attempt.

New rerun publications also persist the exact `source_attempt_id` in their
immutable lineage. The field is optional in the v1 schema so existing v1
artifacts remain readable, but composite recovery admits only reruns that carry
this binding. Followup and delta lineage must not carry it.

On a `staged_file` route the provider writes exactly one untrusted file,
`role-report.md`, into a fresh per-invocation staging directory Mulgae creates
under the provider's disposable namespace scratch area, outside the sealed
workspace view and outside `.mulgae`. The prompt's last trusted layer,
`review:output-destination`, states that exact absolute path; a staged launch
whose packet does not carry its own destination layer fails closed before the
process starts. After the process has fully terminated, the adapter validates
the staged file through the descriptors it retained at creation, reads those
exact bytes, and runs the same acceptance pipeline as stdout bytes: free-form
primary, optional structured extraction, one constrained repair. Accepted bytes
are copied into the Mulgae-owned `role-reports/<role>.md`; the provider-owned
inode is never published. Staging is always removed. Process stdout and stderr
stay bounded private diagnostics for a staged launch, and standard output is
ignored for acceptance.

Staged-file failures are classified, not merged. A missing, empty,
whitespace-only, non-UTF-8, or NUL-bearing staged file
is an operational invalid-provider-output outcome, so the one constrained repair
may still run. A staging boundary violation is a security fail-closed outcome
that never authorizes repair or publication: a symbolic link, an extra hard link,
a non-regular file, an extra directory entry, ownership, mode, or descriptor
identity drift, content that changed while it was read, or a staging path this
adapter did not itself choose. Staging that Mulgae cannot prove it removed is
an artifact failure that overrides provider success.

Markdown/prose is normal success. Mulgae records
`structured_extraction_status` as `structured`, `mixed`, or `reports_only`.
A role may reach `structured` either because the provider returned exact JSON or
because the Mulgae-owned structured extraction trailer transcribed its accepted
report. `attempts[].parse_state` and `attempts[].validation_state` therefore
describe Mulgae's structured extraction coverage for that attempt, not whether
the provider's stdout happened to be JSON. `manifest.role_reports[]` is
unaffected: `path`, `sha256`, `byte_length`, `attempt_id`, `provider_instance`,
and `transport` continue to describe the accepted free-form bytes and the
invocation that carried them. Extraction itself is always `stdout` and receives
no staged-file write grant. Extraction and repair share the one second
invocation a role may use, so `budget.role_paths[].invocation_count` stays `2`
and no preflight or command-result contract version changes.
A transcribed finding is a provider claim, not a Mulgae assertion that the
accepted report made it: Mulgae cannot verify that correspondence, so it admits
a transcription only when every finding reached `evidence_state: verified`
against the immutable target. Unlike the direct structured path, the configured
`validation.evidence.require_verified_for` severities are a floor here rather
than the rule — one unverified finding rejects the whole transcription and the
role stays `reports_only`. A reader distinguishing transcribed findings from
provider-authored ones reads the attempt's invocation inventory: a transcription
carries `002-extract`.
Legacy exact provider-review JSON remains accepted: Mulgae preserves the exact
adapter-extracted assistant bytes as the role report and, when structured
validation succeeds, also retains validated findings. Findings listing and
followup-by-finding admission remain structured-path only; prose-only roles do
not invent findings. Followup output is free-form primary: a successfully
published followup always exposes exactly one `role_report_uris` entry. Optional
structured followup resolution is extracted only when schema, semantic, and
evidence checks succeed (`resolution` enum +
`structured_extraction_status=structured`). When structured extraction is
absent or invalid, Mulgae still commits the role report with
`resolution=null` and `structured_extraction_status=reports_only` and does not
invent `unclear`. `content_verdict` may be `reports_only` when no structured
findings were extracted. Severity thresholds and CI `request_changes` continue
to use only validated structured findings and structured followup resolution.

Diagnostic-only failed runs have no publication authority. `mulgae status
--run <id> --output json` first resolves the publication namespace and, only
when that run is absent, returns the bounded `diagnostic_status_read`
projection from `diagnostics/.../status.json`. The command never exposes raw
provider streams, provider session or turn identifiers, or the runtime JSONL
through this degraded projection. A terminal protocol or
observation-invariant event may contribute the bounded `diagnostic_summary`
described above.

Diagnostic-only status reports `recovery_action: rerun_review`. Runtime
diagnostics and provider streams are not validated publication material, so an
unpublished run cannot be resumed or queried through `findings`. Publication
failures additionally report a stable `terminal_cause` and redacted
`terminal_phase`; installed artifact paths remain absent until P2 commits.
Publication causes distinguish candidate, evidence, schema, serialization,
store-lock, path-preparation, persistence, installation, and commit failures.
`diagnostic_persistence_failed` is reserved for failure to write or finalize
the diagnostic record itself; it does not replace an earlier publication
cause.

Runtime event logs and diagnostic-only run status use the role-path vocabulary
(`role_path_scheduled`, `role_path_started`,
`role_path_completed`, `role_path_cancelled`, and `role_path_*` status counts).
Current writers emit `mulgae-runtime-log.v4`,
`mulgae-runtime-run-status.v3`, and `mulgae-runtime-invocation-status.v2`.
Run-status query and cleanup readers retain v2 compatibility but reject v1
documents and old lane-named fields with the typed unsupported-contract error.
Run-status resume and write paths require the current v3 contract.

`review`, `followup`, `delta`, `rerun`, and `compose` create distinct runs. They
respectively start a review, check one prior finding, review a delta, repeat a
selected attempt, or construct one composite run from an exact incomplete root
and exact recovery runs.

Composition requires an accepted result for every role selected by the root,
including roles whose persisted `required` flag is false. It preserves those
flags and every accepted root result; a failed selected role cannot be omitted
from a new complete composite. `composite_recovery_incomplete` rejects mappings
that leave any selected role unrecovered. The retained compatibility code
`composite_role_not_required` means the recovery role was not selected by the
root, not that its configured `required` flag is false.

Existing v1 composite artifacts remain readable without rewriting their stored
coverage. New composition requests, including repeated mappings, must satisfy
the selected-role coverage rule. A v0.1.19 mapping that omitted a failed optional
role is therefore rejected until that role's exact recovery is included. Exact
mappings that satisfy admission retain their deterministic identity and
idempotent publication. Accepted degraded results retain the existing composite
coverage and CI behavior.

## Output and exits

`mulgae version --json` returns exactly `name` and `version`. Once parsing has
produced a contract-valid request, workflow commands use `--output json` and
return a `mulgae-command-result.v12` envelope. Rejected JSON `init`, `followup`,
`delta`, `rerun`, and `compose` requests also return that envelope.
`request_state: invalid` means syntax was rejected before selector I/O and is
available for all five commands. `request_state: unresolved` is available only
for `followup`, `delta`, and `rerun`, whose project-root or selector resolution
can fail before execution. Child selector failures preserve cancellation and
typed artifact or security exits; only an unclassified resolver failure uses
exit `10` and `selector_resolution_failed`.

Command-result v5 through v11 remain readable but are never emitted by the
current command surface. Other commands do not have rejected-request variants
in v9.
For the top-level `review` command, attributed provider execution details in v9
preserve the assigned role and provider in the reason message. A rate-limited
attempt adds the stable code `provider_rate_limited`, readiness exit `4`,
`retryable: false`, and the `mulgae rerun` next-action hint. A committed
incomplete review also retains the coordinator's `rate_limit` reason. The
`retryable: false` flag describes the non-idempotent command mutation, not the
duration of the provider-side rate limit. Qualification-stage rate limits
instead use `provider_qualification_failed` with `retryable: true`.

Malformed provider frames and general output decoding failures retain the
`provider_output_decode_failed` reason. If a ZCode frame is valid and names the
recognized `computer-use/operation-event` method but its payload cannot be
decoded, Mulgae instead preserves `provider_protocol_event_decode_failed` in
runtime diagnostics, the final review's failed role outcome, run-manifest
failure records, CLI results, and MCP review-tool result reasons. Both reasons
are fail-closed invalid-output outcomes and do not expose the provider transcript.

If one of the commands without a rejected-request variant fails before a
contract-valid request can be frozen, it returns the typed exit and human stderr
even when `--output json` was requested. For example, `export --run latest` with
no committed run returns artifact exit `7` without fabricating an `export`
request envelope. `compose` accepts only exact run IDs and returns the exact
mapping, deterministic composite identity, outcome axes, and reconciliation
state.
`status_required` directs the caller to inspect that run ID instead of blindly
retrying. `retry_safe` is the mutation-level signal: it is `true` when repeating
the same exact mapping is known to be safe because it was not committed or its
successful publication is idempotent, and `false` only for `status_required`.
Reason-level `retryable` remains `false` for composite failures and is not a
substitute for `retry_safe`. Command result v2/v3/v4 and review-preflight v2 are
intentionally unsupported after this contract revision.
Composition admission failures return artifact exit `7` with their stable
composite reason code because Mulgae validates the caller's exact mapping
against committed run artifacts.
Process
exits:

| Exit | Meaning |
|---:|---|
| 0 | success |
| 1 | policy outcome |
| 2 | invalid usage or configuration |
| 4 | provider or readiness unavailable |
| 7 | artifact or integrity failure |
| 8 | security policy failure |
| 9 | cancellation |
| 10 | internal failure |

An untyped failure in one of the closed preparation steps after review planning
accepts the run budget but before the coordinator durably records `run_started`
is a Mulgae preparation failure, not provider readiness evidence. This includes
the coordinator admission prologue; failures after the durable start remain
coordinator execution outcomes. CLI and MCP results report
non-retryable `review_preparation_failed` and retain the allocated run identity.
CLI additionally uses exit `10`, the detailed `review.prepare.<stage>` stage,
the diagnostic artifact URI, and the exact command
`mulgae status --run <id> --output json`. MCP retains its versioned `execution`
stage and carries the closed preparation detail plus the `get_run` instruction
in the safe message; its tool error has neither an exit code nor an artifact URI.
The diagnostic run records the stage in `diagnostic_summary` and a closed
preparation-specific `terminal_cause`; it never exposes the causal error text.
A typed provider, artifact, security, or cancellation failure that directly
caused preparation retains its original class. Independent joined cleanup
failures do not erase a preparation failure. A runtime-diagnostic persistence
failure anywhere in the terminal error tree, including one raised by cleanup,
outranks preparation and remains an artifact failure.
`mulgae doctor` remains an offline static check and is not the remediation for
this internal failure.

CI decisions derive from committed artifacts. Provider output or an uncommitted
candidate has no CI authority.

`mulgae doctor --output json` returns `mulgae-doctor-result.v5`. Capability
detection starts with `schema_version`; consumers of an older result must treat
an absent v2 dimension as unsupported, never as failed. The result reports
`config_v3`, `local_configuration`, and `provider_identity` independently, and
each dimension uses exactly `verified`, `failed`, `unverifiable`, or
`not_applicable`. Provider and role identifiers are fixed, redacted family/role
IDs; executable paths, native homes, credentials, and local configuration values
are not projected.
`config_v3` is a frozen v4 result member name retained for compatibility; it
evaluates the current Config v4 project and local authorities.

Each configured `provider_inventory[]` row reports `binary_available`,
`cli_compatible`, and `application_compatible`. The application dimension is
`not_applicable` outside ZCode. For ZCode it reports the independently observed
`CFBundleShortVersionString`, minimum 3.12.3, and verified-latest 3.12.3;
higher versions remain eligible as `newer_than_verified`.
Binary observation revalidates the exact adapter-owned regular
file through descriptor-safe identity and permission checks. ZCode requires an
executable app-owned Electron runtime, a readable regular `.cjs` launcher, the
launcher's readable built-in provider config, and descriptor-bound
`Contents/Info.plist` metadata. The launcher and provider
config do not require an executable bit. CLI compatibility runs only the admitted direct
`[executable, "--version"]` or ZCode
`[runtime, launcher, "--version"]` command with `ELECTRON_RUN_AS_NODE=1` in a
disposable empty home, with no credential projection or project working
directory. It emits the normalized observed version, current minimum and verified-latest guidance, eligibility,
and compatibility. A version above `verified_latest` preserves the existing
eligible policy while using compatibility `newer_than_verified`.

Top-level `readiness` and `configured_readiness` require every configured
provider to pass binary availability and remain eligible under every applicable
version policy.
`role_route_readiness` separately reports whether every enabled role route is
eligible. Static-admission evidence is not consulted by doctor and cannot gate
offline readiness. `mulgae providers --output json` exposes the independent
`offline_ready_provider_count` and `static_evidence_ready_provider_count`; its
human static profiles remain `unverified` when no static source exists. A
successful or failed live review never mutates these offline observations.

Stable doctor reasons are grouped as follows:

| Dimension | Reason codes |
|---|---|
| Config/local | `config_missing`, `local_config_missing`, `config_yaml_invalid`, `config_size_invalid`, `config_provider_timeout_invalid`, `config_credential_key_detected`, `config_credential_value_detected`, `config_locality_unsafe`, `config_locality_drifted`, `native_home_mismatch` |
| Provider/role identity | `config_provider_identity_invalid`, `config_role_mapping_invalid` |
| Binary | `provider_executable_missing`, `provider_executable_not_executable`, `provider_binary_observation_failed`, `provider_executable_unsafe_identity`, `zcode_launcher_missing`, `zcode_launcher_unreadable`, `zcode_launcher_observation_failed`, `zcode_launcher_unsafe_identity`, `zcode_provider_config_missing`, `zcode_provider_config_unreadable`, `zcode_provider_config_observation_failed`, `zcode_provider_config_unsafe_identity`, `zcode_application_metadata_unreadable`, `zcode_application_metadata_observation_failed`, `zcode_application_metadata_unsafe_identity`, `zcode_application_version_malformed`, `zcode_application_version_below_minimum`, `zcode_application_version_supported`, `zcode_application_version_newer_than_verified` |
| CLI version | `provider_cli_version_supported`, `provider_cli_version_newer_than_verified`, `provider_cli_version_below_minimum`, `provider_cli_version_malformed`, `provider_cli_version_command_failed`, `provider_cli_version_timeout`, `provider_cli_version_unsafe_identity`, `provider_cli_version_observation_failed` |
| Aggregate | `provider_offline_readiness_failed`, `provider_role_route_unavailable`, `provider_security_admission_failed` |

The exact schema remains authoritative for additional locality reason codes
owned by the filesystem/Git admission boundary.

`mulgae heartbeat --provider FAMILY --authorize-live-request` is the only
standalone live diagnostic. For named Codex configurations it also accepts the
explicit `--credential-profile`. Omitting the authorization returns a versioned
`mulgae-provider-heartbeat-result.v3` with `attempted: false` before provider
composition, credential access, or process execution. An authorized heartbeat
discloses that authentication, network, cost, and remote logging may occur,
uses a bounded provider timeout, and sends only Mulgae's immutable synthetic
qualification fixture. It never includes repository source, diffs, review
prompts, or user content. Status is one of `succeeded`, `provider_failure`,
`timeout`, `authentication_failure`, `malformed_response`, or
`execution_failure`; `attempted` states whether the live request launch was
reached. Stable heartbeat reasons are `live_authorization_required`,
`heartbeat_succeeded`, `provider_failure`, `provider_timeout`,
`authentication_required`, `heartbeat_response_malformed`,
`provider_execution_failed`, and `heartbeat_cleanup_failed`.

Offline readiness, heartbeat, and review qualification are independent. A
heartbeat does not mint or persist review authority. `review_qualified` exists
only in the evidence of the explicitly requested review run that performed the
qualification; doctor/setup does not expose or gate on it, and no unrelated
review is promoted into a durable qualification cache.

## Provider content normalization and bounded retry

Provider-authored review and structured follow-up JSON is parsed with duplicate
key rejection before projection. Unknown additional fields and fields owned by
Mulgae are removed from the provider-content projection; Mulgae then injects
trusted identity and verification values. Removed values are never exposed.
Runtime diagnostics use `mulgae-runtime-log.v4` and the
`provider_output_fields_discarded` event to record only sorted JSON Pointer
paths and `discarded_path_count`. At most the first 100 sorted paths are retained
while the count records the complete number. Malformed JSON, duplicate keys,
wrong or missing required provider fields after constrained repair, unverifiable
evidence, and semantic contradictions remain fail-closed.

A transient `provider_unavailable` or ZCode `provider_turn_failed` initial
invocation receives exactly one automatic retry on the same configured provider,
attempt, role, and immutable target. The retry has a fresh execution identity
and separate runtime evidence. Timeout, rate-limit, quota, authentication,
configuration, artifact, security, malformed-output, and semantic failures are
not automatically retried. A rate limit does not cancel or serialize peer-role
invocations and does not mark the provider unusable. A retry consumes the second
invocation slot, so its output cannot also schedule repair.

## Codex MCP configuration observability

Mulgae supports Codex CLI 0.149.0 or newer. At that minimum,
`codex mcp get mulgae --json` exposes the server name, enabled state and disabled
reason, stdio transport command/arguments/environment/working directory,
enabled and disabled tool filters, and startup/tool timeouts. Codex 0.149.0 does
not expose the configured `required` value. Consumers must preserve an absent
field as unobserved and must not infer `required: false`; `config.toml` remains
the authority. Mulgae does not claim a later minimum for observing the field.
Its compatibility check accepts absence or an observed literal `true` and
rejects an observed false value when the configuration requested true.

## Provider qualification readiness

Grok CLI 1.0.34 is the minimum release for configurable selection and 1.0.40
is the latest verified release. The verified Apple Silicon binaries identify
themselves as `grok 1.0.34 (3736acbc8658) [stable]` and
`grok 1.0.40 (eb1a2256660d) [stable]`. Both releases accept selection only
through the ACP conversation: after `session/new`, Mulgae sends
`session/set_model` with the exact `modelId` and, when configured,
`_meta.reasoningEffort`. Omitting a setting leaves that dimension at the
provider default; an effort-only request reuses the current model reported by
`session/new` without guessing or persisting it.

Grok CLI 1.0.40 also acknowledges the `grok-4.7` model with `high` reasoning
effort exactly before prompting. Mulgae uses that pair only as the policy written
for newly initialized projects; existing Config v4 omission retains the generic
provider-default behavior above.

Mulgae does not send `session/prompt` until the `session/set_model` result and
the following `config_option_update` confirm the requested model and reasoning
effort exactly. Provider rejection remains a provider-execution failure;
normalization or an ignored setting is an invalid output envelope. Neither
case removes or rewrites a setting, retries with provider defaults, or changes
providers. Unknown models are rejected by the verified provider. Unknown
reasoning-effort tokens are currently normalized by Grok, so Mulgae detects
the mismatch and fails before prompting. The verified ACP contract does not
publish a model/effort compatibility catalog, so an unsupported-combination
case is not separately defined.

Review and child-run qualification preserve private request packets and nonempty
version/capability stdout and stderr under the diagnostic run before fixture
cleanup. Runtime events retain process exit/termination facts and typed rejection
causes, including empty responses. The existing secure writer screens these
streams; rejected content is dropped with metadata, never copied into public
command output or exports. Each retry has its own qualification attempt directory.
A child command allocates its diagnostic run identity before qualification and
hands the same sink to execution on success. Qualification failure leaves a
terminal diagnostic-only run referenced by the reason's `artifact_uri`; child
result identities and publication artifact URIs remain null. No manifest or P2
publication authority is created by that diagnostic identity.

Current qualification is family/runtime-profile scoped within one command:
Mulgae performs one version-plus-capability probe per distinct provider family
profile, with at most one bounded operational retry, then derives role admission
for configured role routes that share that profile. Shareable
profiles are equivalent across base argv, transport channel/reference/index,
environment, working directory, lifecycle, model, Codex reasoning effort,
executable/launcher identity, ZCode built-in provider-config identity, and
runtime safety policy identity. ZCode
qualification probes use the app-server protocol conversation in plan mode
with every tool denied; their capability evidence is the conversation's
captured assistant response text, read back through the protocol after the
turn completes, and the protocol transcript on stdout is never evidence.
ZCode qualification is additionally namespace-scoped: each role instance owns
its selected provider/model namespace and therefore performs its own probe even
when the remaining runtime profile fields match. Direct-execution authority
construction and Matches bind currentProbeRuntimeDefinitionIdentity for the
exact destination runtime, including instance. Application-layer identity
rewriting cannot copy authority between those namespaces.
Named Codex credential profiles additionally participate in qualification-group
identity. Roles using the same credential profile may share one probe; roles
using different profiles never share qualification or direct-execution
authority. Their provider instances use `codex-<profile>-<role>`. Legacy Codex
configuration retains `codex-<role>`.
Codex qualification takes evidence from its correlated final assistant
message rather than the raw protocol transcript. Required family probes,
including Codex, run concurrently. Capability readiness is decided by bound
immutable fixture evidence: free-form or narrated
provider output is accepted when it proves immutable fixture nonce/input binding
together with transport, lifecycle, authentication, version, and required
process behavior, and mere prompt echo is rejected. A terminal JSON stdout frame
is optional metadata, never a required result transport; when a frame is
present, its integrity (framing policy, byte length, stdout digest, stability
and termination timing, and packet-bound post-output signal receipts) is
enforced fail-closed. Post-output cleanup retains one total one-second deadline;
the SIGTERM grace is capped at half the remaining budget so escalation leaves
time to join the process, readers, and stdout spooler. Receiving JSON alone
does not bypass lifecycle or publication checks.
Packet-transport, lifecycle, signal-receipt, and
frame-integrity violations remain security-policy violations, while missing
fixture binding or prompt echo is instead an operational invalid-provider-output
capability rejection, not a security-policy violation. Capability packets embed
those root/link/role bindings and must not induce workspace or tool reads.
Malformed JSON, duplicate keys, missing bindings, wrong
binding types, and binding mismatches remain rejected. Review prompts own
workspace-selective guidance. Invalid capability formatting,
unbound fixture evidence, security-policy violations, and login-required
responses are never retried; one transient operational probe failure (rate
limit, quota, timeout, provider unavailable, or a typed provider execution
failure) admits at most one additional probe on a freshly materialized fixture.
When a zero-exit capability response fails fixture proof, an explicit native
provider failure is classified through the existing typed failure vocabulary
before retry policy is applied. Unbound or malformed output without such a
failure remains invalid provider output; valid fixture proof is not rejected
merely for mentioning a failure phrase.
Each local capability invocation has a three-minute upper bound.
Every acquired fixture is still drained exactly once, sibling role routes still
derive from a single successful family probe, and the retried attempt is
recorded as a rejected qualification observation carrying a retry mitigation.
There is no durable project-local qualification cache and no path that mints
direct-execution authority from project-local JSON; durable
cross-process reuse is intentionally deferred because a forgeable self-hashed
cache would weaken trust boundaries. Structured review JSON extraction remains
optional: Mulgae may apply one constrained repair, then accept free-form primary
role reports when structured validation does not succeed.

## Failed-run recovery sources

`mulgae-run-recovery.v1` is a separate immutable replay authority at
`<session>/<run>/recovery/manifest.json`. Content-addressed blobs beneath
`recovery/blobs/` retain the captured target/archive, complete initial prompts,
and accepted reports without a provider-content byte ceiling. The structured
manifest remains bounded. The manifest is installed atomically after every
blob and only after provider drain, target verification, and workspace cleanup.

The source records the original role/provider/required policy, threshold,
terminal attempts, accepted findings, and evidence verified against the
captured archive. It preserves `failed` or `cancelled` state. Security,
configuration, artifact-integrity, incomplete-input, cleanup, and storage
failures cannot authorize recovery. A present invalid source causes an artifact
failure; a missing source reports `source_not_retained`. A persisted manifest
is never reconstructed from diagnostics or an old v0.1.19 failure.

Exact failed-rerun reads verify each hash-bound parent and the original input
through at most 128 exact replay links. The stdin, source scope and invocation,
template, role, provider, target, archive, and adapter parameters must agree.
The execution invocation ID is fresh; staged-file replay may also replace only
the canonical final output-destination layer and its matching manifest receipt.
A missing, cyclic, foreign, mutated, or over-depth ancestor denies replay.
An ordinary or recomposed origin ends this traversal after its own scope has
been verified.

CLI status v8 and MCP `get_run` return `failed_run_recovery` with exactly seven
fields: `available`, nullable `source_kind`, nullable `run_id`, nullable
`manifest_sha256`, `accepted_roles`, `retry_attempts` (`role`, `attempt_id`),
and nullable `unavailable_reason`. Available sources use
`source_kind: failed_run_recovery`; unavailable reasons are
`source_not_retained`, `source_invalid`, `publication_in_progress`, and
`published_review`. Available recovery exposes only verified role inventories
and replay identity. It carries no final-review authority, final/report/
role-report URI, finding or outcome axes, provider transcript, runtime event
stream, or native path. When artifact failure wins the existing precedence,
invalid recovery returns a safe corrupt query status with the known session and
run identity and `source_invalid` alongside the typed artifact failure; public
CLI and MCP adapters emit the typed error and do not expose that status as a
successful result. Pure cancellation, security, configuration, and internal
query failures return no recovery status. The typed failure preserves the
existing operational precedence.
The publication `recovery_action` describes publication reconciliation, not
permission to launch a role. An available recovery may expose failed/cancelled
run state while publication remains `not_published`, without final paths,
role-report paths, content/coverage axes, or CI authority.

Exact rerun accepts only a failed attempt from that source, retains its original
provider and input, and records `source_kind: failed_run_recovery` with
`source_recovery_manifest_sha256` in v2 lineage. `source_review_id` is null.
A failed rerun may itself become a recovery source after the same checks.
Composition follows at most 128 same-role lineage links and requires one
committed recovery for every missing selected role. Its v2 provenance uses
`root_source_kind` and `root_recovery_manifest_sha256`; it omits
`root_review_id`. The root source entry and root-derived role/finding references
use the root recovery hash with `source_kind: failed_run_recovery`. Each selected
committed rerun retains its committed rerun review identity with
`source_kind: published_review`: composition source entries and finding sources
use `review_id`, while role outcomes use `source_review_id`. Their recovery
variants use `recovery_manifest_sha256` in composition source and finding source
objects, and `source_recovery_manifest_sha256` in role outcomes. The root hash
participates in the new deterministic composition fingerprint; v1 fingerprints
are unchanged.

Recovery sources remain protected as uncommitted artifacts during cleanup.
Their source edges retain required ancestors, including a published parent of
a failed rerun. Cleanup validates bounded manifest metadata and confirms its
identity without reading input or report blobs. Replay and status reads still
verify all blobs and captured evidence. Normal findings, report, and export
readers still require P2.
No new command, automatic provider substitution, crash recovery, or unlimited
retry loop is introduced. CLI v5/v6/v7/v8/v9 schema examples remain available
along with v10 for explicit backward validation; current CLI envelopes use v11. MCP retains its v1
common envelope, whose `data` object carries the extended status projection.
