# Contracts and artifacts

## Versioning

The public contract surface starts at v1. Configuration uses `version: 2`;
machine documents use identifiers such as `mulgae-run-manifest.v1`; prompts and
role definitions also carry v1 identities.

The initial release is a clean break from the pre-release prototype. Mulgae
does not read old command names, paths, environment variables, or schema
versions.

## Configuration

Configuration has two authorities:

```text
<canonical-project-root>/.mulgae/config.yaml
<canonical-project-root>/.mulgae/local.yaml
```

The Git-shareable `config.yaml` selects provider families and models, role
assignments, validation policy, resource ceilings, and CI thresholds. The
untracked, mode-`0600` `local.yaml` supplies the native home and provider
executable, launcher, and data-home paths. Neither file can add arbitrary
provider commands. Mulgae admits them only as a matching pair and reports their
merged value through `config --mode effective` and field ownership through
`config --mode provenance`.

`mulgae init` creates both files in a new project. When a clone already has the
shared file, init creates only the missing local file and rejects project-policy
options. `init --refresh-local` atomically replaces only `local.yaml` and
rejects project-policy options. Config v1 is rejected and is never migrated
automatically.

Each Config v2 pathname is installed atomically, but initial creation of the two
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

See the complete shared
[`project-config.yaml`](../internal/builtin/assets/examples/project-config.yaml)
and machine-local
[`local-config.yaml`](../internal/builtin/assets/examples/local-config.yaml)
examples.

## Execution budgets and failure reduction

Configuration v2 retains `resources.max_active_lanes` as the explicit number of
provider invocations one Mulgae process may run at once. It is not a provider
identity and does not coordinate another process or project. Machine command
and review-preflight v2 documents describe execution as
`budget.role_paths[]`; each entry identifies `role`, `provider_instance`,
`invocation_count`, `transition_count`, `invocation_timeouts`, and `deadline`.
The array contains at most the seven unique review roles, with at most two
invocations and one initial-to-repair transition per role path.

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

## Embedded versioned contracts

Schemas use JSON Schema Draft 2020-12 and live in
[`internal/builtin/assets/schemas`](../internal/builtin/assets/schemas).
The catalog contains one current schema/example pair for command, doctor, and
MCP tool results, provider/platform evidence, provider review values, repair
and validation values, run/final artifacts, clean/export values, and the
embedded file catalog. `mulgae-mcp-tool-result.v1` is the common structured
content envelope for MCP tools. It binds a Mulgae-issued request identity and
tool name to `success`, `request_changes`, or a typed `error` outcome. The
error object always carries nullable `session_id` and `run_id` fields. They are
both non-null only when Mulgae allocated that exact run before failure. `get_run`
returns `kind: status_read` for publication-backed state or, only when
publication is absent and a completed `failed` or `cancelled` diagnostic status
survived,
`kind: diagnostic_status_read` with `publication_authority: false`, no artifact
or report URI, and `recovery_action: rerun_review`. If neither status exists it
returns the non-retryable artifact error `run_status_unavailable`; allocation
identity or a nonterminal diagnostic snapshot alone does not claim durable
queryability. `run_review` failures are not retryable because another call
creates a distinct run. The initial tool
grammar comprises `preflight_review`, `run_review`, `list_runs`, `get_run`, and
`list_findings`.
Review targets are workspace, stage, dirty,
diff, or patch; stdio is reserved for JSON-RPC and is not a review target. Run
pages admit a limit from 1 through 100, finding responses admit at most 1,000
summaries, and no tool result embeds report or source bodies. `request_changes`
means the review completed with a policy rejection; it is not an MCP call
failure.

The attached transport prefers MCP `2026-07-28` and admits only that version,
`2025-11-25`, or `2025-06-18`. Discovery lists all three newest first. A legacy
`initialize` fixes its negotiated version for the session; a later request
cannot claim a different version. Older versions receive the structured
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

```text
.mulgae/
  diagnostics/
    s_<uuidv7>/
      r_<uuidv7>/
        status.json
        mulgae-runtime.jsonl
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
      review_<uuidv7>.json
```

`manifest.json` is the run index and integrity record. A completed run has at
most one top-level final review. Failed or repaired candidates remain beneath
`attempts/`.

`export --run <id>` writes the redacted bundle and its sidecar manifest beneath
`.mulgae/exports/` unless the operator supplies a safe project-relative
`--output-path`. Mulgae does not modify project Git ignore configuration;
repositories should ignore `/.mulgae/*` and re-include only
`!/.mulgae/config.yaml`.

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

`transport` is adapter-owned per provider family, not configurable. ZCode
review invocations are granted `staged_file`; AGY and Kimi remain `stdout`.
Exact replay (`rerun --exact`) is always `stdout`, because a replay reproduces
the transport its original recorded rather than acquiring a fresh write grant.
Followup, delta, recomposed rerun, and rerun record `transport` identically,
read from the terminal observation of the selected attempt.

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
provider streams or the runtime JSONL through this degraded projection.

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

Runtime event logs and diagnostic-only run status use the v2 role-path
vocabulary (`role_path_scheduled`, `role_path_started`,
`role_path_completed`, `role_path_cancelled`, and `role_path_*` status counts).
Readers reject v1 status documents and old lane-named fields with the typed
unsupported-contract error; there is no compatibility shim.

`review`, `followup`, `delta`, and `rerun` create distinct runs. They
respectively start a review, check one prior finding, review a delta, or repeat
a selected attempt.

## Output and exits

`mulgae version --json` returns exactly `name` and `version`. Workflow commands
use `--output json` and return a `mulgae-command-result.v2` envelope. Command
result v1 and review-preflight v1 are intentionally unsupported after this
contract revision. Process
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

CI decisions derive from committed artifacts. Provider output or an uncommitted
candidate has no CI authority.

`mulgae doctor` reports static admission evidence only. A configured identity
with missing static evidence uses `provider_static_admission_unverified`; this
does not claim that a live review qualification failed. Per-run live
qualification remains observable through that run's diagnostic status and
runtime diagnostics.

## Provider qualification readiness

Current qualification is family/runtime-profile scoped within one command:
Mulgae performs one version-plus-capability probe per distinct provider family
profile, with at most one bounded operational retry, then derives role admission
for configured role routes that share that profile. Shareable
profiles are equivalent across base argv, transport channel/reference/index,
environment, working directory, output bounds, lifecycle, model,
executable/launcher identity, and runtime safety policy identity. ZCode may
share one probe across sibling role instances only when that full shareable
profile matches; AGY profiles also include provider instance because AGY control
evidence is instance-bound. Direct-execution authority construction and Matches
bind currentProbeRuntimeDefinitionIdentity for the exact destination runtime,
including instance. Sibling routes receive a new authority only through an
adapter-owned derivation that revalidates shareable equivalence and exact
destination Matches. Application-layer identity rewriting cannot copy authority.
ZCode and AGY family probes run concurrently when both are required. Capability
readiness is decided by bound immutable fixture evidence: free-form or narrated
provider output is accepted when it proves immutable fixture nonce/input binding
together with transport, lifecycle, authentication, version, and required
process behavior, and mere prompt echo is rejected. A terminal JSON stdout frame
is optional metadata, never a required result transport; when a frame is
present, its integrity (framing policy, byte length, stdout digest, stability
and termination timing, and packet-bound post-output signal receipts) is
enforced fail-closed. Packet-transport, lifecycle, signal-receipt, and
frame-integrity violations remain security-policy violations, while missing
fixture binding or prompt echo is instead an operational invalid-provider-output
capability rejection, not a security-policy violation. Capability packets embed
those root/link/role bindings and must not induce workspace or tool reads;
review prompts own workspace-selective guidance. Invalid capability formatting,
unbound fixture evidence, security-policy violations, and login-required
responses are never retried; one transient operational probe failure (rate
limit, quota, timeout, provider unavailable, or a typed provider execution
failure) admits at most one additional probe on a freshly materialized fixture.
Every acquired fixture is still drained exactly once, sibling role routes still
derive from a single successful family probe, and the retried attempt is
recorded as a rejected qualification observation carrying a retry mitigation.
There is no durable project-local qualification cache and no path that mints
direct-execution or AGY-control authority from project-local JSON; durable
cross-process reuse is intentionally deferred because a forgeable self-hashed
cache would weaken trust boundaries. Structured review JSON extraction remains
optional: Mulgae may apply one constrained repair, then accept free-form primary
role reports when structured validation does not succeed.
