# Contracts and artifacts

## Versioning

The public contract surface starts at v1. Configuration uses `version: 1`;
machine documents use identifiers such as `mulgae-run-manifest.v1`; prompts and
role definitions also carry v1 identities.

The initial release is a clean break from the pre-release prototype. Mulgae
does not read old command names, paths, environment variables, or schema
versions.

## Configuration

There is one configuration authority:

```text
<canonical-project-root>/.mulgae/config.yaml
```

`mulgae init` creates it without overwriting an existing file. Configuration
selects provider paths and models, role assignments, validation policy,
resource ceilings, and CI thresholds. It cannot add arbitrary provider
commands. Use `mulgae config --mode effective` for the admitted value and
`mulgae config --mode provenance` for its source.

The build-owned role document at `assets/roles.yaml` supplies the *initial*
role-to-provider assignment and artist input defaults that `mulgae init` writes.
That is a generation-time default only: once the file exists, it is the sole
authority and is never re-derived from embedded bytes.

See the complete
[`local-config.yaml`](../internal/builtin/assets/examples/local-config.yaml)
example.

## Embedded v1 contracts

Schemas use JSON Schema Draft 2020-12 and live in
[`internal/builtin/assets/schemas`](../internal/builtin/assets/schemas).
The catalog contains one current schema/example pair for command and doctor
results, provider/platform evidence, provider review values, repair and
validation values, run/final artifacts, clean/export values, and the embedded
file catalog.

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

`target/captured-review.json` is a reference-only v2 capture manifest. Exact
target, workspace, project-context, and evidence bytes are stored once under
`target/blobs/sha256-<hex>` and may be shared by any number of manifest entries.
Every blob and the manifest itself is independently support-indexed and verified
before rerun, followup, or delta reconstructs a captured workspace. Existing v1
single-file archives remain readable, but new publications never embed source
bytes as base64 in `captured-review.json`. The in-process handoff uses a
deterministic bundle of the same reference manifest and deduplicated raw blobs;
it does not recreate the v1 base64 JSON representation.

The fixed runtime limits are declared together in `internal/ports/resource_limits.go`
and validated when the production graph is composed. One captured tree admits
at most 10,000 regular files, 64 MiB total, and 4 MiB per file; a Git comparison
view admits two such trees, up to 20,000 files and 128 MiB total. Reference-only
capture manifests and other structured publication members admit 8 MiB, and
fixed-size storage reads admit 32 MiB. These limits bound untrusted source and
control metadata. They do not
cap provider-authored role reports, which are streamed and published at their
actual size.

Capture-manifest feasibility is checked before workspace materialization or
provider execution. A failure is reported as `capture_manifest_too_large` with
the actual member size, member limit, and `provider_invoked=false`; an admitted
capture therefore cannot reach providers and later fail solely because its v2
capture manifest is not publishable.

A source-side or provider-view admission failure is reported as
`capture_workspace_too_large`. Its diagnostic includes the admission stage and
member, actual and maximum file and byte counts, and `provider_invoked=false`.
The combined provider-view limit never weakens the limits on either captured
side.

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

`review`, `followup`, `delta`, and `rerun` create distinct runs. They
respectively start a review, check one prior finding, review a delta, or repeat
a selected attempt.

## Output and exits

`mulgae version --json` returns exactly `name` and `version`. Workflow commands
use `--output json` and return a `mulgae-command-result.v1` envelope. Process
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
