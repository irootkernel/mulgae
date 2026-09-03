# EPIC-002: Composite recovery for incomplete multi-role reviews

Roadmap epic: [EPIC-002](../roadmap/README.md#epic-002-composite-recovery-for-incomplete-multi-role-reviews)

## Goal

Mulgae must recover one or more missing required-role results without rerunning
successful roles, then publish one immutable composite run that is equivalent
to a complete review of the unchanged captured code target. Clients must be
able to use exact public CLI and MCP reads without joining private artifacts or
inferring completeness.

## Scope

This epic adds native composition of a committed incomplete root review and
explicitly selected, committed role reruns. It owns admission, target and
lineage verification, recomputation, publication, recovery, exact queries,
cleanup, CLI and MCP mutations, schemas, examples, documentation, and tests.

The first supported operation accepts one or more recovery runs in one request.
Each recovery must fill exactly one distinct role that is required and missing
from the root review. The request must cover every missing required role; it
cannot publish a still-incomplete composite generation.

Aquarium consumption is separate follow-up work. This epic defines the bounded
public authority that Aquarium can later accept, but it does not change another
repository or assign Aquarium review ordinals.

## Product decisions

### Exact explicit selection

Composition is always an explicit mutation over exact run identities. Mulgae
must not search for a latest or convenient recovery result. The caller supplies
one incomplete root run and one recovery run for each missing required role.
More than one eligible recovery for a role is not ambiguous because the caller
selects the exact input; duplicate role coverage in one request is rejected.

The request is bounded by the existing maximum required-role count. It accepts
at least one recovery run and no more recovery runs than the root required-role
set can contain.

### Eligibility and authority

The root must be a committed ordinary review, not a rerun or composite. Its
required-role set, accepted terminal role results, and normal review policy are
authoritative. A selected role is eligible only when it belongs to that set and
does not already have an accepted terminal result.

Each recovery must be a committed rerun whose verified transitive lineage ends
at a failed attempt for the same missing root role. The rerun result must pass
the ordinary validation, evidence, normalization, integrity, and publication
checks required for an accepted role result. Provider exit success alone is
insufficient.

The root and every recovery must carry the same valid canonical immutable
target-content digest. For staged targets this is the preserved staged capture,
never the current live index. Digest absence, invalidity, mismatch, or
unverifiable lineage fails closed. Repository path, branch, target kind,
provider, model, prompt, template, configuration, sampling, and time metadata
are recorded as provenance where public and safe, but are not additional
composition gates.

### Composite identity and immutability

Successful composition creates a new immutable run with `run_type` set to
`composite`. It has its own exact run identity and a distinct
`review_composition` object. The existing `composite_identity` field continues
to describe captured target identity and must not be overloaded with review
composition semantics.

The composite is self-contained for normal status, findings, report, export,
and cleanup behavior. Publication copies the selected verified role reports and
required target support into the new run; it does not depend on source runtime
files for subsequent reads. Complete provider stdout, stderr, prompt payloads,
and role reports retain their existing no-product-byte-ceiling behavior, while
bounded public projections expose only safe structured provenance.

The root and recovery runs remain immutable and independently queryable. A
composite never rewrites them or presents later execution as concurrent with
the root review.

### Determinism and idempotency

The composition fingerprint includes the exact root identity plus the sorted
mapping from each recovered role to its selected recovery run and accepted
attempt. The same selected inputs return the same composite identity and exact
outcome. A different exact recovery selection is a different request and may
produce a separate immutable composite; no request gains authority through an
implicit latest rule.

Publication is atomic and uses the existing attempt, validation, integrity, and
manifest authority model. Failed candidates remain non-authoritative in their
documented attempt locations. Exact retry or reconciliation reports whether the
same request already committed, is incomplete, or failed.

### Effective review outcome

The application recomputes coverage, findings, content verdict, and
`ci_decision` from the selected accepted role results under the root review
policy. `coverage_status` is `complete` only when every required root role has
exactly one accepted terminal source.

Finding-local identifiers are not globally trusted. The composite assigns new
stable finding identities from the composite identity and source coordinates,
retains each finding when source-local IDs collide, and records the contributing
run, attempt, and role as provenance.

## Public interface

### CLI

The mutation is:

```text
mulgae compose --root-run <r_...> --recovery-run <r_...> [--recovery-run <r_...> ...]
```

It accepts exact IDs only. Human output identifies the committed composite or
the exact reconciliation state. Structured output uses the versioned command
result envelope and includes at least the exact composite run identity,
`run_type`, publication status, shared target-content digest, recovered roles,
coverage status, content verdict, `ci_decision`, and retry-safe reconciliation
fields.

Existing exact-run status, findings, report, and export commands accept the
composite run identity without client-side merging. Existing selectors retain
their documented meanings; `latest` is never a substitute for exact composition
input or reconciliation.

### MCP

MCP adds the bounded mutation `compose_review` with `root_run_id` and a
non-empty bounded `recovery_run_ids` array. It returns the same authoritative
fields as CLI structured output within the existing MCP result envelope.
Existing exact status and findings tools read the returned composite identity.

CLI and MCP share one application use case and must agree on admission,
reason codes, identities, publication state, coverage, findings, verdict, and
CI decision. The MCP protocol version remains unchanged unless implementation
discovers a real wire incompatibility; any public command-result schema change
is introduced as the next version while older result versions and existing v1
run artifacts remain readable.

### Stable reason codes

The public error model adds stable reason codes for:

- `composite_target_mismatch`
- `composite_target_digest_invalid`
- `composite_lineage_mismatch`
- `composite_role_not_required`
- `composite_role_already_satisfied`
- `composite_recovery_incomplete`
- `composite_recovery_unavailable`
- `composite_selection_ambiguous`
- `composite_validation_failed`
- `composite_publication_incomplete`

`composite_selection_ambiguous` applies when one request maps more than one
selected recovery to the same missing role. Separate exact requests that choose
different eligible recoveries are not ambiguous.

Implementations may use a more specific existing integrity, configuration,
cancellation, or internal reason when that boundary fails. Such failures remain
fail-closed and never authorize repair or publication.

## Contracts and ownership

TASK-005 must establish the exact final schema names after inspecting the
nearest owning contracts. The design expects separate version-1 composite run
manifest and final-review schemas rather than changing the meaning of existing
ordinary-review v1 artifacts. Each schema must have exactly one valid example,
owning-package semantic tests, trusted-field injection, generated embedded
checksums, and backward-read coverage.

Ownership follows existing package boundaries:

- `internal/domain` owns composite values, identity, provenance, and invariants.
- `internal/app/reviewcompose` owns admission, exact selection, lineage and
  target checks, role-source selection, recomputation, and orchestration.
- `internal/app/validation` owns untrusted candidate validation and trusted
  field injection.
- `internal/app/publication` owns atomic attempts, manifests, integrity,
  recovery, and final artifacts.
- Query, report, export, and clean owners support self-contained composite runs.
- `internal/entrypoint/mulgae` owns CLI grammar and projections; MCP transport
  wiring projects the same application result without owning policy.
- `internal/builtin/assets` owns embedded schemas, examples, and help assets.

The application and domain layers remain independent of CLI, MCP transport,
filesystem layout, and provider processes. No provider is invoked during
composition.

## Tasks

### TASK-005: Define composite contracts and domain invariants

Owner: domain, contracts, validation, and embedded assets.

Required work:

- Add explicit normal, rerun, and composite run-type semantics.
- Define deterministic composite identity and bounded source provenance.
- Define stable reason codes and composite-specific manifest and final-review
  schemas without overloading captured target identity.
- Preserve backward readability of existing artifacts and projections.
- Generate valid examples, semantic tests, and embedded checksums through the
  repository generators.

Acceptance:

- Schema validation accepts one complete multi-role composite and rejects
  missing roles, duplicate roles, untrusted identities, invalid provenance, and
  invalid target digests.
- Repeated generation is deterministic and leaves the worktree unchanged on the
  second run.
- Architecture and compatibility tests prove trusted ownership and backward
  readability.

### TASK-006: Compose exact accepted role results

Owner: `internal/app/reviewcompose` with existing rerun, review, validation, and
query ports.

Required work:

- Admit one exact committed incomplete root plus one exact committed recovery
  for every missing required role.
- Verify transitive same-role lineage, shared target-content digest, ordinary
  accepted-result integrity, and exact coverage.
- Recompute findings, provenance, finding identities, content verdict, and CI
  decision from root policy.
- Provide deterministic idempotent application results and typed failures.

Acceptance:

- One-role and multi-role recovery succeed without invoking already successful
  roles.
- Different targets, live-stage substitutions, invalid lineage, non-required or
  already satisfied roles, duplicate selections, missing roles, malformed or
  unpublished recovery output, and integrity failures are rejected.
- Provider, model, prompt, template, configuration, sampling, and time metadata
  differences remain eligible when target identity and lineage match.
- Colliding source finding IDs remain distinct with correct provenance.

### TASK-007: Publish and retain a self-contained composite run

Owner: publication, workspace storage, query, report, export, and clean.

Required work:

- Materialize selected verified target support and role results in a new run.
- Publish attempts, validation records, final artifacts, and manifests atomically.
- Reconcile exact retries and recover interrupted publication without granting
  authority to partial output.
- Support exact status, findings, report, export, and lifecycle-safe cleanup.
- Preserve root and recovery artifacts unchanged.

Acceptance:

- Failure injection at every durable write boundary leaves no partial composite
  authoritative and exact reconciliation reports the state.
- Repeating identical inputs returns one authoritative identity; different exact
  mappings cannot conflict.
- The composite remains readable after source runs are independently cleaned
  where existing retention policy permits that cleanup.
- Original runs remain immutable and independently queryable.

### TASK-008: Expose and certify CLI and MCP composition

Owner: CLI entrypoint, MCP adapter, public documentation, and release tests.

Required work:

- Add `mulgae compose` and MCP `compose_review` with exact bounded inputs.
- Align structured results, typed diagnostics, status, findings, report, and
  export projections.
- Document no-blind-retry reconciliation and operator examples.
- Add focused unit and integration tests, exact release-binary coverage, and
  live-provider compatibility checks where the complete gate requires them.

Acceptance:

- CLI and MCP return the same composite identity and effective review for the
  same exact request.
- Exact status and findings queries agree and require no private-artifact join.
- Structured error reason codes are stable and native paths, credentials, and
  raw provider transcripts remain absent from public diagnostics and exports.
- The repository-standard complete `make test` gate passes before the epic is
  claimed complete or release-ready.

## End-to-end acceptance matrix

1. Four required roles succeed, one fails, and an exact same-target rerun
   succeeds; the composite commits with complete coverage.
2. More than one required role is missing and one exact successful recovery is
   supplied for each; one complete composite commits.
3. Any recovery target digest differs, is absent, is invalid, or cannot be
   verified; composition is rejected.
4. A staged target changes after root capture; a rerun of the preserved capture
   remains eligible and a run of the new live stage is rejected.
5. Execution metadata differs while target digest, role, lineage, and integrity
   match; composition remains eligible.
6. A recovery is malformed, invalid, unverified, incomplete, unpublished, or
   otherwise fails ordinary integrity; no composite gains authority.
7. A selected role is not required, already accepted, duplicated, or leaves
   another required role missing; composition is rejected.
8. Several eligible reruns exist; only the caller-selected exact mapping is used
   and no filesystem order, time, or `latest` lookup affects the result.
9. Different sources reuse a finding-local ID; every finding survives with a
   distinct composite identity and correct run, attempt, and role provenance.
10. Every durable publication boundary fails closed; reconciliation never
    reports partial output as committed.
11. Identical composition requests replay idempotently without conflicting
    authority.
12. CLI and MCP status and findings projections agree for the exact composite
    identity.
13. Root and recovery artifacts remain immutable and independently queryable
    after publication.
14. The composite remains self-contained for supported read and lifecycle
    operations and does not require private transcripts.

## Non-goals and prohibited behavior

- Do not compose different target-content digests based on similar diffs, equal
  live Git state, repository paths, branches, or caller assertions.
- Do not automatically discover recovery runs, use `latest`, replace an already
  successful role, or publish an incomplete composition generation.
- Do not invoke providers or rerun successful roles during composition.
- Do not rewrite source artifacts, hide later execution, or present separate
  providers as consensus.
- Do not make clients merge private artifacts or recompute coverage and CI state.
- Do not expose native paths, credentials, raw transcripts, or private source in
  public diagnostics or exports, and do not add a product byte ceiling to
  provider content.
- Do not turn a composite into merge, release, waiver, security-exception, or
  organizational approval.
- Do not change Aquarium or another external repository in this epic.

## Dependencies and completion

TASK-005, TASK-006, TASK-007, and TASK-008 execute sequentially. No project
configuration migration or provider configuration change is required. The
feature is opt-in through the explicit mutation and does not alter ordinary
review, rerun, selector, or `latest` behavior.

EPIC-002 is complete only when the four tasks are accepted, every affected
source, test, embedded contract, example, and contributor document conforms,
the full end-to-end matrix is automated, and `make test` passes. Commit, push,
tag, release, installation, runtime activation, credential changes, and provider
or model selection and configuration changes remain separate explicitly
authorized operations.
