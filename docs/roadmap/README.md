# Mulgae roadmap

This roadmap owns the status and ordering of planned Mulgae work. Current
runtime behavior remains authoritative in source, tests, embedded contracts,
and the contributor documents linked from the [documentation index](../README.md).

## Status vocabulary

- `Planned`: adopted but not started.
- `In Progress`: implementation is active.
- `In Review`: implementation is complete and acceptance is being verified.
- `Completed`: explicit epic or task acceptance is complete.
- `Deferred`: intentionally postponed pending a stated prerequisite or decision.
- `Blocked`: progress cannot continue until a stated blocker is resolved.

Epic status is independent of child task status. Completing every child does
not complete an epic without explicit epic acceptance.

## Epic summary

| Epic | Status | Goal |
|---|---|---|
| [EPIC-001](#epic-001-token-efficient-review-waiting) | Completed | Let attached agents await long reviews without repeated model turns while preserving exact lifecycle and publication authority. |
| [EPIC-002](#epic-002-composite-recovery-for-incomplete-multi-role-reviews) | Completed | Recover missing required-role coverage by composing exact same-target rerun results into one authoritative immutable review. |
| [EPIC-003](#epic-003-zcode-app-server-provider-transport) | Completed | Drive ZCode review and qualification through the ZCode app-server wire protocol instead of one-shot print invocations. |
| [EPIC-004](#epic-004-zcode-first-review-with-grok-recovery) | Completed | Make ZCode the default review provider, add Grok as an explicit recovery provider, retain Codex for selective use, and retire Kimi and AGY. |
| [EPIC-005](#epic-005-codex-app-server-provider-transport) | Completed | Move Codex review and qualification from one-shot exec to an isolated app-server conversation. |
| [EPIC-006](#epic-006-configurable-grok-model-and-reasoning-policy) | Completed | Let projects select one shared Grok model and reasoning effort while preserving provider defaults and exact qualification identity. |
| [EPIC-007](#epic-007-verified-review-contracts) | In Progress | Bind requested project and preflight input to native execution, then expose coherent verified results and self-contained composite evidence through CLI and MCP. |
| [EPIC-008](#epic-008-review-completeness-and-iteration) | Planned | Assess explicit requirements, recheck selected findings as a bounded batch, and compare exact review results without conflating non-observation with resolution. |

## Adopted execution order

The next implementation sequence is **EPIC-007, then EPIC-008**. Complete and
explicitly accept EPIC-007 before starting any EPIC-008 implementation. Within
each Epic, execute its Tasks in table order as independent sequential goals;
a Task depends on completion of the preceding Task. No EPIC-007 Task depends on
EPIC-008. Deferred TASK-004 is not a prerequisite and remains unchanged.

The two Epics are adopted plans, not implemented capabilities or authorization
to change runtime code, configuration, credentials, installed tools, or releases
as part of this documentation update. Task/Epic status changes require actual
implementation and evidence. The specs' requirement checkboxes track verified
requirements only and do not create a second status authority.

## Maintenance tasks

Standalone maintenance tasks sit outside the Epics.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-018 | Completed | Bind `use-mulgae` execution to the requested canonical root before provider transmission; use the native CLI when the attached MCP root cannot be proven, and carry the complete Review Brief within native input limits. Clarify CLI cancellation and audit result-field guidance. | Rehearse wrong-root and equal-content roots without provider execution; check same-root selection, objective boundaries, and timeout behavior; validate skill references and run the complete `make test` gate. |

## EPIC-001: Token-efficient review waiting

Status: Completed

Canonical Outcomes: [product boundaries](../specs/goals.md), [architecture](../architecture/README.md), [public contracts](../specs/contracts.md), [security requirements](../specs/security.md), and the accepted [review-await decision](../architecture-decision-records/review-await.md)

Goal: let an attached coding agent wait for a long Mulgae review without
repeated model turns while preserving exact run identity, explicit
cancellation, and fail-closed publication.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-001 | Completed | Guide attached clients to keep one foreground `run_review` pending and wait on the same deferred handle for up to five minutes at a time. | Validate `skills/use-mulgae`; read back the guidance; run `git diff --check`. |
| TASK-002 | Completed | Add a session-local MCP invocation registry that owns review execution independently of an individual wait request. | Prove monotonic lifecycle state, single execution ownership, bounded shutdown drain, and no restart recovery. |
| TASK-003 | Completed | Add `start_review`, `await_review`, and `cancel_review`, retain foreground compatibility, update the source-distributed skill to prefer the new workflow, and certify supported Codex and Claude clients. | Prove wait cancellation isolation, explicit execution cancellation, repeatable await, exact final identity, unchanged publication authority, legacy fallback, effective tool timeout behavior, and no repeated model turn during one await. |
| TASK-004 | Deferred | After MCP Tasks receives a stable protocol release, replace the custom session-local lifecycle when the Go SDK and supported Codex and Claude clients implement the released contract. | Confirm the stable specification and compatible SDK/client versions, preserve TASK-003 behavior and fallback guarantees, and record exact-client protocol evidence for the standard task surface. |

TASK-002 and TASK-003 share the accepted
[review-await decision](../architecture-decision-records/review-await.md).
TASK-004 begins only after both are complete and MCP Tasks is no longer
experimental. Until then it is the deferred final goal of this epic. TASK-003
delivers the supported custom start/await workflow; it does not promote
TASK-004 or claim the stable MCP Tasks contract. EPIC-001 is complete with
TASK-004 retained as Deferred until the stable MCP Tasks contract and required
SDK and client support are released.

## EPIC-002: Composite recovery for incomplete multi-role reviews

Status: Completed

Canonical Outcomes: [product boundaries](../specs/goals.md), [architecture](../architecture/README.md), [public contracts](../specs/contracts.md), [security requirements](../specs/security.md), and the accepted [composite recovery decision](../architecture-decision-records/composite-review-recovery.md)

Goal: recover one or more missing required-role results against the same
immutable captured target without rerunning successful roles, then publish one
integrity-checked composite authority with complete CLI and MCP projections.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-005 | Completed | Define composite domain values, trusted provenance, stable reason codes, and versioned public schemas without changing the meaning of existing normal or rerun artifacts. | Prove schema examples, semantic validation, backward readability, trusted-field ownership, and deterministic composite identity. |
| TASK-006 | Completed | Add an application composition use case that admits exact root and recovery identities, verifies same-target lineage and ordinary result integrity, and recomputes the effective review from the root policy. | Prove multi-role recovery, exact selection, digest and lineage rejection, validation failures, finding-ID collision handling, and idempotent replay. |
| TASK-007 | Completed | Publish each composite as a self-contained immutable run with atomic recovery, exact query support, and lifecycle-safe cleanup while preserving every source artifact. | Prove durable-write failure recovery, no partial publication authority, source immutability, exact status and findings reads, and dependency-safe cleaning. |
| TASK-008 | Completed | Expose explicit `mulgae compose` and MCP `compose_review` mutations, align CLI and MCP projections, update public documentation, and certify the complete supported workflow. | Prove CLI/MCP parity, no-blind-retry reconciliation, exact composite selection, release-binary behavior, mandatory live-provider compatibility, and the complete `make test` gate. |

TASK-005 through TASK-008 are sequential because each task establishes the
contract required by the next. Native Mulgae composition is the boundary of
this epic. Aquarium consumption of the resulting public authority is separate
follow-up work in the Aquarium repository.

## EPIC-003: ZCode app-server provider transport

Status: Completed

Canonical Outcomes: [product boundaries](../specs/goals.md), [architecture](../architecture/README.md), [public contracts](../specs/contracts.md), [security requirements](../specs/security.md), and the accepted [app-server transport decision](../architecture-decision-records/zcode-app-server-transport.md)

Goal: replace the ZCode family's one-shot print-mode CLI invocation with the
ZCode app-server stdio wire protocol while keeping the staged-file report
transport, sealed workspace capture, disposable credential namespaces, bounded
execution, and fail-closed failure handling unchanged.

Design decisions accepted at design time: the role report keeps arriving
through the staged-file transport with the existing prompt layer and staging
validation, and the print invocation path is fully replaced without a
fallback.

Non-goals: no change to the AGY, Kimi, or Codex transports; no event-derived
report extraction; no new user-facing transport configuration (transport
stays adapter-owned); no persistent multi-turn provider sessions.

Failure behavior: protocol parse errors, unrequested server interaction
requests, missing turn completion, and protocol-reported provider failures
fail closed through typed classification; stderr token classification remains
the fallback.

Migration and rollout boundary: the qualification version floor rises to the
first locally verified app-server-capable ZCode release; there is no
compatibility layer or print fallback, so the cutover ships as one atomic
change.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-009 | Completed | Add an additive protocol packet channel, driver session interface, and process-runner conversation mode (line-oriented exchange, tee-spooled stdout, reused timeout, process-group termination, and classification) with no production caller. | Unit and integration tests against a scripted fake protocol child; `make test-prepare`, `make test-unit`, and `make test-int`. |
| TASK-010 | Completed | Pin the installed app-server wire shapes in a live spike (go/no-go gate), then atomically move ZCode review and qualification invocations onto the protocol, remove the print path and `zcodeContent`, add protocol-native failure classification, raise the version floor, and update contracts, security documentation, and one new ADR. | Focused tests, live spike evidence, updated argv and e2e pins, and the complete `make test` gate including mandatory live ZCode certification. |

TASK-009 lands the dark capability first because it changes no runtime
behavior. TASK-010 is a single atomic cutover: review execution, the
qualification capability probe, and shareable-profile identity must switch
together so a certified route never diverges from the executed route.
TASK-010 begins with a live wire-shape spike that may stop the epic with a
concrete blocker instead of forcing the migration.

## EPIC-004: ZCode-first review with Grok recovery

Status: Completed

Canonical Outcomes: [provider contracts](../specs/contracts.md),
[security boundary](../specs/security.md),
[implementation and release guidance](../implementation-tips/README.md), and
[final provider portfolio decision](../architecture-decision-records/final-provider-portfolio.md)

Goal: make ZCode the default provider for every role, add Grok as an explicit
operator-selected text-role recovery provider over its ACP stdio surface,
retain Codex for selective use, and remove Kimi and AGY without automatic
provider substitution.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-011 | Completed | Unify every protocol invocation purpose behind one channel-plus-driver authority, resolve `DF-001`, and turn the verified Grok CLI 1.0.30 and ACP v1 planning baseline into deterministic protocol, permission, isolation, and lifecycle contracts. | Preserved the named ZCode protocol regressions and proved exact ACP correlation and write authorization, project-policy suppression, cancellation, timeout, process-tree cleanup, and the isolated live matrix. |
| TASK-012 | Completed | Add Grok as an explicitly selectable text-role provider beside Kimi, ZCode, AGY, and Codex, reusing Mulgae's workspace, namespace, credential, and staged-output authorities. Reject Grok artist assignments before execution. | Published the five-provider contract and verified configuration, CLI/MCP projection, exact ACP permission and staged output, typed failures, text-role recovery, artist preflight rejection, and an authorized exact-binary live Grok review. |
| TASK-013 | Completed | Published the final ZCode/Grok/Codex portfolio with typed transitive retirement, cleanup-only structural inspection, ZCode-first defaults, mandatory ZCode/Grok live certification, and opt-in Codex live certification. | Proved retirement and historical-read boundaries, safe cleanup, retained deterministic Codex coverage, schema and documentation conformance, generator idempotence, and the complete `make test` gate; Codex live testing remains an explicit opt-in. |

The tasks were completed sequentially. TASK-011 established the shared protocol
driver authority, TASK-012 introduced the Grok route, and TASK-013 completed the
three-provider cutover across runtime behavior, contracts, documentation, and
release evidence.

## EPIC-005: Codex app-server provider transport

Status: Completed

Goal: move Codex review, extraction, and qualification to one ephemeral
app-server thread and turn per invocation, retaining immutable capture,
read-only permissions, credential isolation, and the `stdout` role-report
contract. Codex stays an explicitly selected provider.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-014 | Completed | Pin Codex 0.154.0 app-server wire behavior and prove that the isolated configuration, read-only workspace, and credential boundary survive the change. Stop the cutover if the boundary cannot be certified. | Isolated handshake and turn probe, actual capability response, exact-binary review, workspace and credential checks. |
| TASK-015 | Completed | Switch the Codex family and profile projection to the protocol driver in one change; remove exec-only arguments, retain final assistant text as the report, and update tests, contracts, help, and the transport decision record. | Scripted protocol failures and success, qualification and role-route tests, generator idempotence, `make test`, and the opt-in two-profile Codex E2E. |

TASK-014 establishes the installed protocol and permission facts used by
TASK-015. The Codex provider minimum rises to the verified 0.154.0 release;
the separate Codex MCP client minimum is unchanged. The complete `make test`
gate retains optional Codex execution, but this epic requires one actual Codex
capability probe and two-profile exact-binary review before acceptance.

## EPIC-006: Configurable Grok model and reasoning policy

Status: Completed

Goal: allow projects to select one Git-shareable Grok model and reasoning
effort for every Grok role and invocation purpose, preserve provider defaults
for omitted fields in existing configurations, and fail closed without
automatic model or provider substitution.

Design decisions accepted at design time: model and reasoning effort are
optional provider-wide Config v4 settings. New initialization writes the
Mulgae-owned `grok-4.7` and `high` generation defaults, while existing Config v4
omission retains provider-default behavior. Mulgae validates syntax and Grok
owns supported meanings beyond that pinned pair. Role-level overrides, a
general provider model catalog, and a general provider-configuration framework
are out of scope. Existing role routing, invocation budgets, and provider
security boundaries remain unchanged.

### Configuration contract

| Surface | Required behavior |
|---|---|
| Project policy | Store optional `providers.grok.model` and `providers.grok.reasoning_effort` only in `.mulgae/config.yaml`. Reject these fields in `.mulgae/local.yaml`; executable paths remain machine-local. |
| Init flags | Expose `--grok-model` and `--grok-reasoning-effort`. Automatic initialization includes Grok and may accept them. Explicit provider selection excluding Grok must reject either flag. |
| Local refresh | Reject either flag with `init --refresh-local`, including an explicitly empty value. Local refresh must preserve existing project-policy bytes and configured settings. |
| Omission | New project initialization writes `grok-4.7` and `high` for dimensions without an explicit override. Each absent field in an existing Config v4 file independently selects the provider default. Never import the operator's ambient Grok configuration. |
| Explicit values | Reject empty strings, YAML nulls, non-string YAML values, whitespace, and control characters. Preserve accepted spelling without trimming or case folding. Remove a project field to restore its default. |
| Safe tokens | Models use the existing `validModel` grammar: 1–128 ASCII characters, an alphanumeric first character, then alphanumerics or `._/-`, with no absolute path, `//`, or `..` path segment. Effort uses 1–128 ASCII characters, an alphanumeric first character, then alphanumerics or `._-`. These are syntax rules, not supported-value catalogs. |
| Init provenance | The Grok discovery row reports each model and effort source independently as `override`, `mulgae_default`, `provider_default`, or `not_selected`. Init validates syntax and records policy; it does not certify provider acceptance or add an implicit live request. |

Existing Config v4 files without these fields must retain their behavior.
CLI, application admission, YAML decoding, and machine-result contracts must
agree on these rules. Adding Grok settings must not relax Codex's existing
model, reasoning-effort, credential-profile, or validation behavior.

After the epic completed, the v0.1.23 release pinned new-project generation to
`grok-4.7` with `high` effort after Grok CLI 1.0.40 acknowledged both settings
exactly before prompting. This did not change the omission semantics of an
already configured project.

### Provider-contract gate

TASK-016 starts with an isolated go/no-go probe. Record the exact Grok binary
identity and version, option placement or ACP request shapes, selection timing,
and evidence that both settings are applied before prompting. Passing argv or
receiving a successful review alone is insufficient; use provider-confirmed
selection or an equivalent version-specific contract check. Do not rely on the
model's self-description. If 1.0.30 cannot satisfy the contract, raise the minimum
to a newer version only after that exact version passes the same checks.

Check an unknown model, an unknown effort, and an unsupported model/effort
combination where the verified provider contract defines one. Distinguish
provider rejection from normalization or ignored settings. Mulgae must pass
admitted values unchanged, preserve typed rejection, and never retry by removing
or rewriting a setting or substituting another model or provider. Ordinary
same-policy retry remains subject to existing classification and budgets.
If selection cannot be established, or provider normalization changes the
requested policy, record a concrete blocker for master's decision before
TASK-017. Do not silently weaken the contract, add a catalog, or claim that
provider rejection was proved by a successful request.

### Invocation and qualification invariants

One admitted settings value must reach review, retry, repair, structured
extraction, qualification, and heartbeat. Keep heartbeat's existing timeout cap
and the purpose-specific tool and staged-output permissions. Share only the
necessary settings representation across application ports and adapters;
provider-specific validation and invocation encoding remain with their owners.

Bind both settings and their omitted-versus-explicit state into qualification
identity, not just the generated invocation. Cover both
`familyRuntimeProfileKeyFor` in `internal/app/reviewrun/family_qualification.go`
and `equivalentFamilyRuntimeProfiles` in
`internal/adapters/providercli/qualifier.go`, together with the resulting
execution-authority receipt and runtime matching. A model-only or effort-only
change must prevent qualification sharing and authority reuse. Omission is not
equivalent to an explicit value merely because today's provider default matches
it. Identical settings must retain existing eligible same-command role sharing;
do not force a separate live probe for every role. Preserve settings through
qualification and execution so a qualified route cannot execute another policy.

### Tasks

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-016 | Completed | Verified Grok CLI 1.0.34 and 1.0.40 ACP selection, raised the minimum to 1.0.34 and verified-latest to 1.0.40, then bound omitted or explicit model and reasoning effort into every internal Grok session and both qualification identities without exposing public configuration. Unknown models preserve typed provider rejection, while normalized effort mismatches fail before prompting without fallback. | Deterministic protocol and identity tests cover omission, model-only, effort-only, combined settings, typed rejection, normalization refusal, and qualification partitioning. The isolated live contract probe on 1.0.40 confirmed exact selection and both fail-closed cases while the 1.0.34 binary established the minimum ACP contract. |
| TASK-017 | Completed | Added optional Git-shareable Grok model and reasoning-effort policy, init flags with independent provenance, exact split-config ownership, production propagation through review and heartbeat paths, and command-result v12 while retaining v11 for backward reads. | Focused configuration, init, schema, CLI, and composition tests passed; both generators were idempotent; an isolated v0.1.23 candidate completed a configured `grok-4.5`/`low` security review with no low-or-higher findings; and the complete `make test` gate passed. |

The tasks remain sequential. TASK-016 records its verified contract and resolves
any blocker before TASK-017 starts. This plan defines acceptance criteria; it is
not implementation or provider-certification evidence.

### Epic acceptance

- Deterministic tests cover neither field, model only, effort only, and both
  fields across configuration and invocation construction. Cover invalid syntax,
  provider rejection, refresh-local and unselected-provider rejection,
  qualification partitioning, and unchanged ZCode/Codex behavior. Use targeted
  retry, repair, extraction, and heartbeat regressions rather than duplicating
  the entire matrix for every path.
- Live evidence covers applied explicit settings and rejection behavior from
  TASK-016, followed by one exact-release-binary Grok review using the project
  settings. Keep live calls bounded to evidence the deterministic tests cannot
  supply; do not require every configuration combination as a separate live run.
  Unsupported-combination evidence may be marked not applicable only when the
  verified contract provides no such combination, with the reason recorded.
- Update the [public contracts](../specs/contracts.md), affected
  [architecture](../architecture/README.md) and
  [security requirements](../specs/security.md), public README, source-distributed
  `use-mulgae` configuration guidance, and affected help, schemas, paired
  examples, and generated assets in their owning changes. Record the verified
  provider version, selection semantics, limitations, and failure behavior in
  the contracts. Preserve existing historical contract readers and follow the
  existing machine-result versioning policy.
- Run both documented generators twice when embedded assets change; the second
  pass must produce no diff. Require the complete `make test` gate and the
  configured Grok exact-binary evidence before explicit epic acceptance. Report
  skipped or blocked checks without treating them as passes. Stop when these
  criteria are met; no additional review loop or unrelated cleanup is required.

## EPIC-007: Verified review contracts

Status: In Progress

Depends on: completed TASK-018 and the existing capture, publication, query,
composite recovery, and attached-lifecycle baseline. No new external provider,
MCP Tasks, or EPIC-008 dependency.

Detailed SOT: [EPIC-007 development dossier](../todo/EPIC-007-verified-review-contracts.md)

Required Outcomes: [verified review contracts](../specs/verified-review-contracts.md)
and the [accepted two-Epic design](../architecture-decision-records/verified-review-iteration.md).
These are adopted requirements, not implemented runtime claims.

Goal: establish native project and preflight guards and a coherent public read
path for review status, structured findings, reports, and supported evidence.
Combine the execution-side and result-side contracts without changing Mulgae's
advisory role or introducing another orchestrator.

Capture identity is a complete target-and-support contract, distinct from the
existing patch-only target digest, request identity, and publication receipt.
TASK-019 defines it, TASK-021 publishes its verification support, TASK-022 exposes
it, and TASK-024 preserves composite source provenance. EPIC-008 consumes this
completed capability; it does not supply a missing identity implementation.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-019 | Completed | Freeze distinct project/capture/request/publication identities, guards, read/page interfaces, errors, and compatibility contracts. | Equal-patch/different-support and same-capture/different-request tests, canonical encoding/cursors, schema semantics, historical support matrix, generators, and `make test-prepare`. |
| TASK-020 | Completed | Expose independently comparable, descriptor-backed project binding through CLI context and MCP get_context. | Equal-content different roots, canonical aliases, linked worktrees, replacement detection, redaction, CLI/MCP parity, and zero provider or persistent-write calls. |
| TASK-021 | Completed | Bind complete preflight input to guarded admission, execute the checked capture/plan, and retain canonical capture verification support in new ordinary/no-change and existing child publications. | Equal-patch support drift, request-only changes, zero provider calls on rejection, retained support integrity, unchanged no-change outcome, legacy guards, and cancellation/await semantics. |
| TASK-022 | Completed | Add one-receipt inspection with verified capture identity/availability, structured finding pages, detail reads, and CLI/MCP parity. | Coherent paging under corruption, cleanup, epoch/filter changes, unavailable historical capture support versus damaged support, and reports-only/diagnostic-only results. |
| TASK-023 | Completed | Add lossless read-only rendered and original role-report access, plus indexed evidence reads under the same receipt. | Full-content reassembly, UTF-8/binary boundaries, all supported indices, stale/malformed offsets, no writes/provider calls, and release-binary fixtures. |
| TASK-024 | Planned | Publish self-contained composite finding evidence and per-source capture provenance while preserving old composites and exact mapping idempotence. | Ordinary/failed-recovery sources, no false common identity for unequal captures, remapped IDs, interrupted publication, source cleanup, historical absence, integrity, export, and replay. |
| TASK-025 | Planned | Certify the integrated native workflow, simplify source-distributed agent guidance, and prepare explicit Epic acceptance. | Frozen consumer fixtures, exact release-binary and actual supported-client behavior, complete `make test`, canonical-document readback, and `git diff --check`. |

### Requirement ownership

| Requirements | Owning implementation Tasks |
|---|---|
| VRC-001 | TASK-019, TASK-020 |
| VRC-002 | TASK-019, TASK-021 |
| VRC-003 | TASK-022 |
| VRC-004 | TASK-022, TASK-023 |
| VRC-005 | TASK-024 |
| VRC-006, VRC-007 | TASK-019 through TASK-025, integrated in TASK-025 |

### Epic acceptance

- [ ] All VRC requirements and seven Tasks have behavior and compatibility
      evidence; no required read needs direct private artifact IO.
- [ ] Guard rejection precedes any provider request, including qualification;
      receipt comparison cannot confuse distinct equal-content worktrees.
- [ ] Inspection, pagination, report and evidence reads preserve publication
      identity and distinguish absent extraction from zero findings. Complete
      capture identity survives restart, differs for equal patches with changed
      support, and is not confused with request identity or historical absence.
- [ ] New composite evidence survives permitted source cleanup; old artifacts
      and idempotent mappings remain unchanged and explicit about capabilities.
- [ ] The exact candidate passes the complete repository gate and required
      client checks; skipped or unavailable evidence is not a pass.
- [ ] Promote durable outcomes, remove the temporary dossier and its TODO entry,
      repair links, and replace Detailed SOT with Canonical Outcomes before
      explicit Epic acceptance. Do not start EPIC-008 merely because tasks passed.

## EPIC-008: Review completeness and iteration

Status: Planned

Depends on: explicit EPIC-007 acceptance, including its completed native guard,
verified query, historical capability, and composite evidence contracts.

Detailed SOT: [EPIC-008 development dossier](../todo/EPIC-008-review-completeness-and-iteration.md)

Required Outcomes: [review completeness and iteration](../specs/review-completeness-and-iteration.md)
and the [accepted two-Epic design](../architecture-decision-records/verified-review-iteration.md).
These are adopted requirements, not implemented runtime claims.

Goal: connect explicit Review Briefs and requirement assessments to bounded
selected-finding rechecks and exact, provider-free comparisons. Keep ordinary
review and batch followup independent of requirements input. Do not move Epic
approval, remediation orchestration, or issue-tracker ownership into Mulgae.

### Review boundary decisions

| Boundary | Adopted rule | Owning Tasks |
|---|---|---|
| Empty Git diff with a Brief | Keep provider-free no-change behavior; persist each requirement as unverified/no_change_target and expose evaluation not run. Workspace assessment needs an explicit new target/preflight. | TASK-026 through TASK-029 |
| Resolution transfer | Require equal complete evaluated-current and after capture identities, not equal patch hashes or equal request digests. | TASK-026, TASK-030 through TASK-032; consumes EPIC-007 |
| Comparison continuation | Bind and revalidate before, after, the complete selected followup set and every receipt, filters, and versions on each page. Read damage fails the page. | TASK-026, TASK-032 |
| Followup conflict | Preserve all eligible claims and observation evidence; conflicting conclusive claims produce unverified with stable reasons, without ordering, time, or majority selection. | TASK-026, TASK-032 |

TASK-033 verifies all four boundaries with deterministic integrated fixtures;
these clarifications do not add Epics, Tasks, or extra live retry campaigns.

### Tasks

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-026 | Planned | Freeze Brief, no-change assessment, batch-run, full receipt-set comparison, conflict rules, and historical support contracts. | Assigned IDs, skipped/nullable outcomes, complete capture versus request identity, receipt permutations, conclusive versus inconclusive claims, legacy fixtures, and generators. |
| TASK-027 | Planned | Capture strict JSON Briefs and references; expose preflight/internal guarded admission with explicit no-change evaluation-not-run state. Enable Brief execution only with TASK-028. | Empty stage/dirty/diff in both modes with/without requirements, invalid input before no-change dispatch, exact current-side references, zero provider calls, no workspace substitution, Unicode, exclusions, and guards. |
| TASK-028 | Planned | Validate and publish owned assessments and Brief provenance; enable Brief execution with provider-free no-change unverified results. | Every selected requirement retained with no_change_target, zero attempts/reports, all verdicts, support integrity, legacy no-change readers/exits, reports-only/protected failures, and call ceilings. |
| TASK-029 | Planned | Expose requirement pages, evidence, coverage, unmet/unverified and no-change evaluation-not-run reporting through verified reads. | No-change counts and reasons after restart, explicit workspace hint without execution, historical absence, transport parity, paging/tamper, export/cleanup, and exact-binary fixtures. |
| TASK-030 | Planned | Admit source findings, capture one new target, and produce provider-free batch preflight with complete current-capture identity and request guards. | Selection/source capability checks, same-patch support/context drift, route/profile mismatch, one capture, zero provider calls, grouping, and budgets. |
| TASK-031 | Planned | Publish one bounded followup_batch with verified current-capture support; expose guarded CLI/MCP start with existing await/cancel. | Per-item outcomes, missing/malformed groups, call ceilings, source/current identity separation, support persistence/tamper, parent immutability, uncertain starts, cancellation, and recovery. |
| TASK-032 | Planned | Add provider-free exact-run comparison with full-capture resolution eligibility, complete receipt-set paging, deterministic conflicts, and Brief-bound requirements. | Equal-patch unequal-support rejection, same-capture different-request eligibility, followup-only deletion/replacement/corruption between pages, selection permutations, conclusive/inconclusive conflicts, historical absence, and no provider/write/live-tree content access. |
| TASK-033 | Planned | Certify initial assessment, one batch recheck, comparison, and the four reviewed boundary rules; finalize guidance and acceptance evidence. | Deterministic no-change/capture/receipt/conflict regressions and compatibility, exact binary/clients, bounded authorized live workflow, complete `make test`, and docs/diff checks. |

### Requirement ownership

| Requirements | Owning implementation Tasks |
|---|---|
| RCI-001 | TASK-026, TASK-027 |
| RCI-002, RCI-003 | TASK-028, TASK-029 |
| RCI-004 | TASK-030, TASK-031 |
| RCI-005 | TASK-032 |
| RCI-006, RCI-007 | TASK-026 through TASK-033, integrated in TASK-033 |

### Epic acceptance

- [ ] All RCI requirements and eight Tasks have supported behavior and legacy
      compatibility evidence, not only schema or model self-attestation.
- [ ] Requirements are explicit, immutable, individually owned, and assessed
      without equating zero findings, met, and approval. Empty Git diffs preserve
      zero provider calls and publish no_change_target/unverified for every
      selected requirement, with evaluation-not-run state visible after restart.
- [ ] A selected batch uses one new target, bounded existing role execution,
      per-finding outcomes, and no automatic per-finding retry or recovery loop.
- [ ] Comparison distinguishes observation from resolution, requires equal full
      current/after captures, and never transfers met across changed Briefs.
- [ ] Every comparison page revalidates the complete selected followup receipt
      set. Read damage fails the page; conflicting intact claims preserve their
      evidence with stable unverified reasons, independent of input order or time.
- [ ] The exact candidate passes the complete gate, supported-client checks,
      and the bounded authorized live demonstration specified in the dossier.
      A failed demonstration is a blocker, not an unlimited retry instruction.
- [ ] Promote durable outcomes, remove the dossier and TODO entry, repair links,
      replace Detailed SOT with Canonical Outcomes, and explicitly accept the
      Epic. No autonomous remediation, provider migration, or other-repository
      implementation is required for closeout.
