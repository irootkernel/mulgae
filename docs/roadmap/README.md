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
| [EPIC-007](#epic-007-verified-review-contracts) | Completed | Bind requested project and preflight input to native execution, then expose coherent verified results and self-contained composite evidence through CLI and MCP. |
| [EPIC-008](#epic-008-review-completeness-and-iteration) | Completed | Add optional explicit requirements assessment to one ordinary review and expose its results through existing verified reads. |
| [EPIC-009](#epic-009-live-workspace-and-git-review) | Completed | Review original workspace and Git targets without source snapshots, using neutral reviewer execution and preserving historical results. |
| [EPIC-010](#epic-010-cursor-acp-review-provider) | Completed | Add Cursor as an explicitly selected text-role provider through an ACP stdio adapter, without changing the ZCode, Grok, or Codex routes. |
| [EPIC-011](#epic-011-agy-stream-json-review-provider) | Completed | Re-admit AGY over its bidirectional `stream-json` stdio wire protocol with one account and make AGY the default `documentation` provider. |
| [EPIC-012](#epic-012-correctness-and-historical-compatibility) | Completed | Repair normalization, teardown/framing, epoch allocation and retained artist reads while preserving the current trust model. |
| [EPIC-013](#epic-013-verified-operation-reuse) | Completed | Remove repeated construction, source parsing and whole-support reads within verified operation lifetimes. |
| [EPIC-014](#epic-014-application-and-contract-ownership) | Completed | Consolidate application and wire-contract ownership, then remove proven retired writers under historical compatibility tests. |
| [EPIC-015](#epic-015-development-verification-simplification) | In Progress | Reduce repeated test preparation and brittle assertions, and separate development verification from release certification. |

## Adopted execution order

EPIC-007, EPIC-009, EPIC-010 and EPIC-011 are complete.
EPIC-010 and EPIC-011 both depend on completed EPIC-009 and do not depend on
each other. Master approved EPIC-008's reduced requirements-assessment scope on
2026-10-27. Its five member Tasks execute as TASK-026, TASK-027, TASK-028,
TASK-029 and TASK-033. TASK-026 through TASK-029 are complete;
this work does not reopen EPIC-007 or block another Epic.

EPIC-012 is complete: TASK-046 through TASK-052 are completed and certified,
and Master accepted the completed Epic result on 2026-10-22.
EPIC-013 is complete: TASK-053 through TASK-059 are completed and certified,
and Master accepted the completed Epic result on 2026-10-24.
EPIC-014's original scope is complete: TASK-060 through TASK-067 are completed
and certified, and Master accepted that result. On 2026-10-27, Master adopted
TASK-068 and TASK-069 as follow-ups for AGY and Grok CLI compatibility
failures found during the deferred live certification. Both Tasks are complete,
and Master accepted the follow-up scope after integrated verification. The
original acceptance and completed Tasks remain recorded. Its prerequisite, explicit
acceptance of EPIC-013, was satisfied; it does not depend on EPIC-008. Under
Master's quota-preservation decision, development and Epic acceptance of
EPIC-014 used the
deterministic gates (`make test-prepare`, `make test-unit`, `make test-int`,
and `make test-release`), `make test-mcp-clients` when MCP consumer paths
change, and ZCode-only live verification (`TestLiveZCodeCapability` and
ZCode-only live review checks). Live provider gates for Grok, Cursor, AGY, and
Codex (`make test-grok`, `make test-cursor`, `make test-agy`, and
`MULGAE_E2E_OPT_IN=1 make test-e2e-opt-in`)
are explicitly deferred to the `v0.1.26` release gate (`release-handler`),
where all five providers (`zcode`, `grok`, `cursor`, `agy`, and `codex`) must
pass on the release candidate. Record those deferred non-ZCode live checks
explicitly at each epic handoff without claiming live coverage for unexercised
providers. Master requested EPIC-013 execution on 2026-10-22 and EPIC-014
execution on 2026-10-24.

Master adopted EPIC-015's development verification simplification on
2026-10-29, and EPIC-015 is now In Progress following completed EPIC-014.
TASK-070 is complete and activated `make test-offline`, `gaori run offline`,
and the [development verification policy](../implementation-tips/development-verification.md);
TASK-071 is complete and reuses proven immutable Catalog and compiled Schema
fixtures across CLI helpers; TASK-072 through TASK-074 remain Planned in table
order.

Within an executable Epic, run Tasks in table order as independent sequential
goals; each Task depends on the preceding Task. EPIC-009, EPIC-010, and
EPIC-011 have no EPIC-008 dependency. Deferred TASK-004 is not a prerequisite
and remains unchanged.

Planned records an approved work definition; active and completed Task/Epic
states require implementation and evidence. The specs'
requirement checkboxes track verified requirements only and do not create a
second status authority. Completion does not authorize configuration,
credential, installation, or release changes.

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

Status: Completed

Depends on: completed TASK-018 and the existing capture, publication, query,
composite recovery, and attached-lifecycle baseline. No new external provider,
MCP Tasks, or EPIC-008 dependency.

Canonical Outcomes: [verified review contracts](../specs/verified-review-contracts.md),
[public contracts](../specs/contracts.md), [architecture](../architecture/README.md),
[security requirements](../specs/security.md),
[verification guidance](../implementation-tips/README.md#verification-for-the-adopted-review-epics),
and the [accepted two-Epic design](../architecture-decision-records/verified-review-iteration.md).

Goal: establish native project and preflight guards and a coherent public read
path for review status, structured findings, reports, and supported evidence.
Combine the execution-side and result-side contracts without changing Mulgae's
advisory role or introducing another orchestrator.

Capture identity is a complete target-and-support contract, distinct from the
existing patch-only target digest, request identity, and publication receipt.
TASK-019 defines it, TASK-021 publishes its verification support, TASK-022 exposes
it, and TASK-024 preserves composite source provenance. Historical readers retain
this completed capability. The reduced EPIC-008 scope uses original-source review
without restoring capture identity or extending it into cross-run resolution
authority.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-019 | Completed | Freeze distinct project/capture/request/publication identities, guards, read/page interfaces, errors, and compatibility contracts. | Equal-patch/different-support and same-capture/different-request tests, canonical encoding/cursors, schema semantics, historical support matrix, generators, and `make test-prepare`. |
| TASK-020 | Completed | Expose independently comparable, descriptor-backed project binding through CLI context and MCP get_context. | Equal-content different roots, canonical aliases, linked worktrees, replacement detection, redaction, CLI/MCP parity, and zero provider or persistent-write calls. |
| TASK-021 | Completed | Bind complete preflight input to guarded admission, execute the checked capture/plan, and retain canonical capture verification support in new ordinary/no-change and existing child publications. | Equal-patch support drift, request-only changes, zero provider calls on rejection, retained support integrity, unchanged no-change outcome, legacy guards, and cancellation/await semantics. |
| TASK-022 | Completed | Add one-receipt inspection with verified capture identity/availability, structured finding pages, detail reads, and CLI/MCP parity. | Coherent paging under corruption, cleanup, epoch/filter changes, unavailable historical capture support versus damaged support, and reports-only/diagnostic-only results. |
| TASK-023 | Completed | Add lossless read-only rendered and original role-report access, plus indexed evidence reads under the same receipt. | Full-content reassembly, UTF-8/binary boundaries, all supported indices, stale/malformed offsets, no writes/provider calls, and release-binary fixtures. |
| TASK-024 | Completed | Publish self-contained composite finding evidence and per-source capture provenance while preserving old composites and exact mapping idempotence. | Ordinary/failed-recovery sources, no false common identity for unequal captures, remapped IDs, interrupted publication, source cleanup, historical absence, integrity, export, and replay. |
| TASK-025 | Completed | Certify the integrated native workflow, simplify source-distributed agent guidance, and prepare explicit Epic acceptance. | Frozen consumer fixtures, exact release-binary and actual supported-client behavior, complete `make test`, canonical-document readback, and `git diff --check`. |

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

- [x] All VRC requirements and seven Tasks have behavior and compatibility
      evidence; no required read needs direct private artifact IO.
- [x] Guard rejection precedes any provider request, including qualification;
      receipt comparison cannot confuse distinct equal-content worktrees.
- [x] Inspection, pagination, report and evidence reads preserve publication
      identity and distinguish absent extraction from zero findings. Complete
      capture identity survives restart, differs for equal patches with changed
      support, and is not confused with request identity or historical absence.
- [x] New composite evidence survives permitted source cleanup; old artifacts
      and idempotent mappings remain unchanged and explicit about capabilities.
- [x] The exact candidate passes the complete repository gate and required
      client checks; skipped or unavailable evidence is not a pass.
- [x] Promote durable outcomes, remove the temporary dossier and its TODO entry,
      repair links, and replace Detailed SOT with Canonical Outcomes before
      explicit Epic acceptance. Do not start EPIC-008 merely because tasks passed.

## EPIC-008: Review completeness and iteration

Status: Completed

Master approved the reduced requirements-assessment scope on 2026-10-27.
This replaces the earlier capture-dependent redesign hold. TASK-026 through
TASK-029 are complete: contracts, local admission/preflight, internal publication
and Git-bound public execution with verified reads. TASK-033 has completed
integrated full/live/client certification. All five member Tasks are complete.

Depends on: completed and accepted EPIC-007 and EPIC-009.

Canonical Outcomes: [requirements assessment](../specs/review-completeness-and-iteration.md),
[public contracts](../specs/contracts.md), [security](../specs/security.md),
[architecture](../architecture/README.md), [verification](../implementation-tips/README.md)
and the [revised design decision](../architecture-decision-records/verified-review-iteration.md#reduced-epic-008-scope).

Goal: add optional explicit requirements to one ordinary review, retain one
assessment per selected item, and expose it through existing verified reads.
Preserve objective-only review and keep test execution, remediation and final
acceptance with Aquarium and the operator.

Exclude batch rechecks, cross-run comparison, resolution transfer, conflict
reduction, full Review Briefs, change/completion modes, referenced-document
capture, requirements-driven CI exits and automatic review loops. Source
snapshots, copied checkouts, replay archives and capture-bound guards remain
retired. The requirement file is invocation input, not a source snapshot.

### Tasks

The five member Tasks run in this order; each depends on its predecessor.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-026 | Completed | Freeze optional requirements input, assigned-ID assessments, count/origin/availability, extraction-policy outcomes, independent section failures and no-change/historical contracts. | Strict input/ownership, local-input/source-evidence separation, valid provider versus placeholder counts, disabled/consumed extraction allowance, whole-response/protected failures, empty-tree HEAD, schema examples/semantics and unchanged budgets/exits. |
| TASK-027 | Completed | Admit a local requirements file alongside the existing objective and expose provider-free CLI/MCP preflight; keep public requirements-bearing execution unavailable until TASK-029. | Safe input paths/Unicode/IDs/owners, untracked local input with staged/committed evidence, known disabled-extraction disclosure, invalid input on all no-change targets, zero provider calls and no target substitution. |
| TASK-028 | Completed | Implement internal execution, validation and publication of role-owned assessments and exact input provenance; public activation remains with TASK-029. | Four verdicts, direct structured output with extraction disabled, consumed allowance, independent section outcomes, counts/origin, whole-response/protected failures, all no-change cases, integrity and restart. |
| TASK-029 | Completed | Expose assessments through verified CLI/MCP reads and enable public requirements-bearing execution/capability together. | Count/origin/availability parity, historical unknown counts, severity-filter independence, pre-activation rejection, paging/tamper, restart, export/cleanup privacy and exact-binary consumer fixtures. |
| TASK-033 | Completed | Certify the integrated requirements-assessment feature and prepare explicit Epic acceptance. | Deterministic failure/compatibility matrix, exact binary/clients, one bounded authorized live requirements review, complete current Make gate, documentation and diff checks. |

TASK-027 exposes admission/preflight, TASK-028 exercises internal execution,
and TASK-029 alone activates public requirements-bearing execution with verified
reads and the existing capability mechanism. Objective-only execution stays
available throughout; no general feature-flag system is introduced.

Master retired the former batch-recheck and cross-run comparison plan on
2026-10-29 because Mulgae will not return to the earlier capture-based design.
TASK-030, TASK-031 and TASK-032 are removed from planned and deferred work.
Their IDs remain reserved and must not be reused.

### Requirement ownership

| Requirements | Owning implementation Tasks |
|---|---|
| RCI-001 | TASK-026, TASK-027 |
| RCI-002, RCI-003 | TASK-028, TASK-029 |
| RCI-006, RCI-007 | TASK-026, TASK-027, TASK-028, TASK-029, integrated in TASK-033 |

RCI-004 (batch rechecks) and RCI-005 (comparison) belong to the retired plan;
their IDs are not reused. Their earlier scope and rationale remain in the
[historical design](../architecture-decision-records/verified-review-iteration.md).

### Epic acceptance

- [x] All five member Tasks and RCI-001/002/003/006/007 have production behavior,
      evidence and historical compatibility checks.
- [x] Optional requirements coexist with the objective; each selected item has
      one owned assessment or an explicit unverified result, with evidence and
      limitations. Zero findings does not imply requirement satisfaction.
- [x] Every existing admitted no-change target, including empty-tree HEAD,
      retains zero provider calls, zero attempts/reports and zero evaluated count,
      with persistent evaluation-not-run plus unverified/no_change_target results.
- [x] Verified CLI/MCP reads preserve input/result integrity, restart behavior,
      bounded paging, privacy and explicit historical capability absence.
      Counts distinguish valid provider answers from Mulgae-derived placeholders;
      severity filters do not hide assessments. Public activation occurs only
      with verified reads in TASK-029. Ordinary review, source selection,
      extraction policy, role budgets and exits remain compatible.
- [x] The exact candidate passes the current complete Make gate, exact-binary
      and supported-client checks and one explicitly authorized bounded live
      requirements review with admitted provider assessments; placeholders alone
      are not structured coverage. No batch/comparison demonstration is required.
- [x] Promote durable outcomes, remove the dossier and its TODO entry, repair
      links, replace Detailed SOT with Canonical Outcomes and obtain explicit
      Epic acceptance.

## EPIC-009: Live workspace and Git review

Status: Completed

Depends on: completed EPIC-007; no EPIC-008 dependency.

Canonical Outcomes: [live workspace and Git review](../specs/live-workspace-and-git-review.md),
[public contracts](../specs/contracts.md), [security boundaries](../specs/security.md),
[architecture](../architecture/README.md), and [verification guidance](../implementation-tips/README.md#verification-for-the-adopted-review-epics).

Goal: review the original workspace or exact Git target without source snapshots,
copied checkouts, created worktrees, or full-source replay archives. Keep neutral
reviewer execution, explicit provider routing, useful results, and historical reads.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-034 | Completed | Freeze live contracts and prove neutral, read-only workspace/Git access and protocol reports for ZCode, Grok, and Codex. | Actual isolated provider probes, exact staged/history reads, hostile guides, non-mutation, and compatibility matrix; failure blocks cutover. |
| TASK-035 | Completed | Implement live workspace/index/resolved-Git source readers without target copies or source archives. | Partial staging, unchanged support, root/merge/range semantics, ignores, conflicts, path safety, binary evidence, and no-change fixtures. |
| TASK-036 | Completed | Separate neutral process/session cwd from the source root and implement safe guide injection, native restrictions, and protocol reports. | All three native protocols, forbidden writes, credential/scratch isolation, concurrent sessions, report completeness, and cancellation. |
| TASK-037 | Completed | Publish honest live-source evidence while preserving atomic results and verified historical readers. | Correct evidence sides, integrity failures, legacy ordinary/child/composite reads and exports, historical absence, and reconciliation without replay. |
| TASK-038 | Completed | Cut over CLI/MCP together, remove source capture and retired execution/configuration, and update affected contracts, assets, help, security authority, and agent guidance in the same change. | Exact-binary transport parity and documented preflight/start/await, rejected retired requests, wrong-root guards, zero-call no-change, no snapshots, cleanup safety, and deterministic generators. |
| TASK-039 | Completed | Certify all source scopes and providers; validate the contracts, assets, documents, and agent guides already updated by their owning tasks. | Complete make test plus explicit Codex opt-in, exact candidate/client checks, generation consistency, final prose/link/diff checks, and explicit acceptance. |

TASK-034 is the provider feasibility prerequisite. A failed probe blocks cutover;
later tasks must not restore snapshots or substitute another provider.

### Requirement ownership

| Requirements | Owning implementation Tasks |
|---|---|
| LWR-001 | TASK-034, TASK-035, TASK-038 |
| LWR-002, LWR-003 | TASK-034, TASK-036 |
| LWR-004 | TASK-034, TASK-037, TASK-038 |
| LWR-005, LWR-006 | TASK-037, TASK-038 |
| LWR-007 | TASK-039 |

### Epic acceptance

- [x] All five selectors use their declared live/index/resolved-Git source semantics.
- [x] ZCode, Grok, and Codex use neutral process/session cwd, isolated credential
      and scratch homes, explicit guide injection, and proven read-only restrictions.
- [x] New reviews create no source snapshots, copied checkouts, worktrees, or
      full-source replay archives. Source consistency limits are explicit.
- [x] Removed requests fail before provider execution. Old artifacts remain
      unchanged and readable/exportable; cleanup and atomic integrity protections remain.
- [x] Exact-binary/client verification, complete make test, and explicit Codex
      opt-in certification pass; missing evidence is not acceptance.
- [x] Promote durable outcomes, retire the dossier and its index entry, repair
      links, and explicitly accept the epic before recording Completed.

## EPIC-010: Cursor ACP review provider

Status: Completed

Depends on: completed EPIC-009. No EPIC-008 dependency.

Canonical Outcomes: [provider contracts](../specs/contracts.md),
[security boundaries](../specs/security.md),
[Cursor ACP transport](../architecture-decision-records/cursor-acp-transport.md),
[final provider portfolio](../architecture-decision-records/final-provider-portfolio.md),
and [verification guidance](../implementation-tips/README.md).

Master accepted EPIC-010 closeout on 2026-10-19. TASK-040 verified all six
installed-CLI stop conditions with Cursor `2026.10.14-0f9edde`. TASK-041
verified separate exact index and committed-object Git reads under the neutral
Git binding. TASK-042 recorded the complete `make test` gate and an exact-binary
Cursor review; live Cursor certification remains separate from the mandatory
ZCode/Grok gate. This closeout changes documentation only and does not repeat
those executable checks.

Goal: add Cursor as an explicitly selected text-role provider through one ACP
stdio adapter. Keep ZCode as the default review provider and Grok as the
operator-selected recovery route. A Cursor failure stays on Cursor; Mulgae does
not substitute another provider.

Design decisions accepted at planning time: launch `agent acp` only, with no
`agent -p` fallback. Process cwd and native session cwd stay at the neutral
reviewer home, and the canonical project root remains a separate typed input.
Ask mode must be confirmed on the wire before prompting. The outer Seatbelt
guard, an empty disposable `HOME`, and projection of only the selected
authentication material are mandatory. Project rules, `AGENTS.md`, and
`mcp.json` supply no execution authority. Artist roles, model selection, and
reasoning effort are outside this epic. Live Cursor certification is opt-in and
stays out of the mandatory ZCode/Grok release gate.

This registration does not change runtime behavior. Current provider behavior
includes explicit Cursor selection. Default role preferences stay unchanged.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-040 | Completed | Pin the installed `agent acp` wire and prove neutral-cwd reads, absent project-instruction injection, visible tool identity, ask-mode acknowledgement before prompting, credential denial, and a correlated completed assistant turn. Stop the epic if any check fails. | Cursor `2026.10.14-0f9edde` passed all six stop conditions through isolated native handshake, read, tool-policy and boundary checks. The pinned behavior is retained in the canonical outcomes. |
| TASK-041 | Completed | Add the Cursor family ACP driver, disposable namespace, Seatbelt launch, and qualification behind the existing protocol runner. Leave public configuration and default role assignment unchanged. | Scripted ACP success and failure, permission rejection, credential isolation, unchanged ZCode, Grok, and Codex behavior, and one native stage fixture: separate index and commit GitCommand calls, each allow_once and completed, with both byte strings in the assistant turn and the neutral home as GIT_WORK_TREE. |
| TASK-042 | Completed | Publish explicit Cursor selection across init, CLI, MCP, schemas, help, contracts, security, and one transport ADR. Keep live certification opt-in. | Generator idempotence, one exact-binary Cursor review, the complete `make test` gate, and a separate opt-in Cursor live check. |

TASK-040 is the provider feasibility prerequisite. A failed probe blocks
TASK-041 and TASK-042. TASK-041 must not expose a public route that diverges
from the pinned wire. TASK-042 is the first task that updates
[product boundaries](../specs/goals.md), [public contracts](../specs/contracts.md),
[security requirements](../specs/security.md), and the
[final provider portfolio](../architecture-decision-records/final-provider-portfolio.md).

### Epic acceptance

- [x] TASK-040 records a passing installed-CLI probe, or the epic stops with a concrete blocker.
- [x] Cursor text roles run through `agent acp` with neutral cwd, Seatbelt, isolated credentials, and fail-closed tool policy.
- [x] ZCode defaults, Grok recovery, and Codex selection remain unchanged, and provider failure causes no substitution.
- [x] Public contracts, security, help, and schemas describe Cursor only after TASK-042, and historical readers remain valid.
- [x] The complete `make test` gate passes. Cursor live certification stays opt-in and is reported separately.
- [x] Promote durable outcomes, remove the dossier and its TODO entry, repair links, replace Detailed SOT with Canonical Outcomes, and explicitly accept the epic.

## EPIC-011: AGY stream-json review provider

Status: Completed

Depends on: completed EPIC-009. No EPIC-008 or EPIC-010 dependency.

Execution scope: implement and verify one AGY account first. Multiple-account
configuration and validation are deferred to the
[AGY multiple-account candidate](../todo/agy-multiple-accounts.md). TASK-043 is
completed under Main's delegated acceptance. TASK-044 is also completed: its six
current-binary controls, repository checks and independent result reviews pass.
Main accepted the internal adapter under Master's delegation. TASK-045's plan
passed independent review. Public integration and the exact-candidate native
single-account gate pass. Unit, integration, release-binary, static and mandatory
ZCode/Grok live checks pass. The Judge and two nonauthor Workers found no new
implementation defect. Main accepted TASK-045 under Master's delegation.
Independent Epic integration review is complete; Master accepted the complete
Epic result on 2026-10-19. At Master's request, vulnerability scanning is now a
separate manual check. Go 1.27.1 remains unchanged, and Master owns the later toolchain
update. The revised gate first passed with a short canonical `TMPDIR`.
Subsequent default-path unit and integration runs exposed four fixture-path
admission defects. Their owned roots are now canonicalized, preserving the
production denial and identity checks. Focused regressions pass under the
inherited, physical and custom symlinked temporary parents. The complete
`make test` gate now passes with the inherited macOS `TMPDIR`, including
mandatory ZCode/Grok live certification and the default opt-in Codex skip.
A native single-account `make test-agy` also passes from the default temporary
location; its existing Make-owned runtime child remains canonical. Earlier
failed invocations remain failed. Separating the manual scan did not remediate
its findings.

TASK-043 verified AGY `1.4.0` neutral-cwd workspace/Git reads, complete stdin,
natural exit `0`, no signals and process-group absence. Separate native
workspace/Git writes and protected credential reads are denied. Empty file-token
authentication rejects before `init` or a user frame; original credentials and
fixtures remain unchanged.

The final tested native profile combines selective `request-review` permissions
with an app-owned agent (`view_file` / `run_command`, instruction and MCP
inheritance disabled). Actual positive turns report unknown source/Git markers
and the agent body nonce while all six instruction tokens stay absent. A source
plugin launches a harmless MCP sentinel on the default positive route; the
matched selected-profile positive completes without launching it. The complete
plugin fixtures, policy and protected source/token integrity remain intact.
Selected-profile synthetic credential requests are denied before execution.
Those denial-terminated turns have empty responses and remain invalid reviews;
their failed response-nonce criterion is preserved separately from assessment
of configuration and native denial evidence.

The installed CLI is now `1.4.2`. TASK-044's current-version matched controls
verify guarded Git reads, source-plugin MCP suppression and canonical-command
translation. Separate appended-operand, numeric-fallback and bare-command
controls receive native pre-execution denials. Both selected positives keep all
six instruction canaries absent across every retained carrier. Source, original
credentials and fixtures stay intact; verified namespace cleanup succeeds. One
earlier startup discriminator was inconclusive before user input and remains
separate from these six passing controls. All use the one default account.

The shared recovery adds opt-in owned PTYs, stdin half-close/drain and child-only
inherited-descriptor sanitization. Existing teardown grace stays `150ms`.
TASK-043 focused race, unit, integration, release-binary and static checks
passed. Its original full `make test` attempt stopped at vulnerability scanning.
The revised complete gate now passes in the default environment described
above. The Judge and two independent Workers passed TASK-043; Main accepted its
bounded result under Master's delegation.
Workers are `opencode / GLM 5.3 / max`; the Judge is
`codex / GPT-6.1-SOL / high`.

Canonical Outcomes:

- [Provider contracts](../specs/contracts.md) and [security boundaries](../specs/security.md).
- [Architecture](../architecture/README.md) and [AGY stream-JSON transport](../architecture-decision-records/agy-stream-json-transport.md).
- [Final provider portfolio](../architecture-decision-records/final-provider-portfolio.md) and [verification guidance](../implementation-tips/README.md).

Goal: re-admit AGY (`FamilyAgy`, `"agy"`) over its bidirectional `stream-json`
stdio wire protocol, make AGY the first default provider preference for the
`documentation` role, using the operator's existing default Gemini account.
AGY does not gain `default_credential_profile`, per-role `credential_profile`,
or machine-local `credential_homes` in this epic. Keep ZCode as the first default
preference for the remaining roles and preserve Grok and Codex routes. An AGY
failure stays on AGY; Mulgae does not substitute another provider.

The native invocation uses `--input-format stream-json --output-format
stream-json`, with no `-p` / `--print` fallback, post-output lifecycle workaround
or loopback hub. Cwd stays at the neutral reviewer home and source access uses
Mulgae's Seatbelt boundary. The verified profile uses `--mode plan`,
`--disable-slash-commands`, `--add-dir <workspaceRoot>` and an app-owned
`--agent`, selective native permissions and fail-closed tool auditing. The skip-
permissions flag from the original plan is superseded by that tested policy.
Only the selected token is imported into a disposable Gemini home, alongside
Mulgae-authored settings and agent files. `--gemini_dir` and `SSH_TTY=/dev/null`
select file authentication; original credential roots stay protected and refresh
writes remain confined to the copy. No live or forced refresh is claimed.

The working implementation supports ZCode, Grok, Codex, Cursor and AGY.
Main accepted all three Tasks under Master's delegation. Independent Epic
integration review completed without a new integration defect. Master accepted
the complete Epic result on 2026-10-19.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-043 | Completed | Add the reviewed opt-in owned-PTY and exchange half-close prerequisites; pin the installed `agy` (`1.2.9+`) `stream-json` wire and prove neutral-cwd workspace/Git reads, Seatbelt write and credential denial, visible `step_update` tool identity, and `--gemini_dir` + `SSH_TTY` file-token isolation for one account. Stop the epic if any in-scope check fails. | Installed `1.4.0` passes the tested wire/read/lifecycle, write/credential-denial, instruction and source-plugin MCP checks under one-account file authentication. The bounded refresh-confinement evidence is accepted; no live refresh is claimed. The Judge and two independent Workers passed the final result; Main accepted it under Master's delegation. |
| TASK-044 | Completed | Add the `FamilyAgy` `stream-json` protocol driver (`agy_protocol.go`), Seatbelt live execution, disposable `--gemini_dir` binding for the default account, model/effort flags, and qualification behind the existing protocol runner. Leave public schemas and default role routing unchanged. | Scripted wire, policy, credential and qualification tests, six installed-CLI controls, unit, integration, release-binary and static checks pass. The Judge and two independent Workers passed the result; Main accepted the internal adapter under Master's delegation. |
| TASK-045 | Completed | Publish single-account `agy` across `init`, `config` (`model`, `reasoning_effort`, `timeout`, local `executable`), `assets/roles.yaml` (`documentation` primary default = `agy`), CLI, MCP, versioned schemas, help, contracts, security, portfolio ADR, and transport ADR. | Generator idempotence, configuration and role-assignment tests, one exact-binary single-account `agy` review, and the complete `make test` gate. |

TASK-043 is the provider feasibility prerequisite. A failed probe blocks
TASK-044 and TASK-045. TASK-044 must not expose a public route that diverges
from the pinned wire. TASK-045 is the first task that updates
[product boundaries](../specs/goals.md), [public contracts](../specs/contracts.md),
[security requirements](../specs/security.md), and the
[final provider portfolio](../architecture-decision-records/final-provider-portfolio.md).

### Epic acceptance

- [x] TASK-043 records a passing installed-CLI probe, or the epic stops with a concrete blocker.
- [x] AGY roles run through `agy --input-format stream-json --output-format stream-json` with neutral cwd, Seatbelt read-only confinement, `--gemini_dir` + `SSH_TTY` file-token isolation, and fail-closed `step_update` tool policy.
- [x] `documentation` defaults to `agy` when configured, ZCode remains the first default for other roles, and provider failure causes no substitution.
- [x] Public contracts, security, help, and schemas describe AGY only after TASK-045, and historical readers remain valid.
- [x] The complete `make test` gate passes and one exact-binary AGY review is recorded.
- [x] Verify the single-account route; multiple-account fields and tests remain outside this epic.
- [x] Promote durable outcomes, remove the dossier and its TODO entry, repair links, and replace Detailed SOT with Canonical Outcomes.
- [x] Master explicitly accepts the complete Epic result.

## EPIC-012: Correctness and historical compatibility

Status: Completed

Depends on: completed EPIC-009, EPIC-010 and EPIC-011. No EPIC-008 dependency.

Canonical Outcomes:

- [Provider content normalization and bounded retry](../specs/contracts.md#provider-content-normalization-and-bounded-retry), [artifact layout](../specs/contracts.md#artifact-layout), [output and exits](../specs/contracts.md#output-and-exits), and [provider qualification readiness](../specs/contracts.md#provider-qualification-readiness) (`76ac2f4`, `bd8657f`, `d1dc8b6`).
- [Architecture review flow and publication](../architecture/README.md#review-flow) (`4a49586`, `3c0ed46`, `9130548`, `d1dc8b6`).
- [Deferred feedback DF-022](../deferred-feedback/README.md#deferred-feedback) and the [embedded schema index](../../internal/builtin/assets/schemas/README.md) (`bd8657f`, `d1dc8b6`).
- [Verification for the adopted review Epics](../implementation-tips/README.md#verification-for-the-adopted-review-epics) (deterministic gates, ZCode-only live certification, and `v0.1.26` non-ZCode live deferral).

Goal: Repair normalization, teardown/framing, epoch allocation and retained artist reads while preserving the current trust model.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-046 | Completed | Preserve original provider coordinates for exact-evidence repair and admit all valid evidence sides. | Permuted findings/evidence, exact patch application, side boundaries and unchanged repair authority (`76ac2f4`). |
| TASK-047 | Completed | Consume conversation cancellation once while preserving complete teardown. | Deterministic cancel/EOF/exit, signal receipts, driver drain and group absence (`4a49586`). |
| TASK-048 | Completed | Assemble stdout lines by scanning incoming chunks once. | Chunk equivalence, byte ownership, long lines, partial EOF and complete capture (`3c0ed46`). |
| TASK-049 | Completed | Stream epoch inventory beyond the accidental 4096-entry lifetime limit. | Boundary counts, malformed/unsafe late entries, overflow/collision and namespace checks (`9130548`). |
| TASK-050 | Completed | Restore strict historical artist input manifests and their support bindings. | Frozen artist and old manifests, publish/read round trip, missing/tampered/cross-run support (`bd8657f`). |
| TASK-051 | Completed | Align Cursor diagnostic IDs, provider transport metadata, structured-limit checks, schema index and sequential qualification documentation with existing runtime contracts. | Port grammar/correlation, exact providers JSON, equal structured limits, schema/example rows, sequential qualification wording and deterministic generation (`d1dc8b6`). |
| TASK-052 | Completed | Certify the complete correctness candidate and promote its durable outcomes. | Deterministic gates (`make test-prepare`, `make test-unit`, `make test-int`, `make test-release`), ZCode live verification, preserved safety invariants, deferred non-ZCode live gates recorded for `v0.1.26`, and canonical outcome promotion. |

Tasks ran in the listed order; each Task after the first depended on its
predecessor. Scope, implementation decisions, negative tests, compatibility,
prohibited actions and handoff details were owned by the retired execution
dossier; durable outcomes are the canonical commits and documents above.
Master accepted the completed Epic result on 2026-10-22.

### Epic acceptance

- [x] Every member Task has implementation and verification evidence for the exact candidate (`76ac2f4`, `4a49586`, `3c0ed46`, `9130548`, `bd8657f`, `d1dc8b6`, and this closeout change).
- [x] Public contracts, historical consumers, fail-closed boundaries and deferred-Epic holds are preserved (consolidated `c4d717e..HEAD` diff audit; schema versions unchanged except the corrected schema index; historical read families green).
- [x] No timing/percentile/benchmark or memory-peak target is introduced; structural and behavioral checks pass (work-counter and construction proofs only).
- [x] Deterministic gates (`make test-prepare`, `make test-unit`, `make test-int`, `make test-release`) and ZCode live verification pass; non-ZCode live provider gates (`grok`, `cursor`, `agy`, `codex`) are explicitly recorded as deferred to the `v0.1.26` five-provider release gate.
- [x] Durable outcomes are promoted to `contracts.md`, `architecture/README.md`, and `implementation-tips/README.md`, and the dossier and its index entry are retired under Master's explicit closeout authorization in the approved execution plan.
- [x] Master explicitly accepts this Epic; technical design agreement and completed child Tasks do not substitute (accepted 2026-10-22).

## EPIC-013: Verified operation reuse

Status: Completed

Depends on: completed and explicitly accepted EPIC-012. No EPIC-008 dependency.

Canonical Outcomes:

- [Immutable value lifetime and proof ownership](../architecture/README.md#immutable-value-lifetime-and-proof-ownership): constructor-proven packets and publication artifacts (`183ea39`), review-independent live publication support built once per publication (`d9894a8`), one verified read context per query call (`38915f5`), and reader-local Git inventory and configuration-parse retention (`71d4f37`).
- [Live reviewer execution](../architecture/README.md#live-reviewer-execution): body-free native path admission through the source port (`4dd4909`).
- [Concurrency, cancellation, and storage](../architecture/README.md#concurrency-cancellation-and-storage) and [provider qualification readiness](../specs/contracts.md#provider-qualification-readiness): distinct-family qualification batches with original-order four-field reduction through the first failed group; fatal selection is batch-scoped, uses canonical precedence with original-order ties, and returns the selected original error unjoined; a fatal qualification returns no run and no routes and reports only the selected error's observations; every started group's acquisitions are drained or explicitly retained; successful ordering and nonfatal admission and projection are unchanged (`278cae4`).
- [Execution budgets and failure reduction](../specs/contracts.md#execution-budgets-and-failure-reduction) (`278cae4`) and [lossless report and evidence reads](../specs/contracts.md#lossless-report-and-evidence-reads) (`38915f5`).
- [Deferred feedback](../deferred-feedback/README.md#deferred-feedback): DF-003, DF-010 and DF-020 resolved; DF-008 and DF-011 remain open with their standing rules; DF-028 and DF-029 record the load-sensitive protected-directory control and the qualification fakes on worker goroutines (`38915f5`, `4dd4909`, `71d4f37`, `278cae4`, and this closeout change).
- [Verification for the adopted review Epics](../implementation-tips/README.md#verification-for-the-adopted-review-epics): deterministic counting, canonical temporary roots, deliberate `-race` probes, no timing targets, and cross-version baseline certification (this closeout change).

Goal: Remove repeated construction, source parsing and whole-support reads within verified operation lifetimes.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-053 | Completed | Reuse constructor-proven immutable packet and publication values without repeated hashing/copying. | Zero values, digest mismatch, nested clone/getter independence and unchanged bytes (`183ea39`). |
| TASK-054 | Completed | Build review-independent publication support once and preserve pre-issuance validation. | Byte equality, zero ID issuance on preflight failure, interrupted/resumed candidate binding and durable commit (`d9894a8`). |
| TASK-055 | Completed | Share one verified read context across query, status, excerpts and report rendering. | DF-010 interleavings, corrupt-status/error preservation, fresh next-request verification and no repeated whole-support pass per excerpt (`38915f5`). |
| TASK-056 | Completed | Separate native path admission from source-body reads through the source port. | DF-011 and late-tool mutation controls, descriptor/protected-path safety, Close and zero admission body reads (`4dd4909`). |
| TASK-057 | Completed | Reuse fixed commit path/OID inventories and identical successful config-byte parsing. | Fresh descriptor checks, changed/appearing/disappearing config, bounded reader-local state and unchanged mutable-source behavior (`71d4f37`). |
| TASK-058 | Completed | Run distinct-family qualification groups concurrently with ordered outcomes and complete cleanup ownership. | Barrier/oracle tests, canonical fatal-failure precedence with original-order ties, complete cleanup and exact namespace/profile authority (`278cae4`). |
| TASK-059 | Completed | Certify reuse against the accepted correctness baseline and document lifetime rules. | Deterministic gates (`make test-prepare`, `make test-unit`, `make test-int`, `make test-release`), ZCode live verification, wire/error/failure-recovery compatibility, deferred non-ZCode live gates recorded for `v0.1.26`, and canonical outcome promotion. |

Tasks ran in the listed order; each Task after the first depended on its
predecessor. Scope, implementation decisions, negative tests, compatibility,
prohibited actions and handoff details were owned by the retired execution
dossier; durable outcomes are the canonical commits and documents above.
Master accepted the completed Epic result on 2026-10-24.

### Epic acceptance

- [x] Every member Task has implementation and verification evidence for the exact candidate (`183ea39`, `d9894a8`, `38915f5`, `4dd4909`, `71d4f37`, `278cae4`, and this closeout change).
- [x] Public contracts, historical consumers, fail-closed boundaries and deferred-Epic holds are preserved (consolidated `cf377d4..278cae4` diff audit; embedded assets, `test/e2e`, `internal/releasecheck` and every testdata fixture byte-identical to the EPIC-012 baseline; binaries built from `cf377d4` and `278cae4` give byte-identical CLI and MCP output over the same stored bytes once paths and per-invocation request IDs and times are replaced, identical typed errors, exits and corrupt-status projections, byte-identical export bundles, and identical publication members and digest-reference graphs under an injective identity mapping with times elided; runtime diagnostics, whose same-family qualification order varies between projects in both versions, match as order-insensitive structural content; fixed-input interrupted-publication states are byte-identical and recover identically across versions; historical read families green; the intentional behavior changes are TASK-056's path-only native admission and TASK-058's concurrent distinct-family qualification and fatal selection, recorded in `CHANGELOG.md` and their canonical documents).
- [x] No timing/percentile/benchmark or memory-peak target is introduced; structural and behavioral checks pass (reuse is proved by disabled-by-default counting seams, deterministic call traces and `-race` barrier controls, never by timing).
- [x] Deterministic gates (`make test-prepare`, `make test-unit`, `make test-int`, `make test-release`) and ZCode live verification pass through one complete `make test` gate on the frozen closeout candidate; non-ZCode live provider gates (`grok`, `cursor`, `agy`, `codex`) are explicitly recorded as deferred to the `v0.1.26` five-provider release gate.
- [x] Durable outcomes are promoted to `architecture/README.md`, `contracts.md`, `deferred-feedback/README.md` and `implementation-tips/README.md`, and the dossier and its index entry are retired under Master's explicit closeout authorization in the approved execution plan.
- [x] Master explicitly accepts this Epic; technical design agreement and completed child Tasks do not substitute (accepted 2026-10-24).

## EPIC-014: Application and contract ownership

Status: Completed

The original TASK-060 through TASK-067 scope remains accepted. Master adopted
TASK-068 and TASK-069 on 2026-10-27. Both Tasks are complete, and Master
accepted the follow-up scope after integrated verification.

Depends on: completed and explicitly accepted EPIC-013. No EPIC-008 dependency.

Canonical Outcomes:

- [Historical compatibility corpus](../implementation-tips/README.md#historical-compatibility-corpus): fixed synthetic artifacts and real-schema read/report/export/recovery/cleanup controls independent of retired writers (`58bbc89`).
- [Dependency direction](../architecture/README.md#dependency-direction) and [runtime wire compatibility controls](../implementation-tips/README.md#runtime-wire-compatibility-controls): shared persisted DTOs and matching strict-JSON mechanics, with caller-owned validation, separate encodings and unchanged acceptance sets (`028257e`).
- [Review request ownership](../architecture/README.md#review-request-ownership) and [run status and failure selection](../architecture/README.md#run-status-and-failure-selection): typed CLI/MCP admission and missing-only status fallback with transport-specific limits and projections (`41ad32a`); the large MCP result-bound test harness correction is `217f813`.
- [Configuration admission ownership](../architecture/README.md#configuration-admission-ownership), [public contracts](../specs/contracts.md#output-and-exits) and [provider isolation](../specs/security.md#provider-isolation): application-owned doctor/admission policy, native-home replacement classification and offline Cursor version checks (`31b3e18`).
- [Live reviewer execution](../architecture/README.md#live-reviewer-execution): shared correlation, diagnostic and read-plan mechanics with family-specific authority, permission, cancellation, EOF and exit rules (`a4d14e2`).
- [Composite support ownership](../architecture/README.md#composite-support-ownership): retired execution/writer removal with historical readers, v2 archive reconstruction, capture encoding, recovery and live multi-file P2 retained; large role-report reads preserve exact bytes and integrity (`cc4a47d`).
- [Ownership guards](../architecture/README.md#ownership-guards), [internal file responsibilities](../architecture/README.md#internal-file-responsibilities) and [relocation checks](../implementation-tips/README.md#ownership-guard-and-relocation-checks): targeted dependency/request-route controls and three same-package pure moves (`8197922`).
- [AGY native policy compatibility](../architecture-decision-records/agy-stream-json-transport.md): minimum-version admission and safe settings normalization without version allowlists, with exact native command and credential restrictions (`39b7b26`).
- [Grok native policy integrity](../specs/security.md#provider-isolation): enforced requirements retained across native bookkeeping, post-drain policy audits and same-provider extraction controls (`8d7fa2c`).
- [Deferred feedback](../deferred-feedback/README.md#deferred-feedback): DF-007, DF-012, DF-013, DF-014, DF-022, DF-024 and DF-025 have delivered resolutions. DF-026, DF-027 and DF-028 remain open; DF-029 remains with its existing owner.
- [Verification guidance](../implementation-tips/README.md#verification-for-the-adopted-review-epics): retained compatibility controls, native serialized execution and compile-only tagged checks. Grok, Cursor, AGY and Codex live campaigns remain deferred to the `v0.1.26` five-provider release gate.

Goal: Consolidate application and wire-contract ownership, then remove proven retired writers under historical compatibility tests.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-060 | Completed | Freeze the minimal synthetic historical compatibility corpus before writer removal. | Exact retained bytes and expected read/report/export/recovery/cleanup outcomes, including integrity negatives; complete VP-2 suite (`58bbc89`). |
| TASK-061 | Completed | Share matching persisted wire shapes and strict-JSON mechanics under explicit owners. | Byte-exact corpus/schema controls, identical acceptance sets, Unicode and distinct digest-domain preservation; complete VP-2 suite (`028257e`). |
| TASK-062 | Completed | Construct typed CLI/MCP review requests and centralize shared status/failure policy. | Existing 12000/4096 limits, binding/roles/no-change behavior, consumer envelopes and full error precedence; complete VP-2 suite (`41ad32a`), with test-harness correction `217f813` verified in TASK-063. |
| TASK-063 | Completed | Move doctor and common admission policy into application services with injected capabilities. | Doctor v7 states/reasons/exits, native-home/config drift, cancellation and prohibited-effect rejection; complete VP-2 suite (`31b3e18`). |
| TASK-064 | Completed | Share identical provider correlation, diagnostic and read-plan mechanics. | Per-family wire/permission/cancel/EOF/exit behavior and deterministic tool diagnostic selection; complete VP-3 suite (`a4d14e2`). |
| TASK-065 | Completed | Remove proven retired execution/writer paths after their fixture and reader dependencies are replaced. | Caller/build-tag inventory, retained compatibility, live P2 and large-report integrity controls; complete VP-3 suite (`cc4a47d`). |
| TASK-066 | Completed | Enforce the established dependency boundaries and split changed files along ownership seams. | Architecture/import checks, raw declaration/import/activation equivalence for the three moves and focused native checks; complete VP-3 suite (`8197922`). |
| TASK-067 | Completed | Promote integrated ownership and retained compatibility outcomes, retire the dossier and prepare the Epic acceptance handoff. | The four deterministic Make gates, `make test-mcp-clients`, all seven tagged-vet checks and ZCode live verification pass, with retained consumers, caller inventory and resolved-feedback accounting (`e5de637`). Four non-ZCode live campaigns remain deferred to `v0.1.26`; explicit Epic acceptance is recorded below. |
| TASK-068 | Completed | Admit AGY versions from the existing 1.2.9 minimum onward without per-version command or settings allowlists; accept safe settings normalization while preserving exact native permissions and credential denies, default model/effort omission, and single-account isolation. | Reproduce native settings omission offline; cover minimum/newer versions, unsafe values, unknown fields and missing nonempty grants; prove exact command admission and denied command variants on the current native binary; run applicable repository checks and exact-candidate `make test-agy`, including source-only marker reads, natural exit, verified report/export, unchanged source/Git/token and runtime cleanup. |
| TASK-069 | Completed | Restore Grok 1.0.70 compatibility with a native policy configuration that remains enforced across review and extraction; preserve boundary integrity and report policy drift at the failing stage. | Cover native policy retention, protected-file drift and forbidden tool/credential access; run applicable repository checks and exact-candidate `make test-grok`, including independent capability certification and the initial-review-to-extraction path on the same provider without policy restoration or bypass. |

TASK-060 through TASK-067 ran in the listed order; each Task after the first
depended on its predecessor. Scope, implementation decisions, negative tests,
compatibility, prohibited actions and handoff details were owned by the retired
execution dossier, preserved in Git history. Durable outcomes are the canonical commits
and documents above. Integrated verification and Epic review for that original
scope are complete, and Master accepted the result.

### Native CLI compatibility follow-ups

Diagnosis against `44654c4` identified two compatibility failures with newer
installed CLIs. AGY 1.4.7 omits default policy fields and an empty allow list
when saving settings; the current audit accepts those omissions only for
established codecs. Grok 1.0.70 replaces the app-authored `config.toml` and
removes `managed_config.toml` during review, so the next invocation fails the
immutable boundary audit. These findings establish follow-up scope; they do
not establish that the original ownership refactor introduced either failure.

TASK-068 follows completed TASK-067. TASK-069 follows TASK-068. Each follow-up
owns its implementation, negative regression controls, applicable repository
checks, provider-specific live gate, documentation and evidence handoff. There
is no separate integration-verification Task. If a Task changes a shared
boundary, it also owns the affected provider regressions. Keep the original
public interfaces and trust boundaries unless a separately approved change is
required; adding a version to an allowlist or restoring removed policy files
does not by itself prove safe compatibility.

The five-provider release-candidate gate remains owned by the release workflow.
Earlier provider evidence from another candidate does not satisfy it. These
Tasks do not authorize release publication or changes to native accounts,
installed executables or persistent provider settings.

### Epic acceptance

The recorded acceptance below covers the original TASK-060 through TASK-067
scope. Master also accepted the completed follow-up scope after its integrated
verification.

- [x] Every original member Task has implementation and verification evidence for the exact candidate (`58bbc89`, `028257e`, `41ad32a`, correction `217f813`, `31b3e18`, `a4d14e2`, `cc4a47d`, `8197922`, and `e5de637`).
- [x] Public contracts, historical consumers, fail-closed boundaries and deferred-Epic holds are preserved.
- [x] No timing/percentile/benchmark or memory-peak target is introduced; structural and behavioral checks pass.
- [x] Deterministic gates (`make test-prepare`, `make test-unit`, `make test-int`, `make test-release`), `make test-mcp-clients`, all seven tagged-vet checks, and ZCode live verification pass; non-ZCode live provider gates (`grok`, `cursor`, `agy`, `codex`) are explicitly recorded as deferred to the `v0.1.26` five-provider release gate.
- [x] Durable outcomes are promoted and dossier/index/roadmap links are reconciled under the documented lifecycle.
- [x] Master explicitly accepts this Epic; technical design agreement and completed child Tasks do not substitute.

### Follow-up acceptance (TASK-068 and TASK-069)

- [x] TASK-068 has implementation evidence and passes its task-owned checks and exact-candidate AGY live certification.
- [x] TASK-069 has implementation evidence and passes its task-owned checks and exact-candidate Grok live certification.
- [x] Master explicitly accepts the follow-up scope before the reopened Epic returns to Completed.

## EPIC-015: Development verification simplification

Status: In Progress

Master adopted this work definition on 2026-10-29. TASK-070 is complete and
activated `make test-offline`, `gaori run offline`, and the proportional
verification guidance together; TASK-071 is complete; TASK-072 through TASK-074
remain governed by the execution dossier.

Depends on: completed and explicitly accepted EPIC-014.

Detailed SOT: [development verification simplification dossier](../todo/development-verification-simplification.md)

Operating policy: [development verification](../implementation-tips/development-verification.md)

Goal: Reduce repeated test preparation and unnecessary assertion maintenance,
and separate development verification from release certification while
preserving product behavior, trust boundaries and supported historical reads.

| Task | Status | Outcome | Verification |
|---|---|---|---|
| TASK-070 | Completed | Added the thin `make test-offline` aggregate and optional `gaori run offline` alias; updated `make test` to invoke `test-offline` once before release and live stages; activated proportional Task, integrated-candidate and release verification guidance together; and captured the focused baseline at `4beb843` (`go1.27.1 darwin/arm64`, `MULGAE_E2E_BINARY` unset, warm host `GOCACHE`). | Verified offline stage membership, order, single execution and failure short-circuiting in `internal/architecture`, preserved individual target flags and full-release stages, validated `.gaori/tester.yaml` mapping, documentation links and `git diff --check`, and recorded the focused baseline (`./internal/entrypoint/mulgae`: `62.333s`, `62.759s` initial run; `./test/e2e`: `35.318s`, `29.389s` initial run) (`1c446eb`). |
| TASK-071 | Completed | Reused package-shared immutable default Catalog and compiled Schema Validator fixtures via `sharedFoundationAssets` (`sync.Once`, `context.Background()`) across CLI fixture helpers (`newFoundationFixtureWithWriter`, `newFoundationFixtureWithEvidence`, `newG006FixtureWithWriter`, `newG008Fixture`, `newG008Composition`, `newG008RealE2EFixture`, `historicalValidator`, and `retainedResolverFixture`) and removed discarded intermediate `Application` and `gittarget` reader constructions while keeping mutable state per-fixture and constructor-negative cases fresh. | Matched focused CLI measurement improved from `62.333s` (`62.759s` initial) to `5.170s` (`5.567s` initial) under `-p 1 -race -count=1`; verified concurrent reuse, defensive-copy isolation and per-fixture mutable separation in `TestSharedFoundationAssetsConcurrentReuseAndIsolation`, plus CLI characterization/historical-corpus consumers, constructor-negative controls, `internal/builtin`, `internal/adapters/jsonschema`, and `internal/architecture` under `-race`. |
| TASK-072 | Planned | Reuse compiler caches in ordinary Mulgae and fake-provider test builds while keeping output binaries, native homes and other mutable fixture state isolated. | Matched representative integration builds, cache reuse across independent fixtures, unchanged offline module settings, failed-build/cleanup controls and affected release-harness checks. |
| TASK-073 | Planned | Remove brittle implementation-spelling and ordinary-prose assertions, synchronize affected release guidance, and assess integration/release overlap by artifact, execution conditions and the claim established. | Existing behavior coverage for retained requirements; preserved dependency/security/cleanup checks, public identifiers, waiver eligibility and exact installed-binary version checks; an explicit retain/remove rationale for overlapping scenarios, with no deletion quota. |
| TASK-074 | Planned | Verify the integrated improvement, promote operating guidance and measured outcomes, retire the dossier and prepare Epic acceptance. | One complete native offline backstop and affected exact-release checks on the final candidate, comparable focused observations, honest remaining limits, reconciled canonical documents and explicit Epic acceptance. |

TASK-070 through TASK-074 run sequentially. Each Task after the first depends
on its predecessor. TASK-070 updated the Makefile, optional Gaori command
mapping, AGENTS.md and contributor guidance in the same change to activate
`make test-offline` and `gaori run offline`. The Gaori alias is an optional
way to run the same gate. At `4beb843` on `go1.27.1 darwin/arm64` with
`MULGAE_E2E_BINARY` unset and a warm host `GOCACHE`, the focused baseline
commands recorded `62.333s` (`62.759s` initial run) for
`go test -p 1 -race -count=1 ./internal/entrypoint/mulgae -run '^(TestApplicationHelpAndUsageOutput|TestApplicationG006FailureParityAcrossCommands)$'`
and `35.318s` (`29.389s` initial run) for
`go test -p 1 -race -count=1 ./test/e2e -run '^(TestIntegrationIsolatedReleaseFixtureProjectContext|TestIntegrationIsolatedReleaseFixtureVerifiedWorkflow)$'`.

The offline aggregate runs preparation, unit and integration stages once.
Existing complete unit/integration target flags remain unchanged, including
race instrumentation and package serialization. Later Tasks use focused
checks; TASK-074 owns the complete offline backstop on native Apple Silicon
macOS. A correction invalidates affected evidence and requires those checks
again; broader repetition needs a shared change or unresolved failure that
invalidates the broader result.

Preserve `make test` as the full gate, including exact release binaries,
mandatory ZCode live checks and conditional Codex execution. The separately
adopted `v0.1.26` five-provider release-candidate obligation remains in force.
After TASK-070 activates the development policy, this harness-only Epic does
not require a routine live campaign. Record live checks as unexecuted and make
no new provider compatibility or release-readiness claim.

Keep production validation, publication integrity, historical fixture bytes
and consumers, dependency direction, credential/filesystem isolation and
cancellation behavior. Compiler-cache reuse does not authorize sharing mutable
native homes or weakening the confined caches in release design gates.
DF-028 remains open; this Epic does not prescribe global parallelism.

### Epic acceptance

- [ ] Every member Task has implementation and scoped verification evidence; the planned command and active guidance agree.
- [ ] Repeated fixture construction and empty-cache builds are reduced where safe, with matched focused observations and preserved behavior; historical timing samples are not used as a performance baseline.
- [ ] Constructor-negative tests, independent mutable fixtures, real-schema checks, historical compatibility and trust boundaries remain effective.
- [ ] Ordinary-prose and implementation-spelling assertions are simplified without losing a required behavior; justified integration/release overlap may remain.
- [ ] One complete offline backstop and affected exact-release checks pass on the final native candidate; failures, invalidated evidence and remaining limits are reported accurately.
- [ ] Mandatory release obligations, including the separate five-provider requirement, remain intact and unexecuted live checks are disclosed.
- [ ] Durable guidance and concise outcomes are promoted; the dossier and its index entry are retired and the roadmap links canonical outcomes.
- [ ] Master explicitly accepts this Epic; completing its Tasks does not substitute for Epic acceptance.
