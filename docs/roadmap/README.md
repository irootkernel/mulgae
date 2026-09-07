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
| [EPIC-003](#epic-003-zcode-app-server-provider-transport) | Planned | Drive ZCode review and qualification through the ZCode app-server wire protocol instead of one-shot print invocations. |

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

Status: Planned

Detailed SOT: [ZCode app-server provider transport dossier](../todo/TODO-zcode-app-server-transport.md)

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
| TASK-009 | Planned | Add an additive protocol packet channel, driver session interface, and process-runner conversation mode (line-oriented exchange, tee-spooled stdout, reused timeout, process-group termination, and classification) with no production caller. | Unit and integration tests against a scripted fake protocol child; `make test-prepare`, `make test-unit`, and `make test-int`. |
| TASK-010 | Planned | Pin the installed app-server wire shapes in a live spike (go/no-go gate), then atomically move ZCode review and qualification invocations onto the protocol, remove the print path and `zcodeContent`, add protocol-native failure classification, raise the version floor, and update contracts, security documentation, and one new ADR. | Focused tests, live spike evidence, updated argv and e2e pins, and the complete `make test` gate including mandatory live ZCode certification. |

TASK-009 lands the dark capability first because it changes no runtime
behavior. TASK-010 is a single atomic cutover: review execution, the
qualification capability probe, and shareable-profile identity must switch
together so a certified route never diverges from the executed route.
TASK-010 begins with a live wire-shape spike that may stop the epic with a
concrete blocker instead of forcing the migration.
