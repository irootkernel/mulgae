# Mulgae contributor documentation

The repository [README](../README.md) is the public product entrypoint for
installation, configuration, and normal use. This `docs/` tree is the
maintainer and contributor authority for product requirements, architecture,
decisions, implementation guidance, operations ownership, and delivery state.

## Documentation profile

- Profile: `single-scope`
- Delivery scope: `mulgae`, rooted at `docs/`
- Documentation language: English
- Canonical roadmap: [`docs/roadmap/README.md`](roadmap/README.md)

## Role ownership

| Role | Canonical owner | Responsibility |
|---|---|---|
| Specifications | [`specs/README.md`](specs/README.md) | Required and implemented behavior, product boundaries, public contracts, and security requirements |
| Architecture | [`architecture/README.md`](architecture/README.md) | Current components, dependency direction, runtime flow, and responsibility boundaries |
| Architecture decision records | [`architecture-decision-records/README.md`](architecture-decision-records/README.md) | Accepted, superseded, deprecated, and rejected structural decisions with rationale |
| Implementation tips | [`implementation-tips/README.md`](implementation-tips/README.md) | Non-normative development, testing, asset-generation, and release guidance |
| Release design gates | [`gating-rules.md`](gating-rules.md) | Offline executable evidence for internal release invariants that valid public input cannot reach |
| Operations | [`ops/README.md`](ops/README.md) | Real-environment operation, diagnosis, recovery, and the bounded absence of an independently operated surface |
| Roadmap | [`roadmap/README.md`](roadmap/README.md) | Epic and task identity, ordering, dependencies, lifecycle vocabulary, and current status |
| TODO | [`todo/README.md`](todo/README.md) | Future epic-sized candidates and temporary dossiers for adopted active epics |
| Deferred feedback | [`deferred-feedback/README.md`](deferred-feedback/README.md) | Small actionable findings intentionally postponed from current work |

The root [changelog](../CHANGELOG.md) records concise user-visible outcomes from
the current release cycle forward. `docs/assets/` contains assets owned by the
public README rather than a separate documentation role. Versioned runtime
schemas, prompts, roles, examples, and help remain owned by
`internal/builtin/assets`.

## Adopted development

[Verified review contracts](specs/verified-review-contracts.md) describes native
project/preflight binding, coherent public result reads, and retained composite
evidence. Its canonical outcomes are linked from
[EPIC-007](roadmap/README.md#epic-007-verified-review-contracts).

Current public execution follows [live workspace and Git review](specs/live-workspace-and-git-review.md)
for EPIC-009. [Contracts](specs/contracts.md), [security](specs/security.md),
[architecture](architecture/README.md), and [verification guidance](implementation-tips/README.md)
describe the implemented model and its limits.

[Review completeness and iteration](specs/review-completeness-and-iteration.md)
defines the implemented optional requirements assessment scope approved on 2026-10-27.
TASK-026 contract foundations, TASK-027 admission/preflight, TASK-028 internal
assessment/publication and TASK-029 verified reads/activation are complete.
Batch rechecks and cross-run comparison remain outside current membership and
acceptance. Local requirements admission and provider-free CLI/MCP preflight
are available. Git-bound requirements execution includes verified CLI/MCP pages,
content resources and rendered reports. TASK-033 has completed integrated
full/live/client certification.

The active provider portfolio is ZCode and Grok. Cursor ACP
([EPIC-010](roadmap/README.md#epic-010-cursor-acp-review-provider),
[retired Cursor ADR](architecture-decision-records/cursor-acp-transport.md)),
Codex app-server review provider
([EPIC-005](roadmap/README.md#epic-005-codex-app-server-provider-transport),
[retired Codex ADR](architecture-decision-records/codex-app-server-transport.md)),
and AGY stream-JSON review provider
([EPIC-011](roadmap/README.md#epic-011-agy-stream-json-review-provider),
[retired AGY ADR](architecture-decision-records/agy-stream-json-transport.md))
have been retired from the active review provider portfolio (Codex remains
verified as an external MCP client). The roadmap records their historical
acceptance.

[EPIC-012 correctness and historical compatibility](roadmap/README.md#epic-012-correctness-and-historical-compatibility)
has completed its member Tasks (`TASK-046` through `TASK-052`), the
deterministic gates, and ZCode-only live certification, with its durable
outcomes promoted to the canonical documents and roadmap; Master accepted the
completed Epic result on 2026-10-22.
[EPIC-013 verified operation reuse](roadmap/README.md#epic-013-verified-operation-reuse)
has completed its member Tasks (`TASK-053` through `TASK-059`), the
deterministic gates, ZCode-only live certification and a cross-version
comparison against the EPIC-012 baseline, with its durable outcomes promoted
to the canonical documents and roadmap; Master accepted the completed Epic
result on 2026-10-24.
[EPIC-014 application and contract ownership](roadmap/README.md#epic-014-application-and-contract-ownership)
consolidates wire, application and provider-mechanics ownership and removes
retired producers under the frozen historical compatibility corpus. Its durable
outcomes are in the canonical documents linked from the roadmap. The temporary
execution dossier is retired. Its original Tasks (`TASK-060` through
`TASK-067`), integrated verification and Epic review are complete, and Master
accepted that result. Master adopted AGY and Grok CLI compatibility follow-ups
(`TASK-068` and `TASK-069`) on 2026-10-27; each owns its provider verification.
The roadmap records follow-up execution and the Epic's separate acceptance
conditions.

[EPIC-015 development verification simplification](roadmap/README.md#epic-015-development-verification-simplification)
reduces repeated fixture construction, cold test builds, and brittle assertions.
Its member Tasks (`TASK-070` through `TASK-074`) and integrated candidate
verification (`make test-offline`, `make test-release`, and `make test`) are
complete, its temporary execution dossier is retired, and its durable guidance
and measured outcomes are promoted to
[development verification](implementation-tips/development-verification.md) and
the [roadmap](roadmap/README.md#epic-015-development-verification-simplification);
Master accepted the completed Epic result on 2026-10-31.

[EPIC-017 herdr-core terminal runtime and Grok migration](roadmap/README.md#epic-017-herdr-core-terminal-runtime-and-grok-migration)
introduces a reusable isolated `herdr-core` terminal runtime backed by Mulgae's
trusted pane trampoline (`__mulgae_paneexec_v1`), hardened outer macOS Seatbelt
(control-plane socket denials, exact `PANE_TTY` binding, and the five-control
`B-1` Bash gate on Git scopes), disposable `HOME`/`GROK_HOME`, and scratch-file
prompt/output delivery, migrating Grok CLI (`FamilyGrok`, `1.0.89`+) in Phase 1
while leaving ZCode, Codex, Cursor, AGY transports, Config v5, and embedded JSON
schemas/examples unchanged (following standalone maintenance `TASK-083`). Its
member Tasks (`TASK-084` through `TASK-087`), cold whole-Epic validation, and
exact-candidate gates (`make test-offline`, `make test-release`,
`make test-herdr`, `make test-e2e`, and live `make test-grok`) are complete, its
temporary execution dossier is retired, and its durable outcomes are promoted to
[architecture](architecture/README.md), [security](specs/security.md),
[contracts](specs/contracts.md),
[live workspace and Git review](specs/live-workspace-and-git-review.md),
[gating rules](gating-rules.md),
[implementation guidance](implementation-tips/README.md), the accepted
[herdr-core terminal transport ADR](architecture-decision-records/herdr-core-terminal-transport.md),
embedded help assets, and `DF-030` in
[deferred feedback](deferred-feedback/README.md); Master accepted the completed
Epic result on 2026-11-21.

The [roadmap](roadmap/README.md#adopted-execution-order) owns Task identities,
execution order, dependencies, and status. The
[design decision](architecture-decision-records/verified-review-iteration.md)
records the grouping and responsibility boundaries.

[EPIC-019 ZCode herdr-core terminal runtime migration via herdr-zcode](roadmap/README.md#epic-019-zcode-herdr-core-terminal-runtime-migration-via-herdr-zcode)
is adopted as planned work (`TASK-094` through `TASK-098`) following completed
`EPIC-017` and `EPIC-018`. Its temporary execution SOT lives at
[ZCode herdr-core terminal runtime migration](todo/TODO-ZCODE-HERDR-CORE-MIGRATION.md)
and its structural rationale lives in the planned
[ZCode herdr-core terminal transport ADR](architecture-decision-records/zcode-herdr-core-transport.md).
The current candidate uses the shared `herdr-core` terminal runtime for ZCode
through `herdr-zcode`. The companion owns Desktop access. ZCode workspace
reviews run shell-free, Config v5 and `doctor-result.v9` remain current, and
omitted model or effort settings inherit the corresponding session setting.

`TASK-097` owns the new-project `GLM-5.4` and `max` defaults and
`mulgae-command-result.v26`. `TASK-098` owns integrated native certification,
the ADR promotion, and `DF-030` closeout.

## Native Haepari review coordination

[EPIC-016](roadmap/README.md#epic-016-native-haepari-review-coordination-and-release-qualification)
delivered native capacity-one coordination for CLI and both MCP review modes
in v0.1.27. The roadmap records the local closeout and limits of the release
qualification. The [specification](specs/haepari-review-coordination.md) defines
the contract, the [ADR](architecture-decision-records/haepari-review-coordination.md)
records the decision, and the [Haepari VM qualification harness](../test/vm/README.md)
documents the guest checks.

## Live review reliability and ZCode efficiency

[EPIC-018](roadmap/README.md#epic-018-live-review-reliability-extraction-fidelity-and-zcode-efficiency)
delivers live-review reliability, structured-extraction, requirements
assessment, and ZCode efficiency improvements across six completed Tasks
(`TASK-088` through `TASK-093`): fail-safe timeout publication and requirements
error/diagnostic isolation, extraction prompt alignment and per-item
requirements verification, lossless `001-initial` read-plan compaction
(`review:live-read-plan` v2), same-profile ZCode qualification sharing and
Git-scope tool hygiene, readiness fixture wording hardening (`v4`), and a
single-goroutine batched FIFO coordinator event loop, while keeping `DF-030`
ZCode outer Seatbelt hardening, Config v5, public JSON schemas, all-or-nothing
findings, and `dd91e69` complete-report retention unchanged. Its member Tasks,
cold whole-Epic validation, and integrated gates (`make test-offline`,
`make test-release`, live `make test-agy` for `TASK-090`, mandatory live ZCode
`make test-e2e` and multi-role `--stage` + `--requirements` verification, and
Master's `make test` check, with non-ZCode `TASK-092` live probes explicitly
deferred to the release gate per `EPIC-014` quota policy) are complete, its
temporary execution dossier is retired, and its durable outcomes are promoted
to [architecture](architecture/README.md), [contracts](specs/contracts.md),
[security](specs/security.md),
[live workspace and Git review](specs/live-workspace-and-git-review.md),
[review completeness and iteration](specs/review-completeness-and-iteration.md),
[implementation guidance](implementation-tips/README.md),
[ZCode transport ADR](architecture-decision-records/zcode-app-server-transport.md),
[AGY stream-json transport ADR](architecture-decision-records/agy-stream-json-transport.md),
and embedded prompt assets; Master accepted the completed Epic result on
2026-11-23.

## Source-of-truth precedence

Current source and tests are authoritative for implemented runtime behavior.
Embedded assets are authoritative for the versioned contracts shipped in the
binary. Specifications state required and implemented behavior; architecture
states current structure; decision records preserve rationale; implementation
tips explain how to change and verify the repository. The roadmap alone owns
delivery identity and status, and neither TODO nor deferred feedback creates a
second status authority.

A mismatch between implementation, tests, embedded contracts, and contributor
documentation is a conformance problem. Update every affected owner in the same
behavior change instead of silently selecting one side.

## Roadmap identity

The canonical roadmap path is the identity namespace. Epic IDs match
`EPIC-[0-9]{3,}` and task IDs match `TASK-[0-9]{3,}`. Epic and task sequences
are independent and monotonic; numbering never restarts per epic and an ID is
never reused. Allocate the greatest number ever present for that kind plus one.
Identity does not encode execution order. Qualify machine-readable cross-scope
references as `mulgae:ID`.

The roadmap defines status meanings and keeps epic status independent from its
children. Completing every child does not complete an epic without explicit
epic acceptance.

## TODO dossier lifecycle

An unadopted TODO file is an epic-sized candidate without roadmap identity or
status. Adoption retains it temporarily, lists it in the TODO index, identifies
its epic, and links it from the roadmap as `Detailed SOT`. Before epic closeout,
promote durable behavior, structure, rationale, guidance, operations knowledge,
and user value to their canonical owners. Closeout removes the dossier and its
index entry, replaces `Detailed SOT` with `Canonical Outcomes`, and then changes
epic status. Git preserves the deleted dossier history.

The [development toolchain guide](implementation-tips/toolchains.md) owns exact
language selection, installation boundaries and the developer command entrypoints.

## Documentation checks

The repository has no dedicated Markdown linter or documentation test target.
For documentation-only changes, read back the affected files, verify relative
links and command claims, and run `git diff --check`. Changes to executable
commands, runtime behavior, embedded contracts, or generated assets still use
the applicable checks in the implementation guidance and `Makefile`.
