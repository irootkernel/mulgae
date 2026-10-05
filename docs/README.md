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
and its [EPIC-008 dossier](todo/EPIC-008-review-completeness-and-iteration.md)
are held for redesign after EPIC-009 acceptance. Their earlier planned interfaces
remain unimplemented. Their adoption grants no current execution capability.

The [roadmap](roadmap/README.md#adopted-execution-order) owns Task identities,
execution order, dependencies, and status. The
[design decision](architecture-decision-records/verified-review-iteration.md)
records the grouping and responsibility boundaries.

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

## Documentation checks

The repository has no dedicated Markdown linter or documentation test target.
For documentation-only changes, read back the affected files, verify relative
links and command claims, and run `git diff --check`. Changes to executable
commands, runtime behavior, embedded contracts, or generated assets still use
the applicable checks in the implementation guidance and `Makefile`.
