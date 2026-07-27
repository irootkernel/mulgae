# KAR Runtime Diagnostics Plan Authority

**Planning status:** COMPLETED; HISTORICAL PLANNING AUTHORITY
**Planning date:** 2026-07-23
**Planning baseline product SOT:** 1.10.0
**Delivered diagnostics product SOT:** 1.11.0; current normative product SOT is 1.12.0

## 1. Authority Boundary

This directory is the repository planning authority for KAR runtime diagnostics. It is deliberately excluded from the runtime product SOT catalog, `CHECKSUMS.sha256`, and the embedded builtin archive. Product behavior is not authoritative until the corresponding contract is promoted into the normative SOT during Diagnostics Epic 1.

If a planning statement conflicts with the current normative SOT, the normative SOT wins until Epic 1 resolves the conflict explicitly. Planning documents must never be used as runtime defaults, schema assets, release evidence, or publication authority.

Document ownership is exclusive:

- [spec.md](./spec.md) owns observable requirements and acceptance criteria.
- [architecture.md](./architecture.md) owns component boundaries, interfaces, and data flow.
- [roadmap.md](./roadmap.md) owns execution order, checklists, verification, and `/goal` text.
- This document owns purpose, scope, non-negotiable constraints, and the handoff to G010.

## 2. Problem Statement

KAR cannot currently diagnose actual-provider failures that stop before P2 publication. A provider `Observe` error can return before stdout or stderr is captured, successful captures remain in memory until publication preparation, non-publishable failures return before the runtime inventory is drained, and several unrelated failures collapse into `internal_invariant` through string matching.

The current safe command-result projection is appropriate for users but insufficient for local root-cause analysis. KAR therefore needs a separate operational diagnostics lifecycle that preserves safe structured events and bounded raw provider streams without granting those diagnostics publication authority.

## 3. Goal

For every run whose session and run identities have been issued, KAR must create a private, durable diagnostic record before spawning a provider and must finalize that record on every terminal path. The record must make normal execution and failure chronology observable across qualification, scheduling, provider execution, parsing, validation, repair, fallback, reduction, publication, and cleanup.

Provider stdout, provider stderr, and KAR runtime events remain separate artifacts. User-facing output remains concise and safe, exposing only a valid diagnostic URI when the artifact actually exists.

## 4. Non-negotiable Requirements

- Diagnostics cover normal `INFO` flow as well as `WARN` and `ERROR` states.
- One run-wide structured log orders events from all concurrent lanes.
- Raw stdout and stderr remain byte-preserving, separate, bounded artifacts.
- Durable local diagnostics retain typed causes; command results retain closed safe projections.
- The secure scan-before-write, `0700` directory, `0600` file, anchored-root, and no-follow rules remain mandatory.
- A diagnostic persistence failure fails closed before provider spawn or terminates the active run as an artifact failure.
- Diagnostics never authorize review publication, CI success, approval, release, or cleanup of unrelated runs.
- Existing P2 paths and publication authority remain unchanged.
- Native login remains user-owned. KAR never logs in, retries it automatically, repairs it, or falls back from it.
- G010-T05 and G010-T06 were required to remain incomplete until all four diagnostics epics completed; both subsequently passed their own gates on 2026-07-26.

## 5. Scope

Included:

- runtime diagnostic event and cause contracts;
- secure diagnostic filesystem storage;
- process and provider observation preservation;
- coordinator and review-run lifecycle instrumentation;
- terminal-state snapshots and diagnostic references;
- CLI human/JSON projection;
- selector, retention, cleanup, and export separation;
- offline verification and actual-provider failure evidence preservation.

Excluded:

- fixing the currently failing actual-provider E2E cause;
- weakening, skipping, or removing `make test-e2e`;
- changing provider assignment or fallback policy;
- adding automatic provider authentication;
- treating a failed E2E as a passing release gate;
- completing G010-T05, G010-T06, or `RELEASE_READY`;
- tags, releases, pushes, or release assets.

## 6. Test-gate Exception

During the four diagnostics epics, the required completion gate is:

```text
make test-prepare
make test-unit
make test-int
```

`make test` is not a diagnostics completion gate because it invokes the currently failing `make test-e2e`. Epic 4 may run `make test-e2e` to collect real diagnostic evidence. Its failure remains a failure and must not be converted to skip or pass; after a run identity is issued, the failure is useful evidence only when the preserved diagnostic URI and artifacts are observable.

After Diagnostics Epic 4:

1. G010-T05 uses the new diagnostics to identify and fix the actual E2E cause, then restores `make test-e2e` to PASS.
2. G010-T06 runs exact final-tree `make test` and may close `RELEASE_READY` only after it passes.

Both handoff steps completed on 2026-07-26. The non-skipping full-workflow `make test-e2e` passed before the exact final-tree `make test`, and the normative checklist then recorded G010 as `RELEASE_READY`.

## 7. Fixed Decisions

- [x] Use four sequential diagnostics epics.
- [x] Treat `sot/plan/**` as planning-only and exclude it from the runtime SOT catalog.
- [x] Reorganize the original root `diagnostics.md`; do not keep a duplicate archive copy.
- [x] Promote the product diagnostics contract as SOT 1.11.0 in Epic 1.
- [x] Keep G010-T05/T06 unchanged until diagnostics completes.
- [x] Ignore current `make test-e2e` failure only as a diagnostics-epic completion gate, never as a truthful test result.
