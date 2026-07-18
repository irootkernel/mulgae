# Package Validation Report

**Specification version:** 1.5.0
**Status date:** 2026-07-18

## G0 Contract and Implementation Baseline

| Baseline property | Declared state |
|---|---|
| Product commands | 17 |
| Canonical probe argv | 4 |
| Catalog | 71 paths |
| Checksummed payloads | 70; `CHECKSUMS.sha256` is self-excluded |
| Schema/example pairs | 23; 16 are G0-required |
| Decision Readiness | **READY** |
| Implementation Status | **G001–G008 COMPLETE; G009 PENDING AND UNAUTHORIZED** |
| External Contract Readiness | **G0 EVIDENCE VERIFIED; G007 OPT-IN ADAPTERS EVIDENCE-GATED** |
The current SOT oracle remains 17 product commands, 4 canonical probe argv, 71 catalog paths, 70 checksummed payloads, 23 schema/example pairs, and 16 G0-required pairs.

This SOT 1.5.0 report records both the preserved Revision 14 contract and the completed implementation boundary through G008. This is not a release approval and does not authorize G009, product/release CI jobs, or release assets.

## G0 Evidence Status

When collected, evidence receipts are stored outside the SOT under `.gjc/_session-019f5a09-5eec-7000-84df-094fcc21b1ce/evidence/g0/`. Those receipts, not this report, prove executed checks.

| Evidence area | Required G0 assertion | Current state |
|---|---|---|
| P0 and schema | Atomic P0 trace and all positive/negative schema cases, including 23 schema/example pairs | **CONTRACT MODEL PASS** — `P0_ATOMIC_OK`, `SCHEMA_OK`; this is not external provider or platform evidence |
| Trace and marker | 71 catalog paths, 17 commands, no orphan, and no forbidden non-normative marker leakage | **CONTRACT MODEL PASS** — `TRACE_OK`, `MARKER_OK` |
| Trust and command | Frozen trust reducer and literal request/output/exit contracts | **CONTRACT MODEL PASS** — `TRUST_OK`, `COMMAND_OK`; no product implementation is exercised |
| Prompt and evidence | Byte-exact framing/replay and separate source/current provenance | **CONTRACT MODEL PASS** — `PROMPT_OK`, `EVIDENCE_OK` |
| Cleanup and assignment model | Transitive retention, deterministic age/size sets, six-role lexical assignment, and budgets | **CONTRACT MODEL PASS** — `CLEANUP_OK`, `ASSIGNMENT_OK`; a model assignment is not the required live assignment |
| Publication | Total classifier with `unmapped=0`, `ambiguous=0`, ten cross-boundary cases, and three P2 exit variants | **PASS** — the contract model remains valid and G006 now implements product publication, recovery, reporting, and committed query surfaces |
| Canonical argv and failure | Four byte-exact canonical probe argv arrays and corrected repair/fallback rows | **CONTRACT MODEL PASS** — `CANONICAL_ARGV_OK`, `FAILURE_MATRIX_OK` |
| Integrity | 71-path catalog, 70 checksummed payload records, raw32 payload-root grammar, and checksum verification contract | **CONTRACT MODEL PASS** — `INTEGRITY_OK`, `CHECKSUMS_OK count=70` |
| Provider probes | All 48 probes for the required `kimi`, `zcode`, and `agy` runtime-contract tuples, three secure-writer indexes, and live six-role assignment | **PASS** — completed by G001; this readiness evidence does not itself support a product tuple |
| Required platform probes | All 11 `darwin-arm64` predicates on a native local POSIX filesystem | **PASS** — completed by G001; `darwin-arm64` is the sole G0 supported platform |
| Intended-future platform inventory | `linux-amd64`, `linux-arm64`, and `darwin-amd64` | **UNSUPPORTED** — fixed intended-future, non-blocking, and release-ineligible |
| Authority | Candidate review, promotion authorization, authority CAS, post-verification, support derivation, and `g0_complete` | **PASS** — completed by G001 before product implementation |
| G007 product adapters | Exactly `kimi`, `zcode`, and `agy`; direct noninteractive profiles, strict output isolation, process bounds/cancellation, tuple/base-argv evidence binding, strict unlisted-family rejection, and provider CLI reporting | **EVIDENCE-GATED** — offline standard tests cover the adapter surface; only the controlled live exact Kimi tuple `local-default` 0.23.6, binary SHA-256 `50c358...`, has **PASS** evidence |

The G0 external join and authority prerequisites are complete. G007 product support is opt-in and evidence-gated: PASS evidence is required for each tuple, while unavailable, failed, and inconclusive tuples remain unsupported.

## Goal Implementation Status

| Goal | Verified delivered boundary | Status | Repository marker |
|---|---|---|---|
| G001 | Authority promotion, post-verification, `g0_complete`, support derivation | **COMPLETE** | `1439c3d` |
| G002 | Domain and ports foundation | **COMPLETE** | `64ac360` |
| G003 | Trusted adapters, embedded contracts, foundation CLI | **COMPLETE** | `905030c` |
| G004 | Prompt validation, bounded repair, fake review slice | **COMPLETE** | `f8eaa89` |
| G005 | Coordinator lanes, direct process runtime, evidence, independent axes | **COMPLETE** | `da1939f` |
| G006 | Publication recovery, reporting, query commands | **COMPLETE** | `feat(g006)` |
| G007 | Opt-in evidence-gated provider adapters for exactly `kimi`, `zcode`, and `agy` | **COMPLETE** | `feat(g007)` |
| G008 | Immutable root/followup/delta/rerun lineage and P2 publication; runtime attempt/target/prompt artifacts; retention/tombstone cleanup; redacted secure export | **COMPLETE** | `feat(g008)` |
| G009 | Release assets and integrated v0.1 release gate | **PENDING AND UNAUTHORIZED** | — |

## G008 Completion Evidence

G008 completion is backed by focused workflow tests, a real composed P2 end-to-end run covering root review plus followup, delta, and exact rerun, repository-wide tests, static analysis, race verification, cleanup review, executor QA/red-team evidence, and architecture review. Production standalone operation without canonical recorded provider/evidence authority remains fail-closed with schema-valid typed failures under G007's opt-in authority rules. G009 release assets and integration remain pending and unauthorized.

## Readiness and Product Boundary

The G001 authority and implementation prerequisites were completed before G002 product code. G001–G008 are complete; G009 remains outside the completed boundary, pending, and unauthorized. No release asset or release claim is authorized by this report, and future platforms remain unsupported and release-ineligible.

## Historical Documentation Validation

The 1.0.0, 1.1.0, 1.2.0, 1.3.0, and 1.4.0 reports remain historical baselines. SOT 1.5.0 carries forward their contract assertions while recording the completed G008 implementation boundary; current checksums and repository tests are authoritative for this revision.
