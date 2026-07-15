# Package Validation Report

**Specification version:** 1.1.0
**Baseline date:** 2026-07-13

## G0 Contract Baseline

| Baseline property | Declared state |
|---|---|
| Product commands | 17 |
| Canonical probe argv | 4 |
| Catalog | 71 paths |
| Checksummed payloads | 70; `CHECKSUMS.sha256` is self-excluded |
| Schema/example pairs | 23; 16 are G0-required |
| Decision Readiness | **READY** |
| Implementation Readiness | **CONDITIONAL** |
| External Contract Readiness | **UNVERIFIED** |
The current SOT oracle is 17 product commands, 4 canonical probe argv, 71 catalog paths, 70 checksummed payloads, 23 schema/example pairs, and 16 G0-required pairs.

This report records the Revision 13 SOT contract baseline; it is not evidence of a completed provider, platform, authority, release, or product implementation. Gate A1 authorization is limited to selected G0 contract paths and does not authorize authority-ref mutation, promotion, `g0_complete`, product code, or actual product/release CI jobs or assets.

## G0 Evidence Status

When collected, evidence receipts are stored outside the SOT under `.gjc/_session-019f5a09-5eec-7000-84df-094fcc21b1ce/evidence/g0/`. Those receipts, not this report, prove executed checks.

| Evidence area | Required G0 assertion | Current state |
|---|---|---|
| P0 and schema | Atomic P0 trace and all positive/negative schema cases, including 23 schema/example pairs | **CONTRACT MODEL PASS** — `P0_ATOMIC_OK`, `SCHEMA_OK`; this is not external provider or platform evidence |
| Trace and marker | 71 catalog paths, 17 commands, no orphan, and no forbidden non-normative marker leakage | **CONTRACT MODEL PASS** — `TRACE_OK`, `MARKER_OK` |
| Trust and command | Frozen trust reducer and literal request/output/exit contracts | **CONTRACT MODEL PASS** — `TRUST_OK`, `COMMAND_OK`; no product implementation is exercised |
| Prompt and evidence | Byte-exact framing/replay and separate source/current provenance | **CONTRACT MODEL PASS** — `PROMPT_OK`, `EVIDENCE_OK` |
| Cleanup and assignment model | Transitive retention, deterministic age/size sets, six-role lexical assignment, and budgets | **CONTRACT MODEL PASS** — `CLEANUP_OK`, `ASSIGNMENT_OK`; a model assignment is not the required live assignment |
| Publication | Total classifier with `unmapped=0`, `ambiguous=0`, ten cross-boundary cases, and three P2 exit variants | **CONTRACT MODEL PASS** — `PUBLICATION_OK`; no product publication occurs |
| Canonical argv and failure | Four byte-exact canonical probe argv arrays and corrected repair/fallback rows | **CONTRACT MODEL PASS** — `CANONICAL_ARGV_OK`, `FAILURE_MATRIX_OK` |
| Integrity | 71-path catalog, 70 checksummed payload records, raw32 payload-root grammar, and checksum verification contract | **CONTRACT MODEL PASS** — `INTEGRITY_OK`, `CHECKSUMS_OK count=70` |
| Provider probes | All 48 probes for the required `kimi`, `zcode`, and `agy` runtime-contract tuples, three secure-writer indexes, and live six-role assignment | **INCONCLUSIVE** — no provider prerequisite is complete; no provider PASS is asserted |
| Required platform probes | All 11 `darwin-arm64` predicates on a native local POSIX filesystem | **INCONCLUSIVE** — no required native platform PASS is asserted |
| Intended-future platform inventory | `linux-amd64`, `linux-arm64`, and `darwin-amd64` | **UNSUPPORTED** — fixed NOT_RUN contract rows; non-blocking and release-ineligible, with no G0 native execution or PASS evidence required |
| Authority | Runtime Gate A and negative promotion/CAS models | **PARTIAL** — candidate review, promotion authorization, authority CAS, and post-verification are not performed |

External Contract Readiness remains **UNVERIFIED** because the 48 provider probes, three secure-writer indexes, live assignment, and 11 required `darwin-arm64` probes have not completed with PASS. The staged contract does not permit intended-future inventory cells to substitute for those prerequisites or to establish support, release eligibility, promotion, or `g0_complete`.

## Readiness and Product Boundary

Decision readiness means the Revision 13 SOT contract is frozen. Implementation readiness remains conditional on the G0 evidence and approval sequence. `g0_complete` requires the promotion and post-verification path; it is not established here. Product implementation, actual product/release CI jobs or assets, and any release additionally require a separate session-bound implementation approval and remain prohibited until that approval exists.

## Historical Documentation Validation

The 1.0.0 report's assertions are not carried forward as execution evidence for 1.1.0. Any Markdown, schema, example, checksum, or runtime validation for this baseline must be recorded only by its corresponding post-Gate-A evidence receipt.
