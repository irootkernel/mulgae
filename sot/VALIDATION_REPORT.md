# Package Validation Report

**Specification version:** 1.13.0
**Status date:** 2026-07-28

## G0 Contract and Implementation Baseline

| Baseline property | Declared state |
|---|---|
| Product commands | 18 |
| Canonical probe argv | 4 |
| Catalog | 86 paths |
| Checksummed payloads | 85; `CHECKSUMS.sha256` is self-excluded |
| Schema/example pairs | 28 |
| Decision Readiness | **READY** |
| Implementation Status | **RELEASE_READY** |
| External Contract Readiness | **G0 PLATFORM EVIDENCE AND G011 LIVE CAPABILITIES VERIFIED FOR `kimi`, `zcode`, AND `agy`** |
The current SOT oracle is 18 product commands, 4 canonical probe argv, 86 catalog paths, 85 checksummed payloads, and 28 schema/example pairs.

This SOT 1.13.0 report preserves G010's prior gate pass as historical evidence and opens G011. Current release readiness requires deterministic acceptance plus one fail-closed live capability certification for Kimi, ZCode, and AGY, all reached through the sole `make test` gate. The former fixed role matrix, planted finding, line citation, process overlap, retry count, full child-workflow live run, and runtime-event cardinality are not current release predicates.

## G0 Evidence Status

When collected, evidence receipts are stored outside the SOT under `.gjc/_session-019f5a09-5eec-7000-84df-094fcc21b1ce/evidence/g0/`. Those receipts, not this report, prove executed checks.

| Evidence area | Required G0 assertion | Current state |
|---|---|---|
| P0 and schema | Atomic P0 trace and all positive/negative schema cases, including 28 schema/example pairs | **CONTRACT MODEL PASS** — `P0_ATOMIC_OK`, `SCHEMA_OK`; this is not external provider or platform evidence |
| Trace and marker | 86 catalog paths, 18 commands, no orphan, and no forbidden non-normative marker leakage | **CONTRACT MODEL PASS** — `TRACE_OK`, `MARKER_OK` |
| Trust and command | Frozen trust reducer and literal request/output/exit contracts | **CONTRACT MODEL PASS** — `TRUST_OK`, `COMMAND_OK`; no product implementation is exercised |
| Prompt and evidence | Byte-exact framing/replay and separate source/current provenance | **CONTRACT MODEL PASS** — `PROMPT_OK`, `EVIDENCE_OK` |
| Cleanup and assignment model | Transitive retention, deterministic age/size sets, six-role lexical assignment, and budgets | **CONTRACT MODEL PASS** — `CLEANUP_OK`, `ASSIGNMENT_OK`; a model assignment is not the required live assignment |
| Publication | Total classifier with `unmapped=0`, `ambiguous=0`, ten cross-boundary cases, and three P2 exit variants | **PASS** — the contract model remains valid and G006 now implements product publication, recovery, reporting, and committed query surfaces |
| Canonical argv and failure | Four byte-exact canonical probe argv arrays and corrected repair/fallback rows | **CONTRACT MODEL PASS** — `CANONICAL_ARGV_OK`, `FAILURE_MATRIX_OK` |
| Integrity | 86-path catalog, 85 checksummed payload records, raw32 payload-root grammar, and checksum verification contract | **CONTRACT MODEL PASS** — `INTEGRITY_OK`, `CHECKSUMS_OK count=85` |
| Provider probes | All 48 probes for the required `kimi`, `zcode`, and `agy` runtime-contract tuples, three secure-writer indexes, and live six-role assignment | **PASS** — completed by G001; this readiness evidence does not itself support a product tuple |
| Required platform probes | All 11 `darwin-arm64` predicates on a native local POSIX filesystem | **PASS** — completed by G001; `darwin-arm64` is the sole G0 supported platform |
| Intended-future platform inventory | `linux-amd64`, `linux-arm64`, and `darwin-amd64` | **UNSUPPORTED** — fixed intended-future, non-blocking, and release-ineligible |
| Authority | Candidate review, promotion authorization, authority CAS, post-verification, support derivation, and `g0_complete` | **PASS** — completed by G001 before product implementation |
| G007 product adapters | Adapters for supported families `kimi`, `zcode`, and `agy`; direct noninteractive profiles, strict output isolation, process bounds/cancellation, runtime-capability diagnostics, provenance capture, strict unlisted-family rejection, and provider CLI reporting | **SUPPORTED BY FAMILY AND CAPABILITY** — version, executable path, SHA, and profile are retained for diagnostics and reproducibility, not general runtime authorization. Unknown or new versions are not denied solely for identity; actionable typed diagnostics report capability failures, while known incompatibilities may be explicitly blocked. |

The G0 external join and authority prerequisites are complete. Current G007 support is family-and-capability based for `kimi`, `zcode`, and `agy`: no configured version/SHA tuple needs a historical PASS receipt to run. Unlisted families remain rejected and no automatic substitution is authorized.

## Goal Implementation Status

| Goal | Verified delivered boundary | Status | Repository marker |
|---|---|---|---|
| G001 | Authority promotion, post-verification, `g0_complete`, support derivation | **HISTORICAL — COMPLETE** | `1439c3d` |
| G002 | Domain and ports foundation | **HISTORICAL — COMPLETE** | `64ac360` |
| G003 | Trusted adapters, embedded contracts, foundation CLI | **HISTORICAL — COMPLETE** | `905030c` |
| G004 | Prompt validation, bounded repair, fake review slice | **HISTORICAL — COMPLETE** | `f8eaa89` |
| G005 | Coordinator lanes, direct process runtime, evidence, independent outcome axes | **HISTORICAL — COMPLETE** | `da1939f` |
| G006 | Publication recovery, reporting, query commands | **HISTORICAL — COMPLETE** | `feat(g006)` |
| G007 | Provider adapters for supported families `kimi`, `zcode`, and `agy` | **HISTORICAL — COMPLETE** | `feat(g007)` |
| G008 | Fake/offline root/followup/delta/rerun lineage and P2 publication proof; not production root review | **HISTORICAL — COMPLETE** | `feat(g008)` |
| G009 | Historical integrated v0.1 gate; no release publication | **REOPENED_PRODUCTION_REVIEW_INCOMPLETE** | **HISTORICAL_GATE_PASS_NON_PRODUCTION** |
| G010 | Config v2 assignments, configured fallback, production child workflows, and historical real-provider full-workflow gate | **HISTORICAL — COMPLETE** | `g010` |
| G011 | Corrected deterministic acceptance and live provider-family certification under the sole `make test` gate | **RELEASE_READY** | `g011` |

## Current Project-local Contract Coverage

Repository verification covers all seven nonempty init provider subsets with
canonical Kimi, ZCode, AGY ordering, rejected JSON init requests, and committed
config survival when stdout delivery fails. Config command coverage rejects an
unavailable or mismatched installed account at readiness exit `4`, rejects an
unsafe or drifting native-home identity at security exit `8`, and exposes no
accepted digest before those checks pass. Embedded-help census tests bind these
behaviors to the sole project-local configuration and no-migration contract.
Pure native-home observation cancellation is retained as `request_cancelled`
at exit `9` for init, config, and doctor, without weakening security or artifact
precedence. CLI E2E coverage also includes auto discovery with zero through
three providers and new/existing root-barrier failure plus retry projections.

## Historical G009 Integrated v0.1 Gate Evidence

Historical integrated-gate evidence is **HISTORICAL_GATE_PASS_NON_PRODUCTION**. It retains the exact 17 load-bearing command registry/binary golden, truthful schema-list v1 rejection, all 25 schema/example pairs and assets, fake/offline canonical lineage evidence, subprocess crash proof, and the full domain, security, publication, cancellation, and fallback suites. It remains historical and did not by itself satisfy G010; the completed G010 items rely on the current evidence recorded in the normative implementation checklist.

The retained historical G009 narrative records the controlled Kimi tuple `kimi/local-default/0.23.6/50c3582a1beeba081271193b74efc39c51b3a0a16b4bf32b754b9482a86a314a/kimi-default` and the original receipt SHA-256 `1227711091fc94aff32dfed18d34f009da7404862b1eb63d99a2313a30c2be27` and raw-output SHA-256 `435639659d6ec453a8271d9a82787e11d4aa1be0450b981b0aab040966172141`. The append-only external ledger remains the evidence authority; development evidence is not retained in this repository. This is historical qualification evidence for the recorded G009 run, not a current product-support boundary. G0 provider-family evidence for `kimi`, `zcode`, and `agy` remains separate. `darwin-arm64` remains the sole supported platform; all intended-future platforms remain unsupported and release-ineligible.

The controlled provider attempt history also records two later opt-in retries on 2026-07-18. Each exited after approximately 30.15 seconds with `status=timeout`, `termination=timed_out`, and `diagnostic=process_timeout`. The durable G009 ledger retains both outcomes. They do not replace or erase the earlier exact-tuple PASS, and do not alter current family-and-capability support; they are disclosed as later external liveness failures rather than hidden.

## Readiness and Publication Boundary

The recorded G001–G010 evidence is historical. G011 is release-ready after the corrected exact final-tree `make test` passed on the supported `darwin-arm64` platform. Future platforms remain unsupported and release-ineligible.

## Historical Documentation Validation

The 1.0.0 through 1.12.0 reports remain historical baselines. SOT 1.13.0 changes no CLI, Config v2, or P2 schema; it corrects the release acceptance boundary. Current checksums and the implementation checklist are authoritative for this revision.
