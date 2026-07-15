# Decision Log and Verification Items

## 1. Accepted Decisions

| ID | Decision | Status | Rationale |
|---|---|---|---|
| D-001 | KAR is standalone and uses `.kar/` | Accepted | Avoids dependency on external organizational tooling |
| D-002 | Canonical final path is `.kar/{session_id}/{run_id}/review_{uuidv7}.json` | Accepted | Clear lineage and approximate chronological ordering |
| D-003 | Session, run, and attempt directory IDs are prefixed UUIDv7 values | Accepted | Prevents namespace collisions and improves diagnostics |
| D-004 | Review ID is generated only after final validation succeeds | Accepted | File existence becomes a meaningful publication signal |
| D-005 | SHA-256 is stored in `manifest.json`, not the final filename | Accepted | Separates identity and chronology from integrity and avoids self-reference |
| D-006 | A completed run has at most one final review artifact | Accepted | Removes ambiguity about which artifact is final |
| D-007 | Completed runs are immutable | Accepted | Preserves auditability and CI reproducibility |
| D-008 | Review, followup, delta, and rerun always create new runs | Accepted | Keeps scope and lineage explicit |
| D-009 | Provider output is JSON-only | Accepted | Enables strict validation and stable automation |
| D-010 | KAR owns final IDs, normalized findings, coverage, and verdict | Accepted | Prevents AI hallucination of system metadata and policy |
| D-011 | Mandatory values are validated for existence and meaning | Accepted | Key presence alone does not provide a usable contract |
| D-012 | AI repair is bounded and constrained to allowed AI-owned paths | Accepted | Improves robustness without allowing review drift |
| D-013 | Default repair budget is one | Accepted | Bounds cost, latency, and semantic drift |
| D-014 | Schema, semantic, and evidence validation are separate stages | Accepted | Each stage addresses a different failure class |
| D-015 | Provider evidence is verified against the immutable target | Accepted | Provider line/path claims are not trusted automatically |
| D-016 | One lane exists per concurrency key | Accepted | Models shared auth, cache, and rate limits more accurately than driver name |
| D-017 | A central coordinator owns dynamic fallback and run completion | Accepted | Avoids race-prone distributed state decisions |
| D-018 | Valid findings never trigger fallback | Accepted | Prevents result shopping |
| D-019 | Security, configuration, artifact, internal, and cancellation failures do not trigger fallback | Accepted | Prevents risk amplification and error masking |
| D-020 | Provider workspace access defaults to `none` | Accepted | Reduces source mutation and broad file access |
| D-021 | Mutation guard is anomaly detection, not isolation | Accepted | Avoids a false security claim |
| D-022 | Project config is declarative-only by default | Accepted | Prevents a reviewed repository from choosing its own reviewer command |
| D-023 | Shell providers are disabled by default and cannot be enabled by project config | Accepted | Improves safety and reproducibility |
| D-024 | Default result combination is called aggregation, not consensus | Accepted | Primary/fallback does not produce independent same-role agreement |
| D-025 | CI policy is separate from review verdict | Accepted | Distinguishes review content from organizational enforcement |
| D-026 | Domain state types remain separate | Accepted | Prevents process, parsing, validation, verdict, and finding lifecycle confusion |
| D-027 | Exact Git object IDs and captured bytes define target identity | Accepted | Mutable refs and patch hashes alone are insufficient for delta and replay |
| D-028 | CLI targeting selects a provider instance, while the scheduler derives the lane from its concurrency key | Accepted | Users choose execution identity, not an internal queue |
| D-029 | A logical attempt contains one initial invocation and optional bounded repair invocations | Accepted | Preserves one role/provider result while recording every child process separately |
| D-030 | **Revision 13 staged platform scope:** `darwin-arm64` is the sole G0 required/blocking native platform; `linux-amd64`, `linux-arm64`, and `darwin-amd64` are intended-future, non-blocking, unsupported, and release-ineligible inventory cells | Accepted — Revised | Windows and network filesystems are unsupported or deferred. Only the required platform cell can block G0 external readiness; future inventory does not claim current support |
| D-031 | `kimi`, `zcode`, and `agy` are intended provider families; `codex` and `claude` are optional configuration only | Accepted | A provider is supported only after the exact tuple and role-fit probes PASS; there is no automatic provider substitution |
| D-032 | Six functional roles are enabled by default; logic and security are the required floor | Accepted | Assignment freezes only after evidence, uses hard PASS constraints and lexical selection, and requires different normalized fallback keys for required roles |
| D-033 | Outcome has four independent axes and the default request-changes threshold is `high` | Accepted | Content verdict, coverage, publication, and CI serialize independently; a high finding does not erase a required-role failure |
| D-034 | Optional exhaustion may publish degraded valid content; required exhaustion is incomplete and preserves valid content | Accepted | Trusted CI policy projects pass or fail separately; incomplete is not content deletion |
| D-035 | Cleanup automatically retains every transitive ancestor reachable from a retained run | Accepted | Retained seed, graph anomalies, dry-run reasons, fixed epoch, and tombstone recovery prevent accidental lineage deletion |
| D-036 | CI uses trusted-base policy and project configuration may only strengthen it monotonically | Accepted | A mixed strengthening/weakening proposal is rejected atomically with exit `2`; provenance and CLI taint are recorded |
| D-037 | A valid committed manifest/lineage epoch is publication authority and publication recovery is derived from durable observations | Accepted | Persisted journal state is a hint; precedence is ambiguity/mismatch, P2 committed, P1 installed, P0 staged, P0-none hint recovery, then corrupt default |
| D-038 | Untrusted prompt sections and referenced evidence carry canonical identity, length, hash, and lineage | Accepted | Prompt wire identity is byte exact; source and current evidence keep separate target and excerpt identities and source evidence cannot become current verification |

## 1.1 Current Decision and Implementation Status

D-030 through D-038 extend D-001 through D-029 and remain the frozen Revision 13 contract decisions. SOT 1.2.0 records that G001 completed Gate A, required provider/platform evidence, promotion, authority CAS, post-verification `g0_complete`, support derivation, and separate implementation approval.

G002 through G005 then completed the domain/ports foundation, trusted adapters and foundation CLI, prompt/validation/fake-review slice, and coordinator/runtime/evidence/axes boundary. G006 through G009 remain pending. The current SOT oracle remains 17 product commands, 4 canonical probe argv, 71 catalog paths, 70 checksummed payloads, 23 schema/example pairs, and 16 G0-required pairs. No pending goal, product live-adapter support, release CI, or release asset is authorized by the completed boundary.


## 2. Superseded Draft Decisions

| Draft concept | Final decision |
|---|---|
| `.kar/runs/<run_id>/` | `.kar/{session_id}/{run_id}/` |
| `review_{hash}.json` | `review_{uuidv7}.json`, with SHA-256 in manifest |
| `lineage_id` | `session_id` |
| `consensus.json` | `aggregation.json` |
| Single status enum | Separate run, task, attempt, parse, validation, evidence, verdict, and lifecycle enums |
| Provider lane keyed only by provider label | Lane keyed by `concurrency_key` |
| Mutation guard as v0.1 protection | Workspace isolation first, mutation detection as supplementary |
| Immediate fallback on parser failure | One constrained repair, then fallback if eligible |
| Project role guide override as normal behavior | Disabled by default or loaded only through explicit trusted policy |
| Rerun adds an attempt to completed run | Rerun creates a child run |
| Historical pre-Revision-13 D-030 | All four native cells were G0 required/blocking | Superseded by the staged-support D-030 revision; the three non-`darwin-arm64` cells are now intended-future, non-blocking, unsupported, and release-ineligible |

## 3. G0 External Verification Items and Future Inventory

These are evidence requirements and future-inventory declarations, not unresolved product semantics and not current PASS claims.

| Item | Required evidence or declared scope | Current contract status |
|---|---|---|
| Intended provider tuple: `kimi` | Its exact runtime-contract tuple's 16 canonical probes and secure-writer index | UNVERIFIED |
| Intended provider tuple: `zcode` | Its exact runtime-contract tuple's 16 canonical probes and secure-writer index | UNVERIFIED |
| Intended provider tuple: `agy` | Its exact runtime-contract tuple's 16 canonical probes and secure-writer index | UNVERIFIED |
| Provider join and assignment | All 48 provider probes, all three secure-writer indexes, and live six-role assignment | UNVERIFIED |
| Required native platform: `darwin-arm64` | All 11 platform predicates on a native local POSIX filesystem | UNVERIFIED; G0 required/blocking |
| Intended-future inventory: `linux-amd64`, `linux-arm64`, `darwin-amd64` | Fixed NOT_RUN contract rows; no G0 native execution or PASS evidence is required, and any future support requires a new scope decision, native evidence, candidate refreeze, and promotion | UNSUPPORTED; non-blocking and release-ineligible |
| Canonical argv bundle | Four compact JSON arrays, individual hashes, and bundle hash | UNVERIFIED |
| Authority promotion | Runtime approval, integrity, candidate reviews, forward CAS, post-verification | UNVERIFIED |
| Absent-authority rollback | Runtime rollback authorization and delete-ref CAS | UNVERIFIED |

A provider tuple is `supported` only after its complete evidence passes. An INCONCLUSIVE or FAIL result is not a PASS and does not allow the provider join, assignment freeze, or External Contract Readiness to advance. The required `darwin-arm64` platform join likewise needs all 11 PASS; the intended-future cells cannot establish present support or make a release eligible.

## 4. Publication and Authority Verification Items

| Item | Required decision or test |
|---|---|
| Four outcome axes | Independent content, coverage, publication, and CI serialization and cross-axis fixtures |
| Trusted-base policy | Monotonic project merge, field provenance, CLI taint, and atomic exit `2` rejection |
| P2 publication authority | Matching final file, committed manifest, lineage edge, and composite epoch |
| P1/P0 recovery | Journal-bound installed or staged artifact recovery without publication authority |
| Cross-boundary crash recovery | Ten named fixtures with total, unambiguous classifier output |
| Corruption handling | Multiple/mismatched, missing, escaped, symlink, or non-regular observations derive immutable `corrupt` and exit `7` |
| Cleanup linearization | Retained seed, ancestor closure, fixed epoch, exact plan hash, tombstone restart, and stale-plan rejection |
| Promotion and rollback | Runtime-only approvals and expected-old-state forward or delete-ref CAS |

## 5. Future Decisions Outside v0.1

- Explicit multi-provider comparison and consensus strategy.
- Cryptographic signing of final artifacts.
- Remote artifact storage.
- Formal chunking for oversized targets.
- Organization-managed policy bundles.
- Provider network sandbox integration.
- Custom project roles beyond built-in roles.
- Structured SARIF export.

These features must preserve the accepted invariants in this specification.
