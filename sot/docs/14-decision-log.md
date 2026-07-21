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
| D-031 | `kimi`, `zcode`, and `agy` are the allowlisted provider families; `codex` and `claude` are not supported | Accepted — Superseded in part by D-040 | Historical G0 qualification used exact tuples and role-fit probes; D-040 supersedes exact-tuple product-support gating while retaining those receipts as historical evidence |
| D-032 | Six functional roles are enabled by default; logic and security are the required floor | Accepted — Revised by D-044 | A singleton eligible family may cover every primary with null fallbacks and degraded resilience; multi-family assignment retains distinct fallback constraints for required roles |
| D-033 | Outcome has four independent axes and the default request-changes threshold is `high` | Accepted | Content verdict, coverage, publication, and CI serialize independently; a high finding does not erase a required-role failure |
| D-034 | Optional exhaustion may publish degraded valid content; required exhaustion is incomplete and preserves valid content | Accepted | Trusted CI policy projects pass or fail separately; incomplete is not content deletion |
| D-035 | Cleanup automatically retains every transitive ancestor reachable from a retained run | Accepted | Retained seed, graph anomalies, dry-run reasons, fixed epoch, and tombstone recovery prevent accidental lineage deletion |
| D-036 | CI uses trusted-base policy and project configuration may only strengthen it monotonically | Superseded by D-043 | Retained as historical reducer behavior only; current configuration has one project-local authority |
| D-037 | A valid committed manifest/lineage epoch is publication authority and publication recovery is derived from durable observations | Accepted | Persisted journal state is a hint; precedence is ambiguity/mismatch, P2 committed, P1 installed, P0 staged, P0-none hint recovery, then corrupt default |
| D-038 | Untrusted prompt sections and referenced evidence carry canonical identity, length, hash, and lineage | Accepted | Prompt wire identity is byte exact; source and current evidence keep separate target and excerpt identities and source evidence cannot become current verification |
| D-039 | G008 owns the application/CLI boundary for `followup`, `delta`, `rerun`, `clean`, and `export`; its composed P2 verification surface also exercises the established `review` workflow, while immutable lineage, retention, and redacted export remain application and adapter responsibilities | Accepted | Keeps CLI parsing/envelope rendering separate from child-run creation, cleanup-plan authority, and export/redaction effects |
| D-040 | Ordinary provider support is family-and-capability based: only allowlisted `kimi`, `zcode`, and `agy` families may run, and each must satisfy its runtime capability and role-fit contracts | Accepted | Version, executable path, SHA-256, and adapter profile are diagnostic provenance for issue reporting and reproduction, not authorization. Direct argv, trusted process-profile safety, bounded execution, fail-closed capability failures, and no automatic family substitution remain required. Historical exact-tuple receipts remain qualification evidence only |
| D-041 | Reopen production review implementation | Accepted — Reopened | Current status is `REOPENED_PRODUCTION_REVIEW_INCOMPLETE`: production `kar review` is composed and wired, but final closure is not authorized until all required offline and authority gates pass and three family-distinct normal P2 receipts exist for `kimi`, `zcode`, and `agy`. Prior integrated-gate evidence is retained as `HISTORICAL_GATE_PASS_NON_PRODUCTION`; it is not a current production-completeness claim. Release CI, asset creation, and publication remain separately approved actions. |
| D-042 | macOS AGY native-auth boundary | Accepted — implementation reopened | AGY authentication uses only an explicitly captured, inode-revalidated installed-user native `HOME`/Keychain context. KAR never substitutes a synthetic `HOME`, projects AGY credentials, or copies OAuth or installation files. KAR's namespace setup, policy, and cleanup paths never write, overwrite, zero, or unlink user AGY authentication or settings files; AGY may still perform normal provider-owned Keychain/profile refresh while running. The authentication home remains separate from the descriptor-bound immutable review CWD and KAR-owned XDG/cache/temp/scratch namespaces. Kimi and ZCode retain isolated `HOME` directories plus credential projection. KAR does not install an AGY `settings.json` policy; its enforceable controls are `--sandbox`, exact immutable-snapshot `--add-dir`, `--mode plan`, bounded time/output, and post-output `SIGTERM`/`SIGKILL`. This decision does not claim live P2 success. |
| D-043 | `.kar/config.yaml` is the sole runtime configuration authority | Accepted | Global, XDG, embedded-default, legacy project, migration, and fallback reads are removed; admission binds descriptor, ownership, mode, checkout, index, commits, and target locality |
| D-044 | Any nonempty subset of `kimi,zcode,agy` is operational | Accepted | Singleton assignment uses null fallbacks and reports degraded resilience at exit `0`; missing primaries remain unavailable |
| D-045 | Provider-native state is projected from configured roots and AGY privilege is explicit | Accepted | Kimi and ZCode use configured descriptor-bound sources. AGY uses the installed-user home and explicit permission mode with no probing or automatic escalation |
| D-046 | Init and review locality are immutable barriers | Accepted | Init crosses durability barriers before commit. Review binds checkout/index, applicable commits, target bytes, config identity, qualification, and every spawn; drift fails closed. Pure native-home observation cancellation aborts init/config/doctor at exit 9 without admitting identity or emitting partial authority. Help is repository-independent because it renders only embedded documentation and reads no configuration. |

## 1.1 Current Decision and Implementation Status

D-030 through D-042 remain historical and active except where explicitly superseded. D-043 through D-046 define the current project-local authority, provider-subset, provider-state, and locality contracts. Production closure remains separately gated by current offline, authority, and family-distinct P2 evidence. The earlier G001 authority record remains historical evidence, not a production `kar review` closure.

The prior G002 through G009 implementation and integrated-gate record is `HISTORICAL_GATE_PASS_NON_PRODUCTION`. Historical evidence remains qualification provenance, not current closure. The current SOT oracle is 17 product commands, 4 canonical probe argv, 85 catalog paths, 84 checksummed payloads, and 25 schema/example pairs. Production closure remains incomplete pending separately required current evidence. Only `darwin-arm64` is supported; future platforms remain unsupported and release-ineligible.


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

These distinguish historical G0 qualification evidence and future-inventory declarations from ordinary provider support; historical G0 PASS receipts do not impose version or SHA-256 product-support gates.

| Item | Required evidence or declared scope | Current contract status |
|---|---|---|
| Historical G0 provider-family evidence: `kimi` | Its exact runtime-contract tuple's 16 canonical probes and secure-writer index | PASS; historical qualification evidence only, not a product-live claim |
| Historical G0 provider-family evidence: `zcode` | Its exact runtime-contract tuple's 16 canonical probes and secure-writer index | PASS; historical qualification evidence only |
| Historical G0 provider-family evidence: `agy` | Its exact runtime-contract tuple's 16 canonical probes and secure-writer index | PASS; historical qualification evidence only |
| Historical provider join and assignment | All 48 provider probes, all three secure-writer indexes, and live six-role assignment | PASS; historical qualification evidence only |
| Historical controlled Kimi qualification receipt | `kimi/local-default/0.23.6/50c3582a1beeba081271193b74efc39c51b3a0a16b4bf32b754b9482a86a314a/kimi-default`; receipt SHA-256 `1227711091fc94aff32dfed18d34f009da7404862b1eb63d99a2313a30c2be27` | PASS; diagnostic provenance, not an ordinary-use version or SHA-256 gate |
| Required native platform: `darwin-arm64` | All 11 platform predicates on a native local POSIX filesystem | PASS; sole supported platform |
| Intended-future inventory: `linux-amd64`, `linux-arm64`, `darwin-amd64` | Fixed NOT_RUN contract rows; no G0 native execution or PASS evidence is required, and any future support requires a new scope decision, native evidence, candidate refreeze, and promotion | UNSUPPORTED; non-blocking and release-ineligible |
| Canonical argv bundle | Four compact JSON arrays, individual hashes, and bundle hash | PASS |
| Authority promotion | Runtime approval, integrity, candidate reviews, forward CAS, post-verification | PASS |
| Absent-authority rollback | Runtime rollback authorization and delete-ref CAS | VERIFIED; available when separately authorized |

An allowlisted provider family is supported when its runtime capability and role-fit contracts succeed. An INCONCLUSIVE or FAIL required capability is not a PASS and does not allow that provider's assignment to advance; it does not authorize a different family as an automatic substitute. Version, executable path, SHA-256, and adapter profile are diagnostic provenance only. The historical exact-tuple evidence above remains qualification evidence and does not constrain ordinary support. The required `darwin-arm64` platform join has all 11 PASS and is the sole supported platform; intended-future cells cannot establish present support or become release eligible. Release CI, asset creation, and publication remain separately approved actions; no asset was created.

## 4. Publication and Authority Verification Items

| Item | Required decision or test |
|---|---|
| Four outcome axes | Independent content, coverage, publication, and CI serialization and cross-axis fixtures |
| Project-local configuration authority | Complete-document semantic admission, code-fixed safety floors, locality re-attestation, and atomic rejection without partial merge |
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
