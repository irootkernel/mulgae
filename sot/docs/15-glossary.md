# Glossary

| Term | Definition |
|---|---|
| Adapter profile | Versioned provider integration rules, including invocation and output contract |
| Aggregation | Deterministic combination of selected valid role results without claiming consensus |
| Attempt | One logical primary or fallback provider selection for a role task, containing an initial invocation and optional repair invocations |
| Invocation | One child-process execution inside an attempt |
| Captured target | Immutable bytes and metadata that define what was reviewed |
| Common contract | Highest-priority KAR prompt instructions shared by all attempts |
| Concurrency key | Key that serializes provider attempts sharing auth, cache, or rate limits |
| Delta | Difference between a previous immutable target snapshot and a newly captured snapshot |
| Evidence | Source location and content that supports a finding |
| Evidence verification | KAR's deterministic check that provider evidence matches the captured target |
| Fallback | Secondary provider attempt scheduled only after a qualifying primary failure |
| Finding | Normalized, evidence-backed review issue assigned a KAR identifier |
| Finding fingerprint | Stable hash used to assist matching or deduplication across runs |
| Followup | New run that evaluates whether one prior finding has been addressed |
| Functional role | Review lens such as logic, security, or testing |
| Config locality context | Immutable proof binding the project root, checkout, complete index, applicable commits, config identity, and parsed target decision |
| Lane | Serial queue for one concurrency key |
| Manifest | Run-level index and integrity record |
| Objective | User-supplied text that narrows review focus without overriding contracts |
| Primary | First configured provider instance for a role task |
| Project config | Sole operator-local runtime authority at `.kar/config.yaml`, admitted through locality and private-file checks |
| Provider driver | Adapter family for a provider CLI |
| Provider instance | Local executable and runtime settings for one driver/account/profile |
| Provider output | Untrusted JSON claim produced by a provider attempt |
| Publication | Store protocol that exposes a final review only through P2 committed authority; P0 and P1 are recovery states, not publication |
| Repair | Bounded AI request to reformat output or fill explicitly allowed missing AI-owned fields |
| Rerun | New run that repeats a prior attempt using exact or recomposed input |
| Review | New independent review run over a captured target |
| Review artifact | Final validated machine-readable result published under the canonical path |
| Review verdict | KAR-computed content result: no findings, findings present, or request changes; completeness is the separate coverage status |
| Role task | Required work for one selected functional role within a run |
| Run | One immutable execution of review, followup, delta, or rerun |
| Session | Lineage grouping a root review and its related later runs |
| System-owned field | Metadata generated deterministically by KAR, never by AI |
| Validation pipeline | Schema, semantic, and evidence checks applied before publication |
| Workspace access | Provider filesystem exposure mode: `none` or `readonly_snapshot`. The legacy `project` concept is not selectable and is rejected; KAR never exposes the live project root through this setting. |
| Content verdict | Aggregation-owned content axis: `no_findings`, `findings_present`, or `request_changes` |
| Coverage status | Coordinator-owned coverage axis: `complete`, `degraded`, or `incomplete` |
| Publication status | Store-derived publication axis: `not_published`, `staged`, `installed`, `committed`, or `corrupt` |
| CI decision | Trusted CI policy axis: `pass` or `fail`, accompanied by reason codes |
| Decision Readiness | Whether the SOT contract is settled; G0 records this as `READY` |
| Implementation Readiness | Current production implementation status. It is `RELEASE_READY`: production `kar review` and its child workflows passed G011 deterministic acceptance plus one live capability certification for each supported family through the sole exact-tree `make test` gate. The prior G002–G009 integrated-gate record remains `HISTORICAL_GATE_PASS_NON_PRODUCTION`, not the current acceptance predicate. Release CI, asset creation, and publication remain separately approved actions. |
| External Contract Readiness | Whether allowlisted provider families satisfy current runtime capability and security contracts and native platform cells satisfy their declared support contracts. G011 verifies the current Kimi, ZCode, and AGY capability boundary; a missing required capability fails closed. Only `darwin-arm64` is supported; future platforms remain unsupported. Historical exact-tuple evidence, including the Kimi receipt `kimi/local-default/0.23.6/50c3582a1beeba081271193b74efc39c51b3a0a16b4bf32b754b9482a86a314a/kimi-default` with receipt SHA-256 `1227711091fc94aff32dfed18d34f009da7404862b1eb63d99a2313a30c2be27`, is diagnostic provenance, not ordinary-use version or SHA-256 gating. |
| Gate A | Session-bound GJC runtime approval that permits G0 contract/evidence work; it is not implementation approval |
| G0 complete | Post-promotion, post-verification authority record that closes G0; spelled `g0_complete` in authority records |
| Implementation approval | Separate session-bound GJC runtime approval required after `g0_complete` before product code may be implemented |
| Intended provider | A configured provider family that is not currently supported because it is unlisted or its required runtime capability contracts have not succeeded; it is never silently substituted. |
| Supported provider | An allowlisted `kimi`, `zcode`, or `agy` provider family whose current runtime capability and security contracts succeed. Version, executable path, SHA-256, and adapter profile are diagnostic provenance for issue reporting and reproduction, not support authorization. Doctor guidance records a minimum-version floor and verified-latest baseline: below-minimum is red, versions above verified latest are yellow and allowed, and unknown versions are yellow. |
| Platform cell | One native platform contract target: `linux-amd64`, `linux-arm64`, `darwin-amd64`, or `darwin-arm64` |
| Safety floor | Code-fixed invariant that the project-local configuration cannot weaken or replace |
| Four-axis outcome | The independent combination of content verdict, coverage status, publication status, and CI decision |
| Persisted journal state | Durable progress hint: `collecting`, `content_validated`, `final_staged`, `final_file_installed`, `manifest_committed`, or `completed` |
| Derived publication state | Recovery classifier result derived from durable observations rather than copied from the journal hint |
| P0 staged authority | Recovery-only authority for exactly one validated staged temporary artifact bound to journal path and hash |
| P0 none | Absence of staged, installed, or committed durable publication observations, with no forbidden partial or multiple artifacts |
| P1 installed authority | Recovery-only authority for exactly one validated installed final artifact bound to journal path and hash, without P2 |
| P2 committed authority | The sole publication authority: a matching final file, committed manifest, lineage edge, and composite epoch |
| Ambiguous or mismatch | A multiple, missing, escaped, symlink, non-regular, journal, path, hash, schema, manifest, edge, or epoch inconsistency that derives `corrupt` and exit `7` |
| Publication classifier | The total reducer ordered ambiguity/mismatch, P2, P1, P0 staged, P0-none hint recovery, then corrupt default |
| Cross-boundary recovery | Recovery from a crash after a durable side effect but before the corresponding journal-state write |
| Retained seed | Explicitly kept, active, uncommitted, corrupt, and newest-per-session runs protected before cleanup ancestor closure |
| Authority-ref CAS | Compare-and-swap update of the authoritative SOT Git ref using the approved expected old state |
| Delete-ref CAS | Compare-and-swap deletion of an authority ref when rollback returns to an initially absent authority |
| Secure writer | Shared scan-before-write persistence boundary for newly durable untrusted bytes |
| G008 application boundary | Historical application-boundary evidence for `followup`, `delta`, `rerun`, cleanup, and redacted export. It is retained as `HISTORICAL_GATE_PASS_NON_PRODUCTION`; production `kar review` is composed and wired, but this historical evidence does not establish its required authority gates or family-distinct normal P2 receipts. |
| G009 integrated verification gate | Historical integrated-gate evidence retaining repository test, `go vet`, race, cleaner, executor-QA, architect-review, and integrated-gate evidence categories. It is classified `HISTORICAL_GATE_PASS_NON_PRODUCTION`; it does not authorize production closure, release CI, asset creation, or publication. |
| Reopened production review | Historical G009 decision token `REOPENED_PRODUCTION_REVIEW_INCOMPLETE`. G011 supersedes that current-state claim with `RELEASE_READY` while retaining the historical integrated-gate record as non-production evidence. |
| Runtime diagnostic event | One validated safe operational transition in the run-wide `kar-runtime-log.v1` sequence |
| Runtime diagnostic sink | Run-scoped port that serializes events, installs separated raw streams, replaces status projections, and finalizes private diagnostics |
| Diagnostic-only run | A private finalized diagnostic record without P2 publication authority |
| Mandatory tail reserve | JSONL capacity reserved only for lifecycle, error, terminal, and finalize events after ordinary event capacity is exhausted |
