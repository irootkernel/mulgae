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
| Global config | Trusted user-local configuration that may define provider executables |
| Lane | Serial queue for one concurrency key |
| Manifest | Run-level index and integrity record |
| Objective | User-supplied text that narrows review focus without overriding contracts |
| Primary | First configured provider instance for a role task |
| Project config | Limited-trust declarative repository configuration |
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
| Workspace access | Provider filesystem exposure mode: none, read-only snapshot, or live project |
| Content verdict | Aggregation-owned content axis: `no_findings`, `findings_present`, or `request_changes` |
| Coverage status | Coordinator-owned coverage axis: `complete`, `degraded`, or `incomplete` |
| Publication status | Store-derived publication axis: `not_published`, `staged`, `installed`, `committed`, or `corrupt` |
| CI decision | Trusted CI policy axis: `pass` or `fail`, accompanied by reason codes |
| Decision Readiness | Whether the SOT contract is settled; G0 records this as `READY` |
| Implementation Readiness | Whether product implementation is authorized; G001 completed the prerequisite, G002–G005 are implemented, and G006–G009 remain separately gated |
| External Contract Readiness | Whether required provider tuples and native platform cells passed; G001 verified the G0 evidence state while product live-adapter support remains pending G007 |
| Gate A | Session-bound GJC runtime approval that permits G0 contract/evidence work; it is not implementation approval |
| G0 complete | Post-promotion, post-verification authority record that closes G0; spelled `g0_complete` in authority records |
| Implementation approval | Separate session-bound GJC runtime approval required after `g0_complete` before product code may be implemented |
| Intended provider | A configured provider family awaiting complete contract evidence; intended is not supported |
| Supported tuple | A provider family, instance, version, binary, and concurrency-key tuple with all required probes passed |
| Platform cell | One native platform contract target: `linux-amd64`, `linux-arm64`, `darwin-amd64`, or `darwin-arm64` |
| Trusted base | The policy baseline used by CI; project configuration may only strengthen it monotonically |
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
