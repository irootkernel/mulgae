# Delivery Roadmap

## 1. Status and Authority Boundary

This roadmap records SOT 1.15.0. Decision Readiness remains **READY**; G001–G012 retain historical evidence, runtime diagnostics are implemented, and G013 is `RELEASE_READY` after the login-recovering exact-binary workflow and subsequent capability suite passed on the final tree.

| Ultragoal | Roadmap phase | Status |
|---|---|---|
| G001 | G0 authority promotion and completion | **COMPLETE** |
| G002 | G1A domain and ports foundation | **COMPLETE** |
| G003 | G1B trusted adapters and foundation CLI | **COMPLETE** |
| G004 | G2 prompt validation, repair, fake review | **COMPLETE** |
| G005 | G3A coordinator, runtime, evidence, independent outcome axes | **COMPLETE** |
| G006 | G3B publication, recovery, reporting | **COMPLETE** |
| G007 | G4 opt-in provider adapters | **COMPLETE** |
| G008 | G5 lineage, cleanup, export | **COMPLETE** |
| G009 | Production review verification | `REOPENED_PRODUCTION_REVIEW_INCOMPLETE` |
| G010 | Historical config-driven multi-provider production release gate | **COMPLETE** |
| G011 | Corrected deterministic acceptance and live family certification | `RELEASE_READY` |
| G012 | Restore exact release-binary actual-provider root/child workflow coverage | `RELEASE_READY` |
| G013 | Exercise production Kimi login recovery before fail-closed family capability certification | `RELEASE_READY` |

G013 executes sequentially: reproduce expired-session interception; correct the gate order; retain fail-closed capability certification; exact final-tree closeout.

G0 keeps one required native platform: `darwin-arm64`. G001 completed the required G0 provider/platform evidence, authority promotion, post-verification, and support derivation. `linux-amd64`, `linux-arm64`, and `darwin-amd64` remain intended-future, non-blocking, unsupported, and release-ineligible.

The current SOT oracle remains 17 product commands, 4 canonical probe argv, 84 catalog paths, 83 checksummed payloads, 27 schema/example pairs, 20 additive G0-required pairs, and 7 frozen-v1 pairs. Prior G009–G012 evidence is historical; G013 completion depends only on its explicit checklist and final `make test`.

## 2. G0: Contract Freeze and Authority Promotion

G0 produces the SOT baseline, fixtures, evidence contracts, and authority records. It produces no product code.

| Step | Deliverable | Gate |
|---|---|---|
| G0-1A | Validator, fixture, tool-lock, secure-writer, prompt/evidence/publication/cleanup/authority evidence contracts | Gate A1; exact payload scope only |
| G0-1B | Non-normative candidate skeleton | G0-1A; cannot leak into normative bytes |
| G0-2 | Integrated SOT documentation and decisions | G0-1B |
| G0-3 | Strict schemas, examples, command/doctor/export envelopes, 4 canonical probe argv, and the 84-path/83-payload catalog | G0-2; 27 schema/example pairs, 20 additive G0-required plus 7 frozen-v1 pairs |
| G0-4 | Freeze candidate bytes, checksums, subtree/root/commit identity, and integrity receipt | G0-3; no authority-eligible probe, assignment, Architect, or Critic evidence exists before this freeze |
| G0-5 | Issue the candidate-bound evidence Gate, then execute all required provider and `darwin-arm64` platform probes | G0-4; future cells remain non-blocking, unsupported, release-ineligible, and fixed NOT_RUN |
| G0-6 | Produce the deterministic live six-role assignment, exact 27-entry receipt index, readiness receipt, and `G0_EXTERNAL_JOIN_ORACLE` result | G0-5; no score-based selection and no candidate refreeze after evidence |
| G0-7 | The single authoritative Architect/Critic review, promotion authorization, authority-ref CAS, and post-verification | G0-6 and a passing `G0_EXTERNAL_JOIN_ORACLE` |

The exact G0 validator set is `p0`, `schema`, `trace`, `marker`, `trust`, `command`, `canonical-argv`, `failure`, `publication`, `prompt`, `evidence`, `cleanup`, `assignment`, `integrity`, `authority`, `checksums-generate`, and `checksums-verify`. Publication validation must prove one total classifier result per case, including `total=true`, `unmapped=0`, `ambiguous=0`, ten named cross-boundary cases, and all P2 outcome exits `0`, `1`, and `4`. Integrity validates the 84-path catalog and 83 checksummed payloads using the raw32 payload-root grammar.
Promotion is acyclic: the G0-4 candidate bytes and identity precede candidate-bound G0-5/G0-6 evidence and the single authoritative G0-7 Architect `CLEAR|APPROVE` and Critic `OKAY` review; that review precedes runtime promotion authorization; authorization precedes authority-ref CAS; CAS precedes post-verification and `g0_complete`. A failed or missing predicate stops promotion. No authority-eligible evidence survives a candidate refreeze. Rollback to an absent initial authority uses delete-ref CAS, not a fabricated zero target. `g0_complete` does not itself authorize product work.
Gate A1/A2 canonical paths are current pointers. Their forward-only issuance and archive verification use the fail-closed protocol in [Artifacts, Lineage, and Storage](08-artifacts-lineage-and-storage.md#15-g0-gate-archive-resolution). Promotion authorization must also bind a fresh candidate-specific authority-ref read whose wire value is exact `ABSENT` or a lowercase 40-hex OID; diagnostic state with `authoritative=false` or a zero-OID sentinel is not promotion evidence.

## 3. G1: Foundation After Authorization

G1 starts only after `g0_complete` and independent implementation approval.

Deliver:
- domain entities, separate state enums, UUIDv7 identifiers, and typed errors;
- trusted configuration, command envelopes, `init`, `config`, `schema`, `help`, and `doctor`;
- immutable target capture and the artifact-store foundation;
- strict versioned DTOs and secure untrusted-byte persistence.

Acceptance:
- invalid transitions and untrusted configuration weakening fail;
- target identity uses captured bytes and object IDs rather than mutable refs;
- doctor reports intended or unverified provider state without substitution;
- product paths do not claim provider or platform support without G4/G6 evidence.

## 4. G2: Fake-Provider Review Slice

Deliver:
- deterministic prompt compilation and exact stdin provenance;
- fake-provider review flow, strict parser, schema/semantic validation, and constrained repair;
- four-axis aggregation inputs and artifact construction without live providers.

Acceptance:
- canonical prompt frames, hashes, replay identity, and source/current evidence boundaries hold;
- high findings and required-role gaps preserve independent content and coverage results;
- no provider output owns final IDs, verdicts, publication authority, or CI policy.

## 5. G3: Coordination, Publication, and Reporting

Deliver:
- central coordinator, concurrency-key lanes, bounded repair and eligible fallback;
- evidence validation, report/query surfaces, and four-axis projections;
- publication, composite lineage epoch, crash recovery, and immutable corruption diagnostics.

Acceptance:
- fallback never follows a valid finding, security event, cancellation, or ineligible failure;
- publication derives `not_published`, `staged`, `installed`, `committed`, or `corrupt` from durable observations, with P2 as the only publication authority;
- a completed run remains immutable and report output agrees with committed JSON;
- coordinator race and recovery cases use deterministic fakes, clocks, and traces.

## 6. G4: Opt-In Provider Contracts

Deliver:
- completed opt-in, evidence-gated adapter construction and `providers`/`doctor` reporting for exactly `kimi`, `zcode`, and `agy`;
- runtime capability and role-fit evidence, with version, executable path, SHA-256, and adapter profile retained as diagnostic provenance.

Acceptance:
- standard CI remains network- and credential-free;
- standalone remains unverified absent injected authority evidence and does not guess, create, or load a hidden authority source;
- an allowlisted configured family is supported when its runtime capability and role-fit contracts succeed; version, executable path, SHA-256, and adapter profile do not gate ordinary use;
- unavailable, inconclusive, failed, missing, or otherwise unsuccessful required runtime capabilities remain unsupported and block dependent assignments; a failure does not authorize family substitution;
- the exact Kimi tuple `kimi/local-default/0.23.6/50c3582a1beeba081271193b74efc39c51b3a0a16b4bf32b754b9482a86a314a/kimi-default`, with receipt SHA-256 `1227711091fc94aff32dfed18d34f009da7404862b1eb63d99a2313a30c2be27`, is historical controlled qualification evidence only; it does not pin ordinary support to that tuple. G0 provider-family evidence for `kimi`, `zcode`, and `agy` remains separate from release/platform status.
- every unlisted provider family, including `codex` and `claude`, remains disabled and is rejected by strict configuration until a separately approved SOT extension lists it; no such family is an automatic fallback.

## 7. G008: Lineage, Retention, and Export

G008 delivered:
- application services and CLI dispatch boundaries for `followup`, `delta`, `rerun`, `clean`, and `export`; fake/composed offline P2 verification does not close production review verification;
- immutable lineage edges, source/current evidence views, retention planning, tombstones, and redacted export;
- executable behavior proven through fake/composed offline P2 workflow coverage across review-shaped, followup, delta, and exact rerun flows, plus focused cleanup and export tests; production `kar review` is composed and wired, but this offline evidence is not a substitute for its required authority gates and family-distinct normal P2 receipts.

G008 acceptance:
- every workflow creates a new run and preserves source bytes;
- clean protects the retained seed, transitive ancestors, corrupt components, and newest session runs;
- dry-run/apply uses fixed epoch and exact plan hash; stale plans fail rather than recompute;
- export and cleanup use secure paths, reject symlink escape, and keep redaction/export ownership in their application and adapter boundaries.

G008 completion is not the G010 production gate. Its evidence remains historical; G010 uses configured assignments, production child workflows, and real-provider E2E.

## 8. G6: Future Platform Support Hardening

This is a future, separately approved product-delivery milestone. It neither establishes G0 success nor changes any cell's current support status.

Deliver:
- native hardening and regression coverage planned for `linux-amd64`, `linux-arm64`, `darwin-amd64`, and `darwin-arm64`;
- process, lock, rename, permission, fsync, recovery, and crash behavior evidence.

Acceptance:
- each future product-supported cell passes its separately approved native platform contract;
- `linux-amd64`, `linux-arm64`, and `darwin-amd64` remain unsupported and release-ineligible until a future scope decision, native evidence, candidate refreeze, and promotion;
- Windows and network filesystems remain unsupported unless a separately approved contract extends the scope;
- platform-specific behavior never weakens publication, cleanup, trust, or security invariants.

## 9. Release Blockers

The following block release or promotion:
- implementation before `g0_complete` and separate implementation approval;
- any missing G0 validator receipt or failed probe required by its join;
- a false external PASS or unsupported-provider declaration;
- project-controlled executable configuration or trust weakening;
- final publication before evidence policy, or publication without a valid P2 composite;
- fallback after valid findings, secret exposure, cancellation, or an ineligible failure;
- mutable completed artifacts, non-atomic final writes, stale cleanup application, or CAS retry with altered expected state;
- absent source/current evidence identity, unversioned machine output, or secret persistence.
- failure of `G0_EXTERNAL_JOIN_ORACLE`; intended-future cells do not block G0 and remain release-ineligible.
- failure of the exact final committed-tree G013 `make test`, including any skipped or failed Kimi, ZCode, AGY, exact-binary workflow, or required Playwright prerequisite; tagging or publishing remains an explicit operator action after technical release readiness.
