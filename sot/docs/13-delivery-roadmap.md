# Delivery Roadmap

## 1. Status and Authority Boundary

This roadmap records Revision 13 Option B under SOT 1.2.0 and the verified delivery boundary through G3A. Decision Readiness is **READY**; G001–G005 are **COMPLETE**; G006–G009 are **PENDING**.

| Ultragoal | Roadmap phase | Status |
|---|---|---|
| G001 | G0 authority promotion and completion | **COMPLETE** |
| G002 | G1A domain and ports foundation | **COMPLETE** |
| G003 | G1B trusted adapters and foundation CLI | **COMPLETE** |
| G004 | G2 prompt validation, repair, fake review | **COMPLETE** |
| G005 | G3A coordinator, runtime, evidence, axes | **COMPLETE** |
| G006 | G3B publication, recovery, reporting | **PENDING** |
| G007 | G4 opt-in provider adapters | **PENDING** |
| G008 | G5 lineage, cleanup, export | **PENDING** |
| G009 | Integrated v0.1 release gate | **PENDING** |

G0 keeps one required native platform: `darwin-arm64`. G001 completed the required G0 provider/platform evidence, authority promotion, post-verification, and support derivation. `linux-amd64`, `linux-arm64`, and `darwin-amd64` remain intended-future, non-blocking, unsupported, and release-ineligible.

The current SOT oracle remains 17 product commands, 4 canonical probe argv, 71 catalog paths, 70 checksummed payloads, 23 schema/example pairs, and 16 G0-required pairs. G001 completion authorized G002–G005 only through their separately accepted stories; it does not authorize pending G006–G009 work or a release.

## 2. G0: Contract Freeze and Authority Promotion

G0 produces the SOT baseline, fixtures, evidence contracts, and authority records. It produces no product code.

| Step | Deliverable | Gate |
|---|---|---|
| G0-1A | Validator, fixture, tool-lock, secure-writer, prompt/evidence/publication/cleanup/authority evidence contracts | Gate A1; exact payload scope only |
| G0-1B | Non-normative candidate skeleton | G0-1A; cannot leak into normative bytes |
| G0-2 | Integrated SOT documentation and decisions | G0-1B |
| G0-3 | Strict schemas, examples, command/doctor/export envelopes, 4 canonical probe argv, and the 71-path/70-payload catalog | G0-2; 23 schema/example pairs, 16 G0-required |
| G0-4 | Freeze candidate bytes, checksums, subtree/root/commit identity, and integrity receipt | G0-3; no authority-eligible probe, assignment, Architect, or Critic evidence exists before this freeze |
| G0-5 | Issue the candidate-bound evidence Gate, then execute all required provider and `darwin-arm64` platform probes | G0-4; future cells remain non-blocking, unsupported, release-ineligible, and fixed NOT_RUN |
| G0-6 | Produce the deterministic live six-role assignment, exact 27-entry receipt index, readiness receipt, and `G0_EXTERNAL_JOIN_ORACLE` result | G0-5; no score-based selection and no candidate refreeze after evidence |
| G0-7 | The single authoritative Architect/Critic review, promotion authorization, authority-ref CAS, and post-verification | G0-6 and a passing `G0_EXTERNAL_JOIN_ORACLE` |

The exact G0 validator set is `p0`, `schema`, `trace`, `marker`, `trust`, `command`, `canonical-argv`, `failure`, `publication`, `prompt`, `evidence`, `cleanup`, `assignment`, `integrity`, `authority`, `checksums-generate`, and `checksums-verify`. Publication validation must prove one total classifier result per case, including `total=true`, `unmapped=0`, `ambiguous=0`, ten named cross-boundary cases, and all P2 outcome exits `0`, `1`, and `4`. Integrity validates the 71-path catalog and 70 checksummed payloads using the raw32 payload-root grammar.
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
- provider probes, profiles, adapter implementations, and `providers`/`doctor` reporting for `kimi`, `zcode`, and `agy`;
- exact tuple capability evidence and assignment inputs.

Acceptance:
- standard CI remains network- and credential-free;
- a tuple is supported only after all required provider and role-fit probes PASS;
- unavailable, inconclusive, or failed tuples remain non-supported and block dependent assignments;
- every unlisted provider family, including `codex` and `claude`, remains disabled and is rejected by strict configuration until a separately approved SOT extension lists it; no such family is an automatic fallback.

## 7. G5: Lineage, Retention, and Export

Deliver:
- followup, delta, rerun, clean, and export;
- immutable lineage edges, source/current evidence views, retention planning, tombstones, and redacted export.

Acceptance:
- every workflow creates a new run and preserves source bytes;
- clean protects the retained seed, transitive ancestors, corrupt components, and newest session runs;
- dry-run/apply uses fixed epoch and exact plan hash; stale plans fail rather than recompute;
- export and cleanup use secure paths and reject symlink escape.

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
