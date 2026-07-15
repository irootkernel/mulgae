# Testing Strategy

## 1. Test Pyramid

| Layer | Primary purpose | Live providers |
|---|---|---:|
| Domain unit tests | State transitions and invariants | No |
| Property tests | IDs, paths, ordering, merge and validation invariants | No |
| Adapter unit tests | Config, schemas, serializers, path safety | No |
| Integration tests | Coordinator, fake lanes, artifacts, Git snapshots | No |
| CLI golden tests | Help, errors, examples, exit codes | No |
| Provider contract tests | Versioned adapter readiness | Optional controlled environment |
| End-to-end smoke tests | Complete workflow | Fake by default, live opt-in |

Standard CI must not require provider credentials or network access.
## 1.1 G0 Contract-Freeze Validation

G0 contract validators produce contract-model receipts, while the candidate-bound provider/platform branch separately establishes external PASS evidence. G001 completed both required branches and the authority gate; G002–G005 then passed their product unit, integration, race, and adversarial suites. The G0 validator set remains exact and complete:

| Operation | Required fixture or input | Required success assertion | Receipt |
|---|---|---|---|
| `p0` | Recovered P0 snapshot and `p0-cases.json` | `P0_ATOMIC_OK` | `E/p0/receipt.json` |
| `schema` | `schema-cases.json`, SOT root | `SCHEMA_OK` | `E/schema/receipt.json` |
| `trace` | `trace-ledger.json`, 71-path catalog | `TRACE_OK`, 17 product commands, no orphan | `E/trace/receipt.json` |
| `marker` | `marker-cases.json`, SOT root | `MARKER_OK`, no forbidden non-normative marker leakage | `E/marker/receipt.json` |
| `trust` | `trust-cases.json` | `TRUST_OK` | `E/trust/receipt.json` |
| `command` | `command-cases.json`, trace ledger | `COMMAND_OK` | `E/command/receipt.json` |
| `canonical-argv` | `canonical-argv.json` | Four byte-exact arrays and bundle hash | `E/tools/canonical-argv-receipt.json` |
| `failure` | `failure-cases.json` | `FAILURE_MATRIX_OK` | `E/failure/receipt.json` |
| `publication` | `publication-cases.json` | `PUBLICATION_OK`, `total=true`, `unmapped=0`, `ambiguous=0`, `cross_boundary_cases=10`, `p2_exit_variants=3` | `E/publication/receipt.json` |
| `prompt` | `prompt-cases.json` | `PROMPT_OK` | `E/prompt/receipt.json` |
| `evidence` | `evidence-cases.json` | `EVIDENCE_OK` | `E/evidence/receipt.json` |
| `cleanup` | `cleanup-cases.json` | `CLEANUP_OK` | `E/cleanup/receipt.json` |
| `assignment` | `assignment-cases.json` | `ASSIGNMENT_OK` | `E/assignment/receipt.json` |
| `integrity` | `integrity-cases.json`, catalog, checksums | `INTEGRITY_OK`, 70 payload files, raw32 reducer | `E/integrity/receipt.json` |
| `authority` | `authority-cases.json`, runtime state receipt | `AUTHORITY_OK` | `E/authority/receipt.json` |
| `checksums-generate` | catalog and SOT payload | `CHECKSUMS_OK`, 70 payload files | `E/checksums-generate/receipt.json` |
| `checksums-verify` | checksums and SOT payload | `CHECKSUMS_OK`, 70 payload files | `E/checksums-verify/receipt.json` |

Every row uses the locked `g0_validate.py` argv and fixture hashes defined by the G0 evidence contract. Shell parsing, alternate arguments, unrecorded reserialization, and a partial operation set are invalid substitutes. Typed non-success results remain readiness `4`, artifact/hash/schema/CAS/stale `7`, security `8`, and internal invariant `10`.
The canonical-argv fixture fixes the label order `provider:kimi`, `provider:zcode`, `provider:agy`, and `platform:darwin-arm64`. Each compact one-line UTF-8 JSON array is hashed as `SHA-256("KAR-G0-ARGV/1" || 0x00 || argv_json_bytes)` without a trailing LF; the fixed-order raw32 bundle uses `KAR-G0-ARGV-BUNDLE/1\n`. The exact supplied hashes are `kimi=c092d46a84dff52a23cf5a08637cf80346a9e6a39adbe3ddac62fbc180950129`, `zcode=724db2f4e04f01ca6240eae1f5a747ecaf9881696b18ad06cd98c53dd2f5458e`, `agy=bbc244436caa277d59ed6785f513f088ad9da292990d5bc6559ceb47eb346520`, `darwin-arm64=b04269cc9a3d8b7763d41e737a8b6a12e2dd49208314dea79448760293862c9b`, and `bundle=c0353931bd27274e001b650a7a3f5e8d2fc7a1412e5a64c1bdf3ccad2adb1cd7`. Provider v2 requires `--runtime-contract` and the fixed `--gate-receipt`; legacy `--evidence-root` and `--index` are rejected. The `failure` fixture requires `timeout`, `auth`, `quota`, and `rate_limit` to have `repair=none` and `fallback=allowed`; no configured eligible fallback means exhaustion, not a changed rule.

The provider/probe branch contains exactly the three runtime-order families `kimi`, `zcode`, and `agy`, each with the same 16 probes: ten base probes plus six role-fit probes. Provider readiness requires all **48 PASS**, three secure-writer indexes **PASS**, and a live assignment receipt **PASS**; selected-only evidence is insufficient. The platform inventory retains `linux-amd64`, `linux-arm64`, `darwin-amd64`, and `darwin-arm64`, but only `darwin-arm64` is required/blocking and must complete native local-POSIX evidence for all 11 platform probes. The three future cells are `intended_future`, non-blocking, unsupported, and release-ineligible, with fixed `NOT_RUN` evidence; they are not execution targets. Provider/platform v1 evidence is compatibility-only, while only v2 evidence can enter readiness. Complete required probe PASS is exit `0`, any required INCONCLUSIVE is `4`, required probe failure is `7`, and security or mutation is `8`. G001 completed the required PASS conjunction; any future revalidation with a non-PASS required input fails closed.

Cross-axis fixtures must preserve a valid high finding with required-role exhaustion as `content_verdict=request_changes` and `coverage_status=incomplete`, then calculate publication and CI separately. Trust fixtures exercise trusted-base precedence, whole-proposal rejection of any mixed strengthening/weakening project proposal, field provenance, CLI taint, and CI non-proof. Assignment fixtures enumerate all six roles in fixed order, require PASS eligibility and different normalized fallback keys for logic and security, reject five-row/`3+1+1` candidates, enforce maximum 24 invocations, and select the lexical hard-constraint winner.

Prompt fixtures exercise canonical frames, declared length, section and stdin hashes, malformed/truncated input, fresh execution identity, and exact replay. Evidence fixtures cover source/current identity separation, stale evidence, path traversal, range errors, spoofing, hash mismatch, and missing immutable bytes. Publication fixtures cover all persisted states, P0/P1/P2 recovery, the ten named cross-boundary observations, and immutable `corrupt` diagnostics. Cleanup fixtures cover retained seeds, transitive ancestors, corrupt graph protection, separate age and size sets, fixed epoch, plan hash, tombstone restart, and stale-plan rejection. Integrity fixtures cover the 71-path catalog, 70-file checksum payload, `KAR-SOT-PAYLOAD-ROOT/1` domain, UTF-8 bytewise sorting, NUL plus raw32 digest records, and the empty-set vector. Authority fixtures cover runtime-only approvals, candidate reviews, forward CAS, delete-ref rollback CAS, post-verification, and the independent implementation approval boundary.
The publication fixture includes each exact cross-boundary ID once: `pub-cross-content-validated-staged-temp`, `pub-cross-final-staged-installed-final`, `pub-cross-final-installed-composite-commit`, `pub-cross-manifest-committed-completed-side-effect`, `pub-cross-hint-low-valid-p2`, `pub-cross-staged-and-installed-conflict`, `pub-cross-p2-manifest-edge-mismatch`, `pub-cross-completed-missing-final`, `pub-cross-final-installed-no-journal`, and `pub-cross-p0-none-impossible-high-hint`.


## 2. Domain Tests

Required cases:

- invalid run and role task transitions are rejected;
- fallback cannot start before a primary terminal failure;
- findings do not trigger fallback;
- cancellation prevents fallback;
- a completed run cannot accept new attempts;
- a published review cannot be replaced;
- a run has at most one final review;
- required-role gaps produce `incomplete`;
- verdict calculation is deterministic;
- finding IDs are stable under different attempt completion orders.

## 3. Coordinator and Lane Tests

Use a deterministic fake executor with scripted outcomes.

Scenarios:

1. Two roles on one concurrency key execute serially.
2. Two independent keys execute concurrently.
3. Primary invalid output receives one repair before fallback.
4. Repair success prevents fallback.
5. Repair exhaustion queues fallback once.
6. Valid `request_changes` result does not queue fallback.
7. Security violation cancels the run and queues no fallback.
8. User cancellation kills active attempts and closes the run.
9. A fallback lane that already has work preserves serial order.
10. Cross-process lock acquisition failure produces a typed readiness or execution diagnostic.
11. Dynamic fallback cannot race with lane shutdown.
12. Results are aggregated deterministically despite randomized completion order.

Avoid timing-only assertions. Use channels, barriers, fake clocks, and event traces.

## 4. Validation Tests

### Schema

- valid examples pass;
- missing mandatory keys fail;
- empty or whitespace-only values fail;
- placeholder values fail semantic validation;
- unknown fields fail;
- invalid enum and type fail;
- multiple JSON objects fail;
- Markdown-fenced JSON fails initial parse and enters repair policy.

### Repair

- only allowed JSON Pointer paths are accepted;
- existing meaningful values cannot be overwritten;
- system-owned paths are rejected;
- severity downgrade is rejected;
- finding deletion or reordering is rejected;
- one repair attempt is enforced;
- a repaired candidate receives full schema, semantic, and evidence validation;
- raw and repaired bytes remain separate artifacts.

### Evidence

- valid path, line, and quote pass;
- path traversal fails;
- path outside scope fails;
- invalid line fails;
- quote mismatch fails;
- old/new side confusion fails;
- high-severity finding without verified evidence fails policy;
- excerpt is generated by KAR, not accepted from provider output.

## 5. Artifact Store Tests

Required cases:

- UUIDv7 path component validation;
- atomic write produces no visible partial final file;
- simulated crash before rename leaves only a temporary file;
- final schema failure prevents rename;
- SHA-256 matches published bytes;
- manifest update is atomic;
- multiple final review files are detected as corruption;
- permissions are set to secure defaults where supported;
- symlink escape is rejected;
- cleanup never leaves artifact root;
- completed source runs remain byte-identical after followup, delta, and rerun.

## 6. Git Target Tests

Create temporary repositories to cover:

- committed base and head;
- moved symbolic base ref after capture;
- staged and unstaged changes;
- untracked files included and excluded;
- rename and copy detection;
- rebase and reverted changes;
- empty delta;
- source run target reconstruction;
- stdin or patch target without comparable snapshot;
- path names with spaces and non-ASCII characters.

The test asserts object IDs and captured bytes, not mutable ref names.

## 7. Configuration Tests

- duplicate YAML keys fail;
- unknown keys fail;
- project config cannot define provider command fields;
- lower-trust layer cannot expand workspace access;
- project prompt override is disabled by default;
- prompt path symlink escape fails;
- lists replace instead of append;
- source-layer diagnostics are accurate;
- resolved config artifact is redacted;
- provider instances sharing a concurrency key share a lane.

## 8. Security Tests

- objective instruction override phrases trigger deterministic lint;
- target instructions remain inside untrusted delimiters;
- secret-like values are not written to env or command artifacts;
- secret output policy blocks publication;
- security failure does not trigger fallback;
- `project` workspace mode requires explicit opt-in;
- shell mode cannot be enabled by project config;
- cleanup and export reject malicious symlinks;
- mutation detection is labeled as detection, not sandbox success.

## 9. CLI and Help Golden Tests

Golden-test:

```text
kar --help
kar help quickstart
kar help config
kar help providers
kar help roles
kar help lanes
kar help prompts
kar help workflows
kar help artifacts
kar help validation
kar help ci
kar help exit-codes
kar help security
```

Also verify:

- README commands match CLI output;
- all linked examples parse;
- schema filenames printed by `kar schema list` exist;
- dangerous flags include warnings;
- negative review language does not imply provider failure;
- product help does not depend on external organizational terminology.

## 10. Provider Adapter Contract Tests

For every declared supported version:

- resolve binary and version;
- run a harmless JSON-only prompt;
- verify non-interactive operation;
- verify stdout contains one JSON object;
- verify stderr is diagnostic only;
- verify timeout and cancellation where feasible;
- verify prompt transport and size limits;
- record adapter profile and version.

A failure changes readiness to `experimental`, `unsupported`, or `unavailable`. It must not silently pass.

## 11. Schema Example Validation

CI validates every JSON example against its declared schema. Semantic examples additionally run through KAR's semantic validator fixture.

The authoritative pair list is the 23 schema/example relationships in `examples/g0-file-catalog.v1.valid.json`. Validation must compile every schema as Draft 2020-12 where applicable and validate each paired example. The seven v1 schema/example pairs remain byte-identical compatibility cases; all 16 added G0 pairs, including provider output v2, final artifact/manifest v2, and provider/platform contract evidence v2, are required positive cases. Provider/platform v1 is compatibility-only and v2 is the only readiness authority. Negative cases remove or corrupt required fields and must fail.

## 12. v0.1 Acceptance Suite

The release gate requires:

- all domain invariants tested;
- race detector clean for coordinator and lanes;
- fake-provider end-to-end runs for all four run types;
- schema examples valid;
- artifact integrity and crash tests passing;
- security policy tests passing;
- help golden tests passing;
- at least one provider adapter verified in an opt-in contract environment;
- no unresolved P0 defect in config trust, publication, cancellation, or fallback.
## 13. Post-G0 Product Verification Boundaries

G1 tests domain, configuration, target capture, artifact, command-envelope, and doctor behavior. G2 tests fake-provider review and deterministic prompt compilation. G3 tests lanes, repair, fallback, four-axis aggregation, evidence, publication recovery, and race behavior. G4 runs opt-in live adapter contracts; it does not convert an intended family to supported without complete tuple evidence. G5 tests lineage, clean, and export. G6 may expand beyond the sole required `darwin-arm64` platform only after a new scope decision, native evidence, candidate refreeze, promotion, and separate implementation approval; Linux and Intel future cells remain unsupported and release-ineligible. None of these product tests substitutes for G0 receipts, and G0 completion plus separate implementation approval remains required before they exist.
