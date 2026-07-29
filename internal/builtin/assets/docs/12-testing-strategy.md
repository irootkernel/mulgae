# Testing Strategy

## 1. Test Pyramid

| Layer | Primary purpose | Live providers |
|---|---|---:|
| Domain unit tests | State transitions and invariants | No |
| Property tests | IDs, paths, ordering, merge and validation invariants | No |
| Adapter unit tests | Config, schemas, serializers, path safety | No |
| Integration tests | Coordinator, fake lanes, artifacts, Git snapshots | No |
| CLI golden tests | Help, errors, examples, exit codes | No |
| Provider contract tests | Family and runtime-capability compatibility | Optional controlled environment |
| Live capability certification | Production boundary for each supported family | Required actual Kimi, ZCode, and AGY |

Unit and integration tests do not require provider credentials or network access. The final G013 `make test` release gate deliberately requires the installed actual providers, their native authentication, available provider service access, and the exact release Mulgae binary.

ID and safe-path properties use fixed-seed standard-library generators so
failures are reproducible: `internal/domain/identifiers_test.go::TestIdentifierParsingSeededCanonicalityProperty`
and `internal/ports/foundation_test.go::TestSafeRelativePathSeededTraversalProperty`.

## 1.1 G0 Contract-Freeze Validation

G0 contract validators and G001–G012 evidence remain historical. G013 supersedes their use as a current production closure mechanism: only the complete preparation, race unit/integration, login-recovering exact-binary real-provider workflow, and subsequent non-skipping family capability suites reached through `make test` can establish current release readiness. The G0 validator set remains exact and complete:

| Operation | Required fixture or input | Required success assertion | Receipt |
|---|---|---|---|
| `p0` | Recovered P0 snapshot and `p0-cases.json` | `P0_ATOMIC_OK` | `E/p0/receipt.json` |
| `schema` | `schema-cases.json`, SOT root | `SCHEMA_OK` | `E/schema/receipt.json` |
| `trace` | `trace-ledger.json`, 84-path catalog | `TRACE_OK`, 17 product commands, no orphan | `E/trace/receipt.json` |
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
| `integrity` | `integrity-cases.json`, catalog, checksums | `INTEGRITY_OK`, 83 payload files, raw32 reducer | `E/integrity/receipt.json` |
| `authority` | `authority-cases.json`, runtime state receipt | `AUTHORITY_OK` | `E/authority/receipt.json` |
| `checksums-generate` | catalog and SOT payload | `CHECKSUMS_OK`, 83 payload files | `E/checksums-generate/receipt.json` |
| `checksums-verify` | checksums and SOT payload | `CHECKSUMS_OK`, 83 payload files | `E/checksums-verify/receipt.json` |

Every row uses the locked `g0_validate.py` argv and fixture hashes defined by the G0 evidence contract. Shell parsing, alternate arguments, unrecorded reserialization, and a partial operation set are invalid substitutes. Typed non-success results remain readiness `4`, artifact/hash/schema/CAS/stale `7`, security `8`, and internal invariant `10`.
The canonical-argv fixture fixes the label order `provider:kimi`, `provider:zcode`, `provider:agy`, and `platform:darwin-arm64`. Each compact one-line UTF-8 JSON array is hashed as `SHA-256("Mulgae-G0-ARGV/1" || 0x00 || argv_json_bytes)` without a trailing LF; the fixed-order raw32 bundle uses `Mulgae-G0-ARGV-BUNDLE/1\n`. The exact supplied hashes are `kimi=c092d46a84dff52a23cf5a08637cf80346a9e6a39adbe3ddac62fbc180950129`, `zcode=724db2f4e04f01ca6240eae1f5a747ecaf9881696b18ad06cd98c53dd2f5458e`, `agy=bbc244436caa277d59ed6785f513f088ad9da292990d5bc6559ceb47eb346520`, `darwin-arm64=b04269cc9a3d8b7763d41e737a8b6a12e2dd49208314dea79448760293862c9b`, and `bundle=c0353931bd27274e001b650a7a3f5e8d2fc7a1412e5a64c1bdf3ccad2adb1cd7`. Provider v2 requires `--runtime-contract` and the fixed `--gate-receipt`; legacy `--evidence-root` and `--index` are rejected. The historical `failure` fixture requires `timeout`, generic `auth`, `quota`, and `rate_limit` to have `repair=none` and `fallback=allowed`; no configured eligible fallback means exhaustion, not a changed rule. G010 tests additionally require explicit `login_required` to fail closed without repair or fallback and to retain provider attribution.

The provider/probe branch contains exactly the three runtime-order families `kimi`, `zcode`, and `agy`, each with the same 16 probes: ten base probes plus six role-fit probes. Provider readiness requires all **48 PASS**, three secure-writer indexes **PASS**, and a live assignment receipt **PASS**; selected-only evidence is insufficient. The platform inventory retains `linux-amd64`, `linux-arm64`, `darwin-amd64`, and `darwin-arm64`, but only `darwin-arm64` is required/blocking and must complete native local-POSIX evidence for all 11 platform probes. The three future cells are `intended_future`, non-blocking, unsupported, and release-ineligible, with fixed `NOT_RUN` evidence; they are not execution targets. Provider/platform v1 evidence is compatibility-only, while only v2 evidence can enter readiness. Complete required probe PASS is exit `0`, any required INCONCLUSIVE is `4`, required probe failure is `7`, and security or mutation is `8`. G001 completed the required PASS conjunction; any future revalidation with a non-PASS required input fails closed.

Cross-axis fixtures must preserve a valid high finding with required-role exhaustion as `content_verdict=request_changes` and `coverage_status=incomplete`, then calculate publication and CI separately. Locality fixtures exercise checkout, full-index, applicable-commit, config-descriptor, target-byte, and spawn-time drift rejection. Assignment fixtures cover singleton null fallbacks and degraded resilience, distinct required-role fallbacks when multiple families are eligible, and the 24-invocation ceiling.

Prompt fixtures exercise canonical frames, declared length, section and stdin hashes, malformed/truncated input, fresh execution identity, and exact replay. Evidence fixtures cover source/current identity separation, stale evidence, path traversal, range errors, spoofing, hash mismatch, and missing immutable bytes. Publication fixtures cover all persisted states, P0/P1/P2 recovery, the ten named cross-boundary observations, and immutable `corrupt` diagnostics. Cleanup fixtures cover retained seeds, transitive ancestors, corrupt graph protection, separate age and size sets, fixed epoch, plan hash, tombstone restart, and stale-plan rejection. Integrity fixtures cover the 84-path catalog, 83-file checksum payload, `Mulgae-SOT-PAYLOAD-ROOT/1` domain, UTF-8 bytewise sorting, NUL plus raw32 digest records, and the empty-set vector. Authority fixtures cover runtime-only approvals, candidate reviews, forward CAS, delete-ref rollback CAS, post-verification, and the independent implementation approval boundary.
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
- excerpt is generated by Mulgae, not accepted from provider output.

## 5. Artifact Store Tests

Required cases:

- UUIDv7 path component validation;
- atomic write produces no visible partial final file;
- direct child-process crash before rename leaves only a temporary file and no visible final file;
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
- `execution.workspace_access` omission is rejected and the closed set is exactly `none|readonly_snapshot`;
- the legacy `project` workspace value is rejected rather than treated as an opt-in;
- project prompt override is disabled by default;
- prompt path symlink escape fails;
- lists replace instead of append;
- source-layer diagnostics are accurate;
- resolved config artifact is redacted;
- provider instances sharing a concurrency key share a lane.

## 8. Security Tests

The security inventory is distributed across the owning packages. This table is
the canonical case-to-test index; every listed test runs offline unless marked
`liveprovider`.

| Security case | Representative enforcing tests |
|---|---|
| Objective instruction override phrases trigger deterministic lint | `internal/app/prompt/objective_test.go::TestLintObjectiveRejectsEveryFrozenConflictClass` |
| Target instructions remain inside untrusted frames | `internal/app/prompt/compiler_test.go::TestCompileEmitsCanonicalSOTPacket`; `internal/app/prompt/compiler_test.go::TestCompilerParserRoundTripArbitraryPayloads` |
| Secret-like configuration is rejected before it can become environment or command authority | `internal/adapters/config/yaml_test.go::TestCredentialDetectorUsesReasonOnlyAndBoundaries`; `internal/adapters/providercli/policy_test.go::TestDirectExecutionEnvironmentAuthorityFailsClosed` |
| Secret output blocks publication | `internal/adapters/filesystem/securewriter_test.go::TestSecureWriterDropsCrossChunkSecretAndCleansTemporaryFile`; `internal/adapters/filesystem/publicationstore_test.go::TestPublicationStoreClassifiesSecretRejectionAsSecurity` |
| Security failure does not trigger fallback | `internal/app/review/policy_test.go::TestSecurityAndCancellationProhibitNewWork`; `internal/app/review/coordinator_test.go::TestCoordinatorEvidenceInvariantFailsClosedWithoutFallback` |
| `project` workspace mode is rejected | `internal/adapters/config/yaml_test.go::TestDecodeRejectsOmittedLegacyWorkspaceAndShellModes` |
| Shell mode cannot be enabled by project configuration | `internal/adapters/config/yaml_test.go::TestDecodeRejectsOmittedLegacyWorkspaceAndShellModes`; `internal/adapters/process/runner_test.go::TestRunnerDoesNotInterpretShellMetacharactersAndSupportsRepeatedRuns` |
| Cleanup and export reject malicious symlinks | `internal/adapters/filesystem/cleanupstore_darwin_test.go::TestCleanupStoreRejectsCleanupWriteSymlinkAncestors`; `internal/adapters/filesystem/exportinstaller_darwin_test.go::TestExportInstallerRejectsEscapingAndNonRegularDestinationsWithoutPartialSuccess` |
| Mutation checks remain supplementary detection and fail closed as security, not sandbox authority | `internal/app/followup/service_test.go::TestStartFollowupRunRejectsMutationDespiteExecutorSelfAttestation`; `internal/app/delta/service_test.go::TestStartDeltaRunRejectsSourceMutationAfterOneChildExecution`; `internal/app/rerun/service_test.go::TestStartRerunClassifiesSourceMutationAsSecurityPolicy` |
| macOS AGY captures and revalidates the installed-user native `HOME`, without a synthetic authentication home or credential projection | `internal/adapters/providercli/credential_source_test.go::TestAGYUsesInstalledHomeWithoutCredentialProjection`; `internal/adapters/environment/inspector_test.go::TestObserveNativeHomeIdentityCapturesDescriptorAndDetectsReplacement` |
| AGY namespace setup and drain do not write, overwrite, zero, or unlink user authentication/settings; normal provider-owned refresh is disclosed separately | `internal/adapters/providercli/credential_source_test.go::TestAGYUsesInstalledHomeWithoutCredentialProjection`; `internal/adapters/providercli/agy_boundary_darwin_test.go::TestAgyAuthSettingsManifestDetectsMutation` |
| AGY keeps the descriptor-bound immutable snapshot as CWD while Mulgae owns XDG, cache, temporary, and scratch namespaces | `internal/adapters/providercli/registry_test.go::TestRegistryObserveWorkspaceUsesGuardedCWDLifecycleAndBoundRequest`; `internal/adapters/providercli/credential_source_test.go::TestAGYUsesInstalledHomeWithoutCredentialProjection` |
| Kimi and ZCode retain isolated `HOME` directories and credential projection | `internal/adapters/providercli/credential_source_test.go::TestCredentialSourceProjectsOnlyDeclaredFamilyFiles`; `internal/adapters/providercli/namespace_test.go::TestCredentialProjectionUsesOnlyProviderHomePaths` |
| AGY argv contains `--sandbox`, the exact immutable-snapshot `--add-dir`, and `--mode plan`, with bounded output/time and post-output `SIGTERM`/`SIGKILL` lifecycle | `internal/adapters/providercli/registry_test.go::TestRegistryObserveWorkspaceBindsProductionAgyAddDirAndPacketReceipt`; `internal/adapters/providercli/agy_lifecycle_test.go::TestAgyLifecycleOfflineRealProcess` |
| Explicit provider `login_required` fails closed before P2, schedules no repair or fallback, reports affected provider instances, and is not automatically retryable | provider CLI classification tests; coordinator transition tests; review-run qualification/runtime tests; CLI human/JSON projection tests |
| Operational qualification failures preserve canonical provider attribution and closed reason codes without raw native output; a rejected selected assignment fails before P2 | qualified-run factory/planner tests and CLI human/JSON projection tests |
| Non-publishable provider execution failures preserve the typed exit and expose only canonical provider instance plus closed attempt-condition code | review-run safe aggregate tests and CLI human/JSON projection tests |

## 9. CLI and Help Golden Tests

Golden-test:

```text
mulgae --help
mulgae help quickstart
mulgae help config
mulgae help providers
mulgae roles
mulgae roles --output json
mulgae help lanes
mulgae help prompts
mulgae help workflows
mulgae help artifacts
mulgae help validation
mulgae help ci
mulgae help exit-codes
mulgae help security
```

Also verify:

- README commands match CLI output;
- all linked examples parse;
- schema filenames printed by `mulgae schema list` exist;
- dangerous flags include warnings;
- negative review language does not imply provider failure;
- product help does not depend on external organizational terminology.

## 10. Provider Adapter Contract Tests

For each supported family (`kimi`, `zcode`, and `agy`) and its runtime capability contract:
- resolve the configured binary and record version, executable path, SHA, and profile as diagnostic provenance;
- run a harmless JSON-only prompt;
- verify non-interactive operation;
- verify stdout contains one JSON object;
- verify stderr is diagnostic only;
- verify timeout and cancellation where feasible;
- verify prompt transport and size limits;
- verify unknown or new versions are accepted when the capability contract succeeds;
- verify missing capabilities produce actionable typed diagnostics; and
- verify documented known incompatibilities are explicitly blocked; and
- for macOS AGY, verify the native authentication-home and non-mutation boundary rather than claiming live P2 success.

Version, path, SHA, and profile must never be general runtime authorization gates, and a historical PASS receipt is not required for every configured tuple. Unlisted families remain rejected and failures must not silently substitute another provider.
Doctor tests cover the exact v2 projection, fixed Kimi/ZCode/AGY inventory, inline JSON result, no diagnostics persistence, ANSI-free rendering, singleton degraded exit `0`, unavailable exit `4`, and locality/security exit `8`.

## 11. Schema Example Validation

CI validates every JSON example against its declared schema. Semantic examples additionally run through Mulgae's semantic validator fixture.

The authoritative current pair list is the 27 schema/example relationships in `examples/g0-file-catalog.v1.valid.json`. Validation must compile every schema as Draft 2020-12 where applicable and validate each paired example. Released v1 pairs remain compatibility cases; v2 provider/platform evidence is the only readiness authority. Negative cases remove or corrupt required fields and must fail.

## 12. v0.1 Acceptance Suite

The release gate requires:

- all domain invariants tested;
- race detector clean for coordinator and lanes;
- fake-provider end-to-end runs for all four run types;
- schema examples valid;
- artifact integrity and crash tests passing;
- security policy tests passing;
- help golden tests passing;
- all three supported provider families certified through the fail-closed live capability gate;
- no unresolved P0 defect in config trust, publication, cancellation, or fallback.
## 13. Post-G0 Product Verification Boundaries

Fake-provider and controlled-process workflow tests are integration tests. They are the authority for product semantics: Config v2, every supported role and provider subset, committed and dirty target capture, qualification planning, scheduling and same-CWD concurrency, repair/fallback policy, root and child workflows, schemas, evidence validation, diagnostics, publication, recovery, cleanup, and CLI exit projection. These suites run with the race detector and may not depend on stochastic provider findings.

`test-e2e` builds the current Mulgae candidate and executes that exact binary through the actual-provider production workflow before performing one live capability certification for each supported family. This order is mandatory: an explicit Kimi login-required qualification must reach Mulgae's bounded native login, fresh credential namespace reconstruction, and one fresh qualification instead of being intercepted by the standalone capability probe. The workflow covers Config v2 init/config/doctor, six-role root review, schema-valid P2 publication, diagnostics, cleanup, followup, delta, exact rerun, and recomposed rerun. Each later family certification retains its production argv and environment boundary, immutable fixture CWD, prompt transport, bounded process lifecycle, output-frame recovery, runtime capability contract, and non-mutation checks. Missing binaries, launcher state, unresolved native authentication, service access, or a valid live response fail rather than skip.

Live release verification does not require a predetermined exact line or quote, role consensus, or a fixed process-time intersection. The root fixture does require one schema-valid security finding so the actual followup command has a trusted source. Scheduling and repair/fallback policy remain exhaustively deterministic below the live boundary; the executable workflow proves their production composition rather than duplicating timing predicates.

`make test` is the sole technical release-ready gate and runs `test-prepare`, `test-unit`, `test-int`, and `test-e2e` in order. No required test may silently skip because a tool, browser runtime, executable, credential, or service prerequisite is absent. Release readiness may be recorded only after the capability and executable workflow layers both pass on the exact final committed tree and the working tree remains clean.

## 14. Runtime Diagnostic Verification

Diagnostic model and port tests reject invalid identifiers, unknown codes, unsafe values, non-UTC timestamps, decreasing elapsed time, non-monotonic sequence, aliased mutable input, and inconsistent status identity. Filesystem tests cover anchored-root creation, `0700`/`0600` modes, symlink/path escape, permissions, secret detection, overflow/drop metadata, JSONL cap and mandatory tail reserve, partial append recovery, crash and fsync failures, atomic status replacement, concurrent append under the race detector, writer failure classification, and exactly-once finalize. G013 retains these deterministic requirements and the exact-binary fail-closed actual-provider boundary under the single `make test` gate.
