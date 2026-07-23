# KAR Runtime Diagnostics Roadmap

This is the execution entrypoint for the four sequential diagnostics goals. Read [sot.md](./sot.md), [spec.md](./spec.md), and [architecture.md](./architecture.md) before starting an epic.

## 1. Status and Evidence Rules

- `[ ]` means incomplete. `[x]` means the requirement and its stated verification have both been observed on the current tree.
- Do not check a box merely because code was written or a proxy test passed.
- Record concrete test names, commands, artifact paths, or receipts beside completed boxes.
- Complete one epic before replacing the active `/goal` with the next epic.
- Do not modify or delete append-only `.gjc/` history.
- Do not mark G010-T05, G010-T06, or `RELEASE_READY` from this roadmap.
- During these epics, `make test-e2e` and therefore `make test` are non-gating. Never report their failure as PASS or convert it to SKIP.

| Epic | Deliverable | Depends on | Status |
|---|---|---|---|
| D-E01 | Contract, model, secure storage | approved planning package | COMPLETE |
| D-E02 | Provider observation and typed causes | D-E01 | COMPLETE |
| D-E03 | Run-wide lifecycle and terminal integration | D-E02 | COMPLETE |
| D-E04 | CLI, cleanup, offline end-to-end diagnostics | D-E03 | NOT_STARTED |

Fixed planning decisions:

- [x] Four sequential epics are required.
- [x] Planning documents are excluded from the runtime product SOT catalog.
- [x] Diagnostics product contracts target SOT 1.11.0.
- [x] G010-T05/T06 start only after D-E04 completes.
- [x] Current actual-provider E2E failure is excluded only from diagnostics completion gates.

## 2. D-E01 — Contract, Model, and Secure Storage

The epic was reopened on 2026-07-23 after failure-injection review found that
same-sink partial appends, finalize retries, and terminal-run reopen behavior
were not covered by the original completion evidence. Commits `fd72c11` and
`a96f804` close those gaps; all completion gates were re-observed on the
corrected tree before the epic returned to `COMPLETE`.

### Goal command

```text
/goal Implement Diagnostics D-E01 as specified by sot/plan/diagnostics: promote the runtime diagnostics contract as SOT 1.11.0, add validated diagnostic event/sink/factory ports, and add the secure .kar/diagnostics store. Verification: both required generators, make test-prepare, and race tests for domain, ports, filesystem, and architecture pass; every D-E01 mandatory checkbox in roadmap.md is checked with concrete evidence; test-e2e is not a completion gate.
```

### Must do

- [x] Promote the accepted diagnostics contract into the normative SOT and set `SPEC_VERSION` to 1.11.0 without adding planning files to the runtime catalog. Evidence: `d8c0352`; builtin manifest reports 85 unique sources, 84 checksum payloads, and zero `plan/` sources.
- [x] Define closed `RuntimeDiagnosticEvent`, `RuntimeDiagnosticSink`, and `RuntimeDiagnosticSinkFactory` boundaries with noop/in-memory test implementations. Evidence: `TestRuntimeDiagnosticClosedCodeSets`, `TestRuntimeDiagnosticFinalizeIsExactlyOnceAndNoopHasNoURI`.
- [x] Validate identifiers, fields, safe values, levels, events, causes, timestamps, elapsed time, and monotonic `seq`. Evidence: `TestRuntimeDiagnosticEventIsClosedSafeAndStamped`, `TestRuntimeDiagnosticEventRejectsUnsafeOrInconsistentFields`, `TestRuntimeDiagnosticClosedCodeSets`, `TestRuntimeDiagnosticPersistenceClassificationIsClosed`, `TestInMemoryRuntimeDiagnosticSinkSerializesRunWideSequence`.
- [x] Implement `.kar/diagnostics/<session>/<run>` anchored directory creation. Evidence: `TestDiagnosticStoreOpenCreatesPrivateInstalledRun`.
- [x] Implement serialized `kar-runtime.jsonl` append with complete-line and concurrency guarantees. Evidence: `TestDiagnosticStoreConcurrentAppendProducesCompleteUniqueSequence`, `TestDiagnosticStoreRecoversPartialJSONLineBeforeAppend`, `TestDiagnosticStoreRollsBackPartialAppendBeforeSameSinkFinalize`, `TestDiagnosticStoreRollsBackAppendAfterSyncFailure`.
- [x] Implement atomic run/attempt/invocation `status.json` replacement. Evidence: `TestDiagnosticStoreAtomicallyReplacesAttemptAndInvocationStatus`, `TestDiagnosticStoreAppendsCompleteEventsAndFinalizesExactlyOnce`, `TestDiagnosticStoreRejectsPostInstallNamespaceSubstitution`.
- [x] Persist stdout and stderr as separate bounded raw artifacts through scan-before-write. Evidence: `TestDiagnosticStorePersistsSeparatedBoundedRawStreamsThroughScanner`.
- [x] Implement caps, mandatory tail reserve, safe drop metadata, durable sync, and finalize behavior. Evidence: `TestDiagnosticStoreReservesTerminalTailAndRecordsOrdinaryDrops`, `TestDiagnosticStoreRawOverflowReturnsSafeDropAndRemovesTemporary`, `TestDiagnosticStoreFinalizeRetryDoesNotDuplicateTerminalEvent`, `TestDiagnosticStoreRejectsReopenOfFinalizedRunWithoutChangingStatus`.
- [x] Test symlink/path escape, permissions, secret detection, overflow, partial write, crash recovery, concurrent append, and writer failure classification. Evidence: `TestDiagnosticStoreRejectsSymlinkEscapeAndUnsafePermissions`, `TestRuntimeDiagnosticEventRejectsUnsafeOrInconsistentFields`, `TestDiagnosticStorePersistsSeparatedBoundedRawStreamsThroughScanner`, `TestDiagnosticStoreRawOverflowReturnsSafeDropAndRemovesTemporary`, `TestDiagnosticStoreRollsBackPartialAppendBeforeSameSinkFinalize`, `TestDiagnosticStoreRollsBackAppendAfterSyncFailure`, `TestDiagnosticStoreConcurrentAppendProducesCompleteUniqueSequence`, `TestDiagnosticStoreClassifiesRawWriterFailure`.
- [x] Regenerate checksums and builtin assets and record the resulting 85/84 catalog evidence. Evidence: both required generators and `make test-prepare` passed on 2026-07-23; `wc -l sot/CHECKSUMS.sha256` is 84 and the embedded manifest has 85 unique sources.

### Must not do

- [x] Do not grant diagnostics publication, CI, approval, or release authority. Evidence: run status fixes `diagnostic_only=true` and `publication_authority=false`; architecture dependency test passes.
- [x] Do not merge raw provider bytes into runtime JSONL. Evidence: event input has no raw byte field and separated-stream filesystem tests pass.
- [x] Do not weaken secure-writer, cap, redaction, fsync, or no-follow rules. Evidence: diagnostic raw persistence composes `SecureFileWriter`; secure, cap, permission, and recovery tests pass.
- [x] Do not instrument every application layer before the model and store contracts pass focused tests. Evidence: D-E01 changes are limited to domain, ports, filesystem, normative SOT, and planning evidence.
- [x] Do not change provider assignment, fallback eligibility, or native authentication behavior. Evidence: no provider, coordinator, reviewrun, or authentication production files changed in D-E01.

### Work method

1. Freeze SOT 1.11.0 requirements and regenerate authoritative assets.
2. Add immutable model and port validation with unit tests.
3. Add in-memory/noop sinks for consumers and ordering tests.
4. Implement the filesystem adapter using existing secure primitives.
5. Prove security and concurrency behavior before exposing the store to runtime code.

### Verification

```sh
go generate ./internal/app/init
go generate ./internal/builtin
make test-prepare
go test -race -count=1 ./internal/domain ./internal/ports ./internal/adapters/filesystem ./internal/architecture
git diff --check
```

Completion evidence:

- [x] All commands above pass on the same tree. Evidence: after corrective commits `fd72c11` and `a96f804`, both generators, `make test-prepare`, the exact focused race command, and `git diff --check` passed again on 2026-07-23; `sot/CHECKSUMS.sha256` remains 84 lines and builtin catalog tests enforce 85 unique sources with no `plan/` source.
- [x] Focused tests name the secure, concurrent, cap, and failure cases required by DIAG-SEC and DIAG-EVENT. Evidence: the `TestDiagnosticStore*` cases cited above run under the focused race command.
- [x] D-E02 can consume the ports without importing filesystem or entrypoint packages. Evidence: noop/in-memory factories live in `internal/ports`; `TestProductionDependencyDirection` passes.

## 3. D-E02 — Provider Observation and Typed Causes

Completed on 2026-07-23 through milestone commits `869d9db`, `f1ceaca`,
`84960bc`, `039a845`, and focused regression commit `f04953b`. The final
preparation and focused race gates were observed again on the completed tree.

### Goal command

```text
/goal Implement Diagnostics D-E02 as specified by sot/plan/diagnostics: preserve the best available process/provider observation on failures, replace string-based runtime error classification with typed causes, and persist separated raw-stream references without changing fallback policy. Verification: make test-prepare and race tests for ports, process, providercli, review, and validation pass; every D-E02 mandatory checkbox in roadmap.md is checked with concrete evidence; test-e2e is not a completion gate.
```

### Must do

- [x] Redesign process/provider result-error contracts so failures retain every valid observation already obtained. Evidence: `TestPartialFailedProviderExecutionObservationRetainsTypedCauseAndStreams`, `TestRegistryObservePreservesRunnerErrorWithObservation`, and `TestRegistryObservePreservesPartialStreamsAndCleanupCause` pass under the focused race gate.
- [x] Define and propagate typed process, transport, provider framing, parsing, binding, validation, and cleanup causes. Evidence: closed causes flow through `ProcessExecutionError`, `ProviderRuntimeError`, `ProviderExecutionObservation`, and validation `RuntimeError`; `TestFailedProviderExecutionObservationRequiresClosedTypedCause`, `TestRegistryObservePreservesTransportVerificationCause`, and `TestApplyRepairCandidateReturnsTypedRepairPlanCause` pass.
- [x] Normalize Kimi, ZCode, and AGY native login/timeout/auth/quota/rate signals at the adapter boundary. Evidence: `TestRegistryObserveNormalizesFamilyNativeFailureSignals` and `TestRegistryObserveClassifiesNativeProviderTimeout` pass.
- [x] Remove generic string-contains classification from runtime policy decisions. Evidence: `runtimeProviderErrorCondition`, `observedStatusCondition`, and validation security mapping consume typed causes; `TestObservedLoginRequiredIsFailClosed` proves arbitrary login-like error text maps to `internal_invariant` while the typed cause maps to `login_required`.
- [x] Preserve stdout/stderr artifacts and references on failed observations whenever safe bytes exist. Evidence: `TestProcessExecutionErrorPreservesTypedPrimaryCauseAndSeparatedEvidence`, `TestRegistryObservePreservesPartialStreamsAndCleanupCause`, and `TestProviderRuntimePersistsSeparatedRawReferences` pass.
- [x] Distinguish provider execution failure, provider output failure, KAR validation failure, and process-group cleanup failure. Evidence: `TestRegistryObserveClassifiesProcessTerminations`, `TestProviderResultFailuresExposeExactTypedCausesWithoutRawText`, validation typed-cause tests, and `TestProcessExecutionFailureKeepsInitiatingCauseAheadOfCleanup` pass.
- [x] Keep user-facing failure class/reason closed and safe while durable diagnostics retain the detailed cause. Evidence: `TestProviderRuntimeErrorExposesOnlyClosedCause`, `TestProviderResultFailuresExposeExactTypedCausesWithoutRawText`, and existing exhaustive attempt-condition validation pass.
- [x] Add family-specific golden/regression cases for malformed stream, invalid envelope, decode failure, native timeout, transport verification, and cleanup failure. Evidence: `TestProviderResultFailuresExposeExactTypedCausesWithoutRawText`, `TestRegistryObserveClassifiesNativeProviderTimeout`, `TestRegistryObservePreservesTransportVerificationCause`, and `TestRegistryObservePreservesPartialStreamsAndCleanupCause` pass.

### Must not do

- [x] Do not make `internal_invariant`, login-required, security, configuration, artifact, cancellation, or mutation failures fallback-eligible. Evidence: `TestDecideTransitionExhaustiveMatrix` and `TestAttemptConditionsAreExactAndExhaustivelyValidated` pass unchanged.
- [x] Do not blame a provider for a KAR process, transport, validation, or workspace invariant. Evidence: typed process, transport, validation, cleanup, and workspace causes remain distinct from provider-native causes in the focused cause tests.
- [x] Do not write provider raw content or free-form errors to command stdout/stderr or test failure messages. Evidence: typed `Error()` projections contain only closed causes, and `TestProviderResultFailuresExposeExactTypedCausesWithoutRawText` verifies fixture bytes are absent.
- [x] Do not infer native status outside the provider adapter boundary. Evidence: family-native inspection is confined to `internal/adapters/providercli`; review tests consume only typed causes and statuses.
- [x] Do not lose the initiating cause when cleanup also fails. Evidence: `TestProcessExecutionFailureKeepsInitiatingCauseAheadOfCleanup` and `TestRegistryObservePreservesPartialStreamsAndCleanupCause` assert wait remains primary and cleanup supplemental.

### Work method

1. Add typed result/cause contracts at ports before changing adapters.
2. Adapt the process runner while retaining lifecycle and termination invariants.
3. Normalize each provider family independently with focused fixtures.
4. Update review runtime mapping and prove the existing transition policy is unchanged.
5. Connect raw observations to D-E01 storage references.

### Verification

```sh
make test-prepare
go test -race -count=1 ./internal/ports ./internal/adapters/process ./internal/adapters/providercli ./internal/app/review ./internal/app/validation
git diff --check
```

Completion evidence:

- [x] All commands above pass on the same tree. Evidence: `make test-prepare`, the exact focused race command, and `git diff --check` passed on 2026-07-23 after commits `869d9db`, `f1ceaca`, `84960bc`, `039a845`, and `f04953b`.
- [x] Tests prove each required typed cause without matching arbitrary error text. Evidence: the named process, provider-family, validation, transport, and cleanup tests above assert `RuntimeDiagnosticCause` values directly.
- [x] Existing exhaustive repair/fallback policy tests remain unchanged or explicitly demonstrate equivalent behavior. Evidence: `TestDecideTransitionExhaustiveMatrix` and `TestAttemptConditionsAreExactAndExhaustivelyValidated` pass without changing `transitionPolicyRows`.

### Post-completion review follow-up

- [x] Lock the spawn-failure policy boundary explicitly. Evidence: `TestObservedSpawnFailurePolicyUsesStatusAndFailsClosedWithoutObservation` proves observed unavailable/configuration/security/internal statuses retain their existing conditions while an unobserved typed spawn failure remains fail-closed; commit `2e7b7ae`.
- [ ] Provider qualification hardening, tracked separately from D-E03 and not a D-E02 completion gate: replace the residual generic `auth`/`login`/`sign in`/`not found`/`unavailable` matching in `classifyProbeFailure` with family-native or typed process signals, backed by false-positive and compatibility fixtures before removing the fallback.
- [x] Keep output diagnostics as one safe external projection while retaining detailed typed causes in `PrimaryCause`. Evidence: provider output regression cases assert the shared `invalid_provider_output` code and their distinct closed causes; the projection helper documents this contract.

## 4. D-E03 — Run-wide Lifecycle and Terminal Integration

### Goal command

```text
/goal Implement Diagnostics D-E03 as specified by sot/plan/diagnostics: open diagnostics before provider spawn, emit the complete run-wide lifecycle across coordinator and reviewrun, and finalize durable diagnostics on every P2 and non-P2 terminal path. Verification: make test-prepare and race tests for review, reviewrun, and publication pass; ordered normal/fallback/login-required/cancellation tests pass; every D-E03 mandatory checkbox in roadmap.md is checked with concrete evidence; test-e2e is not a completion gate.
```

### Must do

- [x] Allocate or expose session/run identity early enough to open the sink before provider spawn. Evidence: `TestIssueRootRunIdentityPreservesSuppliedSession`, `TestCoordinatorExecuteRunPreservesSuppliedRootIdentity`, and `TestServiceExecuteOpensDiagnosticsBeforeQualification` pass; commits `519a8d9` and `ffb4edf`.
- [x] Emit qualification, planning, assignment, budget, lane, attempt, invocation, repair, fallback, cancellation, reduction, publication, and cleanup events. Evidence: `TestIntegrationKARProductionReviewSubprocessAGY`, `TestCoordinatorDiagnosticsReportRepairLifecycle`, `TestCoordinatorDiagnosticsPersistFailureBeforeFallback`, `TestCoordinatorDiagnosticsPersistInitiatingCauseBeforeFallbackProhibitionAndPeerCancellation`, and `TestPublishNextObservedReportsDurableLifecycle` assert the ordered categories; commits `73d89a8`, `2a0ac95`, `7d49660`, and `f6e6a87`.
- [x] Preserve coordinator decision order and map it into one run-wide diagnostic sequence. Evidence: `TestCoordinatorDiagnosticsPersistFailureBeforeFallback` and the AGY integration assert one monotonic ordered stream through reduction, cleanup, publication, and close.
- [x] Make the initiating failure durable before fallback, mitigation, or peer cancellation begins. Evidence: `TestCoordinatorDiagnosticsPersistFailureBeforeFallback`, `TestCoordinatorDiagnosticFailureStopsBeforeFallbackScheduling`, and `TestCoordinatorDiagnosticsPersistInitiatingCauseBeforeFallbackProhibitionAndPeerCancellation` pass.
- [x] Finalize diagnostics before every login-required and non-publishable return. Evidence: `TestServiceExecuteFinalizesLoginRequiredAfterCleanup` and `TestServiceExecuteRetriesTerminalDrainBeforeAbort` observe cleanup followed by exactly one terminal finalize with the expected state/cause.
- [x] Finalize successful and degraded P2 runs and link their committed P2 URI. Evidence: `TestCoordinatorOptionalDegradationAndFourInvocationBound` proves the degraded terminal projection, while `TestIntegrationKARProductionReviewSubprocessAGY` observes the shared finalizer's `runtime_diagnostics_closed`, lane counts, and `status.json.p2_uri` equal to the committed run-manifest URI.
- [x] Treat sink open/write/finalize failure as a typed artifact failure without returning a dangling URI. Evidence: `TestServiceExecuteDiagnosticOpenFailurePreventsQualification`, `TestCoordinatorDiagnosticFailureStopsBeforeFallbackScheduling`, `TestPublishNextObservedPersistenceFailureStopsBeforeInstall`, and `TestServiceExecuteDiagnosticFinalizeFailureHasNoURI` pass.
- [x] Adjust memory inventory drain order so non-P2 evidence is not abandoned. Evidence: `reviewrun.Service.Execute` installs the single deferred `DrainRuntimeArtifactsForRun` immediately after runtime construction and uses the same drain result for P2 preparation; login/non-publishable exits are covered by the ordered terminal tests without bypassing the defer.
- [x] Test primary-only success, primary-failure/fallback-success, login-required/fallback-prohibited, internal-stop/peer-cancellation, cancellation, and publication failure chronology. Evidence: respectively `TestIntegrationKARProductionReviewSubprocessAGY`, `TestCoordinatorDiagnosticsPersistFailureBeforeFallback`, both subtests of `TestCoordinatorDiagnosticsPersistInitiatingCauseBeforeFallbackProhibitionAndPeerCancellation`, `TestServiceExecuteRetriesTerminalDrainBeforeAbort`, and `TestPublishNextObservedPersistenceFailureStopsBeforeInstall` pass.

### Must not do

- [x] Do not spawn providers when the mandatory sink cannot be opened and validated. Evidence: `TestServiceExecuteDiagnosticOpenFailurePreventsQualification` observes no authority/qualification call after the sink open failure.
- [x] Do not hide diagnostic persistence failure behind a provider failure. Evidence: coordinator and publication persistence-failure tests return typed `artifact_failure` and stop before fallback/install.
- [x] Do not let peer cancellation replace the initiating terminal cause. Evidence: login-required and internal-invariant subtests persist the initiating failure before `lane_cancelled`; terminal decision precedence retains typed initiating failures.
- [x] Do not make diagnostics input to the P2 classifier or validator. Evidence: publication lifecycle is an observer invoked after authoritative receipts, and `TestPublishNextObservedPersistenceFailureStopsBeforeInstall` proves it can only stop publication with an artifact failure rather than manufacture P2.
- [x] Do not change configured primary/fallback assignment semantics. Evidence: existing exhaustive transition tests pass unchanged, while `TestCoordinatorDiagnosticsPersistFailureBeforeFallback` observes the pre-existing configured fallback decision.

### Work method

1. Establish lifecycle ownership in `reviewrun` and composition.
2. Wire the sink through coordinator and provider runtime using ports only.
3. Instrument normal transitions before failure transitions.
4. Add non-P2 finalize paths and cause precedence.
5. Link P2 only after publication commits, then instrument namespace/workspace cleanup.

### Verification

```sh
make test-prepare
go test -race -count=1 ./internal/app/review ./internal/app/reviewrun ./internal/app/publication
git diff --check
```

Completion evidence:

- [x] All commands above pass on the same tree. Evidence: `make test-prepare`, the exact focused race command, and `git diff --check` passed on 2026-07-23 after commits `519a8d9`, `ffb4edf`, `73d89a8`, `2a0ac95`, `7d49660`, and `f6e6a87`.
- [x] Ordered event assertions cover all named terminal paths. Evidence: the primary, repair, fallback, login-required, internal-stop, cancellation, and publication tests named above pass with ordered assertions.
- [x] No test uses diagnostics as publication authority. Evidence: P2 assertions continue to require `PublicationAuthorityP2`, final/snapshot/exit coherence, and durable publication receipts independently of diagnostic observations.

## 5. D-E04 — CLI, Cleanup, and End-to-end Diagnostics

### Goal command

```text
/goal Implement Diagnostics D-E04 as specified by sot/plan/diagnostics: expose valid diagnostic URIs consistently in human/JSON results, integrate the reserved diagnostics namespace with retention and cleanup, prove offline end-to-end diagnostics, and preserve discoverable artifacts from the currently failing actual-provider E2E. Verification: make test-prepare, make test-unit, and make test-int pass; an actual make test-e2e run is recorded truthfully and, if it fails after run identity allocation, its private diagnostic URI and artifacts remain inspectable; every D-E04 mandatory checkbox in roadmap.md is checked with concrete evidence. E2E PASS is deferred to G010-T05.
```

### Must do

- [ ] Project the same installed diagnostic URI in human and JSON failure output.
- [ ] Preserve provider attribution for login-required and provider execution failures.
- [ ] Reserve `.kar/diagnostics` so publication selectors do not report it as a malformed session.
- [ ] Observe diagnostics-only failed runs separately from P2 runs and corruption.
- [ ] Extend retention and `kar clean` so linked diagnostics and selected diagnostics-only runs are removed safely and unrelated runs remain.
- [ ] Keep diagnostics and raw streams out of default export.
- [ ] Add offline fake-provider integration for normal, failed, fallback, login-required, concurrent, and persistence-failure flows.
- [ ] Verify status, JSONL, raw artifacts, sequence, IDs, and optional P2 reference are mutually consistent.
- [ ] Preserve a private actual-E2E project/diagnostic path on failure and print only the safe discoverable path.
- [ ] Run the actual-provider E2E once as diagnostic evidence and record its real exit status and diagnostic location.

### Must not do

- [ ] Do not name fake-provider integration tests `TestE2E`.
- [ ] Do not remove, skip, relax, retry away, or report PASS for failing actual-provider assertions.
- [ ] Do not remove `test-e2e` from the Makefile target graph.
- [ ] Do not print raw provider output, credentials, prompts, source bytes, or free-form internal errors.
- [ ] Do not mark G010-T05/T06 or `RELEASE_READY` complete.
- [ ] Do not fix the discovered actual-provider cause within this epic; hand its evidence to G010-T05.

### Work method

1. Complete safe CLI projection and dangling-path tests.
2. Integrate reserved namespace, query, retention, cleanup, and export separation.
3. Prove full offline flow through public composition with fake providers as integration tests.
4. Update the live E2E harness only to preserve private failure artifacts and safe paths.
5. Run actual E2E once, inspect the preserved diagnostics, and create a G010-T05 evidence handoff without changing the failing behavior.

### Required verification gate

```sh
make test-prepare
make test-unit
make test-int
git diff --check
```

Diagnostic evidence command:

```sh
make test-e2e
```

The diagnostic evidence command may fail. A failure is acceptable for D-E04 completion only when it is reported as failure and, after run identity allocation, the output leads to preserved `status.json`, `kar-runtime.jsonl`, and applicable raw stream artifacts. Pre-run failures must remain safe and must not expose a dangling URI.

Completion evidence:

- [ ] All required gate commands pass on the same tree.
- [ ] Offline end-to-end diagnostics satisfy DIAG-AC-001 through DIAG-AC-007.
- [ ] Actual E2E exit status is recorded truthfully.
- [ ] Failure diagnostics needed by G010-T05 are preserved and inspectable, or an unexpected actual E2E PASS is recorded without claiming G010 closeout.

## 6. G010 Handoff

After all four epic status rows are COMPLETE:

- [ ] Create a G010-T05 evidence note containing the failing command, exit status, session/run identity, diagnostic URI, terminal cause, relevant raw artifact references, and rejected root-cause hypotheses.
- [ ] Start G010-T05 to diagnose and fix the actual-provider failure; require `make test-e2e` PASS there.
- [ ] Restore and run the full-workflow actual-provider E2E required by the normative SOT.
- [ ] Start G010-T06 only after T05 passes; require exact final-tree `make test` before `RELEASE_READY`.
