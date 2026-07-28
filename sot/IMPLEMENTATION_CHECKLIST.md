# KAR Implementation Status Checklist

**Status date:** 2026-07-28

SOT 1.14.0 preserves historical G001–G011 evidence and the runtime-diagnostics contract. G012 restores the exact release-binary actual-provider root/child workflow that G011 removed while retaining deterministic acceptance and all three live family capability certifications under the sole `make test` gate. G012 is **IN PROGRESS — RELEASE BLOCKED**. Historical evidence and `.gjc/` remain append-only.

## Goal Completion Snapshot

| Goal | Delivered scope | Status | Repository marker |
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
| G012 | Restore exact release-binary actual-provider root/child workflow coverage while retaining family capability certification | **IN PROGRESS — RELEASE BLOCKED** | `g012` |

The checked items through G011 are historical evidence and do not establish current release readiness. The dedicated G012 section is the current completion authority.

## G0 Contract-Freeze Preconditions

- [x] Record a valid session-bound Gate A approval before creating G0 evidence or a candidate.
- [x] Produce and validate the 85-path catalog and 84-regular-file checksum payload; `CHECKSUMS.sha256` remains self-excluded.
- [x] Complete the exact 17 G0 validator receipts: p0, schema, trace, marker, trust, command, publication, prompt, evidence, cleanup, assignment, canonical-argv, failure, integrity, authority, checksums-generate, and checksums-verify.
- [x] Obtain complete PASS evidence for `darwin-arm64`: native/local-POSIX plus all 11 platform probes.
- [x] Historical G0 only: obtain provider readiness as all three families in runtime order `kimi`, `zcode`, `agy` × all 16 probes (**48 PASS**), three secure-writer indexes (**3 PASS**), and a live assignment receipt (**PASS**) before the recorded authority promotion. Current runtime readiness evaluates the configured nonempty subset.
- [x] Retain `linux-amd64`, `linux-arm64`, and `darwin-amd64` only as `intended_future`, non-blocking, unsupported, and release-ineligible inventory; they are not required G0 execution or release targets.
- [x] Treat provider/platform evidence v1 as byte-identical compatibility-only input; only v2 may enter readiness.
- [x] Post-verify the promoted authority candidate and record `g0_complete`.
- [x] Record the separate session-bound implementation approval before starting any item below.

- [x] Validate the v2 four-axis contract (`content_verdict`, `coverage_status`, `publication_status`, `ci_decision` with reasons) without collapsing one axis into another.
- [x] Validate separate source and current evidence identities; source evidence must never become current verified evidence.
- [x] Validate the deterministic six-role/provider assignment reducer, the code-fixed required floor, admitted project-local additions, and run-local non-weakening CLI selection.
- [x] Validate the four canonical provider/platform argv arrays, their domain-separated hashes, and bundle hash before any probe; legacy `--evidence-root` and `--index` are rejected.
- [x] Validate `timeout`, `auth`, `quota`, and `rate_limit` as `repair=none` and `fallback=allowed`; preserve the distinct exhausted-role projections.
- [x] Validate the publication classifier precedence and all ten named cross-boundary fixtures; persist a journal hint but serialize publication only from durable derived state.
- [x] Validate the 84-file payload root with the `KAR-SOT-PAYLOAD-ROOT/1` domain, UTF-8 bytewise path sort, NUL, raw 32-byte digest, and LF grammar.

## P0 Contracts

- [x] Implement separate domain states for run, role task, attempt, parse, validation, evidence, verdict, and finding lifecycle. See [Domain and State Model](docs/02-domain-and-state-model.md).
- [x] Implement canonical UUIDv7 ID types and prefix validation.
- [x] Implement `.kar/{session_id}/{run_id}/review_{uuidv7}.json` as the only final publication path. See [Artifacts](docs/08-artifacts-lineage-and-storage.md).
- [x] Enforce at most one final review per run.
- [x] Record final file SHA-256 in `manifest.json`.
- [x] Keep completed runs immutable.
- [x] Reject project-controlled executable provider configuration. See [Configuration](docs/04-configuration.md).
- [x] Default provider workspace access to `none`. See [Security](docs/09-security-and-trust.md).
- [x] Implement a central coordinator for dynamic fallback and terminal state.
- [x] Ensure valid findings never trigger fallback.
- [x] Ensure security, cancellation, configuration, artifact, and internal failures never trigger fallback.

## Provider Output and Repair

- [x] Require JSON-only provider output.
- [x] Validate provider output against versioned schemas.
- [x] Apply meaningful-value checks in addition to key presence, including followup summary/rationale, current evidence quotes, every new-finding title/description/recommendation/evidence quote, and present limitations; reject deterministic resolved/rationale contradictions. Evidence: `TestFollowupValidatorRejectsMeaninglessProviderText`, `TestFollowupValidatorRejectsResolvedContradictions`, and `TestFollowupValidatorAcceptsNonContradictoryRationale`.
- [x] Separate AI-owned and KAR-owned mandatory fields. See [Field Ownership Matrix](docs/16-field-ownership-matrix.md).
- [x] Implement one constrained repair attempt by default.
- [x] Support `reformat_only`, `fill_missing_fields`, and quote-only `exact_evidence` repair modes.
- [x] Restrict patch paths to explicit `allowed_paths`.
- [x] Prohibit overwrite of existing meaningful values.
- [x] Preserve all raw and repaired outputs as immutable attempt artifacts.
- [x] Run complete schema, semantic, and evidence validation after repair.

## Target and Evidence

- [x] Resolve Git refs to immutable object IDs at capture time.
- [x] Record staged, unstaged, and untracked scope explicitly.
- [x] Implement target content SHA-256.
- [x] Verify evidence path, side, lines, and quote against captured target.
- [x] Require verified evidence for configured high severities.
- [x] Generate excerpts inside KAR after verification.
- [x] Independently reread immutable source authority after followup, delta, and rerun child execution; classify reread failure or changed source identity/bytes as security policy, publish no child P2, and project exit `8`. Evidence: followup, delta, and rerun source-mutation service tests plus `TestApplicationG008FailureCancellationAndTypedExits`.

## Runtime

- [x] Use direct argv by default.
- [x] Pass only allowlisted environment values.
- [x] Separate stdout result bytes from stderr diagnostics.
- [x] Enforce output and timeout limits.
- [x] Kill complete process groups on cancellation.
- [x] Serialize attempts by concurrency key.
- [x] Add cross-process lane locking where supported.
- [x] Implement fake providers before live adapters.
- [x] Enforce production domain/application dependency direction, including the reviewrun-to-provider qualification port boundary and prohibitions on filesystem, `os/exec`, Cobra, YAML, and JSON Schema capability imports; ignore only generator files selected by a valid `//go:build ignore` constraint. Evidence: `TestProductionDependencyDirection`, `TestBuildIgnoreConstraintDetection`, and `TestAdapterCapabilityImportClassification`.
- [x] G010 macOS AGY native-auth boundary: use only the captured and inode-revalidated installed-user `HOME`/Keychain context for AGY authentication; do not create a synthetic AGY `HOME`, project credentials, or copy OAuth or installation files. KAR's namespace setup, policy, and cleanup paths must not write, overwrite, zero, or unlink user AGY authentication/settings files; normal provider-owned Keychain/profile refresh may still occur during AGY execution. Preserve the descriptor-bound immutable review CWD and KAR-owned XDG/cache/temp/scratch namespaces; enforce `--sandbox`, exact immutable-snapshot `--add-dir`, `--mode plan`, bounded time/output, and post-output `SIGTERM`/`SIGKILL`. AGY's minimum version is 1.1.4. Evidence: installed AGY 1.1.7 native boundary and auth/settings mutation checks passed in the non-skipping final-tree E2E on 2026-07-26.

## Artifacts

- [x] Use secure directory and file permissions.
- [x] Use atomic replacement for mutable run status and publication journal files; install the committed manifest immutably with no replacement.
- [x] Use write, validate, fsync, and atomic rename for final review publication.
- [x] Detect hash mismatch and multiple final files as corruption.
- [x] Add safe retention/tombstone cleanup and redacted secure export paths.
- [x] Allocate every production root and child publication epoch atomically through the root-scoped publication store; never use a process-local counter as production publication authority. Evidence: childrun lineage rejection tests, `TestPublishNextUsesRootBoundEpochTransaction`, `TestPublishNextRejectsStoreWithoutAtomicEpochTransaction`, and filesystem publication epoch/lock tests.

## CLI and CI

- [x] Implement distinct review, followup, delta, and rerun application services with immutable child-workflow lineage.
- [x] Make followup, delta, and rerun create child runs, never mutate the source run.
- [x] Keep review verdict separate from CI decision.
- [x] Implement documented exit-code precedence through the single canonical `FailurePrecedence` reducer used by reviewrun, report, query, and CLI projections. Evidence: `TestFailurePrecedenceIsExactAndClosed`, report/query precedence agreement tests, and application failure-precedence tests.
- [x] Add all required help topics and golden tests.
- [x] Cover all seven init provider subsets and canonical family order in CLI E2E tests.
- [x] Emit the rejected init request/result envelope for unambiguous invalid JSON requests.
- [x] Admit the installed native account before `kar config` exposes an accepted digest.
- [x] Prove committed init bytes survive stdout short-write and closed-pipe delivery failure.
- [x] Census embedded help for sole-source, subset, workspace, AGY, durability, transport, and no-migration requirements.
- [x] Preserve native-home observation cancellation as exit 9 for init/config/doctor without weakening security precedence.
- [x] Cover auto discovery with zero through three providers in human and JSON CLI E2E tests.
- [x] Exercise new/existing root-barrier failure, retry, and installed-unconfirmed directory-sync projections at the CLI boundary.
- [x] Ensure product text never implies approval authority.

## Historical G009 Integrated v0.1 Gate Evidence

- [x] Historical: retain the exact 17 load-bearing command registry/binary golden and the truthful schema-list v1 rejection.
- [x] Historical: validate all 25 schema/example pairs and assets.
- [x] Historical: retain fake/offline canonical lineage evidence from the four-workflow end-to-end execution; this is not production root-review proof.
- [x] Historical: retain subprocess crash proof and the full domain, security, publication, cancellation, and fallback suites.
- [x] Historical: full `go test`, `go vet`, and race verification passed with zero recorded P0 blockers.
- [x] Retain the controlled Kimi historical qualification narrative for the recorded G009 run: `kimi/local-default/0.23.6/50c3582a1beeba081271193b74efc39c51b3a0a16b4bf32b754b9482a86a314a/kimi-default`, its append-only external ledger receipt, receipt SHA-256 `1227711091fc94aff32dfed18d34f009da7404862b1eb63d99a2313a30c2be27`, and raw-output SHA-256 `435639659d6ec453a8271d9a82787e11d4aa1be0450b981b0aab040966172141`. Development evidence is excluded from Git; this is not a current support boundary.
- [x] Preserve the append-only provider attempt history: two later 2026-07-18 retries each ended after approximately 30.15 seconds with `status=timeout`, `termination=timed_out`, and `diagnostic=process_timeout`; retain those ledger events without replacing the earlier PASS.
- [x] Keep G0 provider-family evidence for `kimi`, `zcode`, and `agy` separate from current support. Support those families by runtime capability contract without version, executable path, SHA, or profile allowlisting; retain those fields as diagnostic provenance, produce actionable typed capability diagnostics, explicitly block known incompatibilities only, reject unlisted families, and do not automatically substitute providers. Keep `darwin-arm64` as the sole supported platform.
- [x] Historical integrated-gate classification: **HISTORICAL_GATE_PASS_NON_PRODUCTION**. At G009 closure, production `kar review` composition was wired but remained **REOPENED_PRODUCTION_REVIEW_INCOMPLETE** pending later verification. G011 later supplied capability-only acceptance but is now historical under G012; this row grants no release-publication authority.

## Historical G010 Config-driven Multi-provider Production Gate

The checked requirements in this section describe the 2026-07-26 and 2026-07-27 gate runs. They are retained for provenance. SOT 1.13.0 does not require their fixed role matrix, planted finding, exact line citation, twelve-route qualification cardinality, six-process overlap, whole-review retry policy, or complete child-workflow live execution.

### Contract and configuration

- [x] Freeze SOT 1.10.0 with G010 status `IMPLEMENTATION_IN_PROGRESS`, the six-role primary/fallback matrix, workflow-specific fallback scope, and the exact `make test` release gate.
- [x] Implement canonical Config v2 and reject Config v1 without migration or compatibility fallback. Evidence: `TestConfigV2RoleAssignmentsAndV1Rejection`.
- [x] Require every role primary to reference a configured `kimi`, `zcode`, or `agy` family; require a distinct configured fallback whenever two or more families are configured; permit fallback omission only for a singleton. Evidence: config semantic validation and seven-subset round trips.
- [x] Generate the canonical all-family matrix: `logic=kimi/zcode`, `documentation=agy/zcode`, and `security|maintainability|product|testing=zcode/agy`; deterministically reduce the same role preference order for provider subsets. Evidence: `TestInitializeProjectSupportsAllSevenSelectedSubsets`.
- [x] Expose only redacted role-family assignments through `kar config` and retain strict credential rejection. Evidence: `TestRedactionOmitsExecutableAndNativePaths` and adapter credential tests.

### Planning, fallback, and reporting

- [x] Resolve configured family assignments to current qualified provider routes exactly; reject an absent or unqualified configured primary/fallback instead of silently substituting another family. Scope current qualification to the requested roles for which each family is actually the configured primary or fallback, never unrelated requested roles. Evidence: `TestQualifiedPlannerUsesExactConfiguredPrimaryAndFallbackMatrix`, `TestQualifiedPlannerFailsClosedWhenConfiguredFamilyIsNotQualified`, and `TestQualificationCandidatesAreRestrictedToSelectedPrimaryAndFallbackAssignments`.
- [x] Preserve the primary result without invoking fallback when primary execution produces valid output, including a valid finding. Evidence: `TestCoordinatorDeterministicBoundedConcurrentExecution/valid-request-changes-no-fallback`.
- [x] Schedule configured fallback only for `unavailable`, `timeout`, `authentication`, `quota`, `rate_limit`, or invalid output after its single constrained repair is exhausted. Evidence: `TestDecideTransitionExhaustiveMatrix` and coordinator repair/fallback order tests.
- [x] Forbid fallback for security-policy, configuration, artifact, cancellation, internal, mutation, and valid-finding outcomes. Evidence: the exhaustive transition matrix and coordinator terminal-path tests.
- [x] Refine an explicit native `auth.login_required` signal to provider-attributed `login_required`; fail closed before P2 with exit `4`, reason `provider_login_required`, `retryable=false`, and no repair or fallback. Report every affected provider instance so the user can authenticate outside KAR and rerun the same command from current qualification. Evidence: `TestClassifyProbeFailurePreservesExplicitLoginRequired`, `TestRegistryObserveClassifiesExplicitLoginRequired`, `TestCoordinatorProtectedConditionsNeverScheduleFollowup/login_required`, `TestProviderCurrentQualifierAttributesLoginRequiredWithoutRetry`, `TestQualifiedRunFactoryDoesNotSkipLoginRequiredCandidate`, and `TestApplicationReviewReportsProviderLoginRequiredFailClosed`.
- [x] Preserve each operational current-qualification rejection as configured provider instance plus a closed safe reason code; when a selected primary/fallback route is rejected, fail before P2 with exit `4`, `provider_qualification_failed`, `retryable=true`, canonical provider attribution, and no raw native output. Evidence: `TestQualifiedRunFactoryReportsOperationalQualificationFailure`, `TestQualifiedPlannerAttributesRejectedConfiguredFamily`, and `TestApplicationReviewReportsAttributedQualificationFailures`.
- [x] Preserve primary failure attempts and fallback attempts, and report the successful fallback role as `selected_via=fallback` with matching P2 lineage and exit projection. Evidence: `TestCoordinatorRoutesReceiptLimitsAndCopiesCIPolicy`, publication candidate invariants, and report manifest reconciliation tests.
- [x] Project coordinator security, configuration, artifact, internal, and cancellation stops as their typed non-publishable failure before P2 preparation; never feed cancelled peer roles into publication and collapse the invariant to generic readiness. Evidence: `TestCoordinatorNonPublishableFailurePrecedence` and application failure precedence tests.
- [x] When any lane is non-publishable, attribute every unsuccessful provider lane using only provider instance, role, and a closed attempt-condition code; preserve the highest-precedence typed exit with `provider_execution_failed`, `retryable=false`, no P2 URI, and no raw native output or free-form diagnostics. Retain operational predecessor, lower-precedence, and peer-cancellation facts so fallback exhaustion cannot hide the initiating stop. Evidence: `TestProviderExecutionFailuresAreSafeAndCanonical` and `TestApplicationReviewReportsAttributedProviderExecutionFailure`.
- [x] Initially bound production invocations at 4 minutes, normalized lanes at 49 minutes, and runs at 50 minutes after concurrent current Kimi and ZCode both exhausted the former 2-minute-20-second bound; the later six-lane stabilization item supersedes ZCode's per-invocation timeout only. Run AGY with `--effort low` and native `--print-timeout 3m55s`, and classify AGY's exact nonzero `timeout waiting for response` result as provider timeout rather than internal failure. Evidence: `TestRegistryObserveClassifiesNativeProviderTimeout`, production budget tests, provider observation status/termination cross-product tests, and focused current-provider gate diagnostics.
- [x] Run ZCode headless with `--mode build`, `--json` after the bound prompt, and `--disallowed-tools '*'`; zero tool authority is retained while avoiding plan-approval responses that omit the terminal artifact. Retain the existing packet argv index, require a non-empty top-level `response` string, and isolate its terminal JSON object before validation while preserving bare terminal-JSON compatibility. Reject installed 0.15.2 `--force-mcs` because the GLM-5.2 production path exceeds its cache-control breakpoint limit, and reject the launcher's nonfunctional advertised `--max-turns` option. Evidence: canonical invocation, qualifier, registry argv, and ZCode envelope extraction tests.
- [x] Retain a quote-only `exact_evidence` repair plan when immutable lookup selects the claimed path/side/range but the provider omits or changes exact bytes; unrepairable evidence bypasses repair and proceeds directly to eligible fallback. Evidence: validation exact-evidence tests and `TestInitialQuoteMismatchRetainsExactEvidenceRepairPlan`.

### Production workflows

- [x] Run production `review`, `delta`, and recomposed `rerun` through current Config v2 primary/fallback assignments. Evidence: shared `productionRuntimeGraph`, deferred child services, and configured planner tests.
- [x] Run `followup` with the source finding provider and no configured fallback. Permit exactly one same-provider, same-attempt repair only when the initial bytes are not one JSON object or the normalized document fails the provider-owned schema; semantic contradiction, evidence, trust-boundary, security, mutation, artifact, cancellation, timeout, authentication, quota, and rate-limit failures never gain followup repair authority. Persist initial/repair invocation inventory and attach installed child-run diagnostics to terminal typed failures. Evidence: followup repair-authority validation tests, bounded invocation publication invariants, production child diagnostic wiring, and the 2026-07-27 full-workflow E2E pass.
- [x] Run exact `rerun` exactly once with the source attempt provider; do not apply configured fallback to exact replay. Evidence: source-bound authority, `ReplayStored`, and exact replay assignment tests.
- [x] Revalidate configuration, provider authority, immutable target, prompt, and credential namespace per CLI process and clean KAR-owned temporary state on every terminal path. Evidence: per-command deferred graph composition, packet screening, workspace completion/abort, namespace drain, and private-root cleanup.
- [x] Open and finalize one production runtime diagnostic lifecycle for followup, delta, exact rerun, and recomposed rerun. Delta/rerun reuse coordinator/provider invocation diagnostics; followup persists bounded separated raw streams directly. Preserve provider/validation failure classes through CLI projection, and reserve artifact exit `7` for actual diagnostic or publication persistence failures.

### Test and release gate

- [x] Promote SOT 1.12.0 without changing CLI, Config v2, or P2 schemas; separate direct health for all 12 selected qualification candidates from recovery-aware six-role product acceptance. Evidence: `TestLiveQualificationHealthGate`, `TestLiveRecoverableAssignmentGate`, and `TestE2ELiveFullWorkflowAndNoSkipContract`.
- [x] Classify fake-provider workflow tests as integration tests, never E2E tests. Evidence: `TestIntegrationFakeProviderRepairNormalizationAndAxes`, `TestIntegrationG008ProviderRuntimeCapturesRepairArtifactsDeterministically`, `TestIntegrationG008RealCompositionApplicationChildWorkflows`, and `TestIntegrationArtistHomepageWorkspaceReview`; the only `TestE2E` symbol is the build-tagged actual-provider gate.
- [x] Run `test-unit` and `test-int` independently with `-race -count=1`. Evidence: both exact Make targets passed on 2026-07-22 after the `login_required` implementation.
- [x] Stabilize one non-skipping focused combined live review of an immutable committed `HEAD^...HEAD` fixture with three concurrent independent primary lanes: `logic=kimi`, `security=zcode`, and `documentation=agy`, `max_active_lanes=3`, and three distinct provider instances. The deterministic fixture oracle fixes the two valid-negative roles and the planted security finding's exact head-side evidence. The gate may issue at most three whole-review commands to absorb a transient current-provider execution or fallback; the accepted run itself must publish schema-valid P2 from one successful initial primary invocation per lane with no repair or fallback. A truthful schema-valid role outcome may be `completed` or `degraded`; provider binding, primary selection, successful attempt state, and one-invocation cardinality remain mandatory. `provider_login_required`, security, configuration, and artifact stops are never retried. A native login requirement must fail before P2 with provider attribution rather than being hidden by aggregate readiness. The retained full-workflow helper remains outside the executable E2E set until this focused gate passes and therefore cannot establish release readiness. Evidence: `TestE2EActualProvidersThreeIndependentPrimaryLanes` and clean `make test-e2e` PASS in 168.429 seconds on 2026-07-22.
- [x] Build one current KAR candidate and run non-skipping E2E against the actual Kimi, ZCode, and AGY binaries and native authentication. Evidence: the same clean `make test-e2e` built the candidate and completed the focused three-provider gate on 2026-07-22.
- [x] Split the ZCode family into fixed `zcode-default` and `zcode-secondary` production instances with disjoint credential/concurrency namespaces and deterministic role shards, raise new-project `max_active_lanes` to 4, and exercise `logic=kimi-default`, `security=zcode-default`, `maintainability=zcode-secondary`, and `documentation=agy-default` in one focused live review. The accepted run must use one successful initial primary invocation per role with no repair or fallback, and the four native process intervals must have a nonempty common intersection. Evidence: the same-CWD two-ZCode registry barrier test, exact planner/authority shard tests, `TestE2EActualProvidersFourConcurrentPrimaryLanes`, and clean `make test-e2e` PASS in 173.795 seconds on 2026-07-24.
- [x] Extend ZCode to fixed `zcode-default`, `zcode-secondary`, `zcode-third`, and `zcode-fourth` instances with distinct credential/concurrency namespaces, raise new-project `max_active_lanes` to 6, and exercise all roles in one focused live review: `logic=kimi-default`, `security=zcode-default`, `maintainability=zcode-secondary`, `product=zcode-third`, `documentation=agy-default`, and `testing=zcode-fourth`. The accepted run must use exactly one successful initial primary invocation per role with no repair or fallback, and all six native process intervals must have a nonempty common intersection. Evidence: same-CWD four-ZCode registry barrier test, exact production/planner shard tests, `TestE2EActualProvidersSixConcurrentPrimaryLanes`, and clean `make test-e2e` PASS in 213.270 seconds on 2026-07-25.
- [x] Refine qualification transport security diagnostics without weakening the stop: retain closed prompt-file pre-start/post-termination identity, transport receipt, lifecycle receipt, output frame, and signal receipt subtypes; project every subtype to the same non-retryable security policy as `provider_transport_verification_failed`; and preserve the exact subtype through process, provider qualification, runtime event, and terminal status boundaries without native text or path disclosure. Evidence: focused process/providercli/review/reviewrun cause-propagation tests, exact policy-projection tests, and clean `make test-e2e` PASS in 166.771 seconds on 2026-07-25.
- [x] Stabilize the six-lane gate without weakening provider validation: preserve an exact AGY JSON frame when AGY handles KAR's bound post-output `SIGTERM` by exiting nonzero, constrain material-scope completeness detection to related nearby terms, identify committed-target `head` evidence without prescribing role conclusions, and raise only ZCode's bounded timeout from 4 to 6 minutes while the recalculated worst lanes remain below 49 minutes. Evidence: handled-SIGTERM lifecycle regression, completeness false-positive regression, production timeout/budget tests (worst lane 40m12s; run 40m17s), targeted and full unit/integration race suites, and clean six-role `make test-e2e` PASS in 311.844 seconds on 2026-07-25.
- [x] Make `logic` and `security` the init/project enabled-role floor rather than an implicit per-run union: add `kar init --roles`, let an omitted review selection use all enabled project roles, let explicit review subsets select exactly any enabled nonempty set, and retain required semantics only when a required role is selected. Replace ordinal instance names with `{family}-{role}` for instance, runtime profile, credential namespace, and concurrency identity; retain six concurrent default E2E lanes and prove six same-CWD ZCode role sessions can overlap. Evidence: init/config/policy/domain/publication/query subset tests, 18-template production candidate tests, `TestRegistryRunsSixZCodeRoleInstancesConcurrentlyInSameGuardedCWD`, unit and integration race suites, and `TestE2EActualProvidersSixConcurrentPrimaryLanes` via clean `make test-e2e` PASS in 245.785 seconds on 2026-07-25.
- [x] Supersede the prior init floor with logic as the sole mandatory role: omitted `kar init --roles` enables only logic, explicit init roles are canonicalized with logic, config may require additional enabled roles, explicit root-review role subsets remain exact, and artist remains UI-only and opt-in. Add `kar roles` as the static inventory command and make exhaustion of every selected lane fail with incomplete coverage and exit `4`. Development `.kar/` and `/artifacts/` evidence is excluded from Git while historical G009 tuple and digest narrative remains.
- [x] Exercise the executable recovery-aware full-workflow E2E: Config v2 init/config/doctor, six-role review, followup, three-family delta, exact rerun, and recomposed rerun with schema-valid P2, lineage, assignment, and exit/artifact consistency assertions. Require every configured primary launch and the six initial primary process intervals to overlap, while accepting a bounded primary repair or the exact configured fallback as a successful product outcome. Evidence: `TestE2EActualProvidersSixConcurrentPrimaryLanes` passed the complete workflow in 842.993 seconds on 2026-07-26.
- [x] Prove provider health independently from product recovery by requiring the root runtime diagnostic log to end with `qualified` candidate observations for all 12 selected primary/fallback provider instances and one `qualification_succeeded`. Fail when any required binary, launcher, native authentication, qualification, invocation, or publication step is unavailable; do not convert absence to skip or let role fallback hide provider qualification failure. Evidence: the same non-skipping live gate passed `TestLiveQualificationHealthGate` and the actual root diagnostic assertions on 2026-07-26.
- [x] Make `make test` execute exactly `test-prepare`, `test-unit`, `test-int`, and `test-e2e` in order; define no separate offline, race, release, or retained-receipt gate. Evidence: the Makefile target graph and absence of alternate test gate targets.
- [x] Preserve the 86-path/85-payload catalog, 28 schema/example pairs, checksum grammar, and generated embedded catalog after every SOT update. Evidence: both required generators and `test-prepare` passed on the exact updated SOT tree.
- [x] Run `make test` on the exact final SOT tree and record `RELEASE_READY` only after it succeeds. Evidence: exact final-tree `make test` PASS on 2026-07-26.

## G011 Corrected Release Gate

- [x] Preserve `make test` as the sole technical release gate, executing `test-prepare`, `test-unit`, `test-int`, and `test-e2e` in order.
- [x] Assign deterministic controlled-process tests authority over Config v2, supported roles and provider subsets, committed and dirty targets, qualification planning, scheduling, repair/fallback, root and child workflows, schemas, evidence, diagnostics, publication, recovery, cleanup, and CLI exit projection.
- [x] Limit live E2E authority to one production-boundary capability certification for each supported family: Kimi, ZCode, and AGY. Missing binaries, native authentication, service access, or valid output must fail rather than skip.
- [x] Enforce known-vulnerability scanning and a vulnerability-free dependency graph in `test-prepare`. Evidence: upgrade reachable `golang.org/x/text` from vulnerable v0.34.0 to v0.39.0 or newer, pin `govulncheck` as a Go tool, and require `go tool govulncheck ./...` before lint and vet.
- [x] Correct terminal cleanup error handling. Provider/workspace terminal cleanup retains bounded retry, partial receipt authority, and the initiating failure; production namespace/workspace root deletion now attempts both roots, preserves any primary workflow failure, and projects deletion failure as artifact exit `7` for root review and every child workflow. Evidence: `TestReviewCompositionCleanupFailureIsArtifactFailureAndPreservesPrimaryError`, the `reviewrun` cleanup fault matrix, production child workflow tests, and publication recovery suites.
- [x] Align root-review repair with the production provider-review v3 wire: embed the v3 repair contract, emit a v3-bound dynamic repair plan and template identity, and retain the existing one-repair/fallback transition policy. Evidence: default-template provenance and byte-contract tests, validation repair suites, and the exhaustive transition matrix.
- [x] Project followup, delta, exact rerun, and recomposed rerun provider exhaustion as a safe non-success result. Provider unavailability, invalid output, timeout, authentication, quota, and rate-limit failures use readiness exit `4`; security, artifact, cancellation, configuration, and internal precedence remain unchanged. Evidence: `TestApplicationG008ProviderExecutionFailuresAreNonSuccess` and the existing typed-exit suite.
- [x] Complete deterministic acceptance coverage, including both committed and dirty targets and the required Playwright-backed artist scenario without prerequisite skipping. Evidence: the seven-subset Config v2 binary matrix; fixed-role and provider-route planner matrices; capture scope and six-lane coordinator integration suites; root and G008 child workflow suites; schema, evidence, diagnostics, publication, recovery, and cleanup suites; `TestIntegrationArtistHomepageWorkspaceReview`; and `TestRequiredArtistPrerequisitesFailClosed`.
- [x] Replace the historical full-workflow live test with the three fail-closed family capability certifications. `make test-e2e` resolves and validates every executable/launcher/data-home prerequisite before running `TestLiveKimiCapability`, `TestLiveZCodeCapability`, and `TestLiveAgyCapability`; each test uses the production runtime definition, credential/native-home namespace, immutable fixture CWD, native prompt transport, bounded lifecycle/output parser, direct-execution receipts, terminal drain, and protected-state checks. The former `cmd/kar/live_e2e_test.go` is no longer executable release authority.
- [x] Align SOT 1.13.0, release-candidate build version, generated assets, help/examples, schemas, and supported-platform documentation. `TestMakefileContract` binds the linked candidate version to `sot/SPEC_VERSION`.
- [x] Run `make test` on the exact final committed tree, confirm a clean working tree, and only then record G011 as `RELEASE_READY`. Evidence: the unmodified sole gate passes with `test-prepare`, `test-unit`, `test-int`, and all three `test-e2e` family certifications on the exact committed tree.

## G012 Executable Release Coverage Restoration

- [x] Reopen release readiness after confirming that G011 built but never executed the release KAR binary and excluded retained live negative tests. SOT 1.14.0 and D-060 make the gap release-blocking.
- [ ] Retain the Kimi, ZCode, and AGY live capability certifications and restore every omitted AGY native-home/settings negative test to an always-executed gate.
- [ ] Execute the exact release KAR binary against actual Kimi, ZCode, and AGY through Config v2 init/config/doctor, six-role root review, schema-valid P2 publication, diagnostics, cleanup, followup, delta, exact rerun, and recomposed rerun.
- [ ] Restore fail-closed prerequisite, retry-authority, assignment, qualification-health, artifact-URI, terminal-process, and child-identity harness coverage removed with `cmd/kar/live_e2e_test.go`.
- [ ] Require one exact final committed-tree `make test` PASS with no skips, no weakened prerequisites, and a clean working tree before changing G012 or implementation readiness to `RELEASE_READY`.

## Diagnostics D-E01 — Contract, Model, and Secure Storage

- [x] Promote the normative runtime diagnostic event, status, path, cap, security, durability, and authority-separation contract as SOT 1.11.0 without cataloging `sot/plan/**`. Evidence: `d8c0352`, both required generators, and builtin catalog planning-source assertion.
- [x] Implement closed validated domain events and sink/factory ports with noop and in-memory implementations. Evidence: `4414583`; domain and ports focused race tests.
- [x] Implement the anchored `.kar/diagnostics/<session>/<run>` filesystem store with serialized JSONL, atomic status replacement, separated scanned raw streams, caps, mandatory tail reserve, durable sync, recovery, and exactly-once finalize. Evidence: `ea7b709`, `55b531f`, and focused diagnostic store tests.
- [x] Prove symlink/path escape, permissions, secret/overflow drop, partial/crash recovery, concurrent append, writer failure, and architecture boundaries under the race detector. Evidence: `TestDiagnosticStoreRejectsSymlinkEscapeAndUnsafePermissions`, `TestDiagnosticStorePersistsSeparatedBoundedRawStreamsThroughScanner`, `TestDiagnosticStoreRawOverflowReturnsSafeDropAndRemovesTemporary`, `TestDiagnosticStoreRecoversPartialJSONLineBeforeAppend`, `TestDiagnosticStoreConcurrentAppendProducesCompleteUniqueSequence`, `TestDiagnosticStoreClassifiesRawWriterFailure`, and `TestProductionDependencyDirection`.
- [x] Preserve the 85-path/84-payload catalog and record exact D-E01 verification evidence without changing G010-T05/T06 or `RELEASE_READY`. Evidence: at D-E01 completion there were 85 unique embedded sources, 84 checksum lines, and zero planning sources; G010-T05/T06 and `RELEASE_READY` intentionally remained unchecked at that historical stage and were subsequently closed by the current G010 evidence above.
