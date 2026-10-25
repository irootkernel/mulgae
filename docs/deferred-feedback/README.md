# Deferred feedback

This index owns small actionable findings intentionally postponed from current
work.

- `DF-002` Live review runs intermittently lost every role to an unconditioned
  `internal_invariant` after invocation preparation and before process spawn.
  Spawn-path revalidation refusals are now typed: a proven environment change
  (`ports.ErrProviderSpawnEnvironmentDrift`: executable identity mismatch,
  locality drift) keeps the deterministic `provider_spawn_failed`
  classification, while an inability to establish the environment right now
  classifies as retryable `provider_unavailable` instead of destroying the
  run. Residual: the exact transient trigger (for example a subprocess or
  descriptor failure under concurrent spawn load) is still not captured as
  diagnostic text. Re-entry: when a run retries or fails through
  `provider_execution_failed` at the spawn boundary, capture the bounded
  underlying error in runtime diagnostics before considering further
  hardening.
- `DF-003` Verified reads of v2 reviews and composites reload and verify all
  captured or copied support artifacts; inspection used to repeat the full
  pass up to three times per request. TASK-055 introduced the query-owned
  per-call read context: one entry-point invocation performs each consumed
  publication's snapshot read and whole-support verification once within its
  context, serves every artifact with its own digest-bound read, and confirms
  every consumed publication in dependency postorder before returning. A
  nested public call and each report chunk or MCP continuation verify freshly
  in their own contexts. No deferred work remains.

- `DF-004` ZCode's admitted short native socket directory is shared by guarded
  sessions. The guard isolates each invocation's credentials and scratch, but
  its fixed runtime-directory exception permits one guarded session to alter
  another session's temporary entries or connect to its socket there. Random
  socket names avoid accidental collisions; they do not provide kernel
  isolation between sessions. This is a bounded residual of the approved
  native-IPC exception, rather than a promise of general process or IPC
  containment. Re-entry: a demonstrated interference failure, or a supported
  short per-invocation native temp path, warrants a separately approved
  runtime-directory change with real concurrent-provider certification.

- `DF-005` Optional run-authority observations: closed production adapters
  currently implement the observation capability. A future injected factory
  could omit it, and optional interfaces can shadow each other. Re-entry:
  before adding a factory or changing authority capability composition,
  assert observations are retained and incompatible combinations fail before
  invocation.

- `DF-006` Tool-observation memory: live review validation retains provider-
  chosen operation identities and variants. No problematic memory peak was
  reproduced. Re-entry: a measured peak from a large tool stream warrants
  reducing retained bookkeeping while preserving correlation and the no-
  content-byte-ceiling policy.

- `DF-007` Diagnostic order: TASK-064 orders Grok and Cursor final tool
  validation by ascending raw native string ID. Per-operation checks,
  immediate failures, first rejection and typed refusal remain unchanged.
  `TestProviderToolDiagnosticOrder` covers simultaneous violations after
  successful read admission and target invalidation, opposite insertion
  orders, numeric/Unicode IDs, admission traces and Grok late close-time
  updates. AGY retains its identical unfinished-operation diagnostic.

- `DF-008` Compound qualification failures: an operational
  persistence/artifact failure may lose a secondary qualification cause. A
  simple error join changes terminal or public precedence. Re-entry:
  implement cause retention only with direct terminal, public class and
  original-cause assertions that preserve the current fail-closed precedence.

- `DF-009` Native status diagnostics: unsupported or incomplete native tool
  status correctly rejects a live role report. Re-entry: an observed native
  status that operators cannot distinguish warrants bounded status diagnostic
  tests and an explicitly verified provider-wire interpretation.

- `DF-010` Inspection defensive tests: direct assertions remain useful for
  malformed internal page projections, receipt suppression, paged fallback
  and publication re-observation. Current verified query and publication
  guards reject corrupted state. Standing rule: before changing projection,
  paging or diagnostic recheck code, add negative fake-reader and
  interleaving assertions for those guards; keep the existing shared digest
  parser and MCP guard as the current admission authority. TASK-055 delivered
  the named controls before changing observation:
  `TestInspectionInterleavingsFailClosedAtEveryObservationPoint`,
  `TestInspectionRejectsMissingOrReboundRoleReportSupport`,
  `TestInspectionRejectsCorruptedUnservedSupport`,
  `TestReadFindingInterleavingsAfterSnapshotFailClosed`,
  `TestReadContentInterleavingsFailClosed`,
  `TestReadSourceEvidenceRejectsReboundAndUnservedCorruptSupport` and
  `TestReadRunStatusInterleavingsPreserveCorruptIdentity`
  (`internal/app/query`), `TestRenderMixedExcerptFailuresKeepFatalOverPartial`
  (`internal/app/report`), `TestVerifiedReadParserRejectsMalformedDigestSelectors`,
  `TestVerifiedReadRejectsMalformedInspectionProjection` and
  `TestPagedDiagnosticFallbackIsSuppressed` (`internal/entrypoint/mulgae`),
  `TestContentResourceRejectsMalformedDigestParameters`
  (`internal/entrypoint/mcp`) and `TestMCPInspectFallbackSuppressesPagedRequests`
  (`internal/composition`). No deferred work remains.

- `DF-011` Live source defensive tests: TASK-056 delivered the pre-change
  rejection controls before separating path admission from body reads:
  unresolvable non-branch HEAD spellings with resolvable detached and
  tag-backed positive controls (`TestIntegrationLiveSourceNonBranchHead`;
  the locality attester covers its own spellings in
  `locality_darwin_test.go`), an unborn HEAD selector, an ignore-matched
  symlink present before non-Git admission, and a synchronized successful
  read round before Close (`TestIntegrationLiveSourceConcurrentReadsAndClose`
  also pins `AdmitPath` against racing and synchronized Close). Unsafe
  per-worktree config stays directly covered by
  `TestIntegrationLiveSourceExecutionRejectsUnsafeGitConfig/worktree-config`,
  and post-open root and config replacement for `Read` by
  `TestIntegrationLiveSourceRejectsRootAndConfigReplacement`, and post-open
  root replacement for `AdmitPath` by the root-swap case in
  `TestIntegrationLiveSourceAdmitPathObservesCurrentPath`. The end-to-end
  stage-transition no-change row keeps its read-count assertions plus
  target-based qualification expectations pinning zero provider calls and
  the published result (`internal/app/reviewrun`). Supporting predicate and
  held-descriptor tests distinguish unlink/rename replacement from in-place
  modification against the held descriptor and cover both the five-field
  stability predicate and the two-field namespace predicate.
  `TestIntegrationLiveSourceAdmitPathParity` and
  `TestIntegrationLiveSourceAdmitPathObservesCurrentPath` pin the body-free
  admission outcomes, including the decided mislabeled-raster divergence.
  TASK-057 delivered its pre-change controls, which passed at the base:
  an empty-tree HEAD commit with head-scope no-change
  (`TestIntegrationLiveSourceEmptyTreeHeadNoChange`), protected-name case
  variants committed through plumbing
  (`TestIntegrationLiveSourceInventoryCaseVariants`), an end-to-end
  whole-tree no-change fixture asserting zero provider calls and the
  resulting publication (`TestIntegrationLiveServicePublishesWholeTreeNoChange`
  in `internal/app/reviewrun`), and metadata rejection ahead of retained
  inventories (`TestIntegrationLiveSourceMetadataRejectionControls`).
  TASK-057's retention verification was delivered with the change: the
  config-retention suite covering appearance, disappearance and identical
  reappearance, changed unsafe bytes, same-length rewrites with the mtime
  restored, parser failures never cached and symlink replacement
  (`TestIntegrationLiveSourceExecutionConfigRetention`); the retention
  state checks covering bytes re-read on every revalidation, bounded
  reader-local state and Close clearing
  (`TestIntegrationLiveSourceRetentionState`); the concurrency check
  (`TestIntegrationLiveSourceRetentionConcurrency`); and the reuse counts,
  including a second reader that starts fresh
  (`TestIntegrationLiveSourceReusesCommitInventories` and
  `TestIntegrationLiveSourceExecutionConfigRetention`).
  Standing re-entry rule: before changing the owning reader or admission
  guard, add deterministic rejection cases; any production synchronization
  seam needs its own bounded scope. Open items without such a seam:
  mid-read replacement inside `Read`, whose guards TASK-056 left unchanged;
  the intra-call device/inode mismatch branch of `AdmitPath`'s reopen check;
  and `AdmitPath`'s final `revalidate`, which covers intra-call drift of the
  root identity, namespace or Git binding.

- `DF-012` MCP startup configuration: TASK-062 added
  `TestServePartialToolConfiguration` in
  `internal/entrypoint/mcp/review_request_characterization_test.go`. It covers
  all six nonempty incomplete combinations of Backend, NewRequestID and
  ToolResultSchema, asserting the exact rejection and zero stream/backend
  activity before server startup. No deferred work remains.

- `DF-013` Provider JSON surrogate tests: TASK-061 added
  `TestProviderJSONSurrogateCompatibility` in
  `internal/app/validation/surrogate_compatibility_test.go`. The owning review
  and followup parsers reject lone-low and lone-high surrogates and decode a
  valid pair as the exact Unicode scalar, preserving validation and repair
  outcomes without accepting replacement bytes. No deferred work remains.

- `DF-014` Rejected init result tests: TASK-062 added
  `TestRejectedInitOutputModes` in
  `internal/entrypoint/mulgae/review_request_characterization_test.go`. Invalid
  init flags cover JSON, duplicate JSON, mixed output in both orders, human,
  dangling and omitted output modes. The controls assert exit 2, exact human
  stdout/stderr, or the schema-valid rejected-init envelope with invalid
  request state, no attempted write and `init_selection_invalid`.
  No deferred work remains.

- `DF-015` Source-read allocation: live file reads can retain large source
  bodies without a product byte ceiling. No out-of-memory failure was
  reproduced. Re-entry: measured unacceptable peak memory warrants streaming
  or spooling with complete content and existing file-identity checks
  preserved.

- `DF-016` ZCode fallback credential format: absent an environment secret,
  the current local fallback key is predictable. Native credential access
  requires accepted file ownership and mode 0600. External desktop-format
  behavior remains unverified. Re-entry: a verified provider-format change or
  new confidentiality requirement warrants an explicitly authorized
  credential-format investigation; do not migrate credentials from this
  report alone.

- `DF-017` Codex permission boundary: native Codex permission enforcement is
  the adopted design; Mulgae's outer filesystem guard applies to ZCode and
  Grok. Re-entry: a demonstrated native mutation-permission failure, or a
  newly supported outer guard integration, warrants a separately authorized
  boundary design and real provider certification. No bypass was demonstrated
  in the current receipts.

- `DF-018` Native notification operands: complete operations are checked
  after fragments merge under one tool identity. No malformed admitted
  operand was demonstrated. Re-entry: when a verified provider wire change
  introduces fragment assembly, assert split string operands and reject
  ambiguous assembly before changing admission.

- `DF-019` Grok variant fields: live ReadFile uses target_file and rejects
  the obsolete file_path representation. Legacy staged Write has a separate
  wire contract. Re-entry: before changing a variant or invocation purpose,
  assert its own input field and retain the existing rejection controls.

- `DF-020` Qualification guard tests: the receipt-loop controls now show
  position independence, with the first and a later invalid entry both
  failing closed. Covered by `TestCurrentProbeAppReceiptsRejectsInvalidFirstAndLaterReceipts`
  (unrecognized kind, zero expiry, expiry mismatch, duplicate of the first and
  of a later receipt, with a positive all-valid control; each case asserts it
  is rejected by its intended check),
  `TestValidateQualificationRejectsInvalidFirstAndLaterReceipts`
  (duplicate kind, non-pass state, an all-at-once expired set, and identity
  mismatch, each asserting its own decision reason so no other check can mask
  it), the
  observation-bearing aggregation controls
  `TestQualifiedRunOperationalInvalidOutputObservationKeepsRemainingRoutes`
  (rejected observations stay in the ordered sequence) and
  `TestQualifiedRunFatalCapabilityStageFailsClosed`, the selected-observations
  control `TestQualifiedRunFatalSelectionReportsOnlySelectedObservations`
  (only the selected fatal error's observations are reported), and the labeled
  candidate fallback characterization
  `TestCapabilityEvidenceCandidatesFallbackCharacterization` (which asserts
  the actual candidate count per case). Duplicated malformed JSON payloads
  remain covered by `TestValidateProbeEvidenceRequiresPositiveCapabilityOnly`.
  The original re-entry rule was applied before the TASK-058 aggregation
  change; no deferred work remains.

- `DF-021` Native tool lifecycle tests: current terminal gates reject
  incomplete tools. Direct cases for a statusless update after terminal
  completion and multiple pending candidates would strengthen regression
  coverage. Re-entry: before changing stream state or event-loop
  coordination, assert terminal reopening cannot retain report acceptance and
  every candidate remains correlated.

- `DF-022` Historical v1 captured archive: ports tests cover the legacy
  codec, while ReadRuntimeTarget preserves the original archive bytes after
  target binding. Query-service v1 fixtures now exist (TASK-050): exact v1
  bytes plus wrong-binding, missing, and tampered archive cases run alongside
  v2 controls before the retained support reader changes. The
  [frozen historical corpus](../implementation-tips/README.md#historical-compatibility-corpus)
  also retains those controls, including a non-minified v1 archive. No deferred
  work remains.

- `DF-023` Live admission and artist brief tests: canonical root mismatch is
  rejected before admission, and a binary artist brief is rejected before
  provider task assignment. Direct negative fixtures remain useful. Re-entry:
  before changing either guard, assert a mismatched source root fails with no
  qualification or publication, and PNG, JPEG and WebP brief bodies fail as
  non-text while ordinary text briefs retain their current behavior.

- `DF-024` MCP defensive tests: TASK-062 added
  `TestMCPRequestIdentityAdmission` and `TestMCPLifecycleAndResultBounds` in
  `internal/entrypoint/mcp/review_request_characterization_test.go`. Failed
  and malformed generated request IDs assert the exact SDK JSON-RPC error and
  zero backend calls. Malformed await/cancel IDs reject without new execution
  or cancellation of an active review, followed by a valid cancellation
  control. Encoded results at limit-1, limit and limit+1 exercise the renderer
  and SDK at 1 MiB and both 32 MiB tool routes. SDK cases retain one backend
  production call, including oversized results, and assert the reached public
  success or JSON-RPC error contract. No deferred work remains.

- `DF-025` Historical capture facade: `internal/app/reviewrun/capture_identity.go`
  has no production callers; its manifest wrappers are used only by their own
  tests. This leaves historical contract tests under orchestration ownership.
  Re-entry: before changing retained capture manifests, move those assertions
  to `internal/app/capture`, remove the unused facade and helper, and verify
  the historical encoding and integrity contracts with focused tests.

- `DF-026` Git hardening maintenance: source and provider adapters duplicate
  Git denial settings. No unsafe setting or policy divergence was found;
  each environment deliberately has its own HOME and process defaults. Re-
  entry: when changing Git hardening policy, check both
  `internal/adapters/gittarget/runner.go` and
  `internal/adapters/providercli/live_execution.go` together and verify the
  effective denial settings without merging context-specific environments.

- `DF-027` Unsupported configuration diagnostics: incompatible configuration
  versions fail closed with a generic invalid-YAML reason. The documented
  manual version migration remains valid, but the diagnostic gives little
  help. Re-entry: at the next configuration-version or Doctor-diagnostic
  change, distinguish unsupported versions and point to `mulgae help config`.
  Review compatibility of machine reasons and retain fail-closed admission.

- `DF-028` Load-sensitive protected-directory control: under concurrent
  multi-process `-race` load, the positive control read of `tracked.txt`
  in `TestIntegrationLiveSourceRejectsProtectedGitDirectory/{git,common}`
  intermittently fails with `unsafe_source`. It reproduces at the EPIC-012
  baseline `cf377d4` (three concurrent `-race -count=30` processes, two
  rounds: 5–11 failures per process per round) and on EPIC-013 trees; the
  serialized `make test-int` gate passes. The failure is fail-closed and its
  cause is not established. Re-entry: before changing the protected-directory
  predicate, the reader's stability or namespace checks, or this fixture,
  reproduce with that load recipe, determine whether the positive read's
  precondition races the reader's revalidation or the fixture state, and
  either make the precondition explicit or correct the predicate; never
  loosen the `unsafe_source` rejection.

- `DF-029` Qualification fakes on worker goroutines: since TASK-058 runs
  distinct-family qualification concurrently, `t.Fatal` calls in existing
  fakes (`familyDerivingQualifier` and `syntheticDerivedFamilyRoute` in
  `internal/app/reviewrun/family_qualification_test.go`, and
  `authorityProbeRunner` in `current_qualifier_test.go`) can run on worker
  goroutines, where they stop only that goroutine; the test still fails,
  but its message can mislead. Re-entry: when these fakes next change,
  report failures through return values checked on the test goroutine.

Promote an epic-sized finding to a TODO candidate or an adopted roadmap work
unit. Do not use this index as a second roadmap or status authority.
