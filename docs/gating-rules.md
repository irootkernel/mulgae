# Release design gates

This registry defines offline checks for internal invariants that cannot be
reached through valid public input. Every active gate runs against the exact
release candidate without provider, network, credential, or source-write
access.

## GATE-001: Review preparation failure authority

- **Invariant:** An untyped failure after planning and before durable
  `run_started` becomes a redacted `review_preparation_failed` result with the
  allocated run identity. Typed failures, cancellation, and diagnostic
  persistence retain their higher-priority classifications.
- **Scope:** `internal/app/reviewrun` preparation classification and its CLI and
  MCP projections.
- **Positive scenarios:** Provider-runtime and coordinator-admission failures
  retain the closed preparation stage, diagnostic cause, and run identity in
  application and MCP results.
- **Failure scenarios:** Typed failures and cancellation are not reclassified;
  diagnostic persistence failures remain artifact failures; private causal
  text never reaches public output.
- **Procedure:** From the repository root, create a fresh mode-`0700` directory
  matching `/tmp/mulgae-gate-001.XXXXXX`. Before changing `HOME`, export
  `MULGAE_GO_EXECUTABLE="$(./dev path go)"` and preserve the existing module cache
  with `GOMODCACHE="$(./dev go env GOMODCACHE)"`. Set `HOME`, `TMPDIR`, and
  `GOCACHE` to directories beneath the gate root, and set `GOPROXY=off` and
  `GOSUMDB=off`. Run these commands in order:

  ```sh
  ./dev go test -count=1 ./internal/app/reviewrun -run '^(TestReviewPreparationFailureClassificationIsClosedAndRedacted|TestReviewPreparationClassificationPreservesCausalTypedAndCancellationFailures|TestReviewPreparationClassificationDefersToDiagnosticPersistenceFailure|TestCoordinatorAdmissionFailureIsClassifiedBeforeRunStart|TestCoordinatorAdmissionClassificationPreservesCancellation|TestLiveServiceDiagnosticAndLoginFailuresRetainSafeIdentity)$'
  ./dev go test -count=1 ./internal/entrypoint/mulgae -run '^(TestApplicationReviewPreparationFailureIsInternalAndActionable|TestApplicationIndependentCleanupFailureDoesNotSuppressReviewPreparationFailure)$'
  ./dev go test -count=1 ./internal/entrypoint/mcp -run '^(TestPublicToolErrorProjectsReviewPreparationFailure|TestServeRunReviewPreparationFailurePreservesEnvelopeAndIdentity|TestServeAwaitReviewPreparationFailurePreservesEnvelopeAndIdentity)$'
  ```

  Remove the disposable directory after recording command output and confirm
  that `git status --porcelain --untracked-files=all` is unchanged.
- **Disposable outputs:** The gate directory, Go build cache, test binaries,
  temporary files, and captured stdout and stderr remain under the declared
  `/tmp` root.
- **Pass condition:** Every command exits zero, the named tests all run, no
  external access is attempted, and the source repository status is unchanged.
- **Revalidation triggers:** Changes to preparation stages, failure precedence,
  runtime diagnostics, allocated run identity, CLI result projection, or MCP
  tool-error projection.
- **Sources:** [`docs/specs/contracts.md`](specs/contracts.md),
  [`docs/architecture/README.md#review-flow`](architecture/README.md#review-flow),
  `internal/app/reviewrun/preparation_failure.go`, and
  `internal/app/reviewrun/diagnostics.go`.
- **Owner:** [Review flow architecture](architecture/README.md#review-flow).

## GATE-002: Provider protocol and live-source boundaries

- **Invariant:** Terminal profiles use purpose-scoped tools, stage output
  inside the owned namespace, and preserve neutral cwd and read-only source.
- **Scope:** `internal/adapters/providercli` terminal profiles and projection,
  plus `internal/adapters/process` descriptor and Seatbelt boundaries.
- **Positive scenarios:** Both providers retain source reads and route each
  staged result to its bound invocation.
- **Failure scenarios:** Changed launch bindings, stale account or catalog
  identities, invalid completion nonces, sibling data reads and hard links,
  and protected socket access fail closed. Cancellation and deadlines retain
  their typed cause.
- **Procedure:** Use a fresh mode-`0700` directory under the mounted writable
  `/Volumes/RootKernel/tmp`, or the normal system temporary directory when that
  volume is unavailable. Before changing `HOME`, export
  `MULGAE_GO_EXECUTABLE="$(./dev path go)"` and preserve the existing module
  cache with `GOMODCACHE="$(./dev go env GOMODCACHE)"`. Keep `HOME`, `TMPDIR`,
  and `GOCACHE` beneath the gate root, and set `GOPROXY=off` and `GOSUMDB=off`.
  On native Apple Silicon macOS, run:

  ```sh
  ./dev go test -v -count=1 ./internal/adapters/providercli -run '^(TestZCodeTerminalDriverOffline|TestZCodeTerminalProjectionBindsAndDrainsIndependentLeases|TestZCodeTerminalRunPreparationInterruptionProjection|TestLiveExecutionGuidePlanAndClosedGrokPermissions|TestGrokCredentialProjectionRejectsNonPrivateAuth|TestGrokRegistryLiveReviewExtractionAndLabelScopedDrain)$'
  ./dev go test -v -count=1 ./internal/adapters/process -run '^(TestLiveBoundaryDeniesWritesReadsAndAncestorRename|TestLiveBoundaryDeniesCredentialSymlinksToOutsideTargets|TestLiveBoundaryProtectsExoticCredentialPaths|TestLiveBoundaryRejectsSymlinkAndMissingRootsBeforeLaunch|TestLiveBoundaryRejectsPreexistingCredentialHardlink|TestLiveBoundaryDeniesProtectedUnixSockets|TestLiveBoundaryCredentialAdmissionHonorsCancellation|TestLiveBoundaryCredentialAdmissionHonorsDeadline|TestLiveBoundaryRejectsPreexistingWritableHardlink|TestLiveBoundaryRuntimeTempKeepsOverlappingRootsProtected|TestLiveNeutralLaunchRejectsWrongAndReplacedDescriptor|TestLiveBoundaryProtectsMissingOptionalCredentialHomes|TestPaneExecManagedNamespaceIsolation)$'
  ```

  Remove only the task-owned directory after recording results and confirm that
  `git status --porcelain --untracked-files=all` is unchanged.
- **Disposable outputs:** Go caches, test binaries, fixture credentials,
  protocol state and captured streams remain under the declared temporary root.
- **Pass condition:** Both commands exit zero and every named test runs without
  external provider access, ambient credential reads, or source mutations.
- **Revalidation triggers:** Terminal delivery, live invocation authority,
  credential projection, protected-root policy, accepted report transport, or
  cleanup precedence changes.
- **Sources:** [Contracts](specs/contracts.md), [Security](specs/security.md),
  `internal/adapters/providercli/live_execution.go`,
  `internal/adapters/providercli/zcode_terminal_darwin.go`, and
  `internal/adapters/process/live_boundary_darwin.go`.
- **Owner:** [Provider adapter package map](architecture/README.md#package-map).

ZCode and Grok validate invocation-scoped staged outputs after verified
`ESRCH` teardown and publish the accepted bytes under `stdout` transport.
