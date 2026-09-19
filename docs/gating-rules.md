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
  matching `/tmp/mulgae-gate-001.XXXXXX`. Set `HOME`, `TMPDIR`, and `GOCACHE`
  to directories beneath it, set `GOMODCACHE` to the existing value from
  `go env GOMODCACHE`, and set `GOPROXY=off` and `GOSUMDB=off`. Run these
  commands in order:

  ```sh
  go test -count=1 ./internal/app/reviewrun -run '^(TestReviewPreparationFailureClassificationIsClosedAndRedacted|TestReviewPreparationClassificationPreservesCausalTypedAndCancellationFailures|TestReviewPreparationClassificationDefersToDiagnosticPersistenceFailure|TestServiceExecuteClassifiesProviderRuntimePreparationFailure|TestCoordinatorAdmissionFailureIsClassifiedBeforeRunStart|TestServiceExecuteCoordinatorAdmissionDiagnosticFailureRemainsArtifact|TestServiceExecuteDiagnosticPersistenceOutranksPreparationFailure)$'
  go test -count=1 ./internal/entrypoint/mulgae -run '^(TestApplicationReviewPreparationFailureIsInternalAndActionable|TestApplicationIndependentCleanupFailureDoesNotSuppressReviewPreparationFailure)$'
  go test -count=1 ./internal/entrypoint/mcp -run '^(TestPublicToolErrorProjectsReviewPreparationFailure|TestServeRunReviewPreparationFailurePreservesEnvelopeAndIdentity|TestServeAwaitReviewPreparationFailurePreservesEnvelopeAndIdentity)$'
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

## GATE-002: Provider protocol and staged-output authority

- **Invariant:** Provider protocol drivers admit only correlated, purpose-bound
  responses, credential projection uses only declared private sources, and
  staged review output accepts exactly one descriptor-bound regular file while
  rejecting path, identity, mode, and cleanup violations.
- **Scope:** `internal/adapters/providercli` protocol, credential projection,
  staged-output, and accepted-result observation boundaries.
- **Positive scenarios:** Codex completes one ephemeral app-server turn, Grok
  accepts one correlated write, ZCode completes its selected-model exchange,
  declared credentials project into disposable homes, and a valid staged
  Markdown report is accepted with its digest.
- **Failure scenarios:** Codex write authority, uncorrelated or repeated Grok
  writes, unsafe credential sources, symlink or hard-link output, extra staged
  entries, missing staged output, security violations, and cleanup failures all
  fail closed.
- **Procedure:** From the repository root, create a fresh mode-`0700` directory
  matching `/tmp/mulgae-gate-002.XXXXXX`. Set `HOME`, `TMPDIR`, and `GOCACHE`
  to directories beneath it, set `GOMODCACHE` to the existing value from
  `go env GOMODCACHE`, and set `GOPROXY=off` and `GOSUMDB=off`. Run:

  ```sh
  go test -v -count=1 ./internal/adapters/providercli -run '^(TestCodexProtocolCompletesOneEphemeralTurn|TestCodexProtocolRejectsActualWriteAuthority|TestGrokACPDriveAllowsOneExactlyCorrelatedWrite|TestGrokACPDriveRejectsUncorrelatedAndRepeatedWrites|TestZCodeProtocolDriveCompletesAndPreservesEvidence|TestZCodeProtocolDriveClassifiesFailureBranches|TestCredentialSourceProjectsOnlyDeclaredFamilyFiles|TestGrokCredentialProjectionRejectsNonPrivateAuth|TestCodexCredentialProjectionUsesConfiguredCodexHome|TestStagedOutputAcceptsBoundedMarkdownWithDigest|TestStagedOutputRejectsSymlinkTarget|TestStagedOutputRejectsHardLinkSubstitution|TestStagedOutputRejectsExtraStagedEntries|TestRegistryObserveAcceptsStagedFileOutputAsPrimaryResult|TestRegistryObserveFailsClosedWhenStagedFileIsMissing|TestRegistryObserveClassifiesStagedSecurityViolation|TestRegistryObserveStagingCleanupFailureOverridesProviderSuccess)$'
  ```

  Remove the disposable directory after recording command output and confirm
  that `git status --porcelain --untracked-files=all` is unchanged.
- **Disposable outputs:** The gate directory, Go build cache, test binary,
  temporary protocol state, credentials containing fixture-only bytes, staged
  output, and captured stdout and stderr remain under the declared `/tmp` root.
- **Pass condition:** The command exits zero, every named test runs, no external
  access or ambient credential read occurs, and the source repository status is
  unchanged.
- **Revalidation triggers:** Changes to provider protocol frames, credential
  sources or projection, staged-output leases and validation, accepted result
  transport, or provider cleanup precedence.
- **Sources:** [`docs/specs/contracts.md`](specs/contracts.md),
  [`docs/specs/security.md`](specs/security.md),
  `internal/adapters/providercli/codex_protocol.go`,
  `internal/adapters/providercli/grok_acp_protocol.go`, and
  `internal/adapters/providercli/output_staging_darwin.go`.
- **Owner:** [Provider adapter package map](architecture/README.md#package-map).
