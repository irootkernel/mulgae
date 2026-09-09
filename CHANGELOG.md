# Changelog

This file records concise shipped outcomes and the planned next stable release.

## v0.1.20 - Unreleased

### Added

- Retain verified inputs and accepted results for unpublished failed reviews, and expose
  recovery availability and exact replay data through CLI command-result v7 and MCP `get_run`.
- Add a versioned failed-run recovery source and v2 run, review, and composite
  contracts while preserving v1 reads and existing valid composition identities.

### Changed

- Require ZCode 0.16.5 or newer for app-server protocol review and qualification,
  while preserving staged-file reports and fail-closed cleanup.

### Fixed

- Recover every failed selected role, including optional roles, through exact reruns and
  composition; reject incomplete mappings and update `use-mulgae` to guide the full flow.
- Keep reviews recoverable by classifying transient spawn revalidation as retryable
  `provider_unavailable`, re-reading failed namespace listings, and bounding orphan teardown.

## v0.1.19 - 2026-09-07

### Added

- Add exact, provider-free composite recovery through `mulgae compose` and MCP
  `compose_review`, including deterministic identities, atomic reconciliation,
  and self-contained lifecycle support.
- Add the `mulgae-command-result.v6` envelope while retaining v5 for explicit
  backward reads.
- Add a non-blocking retained-artifact advisory to the source-distributed
  `use-mulgae` skill when at least ten terminal runs are safely deletable.

### Changed

- Await reviews without status polling, check the admitted wait budget, and
  reconcile interrupted waits by exact identity without duplicate starts.
- Accept AGY native JSON response envelopes while preserving exact response
  bytes, and use an adapter-owned system PATH for provider execution.
- Retain private qualification request and process diagnostics before temporary
  workspace cleanup, including diagnostic references for failed child runs.
- Classify Codex process failures from stderr into typed quota, rate-limit,
  availability, timeout, and authentication outcomes, while requiring standalone
  numeric HTTP status tokens for transient classification across all providers.

### Fixed

- Recover composite publication after journal or final installation interruptions
  while preserving the original review identity and publication bindings.
- Render rerun reports with the recorded source attempt and export staged findings
  with their verified index evidence.
- Resume exact composite publication after interruption before journal creation
  without replacing candidate identity or already persisted support files.
- Reject malformed HTTP status suffixes when classifying provider rate limits.
- Route failed goal evidence to rework even without findings, and send remaining
  validation gaps to final review after the bounded remediation pass.
- Export finding-bearing composite reviews without fabricated excerpt evidence
  and retain their committed creation time in rendered reports.
- Recover composite status after interrupted publication, preserve Git target
  identities on reads, and reject findings without a selected role provider.
- Align composite schema constraints with the supported committed states.
