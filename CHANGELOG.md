# Changelog

This file records concise shipped outcomes and the planned next stable release.

## v0.1.20 - Unreleased

### Added

- Retain verified failed-run recovery inputs after successful cleanup, so exact
  role reruns and composition can recover an unpublished review.
- Expose recovery availability, accepted roles, and retry attempts in CLI status
  v7 and MCP `get_run`; preserve recovery lineage across failed reruns.
- Add versioned recovery and v2 lineage/composite contracts while retaining v1
  reads and existing valid composition identities.

### Fixed

- Recover failed selected roles through composition even when they are not
  configured as required, and reject mappings that omit any failed selected role.
- Guide agents from partial review failure through exact role reruns and composite
  result verification in `use-mulgae`.

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
