# Changelog

This file records concise shipped outcomes and the planned next stable release.

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

- Accept AGY native JSON response envelopes while preserving exact response
  bytes, and use an adapter-owned system PATH for provider execution.
- Retain private qualification request and process diagnostics before temporary
  workspace cleanup, including diagnostic references for failed child runs.
- Classify Codex process failures from stderr into typed quota, rate-limit,
  availability, timeout, and authentication outcomes, while requiring standalone
  numeric HTTP status tokens for transient classification across all providers.

### Fixed

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
