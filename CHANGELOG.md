# Changelog

This file records concise shipped outcomes and the planned next stable release.

## v0.1.23 - Unreleased

### Fixed

- Tolerate additive ZCode telemetry notifications with provider-owned payload shapes during app-server reviews.
- Distinguish malformed recognized ZCode protocol events with the public `provider_protocol_event_decode_failed` reason.

## v0.1.22 - 2026-09-19

### Added

- Add Grok as an explicitly selected text-role provider with ACP v1 isolation, staged review output, typed capability
  failures, and an exact-binary live review target while rejecting artist assignments before provider execution.
- Add typed retirement for configuration and direct or
  transitive artifact references to removed provider families.

### Changed

- Move explicitly selected Codex reviews, extraction, and qualification to the app-server protocol with ephemeral threads,
  keeping read-only isolation and `stdout` role-report compatibility. Require Codex 0.154.0 for the provider route.
- Keep sequential `start_review` admission in one attached MCP process by discarding oldest
  terminal identities, and emit `invocation_limit_reached` only when 64 reviews are still running.
- Set the supported provider order to ZCode, Grok, and Codex. Automatic init requires an authenticated Grok CLI 1.0.30
  or newer, configures ZCode and Grok, and assigns every default role to ZCode.
- Require one reports-only ZCode/Grok two-role review and independent capability certification in `make test`;
  keep deeper workflows deterministic and the two-profile Codex live scenario behind `MULGAE_E2E_OPT_IN=1`.
- Publish command-result v11, doctor-result v5, provider-contract-evidence
  v4, provider-heartbeat-result v3, and review-preflight v5.
- Make the ZCode app bundle the sole machine-local launch authority, derive its Electron runtime and app-server launcher, and remove
  external Node.js and launcher-path configuration.
- Publish Config v4 as a clean break: for a v3 ZCode setup, set both version fields to `4`, replace `node_executable` and `launcher` with `app_bundle`,
  then run `init --refresh-local` after the shared policy is valid; a v3 setup that uses Kimi or AGY must remove or reassign those providers, or deliberately reinitialize with the supported ZCode/Grok policy.
- Enforce ZCode app 3.12.3 as an independent minimum, retain higher app releases as eligible but newer than verified,
  and bind descriptor-observed `Info.plist` version identity through qualification and every provider spawn.
- Certify ZCode app 3.12.3 for provider import, explicit `--stdio`, model selection, and reasoning-level
  fallback while retaining the bundled launcher's 0.16.5 protocol version as qualification guidance.

### Fixed

- Bind synthetic heartbeat qualification to the admitted configuration locality so provider readiness reaches the configured runtime.
- Release private protocol transcript spools after qualification and provider execution, including failed conversations.
- Report machine fields for unconfigured ZCode and Grok providers as absent in configuration provenance.
- Allow review preflight to validate named Codex credential-profile instances while preserving the legacy singleton instance and rejecting
  malformed profiles, role mismatches, and profile-bearing non-Codex routes.
- Keep Grok provider evidence satisfiable, restrict current preflight permission modes to the supported
  runtime value, and register deterministic release evidence for internal review-preparation failures.
- Keep source-distributed agent guidance on doctor-result v5 and document
  the GitHub Release publication boundary in the manual release procedure.
- Keep retired-provider doctor results schema-valid, report unsupported init role assignments as
  typed capability failures, and stop the standalone Grok target when capability certification fails.
- Preserve ZCode legacy API-key provider and model selection by linking built-in provider templates, applying last-wins import behavior to unselected
  provider ID collisions, rejecting missing or ambiguous selected entries, and applying the admitted model before any review prompt is sent.
- Preserve model-selection configuration failures through qualification and runtime observation, and match
  ZCode's exact-key legacy config decoding while rejecting unsupported provider kinds and npm-backed providers.
- Require exact certified `session/setModel` success payloads, keep authentication, rate-limit, timeout, and internal errors out of
  configuration classification, and let coherent cancellation or deadlines outrank a concurrent protocol error while retaining session evidence.
- Match ECMAScript object-key enumeration when importing numeric legacy ZCode providers, preserve the v1 Grok/Codex
  profile generation, and make release fixture cleanup operate only on validated directories created by the gate.
- Classify failures between accepted review planning and the coordinator's durably recorded run start as internal preparation failures, changing the CLI result from readiness exit `4` with
  `provider_unavailable` to exit `10` with `review_preparation_failed`; retain their closed diagnostic stage and direct operators to the exact diagnostic run instead of `mulgae doctor`.

### Removed

- Remove the Kimi and AGY runtime, configuration, discovery,
  credential, transport, help, and release-test paths.

## v0.1.21 - 2026-09-12

### Added

- Add bounded ZCode protocol correlation diagnostics with private raw session
  and turn identifiers and safe fingerprints in public run status.
- Add the `mulgae-command-result.v8` envelope while retaining v5, v6, and v7
  for explicit backward reads.

### Changed

- Make ZCode the sole automatic-init provider and the first preference for every
  role while retaining explicit AGY, Kimi, and Codex selection.
- Update runtime diagnostics to `mulgae-runtime-log.v4`,
  `mulgae-runtime-run-status.v3`, and
  `mulgae-runtime-invocation-status.v2`, while retaining run-status v2 reads.
- Expose `provider_rate_limited` for attributed CLI provider failures and for
  MCP qualification failures only when every selected-role failure is a rate
  limit and no higher failure class takes precedence.

### Fixed

- Preserve typed ZCode protocol failures when bounded SIGTERM teardown ends the
  app server, and retain process and protocol evidence if provider observation
  assembly fails.
- Keep model-authored review stdout out of native failure classification while
  retaining stdout authority for provider qualification failures.
- Classify ZCode quota failures ahead of generic turn failures. Verified native
  stderr rate-limit markers also take precedence over that generic fallback;
  Mulgae does not retry them, cancel peer roles, or mark the provider unusable.

## v0.1.20 - 2026-09-10

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
