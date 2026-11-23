# Changelog

This file records concise shipped outcomes and the planned next stable release.

## v0.1.28 - Unreleased

### Changed

- Require pinned Go/Python toolchains for development and VM qualification,
  migrate VM requests to v2, and automatically format Go files before verification.
- Migrate Grok (`1.0.89`+) review, structured extraction, qualification, and heartbeat from legacy ACP to a reusable isolated `herdr-core` terminal runtime (`PaneTTY`, disposable `HOME`/`GROK_HOME` with minimal `requirements.toml`, purpose-scoped tools with the five-control `B-1` Seatbelt Bash gate on index/commit scopes only, read-only staged prompts with completion nonces, post-`ESRCH` staged output validation published under `result_transport: "stdout"`, graph-owned `herdr-core` lifecycle teardown, shared control-plane boundary denials across all providers, and offline doctor `herdr-core` readiness checks) without starting `herdr-core` for ZCode, Codex, AGY, or Grok `--version`.
- Converge the active provider inventory to two families (`zcode`, `grok`), reject Config v5 `providers.cursor`, `providers.codex`, and `providers.agy` and their role assignments fail-closed with `config_provider_retired`, fail public reads/exports of historical and live retired-provider artifacts (`kimi`, `cursor`, `codex`, `agy`) with `retired_provider_artifact` (while keeping `mulgae clean` operational), remove Codex-only credential profile fields (`default_credential_profile`, `credential_homes`, `roles.*.credential_profile`, and `heartbeat --credential-profile`), and publish `mulgae-command-result.v25`, `mulgae-doctor-result.v9`, `mulgae-provider-heartbeat-result.v6`, and `mulgae-review-preflight.v13` while preserving frozen historical schema/example pairs.
- Strengthen live-source evidence drift handling in both requirements and non-requirements review modes so real drift on admitted paths, root/index revalidation, `git cat-file`, and post-open TOCTOU reopens fails closed (capturing security-rejected markers on `live_source_unsafe`), while separating untrusted provider citation faults (absent non-admitted paths, invalid/excluded paths, and non-regular non-admitted workspace paths on initial open) into bounded failures (`invalid_assessment` or `unrepairable_evidence_claim`).
- Propagate originating security `RuntimeDiagnosticCause` values (`provider_ownership_violation`, `live_source_unsafe`, `provider_packet_security_rejected`, `diagnostic_security_rejected`, `workspace_revalidation_failed`, `provider_output_staging_violation`, and `provider_process_group_cleanup_failed`) through coordinator diagnostic events and attempt status without altering public `security_violation` reason codes.
- Omit repository-wide `reads` from `002-extract` prompts via compact `review:live-extract-target` v1 metadata (while keeping the full admitted read set on `001-initial` and `repair`) and align `extract-provider-review.v1.txt`, `requirements.v1.txt`, and `reviewer-guide.v1.txt` so initial reports include exact verbatim target excerpts and structured extraction operates as pure transcription without re-reading source or fabricating `findings: []` (plain-text refusal in non-requirements mode; omitted top-level `findings` key in `--requirements` mode retaining verified requirements and keeping `reports_only`).
- Compact `001-initial` and `repair` read plans losslessly in `review:live-read-plan` v2 (HTML escaping disabled, no byte or item ceiling) by keeping changed candidate reads and non-allowlisted or template-mismatch paths verbatim in `reads` while grouping remaining positive-allowlist supporting and whole-tree paths into side-scoped `supporting_reads` templates (`native_path_template` / `git_command_template`), leaving in-memory `execution.Reads()` and `review:live-extract-target` v1 unchanged; align `common.v1.txt`, the AGY isolated agent policy (`git_command` and guarded `supporting_reads` expansion), and `make test-agy` (adding the seventh `templated` native command control).
- Isolate ordinary per-item requirements validation and pure bounded provider citation faults to the offending `requirement_id` (`invalid_assessment`) while preserving valid sibling requirements, keeping whole-section rejection for duplicate/foreign/wrong-owner/non-object rows, running `ReviewValidator.Validate` unconditionally on omitted-`findings` responses with `nil` candidate fallback, applying Option A `assessmentPending` scheduling and monotone `initial -> extract` merging with deterministic input-order `NormalizedRequirementsOutput`, and keeping findings extraction strictly all-or-nothing.
- Share one qualification probe across equivalent same-profile ZCode role routes using adapter-owned `DeriveEquivalentRouteDirectExecutionAuthority` (binding ZCode app-bundle version/metadata and model/effort equivalence, keeping AGY strictly per-instance, and projecting rejected or mismatched `provider/updateAccountConfig` alongside unavailable model/thought selections as typed configuration failures with zero publication authority), and narrow ZCode `toolAllowlist` to `["Read","Bash"]` on Git-backed scopes (`stage`, `head`, `commit`, `diff`) while aligning `reviewer-guide.v1.txt` to direct Git-scope inspection through the read plan's `git --no-pager show` commands.
- Bump the qualification readiness probe fixture to `current-qualification-fixture-v4`, preserving line 1 verbatim and adding neutral synthetic-test-identifier framing before `root`/`link`/`role` while retaining exact `{"root","link","role"}` JSON and nonce/link verification with four-provider (`zcode`, `grok`, `codex`, `agy`) and `mulgae heartbeat` test coverage.
- Replace the review coordinator's full-wave barrier between initial and follow-up invocations with a single-goroutine batched FIFO event loop that retains the initial shared start gate after `PrepareInitial`, drains ready completions into canonical-role-order commit batches, admits per-role follow-ups (`002-extract`, `retry`, `repair`) immediately in FIFO order while slower peers remain in `001-initial`, enforces run-wide invocation ceilings and global ordinal tracking, and drains all in-flight invocations before stop/deadline commits and worker shutdown while preserving deterministic `RoleSummaries`, `Findings`, `Evidence`, `Outcomes`, `RunState`, and per-role trace projections.

### Removed

- Remove Cursor (`cursor`), Codex (`codex`), and AGY (`agy`) review provider support across runtime adapters, qualification, discovery, `init` (`--cursor-executable`, `--codex-*`, `--agy-*`, and `--providers cursor|codex|agy`), `heartbeat`, `doctor`, `providers`, VM qualification inputs, documentation, and live gates (`make test-cursor`, `make test-agy`, `make test-e2e-opt-in`), while retaining Codex as an external MCP client (`make test-mcp-clients`, `make test-mcp-requirements-clients`) and retaining defense-in-depth `~/.cursor`/`~/.config/cursor`/`~/.codex`/`~/.gemini` credential-root denials, `.cursor`/`.cursorrules` content detection, Grok `[compat.cursor]` lockdown, and `cursor_auth_token` secret-key refusal.

### Fixed

- Restore ZCode 3.18.2 reviews for accounts protected by macOS Keychain.
- Accept optional Grok CLI release-channel version tags (such as `[stable]` or `[beta]`) and register the synthetic `grok-logic` namespace so `mulgae heartbeat --provider grok` works even when no review role uses Grok.
- Restore timeout publication consistency so provider timeouts project `AttemptTimedOut` paired with `FailureTimeout` (preserving partial-timeout publication of peer reports and requirements), enclosing run deadlines during optional extraction complete the role as `AttemptSucceeded` with its accepted report intact and project `RunCompleted` when all roles succeeded, and never-started roles cancel cleanly instead of failing with illegal state transitions.
- Enforce exact-match closed Mulgae-owned key sets with a complete tree pre-pass and deterministic protected-key precedence across all five requirements wire objects (`requirements`, `assessment`, `evidence`, `current`, `visual`), keeping ordinary unknown keys bounded as `invalid_assessment` and allowing `visual.sha256`.
- Emit complete single-pass parse/validation diagnostics, invocation status states, raw stdout/stderr capture, and `pendingExtraction`/`pending` cleanup across initial, repair, extraction, fallback, and security-rejected paths in requirements mode without double-capturing streams or overflowing bounded `candidate.*.json` members (omitting `candidate.*.json` when the findings projection exceeds 8 MiB while keeping full unbounded output in `stdout.raw`).

## v0.1.27 - 2026-11-10

### Changed

- Add sealed Haepari guest qualification preparation, installed CLI/MCP and native controller checks, and manual cleanup gates, with explicit incomplete outcomes for unobserved scenarios.
- Update the complete `use-mulgae` skill for native review coordination and recovery while preserving existing Config v5 provider/role policy, machine paths and retained review/requirements history across upgrades.
- Coordinate live CLI and MCP reviews through one owned Haepari advisory grant before provider qualification, or validate and monitor an inherited `HAEPARI_LOCK_GRANT` read-only without mutating parent lock state. No-change review and preflight remain controller-free.
- Retain unknown local drain proof across owned v2 and borrowed v3 intent records during cleanup, preserve accepted role reports and published incomplete results on operational partial-role failure without cross-run coverage, and preserve verified published results when final grant disposition fails, with bounded coordination diagnostics in existing status and error envelopes.

### Fixed

- Accept Grok's early zero-tool initialization only after binding it to the authenticated session, while rejecting active MCP tools and mismatched identities.
- Accept AGY's canonical file-read events through the existing workspace read authority while retaining credential boundaries and tool-identity checks.
- Preserve cancellation after Haepari acquisition by recording the native reply under a bounded context before cancelling the original request, while retaining genuine storage failures.
- Preserve the requirements output contract through structured extraction and reformat repair, so supported assessments in accepted role reports can reach native results without conflicting finding-only JSON instructions.

## v0.1.26 - 2026-10-31

### Added

- Assess optional local requirements through selected owner roles in Git-backed reviews, with provider-free admission and execution preflight plus verified CLI/MCP pages, content reads and reports retaining every verdict, rationale, evidence and limitation, including explicit unverified no-change results.
- Review text roles with AGY over stream-JSON using one default Gemini account, preferring AGY for new documentation assignments when available while preserving configured routes and providing single-account live verification with `make test-agy`.
- Select Cursor explicitly for text roles through init, CLI and MCP with matching schemas, help and contracts, without adding Cursor to default role preferences or the default live gate.

### Changed

- Admit Grok, Cursor and AGY native file reads by path without reading file bodies, allowing reads of invalid image content while retaining `unsupported_content` when evidence cites it.
- Qualify distinct provider families concurrently outside `max_active_lanes`, keeping same-family probes sequential, waiting for all started families before selecting the highest-precedence failure, and converting qualification panics to typed internal failures.
- Publish command-result v23, preflight v11, review-artifact v4, run-manifest v4 and support-index v4 contracts with requirements-assessment support while retaining historical readers.
- Provide `make test-offline` for deterministic development verification and move vulnerability scanning outside the standard test gate to the separate `go tool govulncheck ./...` command.

### Fixed

- Restore Grok review and extraction compatibility while retaining native security policy, rejecting drift in the affected invocation and preserving quota failure signals.
- Restore AGY workspace and Git reviews with supported newer CLI versions while preserving exact native read permissions.
- Read live role reports larger than the structured artifact limit.
- Report simultaneous provider read-plan violations in a deterministic order.
- Report native-home replacement as a security failure in doctor and providers, and restore offline Cursor version checks.
- Preserve independent failures when CLI status encounters a missing publication or diagnostic record, instead of reporting success or suppressing the diagnostic failure.
- Prevent inherited file descriptors from reaching provider processes, and let protocol sessions close stdin while draining the final output.
- Bind exact-evidence repair to original provider response coordinates after finding and evidence sorting, and protect existing index-side values from fill-missing-fields repair.
- Allocate publication epochs beyond 4,096 retained epoch files while preserving bounded reads and validation of every retained member.
- Read historical artist-enabled runtime targets with verified support paths, kinds, index membership and content digests.
- Preserve Cursor session diagnostics for native identifiers outside the diagnostic grammar, and report ZCode and Grok result transport as `stdout`.
- Disable all built-in tools in tool-free ZCode qualification and extraction sessions so capability probes cannot stall on interactive plan approval.

## v0.1.25 - 2026-10-12

### Changed

- Review original workspace, index and Git sources through CLI/MCP with neutral read-only execution and independent project binding,
  requiring manual Config v5 migration and retiring capture-bound selectors and child/replay/compose execution while preserving historical reads, exports and publication reconciliation.
- Stop applying `.mulgaeignore` exclusions. Reassess previously excluded files before
  review: Git ignore rules do not exclude tracked files or restrict provider reads.

### Fixed

- Terminate detached provider descendants before completing namespace cleanup,
  even after the direct process and protocol streams have ended.
- Preserve live review runs with missing or corrupted indexed support during
  cleanup, hashing large retained content without a byte ceiling.
- Allow committed Git targets during unrelated index conflicts and preserve
  `conflicted_index` for stage admission.
- Preserve structured ZCode findings by excluding intermediate tool-call narration
  from extraction responses while retaining complete role reports.
- Preserve typed live-source admission reasons in MCP errors and document whole-selection rejection of source symlinks.
- Reject executable-bearing and unsupported local Git settings before live provider execution, and disable provider Git transport protocols.
- Preserve provider qualification lifecycle events and safe candidate outcomes in live review diagnostics, and stop execution when those records cannot be saved.
- Reject Grok live reports when a completed native tool operation falls outside the read plan or its correlated input or completion is missing.
- Honor escaped interior separators in non-Git workspace `.gitignore` rules so candidate selection matches Git.
- Report verified Git checkouts without a first commit correctly in doctor.
- Escape terminal controls in human CLI output and reject bare GitHub, Slack and secret-key tokens before redacted export packaging.

## v0.1.24 - 2026-09-29

### Added

- Retain composite source findings, receipts, indexed evidence and per-role capture support for verified reads after permitted source cleanup, with command-result v18 and preflight v7.

- Add lossless read-only CLI/MCP report and indexed-evidence access with receipt-bound continuation, original role reports, and command-result v17.

- Add coherent CLI/MCP inspection, receipt-bound finding pages and complete finding-detail chunks, with verified capture availability and command-result v16.
- Bind review execution to preflight with paired project/request guards, retain complete capture evidence for new publications including no-change reviews, and expose preflight v6 and command-result v15.
- Add read-only CLI `context` and MCP `get_context` for independent local worktree identity comparison, reject changed server roots, and emit command-result v14 while retaining earlier schemas.

### Changed

- Use native project/request guards and receipt-bound result reads in the distributed `use-mulgae` skill, README and help, with explicit legacy and client-capability fallbacks.
- Require Go 1.27.1 or newer and update Mulgae's direct dependencies and pinned development checks for Go 1.27.
- Use ZCode's v2 desktop Individual Coding Plan state instead of legacy CLI config, add optional project model and
  reasoning settings, and publish command-result v13.

### Fixed

- Require `use-mulgae` to verify an attached MCP server's project root before provider execution and use the native CLI when that binding is unproven.

## v0.1.23 - 2026-09-22

### Changed

- Require Grok CLI 1.0.34 or newer and bind configured model and reasoning effort to ACP sessions and qualification identity, failing before prompting when Grok rejects or normalizes the requested policy.
- Add Git-shareable Grok model and reasoning-effort policy, default new Grok configurations to `grok-4.7` with `high` effort, expose init flags and provenance, propagate the policy through every invocation path, and publish command-result v12 while retaining v11 for backward reads.

### Fixed

- Preserve complete provider stdout and stderr larger than 8 MiB as variable-sized publication support instead of rejecting an otherwise valid review.
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
