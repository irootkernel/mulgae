# KAR Runtime Diagnostics Specification

This document defines the planned observable contract. Requirement IDs are stable references for [roadmap.md](./roadmap.md). Until Epic 1 promotes them into the normative product SOT, they remain planning requirements.

## 1. Artifact Identity and Layout

- **DIAG-PATH-001:** Operational diagnostics MUST use `.kar/diagnostics/<session_id>/<run_id>/`.
- **DIAG-PATH-002:** Identity MUST follow `session -> run -> attempt -> invocation`; role and provider names MUST NOT be path identities.
- **DIAG-PATH-003:** A run MUST contain `status.json` and `kar-runtime.jsonl`.
- **DIAG-PATH-004:** Each invocation MUST have its own `status.json`, `stdout.raw`, and `stderr.raw`; safe command/environment metadata MAY be stored separately.
- **DIAG-PATH-005:** Existing P2 artifacts MUST remain under `.kar/<session_id>/<run_id>/` without path migration.
- **DIAG-PATH-006:** Diagnostic paths MUST be safe relative artifact URIs and MUST exist before being projected to users.

```text
.kar/diagnostics/<session_id>/<run_id>/
├── status.json
├── kar-runtime.jsonl
└── attempts/<attempt_id>/
    ├── status.json
    └── invocations/<sequence>-<purpose>/
        ├── command.json
        ├── env.json
        ├── status.json
        ├── stdout.raw
        └── stderr.raw
```

## 2. Runtime Event Contract

- **DIAG-EVENT-001:** `kar-runtime.jsonl` MUST contain one complete JSON object per line using schema `kar-runtime-log.v1`.
- **DIAG-EVENT-002:** Every event MUST contain `schema_version`, UTC RFC3339Nano `time`, `level`, safe `msg`, monotonically increasing run-wide `seq`, monotonic `elapsed_ms`, `component`, `operation`, `event`, `session_id`, and `run_id`.
- **DIAG-EVENT-003:** Applicable events MUST carry validated attempt, invocation, role, provider, cause, failure, mitigation, state, outcome, stream, offset, length, termination, exit-code, and artifact-reference fields.
- **DIAG-EVENT-004:** File paths, Go line numbers, prompts, source content, provider raw content, credentials, and free-form error chains MUST NOT be copied into the runtime JSONL.
- **DIAG-EVENT-005:** One serialized writer or equivalent synchronization MUST assign `seq` and prevent interleaved JSON lines across concurrent lanes.
- **DIAG-EVENT-006:** `run_started`, failure detection, fallback decisions, security stops, and terminal states MUST be durable synchronization points.

Required event families:

- command/run: `command_accepted`, `runtime_diagnostics_opened`, `session_created`, `run_created`, `run_started`, `run_completed`, `run_stopped`, `runtime_diagnostics_closed`;
- qualification/planning: `qualification_started`, `qualification_candidate_checked`, `qualification_succeeded`, `qualification_rejected`, `review_plan_created`, `assignment_resolved`, `run_budget_accepted`;
- scheduling: `lane_scheduled`, `lane_started`, `attempt_created`, `attempt_started`, `attempt_completed`, `attempt_failed`, `lane_completed`, `lane_cancelled`;
- process: `provider_invocation_prepared`, `provider_spawn_revalidated`, `provider_process_started`, `provider_io_observed`, `provider_process_exited`, `provider_process_timed_out`, `provider_process_cancelled`, `provider_process_terminated`;
- parsing/validation: `provider_output_received`, `provider_output_parse_started`, `provider_output_parsed`, `provider_output_parse_failed`, `candidate_validation_started`, `candidate_validation_succeeded`, `candidate_validation_failed`, `repair_scheduled`, `repair_started`, `repair_completed`, `repair_exhausted`;
- fallback/reduction: `fallback_eligible`, `fallback_scheduled`, `fallback_started`, `fallback_completed`, `fallback_prohibited`, `role_completed`, `role_exhausted`, `coordinator_reduction_started`, `coordinator_reduction_completed`;
- publication/cleanup: `publication_preparation_started`, `publication_staged`, `publication_installed`, `publication_committed`, `publication_failed`, `provider_namespace_drain_started`, `provider_namespace_drained`, `workspace_cleanup_started`, `workspace_cleanup_completed`.

## 3. Levels and Raw Streams

- **DIAG-STREAM-001:** Normal lifecycle transitions MUST be `INFO`; mitigated or degraded transitions MUST be `WARN`; terminal failures MUST be `ERROR`.
- **DIAG-STREAM-002:** stdout and stderr MUST be stored separately and MUST NOT be merged with KAR events.
- **DIAG-STREAM-003:** Raw bytes MUST NOT receive timestamps, prefixes, newline normalization, or KAR messages.
- **DIAG-STREAM-004:** `provider_io_observed` MUST record safe stream, offset, and length metadata so raw I/O can be correlated with run events.
- **DIAG-STREAM-005:** Each stream and the runtime log MUST have separately frozen caps. Mandatory lifecycle/error/terminal events MUST retain a reserved tail budget.

## 4. Typed Causes

- **DIAG-CAUSE-001:** Provider and process errors MUST cross application boundaries as typed statuses or causes, not string-contains classification.
- **DIAG-CAUSE-002:** Durable diagnostics MUST distinguish at least `provider_spawn_failed`, `provider_process_wait_failed`, `provider_process_group_cleanup_failed`, `provider_transport_verification_failed`, `provider_output_frame_missing`, `provider_output_envelope_invalid`, `provider_output_decode_failed`, `provider_result_binding_failed`, `provider_observation_invalid`, `provider_observation_mismatch`, `candidate_validation_failed`, `candidate_repair_plan_invalid`, `workspace_revalidation_failed`, and `diagnostic_persistence_failed`.
- **DIAG-CAUSE-003:** Provider-native login, timeout, authentication, quota, and rate-limit signals MUST be normalized at the provider adapter boundary.
- **DIAG-CAUSE-004:** The user-facing result MUST retain closed safe reason codes; detailed local causes MUST NOT expose raw native output.
- **DIAG-CAUSE-005:** Free-form error detail, if retained, MUST be a bounded secure artifact referenced by `detail_uri`, never an inline JSONL value.

## 5. Status and Lifecycle

- **DIAG-STATE-001:** The run sink MUST open after session/run identity allocation and before any provider process spawn.
- **DIAG-STATE-002:** Failure to create or validate the sink MUST fail closed as an artifact failure without spawning a provider.
- **DIAG-STATE-003:** Every terminal path, including login-required, configuration, security, cancellation, internal, and non-P2 provider failure, MUST finalize the sink.
- **DIAG-STATE-004:** `kar-runtime.jsonl` is the chronological source; `status.json` is an atomic current-state projection.
- **DIAG-STATE-005:** Run status MUST identify schema, session/run, state, timestamps, selected roles, lane counts, last sequence, terminal failure, optional P2 reference, `diagnostic_only=true`, and `publication_authority=false`.
- **DIAG-STATE-006:** Attempt/invocation status MUST identify role, provider, primary/fallback selection, purpose, process, parse/validation states, and artifact references.
- **DIAG-STATE-007:** A P2 success MUST link to its diagnostic run without making diagnostics part of P2 authority.

## 6. Security and Durability

- **DIAG-SEC-001:** Diagnostic directories MUST be `0700`; files MUST be `0600`.
- **DIAG-SEC-002:** All writes MUST remain under an approved anchored root with openat/no-follow traversal and symlink/path-escape rejection.
- **DIAG-SEC-003:** Provider/user bytes and free-form details MUST pass the existing bounded scan-before-write boundary.
- **DIAG-SEC-004:** A secret match or scan overflow MUST terminate the producer, zero/drop content, remove temporary files, and persist only safe channel/detector/count/source metadata.
- **DIAG-SEC-005:** A security rejection MUST prohibit repair, fallback, and publication and preserve exit 8 semantics.
- **DIAG-SEC-006:** Atomic replacement, fsync, directory fsync, and crash/partial-line handling MUST preserve a truthful last durable state.

## 7. Namespace, Cleanup, and Export

- **DIAG-OPS-001:** `.kar/diagnostics` MUST be a reserved private namespace and MUST NOT be reported as a malformed publication session.
- **DIAG-OPS-002:** Diagnostics-only failed runs MUST NOT be classified as P2 runs or publication corruption.
- **DIAG-OPS-003:** Successful diagnostics and failed diagnostics-only runs MUST have bounded retention and explicit cleanup behavior.
- **DIAG-OPS-004:** Cleaning a P2 run MUST safely clean its linked diagnostics; cleanup MUST NOT delete unrelated diagnostics.
- **DIAG-OPS-005:** Default export MUST exclude operational diagnostics and raw provider streams.
- **DIAG-OPS-006:** Diagnostics export is out of scope until a separate secure export/redaction contract is approved.

## 8. User-facing Projection

- **DIAG-CLI-001:** Human and JSON failure output MUST expose the same diagnostic URI when session/run identity exists and the diagnostic artifact was installed.
- **DIAG-CLI-002:** A nonexistent or failed-to-install diagnostic path MUST NOT be projected.
- **DIAG-CLI-003:** Login-required output MUST preserve provider attribution and the diagnostic URI without native output.
- **DIAG-CLI-004:** Command output MUST remain a closed safe projection and MUST NOT print provider stdout, stderr, prompts, source bytes, or free-form internal errors.

## 9. Acceptance Criteria

- **DIAG-AC-001:** A primary-only success produces ordered full-flow events, status snapshots, separated raw streams, and a matching P2 reference.
- **DIAG-AC-002:** Primary failure followed by fallback success records cause, eligibility, scheduling, and selected fallback chronology.
- **DIAG-AC-003:** Login-required records attribution and a terminal diagnostic while prohibiting repair, fallback, and P2.
- **DIAG-AC-004:** Non-P2 provider, security, artifact, cancellation, and internal stops leave durable terminal diagnostics.
- **DIAG-AC-005:** Concurrent lanes produce unique increasing sequences and complete JSONL lines under the race detector.
- **DIAG-AC-006:** Symlink, permission, cap, secret, crash, and partial-write tests fail closed without unsafe bytes.
- **DIAG-AC-007:** Cleanup and run selection keep diagnostics and P2 authority separate.
- **DIAG-AC-008:** Actual-provider E2E failure after run identity allocation exposes a preserved diagnostic URI suitable for G010-T05 investigation; E2E PASS is not required by the diagnostics initiative.

