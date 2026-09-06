# Mulgae recovery

Load this reference when current state may be stale, a mutation's outcome is
unknown, a run is diagnostic-only or incompletely published, or a provider
failed.

## Reconcile authoritative state

If a known lifecycle invocation is still pending, preserve its `i_...` identity
and await it in the same live MCP session before applying the terminal run
inspection below. A host timeout or retryable `await_cancelled` ends only the
observer; it does not cancel execution or authorize another start. Re-await that
same invocation. If awaiting cannot continue, report the concrete limitation
without switching to another execution or polling run status. `get_run` is not
a live invocation snapshot, and start need not return a durable run ID.

1. Stop issuing mutations. Preserve the complete command envelope, exit code,
   and any exact session, run, and attempt IDs already returned.
2. Re-read the exact run, including an identity returned on a failed MCP
   `run_review`, with MCP `get_run`. When MCP is unavailable, use:

   ```bash
   mulgae status --run r_... --output json
   ```

   `run_status_unavailable` means Mulgae allocated the returned identity but no
   durable publication or bounded diagnostic status survived. Report that
   limit; do not infer state or retry the review.

3. Trust the current `publication_status`, `diagnostic_only`,
   `publication_authority`, stable reasons, and `recovery_action`; do not infer
   completion from provider output, conversation memory, runtime logs, or the
   mere presence of files.
4. If no exact run ID was returned, report the outcome as unknown. Mulgae has no
   read-only command that safely reconstructs an unknown ID from conversation
   context. Do not guess an ID or start another run to probe state. The
   `latest` selector on `followup`, `delta`, `rerun`, and `export` resolves
   the newest committed run, but each of those commands mutates or writes;
   `latest` is never a read-only probe.

Never retry an uncertain `start_review`: a second start creates another review.
Invocation state is process-local and is lost when that server exits. On
disconnect, `invocation_not_found`, or `invocation_registry_closed`, stop
automated waiting. Do not guess an invocation identity or claim that a new
server can recover it. Reconcile an exact returned run ID through `get_run` when
one is available; without one, report the outcome as unknown. Do not use repeated
`list_runs`, status-file checks, or OS process scans to reconstruct live state.

The registry retains at most 64 cumulative invocation identities so terminal
results remain repeatable. `invocation_limit_reached` is non-retryable in that
server session. Reconcile every exact returned run ID, then restart the attached
MCP server before starting another review; the restart discards every preserved
invocation identity. `invocation_registry_closed` is likewise non-retryable and
means that the server session is ending rather than that one observer timed out.

## Respect idempotency boundaries

Read-only `version`, `doctor`, `config`, `providers`, `roles`, `status`,
`findings`, and review `--preflight` calls may be repeated. `clean --dry-run` is
also read-only. Repeatability does not make run queries a live polling interface.

`init`, `review`, `followup`, `delta`, `rerun`, `report`/`export` writes (each
requires `--run` and `--output-path`), and clean apply mutate durable or
external state and have no caller-supplied idempotency key. Re-observe their
documented postcondition before any retry. A second review-like command is a new
run, not a retry of the same mutation. `compose` is different: its exact root
and recovery mapping is its idempotency key, but `status_required` still requires
an exact status read before that mapping may be repeated.

## Recover the smallest supported unit

- For `composite_publication_incomplete` or `status_required`, preserve the
  deterministic run ID and inspect it with exact `status` or MCP `get_run`.
  Repeat the same exact root and recovery mapping only after the read reports
  that nothing committed; never treat reason-level `retryable` as the
mutation-level retry decision.
- Composition admission failures use artifact exit `7` with their stable
  composite reason code because the exact caller mapping is validated against
  committed run artifacts; they are not generic CLI syntax failures.
- For `diagnostic_only: true`, no publication authority exists, artifact and
  report URIs are absent, and findings cannot be queried. Follow
  `recovery_action: rerun_review` only after the user
  authorizes a new review; retain the failed run as diagnostic evidence.
- For a committed run with one failed role, prefer the source run and exact
  attempt IDs. When selecting by role and provider, use the persisted
  `provider_instance` exactly; never substitute a provider family or another
  provider automatically.
- For `project_root_mismatch`, confirm the canonical Git worktree root. If that
  root is uninitialized, obtain explicit initialization authority before
  running `mulgae init`; do not initialize or create nested `.mulgae` state in
  a subdirectory.
- For `run_selector_unavailable`, verify the source run from the project root.
  For `attempt_selector_unavailable`, prefer the exact attempt ID or re-read the
  run to obtain the persisted provider instance. Neither failure establishes a
  configuration problem.
- For `selector_resolution_failed`, preserve the v6 envelope request ID and
  bounded reason, stop mutations, and report the failure. Do not treat the
  generic internal exit as evidence that doctor will find a problem.
- For selector resolution that returns `request_cancelled`, retain exit `9`
  and retry only when authorized. Typed artifact and security failures retain
  exits `7` and `8`; follow their bounded reason instead of treating them as
  internal failures.
- For a stale child-run source, re-read the source run. Do not bypass immutable
  target or lineage checks.
- For configuration or readiness failure, use current effective config,
  `mulgae doctor --output json`, and
  `mulgae providers --include-unverified --output json`; fix only the reported
  prerequisite with explicit authorization.
- For doctor v2, diagnose `binary_available` and `cli_compatible` reason codes
  per configured provider. Do not treat absent static evidence, an unobserved
  field from an older schema, heartbeat state, or prior review evidence as an
  offline failure.
- If shared `.mulgae/config.yaml` exists but `.mulgae/local.yaml` is missing,
  bootstrap it with authorized `mulgae init`. If local provider paths are stale
  or no longer match the shared provider set, use authorized
  `mulgae init --refresh-local`; never rewrite the shared policy as recovery.
- For `project_committed_local_missing`, preserve the committed shared policy.
  If an unadmitted `local.yaml` pathname caused a collision, move that exact
  file aside only with explicit authorization; then retry plain `mulgae init`
  to create the matching local authority.
- For cleanup uncertainty, repeat the dry-run. Never resume a private tombstone
  or delete protected paths manually.
- For publication statuses that expose a recovery action, report that action.
  Do not edit journals, manifests, attempts, validation records, diagnostics,
  or final reviews; supported recovery is owned by Mulgae's publication path.

## Service and process failures

Mulgae has no daemon, service, or durable job controller. A foreground process
ending does not prove that publication committed. Reconcile with exact status.
Provider authentication, quota, rate-limit, timeout, and permission failures
are typed provider outcomes; preserve the assigned provider and apply only the
smallest documented remediation. Never weaken sandbox, locality, evidence,
validation, integrity, or publication fences to make recovery pass.

Mulgae itself may consume the second invocation slot for exactly one
same-provider retry after `provider_unavailable` or `provider_turn_failed`.
Inspect the run before requesting any further rerun. That automatic retry keeps
the role, provider, attempt, and immutable target fixed, records separate runtime
evidence, and prevents a later repair invocation. Other provider failure classes
are not automatically retried.

Runtime log v3 may report `provider_output_fields_discarded` with only bounded,
sorted JSON Pointer paths and `discarded_path_count`; it never exposes removed
values. This is successful provider-content normalization, not a security-policy
failure. Malformed JSON, duplicate keys, invalid evidence, and semantic
contradictions remain terminal according to their typed reason.

`provider_failure`, `timeout`, `authentication_failure`,
`malformed_response`, and `execution_failure` from heartbeat describe only that
explicit synthetic live request. Do not promote them into setup readiness or
review qualification and do not retry heartbeat without new user intent.
