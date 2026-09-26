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
   `run_review`, with `get_run` only on an MCP server proven to serve the
   requested canonical root. When MCP is unavailable or its root is unproven
   or different, run the CLI from the requested root:

   ```bash
   mulgae status --run r_... --output json
   ```

   `run_status_unavailable` means Mulgae allocated the returned identity but no
   durable publication or bounded diagnostic status survived. Report that
   limit; do not infer state or retry the review.

3. Trust the current `publication_status`, `failed_run_recovery`,
   `diagnostic_only`, `publication_authority`, stable reasons, and
   `recovery_action`; do not infer
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
server can recover it. Reconcile an exact returned run ID through the status
query above from the requested root. Without an ID, report the outcome as
unknown. Do not use repeated `list_runs`, status-file checks, or OS process
scans to reconstruct live state.

The registry retains at most 64 identities. Oldest terminal identities may be
discarded to admit a new start, so await of a discarded ID is
`invocation_not_found`. `invocation_limit_reached` is non-retryable and means
64 reviews are still running; do not start another execution path. Identities
are discarded without recovery when the server exits.
`invocation_registry_closed` is non-retryable and means that the
server session is ending rather than that one observer timed out.

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

## Recover a partially failed review

Use this path after terminal status confirms either a committed ordinary review
with `coverage_status: incomplete`, or `failed_run_recovery.available: true`.
Keep the exact root run, session, source hash when present, selected roles,
accepted results, and failed attempt IDs. A recovery source has no review ID
or final publication authority. Do not infer availability from `diagnostic_only`.
Recover every failed selected role, including `required: false` roles such as
maintainability. Do not change `required_roles` to work around a failed result.

1. Inspect the exact root status. For an available failed-run source, use
   `failed_run_recovery.retry_attempts` and preserve `accepted_roles` and
   `manifest_sha256`. For a committed incomplete root, inspect its referenced
   committed artifacts to identify each failed role's exact attempt. Retain
   accepted root roles; composition
   rejects attempts to replace them. A skipped role without a failed attempt
   cannot supply the required rerun lineage; report that concrete limitation.
2. Within existing authorization for recovery, run one exact rerun per failed
   role from the canonical project root and await each command's terminal result.
   In these examples, set shell variables from the exact observed IDs:

   ```bash
   mulgae rerun --run "$root_run_id" --attempt "$failed_attempt_id" --replay exact --output json
   ```

   Rerun is CLI-only. Preserve the assigned provider and immutable target. A
   fresh review of apparently identical source does not establish rerun lineage.
   Do not use `delta`, a new root review, or `--replay recompose` as an automatic
   replacement for this recovery. A failed rerun does not authorize an unlimited
   retry loop; inspect its typed reason and the returned run ID. If that failed
   rerun has an available recovery source, another authorized exact rerun uses
   its own retry attempt. Preserve the chain to the original root and report
   any remaining blocker.
3. Read each exact recovery run after completion. Confirm committed publication,
   its accepted role result, target digest, and lineage back to the failed root
   attempt. Retain transitive same-role rerun lineage when a later rerun recovered
   an earlier failed rerun. A content finding or CI rejection is distinct from
   failure to deliver an accepted role result.
4. Once every missing selected role has an accepted recovery, compose once using
   `compose_review` on an MCP server proven to serve the requested root, with
   `root_run_id` and `recovery_run_ids`, or use the CLI from that root:

   ```bash
   mulgae compose --root-run "$root_run_id" --recovery-run "$recovery_run_id" \
     --recovery-run "$second_recovery_run_id" --output json
   ```

   Supply exactly one recovery run per missing role; omit the second flag when
   only one role failed. Never use `latest`. Composition invokes no provider,
   preserves accepted root results, and creates a separate immutable composite;
   it does not change the root or recovery runs.
5. Read the exact composite status and check publication authority, coverage,
   role coverage, and CI independently. Report the composite ID as the combined
   result. `complete` coverage does not imply CI pass or merge approval, and an
   accepted degraded report retains the existing degraded-role CI behavior.
   Query composite findings normally, but do not request composite excerpts.

On `composite_recovery_incomplete`, identify the unrecovered role or incomplete
recovery instead of repeating the same mapping. On `composite_role_not_required`,
check whether the role was selected in the root and check the installed version.
On target, lineage, or integrity rejection, stop and report the mismatch; do not
edit private artifacts or substitute unrelated successful runs. For uncertain
publication, follow the exact-ID reconciliation rules below before any retry.

**v0.1.19 compatibility:** this release only admitted required-role recoveries.
An optional-only failure could return `composite_role_already_satisfied`; a mixed
failure could reject its optional recovery with `composite_role_not_required`.
It could also omit failed optional roles when composing required-role recoveries.
These outcomes do not prove that all selected roles were reviewed. The corrected
behavior is in the v0.1.20 source cycle; do not assume it is installed or authorize
an upgrade automatically. Preserve exact run IDs and report the version blocker.
Existing v1 artifacts remain readable, but new compose requests must recover all
selected roles, including a repeated old mapping that previously omitted one.

A v0.1.19 diagnostic-only failure has no retained recovery manifest and cannot
be recovered retrospectively. The new source is available only after normal
failure handling completes provider drain and workspace cleanup. Forced process
termination and power loss have no recovery guarantee. A present corrupt source
fails closed; never edit it or promote diagnostic reports into accepted results.

Inspection example for an MCP server proven to serve the requested root
(replace the ID with the exact returned value):

```json
{"name":"get_run","arguments":{"run_id":"r_..."}}
```

Read `data.failed_run_recovery`; rerun remains CLI-only. Once every missing role
is recovered, call the existing `compose_review` tool with the exact root and
committed recovery run IDs. The MCP v1 envelope and CLI v11 envelope carry their
own documented data shapes; do not infer one from the other's version.

## Recover the smallest supported unit

- For `composite_publication_incomplete` or `status_required`, preserve the
  deterministic run ID and inspect it with exact `status` or MCP `get_run`.
  Repeat the same exact root and recovery mapping only after the read reports
  that nothing committed; never treat reason-level `retryable` as the
mutation-level retry decision.
- Composition admission failures use artifact exit `7` with their stable
  composite reason code because the exact caller mapping is validated against
  committed run artifacts; they are not generic CLI syntax failures.
- For `failed_run_recovery.available: true`, use the exact retry attempts above;
  successful roles remain retained even though no final review was published.
- For unavailable recovery, read `unavailable_reason` and existing typed terminal
  reasons. `source_not_retained` does not authorize reconstruction from logs or
  a blind rerun. Diagnostic-only runs have no final or report URIs and cannot
  serve findings queries. A new review requires existing or new user authority.
  `publication_in_progress` requires publication reconciliation;
  `published_review` means use the committed review's coverage and attempts.
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
- For `selector_resolution_failed`, preserve the v11 envelope request ID and
  bounded reason, stop mutations, and report the failure. Do not treat the
  generic internal exit as evidence that doctor will find a problem.
- For selector resolution that returns `request_cancelled`, retain exit `9`
  and retry only when authorized. Typed artifact and security failures retain
  exits `7` and `8`; follow their bounded reason instead of treating them as
  internal failures.
- For a stale child-run source, re-read the source run. Do not bypass immutable
  target or lineage checks.
- For configuration or readiness failures, use current effective config,
  `mulgae doctor --output json`, and
  `mulgae providers --include-unverified --output json`; fix only the reported
  prerequisite with explicit authorization. Do not use this path for
  `provider_rate_limited` or for a CLI `provider_qualification_failed` whose
  listed reasons are all `rate_limit`.
- For `mulgae-doctor-result.v5`, diagnose `binary_available` and
  `cli_compatible` reason codes per configured provider. Do not treat absent
  static evidence, a field unobserved in an older schema, heartbeat state, or
  prior review evidence as an offline failure.
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

When CLI `mulgae review` returns `review_preparation_failed` with exit `10`,
inspect the exact diagnostic-only run using the returned
`mulgae status --run <id> --output json` command. For MCP `run_review` or
`await_review`, preserve the returned session and run identities and inspect
that run with `get_run`. Record the closed `review.prepare.<stage>` and terminal
cause when reporting the failure. Do not run `mulgae doctor`: it verifies
offline readiness and cannot diagnose this internal preparation invariant. Do
not blindly repeat the review mutation; a replacement review requires explicit
operator authority.

When MCP `run_review` or terminal `await_review` returns
`provider_rate_limited` as an error, every qualification failure recorded for
the selected roles was a provider rate limit, and no higher failure class took
precedence. Inspect the exact returned run once. Qualification ended before
provider execution, so the diagnostic-only run has no accepted role, failed
attempt, or exact rerun source. Do not use doctor or heartbeat to test the
limit, call `mulgae rerun`, immediately start a replacement review, or
substitute another provider. Report that a new review may be needed after the
rate limit clears and requires user authority. Public `retryable: false`
protects the non-idempotent review mutation from blind repetition; it does not
classify the provider condition as permanent.

In a CLI command-result envelope, `provider_rate_limited` instead identifies an
attributed provider-execution failure. Preserve its exact role and provider,
then reconcile the returned run before choosing partial-failure recovery.

When CLI `provider_qualification_failed` lists only `rate_limit` reasons, apply
the same no-probe and new-review guidance as the MCP qualification failure.
Its `retryable: true` value describes provider readiness; it does not authorize
an immediate repeat of the review command.

A rate limit observed during provider execution rather than qualification
completes `run_review` or terminal `await_review` with `outcome: success`,
`terminal_exit_code: 4`, and a `rate_limit` reason. This is a committed
incomplete review, not a successful review verdict. Inspect the exact run once,
then recover only its failed roles through the partial-failure flow above.

Mulgae itself may consume the second invocation slot for exactly one
same-provider retry after `provider_unavailable` or `provider_turn_failed`.
Inspect the run before requesting any further rerun. That automatic retry keeps
the role, provider, attempt, and immutable target fixed, records separate runtime
evidence, and prevents a later repair invocation. Other provider failure classes
are not automatically retried.

Runtime log v4 may report `provider_output_fields_discarded` with only bounded,
sorted JSON Pointer paths and `discarded_path_count`; it never exposes removed
values. This is successful provider-content normalization, not a security-policy
failure. Malformed JSON, duplicate keys, invalid evidence, and semantic
contradictions remain terminal according to their typed reason.

`provider_failure`, `timeout`, `authentication_failure`,
`malformed_response`, and `execution_failure` from heartbeat describe only that
explicit synthetic live request. Do not promote them into setup readiness or
review qualification and do not retry heartbeat without new user intent.
