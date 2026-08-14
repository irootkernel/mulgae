# Mulgae recovery

Load this reference when current state may be stale, a mutation's outcome is
unknown, a run is diagnostic-only or incompletely published, or a provider
failed.

## Reconcile authoritative state

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

## Respect idempotency boundaries

Read-only `version`, `doctor`, `config`, `providers`, `roles`, `status`,
`findings`, and review `--preflight` calls may be repeated. `clean --dry-run` is
also read-only.

`init`, `review`, `followup`, `delta`, `rerun`, `report`/`export` writes (each
requires `--run` and `--output-path`), and clean apply mutate durable or
external state and have no caller-supplied idempotency key. Re-observe their documented postcondition before any retry. A second
review-like command is a new run, not a retry of the same mutation.

## Recover the smallest supported unit

- For `diagnostic_only: true`, no publication authority exists, artifact and
  report URIs are absent, and findings cannot be queried. Follow
  `recovery_action: rerun_review` only after the user
  authorizes a new review; retain the failed run as diagnostic evidence.
- For a committed run with one failed role, use the rerun command printed in
  the report, substituting its `<family>` placeholder, or the source run and
  attempt IDs. Do not substitute a provider automatically.
- For a stale child-run source, re-read the source run. Do not bypass immutable
  target or lineage checks.
- For configuration or readiness failure, use current effective config,
  `mulgae doctor --output json`, and
  `mulgae providers --include-unverified --output json`; fix only the reported
  prerequisite with explicit authorization.
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
