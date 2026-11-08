# Mulgae recovery

Load this reference when current state may be stale, a mutation's outcome is
unknown, a run is diagnostic-only or incompletely published, or a provider
failed.

## Reconcile authoritative state

If a known lifecycle invocation is still pending, preserve its `i_...` identity
and await it in the same live MCP session before applying the terminal run
inspection below. Queue waiting for `mulgae-review` stays inside the original
review invocation. A host timeout, native queue observation timeout, or
retryable `await_cancelled` ends only the observer; it leaves a queued or
running review in that same invocation and does not cancel execution or
authorize another start or queue request. Re-await that same invocation. If
awaiting cannot continue, report the concrete limitation without switching to
another execution or polling run status. `get_run` is not a live invocation
snapshot, and start need not return a durable run ID.

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
   `diagnostic_only`, `publication_authority`, stable reasons,
   `diagnostic_summary`, and `recovery_action`; do not infer
   completion from provider output, conversation memory, runtime logs, or the
   mere presence of files. Bounded `haepari_*` causes and coordination
   `diagnostic_summary` tokens distinguish readiness/capability refusal, queue
   wait expiry, cancellation, hold-budget reservation refusal, renewal or parent
   protection loss, unknown local drain (`haepari_local_drain_unverified`),
   persistence failure, and final disposition errors.
4. When controller contact or renewal is lost, or maximum hold expires, Mulgae
   stops new provider dispatch, requests native cancellation and drain, and
   fails closed without falling back to uncoordinated execution. A borrower
   under `HAEPARI_LOCK_GRANT` stops and drains its own child work when parent
   grant validity is lost and never cancels, releases, or force-releases the
   parent's grant. When local provider/source termination cannot be proven
   (`haepari_local_drain_unverified`), Mulgae retains the cleanup owner and
   protects the run's artifacts from `mulgae clean` without releasing or
   cancelling the grant; report that uncertainty and escalate rather than
   force-releasing, mutating controller state, or deleting `.mulgae/` manually.
   After verified local drain, an operational release or observation-persistence
   failure remains an error without suppressing an otherwise valid P2
   publication. Inspect the exact returned run ID through
   `inspect_review`/`inspect` or `get_run`/`status`.
5. If no exact run ID was returned, report the outcome as unknown. Mulgae has no
   read-only command that safely reconstructs an unknown ID from conversation
   context. Do not guess an ID or start another run to probe state. The
   `latest` selector on `export` resolves the newest committed run, but export
   writes an external bundle;
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

Native `inspect_review` or CLI `inspect` can provide coherent publication,
source/capture availability and finding state when available. Use the expected project binding and
follow [verified reads](verified-reads.md). Exact `get_run`/`status` remains useful
for recovery attempt inventory. Neither route is a live progress query, and an
additional status read does not extend an inspection's publication receipt.
Guard mismatches stop before execution; do not retry without the expected values
or refresh them automatically to bypass drift.

## Respect idempotency boundaries

Read-only `version`, `doctor`, `config`, `providers`, `roles`, `status`,
`context`, `inspect`, `findings`, `read-finding`, `read-report`, `excerpt`, and
review `--preflight` calls may be repeated. Preserve expected bindings, receipts
and content digests across continuations; a mismatch stops that read.
`clean --dry-run` is also read-only. Repeatability does not make run queries a live polling interface.

`init`, `review`, `report`/`export` writes (both require `--run`; `report` also
requires `--output-path`, while `export` defaults to `.mulgae/exports/<run-id>.zip`),
and clean apply mutate durable or external state and have no
caller-supplied idempotency key. Re-observe their documented postcondition before
any retry. A second review is a new run. Historical child and composite results
remain readable; they supply no current replay or composition mutation.

## Recover a partially failed review

New execution has no retained-source replay, child or compose operation.
On operational partial-role failure, Mulgae preserves accepted role reports as
historical evidence under the original run, completes native provider and source
drain, and releases an owned `mulgae-review` grant before returning for a user
decision (so unrelated queued reviews may proceed while the original result
remains incomplete). Inspect the exact terminal identity once. Distinguish
committed incomplete coverage, retained historical failed-run support,
diagnostic-only status and `run_status_unavailable`. Do not rerun roles, compose
reports, substitute another provider for a failed role, or combine coverage
across runs. Any new full review of current source requires explicit user
authority and acquires a new FIFO position on `mulgae-review`, inheriting no
queue position, continuation, or lease from the prior run while leaving old
results unchanged.

Historical accepted roles, retry attempts, manifests, blobs and lineage remain
verified inspection facts. Read only public supported surfaces; never reconstruct
or edit recovery inputs from raw logs. Missing historical support is unavailable;
bound corruption fails closed.

Publication reconciliation remains provider-free and follows native P0/P1/P2
classification. Await active work before a supported reconciliation, preserve
exact identities and do not blindly repeat uncertain mutations. Do not describe
publication recovery as source replay or completed role coverage.
