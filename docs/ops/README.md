# Operations

Mulgae is a local CLI and attached MCP server, not an independently deployed
service or daemon. This delivery scope therefore has no separate production
environment, deployment control plane, or operations runbook.

Public installation, configuration, and user troubleshooting belong in the
repository [README](../../README.md). Development environment setup, test
execution, release preparation, and manual publication guidance belong to the
[implementation tips](../implementation-tips/README.md). Security requirements
for credentials, provider processes, workspaces, and local artifacts belong to
the [security specification](../specs/security.md).

Add a runbook here only if Mulgae gains an independently operated environment
with a verified owner, prerequisites, safe diagnosis, recovery, success checks,
rollback, and escalation boundary.

## Local client behavior

The [adopted review Epics](../roadmap/README.md#adopted-execution-order) add no
independently operated service. Current local clients follow these requirements,
including the EPIC-007 guards and verified reads:

- Establish the requested root independently before trusting an attached server
  binding. Reject project/request drift before provider calls; obtaining another
  preflight is not permission to execute a changed request automatically.
- Read exact run identities through verified inspection and continuation
  receipts. Historical unsupported evidence, reports-only results, and
  diagnostic-only runs remain distinct. Do not compensate with raw private
  artifact reads, current-tree excerpts, or silent publication repairs.
- A start response lost or an await interrupted does not authorize a second
  execution. Preserve available invocation/run identities, reuse the same live
  await handle, and reconcile exact terminal status under the existing rules.

## Planned local client behavior

EPIC-008 requirements remain future behavior, not commands supported by the
current binary:

- Batch followup does not introduce restart recovery or automatic failed-group
  reruns; report the explicit capability limit.
- Expose unmet/unverified requirements and unresolved/unknown recheck results
  even when the operational command completed. A Brief with an empty Git diff
  records evaluation not run and no_change_target; all selected requirements
  remain unverified with no provider calls. A workspace evaluation needs an
  explicit new target/preflight and correctly scoped references, not an automatic
  fallback. Invalid Briefs or guards still fail before no-change publication.
- Apply followup resolutions only to an after run with the same verified complete
  capture, not merely the same patch digest. Request-only differences such as
  objectives are separate provenance. Historical capture identity absence is
  unavailable, not permission to read current source or infer equality.
- Keep the full selected followup receipt set fixed during comparison paging.
  If any selected run disappears, changes, or is corrupt, stop that continuation
  with its typed read error rather than silently omitting it. A fresh comparison
  with a revised selection is an explicit separate read request.
- Display all conflicting eligible followup claims and after observations with
  stable unverified reasons; do not choose the newest or first result. Inconclusive
  claims are not negative verdicts. Non-observation is not resolution, and a
  changed Brief does not inherit previous satisfaction.
- Keep current installed host configuration and provider policy untouched during
  adoption. Update public README and source-distributed skill guidance only when
  the owning implementation has verified the new path; retain safe legacy/CLI
  fallback where capabilities are unavailable.

See [verified review contracts](../specs/verified-review-contracts.md) for current
behavior and [review completeness and iteration](../specs/review-completeness-and-iteration.md)
for planned behavior.
