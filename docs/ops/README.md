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
including independent project binding and verified reads:

- Establish the requested root independently before trusting an attached server
  binding. Reject wrong or replaced roots before provider calls. Hold workspace
  and index state unchanged through completion; source identity is metadata, not
  a content/request drift guarantee.
- Read exact run identities through verified inspection and continuation
  receipts. Historical unsupported evidence, reports-only results, and
  diagnostic-only runs remain distinct. Do not compensate with raw private
  artifact reads, current-tree excerpts, or silent publication repairs.
- A start response lost or an await interrupted does not authorize a second
  execution. Preserve available invocation/run identities, reuse the same live
  await handle, and reconcile exact terminal status under the existing rules.

## Planned local client behavior

The reduced [EPIC-008 requirements assessment](../specs/review-completeness-and-iteration.md)
is Planned and unimplemented. It adds no command available in the current binary.
TASK-027 will expose admission/preflight and TASK-028 internal execution;
public requirements-bearing execution/capability will activate with verified
CLI/MCP reads in TASK-029. Objective-only execution remains available throughout.

- Supply optional explicit requirements alongside the existing objective and
  target. Requirements do not grant execution permission or enlarge source scope.
  The local requirements file need not be in the reviewed commit; code evidence
  still follows the selected workspace, index or resolved Git objects.
- Display unmet/unverified items and evidence limitations independently of
  ordinary findings, severity filters and operational success. Keep valid provider
  unverified answers distinct from Mulgae-derived missing-answer placeholders;
  only admitted provider answers contribute to evaluated_count.
- Disclose disabled extraction in preflight without enabling it. A consumed
  additional-invocation allowance is a result limitation, not permission for a
  third call. Keep accepted primary reports on ordinary extraction failure.
- On any existing admitted no-change target, including empty-tree HEAD,
  preserve zero provider calls and evaluation not run, with every selected item
  unverified/no_change_target. Invalid input still fails admission. Workspace
  evaluation requires an explicit new request.
- Use verified public reads after restart; distinguish historical unavailable
  assessments and unknown counts from not-requested or not-run results.
  Never reconstruct missing evidence from current source or treat met as final
  approval.
- Preserve current host configuration and provider policy. Publish usage/help
  and source-distributed guidance only after the owning runtime path is verified.

Batch rechecks, cross-run comparison, resolution transfer and automatic
remediation are outside this Epic. Aquarium and the operator retain test
execution, remediation and acceptance.

See [live workspace and Git review](../specs/live-workspace-and-git-review.md)
for current execution and [verified review contracts](../specs/verified-review-contracts.md)
for retained historical foundations.
