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

## Requirements assessment

The reduced [EPIC-008 requirements assessment](../specs/review-completeness-and-iteration.md)
supports optional requirements in Git-backed reviews with verified CLI/MCP reads.
Admission and preflight run without provider execution. Objective-only execution
remains available without a requirements file.

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

## Haepari coordination operations

The common live CLI/MCP owner path requires Haepari's separately owned local
controller. Select an existing private `HAEPARI_HOME` with `advisory-lock/v1`
and a capacity-one `mulgae-review` resource. Its hold policy must cover the full
admitted run budget, preparation and two minutes of cleanup. Missing or unsafe
prerequisites fail closed. Resolve setup and policy changes under their separate
authority; review execution does not repair, register or change resources.
No-change review, local preflight and verified reads need no controller.

An existing valid Config v5 project keeps its shared policy, private machine
paths, configured role/provider routes, credential profiles and historical
review/requirements results across this upgrade. Do not replace the pair with
a fresh `mulgae init`. Retained failed-run reports and retry inventories grant
inspection authority only. Legacy unknown drain and unverified owned or
borrowed work remain protected by native cleanup; preserve that obligation
when moving an existing project. The complete paired
[`use-mulgae` skill](../../skills/use-mulgae/SKILL.md) follows the same native
CLI and MCP lifecycle without an outer lock wrapper. Candidate preservation
and discovery checks are described in the
[verification guidance](../implementation-tips/README.md#haepari-integration-verification).

When `HAEPARI_LOCK_GRANT` is present, Mulgae validates the inherited grant
through read-only controller inspection (`hello`, `resource.inspect`, and bounded
`locks.list`) and monitors parent validity during child execution without
acquiring, renewing, cancelling, or releasing the parent grant. Malformed,
mismatched, stale, ended or expired references fail closed. Once a borrowed
child run verifies its own local provider/source drain in its private v3 intent,
its child artifacts may be cleaned independently while the parent grant remains
live. The [coordination specification](../specs/haepari-review-coordination.md)
owns the owner and borrower behavior and qualification requirements.

A lost wait or start response does not authorize another review. Preserve the
original acquisition and native invocation/run, inspect using their supported
read paths and distinguish queue timeout, cancellation acknowledgement, verified
termination, cleanup and grant disposition. A borrower never disposes its
parent's grant. Unavailable control or unknown drain requires reporting and
the owning integration's recovery; it does not authorize direct execution,
force release, controller changes or automatic rerun. Capture the actual native
conditions and escalate missing authority to Master. Use existing
`mulgae status --run <run-id> --output json` or MCP `get_run` for bounded
coordination summaries. A committed result remains inspectable after an
operational disposition error; missing supplementary diagnostics do not establish
clean release or cleanup. Never edit intent/status files to simulate recovery.
