# Composite review recovery

Status: Accepted

## Context

A multi-role review can commit with incomplete coverage, or stop without a
final review after an internal error or cancellation. Accepted role results
should remain usable when Mulgae can prove their inputs, output, and cleanup.
Runtime diagnostics alone do not provide that proof.

## Decision

Mulgae retains failed ordinary reviews and failed reruns in a separate,
immutable `mulgae-run-recovery.v1` source. It freezes every selected role's
initial prompt before dispatch, including roles cancelled while queued. The
source binds the captured target and archive, role/provider assignments,
threshold, attempts, accepted reports, findings, and verified evidence.

Preparation grants no replay authority. Provider termination, target
revalidation, and workspace release must succeed before publication installs
the recovery manifest last. Security, configuration, artifact, missing-input,
cleanup, and persistence failures deny recovery. A retention or persistence
refusal preserves the original execution failure and exit; it cannot turn the
failed run into a successful or publishable review. If mandatory provider drain,
abort, or workspace cleanup independently fails, that failure remains in the
normal operational precedence and may determine the final failure class and
exit. Recovery never grants final-review publication or CI pass.

Failed-run retention uses one cooperative ten-minute budget created before
preparation. Caller cancellation is detached so a cancelled review can still be
retained, but the deadline is not refreshed per stage. Preparation, sealing,
retention diagnostics, provider drain, workspace release, and persistence share
that remaining budget. Retention drain keeps the shared context and clips each
attempt to one minute. Mandatory cleanup after retention failure or timeout
still uses the ordinary detached one-minute drain policy and may make the
overall return exceed ten minutes. The budget is cooperative; it does not
interrupt an arbitrary blocking kernel filesystem call. Retention stays
synchronous: there is no abandoned background writer and no operator timeout
knob.

`rerun --run ... --attempt ...` accepts either a committed review or an exact
failed-run recovery source. It rejects attempts to replace an accepted role in
a recovery source. A failed rerun may retain another recovery source under the
same rules, with its exact parent and source attempt. No provider substitution
or unconditional internal-error retry is introduced.

`compose` requires an explicitly selected ordinary root and one committed
rerun for every missing selected role, regardless of its `required` flag.
The root may be a committed incomplete review or a verified recovery source.
Trusted code checks target identity, report integrity, and transitive same-role
lineage, bounded to 128 links, before recomputing the root policy. It preserves
accepted root roles and rejects incomplete or ambiguous mappings.

Recovery references use a run ID and manifest hash, never a synthetic review
ID. Reruns derived from recovery use v2 run/final schemas; composites rooted in
recovery use v2 composite schemas. Their deterministic identity includes the
root recovery hash. Existing v1 reads and previously valid v1 composition
identities remain unchanged.

## Consequences

CLI status v7 and MCP `get_run` expose `failed_run_recovery`: availability,
source identity, accepted roles, retry attempts, and an unavailable reason.
Publication recovery actions remain separate from role replay admission.
Findings, report, and export still require a committed final review.

Cleanup protects recovery sources as uncommitted artifacts and follows their
source lineage when retaining ancestors. It does not delete a failed source
merely because a composite has been published.

There is no retrospective recovery of v0.1.19 diagnostic-only runs, promotion
of logs into accepted results, or recovery after forced process termination or
power loss. A missing manifest is unavailable; a present but invalid source
fails closed. Operators must reconcile exact IDs before any retry.

The selected-role rule also corrects v0.1.19 composition admission: new mappings
must recover every selected role, including optional roles. Older artifacts
remain readable, but an old mapping that omitted a failed role is rejected.
