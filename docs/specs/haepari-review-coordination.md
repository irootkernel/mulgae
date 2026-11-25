# Native Haepari review coordination

## Scope and source authority

Mulgae v0.1.27 shipped the shared owner and borrower paths and their paired
skill. The [roadmap](../roadmap/README.md#epic-016-native-haepari-review-coordination-and-release-qualification)
records delivery and the limits of release qualification. The
[ADR](../architecture-decision-records/haepari-review-coordination.md) records
the design rationale.

Aquarium `EPIC-032/TASK-092` is the consumer obligation. The original accepted
Aquarium baseline is `759883a47676ad9efae2dd8ae373878a431ce031` and the frozen
Aquarium rollout source is `bddaccca94a98abb5bdfd3d97503b1cdb78585e7`. The
original authority and source paths are listed in the retired execution dossier
at Mulgae commit `d266b5bc7b69f69ca3d45e42863627161c1f548e`. The Mulgae
inspection baseline is `f80eacf57d15d90ddee16a4722ed7472bfe9c246`.

The native dependency is Haepari v0.1.0 and `advisory-lock/v1`, as defined by
its [released lock contract](https://github.com/irootkernel/haepari/blob/v0.1.0/docs/contracts/locks.md).
An API beyond that frozen contract is a dependency change requiring resolution
before acceptance. Integration adds no provider, source snapshot, replay,
compose, or external execution-lease feature.

## Admission and ownership

The shared native review path serves CLI, foreground MCP `run_review`, and
asynchronous MCP `start_review` execution. Before live provider qualification,
role execution, or extraction, an ordinary review acquires the capacity-one
`mulgae-review` lock exactly once in the selected Haepari Installation.
Queue waiting stays within the original review invocation. Review-level
serialization preserves parallel native roles inside the admitted review.

Read-only local preflight and receipt-bound inspection remain provider-free
and require no grant. A no-change target that invokes no provider also requires
no grant. Public review input keeps its existing transport grammar; neither
Aquarium nor `use-mulgae` adds a lock wrapper or a direct-execution fallback.

Persist the acquisition key and complete payload before sending acquisition.
Bind that record to the original Mulgae invocation and allocated run identity;
retain the selected Installation and native request/grant/generation identities.
A failed persistence step admits no acquisition or provider request. Native
paths and raw Haepari responses remain private; public status and errors use
Mulgae-owned bounded projections and typed reasons under existing versioning
and failure precedence in [contracts](contracts.md).

Local source/configuration admission precedes provider execution. Revalidate
the admitted source, project binding, configuration and remaining budget after
a queue wait and before provider dispatch. A source-identity digest is selection
metadata, not an atomic content fingerprint. Workspace/index stability remains
the caller's obligation throughout waiting and execution.

## Owned grant lifecycle

The acquiring process renews in process, using the native returned liveness
and maximum-hold deadlines. Mulgae requires remaining hold to exceed the full
admitted run budget plus two minutes for terminal cleanup. Preparation has its
own deadline at maximum hold minus both reservations. An independent guard
cancels active work at maximum hold minus cleanup reserve or known liveness
loss; a stalled renewal cannot postpone that guard. Calls are bounded to 30
seconds, queue observations to 15 seconds, and renewal calls additionally to the
known safe lease interval. The registered maximum hold must cover the admitted
execution and cleanup budget. An insufficient policy fails admission; review
execution cannot silently update the resource or change Installation. Resource
registration and policy changes retain their separate setup authority.

Retain the same key and payload across native observation timeouts and replay.
An observation timeout leaves a queued request pending. Resume observation of
that request rather than acquiring another queue position or dispatching another
review. On abandonment or cancellation, cancel through its actual native request
ID. If granting races cancellation, reconcile the native terminal receipt before
provider dispatch. Never release a later grant generation.

After protected work ends, the owner releases on success, failure and
cancellation before waiting for a user decision. Cancellation acknowledgement,
process termination, verified drain, grant disposition and review publication
are separate observations. When drain is unknown, retain the native cleanup
owner and report uncertainty; do not claim protected work ended or cleanup
succeeded. Advisory expiry can free capacity while work continues.

The private v2 intent records `local_drain_state` as `not_started`, `unverified`
or `verified`. Persist `unverified` before protected effects; only proven provider
termination and source closure establish `verified`. Native terminal state does
not supply local proof. Historical v1 records remain readable with unknown local
proof. Cleanup protects unknown, invalid, unresolved, nonterminal or unverified
intent in diagnostic-only and linked publication trees. It checks exact intent
bytes and descriptor identity again before deletion; ordinary diagnostics without
an intent retain their existing cleanup policy.

Renewal continues through one bounded provider/source cleanup operation shared
by normal and deferred cleanup. Unknown completion retains its cleanup owner and
intent without Release or Cancel. After verified completion, a purely operational
Release or observation-persistence error remains an error but does not suppress
an otherwise valid P2 publication. Capture the actual P2 reference before error
projection, preserving its original state, coverage and findings/CI axes.

If the controller is unavailable or renewal fails, stop new provider dispatch,
request native cancellation and drain, and report the actual terminal or unknown
outcome. Do not silently run directly. Controller restart, caller loss, maximum
hold expiry and stale identities must retain this behavior. A lock replay never
authorizes replay of provider execution or publication.

## Borrowed grant lifecycle

When `HAEPARI_LOCK_GRANT` is present in the environment, Mulgae validates its
closed JSON reference before controller access or intent I/O. No-change and
provider-free requests still require no coordination.

`HAEPARI_LOCK_GRANT` follows Haepari's closed JSON reference containing
`installation_id`, `lock_id`, `grant_id` and positive `generation` within an
8,192-byte ceiling. The environment value alone is not proof. Before skipping
acquisition, Mulgae performs read-only native `hello`, `resource.inspect`, and
bounded `locks.list` (`lock=mulgae-review&limit=100`) lookup on the selected
Installation under one 30-second whole-inspection deadline. Each page must use a
strictly progressing cursor, and deadline checks compare against that matching
page's `now` timestamp. Admission requires the intended lock, matching current
`grant_id` and `generation`, `granted` state, and unexpired liveness and
maximum-hold deadlines covering the full admitted run budget plus two minutes of
cleanup.

Before any provider qualification, role execution or extraction, the borrower
persists a private `mulgae-haepari-lock-intent.v3` record with
`local_drain_state: unverified`, `borrowed_grant`, and `observed_request`
(without an acquisition payload or receipt). Only proven child provider
termination and source closure set `local_drain_state: verified`. Same-run v3
replay is refused before provider dispatch. Cleanup protects unverified v3 child
trees and allows verified v3 child artifacts to be removed independently while
the parent grant remains live.

A borrower never acquires, waits, renews, cancels, releases, force-releases or
transfers ownership of its parent's request/grant, including on child failure or
cancellation. Wrong Installation/lock, unknown identity, stale generation or
ended/expired grant fails admission with its native typed condition. The
borrower never reacquires under another key or bypasses Haepari. During child
execution, an independent deadline guard and periodic read-only `locks.list`
monitor adopt parent renewal extensions and stop new provider dispatch, cancel,
and drain child native work when parent grant validity is lost. The reference is
same-user coordination, not a credential or a new security boundary.

## Partial results and advisory limits

On partial-role failure, preserve accepted reports as historical evidence under
their original run. Do not rerun roles, compose reports, substitute providers or
combine coverage across runs. Release an owned grant after native termination
and before requesting a user decision; an unrelated queued review may then
proceed while the original result remains incomplete.

A new full current-source review requires explicit execution authority and a
new FIFO acquisition. It inherits no queue position, continuation or lease.
Existing uncertain-start recovery keeps the original invocation/run and its
verified inspection path; a new lock grant confers no retry authority.

Advisory serialization reduces competing cooperating reviews. It cannot promise
provider rate-limit immunity or police callers that skip the lock. Grant expiry
does not forcibly terminate native work, so overlap remains possible after lost
renewal or maximum hold. This feature does not provide managed unknown-execution
containment. Coverage, findings/CI, publication and lock disposition stay separate.

## Supported observation

CLI v26 and MCP v1 retain their existing envelopes. Owned `haepari_*` causes and
`diagnostic_summary` tokens distinguish readiness, queue expiry, cancellation,
hold reservation, protection loss, unknown local drain, persistence and final
disposition. Native free text, paths and identities are not public diagnostics.
Coordination failures remain non-provider failures with normal failure precedence.

Verified P2 reads remain publication-first. A valid same-session/same-run
coordination summary may enrich status/get_run; missing, unsupported, unreadable,
corrupt or mismatched supplementary diagnostics are omitted. Absence of a summary
does not prove clean disposition. Independently corrupt P2 still fails verification.

## Migration and release qualification

Preserve existing provider/role assignments, project and machine-local policy,
historical review and requirements results, retry state and active-work
obligations. Use meaningful prior-version fixtures and source-backed migration
assertions; do not overwrite active user state or substitute a fresh init for
migration. Complete `use-mulgae` verification covers CLI, foreground MCP and
asynchronous MCP using the actual released binary and matching full skill tree,
including fresh-session discovery and result retrieval.

The [verification guidance](../implementation-tips/README.md#haepari-integration-verification)
defines candidate, guest and release checks. Fixture and VM-only results cover
only their exercised scenarios. Release, installation,
live-provider execution, host changes and Sorage operations retain separate
authorization. Aquarium owns acceptance of the producer return and updates
to its supported Mulgae floor.
