# Native Haepari review coordination

## Adoption boundary

EPIC-016 adopts these requirements in stages. `TASK-076` establishes the native
port, client, state-root admission and durable acquisition identity. The
`TASK-077` implementation connects the common live CLI/MCP owner lifecycle,
private local-drain proof and bounded status projection. Borrowing, complete
failure recovery, migration and qualification remain `TASK-078` through
`TASK-081` obligations. These source changes do not establish installed or
released behavior. The [roadmap](../roadmap/README.md#epic-016-native-haepari-review-coordination-and-release-qualification)
owns status; this document owns the product contract. The
[decision](../architecture-decision-records/haepari-review-coordination.md)
owns its rationale.

The consumer obligation is Aquarium `EPIC-032/TASK-092`. Its accepted source
contract is pinned by the [execution dossier](../todo/TODO-HAEPARI-REVIEW-COORDINATION.md#original-authority).
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

Until `TASK-078` implements borrowing, any present `HAEPARI_LOCK_GRANT`, including
an empty value, is refused before controller access or intent I/O. No-change and
provider-free requests still require no coordination. The following borrowing
contract remains a pending obligation.

`HAEPARI_LOCK_GRANT` follows Haepari's closed JSON reference containing
`installation_id`, `lock_id`, `grant_id` and positive `generation`. The environment
value alone is not proof. Before skipping acquisition, perform read-only native
lookup on the selected Installation and require the intended lock, matching
current grant/generation, `granted` state, and unexpired liveness and maximum-hold
deadlines. Follow the native bounded pagination and same-page effective-time
contract.

A borrower never renews, cancels, releases, force-releases or transfers ownership
of its parent's request/grant, including on child failure or cancellation.
Wrong Installation/lock, unknown identity, stale generation or ended/expired
grant fails with its native typed condition. The borrower must not reacquire
under another key or bypass Haepari. It stops new provider dispatch and cancels
and drains its own native work when grant validity is lost. The reference is
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

CLI v23 and MCP v1 retain their existing envelopes. Owned `haepari_*` causes and
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

The [verification guidance](../implementation-tips/README.md#planned-haepari-integration-verification)
and [dossier](../todo/TODO-HAEPARI-REVIEW-COORDINATION.md) define candidate,
guest, release and completion evidence. Haepari fixtures or VM-only success do
not complete the producer obligation. Release, installation, live-provider
execution, host changes and Sorage operations retain separate authorization.
Aquarium accepts the producer return and updates its supported Mulgae floor;
Mulgae must not claim that consumer acceptance from its own tests or release.
