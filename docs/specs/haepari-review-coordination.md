# Native Haepari review coordination

## Adoption boundary

EPIC-016 adopts these requirements for staged implementation. `TASK-076`
establishes the unwired native coordination port, `internal/adapters/haepari`
client and state-root admission, private diagnostic intent store
(`diagnostics/s_<uuidv7>/r_<uuidv7>/haepari-lock.json`) and `internal/app/reviewrun`
single-acquisition/replay foundation; live runtime wiring and later `EPIC-016`
lifecycle, public projection and certification tasks (`TASK-077` through
`TASK-081`) remain pending, so the current binary does not invoke Haepari during
live CLI or MCP execution yet. The [roadmap](../roadmap/README.md#epic-016-native-haepari-review-coordination-and-release-qualification)
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
and maximum-hold deadlines. The registered maximum hold must cover the admitted
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

If the controller is unavailable or renewal fails, stop new provider dispatch,
request native cancellation and drain, and report the actual terminal or unknown
outcome. Do not silently run directly. Controller restart, caller loss, maximum
hold expiry and stale identities must retain this behavior. A lock replay never
authorizes replay of provider execution or publication.

## Borrowed grant lifecycle

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
