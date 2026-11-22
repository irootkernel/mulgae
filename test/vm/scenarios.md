# Required guest observations

The authoritative scope is [the coordination specification](../../docs/specs/haepari-review-coordination.md)
and the accepted TASK-080 plan. Every scenario below requires its original observation. A driver or fixture PASS
cannot waive an unobserved row.

The guest entrypoint uses a validated native ParentChain array, actual Darwin
hypervisor and hardware UUID, complete skill tree and sealed candidate/profile
identities. It does not reacquire the occupied outer VM resource. The released
Haepari controller used for synthetic reviews is a separate foreground process
with a capacity-one `mulgae-review` lock.

| Scenario | Required original observation | Prepared driver coverage; original Job evidence remains required |
|---|---|---|
| Prior state | Run old v0.1.26 public interfaces before installing the candidate; preserve custom role routes/timeouts/profile aliases, P2 requirements/history, failed recovery and relevant active state across upgrade/restart | Old init/custom policy, requirements publication, failed/recovery reads, and an actual old active caller/provider protected across candidate reads and cleanup |
| Installed transports | CLI, foreground MCP `run_review`, async `start_review` + `await_review`; receipt-bound historical/role/requirements content retrieval | Three review transports and receipt-bound historical requirements and role content through CLI and MCP resources |
| Shared Installation | Distinct projects queue behind one native grant, concurrent roles stay inside it; release allows waiter | Distinct project roots, native queued waiters, and one granted request for concurrent logic/security roles |
| Replay/reconnect | Same saved acquisition key/payload returns the original request/sequence; wait timeout/reconnect preserves position | Native same-key replay and wait timeout; a forwarding fault case drops an actual native admission response, reconciles its exact request and refuses provider dispatch |
| Cancellation | Abandoned native request and grant/cancel race dispatch at most once | Async cancellation and grant/cancel handoff race after Mulgae persists the exact native queued identity; both trigger observations are retained and MCP fixture reads remain serialized |
| Borrower | Matching live grant remains read-only; wrong Installation/lock/unknown grant/stale generation/expired/ended fail closed; independent v3 cleanup | Matching grant, complete negative admission matrix, expired-grant reuse and independent v3 cleanup with unchanged parent identity/deadlines |
| Loss and drain | Renewal failure, hold expiry, caller loss, controller restart stop dispatch and preserve native cancellation/drain proof; unknown drain protects cleanup | Real SQLite restart, caller cancellation, borrower liveness loss, controller loss, hold-budget refusal/native expiry, and abrupt caller death with protected unverified intent. Running-owner reserve guards retain their separate deterministic evidence |
| Partial role and fresh FIFO | Keep accepted reports in the original run, release after native termination, allow unrelated waiter, then explicitly start a distinct full review with a new request/FIFO position and no inherited coverage | Driver code prepared; actual guest execution remains due |
| Provider-free compatibility | Preflight, no-change review and receipt-bound reads make zero provider/controller calls | Context/preflight, candidate no-change review, and receipt-bound CLI/MCP requirement/role content reads against an unstarted controller home |
| Live providers/clients | Serial owning Make targets for ZCode, Grok, AGY, primary-home Codex and real Codex/Claude requirements clients | Executable route prepared; actual account/profile-bound runs remain due |
| Cleanup | Before/after inventory, waited owned helpers, exact owned roots and installed artifact/profile identities | Executable route prepared; actual guest observations remain due |

Both public and private unknown-drain causes are exactly
`haepari_local_drain_unverified`. A clean logical release is not physical
process-drain proof. Capacity greater than one is outside the capacity-one claim.
Go HTTP-controller fixtures are supplemental deterministic evidence; they do not
prove native SQLite persistence or actual installed guest behavior. The response-loss
forwarder relays the released controller\'s replies and drops one admitted response;
it does not construct a controller receipt or alter its database.

Synthetic app-server cases never request native account credentials. Their authentication
callback coverage comes from the isolated-home integration tests; actual provider
sign-in, model calls and native client/skill discovery remain separate qualifications.

Live providers and native clients run in the guest user's normal Aqua session.
Observe account status there before declaring a login missing: SSH keychain
access errors do not prove the GUI account is logged out. Retain the GUI helper's
actual command exit, process drain and service teardown alongside native Job
and consumer cleanup results. An unverified helper drain keeps qualification
incomplete.

## Manual observations while awaiting_manual

Use the workspace from the native `manual_preparation_stopped` event. The
retained `results/<suite>/manual-staging.json` identifies the exact installed
fixture, candidate/profile/Job/lease, bundle and owned root. Preserve its private
original bytes. Preparation failures remain recorded and must not be silently
converted to manual PASS.

1. `installed-cli-mcp-transport-check`: observe `mulgae version --json`,
   `config --mode effective --output json`, actual CLI review, both MCP modes
   and receipt-bound result retrieval. Use existing registered guest tooling.
2. `fresh-session-skill-discovery-check`: in fresh supported native guest
   consumers, install/discover the matching complete six-file `use-mulgae`
   package through the supported native skill mechanism. Record actual source
   paths/profile and negatives; a directory copy alone is not discovery proof.
3. `prior-state-migration-coexistence-check`: read the old project's actual
   configuration, requirements/history and failed recovery with the installed
   candidate. Compare bytes/modes/typed identities after restart, without
   running candidate init on it. Old v0.1.26 never created native coordination
   intents; record that source-backed absence separately.
4. `post-manual-cleanup-inventory-check`: close fresh clients and stop/wait
   every fixture-owned helper. From the sealed bundle directory, outside the owned
   root, run:

   ```sh
   ./source/dev python -B test/vm/finalize.py \
     --stage <native-workspace>/results/<suite>/manual-staging.json
   ```

The finalizer verifies guest and sealed identities, refuses roots with open
handles or unreadable inventory, removes only the owned temporary fixture, and
writes separate bound cleanup/inventory documents. Complete this while the same
Job remains `awaiting_manual`, then transfer original evidence into
`<saved-host-run>/results/<suite>` through the already authorized manual
transport. Do not use host-generated booleans as guest cleanup proof.

Submit an actual native `haepari.manual-result/v1` record containing exactly:

```json
{
  "schema": "haepari.manual-result/v1",
  "job_id": "<native-job-id>",
  "installation_id": "<selected-installation-id>",
  "profile_id": "<sealed-target-profile-id>",
  "profile_digest": "<raw-64-hex-profile-digest>",
  "expected_revision": 1,
  "observer": "<actual-observer>",
  "scenarios": [
    {
      "id": "installed-cli-mcp-transport-check",
      "status": "unobserved",
      "evidence_references": []
    }
  ]
}
```

Replace the example revision with the current native revision and include all
four scenario IDs. Status is `pass`, `fail` or `unobserved`; observed rows
require actual relative evidence references. No aggregate verdict, cleanup flag,
notes alias or other extra native field is accepted. Never turn the illustrative
unobserved row into an observation.

Use the saved host adapter's `--manual-complete-input` and
`--expected-revision` with the same original request, resource, suite, mode,
prepared directory and run directory. It validates `inspect`'s current Receipt
and the separate cleanup/inventory bindings before calling
`haepari manual complete <job> --input <json> --expected-revision <n> --json`.
An acknowledgment is not the final Result. Reconcile the same Job through
collection, cleanup and final native verdict.

Job verdict, Mulgae review outcome, content verdict, evidence completeness,
consumer/native cleanup, capacity observation and Task/Epic acceptance remain
separate. Every due but unobserved row keeps TASK-080 incomplete.
