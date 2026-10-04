---
name: use-mulgae
description: Run authorized Mulgae reviews with project and preflight guards, await MCP completion without polling, and inspect verified findings, reports and evidence. Also supports verified run inspection, configuration diagnosis, cleanup planning and provider-free publication reconciliation, with capability-aware CLI fallbacks.
---

# Use Mulgae

## Default: start once, await completion

For a new root review, prefer attached Mulgae MCP when `start_review`,
`await_review`, and `cancel_review` are all connected and the live server's
project binding matches the independently established requested root. Complete
[preparation](#establish-current-authority) and [target binding](#bind-the-review-target)
before starting. Select exactly one authorized target: `workspace`, `stage`,
`head`, `commit`, or `diff`.
MCP stdin is transport-only. Select the path from observed capabilities and
connected tools, not the version string alone. With native `project_binding`
and `live_source` capabilities at `v1`, use the same target, objective,
roles and explicit/default selections for preflight and execution:

```text
# Obtain expected binding independently with CLI context from the requested root.
get_context({})
# Compare project_binding to that expectation before continuing.
preflight_review({"target":{"kind":"stage"},"expected_project_binding":"<CLI binding>"})
# Inspect source identity, target, routing, warnings and budget.run_deadline.
# Check retention below and keep workspace/index unchanged through completion.
start_review({"target":{"kind":"stage"},"expected_project_binding":"<CLI binding>"})
await_review({"invocation_id":"<returned invocation_id>"})
# After the terminal response, inspect the exact returned run ID.
```

These are supported server contracts, not proof that every installed host
exposes the tools and resources. If a needed surface is unavailable, select a
supported CLI or [legacy path](references/legacy.md) before starting. Never
remove a requested guard to make a call succeed.

Call start exactly once. A successful start or a pending await is not a completed
review and does not guarantee a durable run ID. Keep one `await_review` pending
on the returned invocation until completion. Never repeat an uncertain start or
start another review to change transports.
Run preflight, start and await sequentially, waiting for each preceding response.
Never put start and await in the same tool batch or invent the invocation ID
before start returns it.
On non-retryable `invocation_limit_reached`, 64 reviews are still running in
that MCP session. Follow [recovery.md](references/recovery.md) rather than
retrying start or bypassing the concurrent bound through another execution path.

Prefer a host-native wait that suspends the pending tool call until completion.
If the host returns a deferred handle or cell, wait only on that same handle for
up to five minutes at a time, or the longest shorter duration the host supports
and higher-priority instructions permit. Return early on completion. Do not
resume model reasoning merely for liveness or shorter empty waits unless
higher-priority host instructions require it. Required progress reports do not
require a new Mulgae status call. Waiting on the same pending handle is not
Mulgae status polling.

Do not repeatedly call `get_run`, `list_runs`, `inspect_review`, CLI `status` or
`inspect`, inspect status-file existence, or poll OS processes while waiting.
Mulgae has no bounded-wait or invocation-snapshot tool: `get_run` reads publication-backed or completed
failed/cancelled diagnostic state, not live invocation progress. If the user
asks for progress, report the known pending state and observation limits;
do not replace the await with a recurring query loop.

When readable, check the host's hard tool-call timeout against preflight's
`budget.run_deadline`, the admitted run budget. Do not use the policy ceiling
`budget.ceilings.run_deadline` for this comparison. One uninterrupted await needs
a host deadline above the admitted budget, with room for transport overhead.
Do not change host or provider configuration without authorization.
An unknown host deadline is not evidence that async is unavailable: report the
uncertainty and try awaiting. A verified shorter deadline
or observed host timeout may require re-awaiting the same invocation while the
same MCP session lives. Neither a host handle wait nor a tool timeout extends
the admitted review deadline.

An await timeout or retryable `await_cancelled` ends only that observer, not the
review. Re-await the preserved invocation in the same live session without
restarting execution. On disconnect, `invocation_not_found`, or
`invocation_registry_closed`, stop automated waiting and follow
[recovery.md](references/recovery.md). If awaiting cannot continue, report the
concrete limitation; do not substitute run-status polling or a new execution.

Use `cancel_review` only for a preserved invocation returned by `start_review`
and only on explicit user intent. Its acknowledgement is not completion: await
the same invocation for the terminal result. Keep the MCP session attached;
server shutdown cancels active reviews and discards invocation
identities. Cancellation never rolls back an already committed publication.

## Establish current authority

1. Work from the canonical Git repository root.
2. Confirm availability with `command -v mulgae` and `mulgae version --json`.
   Do not install or upgrade Mulgae automatically.
3. Before execution or configuration work, check for both `.mulgae/config.yaml`
   and `.mulgae/local.yaml`. If either is absent, stop that workflow unless the
   user explicitly requested initialization; then read
   [lifecycle.md](references/lifecycle.md). The first file is shared project
   policy; the second is private machine configuration. Native context and verified
   reads do not require initialization or provider readiness.
4. For execution or configuration diagnosis, read admitted configuration with:

   ```bash
   mulgae config --mode effective --output json
   mulgae config --mode provenance --output json
   ```

   Use `mulgae doctor --output json` for offline setup readiness. In
   `mulgae-doctor-result.v5`, consume `config_v3`, `local_configuration`, and
   `provider_identity` independently. For each configured provider, consume
   `binary_available` and `cli_compatible`, then read `configured_readiness`.
   Static admission and prior review qualification do not gate this state.

5. Derive the next action from current Mulgae output, never from conversation
   memory. Preserve exact session (`s_...`), run (`r_...`), attempt (`a_...`),
   and finding (`F...`) IDs.

## Bind the review target

Establish the requested canonical Git worktree root independently, then run:

```bash
mulgae context --output json
```

This read observes local identity without initializing configuration, reading
credentials or invoking providers. For attached MCP, compare its `get_context`
`data.project_binding` with CLI `result.project_binding`. Do not obtain the
expected value by copying the server's own response. Equal source bytes or
patch hashes do not identify a worktree, and changing the shell directory does
not retarget an attached server. Keep every subsequent operation on that root.
A mismatch or root drift stops the guarded operation; do not suppress the error.

Read each required capability independently. Empty, missing or unknown versions
are unsupported. If native binding is absent, use the restricted
[legacy binding procedure](references/legacy.md#legacy-root-and-preflight-binding)
or the CLI from the requested root. A failed native binding check is not an
invitation to retry without it. An explicitly requested non-Git workspace can
use the CLI from its canonical root without an expected Git binding; preflight
reports the empty binding and capability. Do not treat that route as guarded.

Build the complete review objective as one line, with explicit section separators
and no remaining NUL, CR or LF. Count UTF-8 bytes: MCP accepts at most 4096;
CLI accepts at most 12000. Select CLI before starting when the complete objective
fits only its limit. If neither limit fits, stop without truncating or splitting
the review. Preserve roles, provider routing and source-transmission scope.

Run preflight on the selected execution path with the independently obtained
expected project binding. Inspect source selection metadata, read plan, routes,
artist validation, warnings and enclosing budget. Use those same selected inputs
on execution with `expected_project_binding` alone. CLI uses
`--expected-project-binding`. Wrong or replaced roots fail before provider work.

`live_source: v1` identifies the current execution contract. Empty
`execution_guard` and `capture_identity` capabilities are expected; they do not
trigger a legacy fallback. Source identity hashes selection metadata, not an
atomic content view. Hold workspace/index state unchanged until completion.
There is no request-digest guard, source snapshot, full-tree fingerprint or drift
monitor. Fixed committed operands are resolved once. Retired capture-bound
requests, dirty/patch/stdin targets and child/compose execution fail closed.
Never remove a requested guard, replace a failed provider or retry a mutation
without authority. A project binding is not an idempotency key.

## Advise on durable artifact retention

Before executing `review`, check retention once
from the canonical project root. For a root review, do this after its preflight
succeeds and before provider work:

```bash
mulgae clean --all --dry-run --output json
```

This command is observation-only. Read `result.affected_run_count` and
`result.affected_bytes`; they describe safely deletable terminal run artifacts,
not every stored capture. When the count is at least 10, tell the user the count
and bytes and offer cleanup, but do not wait for a response or delay the current
review. Say nothing when the count is lower. If the observation fails, report
that the advisory is unavailable and continue; it is not a review gate.

Never delete artifacts merely because the threshold was reached. If the user
requests cleanup while a review is active, await its terminal result and re-read
the run before cleanup. Then read [lifecycle.md](references/lifecycle.md). When
the user did not select a cleanup scope, show dry runs for `--older-than 30d`
and `--all`, recommend the age-bounded option, and ask for an exact choice.
Apply only the authorized selector without `--dry-run`, then repeat its dry run
and report the remaining eligible count and bytes.

## Read the terminal result

Read the common structured envelope even for `request_changes` or `error`.
`request_changes` reports a content policy outcome; it does not by itself prove
complete coverage. Inspect coverage, publication authority, and CI independently.
For incomplete or failed reviews, read [recovery.md](references/recovery.md)
before selecting another action. Historical accepted-role and failed-run
inventories remain readable, but grant no child, rerun, compose or source replay
authority. Provider-free publication reconciliation is separate from execution.
A new review requires authority and observes current source; it cannot recover
an old snapshot or silently substitute a provider.

Preserve the exact returned run ID, including one attached to a failed review.
Only after terminal completion, prefer `inspect_review` or CLI `inspect` with
the expected project binding when `inspection: v1` is supported. This returns
status, source/capture availability and a finding page under one publication receipt.
Use `get_run` or CLI `status` when recovery needs its attempt inventory, or when
inspection is unavailable; those separate reads do not establish a page receipt.
If no run ID was returned, report the terminal outcome without inventing one.

When `run_review` or terminal `await_review` returns the error code
`provider_rate_limited`, every qualification failure recorded for the selected
roles was a provider rate limit, and no higher failure class took precedence.
Inspect the exact returned run once. Qualification ended before provider
execution, so the diagnostic-only run has no accepted role, failed attempt, or
replay source. Do not call doctor or heartbeat to test the limit, start a
replacement review, or substitute another provider.
Report that a new review may be needed after the rate limit clears and requires
user authority. The error's `retryable: false` protects the non-idempotent
review mutation from blind repetition; it does not mean the provider failure is
permanent.

A rate limit observed during provider execution rather than qualification
completes `run_review` or terminal `await_review` with `outcome: success`,
`terminal_exit_code: 4`, and a `rate_limit` reason. This is a committed
incomplete review, not a successful review verdict. Inspect the exact run once,
then report incomplete coverage and require authority for any new review.

Read findings only under committed publication authority. Use the returned
`publication_receipt` for pages, details, reports and every supported evidence
index, following [verified-reads.md](references/verified-reads.md). CLI has
native read-only `inspect`, `read-finding` and `read-report` surfaces; a report
write is unnecessary for supported verified reads. Composite evidence is
available per item when retained; legacy absence is explicit.

Diagnostic-only results have no publication receipt or findings. Historical
`failed_run_recovery` describes retained evidence, not executable replay.
Treat `run_status_unavailable` as an allocated identity without durable status;
stop rather than retrying the review. Preserve coverage, extraction, publication
and CI as independent axes. Zero extracted findings in `reports_only` or `mixed`
output does not establish a clean report. Verify advisory findings against the
retained source evidence and current code before changing anything.

## Fallbacks

Choose the execution path before starting a new review. State the concrete tool
or host limitation once. An unproven MCP root or an objective above 4096 bytes
that still fits the CLI limit requires the CLI path. Slowness, a pending handle,
or an unknown host timeout alone does not justify abandoning the async
lifecycle. Never switch an already-started invocation to `run_review` or CLI
execution.

### Foreground MCP

If any of the three lifecycle tools is unavailable, use one foreground
`run_review` with the same admitted inputs and independent project binding. The host's hard tool-call timeout must be verified to exceed
preflight's `budget.run_deadline`, allowing transport overhead. If that timeout
is insufficient or cannot be verified, choose the CLI before starting instead.
Cancelling a foreground MCP request cancels the review, unlike cancelling an
`await_review` observer; a host timeout can therefore cancel
execution or leave its outcome unknown. For an admitted foreground call, use the
same pending-handle wait policy as above. A lost or uncertain foreground call is
not safe to retry.

If the user explicitly requests cancellation on this foreground path, cancel
the MCP request itself. Do not call `cancel_review`: a `run_review` call has no
registry invocation for that tool to cancel. Preserve any returned run ID and
reconcile the outcome as described in [recovery.md](references/recovery.md).

### CLI execution and host waiting

Use the CLI when Mulgae MCP tools are unavailable, when the attached server's root cannot be bound to the requested root,
when the complete objective exceeds the MCP limit, or for CLI-only commands
such as report/export writes. A host that cannot read MCP resources
can use receipt-bound CLI content reads from the same independently bound root.
Do not start a second MCP server from a shell when an attached server is already
available. The CLI is also a fallback when no usable MCP execution path can be selected before
starting.

Run the command once and await completion through the host's process-wait
facility. Preserve any returned process handle and wait on that same handle,
using the longest waits permitted by the host and higher-priority instructions.
A CLI process has no MCP
invocation ID; never start another review to obtain one.

A passive host wait timeout leaves the same CLI process running; continue
waiting on its preserved handle. A host deadline that interrupts or terminates
the process instead requests cancellation or leaves the outcome uncertain. It
is not a harmless observer timeout. Preserve the process handle and any exact
returned run ID, reconcile the terminal result when possible, and never start
a duplicate review to recover from that deadline. Interrupt the process
yourself only on explicit user intent; see [lifecycle.md](references/lifecycle.md#cancel-foreground-work).

Only if the host provides no completion-wait facility and exposes only a
nonblocking process-handle status check, use that check as a last resort. After
each nonterminal result, wait 50 seconds through the host's wait or sleep facility
before checking the same handle again. Shorter sleeps may be combined without
extra status checks. If timed waiting is unavailable, stop automated polling and
report the limitation. Stop on terminal completion, a lost handle, or an
operational error; use recovery for an uncertain outcome. Never use Mulgae run
queries, file existence, or OS process scans as substitutes.

Use exactly one authorized selector: `--workspace`, `--stage`, `--head`,
`--commit REVISION`, or `--diff LEFT..RIGHT` / `LEFT...RIGHT`. Run from the
independently established root:

```bash
mulgae review --stage --preflight --expected-project-binding "$project_binding" --output json
mulgae review --stage --expected-project-binding "$project_binding" --output json
```

Keep objective, role and artist inputs identical and workspace/index state
unchanged. Inspect the exact terminal run and use its receipt-bound content
surfaces. A CLI process has no MCP invocation identity.

## Apply safety boundaries

- Use structured output, exact IDs, stable error codes, and command
  preconditions. Mulgae has no client idempotency key: review-like commands
  create new runs, so never blindly retry an uncertain mutation.
- Child/replay/compose creation is retired. Historical artifacts and failed-run
  inventories remain inspection facts and grant no execution authority.
- Require explicit user intent for initialization, imported-session use,
  cancellation, cleanup, provider or role changes, or any requested reset,
  service control, goal change, or repair. Read
  [lifecycle.md](references/lifecycle.md) before lifecycle actions.
- Treat `heartbeat` as a separate live provider request, never as setup or
  inspection. Run it only when the user explicitly selects one configured
  provider and authorizes authentication, network access, cost, and remote
  logging with `--authorize-live-request`.
- Read [authoring.md](references/authoring.md) only for provider, credential
  profile, role, artist, or configuration authoring requests.
- Read [recovery.md](references/recovery.md) when state is stale, a mutation's
  outcome is unknown, publication is incomplete, or a provider failed.
- Re-read effective configuration after configuration changes and exact run
  inspection after review completion. Start and cancellation acknowledgements must
  be followed by terminal awaiting, not immediate run-status queries.
- Never weaken path, locality, source admission, validation, evidence, or publication
  fences. Never edit manifests, attempts, diagnostics, or final artifacts.
- Preserve Mulgae's product boundary: it is a local advisory code-review CLI,
  not merge approval, consensus, a hosted service, a task manager, or an agent
  orchestrator.
- Commit only `.mulgae/config.yaml`. Never commit or share
  `.mulgae/local.yaml`, any other `.mulgae/**` path, provider homes,
  credentials, raw provider transcripts, diagnostics, or exported review
  bundles.
