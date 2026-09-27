---
name: use-mulgae
description: Run authorized Mulgae reviews with project and preflight guards, await MCP completion without polling, and inspect verified findings, reports and evidence. Also supports finding follow-up, configuration diagnosis, cleanup planning and exact partial-failure recovery, with capability-aware CLI and legacy fallbacks.
---

# Use Mulgae

## Default: start once, await completion

For a new root review, prefer attached Mulgae MCP when `start_review`,
`await_review`, and `cancel_review` are all connected and the live server's
project binding matches the independently established requested root. Complete
[preparation](#establish-current-authority) and [target binding](#bind-the-review-target)
before starting. Select exactly one authorized target: `workspace`, `stage`,
`dirty`, `diff`, or `patch`.
MCP stdin is transport-only. Select the path from observed capabilities and
connected tools, not the version string alone. With native `project_binding`
and `execution_guard` capabilities at `v1`, use the same target, objective,
roles and explicit/default selections for preflight and execution:

```text
# Obtain expected binding independently with CLI context from the requested root.
get_context({})
# Compare project_binding to that expectation before continuing.
preflight_review({"target":{"kind":"stage"},"expected_project_binding":"<CLI binding>"})
# Inspect capture, request_receipt, routing, warnings and budget.run_deadline.
# Check retention below, then preserve both guard values from this preflight.
start_review({"target":{"kind":"stage"},"expected_project_binding":"<CLI binding>","expected_request_digest":"<request_receipt.request_digest>"})
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
invitation to retry without it.

Build the complete review objective as one line, with explicit section separators
and no remaining NUL, CR or LF. Count UTF-8 bytes: MCP accepts at most 4096;
CLI accepts at most 12000. Select CLI before starting when the complete objective
fits only its limit. If neither limit fits, stop without truncating or splitting
the review. Preserve roles, provider routing and source-transmission scope.

Run preflight on the selected execution path with the independently obtained
expected binding. Inspect the admitted target, complete capture, request receipt,
role transmissions, warnings and budget. Pass its `request_receipt.request_digest`
with the same binding to execution. The paired guards reject project or request
drift before provider work. Execution captures and plans once, checks that
request against the receipt, and consumes the same admitted snapshot and plan.
Guards do not grant idempotency or provider availability. Preserve omitted versus
explicit selectors; do not recompute or splice component digests yourself.

Native guards replace the legacy duplicate CLI/MCP preflight comparison. On
`project_binding_mismatch` or `request_digest_mismatch`, stop and explain the
changed input; obtain a new deliberate preflight decision within the authorized
scope. Do not silently adopt a new digest. `guard_incomplete`, `guard_invalid`
and `contract_unsupported` require correcting the request or selecting a path
that supports the required contract, never dropping a guard. Non-Git workspaces
retain their unguarded compatibility path; they cannot satisfy a requested guard.

## Advise on durable artifact retention

Before executing `review`, `followup`, `delta`, or `rerun`, check retention once
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
For a committed incomplete review or `failed_run_recovery.available: true`, read
[partial-failure recovery](references/recovery.md#recover-a-partially-failed-review)
before choosing another review. Recover the failed roles through exact reruns,
then compose their committed results with the original root. A successful rerun
does not update the root or finish the whole review. Check recovery availability
before treating an unpublished run as diagnostic-only; never repeat accepted
roles. A missing source cannot be reconstructed from runtime logs.

Preserve the exact returned run ID, including one attached to a failed review.
Only after terminal completion, prefer `inspect_review` or CLI `inspect` with
the expected project binding when `inspection: v1` is supported. This returns
status, capture availability and a finding page under one publication receipt.
Use `get_run` or CLI `status` when recovery needs its attempt inventory, or when
inspection is unavailable; those separate reads do not establish a page receipt.
If no run ID was returned, report the terminal outcome without inventing one.

When `run_review` or terminal `await_review` returns the error code
`provider_rate_limited`, every qualification failure recorded for the selected
roles was a provider rate limit, and no higher failure class took precedence.
Inspect the exact returned run once. Qualification ended before provider
execution, so the diagnostic-only run has no accepted role, failed attempt, or
exact rerun source. Do not call doctor or heartbeat to test the limit, call
`mulgae rerun`, start a replacement review, or substitute another provider.
Report that a new review may be needed after the rate limit clears and requires
user authority. The error's `retryable: false` protects the non-idempotent
review mutation from blind repetition; it does not mean the provider failure is
permanent.

A rate limit observed during provider execution rather than qualification
completes `run_review` or terminal `await_review` with `outcome: success`,
`terminal_exit_code: 4`, and a `rate_limit` reason. This is a committed
incomplete review, not a successful review verdict. Inspect the exact run once,
then follow partial-failure recovery without repeating accepted roles.

Read findings only under committed publication authority. Use the returned
`publication_receipt` for pages, details, reports and every supported evidence
index, following [verified-reads.md](references/verified-reads.md). CLI has
native read-only `inspect`, `read-finding` and `read-report` surfaces; a report
write is unnecessary for supported verified reads. Composite evidence is
available per item when retained; legacy absence is explicit.

Diagnostic-only results have no publication receipt or findings. Check
`failed_run_recovery` before deciding whether exact recovery is available.
Treat `run_status_unavailable` as an allocated identity without durable status;
stop rather than retrying the review. Preserve coverage, extraction, publication
and CI as independent axes. Zero extracted findings in `reports_only` or `mixed`
output does not establish a clean report. Verify advisory findings against the
captured evidence and current code before changing anything.

## Fallbacks

Choose the execution path before starting a new review. State the concrete tool
or host limitation once. An unproven MCP root or an objective above 4096 bytes
that still fits the CLI limit requires the CLI path. Slowness, a pending handle,
or an unknown host timeout alone does not justify abandoning the async
lifecycle. Never switch an already-started invocation to `run_review` or CLI
execution.

### Foreground MCP

If any of the three lifecycle tools is unavailable, use one foreground
`run_review` with the same admitted inputs and both execution guards when
supported. The host's hard tool-call timeout must be verified to exceed
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

Use the CLI when Mulgae MCP tools are unavailable, when the authorized target
is stdin, when the attached server's root cannot be bound to the requested root,
when the complete objective exceeds the MCP limit, or for CLI-only commands
such as follow-up and report/export writes. A host that cannot read MCP resources
can use receipt-bound CLI content reads from the same independently bound root.
Do not start a second MCP server from a shell when an attached server is already
available. The CLI is also a fallback when no usable MCP execution path can be selected before
starting.

Run the command once and await completion through the host's process-wait
facility. Preserve any returned process handle and wait on that same handle,
using the longest waits permitted by the host and higher-priority instructions.
This also applies to CLI-only child workflows. A CLI process has no MCP
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

Use exactly one authorized selector: `--diff RANGE`, `--stage`, `--dirty`,
`--workspace`, `--patch PATH`, or `--stdin`. With native guard support, run from
the requested root and populate these variables from structured native output:

```bash
mulgae review --stage --preflight \
  --expected-project-binding "$project_binding" --output json
mulgae review --stage --expected-project-binding "$project_binding" \
  --expected-request-digest "$request_digest" --output json
```

Keep the complete objective and role arguments identical across both commands.
Preflight creates no run, diagnostics, publication or provider invocation and
cannot be combined with `--session`. Read the complete versioned JSON envelope,
including when the process exits nonzero. Current source emits
`mulgae-command-result.v18`; preserve supported historical decoding. Exit `1`
is a content-policy outcome. Use stable typed reasons for failures, as described
in [lifecycle.md](references/lifecycle.md), rather than parsing provider prose.

After completion, read the exact run through
[verified-reads.md](references/verified-reads.md). If an authorized fix is present
in the selected target, a follow-up uses the original run and verified exact
finding ID:

```bash
mulgae followup --run r_... --finding F001 --dirty \
  --objective "Check whether the original finding is resolved." --output json
```

Await that child command and inspect its returned run. A rerun or follow-up does
not rewrite the original result. For partial failure, follow
[recovery.md](references/recovery.md#recover-a-partially-failed-review), preserving
the deterministic composite run ID and reconciling `status_required` or
`composite_publication_incomplete` before any retry.

Only when shareable files are requested, use explicit safe relative destinations:

```bash
mulgae report --run r_... --output-path reports/review.md --output json
mulgae export --run r_... --output-path exports/review.zip --output json
```

These are writes. The redacted export allowlist excludes additional copied
composite source findings, receipts, captures and evidence bodies; local verified
read access does not authorize exporting private support.

## Apply safety boundaries

- Use structured output, exact IDs, stable error codes, and command
  preconditions. Mulgae has no client idempotency key: review-like commands
  create new runs, so never blindly retry an uncertain mutation.
- Run child workflows from the canonical Git worktree root. On
  `project_root_mismatch`, confirm that root before retrying. If the confirmed
  root is not initialized, request explicit initialization authority before
  running `mulgae init`; never create nested `.mulgae` state from a
  subdirectory.
- Before requesting a rerun, inspect whether Mulgae already consumed its single
  same-provider retry for `provider_unavailable` or `provider_turn_failed`.
  Runtime-log v4 field-discard events contain paths and counts only, never the
  discarded provider values.
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
- Never weaken path, locality, capture, validation, evidence, or publication
  fences. Never edit manifests, attempts, diagnostics, or final artifacts.
- Preserve Mulgae's product boundary: it is a local advisory code-review CLI,
  not merge approval, consensus, a hosted service, a task manager, or an agent
  orchestrator.
- Commit only `.mulgae/config.yaml`. Never commit or share
  `.mulgae/local.yaml`, any other `.mulgae/**` path, provider homes,
  credentials, raw provider transcripts, diagnostics, or exported review
  bundles.
