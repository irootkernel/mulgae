---
name: use-mulgae
description: Start Mulgae reviews asynchronously through MCP and await completion without status polling. Use for authorized code reviews, run inspection, finding follow-up, configuration diagnosis, cleanup planning, and partial-failure recovery through exact reruns and composition. Use foreground MCP or CLI execution when the async lifecycle is unavailable.
---

# Use Mulgae

## Default: start once, await completion

For a new root review, prefer attached Mulgae MCP when `start_review`,
`await_review`, and `cancel_review` are all connected for the canonical project.
Complete [preparation](#establish-current-authority) before starting. Select
exactly one authorized target: `workspace`, `stage`, `dirty`, `diff`, or `patch`.
MCP stdin is transport-only. Use the same target, objective, and roles for
preflight and execution; the staged target below is illustrative:

```text
preflight_review({"target": {"kind": "stage"}})
# Inspect capture, routing, warnings, and budget.run_deadline; check retention below.
start_review({"target": {"kind": "stage"}})
# Preserve the exact returned invocation_id; do not invent or substitute an ID.
await_review({"invocation_id": "<returned invocation_id>"})
# Only after the terminal envelope returns, inspect its exact run ID.
```

Call start exactly once. A successful start or a pending await is not a completed
review and does not guarantee a durable run ID. Keep one `await_review` pending
on the returned invocation until completion. Never repeat an uncertain start or
start another review to change transports.
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

Do not repeatedly call `get_run`, `list_runs`, CLI `status`, inspect status-file
existence, or poll OS processes while waiting. Mulgae has no bounded-wait or
invocation-snapshot tool: `get_run` reads publication-backed or completed
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
3. Check for both `.mulgae/config.yaml` and `.mulgae/local.yaml`. If either is
   absent, stop unless the user explicitly requested initialization; then read
   [lifecycle.md](references/lifecycle.md). The first file is shared project
   policy; the second is private machine configuration.
4. Read admitted configuration with:

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
Only after terminal completion,
call `get_run` for that ID. If no run ID was returned, report the terminal outcome
without inventing one.

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

Call `list_findings` only when the status has publication authority;
diagnostic-only status has no findings. Treat `run_status_unavailable` as an
allocated identity without durable status and stop rather than retrying the
review. Use `minimum_severity: low` for the broadest permitted finding query.
Follow a resource's canonical `nextURI` exactly until `complete` is true when
the report or verified evidence is needed; do not invent offsets or paths.
Verify findings against the captured target and current code before changing
anything, as described in the CLI workflow below.

## Fallbacks

Choose the execution path before starting a new review. State the concrete tool
or host limitation once. Slowness, a pending handle, or an unknown host timeout
alone does not justify abandoning the async lifecycle. Never switch an
already-started invocation to `run_review` or CLI execution.

### Foreground MCP

If any of the three lifecycle tools is unavailable, use one foreground
`run_review` with the preflight arguments only when the host's hard tool-call
timeout is verified to exceed preflight's `budget.run_deadline`, allowing
transport overhead. If that timeout is insufficient or cannot be verified,
choose the CLI before starting instead. Cancelling a foreground MCP request cancels the review,
unlike cancelling an `await_review` observer; a host timeout can therefore cancel
execution or leave its outcome unknown. For an admitted foreground call, use the
same pending-handle wait policy as above. A lost or uncertain foreground call is
not safe to retry.

If the user explicitly requests cancellation on this foreground path, cancel
the MCP request itself. Do not call `cancel_review`: a `run_review` call has no
registry invocation for that tool to cancel. Preserve any returned run ID and
reconcile the outcome as described in [recovery.md](references/recovery.md).

### CLI execution and host waiting

Use the CLI when Mulgae MCP tools are unavailable, when the authorized target
is stdin, or for commands outside the MCP surface such as follow-up, report, and
export. Do not start a second MCP server from a shell when an attached server is
already available. The CLI is also a fallback when no usable MCP execution path
can be selected before starting.

Run the command once and await completion through the host's process-wait
facility. Preserve any returned process handle and wait on that same handle,
using the longest waits permitted by the host and higher-priority instructions.
This also applies to CLI-only child workflows. A CLI process has no MCP
invocation ID; never start another review to obtain one.

Only if the host provides no completion-wait facility and exposes only a
nonblocking process-handle status check, use that check as a last resort. After
each nonterminal result, wait 50 seconds through the host's wait or sleep facility
before checking the same handle again. Shorter sleeps may be combined without
extra status checks. If timed waiting is unavailable, stop automated polling and
report the limitation. Stop on terminal completion, a lost handle, or an
operational error; use recovery for an uncertain outcome. Never use Mulgae run
queries, file existence, or OS process scans as substitutes.

1. Match exactly one target to the authorized scope: `--diff RANGE`, `--stage`,
   `--dirty`, `--workspace`, `--patch PATH`, or `--stdin`.
2. Inspect the immutable capture and routing plan before provider work:

   ```bash
   mulgae review --stage --preflight --output json
   ```

   Replace `--stage` with the selected target. Preflight creates no session,
   run, diagnostic, publication, or provider invocation, and cannot be
   combined with `--session`.
3. Perform the requested external review before claiming it happened:

   ```bash
   mulgae review --diff origin/main...HEAD \
     --objective "Review this change before merge." \
     --output json
   ```

4. Read the complete `mulgae-command-result.v12` JSON envelope even when the
   process exits nonzero. Exit `1` is a policy outcome. A rejected `followup`,
   `delta`, `rerun`, or `compose` request still has a machine envelope:
   `request_state` `invalid` means syntax rejection, while `unresolved` applies
   only to `followup`, `delta`, and `rerun` when pre-execution selector or
   project-root resolution failed. Use the stable reason code and bounded
   message; JSON does not expose raw internal errors or require a public stage
   or remediation field. Treat exits `2`, `4`, `7`, `8`, `9`, and `10` by that
   envelope rather than prose or provider output. Read
   [lifecycle.md](references/lifecycle.md) for child-workflow selector failures.
   For composite recovery, follow
   [partial-failure recovery](references/recovery.md#recover-a-partially-failed-review)
   and call `compose_review` or `mulgae compose` with one exact root and every
   exact recovery run. Preserve its deterministic run ID. For CLI, `status_required` means inspect that ID and never blindly
   retry. For MCP, apply the same rule when
   `composite_publication_incomplete` returns non-null `session_id` and
   `run_id` with `retryable: false`.
5. After command completion, re-read status using the exact returned run ID.
   Query findings only if that status has publication authority:

   ```bash
   mulgae status --run r_... --output json
   mulgae findings --run r_... --severity low --output json
   ```

   `--severity` sets the minimum reported severity; `low` is the broadest
   query and omits `info`-level findings.

6. Treat findings as advisory hypotheses. A finding may have been transcribed
   from a role's free-form report by Mulgae's structured extraction pass, so
   verify each finding against the captured target and current code before
   changing anything:

   ```bash
   mulgae excerpt --run r_... --finding F001 \
     --current-target-sha256 sha256:... --output json
   ```

   The digest is the `target.content_sha256` recorded in the final artifact
   at `status`'s `final_artifact_uri`. Record only claims supported by current
   evidence, and report each finding to the user as valid, invalid, or out of
   scope.
7. After an authorized fix exists in the selected target, check it with the
   original run and finding IDs:

   ```bash
   mulgae followup --run r_... --finding F001 --dirty \
     --objective "Check whether the original finding is resolved." \
     --output json
   ```

   Re-read the new run's status after the command.

8. Produce shareable artifacts from a committed run only when the user asks:

   ```bash
   mulgae report --run r_... --output-path reports/review.md --output json
   mulgae export --run r_... --output-path exports/review.zip --output json
   ```

   `report` renders the human-readable report; `export` writes the redacted
   review bundle. Both require a safe relative `--output-path`.

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
  status after review completion. Start and cancellation acknowledgements must
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
