---
name: use-mulgae
description: Use Mulgae safely through attached MCP tools or the CLI for local multi-provider code reviews, run inspection, findings follow-up, configuration diagnosis, cleanup planning, and recovery. Trigger when a user asks an AI coding agent to run, inspect, continue, diagnose, configure, clean up, or recover a Mulgae workflow in a project.
---

# Use Mulgae

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

   Use `mulgae doctor --output json` for offline setup readiness. In doctor v2,
   consume `config_v3`, `local_configuration`, `provider_identity`, each
   configured provider's `binary_available` and `cli_compatible`, and
   `configured_readiness` independently. Static admission and prior review
   qualification do not gate this state.

5. Derive the next action from current Mulgae output, never from conversation
   memory. Preserve exact session (`s_...`), run (`r_...`), attempt (`a_...`),
   and finding (`F...`) IDs.

## Prefer the attached MCP workflow

1. Use attached Mulgae MCP tools when they are available for the canonical
   project. Match exactly one target: `workspace`, `stage`, `dirty`, `diff`, or
   `patch`. MCP stdin is transport-only and cannot be a review target.
2. Call `preflight_review` with the selected `target` and the same optional
   `objective` and `roles` intended for execution. Inspect capture counts,
   routing, warnings, and the admitted run deadline before provider work.
3. If the plan matches the authorized scope, call `run_review` once with the
   same arguments. Wait for its foreground result. Do not poll `list_runs` or
   `get_run` while it is active; progress notifications are observation only.
4. Read the common structured envelope even when the outcome is
   `request_changes` or `error`. Preserve the exact returned run ID, including
   the identity attached to a failed `run_review`. Do not retry a lost or
   uncertain `run_review`: a second call creates another run.
5. After the foreground call returns, call `get_run` with the exact run ID. Call
   `list_findings` only when the result has publication authority; a
   diagnostic-only result has no findings. Treat `run_status_unavailable` as an
   allocated identity without durable status and stop rather than retrying the
   review. Use `minimum_severity: low` for the broadest permitted finding query.
   Follow a resource's canonical `nextURI` exactly until `complete` is true when
   the report or verified evidence is needed; do not invent offsets or paths.
6. Cancel the MCP request only on explicit user intent. Cancellation reaches
   the same foreground review and provider processes; it does not roll back an
   already committed publication.

## Fall back to the CLI

Use the CLI when Mulgae MCP tools are unavailable, when the authorized target
is stdin, or for commands outside the MCP surface such as follow-up, report, and
export. Do not start a second MCP server from a shell when an attached server is
already available.

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

4. Read the complete `mulgae-command-result.v5` JSON envelope even when the
   process exits nonzero. Exit `1` is a policy outcome. A rejected `followup`,
   `delta`, or `rerun` request still has a machine envelope: `request_state`
   `invalid` means syntax rejection, while `unresolved` means pre-execution
   selector or project-root resolution failed. Use the stable reason code and
   bounded message; JSON does not expose raw internal errors or require a
   public stage or remediation field. Treat exits `2`, `4`, `7`, `8`, `9`, and
   `10` by that envelope rather than prose or provider output. Read
   [lifecycle.md](references/lifecycle.md) for child-workflow selector failures.
5. Immediately re-read authoritative state using the exact returned run ID:

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
  Runtime-log v3 field-discard events contain paths and counts only, never the
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
- Re-read effective configuration or exact run status after every mutation.
- Never weaken path, locality, capture, validation, evidence, or publication
  fences. Never edit manifests, attempts, diagnostics, or final artifacts.
- Preserve Mulgae's product boundary: it is a local advisory code-review CLI,
  not merge approval, consensus, a hosted service, a task manager, or an agent
  orchestrator.
- Commit only `.mulgae/config.yaml`. Never commit or share
  `.mulgae/local.yaml`, any other `.mulgae/**` path, provider homes,
  credentials, raw provider transcripts, diagnostics, or exported review
  bundles.
