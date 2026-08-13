---
name: use-mulgae
description: Use Mulgae safely for local multi-provider code reviews, run inspection, findings follow-up, configuration diagnosis, cleanup planning, and recovery. Trigger when a user asks an AI coding agent to run, inspect, continue, diagnose, configure, clean up, or recover a Mulgae workflow in a project.
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

5. Derive the next action from current Mulgae output, never from conversation
   memory. Preserve exact session (`s_...`), run (`r_...`), attempt (`a_...`),
   and finding (`F...`) IDs.

## Run the normal workflow

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

4. Read the complete JSON envelope even when the process exits `1`; it is a
   policy outcome. Treat exits `2`, `4`, `7`, `8`, `9`, and `10` according to
   their stable error code, stage, and remediation hint. Do not infer success
   from prose or provider output.
5. Immediately re-read authoritative state using the exact returned run ID:

   ```bash
   mulgae status --run r_... --output json
   mulgae findings --run r_... --severity low --output json
   ```

   `--severity` sets the minimum reported severity; `low` is the broadest
   query and omits `info`-level findings.

6. Treat findings as advisory hypotheses. Verify each finding against the
   captured target and current code before changing anything:

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
- Require explicit user intent for initialization, imported-session use,
  cancellation, cleanup, provider or role changes, or any requested reset,
  service control, goal change, or repair. Read
  [lifecycle.md](references/lifecycle.md) before lifecycle actions.
- Read [authoring.md](references/authoring.md) only for provider, role, artist,
  or configuration authoring requests.
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
