# Workflows

Every review-like command requires exactly one target:

```text
--workspace
--stage
--dirty
--diff REVISION_RANGE
--patch RELATIVE_PATH
--stdin
```

Common commands:

```bash
mulgae review --diff origin/main...HEAD --objective "Review before merge."
mulgae status --run r_...
mulgae findings --run r_... --severity high
mulgae report --run r_... --output-path reports/review.md
```

Inspect the capture and configured execution envelope without running providers:

```bash
mulgae review --stage --preflight --output json
```

Preflight performs complete immutable capture, directory-view admission, and
capture-manifest construction, then reports
the exact source file set transmitted to every selected role, each role's
provider route, effective provider timeouts, AGY permission mode, and enclosing
lane/run budgets. `qualification` is `not_run`: preflight does not discover,
qualify, repair, or invoke a provider, and it creates no session, run,
diagnostics, publication, or durable review artifact. The workspace manifest is
listed separately as `generated_at_execution`; its ephemeral filesystem identity
is not represented as source evidence.

Source capture has no fixed file-count, aggregate-byte, per-file, diff, patch,
stdin, or capture-manifest ceiling. Preflight still rejects malformed paths,
reserved namespaces, selected symlinks and special files, invalid raster
signatures, and files excluded by capture policy. Other malformed preflight
projections use `preflight_result_validation_failed`.
Both include a safe stage and next-action hint without creating diagnostics or
printing captured paths. Human failures from every command include a stable
code, public stage, and minimum remediation hint.

An explicit AGY `safe` mode produces a warning because headless tool requests
may be denied. A no-change target reports `status: no_change` with no
transmissions or execution budget. `--preflight` cannot be combined with
`--session`.

Child workflows create new immutable runs:

```bash
mulgae followup --run latest --finding F001 --dirty
mulgae delta --since-run latest --dirty --roles logic,testing
mulgae rerun --run latest --role logic --provider zcode
```

`followup` checks one finding, `delta` reviews changes relative to a prior run,
and `rerun` repeats one prior attempt. Use `--output json` for machine-readable
command envelopes.
