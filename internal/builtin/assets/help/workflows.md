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

Child workflows create new immutable runs:

```bash
mulgae followup --run latest --finding F001 --dirty
mulgae delta --since-run latest --dirty --roles logic,testing
mulgae rerun --run latest --role logic --provider zcode
```

`followup` checks one finding, `delta` reviews changes relative to a prior run,
and `rerun` repeats one prior attempt. Use `--output json` for machine-readable
command envelopes.
