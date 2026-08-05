# Artifacts

Mulgae stores configuration and durable review state beneath `.mulgae/`.
A published run has the form:

```text
.mulgae/
  s_<uuidv7>/
    r_<uuidv7>/
      manifest.json
      runtime.jsonl
      attempts/
      validation/
      review_<uuidv7>.json
```

`manifest.json` records lineage, target identity, attempts, outcome axes, and
artifact hashes. A completed run has at most one top-level final review.
Invalid and repaired candidates remain under `attempts/`.

Failed runs without publication authority retain a bounded status under
`.mulgae/diagnostics/`. `status --run <id>` checks published artifacts first and
then reads that diagnostic-only status when no published run exists. It does
not expose raw provider streams or runtime event logs.

Use `status`, `findings`, and `report` to inspect a run. `clean --mode plan`
produces a hash-bound retention plan; applying it requires the exact plan hash.
`export` creates a redacted bundle at a safe project-relative path.
