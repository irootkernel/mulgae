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

Use `status`, `findings`, and `report` to inspect a run. `clean --mode plan`
produces a hash-bound retention plan; applying it requires the exact plan hash.
`export` creates a redacted bundle at a safe project-relative path.
