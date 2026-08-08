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
      role-reports/
        <role>.md
      target/
        target.bytes
        target-manifest.json
        captured-review.json
        blobs/
          sha256-<hex>
      review_<uuidv7>.json
```

`manifest.json` records lineage, target identity, attempts, outcome axes,
role-report inventory, and artifact hashes. Successful selected roles also
publish Mulgae-owned free-form role reports under `role-reports/`. A completed
run has at most one top-level final review. Invalid and repaired candidates
remain under `attempts/`.

`target/captured-review.json` is a reference-only v2 manifest. Exact captured
bytes are stored once under `target/blobs/sha256-<hex>` and may be shared by
multiple manifest entries. Mulgae verifies the manifest, support index, and
every referenced blob before a child workflow reconstructs the capture. Legacy
v1 archives remain readable, but new publications do not embed captured source
bytes as base64 in one JSON member.

Each `manifest.role_reports[]` entry carries role, path, sha256, byte length,
`provider_instance`, `attempt_id`, `content_type`, and a required `transport`
of `staged_file` or `stdout`, the provider output transport that carried the
accepted bytes for that role. Mulgae writes every published file itself; a
`staged_file` route only means the provider first wrote one validated file in
an isolated staging directory outside `.mulgae`. Accepted role reports have no
fixed size ceiling; structured artifacts and diagnostic previews remain bounded.

Failed runs without publication authority retain a bounded status under
`.mulgae/diagnostics/`. `status --run <id>` checks published artifacts first and
then reads that diagnostic-only status when no published run exists. It does
not expose raw provider streams or runtime event logs.

Use `status`, `findings`, and `report` to inspect a run. `clean --mode plan`
produces a hash-bound retention plan; applying it requires the exact plan hash.
`export` creates a redacted bundle at a safe project-relative path.
