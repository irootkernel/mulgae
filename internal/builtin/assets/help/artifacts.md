# Artifacts

Configuration and durable review state live beneath `.mulgae/`. Only
`config.yaml` is shareable policy; `local.yaml` and runtime state remain private.
A new live review uses this logical layout:

```text
.mulgae/{session_id}/{run_id}/
  manifest.json
  status.json
  mulgae-runtime.jsonl
  attempts/
  validation/
  role-reports/<role>.md
  source/source.json
  publication/
  support/index.json
  excerpts/
  review_<uuidv7>.json
```

The v3 artifact and manifest bind live source selection, attempt/provider
identity, complete reports, verified excerpts and selected raster observations.
They contain no target capture manifest, copied source tree or full-source
replay archive. Source identity is selection metadata, not an atomic content
fingerprint. Source closure and provider drain are separate trusted provenance.

Publication retains P0/P1/P2 reconciliation, one top-level final review and
fail-closed integrity. A no-change run publishes with zero attempts and no
provider identity. Interrupted publication is reconciled without provider
execution; a read never fabricates a final result or repairs damaged support.

Historical ordinary, child, composite and failed-run records keep their old
artifact layouts. Their readers verify the complete bound capture/blob and
lineage inventory. Composite evidence remains self-contained where retained;
missing historical capture identity remains unavailable. These records grant
no new rerun, child, compose or source replay operation.
Historical composite runs have no provider runtime stream or attempts. Their
`target/` capture and `validation/final-candidate.json` remain reader-only
support; they are not live source artifacts.

Use exact public status, inspect, findings, read-report, read-finding and excerpt
surfaces. Receipt v2 and export v2 distinguish source identity from historical
target identity. Content is read in integrity-bound chunks; missing evidence
cannot be replaced from today's files.

Redacted exports default to `.mulgae/exports/<run-id>.zip` with a manifest
sidecar. They exclude native paths, credentials, raw provider streams and full
private source archives. Cleanup uses native dry-run eligibility and retains
active, incomplete, corrupt and required-ancestor state. Never delete runtime
files to simulate recovery or bypass cleanup protection.
