# Artifacts

Mulgae stores configuration and durable review state beneath `.mulgae/`.
An ordinary provider-executed run uses the following layout. A retained
`recovery/` namespace appears only when a failed or cancelled run is preserved;
a top-level review file grants final-review authority only after a verified P2
commit.

```text
.mulgae/
  config.yaml
  local.yaml
  exports/
    r_<uuidv7>.zip
    r_<uuidv7>.manifest.json
  s_<uuidv7>/
    r_<uuidv7>/
      manifest.json
      runtime.jsonl
      attempts/
      validation/
      role-reports/
        <role>.md
      target/
        capture-manifest.json
        target.bytes
        target-manifest.json
        captured-review.json
        blobs/
          sha256-<hex>
      recovery/
        manifest.json
        blobs/
          sha256-<hex>
      review_<uuidv7>.json
```

A composite recovery run is provider-free and uses a smaller self-contained
layout:

```text
.mulgae/
  s_<uuidv7>/
    r_<composite-uuidv7>/
      manifest.json
      status.json
      validation/
        final-candidate.json
      publication/
        journal.json
      role-reports/
        <role>.md
      support/
        index.json
        composite.json
        findings/
          F001.json
        sources/
          <role>/target/
            capture-manifest.json
            captured-review.json
            blobs/
              sha256-<hex>
      excerpts/
        F001_1.md
      target/
        target.bytes
        target-manifest.json
        captured-review.json
        blobs/
          sha256-<hex>
      review_<uuidv7>.json
  store/
    epochs/
      epoch_<number>.json
    lineage-edges/
      e_<uuidv7>.json
```

The composite copies every selected role report, original finding, available
evidence index, and complete source capture so reads remain independent of the
source runs after allowed cleanup. `support/composite.json` binds finding ID
remapping, evidence identities, and portable source receipts. Ordinary source
receipts retain publication hashes and epoch; failed recovery sources retain a
recovery manifest digest and attempt identity without claiming publication.
Neither includes the local project binding. Per-role capture files appear only
when complete source material is available; otherwise metadata records
`capture_identity_unavailable`. A common composite capture identity requires all
selected role sources to verify the same identity, including roles with no
findings.

Composition does not execute providers or revalidate their output, so the
composite has no provider runtime stream or attempts.
`validation/final-candidate.json` retains the immutable publication candidate
for interruption recovery. The root `target/captured-review.json` and its blobs
remain present when the source review retained that archive. Historical
composites retain their existing layout and can report evidence unavailable.

For an ordinary run, `manifest.json` records lineage, target identity, attempts,
outcome axes, role-report inventory, and artifact hashes. Successful selected
roles also publish Mulgae-owned free-form role reports under `role-reports/`.
A completed run has at most one top-level final review. Invalid, repaired, and
extracted candidates remain under `attempts/`. A structured extraction trailer
records
`attempts/<a_...>/candidate.extracted.NNN.json`,
`attempts/<a_...>/invocations/002-extract/`, and
`prompts/<a_...>/002-extract.{stdin,manifest.json}`. It never replaces the role
report: `role-reports/<role>.md` keeps the accepted free-form bytes.

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
an isolated staging directory outside `.mulgae`. Accepted role reports and raw
provider stdout/stderr have no product byte ceiling; structured artifacts and
public diagnostic metadata retain their own contracts.

Failed or cancelled runs with retained recovery keep the verified source under
`recovery/manifest.json` and `recovery/blobs/`. `status --run <id>` checks
published artifacts first and then the retained recovery source. A recovery
status uses result kind `status_read` with `failed_run_recovery`; exact run
resolution also finds recovery-only runs. Recovery exposes accepted roles and
retry attempts for replay admission, but never grants final-review, publication,
or report authority. When no retained recovery exists, a typed
publication-not-found lookup may use the bounded diagnostic-only status under
`.mulgae/diagnostics/`. It does not expose raw provider streams or runtime event
logs.

Use `inspect` for publication state and a finding page from one verified
snapshot. Continue its pages with the same command, selectors, and receipt.
`findings` also provides its own paged query. `read-finding`, `read-report`, and
indexed `excerpt` return complete content in bounded chunks without writing files. Preserve the expected
project binding, publication receipt, and full-content digest through
continuations. `status` and `report --output-path` retain their separate status
and file-writing behavior.

`clean --older-than 30d` removes safely deletable terminal runs older than 30
whole days; add `--dry-run` for a read-only summary. `clean --all` removes every safely deletable terminal
run regardless of age. Active, incomplete, corrupt, unknown, and required lineage
state remains protected.
`export --run <id>` creates a redacted bundle and its manifest beneath
`.mulgae/exports/` by default. Pass `--output-path <relative-path>` to place an
intentional copy elsewhere beneath the project root. Mulgae does not modify Git
ignore configuration. Use `/.mulgae/*` followed by
`!/.mulgae/config.yaml`; commit only that shared policy file and never commit or
share `local.yaml` or any other `.mulgae/**` content.

New complete captures retain `target/capture-manifest.json` alongside the
reference archive and raw blobs, bound by support-index v2. This includes
no-change reviews, which still have no provider attempts. Reads verify the full
capture inventory; missing bound support is corruption. Historical artifacts
without complete support do not acquire a capture identity from their patch.

Composite support stays local. Availability for verified reads does not admit
source receipts, capture archives, or original finding support into a redacted
export bundle. Existing explicit export options and redaction rules remain in
force.
