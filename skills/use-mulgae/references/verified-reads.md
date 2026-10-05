# Verified Mulgae result reads

Read this reference after a review terminates, or for an authorized inspection of
an exact existing run. Establish the requested root and compare native project
binding as described in [SKILL.md](../SKILL.md#bind-the-review-target). Reads
invoke no provider and do not create report files.

## Select available contracts

Use `get_context` or verified inspection `capabilities` and the host's connected
tools/resources for read support. Preflight v8 has a narrower advertisement and
leaves the inspection/page/content fields empty. The
relevant values are `inspection`, `finding_pages`, `finding_details`,
`report_content`, `indexed_evidence`, and `composite_evidence`, each `v1` when
supported. Unknown or absent versions do not establish support. Binary support
and per-artifact availability are separate: an older composite can remain
readable while its evidence is unavailable.

If the host cannot expose a resource but the CLI supports its read contract,
use CLI from the independently established root with the same expected binding
and publication receipt. Read [legacy.md](legacy.md#legacy-result-access) only
when the needed native contract is absent. Never bypass a mismatch, corruption
or security error by changing to an unguarded or private-file read.

## Inspect one publication

MCP `inspect_review` accepts `run_id`, `expected_project_binding`,
`minimum_severity`, `limit`, `cursor`, and `expected_publication_receipt`.
Start with the exact run and expected binding. CLI equivalent:

```bash
mulgae inspect --run "$run_id" \
  --expected-project-binding "$project_binding" --output json
```

Read `publication_authority`, `publication_state`, `coverage_status`,
`structured_extraction_status`, `ci_decision`, `capture_availability`,
`failed_run_recovery`, `publication_receipt`, and `role_reports` independently.
A diagnostic-only observation has no receipt or content references. No receipt
means no verified finding/content reads. A retained historical failed-run source supports verified inspection only.

A current live result advertises `source_evidence: v1`, `capture_availability:
not_captured` and explicit source identity. Read its excerpts with
`--source-identity-sha256`; historical excerpts use their retained target digest.
Source identity hashes selection metadata, not today's content or an archived tree.
Retained raster URIs use the exact source identity, side and path issued by query.
Never fall back to current source to fill missing evidence.

A verified capture proves complete retained material; `target_sha256` alone
hashes the target bytes. `capture_identity_unavailable` is historical absence.
Missing or corrupt bound support fails the read and cannot be treated as absence.
For a composite, common capture is available only when every selected role source,
including roles without findings, has the same verified capture identity.

## Consume finding pages

`inspect_review`/CLI `inspect` and `list_findings`/CLI `findings` return structured
summaries with IDs, `detail_uri`, and indexed `evidence` references. CLI `findings`
requires `--severity`; `low` is the broadest supported floor and excludes `info`.
MCP uses `minimum_severity: low`. Default limit is 100; accepted limits are
1 through 1000. `finding_count` is the filtered total and `returned_count` is
only this page's size.

Preserve the returned `publication_receipt`. Follow `next_cursor` until it is
empty, keeping the same command/query kind, run, binding, severity and limit.
Pass `expected_publication_receipt` in MCP or the CLI equivalent on continuation:

```bash
mulgae inspect --run "$run_id" --severity low --limit 100 \
  --cursor "$next_cursor" --expected-project-binding "$project_binding" \
  --expected-publication-receipt "$publication_receipt" --output json
```

Do not transfer an inspect cursor to findings, change filters mid-page, or fall
back to `latest`. Receipt/cursor mismatch, cleanup or integrity failure stops
that consumption. A new snapshot requires a deliberate fresh inspection; never
combine pages from different receipts.

Summaries omit complete explanations and report bodies. Zero extracted findings
in `reports_only` or `mixed` output does not prove the role reports are clean.
Read the relevant original reports and complete finding details before judgment.

## Read complete content

Use returned `detail_uri`, `role_reports[].uri` and each `evidence[].uri` through
the host's MCP resource reader. Preserve the URI exactly. For rendered Markdown,
use the advertised report resource template with the exact run, project binding
and publication receipt. Only canonical parameter order and encoding are
accepted. If the host cannot construct or read that resource, use CLI:

```bash
mulgae read-finding --run "$run_id" --finding "$finding_id" \
  --expected-project-binding "$project_binding" \
  --expected-publication-receipt "$publication_receipt" --output json
mulgae read-report --run "$run_id" \
  --expected-project-binding "$project_binding" \
  --expected-publication-receipt "$publication_receipt" --output json
mulgae read-report --run "$run_id" --role logic \
  --expected-project-binding "$project_binding" \
  --expected-publication-receipt "$publication_receipt" --output json
mulgae excerpt --run "$run_id" --finding "$finding_id" \
  --source-identity-sha256 "$source_identity_sha256" --evidence-index 0 \
  --expected-project-binding "$project_binding" \
  --expected-publication-receipt "$publication_receipt" --output json
```

For a live result, use the inspected source identity. Historical results instead
use `--current-target-sha256` with the inspected target digest. Neither value is
a hash of today's working tree. Select every
relevant verified evidence index from the summary; zero-based indices range from
0 through 19. Index zero is not the complete evidence inventory. Keep unavailable
items explicit and stop any judgment that requires their missing evidence.

CLI chunks expose `content_sha256`, `encoding`, `offset`, `total_bytes`,
`returned_bytes`, `next_offset`, and `content`. On continuation, keep all content
selectors unchanged and supply the issued `--offset`,
`--expected-publication-receipt` and `--expected-content-sha256`. Stop at
`next_offset: null`. MCP exposes corresponding native metadata and
`io.mulgae/nextURI`; follow the returned continuation exactly to completion.
Do not reuse legacy-only continuation URIs as receipt-bound reads.

Chunks contain at most 16,384 source bytes and never split UTF-8 text. Decode
binary content according to its declared encoding. Reassemble in offset order
and compare total length and the complete-content digest before claiming a full
read. There is no product total-content ceiling; do not truncate a large report
or treat the first chunk as complete. Empty valid content can finish at offset
zero. Offset or content-digest errors stop the read.

Historical composite finding details include copied `source_finding` and
`source_receipt`. Published sources have P2 provenance; failed recovery sources
have a recovery-manifest digest and attempt, without a fabricated review ID or
publication receipt. Verified composite evidence reads its retained copies,
never the live source run or working tree. Historical composites without copied
evidence remain explicitly unavailable and are not retrofitted by reads.

Treat findings as advisory hypotheses. Compare verified retained evidence with
current code before an authorized edit and report valid, invalid or out-of-scope
judgments with their limits. Never parse private final/role-report files as a
substitute for these verified surfaces. Source cleanup remains governed by native
cleanup protections, including retained failed-recovery roots.
