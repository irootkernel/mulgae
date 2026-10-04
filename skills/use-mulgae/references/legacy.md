# Legacy Mulgae compatibility

Use this reference only when a needed native capability or host surface is
absent. A typed binding, guard, receipt, integrity or security failure is not
legacy absence. Never strip a requested guard or start a replacement review to
switch transports. Report the concrete limitation and preserve the user's scope.

## Legacy root and preflight binding

Without native `project_binding`, attached MCP requires trusted launch-time
evidence that this live server's canonical root equals the requested root.
Registration/configuration, a tool name, successful preflight and equal patch
hashes cannot prove it. If launch identity is missing or different, use CLI from
the requested canonical root before starting. Do not launch another MCP server
to retarget an existing session. Apply this root boundary to all reads and publication reconciliation as well as execution.

A current `live_source: v1` server uses independent project binding only.
Empty `execution_guard` and `capture_identity` values do not establish legacy
absence. Never manufacture capture receipts or duplicate preflights to simulate
a content-drift guarantee. A required unsupported capability stops its dependent
action; use a capable CLI from the independently selected root before starting.

## Legacy result access

Prefer the capable CLI when only the MCP host lacks resource access. The
following limitations apply only to older binaries without native finding pages
or content reads.

Legacy CLI findings JSON returns a verified count and `review_artifact_uri`,
not finding IDs. Status and findings paths must agree, but matching paths do not
bind two queries or a later file read to one publication receipt. Do not parse
human findings output or open private final JSON to manufacture verified IDs.

Legacy `mulgae report` writes a file and requires an authorized safe relative
`--output-path`. Its rendered file supplies advisory candidate IDs and the target
digest; the result does not bind a later read of that file to its bytes. For an
ordinary run, verify selected IDs against the captured target with CLI `excerpt`
and then inspect current code. Without an authorized report write or another
trusted source for exact IDs and target digest, stop ID-dependent judgments and
follow-up. Historical composites without evidence cannot support excerpt-based
verification; report that limit rather than reading source runs privately.

On a proven legacy MCP root, follow each resource's canonical `nextURI` through
completion. Existing report/evidence URIs retain their historical verification
and metadata; they do not acquire publication-receipt binding implicitly.
Never read a resource from an unbound server or upgrade an artifact in place.
