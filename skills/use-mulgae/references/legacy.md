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
to retarget an existing session. Apply this root boundary to all reads and child
or recovery workflows as well as execution.

When native `execution_guard` is absent and an unguarded review is within the
user's authorization, compare CLI and bound-MCP preflight using exactly the same
target, objective and roles. Compare `requested_kind`, `captured_kind`, `git_mode`,
`sha256`, `size`, file-set IDs and policy identities, and role transmissions.
A difference or observed target change stops provider execution. These checks
cannot atomically bind a mutable target to later execution and cannot satisfy
an explicitly requested native guard. Use the same arguments for execution and
report the unguarded limitation.

An attached server without guard support can still be bypassed before execution
by a capable native CLI using paired guards. Keep its independently observed
binding and fresh preflight receipt; do not splice receipts across binaries or
change the authorized target. If no available path supports a requested guard,
stop and report the unsupported contract.

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
