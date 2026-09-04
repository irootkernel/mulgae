# Composite review recovery

Status: Accepted

## Context

An ordinary multi-role review can commit with incomplete coverage after one or
more required roles fail. A later exact rerun can recover a failed role, but
clients must not merge independent private artifacts or mistake later execution
for the original review.

## Decision

Mulgae creates a new immutable `composite` run only from an explicitly selected
committed ordinary root and one explicitly selected committed rerun for every
missing required role. Trusted application code verifies transitive same-role
lineage, ordinary publication integrity, and exact target-content digest
equality before recomputing the effective review under the root's published
policy.

Every newly published rerun binds its exact source attempt in immutable
lineage. The additive v1 field preserves legacy readability; a legacy rerun
without that binding remains queryable but is not eligible as a composite
recovery source because its exact origin cannot be proved.

Composite artifacts use dedicated v1 manifest and final-review schemas. Their
`review_composition` provenance is distinct from captured target identity and
child-run lineage. Publication copies the verified role reports and target
support required by normal readers, so source runs remain immutable,
independently queryable, and eligible for ordinary cleanup.

An exact root-and-recovery mapping has one durable fingerprint and converges on
one composite run identity. Mulgae never discovers a latest recovery, replaces
an already accepted role, invokes a provider, or publishes incomplete coverage
during composition.

## Consequences

CLI and MCP callers must supply exact run IDs and handle an explicit
reconciliation state. Query, report, export, and cleanup operate on the new run
without joining private source artifacts. Different exact recovery selections
may intentionally create different composite authorities.
