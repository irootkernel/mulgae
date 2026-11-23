# Coordinate reviews in the shared native execution path

Status: Accepted. Implemented in EPIC-016 and first released in v0.1.27.

## Context

CLI, foreground MCP and asynchronous MCP share review application execution.
Aquarium requires review-level capacity-one coordination before provider
qualification and through protected execution and cleanup. Its operators also
need to inspect results and perform local preflight without acquiring a grant.
Before EPIC-016, the shared path had no Haepari advisory integration.

## Decision

Place coordination policy in the application review lifecycle, expose native
lock operations through an inward-facing port, implement Haepari integration
in an adapter, and wire it through composition. Keep domain/application code
independent of concrete controller transport and process details. The shared
path owns persisted acquisition identity, cancellation, renewal and release.
Transport entrypoints retain request grammar and session-local lifecycle.

Use Haepari v0.1.0 `advisory-lock/v1`. The
[coordination specification](../specs/haepari-review-coordination.md) owns owner,
borrower, source consistency, failure and compatibility requirements. Neither
Aquarium nor the paired skill acquires an outer review lock.

## Alternatives and consequences

Separate CLI/MCP wrappers would duplicate ownership and leave native calls
uncoordinated. A skill-only lock would depend on every caller following prose.
Both are rejected because the shared native boundary must cover all transports.
Role-level acquisitions would serialize work inside a review and are rejected;
roles remain parallel under one review grant.

Haepari becomes a runtime prerequisite for coordinated live reviews. A missing
controller or invalid grant fails closed; preflight, verified reads and
provider-free no-change remain outside acquisition. Setup authority owns resource
registration and maximum-hold policy. An expired advisory grant can overlap
native work that has not stopped. It supplies no execution permission, process
containment or automatic review retry.

Implementation must preserve current result and failure contracts or version
affected public shapes under repository rules. The design does not allocate a
new schema version or claim existing binaries expose future lock state.
