# Product specifications

This directory is the canonical owner for Mulgae's required and implemented
behavior and durable product contracts.

- [Product goals and boundaries](goals.md) defines the product purpose,
  guarantees, non-goals, and release boundary.
- [Contracts and artifacts](contracts.md) defines configuration, schemas,
  prompts, artifacts, versioning, field ownership, and exits.
- [Security requirements and trust model](security.md) defines trust boundaries,
  isolation, credential handling, validation, and fail-closed behavior.

## Adopted implementation requirements

- [Verified review contracts](verified-review-contracts.md) defines native
  project/preflight guards and coherent, bounded result inspection for EPIC-007.
- [Review completeness and iteration](review-completeness-and-iteration.md)
  defines immutable Briefs, requirements assessment, selected-finding batch
  followup, and provider-free comparison for EPIC-008.

These are adopted requirements, not a claim that current binaries implement the
new interfaces. Their verification checkboxes remain unchecked until supported
by behavior and compatibility evidence. The [roadmap](../roadmap/README.md)
alone owns Task/Epic lifecycle and execution order.

Current source, tests, and embedded contracts remain authoritative for what the
binary implements. A mismatch with these specifications is a conformance defect
to resolve in the same behavior change.
