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
  followup, and provider-free comparison preserved for EPIC-008 redesign.
- [Live workspace and Git review](live-workspace-and-git-review.md) defines
  snapshot-free targets, neutral reviewer execution, and historical compatibility
  for EPIC-009.

Checked requirements in the EPIC-007 and EPIC-009 specifications denote verified
behavior and compatibility. EPIC-008 remains under a redesign hold; its unchecked
requirements do not claim implemented behavior.
The [roadmap](../roadmap/README.md) alone owns Task/Epic lifecycle and execution
order.

Current source, tests, and embedded contracts remain authoritative for what the
binary implements. A mismatch with these specifications is a conformance defect
to resolve in the same behavior change.
