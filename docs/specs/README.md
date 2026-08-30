# Product specifications

This directory is the canonical owner for Mulgae's required and implemented
behavior and durable product contracts.

- [Product goals and boundaries](goals.md) defines the product purpose,
  guarantees, non-goals, and release boundary.
- [Contracts and artifacts](contracts.md) defines configuration, schemas,
  prompts, artifacts, versioning, field ownership, and exits.
- [Security requirements and trust model](security.md) defines trust boundaries,
  isolation, credential handling, validation, and fail-closed behavior.

Current source, tests, and embedded contracts remain authoritative for what the
binary implements. A mismatch with these specifications is a conformance defect
to resolve in the same behavior change.
