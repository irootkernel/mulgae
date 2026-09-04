# Architecture decision records

This directory preserves accepted, superseded, deprecated, and rejected
structural decisions with their rationale. Current architecture remains owned
by [`docs/architecture/README.md`](../architecture/README.md); these records
explain why durable choices were made.

## Accepted

- [Composite review recovery](composite-review-recovery.md) records why exact
  same-target reruns are combined into a new immutable authority.
- [Review await design](review-await.md) records the accepted session-local MCP
  review lifecycle and its rejected alternatives.
