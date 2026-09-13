# Architecture decision records

This directory preserves accepted, superseded, deprecated, and rejected
structural decisions with their rationale. Current architecture remains owned
by [`docs/architecture/README.md`](../architecture/README.md); these records
explain why durable choices were made.

## Accepted

- [Final provider portfolio](final-provider-portfolio.md) records why ZCode,
  Grok, and Codex are the supported families and how retired references fail.
- [Composite review recovery](composite-review-recovery.md) records why exact
  same-target reruns are combined into a new immutable authority.
- [Review await design](review-await.md) records the accepted session-local MCP
  review lifecycle and its rejected alternatives.
- [ZCode app-server transport](zcode-app-server-transport.md) records why ZCode
  review and qualification speak the app-server protocol and the wire shapes
  its live spike pinned.
