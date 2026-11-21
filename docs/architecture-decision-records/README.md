# Architecture decision records

This directory preserves accepted, superseded, deprecated, and rejected
structural decisions with their rationale. Current architecture remains owned
by [`docs/architecture/README.md`](../architecture/README.md); these records
explain why durable choices were made.

## Accepted

- [Final provider portfolio](final-provider-portfolio.md) records the supported
  families, role preferences and historical retirement boundaries.
- [Composite review recovery](composite-review-recovery.md) records why exact
  same-target reruns are combined into a new immutable authority.
- [Review await design](review-await.md) records the accepted session-local MCP
  review lifecycle and its rejected alternatives.
- [ZCode app-server transport](zcode-app-server-transport.md) records why ZCode
  review and qualification speak the app-server protocol and the wire shapes
  its live spike pinned.
- [Codex app-server transport](codex-app-server-transport.md) records the
  ephemeral Codex protocol route and its report and isolation boundaries.
- [Cursor ACP transport](cursor-acp-transport.md) records explicit Cursor
  selection and the ACP session, permission, and credential boundaries.
- [AGY stream-JSON transport](agy-stream-json-transport.md) records the
  single-account stream protocol, guarded reads and natural-exit boundary.
- [herdr-core terminal transport](herdr-core-terminal-transport.md) records
  EPIC-017's reusable isolated `herdr-core` terminal runtime, trusted pane
  trampoline (`__mulgae_paneexec_v1`), control-plane and exact-TTY Seatbelt
  hardening, disposable `GROK_HOME` scratch-file delivery, and Phase 1 Grok
  `1.0.89+` migration and live certification.

## Accepted design for planned implementation

- [Coordinate reviews in the shared native execution path](haepari-review-coordination.md)
  records EPIC-016's native boundary, ownership and advisory limits. Implementation
  and released qualification remain pending.

- [Native review contracts before review completeness and iteration](verified-review-iteration.md)
  records why EPIC-007 groups native binding with verified inspection, and why
  EPIC-008 originally grouped requirements assessment with followup and comparison.
  Its 2026-10-27 revision narrows EPIC-008 to optional requirements assessment
  and verified reads, preserving the earlier rationale as historical context.
  Design acceptance does not mean the new capabilities are implemented; the
  roadmap owns delivery status.
