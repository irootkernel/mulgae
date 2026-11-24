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
- [herdr-core terminal transport](herdr-core-terminal-transport.md) records
  EPIC-017's reusable isolated `herdr-core` terminal runtime, trusted pane
  trampoline (`__mulgae_paneexec_v1`), control-plane and exact-TTY Seatbelt
  hardening, disposable `GROK_HOME` scratch-file delivery, and Phase 1 Grok
  `1.0.89+` migration and live certification.
- [Coordinate reviews in the shared native execution path](haepari-review-coordination.md)
  records EPIC-016's native boundary, ownership and advisory limits.

## Deprecated / Retired

- [Cursor ACP transport](cursor-acp-transport.md) preserves the historical
  explicit Cursor ACP transport decision; Cursor support has been retired from
  the active provider portfolio.
- [Codex app-server transport](codex-app-server-transport.md) preserves the
  historical ephemeral Codex review provider transport decision; Codex review
  provider support has been retired from the active provider portfolio (Codex
  remains verified only as an external MCP client).
- [AGY stream-JSON transport](agy-stream-json-transport.md) preserves the
  historical single-account AGY review provider transport decision; AGY review
  provider support has been retired from the active provider portfolio.

## Accepted design for planned implementation

- [Native review contracts before review completeness and iteration](verified-review-iteration.md)
  records why EPIC-007 groups native binding with verified inspection, and why
  EPIC-008 originally grouped requirements assessment with followup and comparison.
  Its 2026-10-27 revision narrows EPIC-008 to optional requirements assessment
  and verified reads, preserving the earlier rationale as historical context.
  Design acceptance does not mean the new capabilities are implemented; the
  roadmap owns delivery status.
- [ZCode herdr-core terminal transport](zcode-herdr-core-transport.md) records
  EPIC-019's fully decoupled design migrating `FamilyZcode` onto Mulgae's shared
  isolated `herdr-core` terminal runtime via `herdr-zcode` (`--runtime core`,
  `prepare-isolated`, `--catalog-file`, `--check-desktop --json`), retiring
  Mulgae's Go-side ZCode Desktop internal coupling, defaulting new projects to
  `GLM-5.4` / `max` while preserving ZCode's current model on Config v5
  omission, and unifying workspace shell-free isolation (`DF-030`). Design
  acceptance does not mean the new transport is implemented; the roadmap owns
  delivery status.
